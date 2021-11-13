#!/usr/bin/env python
# coding=utf-8

import grpc

from datetime import datetime, timezone, timedelta
import time
import sys
import logging
import socket
import os
import re
import struct
import ipaddress
import json
import traceback
import subprocess
from threading import Timer
import pwd

# sys.path.append('/usr/lib/python3.6/site-packages/sdk_protos')
import sdk_service_pb2
import sdk_service_pb2_grpc
import config_service_pb2
import sdk_common_pb2

# Local gNMI connection
from pygnmi.client import gNMIclient, telemetryParser

# To report state back
import telemetry_service_pb2
import telemetry_service_pb2_grpc

from logging.handlers import RotatingFileHandler

#
# BGP imports
#
import netns
import signal


############################################################
## Agent will start with this name
############################################################
agent_name='bgp_ping_mesh'

############################################################
## Open a GRPC channel to connect to sdk_mgr on the dut
## sdk_mgr will be listening on 50053
############################################################
#channel = grpc.insecure_channel('unix:///opt/srlinux/var/run/sr_sdk_service_manager:50053')
channel = grpc.insecure_channel('127.0.0.1:50053')
metadata = [('agent_name', agent_name)]
stub = sdk_service_pb2_grpc.SdkMgrServiceStub(channel)

# Try global gNMI connection
#gnmi = gNMIclient(target=('unix:///opt/srlinux/var/run/sr_gnmi_server',57400),
#                  username="admin",password="admin",
#                  insecure=True, debug=False)
#gnmi.connect()

############################################################
## Subscribe to required event
## This proc handles subscription of: Interface, LLDP,
##                      Route, Network Instance, Config
############################################################
def Subscribe(stream_id, option):
    # XXX Does not pass pylint
    op = sdk_service_pb2.NotificationRegisterRequest.AddSubscription
    if option == 'cfg':
        entry = config_service_pb2.ConfigSubscriptionRequest()
        # entry.key.js_path = '.' + agent_name
        request = sdk_service_pb2.NotificationRegisterRequest(op=op, stream_id=stream_id, config=entry)

    subscription_response = stub.NotificationRegister(request=request, metadata=metadata)
    logging.info( f'Status of subscription response for {option}:: {subscription_response.status}' )

############################################################
## Subscribe to all the events that Agent needs
############################################################
def Subscribe_Notifications(stream_id):
    '''
    Agent will receive notifications to what is subscribed here.
    '''
    if not stream_id:
        logging.info("Stream ID not sent.")
        return False

    # Subscribe to config changes, first
    Subscribe(stream_id, 'cfg')

def Add_Telemetry( path_obj_list ):
    telemetry_stub = telemetry_service_pb2_grpc.SdkMgrTelemetryServiceStub(channel)
    telemetry_update_request = telemetry_service_pb2.TelemetryUpdateRequest()
    for js_path,obj in path_obj_list:
      telemetry_info = telemetry_update_request.state.add()
      telemetry_info.key.js_path = js_path
      telemetry_info.data.json_content = json.dumps(obj)
    logging.info(f"Telemetry_Update_Request :: {telemetry_update_request}")
    telemetry_response = telemetry_stub.TelemetryAddOrUpdate(request=telemetry_update_request, metadata=metadata)
    return telemetry_response

def Remove_Telemetry(js_paths):
    telemetry_stub = telemetry_service_pb2_grpc.SdkMgrTelemetryServiceStub(channel)
    telemetry_del_request = telemetry_service_pb2.TelemetryDeleteRequest()
    for path in js_paths:
      telemetry_key = telemetry_del_request.key.add()
      telemetry_key.js_path = path
    logging.info(f"Telemetry_Delete_Request :: {telemetry_del_request}")
    telemetry_response = telemetry_stub.TelemetryDelete(request=telemetry_del_request, metadata=metadata)
    return telemetry_response

from threading import Thread
class BGPMonitoringThread(Thread):
   def __init__(self,interfaces):
      Thread.__init__(self)
      self.interfaces = interfaces
      self.state_per_peer = {} # Keyed by IP

   def run(self):
    """
    Hardcoded interfaces for now...
    Outgoing packets are routed via 'gateway' device
    Incoming comes in in srbase-default under e1-1.0, e1-2.0, etc.
    """
    from scapy.all import sniff
    from scapy.layers.inet import IP, TCP

    while not os.path.exists('/var/run/netns/srbase-default'):
      logging.info("Waiting for srbase-default netns to be created...")
      time.sleep(1)

    def handle_bgp_keepalive(packet,is_ping):
        # Format: (TSVal, TSEcr)
        ts = [ val for opt,val in packet[TCP].options if opt=='Timestamp' ]
        if ts==[]:
            logging.warning( "No TCP timestamp option found in packet" )
            return
        else:
           tsval,tsecr = ts[0]
        ip = packet[IP]
        peer = ip.dst if is_ping else ip.src
        logging.info(f'handle_bgp_keepalive is_ping={is_ping} ts={ts} peer={peer} len={len(packet)} if={packet.sniffed_on}')
        if peer in self.state_per_peer:
            s = self.state_per_peer[ peer ]
            if is_ping:
               s.update( { 'time': packet.time, 'ts': tsval, 'count': s['count']+1 } )
            elif tsecr==s['ts']:
               s['ts'] = 0 # Update to match only once
               now_ts = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
               data = {
                 'last_update': { "value" : now_ts },
                 'rtt': int( (packet.time - s['time']) * 1e06 ),
                 'hops': 64 - ip.ttl,
                 'keep_alives': s['count']
               }
               Add_Telemetry( [(f'.bgp_ping_mesh.peer{{.ip=="{peer}"}}', data )] )
            else:
               logging.warning( f"Ignoring PONG with TS mismatch: {ts} != {s}" )
        elif is_ping:
            self.state_per_peer[ peer ] = { 'time': packet.time, 'ts': tsval, 'count': 1 }
        else:
            logging.warning( f"Ignoring PONG without state for peer={peer}" )

    def check_for_bgp_keepalive(packet):
        if len(packet) == 85 and packet.sniffed_on == 'gateway': # outgoing PING BGP keep-alive
            handle_bgp_keepalive(packet,is_ping=True)
        elif len(packet) == 66 and packet.sniffed_on != 'gateway': # PONG
            handle_bgp_keepalive(packet,is_ping=False)

    with netns.NetNS(nsname="srbase-default"):
       try:
          sniff( iface=["gateway"] + self.interfaces, filter="tcp port 179",
                 prn=check_for_bgp_keepalive, store=False)
       except Exception as e:
          logging.error(e)

##################################################################
## Proc to process the config Notifications received by auto_config_agent
## At present processing config from js_path containing agent_name
##################################################################
def Handle_Notification(obj, state):
    if obj.HasField('config'):
        logging.info(f"GOT CONFIG :: {obj.config.key.js_path}")

        json_str = obj.config.data.json.replace("'", "\"")
        data = json.loads(json_str) if json_str != "" else {}
    else:
        logging.info(f"Unexpected notification : {obj}")

    return False

class State(object):
    def __init__(self):
        self.params = {}  # Set through config

    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)

##################################################################################################
## This is the main proc where all processing for BGP Ping Mesh starts.
## Agent registration, notification registration, Subscrition to notifications.
## Waits on the subscribed Notifications and once any config is received, handles that config
## If there are critical errors, Unregisters the fib_agent gracefully.
##################################################################################################
def Run():
    sub_stub = sdk_service_pb2_grpc.SdkNotificationServiceStub(channel)

    # optional agent_liveliness=<seconds> to have system kill unresponsive agents
    response = stub.AgentRegister(request=sdk_service_pb2.AgentRegistrationRequest(), metadata=metadata)
    logging.info(f"Registration response : {response.status}")

    request=sdk_service_pb2.NotificationRegisterRequest(op=sdk_service_pb2.NotificationRegisterRequest.Create)
    create_subscription_response = stub.NotificationRegister(request=request, metadata=metadata)
    stream_id = create_subscription_response.stream_id
    logging.info(f"Create subscription response received. stream_id : {stream_id}")

    try:
      Subscribe_Notifications(stream_id)

      stream_request = sdk_service_pb2.NotificationStreamRequest(stream_id=stream_id)
      stream_response = sub_stub.NotificationStream(stream_request, metadata=metadata)

      state = State()
      count = 1

      for r in stream_response:
        logging.info(f"Count :: {count} NOTIFICATION:: \n{r.notification}")
        count += 1
        for obj in r.notification:
            if obj.HasField('config') and obj.config.key.js_path == ".commit.end":
                # TODO if enabled...
                if not hasattr(state,'bgpthread'):
                   state.bgpthread = BGPMonitoringThread(interfaces=["e1-1.0","e1-2.0"])
                   state.bgpthread.start()
            else:
                Handle_Notification(obj, state)
                logging.info(f'Updated state: {state}')

    finally:
      Exit_Gracefully(0,0)

    return True
############################################################
## Gracefully handle SIGTERM signal
## When called, will unregister Agent and gracefully exit
############################################################
def Exit_Gracefully(signum, frame):
    logging.info( f"Caught signal :: {signum}\n will unregister BGP Ping Mesh agent" )
    try:
        response=stub.AgentUnRegister(request=sdk_service_pb2.AgentRegistrationRequest(), metadata=metadata)
        logging.info( f'Exit_Gracefully: Unregister response:: {response}' )
    finally:
        logging.info( f'GOING TO EXIT NOW' )
        sys.exit()

##################################################################################################
## Main from where the Agent starts
## Log file is written to: /var/log/srlinux/stdout/evpn_proxy_agent.log
## Signals handled for graceful exit: SIGTERM
##################################################################################################
if __name__ == '__main__':

    # grpc_eventlet.init_eventlet() # Fix gRPC eventlet interworking

    # hostname = socket.gethostname()
    stdout_dir = '/var/log/srlinux/stdout' # PyTEnv.SRL_STDOUT_DIR
    signal.signal(signal.SIGTERM, Exit_Gracefully)
    if not os.path.exists(stdout_dir):
        os.makedirs(stdout_dir, exist_ok=True)
    log_filename = f'{stdout_dir}/{agent_name}.log'
    logging.basicConfig(
      handlers=[RotatingFileHandler(log_filename, maxBytes=3000000,backupCount=5)],
      format='%(asctime)s,%(msecs)03d %(name)s %(levelname)s %(message)s',
      datefmt='%H:%M:%S', level=logging.INFO)
    logging.info("START TIME :: {}".format(datetime.now()))
    Run()
