#!/usr/bin/env python
# coding=utf-8

import grpc

from datetime import datetime
import time
import sys
import logging
import os
import json
import traceback

# sys.path.append('/usr/lib/python3.6/site-packages/sdk_protos')
import sdk_service_pb2
import sdk_service_pb2_grpc
import config_service_pb2
import sdk_common_pb2

# To report state back
import telemetry_service_pb2
import telemetry_service_pb2_grpc

from logging.handlers import RotatingFileHandler

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

def ListInterfaces(network_instance):
    """
    Uses a local gNMI connection to list interfaces in the given network instance.
    Requires Unix socket to be enabled for gNMI
    Note the hardcoded admin/admin credentials (not checked by current config)

    For production deployment, it may be better to list interfaces explicitly
    in the Yang model config, such that this gNMI connection (and user/password)
    are not necessary
    """
    from pygnmi.client import gNMIclient
    logging.info( "ListInterfaces through gNMI..." )
    with gNMIclient(target=('unix:///opt/srlinux/var/run/sr_gnmi_server',57400),
                    username="admin",password="NokiaSrl1!",
                    insecure=True, debug=False) as c:
        path = f"/network-instance[name={network_instance}]/interface"
        data = c.get(path=[path],encoding='json_ietf')
        logging.info( f"ListInterfaces: {data}" )
        res = data['notification'][0]['update'][0]['val']

        def shorten(i):
            return i.replace("ethernet-","e").replace('/','-')

        return [ shorten( intf['name'] ) for intf in res['interface'] ]

    # return [ "e1-1.0", "e1-2.0" ] # Hardcoded until fixed

from threading import Thread
class BGPMonitoringThread(Thread):
   def __init__(self,network_instance):
      Thread.__init__(self)
      self.network_instance = network_instance
      self.stop = False
      self.state_per_peer = {} # Keyed by IP

   def run(self):
    """
    Outgoing packets are routed via 'gateway' device
    Incoming comes in in srbase-default under e1-1.0, e1-2.0, etc.
    """

    netinst = f"srbase-{self.network_instance}"
    while not os.path.exists(f'/var/run/netns/{netinst}'):
      logging.info(f"Waiting for {netinst} netns to be created...")
      time.sleep(1)

    interfaces = ["gateway"] + ListInterfaces( self.network_instance )

    def handle_bgp_keepalive(packet,is_ping):
        from scapy.layers.inet import IP, TCP

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
               rtt = int( (packet.time - s['time']) * 1e06 )
               s['min_rtt'] = min( s['min_rtt'] if 'min_rtt' in s else rtt, rtt )
               s['max_rtt'] = max( s['max_rtt'] if 'max_rtt' in s else rtt, rtt )
               s['sum_rtt'] = (s['sum_rtt']+rtt) if 'sum_rtt' in s else rtt

               if 'last_ttl' in s and s['last_ttl']!=ip.ttl:
                  s['ttl_changes'] = 1 if 'ttl_changes' not in s else (s['ttl_changes']+1)
               s['last_ttl'] = ip.ttl

               now_ts = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
               data = {
                 'last_update': { "value" : now_ts },
                 'last_rtt_in_us': rtt,
                 'min_rtt_in_us': s['min_rtt'],
                 'max_rtt_in_us': s['max_rtt'],
                 'avg_rtt_in_us': s['sum_rtt'] // s['count'],
                 'hops': 64 - ip.ttl,
                 'keep_alives': s['count'],
                 'hops_changes': s['ttl_changes'] if 'ttl_changes' in s else 0,
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

    def stop_filter(packet):
        return self.stop # Stop sniffing when flag is set

    from scapy.all import sniff
    with netns.NetNS(nsname=netinst):
       try:
          # Could filter on IP length using ip[2:2] too, minus 14 bytes eth
          filter = "tcp port 179 and (len==85 or len==66)"
          sniff( iface=interfaces, filter=filter, stop_filter=stop_filter,
                 prn=check_for_bgp_keepalive, store=False )
          logging.info( f"BGPMonitoringThread: sniff process in '{netinst}' exiting" )
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

        if 'admin_state' in data:
            state.admin_state = data['admin_state'][12:] # strip "ADMIN_STATE_"
        if 'network_instance' in data:
            state.network_instance = data['network_instance']['value']
    else:
        logging.info(f"Unexpected notification : {obj}")

    return False

class State(object):
    def __init__(self):
        self.network_instance = 'default'  # Set through config
        self.admin_state = 'enable'

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
                   if state.admin_state == "enable":
                      state.bgpthread = BGPMonitoringThread(state.network_instance)
                      state.bgpthread.start()
                elif state.admin_state == "disable":
                   logging.info( "Stopping BGP keep-alive sniff thread after next packet..." )
                   state.bgpthread.stop = True
                   del state.bgpthread
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
