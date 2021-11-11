#! /usr/bin/env python3

from collections import Counter
from scapy.all import sniff, TCP

## Create a Packet Counter
packet_counts = Counter()

def handle_bgp_keepalive(packet):

    if TCP in packet:
        for opt, val in packet[TCP].options:  #  consider all TCP options
            if opt == 'Timestamp':
                TSval, TSecr = val  #  decode the value of the option
                print('TSval =', TSval)

    # Create tuple of Src/Dst in sorted order
    key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
    packet_counts.update([key])
    return f"{packet.time} {packet.sniffed_on} Packet #{sum(packet_counts.values())}: {packet[0][1].src} ==> {packet[0][1].dst}"

## Setup sniff, filtering for BGP packets
sniff(iface=["e1-1","e1-2"], filter="tcp port 179", prn=handle_bgp_keepalive, count=10, store=False)

## Print out packet count per A <--> Z address pair
print("\n".join(f"{f'{key[0]} <--> {key[1]}'}: {count}" for key, count in packet_counts.items()))
