# srl-ping-mesh
An agent that measures and reports BGP peering keep-alive RTT/TTL metrics based on observed keep-alive packets.

# BGP keep-alive
By default, BGP peers exchange keep-alive packets every 30s to ensure the peer remains reachable. These small TCP packets are a stable stream of potential network observations, providing insight into changes in the network paths between peers. If the peers are located across a wide area network (say: BGP between PoP locations and central data centers), this traffic can serve as the proverbial "canary" to detect potential issues.

The resulting telemetry can be subscribed to, reported on a dashboard, etc.

## Python scapy
The Python [scapy](https://scapy.net/) library is a small packet processing tool to capture packets based on bpf filters (for example: BGP keep-alive packets).
