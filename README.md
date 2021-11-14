# bgp-ping-mesh
An agent that measures and reports BGP peering keep-alive RTT/TTL metrics based on observed keep-alive packets.
![plot](./BGP_Ping_Mesh.png)

# Concept
Consider a globally distributed network with various sites, for example as described by [Roblox Engineering](https://blog.roblox.com/2021/04/network-packet-loss-latency-monitoring-roblox-cloud/). There is a general need to monitor latency and path changes between sites, and while you can do that by deploying agents on generic servers, why not simply report on traffic that is already traversing the network?

Given a truly open NOS like SR Linux, we can add whatever monitoring or reporting we want. For example: BGP keep-alive packets

# BGP keep-alive
By default, BGP peers exchange keep-alive packets every 30s to ensure the peer remains reachable. These small TCP packets are a stable stream of potential network observations, providing insight into changes in the network paths between peers. If the peers are located across a wide area network (say: BGP between PoP locations and central data centers), this traffic can serve as the proverbial "canary" 🐥 to detect potential issues.

The resulting telemetry can be subscribed to, reported on a dashboard, etc.

## Python scapy
The Python [scapy](https://scapy.net/) library is a small packet processing tool to capture packets based on bpf filters (for example: BGP keep-alive packets).
