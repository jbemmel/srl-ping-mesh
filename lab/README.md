# Demo lab for BGP Keep-Alive tracking agent

1. Deploy the lab
```
sudo clab deploy --reconfigure -t srl-bgp-ping-mesh.lab.yml
```

2. Check BGP peering status srl1<->srl2
```
ssh admin@clab-bgp-ping-mesh-srl1
/show network-instance default protocols bgp neighbor
```

Sample output:
```
-------------------------------------------------------------------------------------------------------------------------------------------------------------
BGP neighbor summary for network-instance "default"
Flags: S static, D dynamic, L discovered by LLDP, B BFD enabled, - disabled, * slow
-------------------------------------------------------------------------------------------------------------------------------------------------------------
-------------------------------------------------------------------------------------------------------------------------------------------------------------
+----------------------+--------------------------------+----------------------+--------+------------+------------------+------------------+----------------+
|       Net-Inst       |              Peer              |        Group         | Flags  |  Peer-AS   |      State       |      Uptime      |    AFI/SAFI    |         [Rx/Active/Tx]         |
+======================+================================+======================+========+============+==================+==================+================+
| default              | 1.1.1.2                        | leaves               | S      | 65000      | established      | 0d:0h:2m:43s     | ipv4-unicast   | [5/0/5]                        |
|                      |                                |                      |        |            |                  |                  | evpn           | [0/0/0]                        |
+----------------------+--------------------------------+----------------------+--------+------------+------------------+------------------+----------------+
-------------------------------------------------------------------------------------------------------------------------------------------------------------
Summary:
1 configured neighbors, 1 configured sessions are established,0 disabled peers
0 dynamic peers

```

3. Check agent statistics
```
info from state /bgp-ping-mesh
```

Sample output:
```
A:srl1# info from state /bgp-ping-mesh
    bgp-ping-mesh {
        peer 1.1.1.2 {
            last-update "a minute ago"
            last-rtt-in-us 13714
            min-rtt-in-us 6738
            max-rtt-in-us 52907
            avg-rtt-in-us 21026
            hops 0
            hops-changes 0
            keep-alives 8
        }
    }
```

4. Bring down direct link to srl2
```
enter candidate  
/interface ethernet-1/1 admin-state disable  
commit stay
```

5. After about 30 seconds (BGP keep-alive timer), check state again
```
info from state /bgp-ping-mesh
```

Sample output:
```
A:srl1# info from state /bgp-ping-mesh
    bgp-ping-mesh {
        peer 1.1.1.2 {
            last-update "16 seconds ago"
            last-rtt-in-us 63570
            min-rtt-in-us 6738
            max-rtt-in-us 63570
            avg-rtt-in-us 19315
            hops 1           <-- increased
            hops-changes 1   <-- hop count change detected
            keep-alives 12
        }
    }
```
