CS_118 Computer Networks: Project 2 (SimpleRouter)
====================================

In this project, you will be writing a simple router with a static routing table. Your router will receive raw Ethernet frames and process them just like a real router: forward them to the correct outgoing interface, create new frames, etc. The starter code will provide the framework to receive Ethernet frames; your job is to create the forwarding logic.

You are allowed to use some high-level abstractions, including C++11 extensions, for parts that are not directly related to networking, such as string parsing, multi-threading, etc.

For more detailed information about the project and starter code, please refer to the project spec.

## Acknowledgement

The implementation is based on thr oriingal code for UCLA CS118 Project3 by professor Alexander Afanasyev.

This edition(including autograde.py) is a homework of cns course in THUSS. Use the code, you should get 45/45 score in auto grade. However, it is not promised to pass the homework test with full score.

## simple_router
### route
client  client-eth0 10.0.1.100/8
--------------------------------
Router(sw0) sw0-eth1(->server1)  192.168.2.1/24
	    sw0-eth2(->server2)  172.64.3.1/16
            sw0-eth3(->server3)  10.0.1.1/8
----------------------------------------------
server1  server1-eth0  192.168.2.2/24
server2  server2-eth0  172.64.3.1/16

### The corresponding routing table for the SimpleRouter sw0 in this default topology:
Destination Gateway    Mask           Iface
−−−−−−−−−−−− −−−−−−−−−−−− −−−−−−−−−−−−−−−− −−−−−−−−
0.0.00      10.0.1.100 0.0.0.0        sw0−eth3
192.168.2.2 0.0.0.0    255.255.255.0  sw0−eth1
172.64.3.10 0.0.0.0    255.255.0.0    sw0−eth2

