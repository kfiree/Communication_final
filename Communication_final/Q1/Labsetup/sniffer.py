#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
	pkt.show()

#pkt = sniff(filter='icmp', prn=print_pkt)
pkt = sniff(filter='tcp and dst port 23', prn=print_pkt)
#pkt=sniff(filter='net 128.230.0.0/16', prn=print_pkt)
