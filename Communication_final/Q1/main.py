from scapy.all import *


def print_pkt(pkt):
    pkt.show()

#tcp and dst port 23 and src host 10.9.0.5'
tcp = TCP()
ip = IP()
pkt = ip / tcp
pkt.show()
send(pkt, verbose=0)