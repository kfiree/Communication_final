from scapy.all import *


def print_pkt(pkt):
    pkt.show()


# ----- Task 1.1: Sniffing Packets -----

def q1A_B():
    f1 = 'icmp'
    f2 = 'tcp and dst port 23 and src host 10.9.0.5'
    f3 = 'net 128.230.0.0/16'

    pkt1 = sniff(filter=f1, prn=print_pkt)
    pkt1.show()
    pkt2 = sniff(filter=f2, prn=print_pkt)
    pkt2.show()
    pkt3 = sniff(filter=f3, prn=print_pkt)
    pkt3.show()


# ----- Task 1.2: Spoofing ICMP Packets -----

def q2A():
    ip = IP(src='1.2.3.4', dst='')  # add dst
    icmp = ICMP()
    pkt = ip / icmp
    pkt.show()
    send(pkt, verbose=0)


# ----- Task 1.3: Traceroute -----

# might use http://dnaeon.github.io/traceroute-in-python/

def q3():
    messageReceived = False
    i = 1
    hostName = 'ynet.co.il'
    while not messageReceived:
        ip = IP(ttl=i, dst=hostName)  # add dst?
        icmp = ICMP()
        pkt = ip / icmp
        reply = sr1(pkt, verbose=0)
        if reply is None:
            # no reply
            print('error. no reply received')
            break
        elif reply.type == 3:
            print("we have reached our destination")
            messageReceived = True
        else:
            print("message have been dropped by", reply.src)
        i += 1


