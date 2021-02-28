from scapy.all import *


def print_pkt(pkt):
    pkt.show()


# ----- Task 1.1: Sniffing Packets -----

def q1A_B():
    print("----- Task 1.1: Sniffing Packets -----")
    f1 = 'icmp'
    f2 = 'tcp and dst port 23'
    f3 = 'net 128.230.0.0/16'

    pkt1 = sniff(filter=f1, prn=print_pkt)
    pkt2 = sniff(filter=f2, prn=print_pkt)
    pkt3 = sniff(filter=f3, prn=print_pkt)


# ----- Task 1.2: Spoofing ICMP Packets -----

def q2():
    print("----- Task 1.2: Spoofing ICMP Packets -----")
    ip = IP(src='1.2.3.4', dst = '10.0.2.7')  # add dest ( send it to another VM in the same network)
    icmp = ICMP()
    pkt = ip / icmp
    pkt.show()
    send(pkt, verbose=0)


# ----- Task 1.3: Traceroute -----

# might use http://dnaeon.github.io/traceroute-in-python/
#todo check what todo when there is no reply
def q3():
    messageReceived = False
    i = 1
    hostName = 'ynet.co.il'
    while not messageReceived:
        print("#### iterarion num = ", i," ####")
        ip = IP(ttl=i, dst=hostName)  # add dst?
        icmp = ICMP()
        pkt = ip / icmp
        reply = sr1(pkt, verbose=0)
        if reply is None:
            # no reply
            print('error. no reply received')
            break
        elif reply.type == 3:
            print("we have reached our destination, and its only took ", i, "routes")
            messageReceived = True
        else:
            print("message have been dropped by", reply.src, " after ", i, " routers")
        i += 1
    print("we have reached our destination, and its only took ", i, "routes!")

# ----- Task 1.4: Sniffing and-then Spoofing -----

def spoof(pkt):
    #print("original ---- dst", pkt[IP].dst, " src=", pkt[IP].src)
    if ICMP in pkt and pkt[ICMP].type == 8:
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
        icmp = ICMP(type = 0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)

        spoofedPkt = ip/icmp
        print("---------------------------------------------------------------------------------------------------")
        pkt.show()
        print("############# spoofed ------ dst", spoofedPkt[IP].dst, " src=", spoofedPkt[IP].src, "#############")
        spoofedPkt.show()
        print("---------------------------------------------------------------------------------------------------")
        send(spoofedPkt, verbose=0)
        # check if echo reply 


def q4():
    sniff(filter='icmp', prn=spoof)



pointersDict = {
    1:q1A_B, 
    2:q2, 
    3:q3, 
    4:q4
    }

task = pointersDict.get(int(input("choose task : \n task number 1.")))

if task is not None:
    task()
else:
    print('no such task')