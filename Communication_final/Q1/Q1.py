from scapy.all import *


def print_pkt(pkt):
    pkt.show()


# ----- Task 1.1: Sniffing Packets -----

def q1A_B():
    print("----- Task 1.1: Sniffing Packets -----")
    f1 = 'icmp'
    f2 = 'tcp and dst port 23 and src host 10.0.2.4'
    f3 = 'dst net 128.230.0.0/16'


    pkt1 = sniff(filter=f1, prn=print_pkt)
    pkt2 = sniff(filter=f2, prn=print_pkt)
    pkt3 = sniff(filter=f3, prn=print_pkt)


# ----- Task 1.2: Spoofing ICMP Packets -----

def q2():
    print("----- Task 1.2: Spoofing ICMP Packets -----")
    ip = IP(src='1.2.3.4', dst = '10.0.2.5')  # add dest ( send it to another VM in the same network)
    icmp = ICMP(type=0)

    pkt = ip / icmp
    pkt.show()
    send(pkt, verbose=0)


# ----- Task 1.3: Traceroute -----

#todo check what need to be done when there is no reply
def q3():
    messageReceived = False
    i = 1
    routeNum = 0
    hostName = 'google.com'
    while not messageReceived:
        print(".\n.\n")
        ip = IP(ttl=i, dst=hostName)  # add dst?
        icmp = ICMP()
        pkt = ip / icmp
        reply = sr1(pkt, verbose=0, timeout = 5)

        if reply is None:
            # no reply
            print('error. no reply received')

        #type == 0 -> (echo reply) dest reached
        elif reply.type == 0:
            print("we have reached our destination, and it only took ", routeNum, "routes")
            break

        #should be type == 11 ->  packet time to live exceeded
        else:
            print("dropped by", reply.src,"\npassed through", routeNum, "routers, reply type =", reply.type)
            routeNum += 1
        i += 1

# ----- Task 1.4: Sniffing and-then Spoofing -----

def spoof(pkt):
    #print("original ---- dst", pkt[IP].dst, " src=", pkt[IP].src)
    if ICMP in pkt and pkt[ICMP].type == 8:
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
        icmp = ICMP(type = 0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
        
        if pkt.haslayer(Raw):
            spoofedPkt = ip/icmp/pkt[Raw].load
        else:
            spoofedPkt = ip/icmp

        send(spoofedPkt)
        # check if echo reply 


def q4():
    sniff(filter='icmp', prn=spoof)



pointersDict = {1:q1A_B, 2:q2, 3:q3, 4:q4}
taskNum= input("choose task : \n task number 1.")
task = pointersDict.get(int(taskNum))

if task is not None:
    task()
else:
    print('\n no such task')