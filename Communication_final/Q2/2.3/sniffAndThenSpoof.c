#include <unistd.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include "myheader.h"

// Here we will send spoofed packet that we caught from the other VM.

unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   /* treat the odd byte at the end, if any */
   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16
   sum += (sum >> 16);                  // add carry
   return (unsigned short)(~sum);
}



/* Create a raw socket with IP protocol. The IPPROTO_RAW parameter
* tells the sytem that the IP header is already included;
* this prevents the OS from adding another IP header. */

int sendSpoofedPkt(struct in_addr src, struct in_addr dst){
	int sd;
	struct sockaddr_in sin;
	char buffer[1500];
	memset(buffer, 0, 1500);
	sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(sd < 0) {
		perror("socket() error"); 
		exit(-1);
	}

	/* This data structure is needed when sending the packets
	* using sockets. Normally, we need to fill out several
	* fields, but for raw sockets, we only need to fill out
	* this one field */

	sin.sin_family = AF_INET;
	sin.sin_addr = dst;

	// Here you can construct the IP packet using buffer[]
	// - construct the IP header ...
	struct ipheader *ip = (struct ipheader *) buffer;
   	ip->iph_ver = 4;
   	ip->iph_ihl = 5;
	ip->iph_ttl = 20;
	ip->iph_sourceip = dst;
	ip->iph_destip = src;
	ip->iph_protocol = IPPROTO_ICMP;
	ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));
	
	// - construct the TCP/UDP/ICMP header ...
   	struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
   	icmp->icmp_type = 0; //ICMP Type: 8 is request, 0 is reply.

	// Calculate the checksum for integrity
	icmp->icmp_chksum = 8;
	icmp->icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(struct icmpheader));
	
	// - fill in the data part if needed ...
	// Note: you should pay attention to the network/host byte order.
	/* Send out the IP packet.
	* ip_len is the actual size of the packet. */

	if(sendto(sd, buffer, ntohs(ip->iph_len), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("sendto() error");
		exit(-1);
	}
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

    char* src = inet_ntoa(ip->iph_sourceip);
    char* dst = inet_ntoa(ip->iph_destip);
    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("         To: %s\n", inet_ntoa(ip->iph_destip));    

    /* determine protocol */
    switch(ip->iph_protocol) {                                 
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            // TODO: Here we need to send the spoofed packet we catch. (ICMP reply)
            // also, we need to get the ip src, and dest to assign to the new packet we spoofing.
            sendSpoofedPkt(ip->iph_sourceip, ip->iph_destip);
            
            return;
        default:
            printf("   Protocol: others\n");
            return;
    }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "proto ICMP";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  pcap_setfilter(handle, &fp);

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}
