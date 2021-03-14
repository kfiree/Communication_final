#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include "myheader.h"

unsigned short in_cksum (unsigned short *buf, int length);

/* Create a raw socket with IP protocol. The IPPROTO_RAW parameter
* tells the sytem that the IP header is already included;
* this prevents the OS from adding another IP header. */
int main(){
	int sd;
	struct sockaddr_in sin;
	char buffer[1500];
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

	// Here you can construct the IP packet using buffer[]
	// - construct the IP header ...
	struct ipheader *ip = (struct ipheader *) buffer;
   	ip->iph_ver = 4;
   	ip->iph_ihl = 5;
	ip->iph_ttl = 20;
	ip->iph_sourceip.s_addr = inet_addr("127.0.0.53");
	ip->iph_destip.s_addr = inet_addr("10.0.2.5");
	ip->iph_protocol = IPPROTO_ICMP;
	ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));
	
	// - construct the TCP/UDP/ICMP header ...
   	struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
   	icmp->icmp_type = 8; //ICMP Type: 8 is request, 0 is reply.

	
	icmp->icmp_chksum = 0;
	//icmp->icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(struct icmpheader));
	

	/* Send out the IP packet.
	* ip_len is the actual size of the packet. */

	if(sendto(sd, buffer, ip->iph_len, 0, (struct sockaddr *)&sin,sizeof(sin)) < 0) {
		perror("sendto() error");
		exit(-1);
	}
}
