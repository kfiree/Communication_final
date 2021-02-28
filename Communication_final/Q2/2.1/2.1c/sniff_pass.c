#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <ctype.h>
//#include <netinet/tcp.h>

/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

struct tcpheader{
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seq;
  uint32_t ack;
  uint8_t  data_offset;  // 4 bits
  uint8_t  flags;
  uint16_t window_size;
  uint16_t checksum;
  uint16_t urgent_p;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{

  int i=0;
  int size_data=0;
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 

    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("         To: %s\n", inet_ntoa(ip->iph_destip));  
    
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));
      
    printf("       From: %d\n", ntohs(tcp->src_port));   
    printf("         To: %d\n", ntohs(tcp->dst_port)); 

    /* determine protocol */
    switch(ip->iph_protocol) {                                 
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            break;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            break;
        default:
            printf("   Protocol: others\n");
            break;
    }
    
    char *data = (u_char *)packet + sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct tcpheader);
    size_data = ntohs(ip->iph_len) - (sizeof(struct ipheader) + sizeof(struct tcpheader));
    
    if(size_data > 0)
    {
    	printf("   Payload(%d bytes):\n", size_data);
    	for(i=0; i<size_data; i++)
    	{
    		if(isprint(*data))
    		{
    			printf("%c", *data);
    		}
    		else{
    			printf(".");
    		}
    		data++;
    	}
    }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "proto TCP and dst portrange 10-100";
//  char filter_exp[] = "proto ICMP and (host 10.0.2.4 and 10.0.2.5)";
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
