
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

//#include <sys/socket.h>
//#include <netinet/in.h>
#include <arpa/inet.h>
//#include <netinet/if_ether.h>
//#include <net/ethernet.h>
#include <netinet/ether.h>
//#include <netinet/ip.h>

#include <pcap.h>

/*
 * COMPILATION: gcc -Wall ip_addr.c -o ips -lpcap
 *
 * Combine with WHOIS:
 * for ip in $(./ips pcap_file.pcapng | sort | uniq); do echo $ip $(whois $ip | grep OrgName); done
 *
 * BASIC USAGE: ./ips pcap_file.pcapng | sort | uniq
 *
 * Most of this code is from Cedric Olivero: https://github.com/CedricOL07/p2a
 */

#define D_HOST_MAC_ADDR 6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[D_HOST_MAC_ADDR]; /* destination host address */
        u_char  ether_shost;                  /* source host address */
        u_short ether_type;                   /* IP, ARP, RARP, etc */
};

/* IP header */
const struct sniff_ip *ip_layer;
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

void packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet);

int main(int argc, char **argv) {
  fflush(stdin);
  char errbuf[PCAP_ERRBUF_SIZE];
  if (argc!=2) {
    printf("Usage: ./ips pcap_file.pcapng\n");
    exit(1);
  }
  if (access(argv[1], F_OK)!=0) {
    printf("Usage: ./ips pcap_file.pcapng\n");
    exit(1);
  }
  pcap_t *handle = pcap_open_offline(argv[1], errbuf); // retrieve PCAP file passed as argument
  if(handle == NULL){
    printf("[ERROR] %s\n", errbuf);
    exit(1);
  }
  pcap_loop(handle, 0, packet_handler, NULL); // int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
  return 0;
}

void packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet) {
  /*Pointers to initialze the structures*/
  const struct ether_header *eth_header;
  const struct sniff_ethernet *ethernet;
const struct sniff_tcp *tcp; /* The TCP header */
  /* Pointers to start point of various headers */
  const u_char *ip_header;
  //const u_char *udp_header;
  /* Variables indicating the length of a packet part*/
  int ethernet_header_length;
  int ip_header_length;
  int length_ip;
  /* initiate new arrays for MAC/IP addresses */
  char mac_src[20], mac_dst[20];
  char ip_src[20], ip_dst[20];
  /* Packet nbr info */

  // Get Ethernet packet
  eth_header = (struct ether_header *) (packet);
  ethernet = (struct sniff_ethernet*)(packet);

  // Recover MAC addresses.
  ether_ntoa_r(&ethernet->ether_shost, &mac_src);
  ether_ntoa_r(&ethernet->ether_dhost, &mac_dst);

  if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {return;}

  /* Header lengths in bytes */
  ethernet_header_length = 14;
  // Find start of IP header.
  ip_header = packet + ethernet_header_length;
  /* The second-half of the first byte in ip_header
     contains the IP header length (IHL). */
  ip_header_length = ((*ip_header) & 0x0F);
  /* The IHL is number of 32-bit segments. Multiply
     by four to get a byte count for pointer arithmetic */
  ip_header_length *= 4;
  ip_layer = (struct ip_layer*)(ip_header);

  // Recover IP addresses.
  printf("%s\n", inet_ntoa(ip_layer->ip_src));
  printf("%s\n", inet_ntoa(ip_layer->ip_dst));
}
