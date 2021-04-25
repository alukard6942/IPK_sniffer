#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <string>
#include <stdbool.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <iostream>

#include <pcap.h>

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

#define D_HOST_MAC_ADDR 6

/* Ethernet header */
struct sniff_ethernet {
    u_char  ether_dhost[D_HOST_MAC_ADDR]; /* destination host address */
    u_char  ether_shost;                  /* source host address */
    u_short ether_type;                   /* IP, ARP, RARP, etc */
};

/* IP header */
struct sniff_ip *ip_layer;
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

#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)

/* TCP header */
struct sniff_tcp {
    u_short th_sport;   /* source port */
    u_short th_dport;   /* destination port */
    u_int32_t th_seq;       /* sequence number */
    u_int32_t th_ack;       /* acknowledgement number */

    u_char th_offx2;    /* data offset, rsvd */
#define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;     /* window */
    u_short th_sum;     /* checksum */
    u_short th_urp;     /* urgent pointer */
};

std::string pack_header (const struct pcap_pkthdr *header,const u_char *packet) {

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
	ether_ntoa_r((struct ether_addr *)&ethernet->ether_shost, (char *) &mac_src);
	ether_ntoa_r((struct ether_addr *)&ethernet->ether_dhost, (char *) &mac_dst);
	
	if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {return "NONE";}
	
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
	ip_layer = (struct sniff_ip*)(ip_header);

    auto ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	auto size_ip = IP_HL(ip)*4;
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);

	auto src_port =std::to_string(ntohs(tcp->th_sport));
	auto dst_port =std::to_string(ntohs(tcp->th_dport));
	
	// timestamp 
	struct tm *p = localtime((const time_t*)&header->ts.tv_sec);
	char form_time[1000];
	size_t len = strftime(form_time, sizeof form_time - 1, "%FT%T%z", p);
	// move last 2 digits
	if (len > 1) {
		char minute[] = { form_time[len-2], form_time[len-1], '\0' };
		sprintf(form_time + len - 2, ":%s", minute);
	}


  	// header in format 
  	// čas IP : port > IP : port, length délka
	return std::string(form_time) + " : " + inet_ntoa(ip_layer->ip_src) + " : "+src_port+" > " + inet_ntoa(ip_layer->ip_dst) + " : "+dst_port+", length " + std::to_string(header->len); 
}

void pack_print(const u_char *packet, struct pcap_pkthdr *header);
void addexp(std::string *buffer, std::string expr);
void addport(std::string *buffer, std::string expr);
int usage();
int help();


int main(int argc, char *argv[]) {

	char *interface = NULL;
	pcap_t *handle;					/* Session handle */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;			/* The compiled filter */
	std::string filter_exp = "";
	std::string port = "";
	bpf_u_int32 mask;				/* Our netmask */
	bpf_u_int32 net;				/* Our IP */
	struct pcap_pkthdr header;		/* The header that pcap gives us */
	const u_char *packet;			/* The actual packet */
	char errBuffer[PCAP_ERRBUF_SIZE];

	int N_iter = 1;
	

	// fucking getopt is stupid and i dont want to play with it anymore
	for (int i = 1; i < argc; i++){
		char *argm = argv[i]; 

		if (!strcmp(argm, "-h") || !strcmp(argm, "--help")){
			return help();
		}
		else if (!strcmp(argm, "-i") || !strcmp(argm, "--interface")){
			// call only once
			if ( interface ) return usage(); 
			// optional argument
			if ( i+1 < argc && argv[i+1][0] != '-'){ 
				interface = argv[++i];
			}
		}
		else if (!strcmp(argm, "-t") || !strcmp(argm, "--tcp")){
			addexp(&filter_exp, "tcp");
		}
		else if (!strcmp(argm, "-u") || !strcmp(argm, "--udp")){
			addexp(&filter_exp, "udp");
		}
		else if (!strcmp(argm, "--icmp")){
			addexp(&filter_exp, "icmp");
		}
		else if (!strcmp(argm, "--arp")){
			addexp(&filter_exp, "arp");
		}
		else if (!strcmp(argm, "-n")){
			if ( i+1 < argc && argv[i+1][0] != '-'){ 

				// verbose convert str to int, very intuityve not have to look up tree time how to use much
				if (sscanf( argv[++i], "%d", &N_iter) != 1) 
					return usage(); 

			}
			else return usage();
		}
		else if (!strcmp(argm, "-p")){
			// requres argument
			if ( i+1 < argc && argv[i+1][0] != '-'){ 
				port = argv[++i];
			}
			else return usage();
		}
		else {
			return usage();
		}
	}
	if ( port.length()) addport(&filter_exp, "port " + port);

	if (!interface) {
		pcap_if_t *result;

		if(pcap_findalldevs(&result, errBuffer) == -1) {
			fprintf(stderr, "%s", errBuffer);
			exit(2);
		}
		
		pcap_if_t *dev = NULL;
		for (auto elem = result; elem; elem = elem->next) {
			printf("%s", elem->name);
			printf("\n");
		} 
		return 0;
	}

	/* Find the properties for the device */
	if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", interface, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp.c_str(), pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp.c_str(), pcap_geterr(handle));
		return(2);
	}

	for(; N_iter > 0; N_iter--){
		/* Grab a packet */
		packet = pcap_next(handle, &header);
		pack_print(packet, &header);
	
	}

	/* And close the session */
	pcap_close(handle);
	return(0);
}

char printable( char c ){

	return (c > 32 && c < 127) ? c : '.';

}

void pack_print(const u_char *packet, struct pcap_pkthdr *header){

	const int linelen = 15;

	/* Print its length */
	//auto ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    //auto tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	
	std::cout<< pack_header(header, packet) << std::endl;

	for (int i =0; i < header->len; i++){

		printf("0x%04x ",i);
		for (int l =0; l < linelen; l++){
			if (i+l < header->len)
				printf("%02x ", packet[i+l]);
			else 
				printf("   ");
		}
		printf(" ");
		for (int l =0; l < linelen && i < header->len; l++){
			int tmp = i+l < header->len ? i+l : header->len ;
			printf("%c", printable(packet[i++]));
		}
		printf("\n");
	}

}

void addexp(std::string *buffer, std::string expr){

	if (buffer->length() == 0)
		*buffer = expr;
	else 
		*buffer = "( "+expr + " or " + *buffer +" )" ;
}

void addport(std::string *buffer, std::string expr){

	if (buffer->length() == 0)
		*buffer = expr;
	else 
		*buffer += " and " + expr;
}

int usage(){
	printf("Volání programu:"
"./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num} \n");
	return 1;
}
int help(){
	usage();
	printf("kde:\n"
"-i eth0 (právě jedno rozhraní, na kterém se bude poslouchat. Nebude-li tento parametr uveden,\n"
		"\tči bude-li uvedené jen -i bez hodnoty, vypíše se seznam aktivních rozhraní)\n"
"-p 23 (bude filtrování paketů na daném rozhraní podle portu; nebude-li tento parametr uveden,\n"
		"\tuvažují se všechny porty; pokud je parametr uveden, může se daný port vyskytnout jak v source,\n" 
		"\ttak v destination části)\n"
"-t nebo --tcp (bude zobrazovat pouze TCP pakety)\n"
"-u nebo --udp (bude zobrazovat pouze UDP pakety)\n"
"--icmp (bude zobrazovat pouze ICMPv4 a ICMPv6 pakety)\n"
"--arp (bude zobrazovat pouze ARP rámce)\n"
		"\tPokud nebudou konkrétní protokoly specifikovány, uvažují se k tisknutí všechny \n"
		"\t(tj. veškerý obsah, nehledě na protokol)\n"
"-n 10 (určuje počet paketů, které se mají zobrazit; pokud není uvedeno, uvažujte zobrazení pouze jednoho paketu)\n"
		"\targumenty mohou být v libovolném pořadí\n");

return 0;
}

