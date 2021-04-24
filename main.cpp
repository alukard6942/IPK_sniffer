#include <stdio.h>
#include <pcap.h>
#include <getopt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>

void pack_print(const u_char *packet, struct pcap_pkthdr *header);
void addexp(std::string *buffer, std::string expr);
void addport(std::string *buffer, std::string expr);
int usage();
int help();


int main(int argc, char *argv[]) {

	char *interface = NULL;
	pcap_t *handle;					/* Session handle */
	char *dev;						/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;			/* The compiled filter */
	std::string filter_exp = "";
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
				addport(&filter_exp, "port " + std::string(argv[++i]));
			}
			else return usage();
		}
		else {
			return usage();
		}
	}

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
		return 0;
		} 
	}

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
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

	static int iter = 0;
	static int linelen = 20;

	/* Print its length */
	printf("%d. len:[%d]\n", header->len);

	for (int i =0; i < header->len; i++){

		for (int l =0; l < linelen; l++){
			if (i+l < header->len)
				printf("%3x", packet[i+l]);
			else 
				printf("   ");
		}
		printf("  ");
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
		*buffer += " or " + expr;
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

