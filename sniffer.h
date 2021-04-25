/**
 * File: sniffer.h
 * Author: xkoval18 <xkoval18@github>
 * Date: 24.04.2021
 * Last Modified Date: 24.04.2021
 */

#include <string>
#include <pcap.h>



#define DBG(val) cerr<<__LINE__<<": "<<val<<endl;

using namespace std;

class Sniffer {
	public:
		Sniffer();
		~Sniffer();
		void set_name(string device_name);

		void filter_typ (string expr);
		void filter_port(string expr);
		void filter_clean();

		static
		void print_all_devs();

		void next();
		void print();
		string to_printable();

	private:
		string filters();

		string Device;
		pcap_t *Handle;					/* Session handle */

		string Filters_type = "";
		string Filters_port = "";
		bpf_u_int32 mask;
		bpf_u_int32 Net;
		const u_char * packet;
		struct pcap_pkthdr Header;		/* The header that pcap gives us */
		//struct pcap_pkthdr header;
};
