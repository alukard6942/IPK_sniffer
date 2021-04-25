/**
 * File: sniffer.cpp
 * Author: xkoval18 <xkoval18@github>
 * Date: 24.04.2021
 * Last Modified Date: 24.04.2021
 */

#include <string>
#include <pcap.h>
#include <iostream>
#include <time.h>
#include <arpa/inet.h>
#include "sniffer.h"

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

using namespace std;


// viz. https://www.tcpdump.org/pcap.html
Sniffer::Sniffer(string device_name){
	this->Device = device_name;
	char errbuff[PCAP_ERRBUF_SIZE];
	
	if (pcap_lookupnet(Device.c_str(), &Net, &mask, errbuff) == -1) {
		cerr<< "Couldn't get netmask for device "<<Device<<": "<<errbuff<<endl;
		
		Net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	Handle = pcap_open_live(Device.c_str(), BUFSIZ, 1, 1000, errbuff);
	if (Handle == NULL) {
		cerr<<"Couldn't open device "<<Device<<": "<<errbuff<<endl;
		exit(2);
	}

	/* Compile and apply the filter */
	struct bpf_program fp;	/* The compiled filter */
	if (pcap_compile(Handle, &fp, filters().c_str(), 0, Net) == -1) {
		cerr<<"Couldn't parse filter "<<filters()<<": "<<pcap_geterr(Handle)<<endl;
		exit(2);
	}
	if (pcap_setfilter(Handle, &fp) == -1) {
		cerr<<"Couldn't install filter "<<filters()<<": "<<pcap_geterr(Handle)<<endl;
		exit(2);
	}
}

void Sniffer::print_all_devs(){
	pcap_if_t *result;
	char errbuff[PCAP_ERRBUF_SIZE];

	if(pcap_findalldevs(&result, errbuff) == -1) {
		fprintf(stderr, "%s", errbuff);
		exit(2);
	}
	
	pcap_if_t *dev = NULL;
	for (auto elem = result; elem; elem = elem->next) {
		cout<<elem->name<<endl;;
	} 
}

// the main sniffing fc
void Sniffer::next(){

	DBG( filters() );

	const u_char *Packet;			/* The actual packet */
	
	Packet = pcap_next(Handle, &Header);
}

string Sniffer::to_printable(){

	string out = "";

	for (int i =0; i< Header.len; i++){
		char c = packet[i];

		if (c <= 32 || c >= 127){
			out += '.';
		} else {
			out += c;
		}
	}

	return out;
}

void Sniffer::print(){
	static int iter = 0;
	static int linelen = 20;

	auto printable = to_printable();

	// header
	printf("%d. len:[%d]\n", Header.len);

	uint32_t *ipadd = (uint32_t *)(packet + SIZE_ETHERNET);
	struct in_addr ip_addr;
    ip_addr.s_addr = *ipadd;
	auto fromadd = inet_ntoa(*ip_addr);


	// time viz stack
	struct tm *p = localtime((const time_t*)&Header.ts.tv_sec);
  	char form_time[100];
  	size_t len = strftime(form_time, sizeof form_time - 1, "%FT%T%z", p);
  	// move last 2 digits
  	if (len > 1) {
  	  char minute[] = { form_time[len-2], form_time[len-1], '\0' };
  	  sprintf(form_time + len - 2, ":%s", minute);
  	}
	cout<<form_time<<" "
		<<fromadd<<  " "
		<<endl;



	// lined packet
	for (int i =0; i < Header.len; i++){

		for (int l =0; l < linelen; l++){
			if (i+l < Header.len)
				// formated
				printf("%3x", packet[i+l]);
			else 
				cout<< "   ";
		}
		cout<<" ";

		// can end befor line
		for (int l =0; l < linelen && i < Header.len; l++){
			cout<<printable[packet[i++]];
		}
		cout<<endl;
	}

}


void Sniffer::filter_typ (string expr){
	auto len = Filters_type.length();
	if (!len){
		Filters_type += expr; 
	} else {
		Filters_type += " or " + expr; 
	}
}
void Sniffer::filter_port(string expr){
	this->Filters_port = "port " + expr;
}
void Sniffer::filter_clean(){
	this->Filters_port = "";
	this->Filters_type = "";
}
string Sniffer::filters(){
	auto len = Filters_port.length();

	string out =  "";

	// just filters
	if (!Filters_port.length()){
		return Filters_type;
	} 
	// both
	else if (this->Filters_type.length()){
		return "("+Filters_type+") and "+Filters_port;
	}
	// just port
	else {
		return Filters_port;
	}
}


