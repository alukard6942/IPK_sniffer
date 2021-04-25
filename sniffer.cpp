/**
This document is Copyright 2002 Tim Carstens. All rights reserved. Redistribution and use, with or without modification, are permitted provided that the following conditions are met:

Redistribution must retain the above copyright notice and this list of conditions.
The name of Tim Carstens may not be used to endorse or promote products derived from this document without specific prior written permission.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
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

Sniffer::Sniffer(){
}

// viz. https://www.tcpdump.org/pcap.html
void Sniffer::set_name(string device_name){
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

	const u_char *Packet;			/* The actual packet */
	
	packet = pcap_next(Handle, &Header);
}

string Sniffer::to_printable(){

	string out = "";

	for (int i =0; i< Header.len; i++){
		char c = packet[i];

		if (c <= 32 || c >= 126){
			out += '.';
		} else {
			out += c;
		}
	}

	return out;
}

void Sniffer::print(){

	auto printable = to_printable();


	uint32_t *ipadd = (uint32_t *)(packet + SIZE_ETHERNET);
	struct in_addr ip_addr;
    ip_addr.s_addr = *ipadd;

	// get time form sec since epoch
	struct tm *p = localtime((const time_t*)&Header.ts.tv_sec);
  	char time_s[100];
  	size_t len = strftime(time_s, sizeof time_s - 1, "%FT%T%z", p);
  	// move last 2 digits
  	if (len >= 0) {
  	  char minute[] = { time_s[len-2], time_s[len-1], '\0' };
  	  sprintf(time_s + len - 2, ":%s", minute);
  	}
	cout<<time_s<<" : "
		<< "IP : port > IP : port "
		<< "length " << Header.len << " bytes"
		<<endl;


	for (int i =0; i < Header.len; i++){

		printf("0x%04x ", i);
		int j = 0;
		for (; j < 16; j++){
			if (i+j > Header.len)
				cout<< "   ";
			else 
				printf("%02x ", packet[i+j]);
		}
		cout<<" ";

		j = 0;
		for (; j < 16; j++){
			if (i+j > Header.len)
				break;
			else 
				cout<<printable[packet[i++]];
		}

		i += j;
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


