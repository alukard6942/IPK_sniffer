/**
 * File: main.cpp
 * Author: xkoval18 <xkoval18@github>
 * Date: 24.04.2021
 * Last Modified Date: 24.04.2021
 */

#include <iostream>
#include "sniffer.h"

using namespace std;

int main (int argc, char **argv){

	auto sniffer = new Sniffer();
	int iteratios = 1;
	bool find_only = true;
	string name; 

	for (int i = 1; i < argc; i++){
		auto ar_s = string(argv[i]);

		if ((ar_s == "-i" or ar_s == "--interface") and i+1 < argc) {
			find_only = false;
			name = string(argv[++i]);
		}
		else if ((ar_s == "-i" or ar_s == "--interface")) {
			find_only = true;
		}
		else if (ar_s == "-p" and i+1 < argc) 
			sniffer->filter_port(string(argv[++i]));
		else if (ar_s == "-t" or ar_s == "--tcp") 
			sniffer->filter_typ("tcp");
		else if (ar_s == "-u" or ar_s == "--udp") 
			sniffer->filter_typ("udp");
		else if (ar_s == "--icmp") 
			sniffer->filter_typ("icmp");
		else if (ar_s == "--arp") 
			sniffer->filter_typ("arp");
		else if (ar_s == "-n" and i+1 < argc)
			iteratios = std::stoi(argv[++i]);
		
		else {
			cerr << "invalid option" << ar_s<< endl;
			return 1;
		}
	}

	if (find_only){
		Sniffer::print_all_devs();
		return 0;
	} else {
		sniffer->set_name(name);
	}

	while (iteratios--){
		sniffer->next();

		sniffer->print();
	}
}
