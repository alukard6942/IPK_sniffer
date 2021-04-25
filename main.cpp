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

	Sniffer::print_all_devs();

	auto sniffer = new Sniffer("wlan0");
	
	sniffer->filter_typ("udp");
	sniffer->filter_port("22");


	auto pack = sniffer->next();

	pack.print();


}
