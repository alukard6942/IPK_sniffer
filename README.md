# IPK_sniffer
> 2. projekt do IPK sniffer packetu.
> použitý jazik c++
> dependence: libpcap-dev



## 1.0 uvod do problematiky
Za pomocí knihovny pcap program ipk-sniffer zachytává síťové pakety.

## 2.0 implemetace 
Trída sniffer která umožnuje zachytávání packetů a jejich formatovaný výtisk.

### 2.1 Sniffer( string device_name )
Constructor objektu Sniffer, umožnuje zachytávání packetů nad rozhraním "device_name".

### 2.2 print_all_dev() 
Statická třídní funkce pro vytisknutí všech dostupných rozhraní.

### 2.3 next()
Posune hlavu Snifferu na další packet.

### 2.4 print()
Vytiskne formatovanou reprezentaci packetu.

## použité zdroje

Programming with pcap [online]. The Tcpdump Group., 2002 [cit. 2021-4-25]. Dostupné z: https://www.tcpdump.org/pcap.html
