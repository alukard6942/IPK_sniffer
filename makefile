
CFLAG=-std=c++11
CC=g++

ipk-sniffer: ./main.cpp
	$(CC) $(CFLAG) main.cpp -lpcap -o ipk-sniffer

clean:
	rm -rf 	./test ./out.txt ./ipk-sniffer 


