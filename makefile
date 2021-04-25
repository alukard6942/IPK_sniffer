
CFLAGS=-g -std=c++11 -Wall -pedantic
CC=g++

verbose: clean 
	$(CC) $(CFLAG) main.cpp sniffer.cpp sniffer.h -o ipk-sniffer -lpcap

ipk-sniffer: main.cpp sniffer.o
	$(CC) $(CFLAG) main.cpp sniffer.h -o ipk-sniffer -lpcap

sniffer.o: sniffer.cpp sniffer.h
	$(CC) $(CFLAG) -c sniffer.cpp sniffer.h -o sniffer.o -lpcap

clean:
	rm -rf ./test 
	rm -rf ./out.txt 
	rm -rf ./ipk-sniffer 
	rm -rf ./sniffer.o 


