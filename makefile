
CFLAGS=-g -std=c++11 -Wall -pedantic
CC=g++

verbose: clean 
	$(CC) $(CFLAG) main.cpp sniffer.cpp sniffer.h -o ipk-sniffer -lpcap

ipk-sniffer: main.cpp sniffer.o
	$(CC) $(CFLAG) main.cpp sniffer.h -o ipk-sniffer

sniffer.o: sniffer.cpp sniffer.h
	$(CC) $(CFLAG) -c sniffer.cpp sniffer.h -lpcap -o sniffer.o 

documentace.pdf: README.md
	pandoc --toc  -o documentace.pdf README.md

pack: clean documentace.pdf ipk-sniffer
	zip xkoval18.zip sniffer.h sniffer.cpp main.cpp documentace.pdf README.md


clean:
	rm -rf ./test 
	rm -rf ./out.txt 
	rm -rf ./ipk-sniffer 
	rm -rf ./sniffer.o 
	rm -rf documentace.pdf
	rm -rf output.pdf


