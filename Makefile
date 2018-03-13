all: pcap_test

pcap_test : main.o
		gcc -g -o pcap_test main.o -lpcap
main.o : main.c data.h
		gcc -g -c -o main.o main.c
clean:
	rm -rf pcap_test
	rm -rf *.o
