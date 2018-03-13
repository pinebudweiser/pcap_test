#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include "data.h"

#define MAX_IP_PACKET_SIZE 	0xFFFF
#define NON_PROMISCUOUS 	0x0
#define TIME_OUT		0xFF

void print_mac(uint8_t* arr)
{
	printf("%x:%x:%x:%x:%x:%x\n", arr[0], arr[1], arr[2], arr[3], arr[4], arr[5]);	
}

int main(int argc, char** argv)
{

	char* interface = *(argv+1);
	char errBuf[PCAP_ERRBUF_SIZE] = { 0, };
	const unsigned char* pkt_data = 0;
	struct pcap_pkthdr* pkt_header = 0;
	ETH e1_test;
	pcap_t* pcDescriptor = 0;

	if (argc != 2)
	{
		printf("[err] Please input only one argument\n");
		return 1; 
	}
	
	pcDescriptor = pcap_open_live(interface, MAX_IP_PACKET_SIZE, NON_PROMISCUOUS, TIME_OUT, errBuf);

	if (!pcDescriptor)
	{
		printf("[err] Can't open device. reason : %s\n", errBuf);
		return 1;	
	}
	while(1)
	{
		pcap_next_ex(pcDescriptor, &pkt_header, &pkt_data);
		memcpy(&e1_test, pkt_data, sizeof(e1_test));
		print_mac(e1_test.DstMAC);
	}

	return 0;
}
