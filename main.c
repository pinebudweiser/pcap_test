#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include "data.h"

#define NON_PROMISCUOUS 	0
#define ETH_HEADER_SIZE		14
#define TIME_OUT		0xFF
#define MAX_IP_PACKET_SIZE 	0xFFFF
#define PROTOCOL_TCP		0x6
#define ETH_IPV4		0x0800

/* prototype */
void print_mac(uint8_t*);
void print_ip(uint8_t*);
void print_port(uint16_t*);
void print_data(uint8_t*, uint8_t);

int main(int argc, char** argv)
{
	ETH* ethHeader;
	IP* ipHeader;
	TCP* tcpHeader;
	uint8_t dataBuf[16] = { 0, };
	const uint8_t ethHeaderSize = sizeof(ETH);
	uint8_t ipHeaderSize = sizeof(IP);
	uint8_t tcpHeaderSize = sizeof(TCP);
	char errBuf[PCAP_ERRBUF_SIZE] = { 0, };
	const unsigned char* pktData;
	char* interface = 0;
	struct pcap_pkthdr* pktHeader;
	pcap_t* pktDescriptor;

	if (argc != 2)
	{
		printf(" [err] Please input only one argument\n");
		return 1; 
	}

	interface = *(argv+1);
	pktDescriptor = pcap_open_live(interface, MAX_IP_PACKET_SIZE, NON_PROMISCUOUS, TIME_OUT, errBuf);

	if (!pktDescriptor)
	{
		printf(" [err] Can't open device. reason : %s\n", errBuf);
		return 1;	
	}

	while (1)
	{
		uint32_t offset = 0;
		uint32_t dataSize = 0;	

		pcap_next_ex(pktDescriptor, &pktHeader, &pktData);	
		ethHeader = (ETH*)(pktData);
		if (ntohs(ethHeader->EType) == ETH_IPV4)
		{
			offset += ethHeaderSize;
			ipHeader = (IP*)(pktData+offset);
			ipHeaderSize = ((uint8_t)(ipHeader->IHL)<<2); // Add optional Header
		}
		if (ipHeader->ProtocolID == PROTOCOL_TCP)	
		{
			offset += ipHeaderSize;
			tcpHeader = (TCP*)(pktData+offset);
			tcpHeaderSize = ((uint8_t)(tcpHeader->HeaderLength)<<2);	// Add TCP Header Length

			printf("--------------------------------------------\n");
			print_mac(ethHeader->SrcMAC);
			print_mac(ethHeader->DstMAC);
			print_ip(&(ipHeader->SrcIP));
			print_ip(&(ipHeader->DstIP));
			print_port(&(tcpHeader->SrcPort));
			print_port(&(tcpHeader->DstPort));

			offset += tcpHeaderSize;
			dataSize = (ntohs(ipHeader->TotalLength) - (offset-ETH_HEADER_SIZE));
			if (dataSize)// IS Data NULL?
			{
				print_data(&pktData+offset, dataSize);
			}
			printf("--------------------------------------------\n");
		}
	}
	return 0;
}

void print_mac(uint8_t* mac)
{
	printf(" mac : %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(uint8_t* ip)
{
	printf(" ip : %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]); 
}

void print_port(uint16_t* port)
{
	printf(" port : %d\n", ntohs(*port));
}

void print_data(uint8_t* data, uint8_t dataSize)
{
	if (dataSize > 16)
	{
		dataSize = 16;	
	}
	printf(" Data : ");
	for (int i = 0; i < dataSize; i++)
	{
		printf("%02x ", data[i]);
	}
	printf("\n");
}
