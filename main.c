#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include "data.h"

#define NON_PROMISCUOUS 	0x0
#define ETH_HEADER_SIZE		0xE
#define TIME_OUT		0xFF
#define MAX_IP_PACKET_SIZE 	0xFFFF
#define PROTOCOL_TCP		0x6

void print_mac(uint8_t* mac1, uint8_t* mac2)
{
	printf("src mac : %02x:%02x:%02x:%02x:%02x:%02x\n", mac1[0], mac1[1], mac1[2], mac1[3], mac1[4], mac1[5]);
	printf("dst mac : %02x:%02x:%02x:%02x:%02x:%02x\n", mac2[0], mac2[1], mac2[2], mac2[3], mac2[4], mac2[5]);
}
void print_ip(uint32_t* ip1, uint32_t* ip2)
{
	uint8_t* byteIP1 = (uint8_t*)ip1;
	uint8_t* byteIP2 = (uint8_t*)ip2;

	printf("src ip : %d.%d.%d.%d\n", byteIP1[0], byteIP1[1], byteIP1[2], byteIP1[3]); 
	printf("dst ip : %d.%d.%d.%d\n", byteIP2[0], byteIP2[1], byteIP2[2], byteIP2[3]);
}
void print_port(uint16_t port1, uint16_t port2)
{
	port1 = ntohs(port1);
	port2 = ntohs(port2);

	printf("src port : %d\n", port1);
	printf("dst port : %d\n", port2);
}

int main(int argc, char** argv)
{
	ETH etherHeader;
	IP ipHeader;
	TCP tcpHeader;
	char errBuf[PCAP_ERRBUF_SIZE] = { 0, };
	char* interface = *(argv+1);
	const unsigned char* pktData = 0;
	pcap_t* pktDescriptor = 0;
	struct pcap_pkthdr* pktHeader = 0;
	const uint8_t ethHeaderSize = sizeof(etherHeader);
	uint8_t ipHeaderSize = sizeof(ipHeader);
	uint8_t tcpHeaderSize = sizeof(tcpHeader);

	if (argc != 2)
	{
		printf("[err] Please input only one argument\n");
		return 1; 
	}
	
	pktDescriptor = pcap_open_live(interface, MAX_IP_PACKET_SIZE, NON_PROMISCUOUS, TIME_OUT, errBuf);

	if (!pktDescriptor)
	{
		printf("[err] Can't open device. reason : %s\n", errBuf);
		return 1;	
	}

	while (1)
	{
		uint32_t offset = 0;
		char dataBuf[16] = { 0, };

		pcap_next_ex(pktDescriptor, &pktHeader, &pktData);
		memcpy(&etherHeader, &pktData[offset], ethHeaderSize);
		if (ntohs(etherHeader.EType) == 0x0800)
		{
			offset += ethHeaderSize;
			memcpy(&ipHeader, &pktData[offset], ipHeaderSize);
			ipHeaderSize += (((ipHeader.VERIHL&0x0F)<<2) - BASIC_IP_HEADER_LENGTH); // Add optional Header
			offset += ipHeaderSize;
		}
		if (ipHeader.ProtocolID == PROTOCOL_TCP)	
		{
			memcpy(&tcpHeader, &pktData[offset], tcpHeaderSize);	
			offset += ((tcpHeader.HeaderLength>>4)<<2);	// Add TCP Header Length

			print_mac(etherHeader.SrcMAC, etherHeader.DstMAC);
			print_ip(&ipHeader.SrcIP, &ipHeader.DstIP);
			print_port(tcpHeader.SrcPort, tcpHeader.DstPort);

			if ( ntohs(ipHeader.TotalLength) != (offset - ETH_HEADER_SIZE) )	// IS Data NULL?
			{
				memcpy(dataBuf, &pktData[offset], 16);
				printf("DATA : %s\n", dataBuf);
			}
		}
	}
	return 0;
}
