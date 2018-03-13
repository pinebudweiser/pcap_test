#include <stdint.h>

#define BASIC_IP_HEADER_LENGTH 	20
#define BASIC_TCP_HEADER_SUB 	13

typedef struct Ethernet{
	uint8_t DstMAC[6];
	uint8_t SrcMAC[6];
	uint16_t EType[2];
}ETH;	// DIX 2.0
typedef struct InternetProtocol{
	uint8_t VERIHL;
	uint8_t UnUse1;
	uint16_t TotalLength;
	uint32_t UnUse2;
 	uint8_t UnUse3;
	uint8_t ProtocolID;
	uint16_t UnUse4;
	uint32_t SrcIP;
	uint32_t DstIP;
	uint8_t Option[0]; // ((VERIHL&0x0F)<<2) - BASIC_IP_HEADER_LENGTH
}IP;
typedef struct TCP{
	uint16_t SrcPort;
	uint16_t DstPort;
	uint32_t UnUse1[2];
	uint8_t HeaderLength;
	uint8_t UnUse[0]; // ((HeaderLength>>4)<<2) - BASIC_TCP_HEADER_SUB
}TCP;