#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#define DEVICE_NAME "packet_sniffer"
#define BUFFER_SIZE  4096
#define IP_BUFF_SIZE 16

struct net_packet {
	char src[IP_BUFF_SIZE];
	char dst[IP_BUFF_SIZE];
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t protocol;
}  __attribute__ ((aligned));

#endif

