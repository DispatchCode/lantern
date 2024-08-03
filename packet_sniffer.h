#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#define DEVICE_NAME "packet_sniffer"
#define BUFFER_SIZE  4096

// Generic buffer size
#define NETWORK_LAYER    40
#define TRANSPORT_LAYER  40

#define MASK_NETWORK  0x0000ffff
#define MASK_TRANSPORT  0xffff0000

struct net_packet {
	unsigned long timestamp_sec;
	unsigned long timestamp_nsec;
	char network[40];
	char transport[40];

	int protocol;
}  __attribute__ ((aligned));

#endif

