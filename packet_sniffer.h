#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#define DEVICE_NAME "packet_sniffer"
#define BUFFER_SIZE  4096

#define HTTP_METHOD_SIZE 8
#define HTTP_BODY_SIZE   1024
#define HOSTNAME_SIZE    256


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
	char http_method[HTTP_METHOD_SIZE];
	char http_body[HTTP_BODY_SIZE];
	char hostname[HOSTNAME_SIZE];
	int length;
	int skb_len;
}  __attribute__ ((aligned));

#endif

