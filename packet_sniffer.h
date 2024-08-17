#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/icmp.h>
#include <linux/igmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define DEVICE_NAME "packet_sniffer"
#define BUFFER_SIZE  4096

#define HTTP_METHOD_SIZE 8
#define HTTP_BODY_SIZE   1024
#define HOSTNAME_SIZE    256

#define MASK_NETWORK  0x0000ffff
#define MASK_TRANSPORT  0xffff0000

struct net_packet {
	unsigned long timestamp_sec;
	unsigned long timestamp_nsec;

	struct ethhdr ethh;

	union {
		struct tcphdr tcph;
		struct udphdr udph;
		struct igmphdr igmph;
		
		union {
			struct icmphdr icmpv4h;
			struct icmp6hdr icmpv6h;
		} icmph;
	} transport;

	union {
		struct ipv6hdr ipv6h;
		struct iphdr ipv4h;
	} network;

	int protocol;
	int eth_protocol;
	// Not used yet
	//char http_method[HTTP_METHOD_SIZE];
	//char http_body[HTTP_BODY_SIZE];
	//char hostname[HOSTNAME_SIZE];
	int length;
	int skb_len;
	int cpu_id;
};

#endif

