#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <string.h>
#include <time.h>
#include "packet_sniffer.h"

#define DEVICE_FILE "/dev/packet_sniffer"

void print_packet_info(struct net_packet *pkt);


int main() {
    char buffer[BUFFER_SIZE] = {0};
	int fd = open(DEVICE_FILE, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open device file");
        return EXIT_FAILURE;
    }

	struct net_packet *pkt;
	while(1) {
    	ssize_t bytes_read = read(fd, buffer, BUFFER_SIZE-1);

		printf("bytes_read: %d\n", bytes_read);
    	if (bytes_read < 0) {
    	    perror("Failed to read from device file");
    	} else if (bytes_read == 0) {
    	    printf("No data available\n");
    	} else {
			for(int i=0; i<bytes_read / sizeof(struct net_packet); i++) {
				pkt = (struct net_packet*) buffer;
    			print_packet_info(pkt);
			}
		}
	}

    close(fd);
    return EXIT_SUCCESS;
}

void print_packet_info(struct net_packet *pkt) {
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
    char time_buff[64];
    struct tm *tm_info;
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct udphdr *udp;

	ip = (struct iphdr*) pkt->network;

    inet_ntop(AF_INET, &ip->saddr, src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip->daddr, dst, INET_ADDRSTRLEN);

    tm_info = localtime((time_t*)&pkt->timestamp_sec);
    strftime(time_buff, sizeof(time_buff), "%d/%m/%Y %H:%M:%S", tm_info);

    printf("Timestamp: %s.%03lu\n", time_buff, pkt->timestamp_nsec);
    printf("Source IP: %s\n", src);
    printf("Destination IP: %s\n", dst);
    printf("Protocol: %s\n", ip->protocol == IPPROTO_TCP ? "TCP" : 
                                ip->protocol == IPPROTO_UDP ? "UDP" : 
                                "Other");

    if (ip->protocol == IPPROTO_TCP) {
		tcp = (struct tcphdr*) pkt->transport;
        printf("Source Port: %u\n", ntohs(tcp->source));
        printf("Destination Port: %u\n", ntohs(tcp->dest));
    } else if (ip->protocol == IPPROTO_UDP) {
		udp = (struct udphdr*) pkt->transport;
        printf("Source Port: %u\n", ntohs(udp->source));
        printf("Destination Port: %u\n", ntohs(udp->dest));
    }
}

