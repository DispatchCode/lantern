#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <netinet/ip.h>

#include "packet_sniffer.h"

#define DEVICE_FILE "/dev/packet_sniffer"

inline static char *net_decode_protocol(uint8_t protocol) {
	switch(protocol) {
		case IPPROTO_TCP:
			return "TCP";
		case IPPROTO_UDP:
			return "UDP";
		case IPPROTO_ICMP:
			return "ICMP";
		default:
			return "unknown";
	}
}


int main() {
	int fd;
	char buffer[BUFFER_SIZE];
	ssize_t bytes_read;
	struct net_packet *packet;

	fd = open(DEVICE_FILE, O_RDONLY);
	if(fd < 0) {
		perror("Failed to open device file");
	}

	while(1) {
		bytes_read = read(fd, buffer, BUFFER_SIZE - 1);
		if(bytes_read > 0) {
			packet = (struct net_packet*) buffer;
			for(int i=0; i<bytes_read / sizeof(struct net_packet); i++) {
				printf("Packet: %s -> %s, protocol: %s, src_port: %u, dest_port: %u\n",
                       		packet[i].src, packet[i].dst, net_decode_protocol(packet[i].protocol),
                       		packet[i].src_port, packet[i].dst_port);
			}
		}
		else if(bytes_read == 0) {
			printf("No data available\n");
		}
		else {
			printf("Failed to read from device file");
			break;
		}
	}

	close(fd);

	return 0;
}

