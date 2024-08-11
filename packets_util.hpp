#ifndef PACKETS_UTIL_HPP
#define PACKETS_UTIL_HPP

#include <wx/wx.h>
#include <wx/string.h>
#include <tuple>
#include <arpa/inet.h>
#include <netdb.h>
#include <string>

#include <iostream>

inline wxString pkt_get_cpuid(struct net_packet& pkt) {
	wxString cpuid_str;
	cpuid_str << pkt.cpu_id;
	return cpuid_str;
}

inline wxString pkt_get_len(struct net_packet& pkt) {
	wxString skb_len_str;
	skb_len_str << pkt.skb_len;
	return skb_len_str;
}

inline wxString pkt_ip2str(struct net_packet& pkt, int is_src) {
	char ip[INET6_ADDRSTRLEN];
	if(pkt.network.ipv4h.version == 4) {
		inet_ntop(AF_INET, is_src ? &pkt.network.ipv4h.saddr : &pkt.network.ipv4h.daddr, ip, INET_ADDRSTRLEN);
	}
	else {
		inet_ntop(AF_INET6, is_src ? &pkt.network.ipv6h.saddr :  &pkt.network.ipv6h.daddr, ip, INET6_ADDRSTRLEN);
	}

	return wxString::FromAscii(ip);
}

inline wxString pkt_get_protocol(struct net_packet& pkt) {
	switch(pkt.protocol) {
 		case IPPROTO_TCP : return wxString("TCP");
		case IPPROTO_UDP : return wxString("UDP");
		default: return wxString("OTHER");
	}
}

inline wxString pkt_get_time(struct net_packet& pkt) {
	time_t timestamp = static_cast<time_t>(pkt.timestamp_sec);
	struct tm *tm_info = localtime(&timestamp);
	char time_buf[64];
	strftime(time_buf, sizeof(time_buf), "%d/%m/%Y %H:%M:%S", tm_info);
	return wxString::Format("%s.%03lu", time_buf, pkt.timestamp_nsec / 1000000);
}

inline std::tuple<wxString, wxString> pkt_get_ports(struct net_packet& pkt) {
	wxString src_port, dst_port;

	if(pkt.protocol == IPPROTO_TCP) {
		src_port << pkt.transport.tcph.source;
		dst_port << pkt.transport.tcph.dest;
		return {src_port, dst_port};
	}

	if(pkt.protocol == IPPROTO_UDP) {
		src_port << pkt.transport.udph.source;
		dst_port << pkt.transport.udph.dest;
		return {src_port, dst_port};
	}

	return {wxT(""), wxT("")};
}

#endif
