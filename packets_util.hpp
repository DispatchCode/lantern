#ifndef PACKETS_UTIL_HPP
#define PACKETS_UTIL_HPP

#include <wx/wx.h>
#include <wx/string.h>
#include <tuple>
#include <arpa/inet.h>
#include <netdb.h>
#include <string>

#include <iostream>

#define PROTO_STR(p, pkt) \
	wxString::Format(p" (%d)", pkt.protocol);


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
		case IPPROTO_IGMP: return PROTO_STR("IGMP", pkt);
 		case IPPROTO_TCP : return PROTO_STR("TCP", pkt);
		case IPPROTO_UDP : return PROTO_STR("UDP", pkt)
		default: 		   return PROTO_STR("OTHER", pkt);
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

inline wxString pkt_igmp_get_type(struct net_packet& pkt) {
	switch(pkt.transport.igmph.type) {
		case 0x11:
			return wxT("Membership Query");
		case 0x12:
			return wxT("IGMPv1 Membership Report");
		case 0x16:
			return wxT("IGMPv2 Membership Report");
		case 0x17:
			return wxT("Leave Group");
		case 0x22:
			return wxT("IGMPv3 Membership Report");
		default:
			return wxT("invalid type");
	}
}

#endif
