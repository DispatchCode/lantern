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

inline std::tuple<wxString, wxString> pkt_get_ips(struct net_packet& pkt) {
	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];

	if(pkt.network.ipv4h.version == 4) {
		inet_ntop(AF_INET, &pkt.network.ipv4h.saddr, src, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &pkt.network.ipv4h.daddr, dst, INET_ADDRSTRLEN);
	}
	else {
		inet_ntop(AF_INET6, &pkt.network.ipv6h.saddr, src, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &pkt.network.ipv6h.daddr, dst, INET6_ADDRSTRLEN);
	}

	return {wxString::FromAscii(src), wxString::FromAscii(dst)};
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
	wxString src_port = wxT(""), dst_port = wxT("");

	if(pkt.protocol == IPPROTO_TCP) {
		src_port << pkt.transport.tcph.source;
		dst_port << pkt.transport.tcph.dest;
	}

	if(pkt.protocol == IPPROTO_UDP) {
		src_port << pkt.transport.udph.source;
		dst_port << pkt.transport.udph.dest;
	}

	return {src_port, dst_port};
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
