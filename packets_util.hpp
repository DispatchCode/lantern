#ifndef PACKETS_UTIL_HPP
#define PACKETS_UTIL_HPP

#include <wx/wx.h>
#include <wx/string.h>
#include <tuple>

#include <arpa/inet.h>
#include <netdb.h>

#include <string>

#include <iostream>


#define NEXTHDR_ICMP  58 /* ICMP for IPv6 */


#define PROTO_STR(p, pkt) \
	wxString::Format(p" (%d)", pkt.protocol);

#define WXTREE_APPEND(tree_id, root, str, val) \
	tree_id->AppendItem(root, str, val);


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

inline std::tuple<wxString, wxString> pkt_get_eth_addr(struct net_packet& pkt) {
	wxString wxSrc, wxDst;

	wxSrc = wxString::Format("%02X:%02X:%02X:%02X:%02X:%02X",
						pkt.ethh.h_source[0], pkt.ethh.h_source[1], pkt.ethh.h_source[2],
						pkt.ethh.h_source[3], pkt.ethh.h_source[4], pkt.ethh.h_source[5]);

	wxDst = wxString::Format("%02X:%02X:%02X:%02X:%02X:%02X",
						pkt.ethh.h_dest[0], pkt.ethh.h_dest[1], pkt.ethh.h_dest[2],
						pkt.ethh.h_dest[3], pkt.ethh.h_dest[4], pkt.ethh.h_dest[5]);

	return {wxSrc, wxDst};
}

inline std::tuple<wxString, wxString> pkt_get_ips(struct net_packet& pkt) {
	char src[INET6_ADDRSTRLEN] = {0};
	char dst[INET6_ADDRSTRLEN] = {0};

	if(htons(pkt.eth_protocol) == ETH_P_IP) {
		inet_ntop(AF_INET, &pkt.network.ipv4h.saddr, src, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &pkt.network.ipv4h.daddr, dst, INET_ADDRSTRLEN);
	}
	else { // TODO if other protocols are supported, change with a switch
		inet_ntop(AF_INET6, &pkt.network.ipv6h.saddr, src, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &pkt.network.ipv6h.daddr, dst, INET6_ADDRSTRLEN);
	}

	return {wxString::FromAscii(src), wxString::FromAscii(dst)};
}

// TODO refactoring of PROTO_STR, use directly the protocol valu (?)
inline wxString pkt_get_protocol(struct net_packet& pkt) {
	switch(pkt.protocol) {
		case IPPROTO_IP  : return PROTO_STR("IPv4", pkt);
		case IPPROTO_IGMP: return PROTO_STR("IGMP", pkt);
 		case IPPROTO_TCP : return PROTO_STR("TCP", pkt);
		case IPPROTO_UDP : return PROTO_STR("UDP", pkt);
		case IPPROTO_IPV6: return PROTO_STR("IPv6", pkt);
		case NEXTHDR_ICMP: return PROTO_STR("ICMPv6", pkt);
		default: 		   return PROTO_STR("OTHER", pkt);
	}
}

inline wxString pkt_icmpv6_get_type(struct net_packet& pkt) {
	uint8_t type = pkt.transport.icmph.icmpv6h.icmp6_type;

	switch(type) {
		case 1: return wxString::Format("Destination unreachable");
		case 2: return wxString::Format("Packet too big");
		case 128: return wxString::Format("Echo Request");
		case 129: return wxString::Format("Echo Reply");
		case 135: return wxString::Format("Neighbor Solicitation");
		case 136: return wxString::Format("Neighbor Advertisement");
		default: return wxString::Format("[still unsupported, %u]", type);
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
