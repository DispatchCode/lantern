#include "read_packets.hpp"
#include "packet_sniffer.h"
#include "packets_util.hpp"

#include <iostream>

#define DEVICE_FILE "/dev/packet_sniffer"
#define PKTS_BATCH 50

#define ID_BLOCK_SRC 0x1122
#define ID_BLOCK_DST 0x1123

inline wxColour color_by_protocol(int protocol) {
	switch(protocol) {

		case IPPROTO_TCP:
			return wxColour(203, 245, 221);
		case IPPROTO_UDP:
			return wxColour(213, 255, 255);
    }

	return wxColour(255,255,255);
}

bool PacketReader::OnInit()
{
	PacketReaderWindow *window = new PacketReaderWindow(wxT("Packet sniffer"));
	window->SetSize(wxSize(1920, 1080));
	window->SetAutoLayout(true);
	window->Show(true);
	return true;
}

void PacketReaderWindow::OnAbout(wxCommandEvent& event)
{
	wxString msg;
	msg.Printf(wxT("Packet sniffer and analyser"));

	wxMessageBox(msg, wxT("About"), wxOK | wxICON_INFORMATION, this);	
}

void PacketReaderWindow::OnQuit(wxCommandEvent& event)
{	
	running = false;
	Close(true);
}


void PacketReaderWindow::OnPopupClick(wxCommandEvent& event)
{
	struct net_packet pkt;
	void *data = static_cast<wxMenu*>(event.GetEventObject())->GetClientData();
	int index = static_cast<int>(reinterpret_cast<std::intptr_t>(data));

	if(index > packets.size()) 
		return;

	{
		std::unique_lock<std::mutex> lock(packetMutex);
		pkt = packets[index];
	}

	auto [src, dst] = pkt_get_ips(pkt);

	switch(event.GetId()) {
		case ID_BLOCK_SRC:
			wxMessageBox(wxString::Format("Block source: %s", src), wxT("Ban address"), wxOK | wxICON_INFORMATION, this);
		break;
		case ID_BLOCK_DST:
			wxMessageBox(wxString::Format("Block destination: %s", dst), wxT("Ban address"), wxOK | wxICON_INFORMATION, this);
		break;
	}
}

void PacketReaderWindow::ShowContextMenu(wxListEvent& event)
{
	int index = event.GetItem();
	void *data = reinterpret_cast<void*>(index);
	wxMenu popup;
	popup.SetClientData(data);
	popup.Append(ID_BLOCK_SRC, "Ban source IP");
	popup.Append(ID_BLOCK_DST, "Ban destination IP");
	popup.Connect(wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler(PacketReaderWindow::OnPopupClick), NULL, this);
	PopupMenu(&popup);
}

void PacketReaderWindow::OnMouseDownEvent(wxListEvent& event)
{
	wxMouseState mouseState = wxGetMouseState();
	if(mouseState.RightIsDown()) {
		return;
	}

	struct net_packet pkt;
	int index = event.GetItem();

	if(index < packets.size())
	{
		{
			std::unique_lock<std::mutex> lock(packetMutex);
			pkt = packets[index];
		}

		detailsTree->DeleteAllItems();
		
		auto [eth_src, eth_dst] = pkt_get_eth_addr(pkt);
		wxTreeItemId eth_root = detailsTree->AddRoot("Ethernet Frame");
		detailsTree->AppendItem(eth_root, wxString::Format("Source: %s",  eth_src));
		detailsTree->AppendItem(eth_root, wxString::Format("Destination: %s", eth_dst));
		detailsTree->AppendItem(eth_root, wxString::Format("Transport Protocol: %s", pkt_get_protocol(pkt)));

		detailsTree->Expand(eth_root);
	
		wxTreeItemId ip;
		auto [src, dst] = pkt_get_ips(pkt);

		switch(htons(pkt.eth_protocol)) {
			case ETH_P_IP: {
				ip = detailsTree->InsertItem(eth_root, 3, "IPv4 Header");
				detailsTree->AppendItem(ip, wxString::Format("src: %s", src));
				detailsTree->AppendItem(ip, wxString::Format("dest: %s", dst));
				detailsTree->AppendItem(ip, wxString::Format("TOS: %u", pkt.network.ipv4h.tos));
				detailsTree->AppendItem(ip, wxString::Format("TTL: %u", pkt.network.ipv4h.ttl));				

				detailsTree->Expand(ip);
				break;
			}
			case ETH_P_IPV6: {
				ip = detailsTree->InsertItem(eth_root, 3, "IPv6 Header");
				detailsTree->AppendItem(ip, wxString::Format("src: %s", src));
				detailsTree->AppendItem(ip, wxString::Format("dest: %s", dst));
				detailsTree->AppendItem(ip, wxString::Format("payload len: %u", pkt.network.ipv6h.payload_len));
				detailsTree->AppendItem(ip, wxString::Format("hop limit: %u", pkt.network.ipv6h.hop_limit));

				detailsTree->Expand(ip);
				break;			
			}
		}

		switch(pkt.protocol) {
			case NEXTHDR_ICMP: {
				wxTreeItemId icmp = detailsTree->InsertItem(ip, 4, "ICMPv6 Header");
				detailsTree->AppendItem(icmp, wxString::Format("Type: %s", pkt_icmpv6_get_type(pkt)));
				detailsTree->AppendItem(icmp, wxString::Format("Sequence: %u", pkt.transport.icmph.icmpv6h.icmp6_dataun.u_echo.sequence));

				detailsTree->Expand(icmp);
			break;
			}
			case IPPROTO_TCP: {
				wxTreeItemId root = detailsTree->InsertItem(ip, 4, "TCP Header");
				detailsTree->AppendItem(root, wxString::Format("src port: %u", pkt.transport.tcph.source));
				detailsTree->AppendItem(root, wxString::Format("dst port: %u", pkt.transport.tcph.dest));
				detailsTree->AppendItem(root, wxString::Format("seq: %u", ntohl(pkt.transport.tcph.seq)));
				detailsTree->AppendItem(root, wxString::Format("ack_seq: %u", ntohl(pkt.transport.tcph.ack_seq)));
				detailsTree->AppendItem(root, wxString::Format("check: %u", ntohs(pkt.transport.tcph.check)));

				wxTreeItemId flags = detailsTree->InsertItem(root, 4, "Flags");
				detailsTree->AppendItem(flags, wxString::Format("doff: %u", pkt.transport.tcph.doff << 2));
				detailsTree->AppendItem(flags, wxString::Format("fin: %u", pkt.transport.tcph.fin));
				detailsTree->AppendItem(flags, wxString::Format("syn: %u", pkt.transport.tcph.syn));
				detailsTree->AppendItem(flags, wxString::Format("rst: %u", pkt.transport.tcph.rst));
				detailsTree->AppendItem(flags, wxString::Format("ack: %u", pkt.transport.tcph.ack));

				detailsTree->Expand(root);
				break;
			}
			case IPPROTO_UDP: {
				wxTreeItemId root = detailsTree->InsertItem(eth_root, 4, "UDP Header");
				detailsTree->AppendItem(root, wxString::Format("src port: %u", pkt.transport.udph.source));
				detailsTree->AppendItem(root, wxString::Format("dst port: %u", pkt.transport.udph.dest));
				detailsTree->AppendItem(root, wxString::Format("len: %u", ntohs(pkt.transport.udph.len)));
				detailsTree->AppendItem(root, wxString::Format("check: %u", ntohs(pkt.transport.udph.check)));

				detailsTree->Expand(root);
				break;
			}
			case IPPROTO_IGMP:{
				wxTreeItemId root = detailsTree->InsertItem(eth_root, 4, "IGMP Header");
				detailsTree->AppendItem(root, wxString::Format("type: %s", pkt_igmp_get_type(pkt)));

				detailsTree->Expand(root);
				break;
			}
		}		
	}
}

void PacketReaderWindow::StartPacketReader()
{
	running = true;

	readerThread = std::thread([this]() {
		int fd = open(DEVICE_FILE, O_RDONLY);
		if(fd < 0) {
			wxMessageBox("Failed to open device file", "Error", wxICON_ERROR);
			return;
		}
		
		while(running)
		{
			struct net_packet pkts[PKTS_BATCH] = {0};
			ssize_t bytes_read = read(fd, pkts, sizeof(struct net_packet) * PKTS_BATCH);
			if(bytes_read > 0) {
				int num_packets = bytes_read / sizeof(struct net_packet);
				
				std::thread([this, pkts, num_packets]() {
					std::scoped_lock lock(packetMutex, queueMutex);
				
					for(int i=0; i < num_packets; i++) {
						packets.emplace_back(pkts[i]);
						incomingPackets.emplace(pkts[i]);
					}
				}).detach();
		
				wxThreadEvent event(wxEVT_THREAD, wxID_ANY);
				wxQueueEvent(this, event.Clone());
			
			}
		}
		close(fd);
	});

	Bind(wxEVT_THREAD, [this](wxThreadEvent&) {
		struct net_packet pkt;	
		int itemCount;

		{	
			std::scoped_lock lock(queueMutex);
			if(incomingPackets.empty()) return;
			
			pkt = incomingPackets.front();
			incomingPackets.pop();
			itemCount = pktList->GetItemCount();
		}

		wxString cpuid_str   = pkt_get_cpuid(pkt);
 		wxString skb_len_str = pkt_get_len(pkt);
		wxString protocol 	 = pkt_get_protocol(pkt);;
		wxString timestamp 	 = pkt_get_time(pkt);
		auto [src, dst] 	 = pkt_get_ips(pkt);
		auto [src_port, dst_port] = pkt_get_ports(pkt);

		long index = pktList->InsertItem(itemCount, wxString::Format("%d", itemCount+1));
		pktList->SetItem(index, 1, cpuid_str);
		pktList->SetItem(index, 2, src);
		pktList->SetItem(index, 3, src_port);
		pktList->SetItem(index, 4, dst);
		pktList->SetItem(index, 5, dst_port);
		pktList->SetItem(index, 6, timestamp);
		pktList->SetItem(index, 7, protocol);
		pktList->SetItem(index, 8, skb_len_str);
		
		pktList->SetItemBackgroundColour(index, color_by_protocol(pkt.protocol));
	});
} 

PacketReaderWindow::~PacketReaderWindow() {
	running = false;
	if (readerThread.joinable()) {
		readerThread.join();
	}
}

PacketReaderWindow::PacketReaderWindow(const wxString& title) : wxFrame(NULL, wxID_ANY, title)
{
	/* MENU */
	wxMenu *fileMenu = new wxMenu;
	wxMenu *helpMenu = new wxMenu;

	helpMenu->Append(wxID_ABOUT, wxT("&About...\tF1"), wxT("Show About dialog"));
	fileMenu->Append(wxID_EXIT, wxT("E&xit\tAlt-X"), wxT("Quit this program"));

	wxMenuBar *menuBar = new wxMenuBar;
	menuBar->Append(fileMenu, wxT("&File"));
	menuBar->Append(helpMenu, wxT("&Help"));

	SetMenuBar(menuBar);
	
	/* STATUS BAR */
	CreateStatusBar(2);
	SetStatusText(wxT("Packet Sniffer"));

	/* WINDOW CONTENT */
	wxBoxSizer *contSizer = new wxBoxSizer(wxVERTICAL);

	wxSplitterWindow *splitter = new wxSplitterWindow(this, wxID_ANY);
	
	// packet and detail panels
	wxPanel *packetsPanel = new wxPanel(splitter, wxID_ANY, wxDefaultPosition, GetSize());
	wxPanel *detailsPanel = new wxPanel(splitter, wxID_ANY);	

	// top panel used to show packets
	pktList = new wxListCtrl(packetsPanel, wxID_ANY, wxDefaultPosition, wxSize(GetSize().GetWidth(), -1), wxLC_REPORT | wxLC_SINGLE_SEL | wxBORDER_SUNKEN);
	pktList->InsertColumn(0, "Pkt #", wxLIST_FORMAT_LEFT);
	pktList->InsertColumn(1, "CPU #", wxLIST_FORMAT_LEFT);	
	pktList->InsertColumn(2, "Source IP", wxLIST_FORMAT_LEFT, 300);
	pktList->InsertColumn(3, "Port", wxLIST_FORMAT_LEFT);
	pktList->InsertColumn(4, "Destination IP", wxLIST_FORMAT_LEFT, 300);
	pktList->InsertColumn(5, "Port", wxLIST_FORMAT_LEFT);
	pktList->InsertColumn(6, "Timestamp", wxLIST_FORMAT_LEFT, 250);
	pktList->InsertColumn(7, "Protocol", wxLIST_FORMAT_LEFT, 150);
	pktList->InsertColumn(8, "Length", wxLIST_FORMAT_LEFT);
	
	wxBoxSizer *pktListSizer = new wxBoxSizer(wxVERTICAL);
	pktListSizer->Add(pktList, 1, wxEXPAND | wxALL, 5);
	packetsPanel->SetSizer(pktListSizer);
	
	// bottom panel, used to show details
	detailsTree = new wxTreeCtrl(detailsPanel, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTR_DEFAULT_STYLE | wxBORDER_SUNKEN);
	
	wxBoxSizer *detailSizer = new wxBoxSizer(wxVERTICAL);
	detailSizer->Add(detailsTree, 1, wxEXPAND | wxALL, 5);
	detailsPanel->SetSizer(detailSizer);

	splitter->SplitHorizontally(packetsPanel, detailsPanel, (int)(0.80 * GetSize().GetHeight()));

	contSizer->Add(splitter, 1, wxEXPAND);
	SetSizerAndFit(contSizer);

	/* LIST(S) EVENTS */
	pktList->Bind(wxEVT_LIST_ITEM_SELECTED, &PacketReaderWindow::OnMouseDownEvent, this);
	
	/* CONTEXT MENU, wxFrame */
	pktList->Bind(wxEVT_LIST_ITEM_RIGHT_CLICK, &PacketReaderWindow::ShowContextMenu, this);

	StartPacketReader();
}
