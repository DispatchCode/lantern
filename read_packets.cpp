#include "read_packets.hpp"
#include "packet_sniffer.h"
#include "packets_util.hpp"

#include <iostream>

#define DEVICE_FILE "/dev/packet_sniffer"

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
	window->SetInitialSize();
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

void PacketReaderWindow::OnMouseDownEvent(wxListEvent& event)
{
	int index = event.GetItem();
	if(index < packets.size())
	{
		struct net_packet pkt = packets[index];
		detailsTree->DeleteAllItems(); // TODO find a better way
		
		switch(pkt.protocol) {
			case IPPROTO_TCP: {
				wxTreeItemId root = detailsTree->AddRoot("TCP Header");
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
			}
			break;
			case IPPROTO_UDP: {
				wxTreeItemId root = detailsTree->AddRoot("UDP Header");
				detailsTree->AppendItem(root, wxString::Format("src port: %u", pkt.transport.udph.source));
				detailsTree->AppendItem(root, wxString::Format("dst port: %u", pkt.transport.udph.dest));
				detailsTree->AppendItem(root, wxString::Format("len: %u", ntohs(pkt.transport.udph.len)));
				detailsTree->AppendItem(root, wxString::Format("check: %u", ntohs(pkt.transport.udph.check)));

				detailsTree->Expand(root);
			break;
			}
			case IPPROTO_IGMP:{
				wxTreeItemId root = detailsTree->AddRoot("IGMP Header");
				detailsTree->AppendItem(root, wxString::Format("type: %s", pkt_igmp_get_type(pkt)));

				detailsTree->Expand(root);
			}
			break;

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
			// TODO read multiple packets, dispatch to many threads (?)
			struct net_packet pkt;
			ssize_t bytes_read = read(fd, &pkt, sizeof(struct net_packet));
			if(bytes_read > 0) {
				std::lock_guard<std::mutex> lock(packetMutex);
				packets.emplace_back(pkt);
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
			std::lock_guard<std::mutex> lock(packetMutex);
			pkt = packets.back();
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
		pktList->SetItem(index, 3, dst);
		pktList->SetItem(index, 4, src_port);
		pktList->SetItem(index, 5, dst_port);
		pktList->SetItem(index, 6, timestamp);
		pktList->SetItem(index, 7, protocol);
		pktList->SetItem(index, 8, skb_len_str);
		
		pktList->SetItemBackgroundColour(index, color_by_protocol(pkt.protocol));
	});
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
	wxPanel *packetsPanel = new wxPanel(splitter, wxID_ANY);
	wxPanel *detailsPanel = new wxPanel(splitter, wxID_ANY);	

	// top panel used to show packets
	pktList = new wxListCtrl(packetsPanel, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLC_REPORT | wxLC_SINGLE_SEL | wxBORDER_SUNKEN);
	pktList->InsertColumn(0, "Pkt #", wxLIST_FORMAT_LEFT);
	pktList->InsertColumn(1, "CPU #", wxLIST_FORMAT_LEFT);	
	pktList->InsertColumn(2, "Source IP", wxLIST_FORMAT_LEFT, 200);
	pktList->InsertColumn(3, "Destination IP", wxLIST_FORMAT_LEFT, 200);
	pktList->InsertColumn(4, "Src Port", wxLIST_FORMAT_LEFT);
	pktList->InsertColumn(5, "Dst Port", wxLIST_FORMAT_LEFT);
	pktList->InsertColumn(6, "Timestamp", wxLIST_FORMAT_LEFT, 200);
	pktList->InsertColumn(7, "Protocol", wxLIST_FORMAT_LEFT);
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
	
	StartPacketReader();
}
