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
		infoList->DeleteAllItems(); // TODO find a better way
		infoList->InsertItem(0, pkt.protocol);
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
	
		{
			std::lock_guard<std::mutex> lock(packetMutex);
			pkt = packets.back();
		}

		wxString buffer_size;
		buffer_size << packets.size();

		wxString cpuid_str   = pkt_get_cpuid(pkt);
 		wxString skb_len_str = pkt_get_len(pkt);
		wxString src 		 = pkt_ip2str(pkt, true);
		wxString dst 		 = pkt_ip2str(pkt, false);
		wxString protocol 	 = pkt_get_protocol(pkt);;
		wxString timestamp 	 = pkt_get_time(pkt);
		auto [src_port, dst_port] = pkt_get_ports(pkt);

		long index = listCtrl->InsertItem(listCtrl->GetItemCount(), buffer_size);
		listCtrl->SetItem(index, 1, cpuid_str);
		listCtrl->SetItem(index, 2, src);
		listCtrl->SetItem(index, 3, dst);
		listCtrl->SetItem(index, 4, src_port);
		listCtrl->SetItem(index, 5, dst_port);
		listCtrl->SetItem(index, 6, timestamp);
		listCtrl->SetItem(index, 7, protocol);
		listCtrl->SetItem(index, 8, skb_len_str);
		
		listCtrl->SetItemBackgroundColour(index, color_by_protocol(pkt.protocol));
	});
} 


PacketReaderWindow::PacketReaderWindow(const wxString& title) : wxFrame(NULL, wxID_ANY, title)
{
	wxMenu *fileMenu = new wxMenu;
	wxMenu *helpMenu = new wxMenu;

	helpMenu->Append(wxID_ABOUT, wxT("&About...\tF1"), wxT("Show About dialog"));
	fileMenu->Append(wxID_EXIT, wxT("E&xit\tAlt-X"), wxT("Quit this program"));

	wxMenuBar *menuBar = new wxMenuBar;
	menuBar->Append(fileMenu, wxT("&File"));
	menuBar->Append(helpMenu, wxT("&Help"));

	SetMenuBar(menuBar);

	CreateStatusBar(2);
	SetStatusText(wxT("Packet Sniffer"));

	wxBoxSizer *box = new wxBoxSizer(wxVERTICAL);

	listCtrl = new wxListCtrl(this, wxID_ANY, wxDefaultPosition, wxSize(-1,-1), wxLC_REPORT | wxLC_SINGLE_SEL | wxBORDER_SUNKEN);
	listCtrl->InsertColumn(0, "Pkt #", wxLIST_FORMAT_LEFT, 75);
	listCtrl->InsertColumn(1, "CPU #", wxLIST_FORMAT_LEFT, 50);	
	listCtrl->InsertColumn(2, "Source IP", wxLIST_FORMAT_LEFT, 150);
	listCtrl->InsertColumn(3, "Destination IP", wxLIST_FORMAT_LEFT, 150);
	listCtrl->InsertColumn(4, "Src Port", wxLIST_FORMAT_LEFT, 55);
	listCtrl->InsertColumn(5, "Dst Port", wxLIST_FORMAT_LEFT, 55);
	listCtrl->InsertColumn(6, "Timestamp", wxLIST_FORMAT_LEFT, 200);
	listCtrl->InsertColumn(7, "Protocol", wxLIST_FORMAT_LEFT, 80);
	listCtrl->InsertColumn(8, "Length", wxLIST_FORMAT_LEFT, 100);

	wxBoxSizer *info = new wxBoxSizer(wxVERTICAL);
	
	infoList = new wxListCtrl(this, wxID_ANY, wxDefaultPosition, wxSize(-1,-1), wxLC_REPORT);
	infoList->InsertColumn(0, "Packet Information", wxLIST_FORMAT_LEFT, 550);
	infoList->InsertItem(0,wxT(""));

	listCtrl->Bind(wxEVT_LIST_ITEM_SELECTED, &PacketReaderWindow::OnMouseDownEvent, this);
	
	box->Add(listCtrl, 1, wxEXPAND | wxALL, 5);
	box->Add(infoList, 1, wxEXPAND | wxALL, 5);

	SetSizer(box);

	StartPacketReader();
}
