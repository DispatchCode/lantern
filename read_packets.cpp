#include "read_packets.hpp"
#include "packet_sniffer.h"

#define DEVICE_FILE "/dev/packet_sniffer"



Packet::Packet(const struct net_packet& pkt)
{
	timestamp_sec = pkt.timestamp_sec;
	timestamp_nsec = pkt.timestamp_nsec;
	memcpy(&network, &pkt.network, sizeof(network));
	memcpy(&transport, &pkt.transport, sizeof(transport));
	protocol = pkt.protocol;
}

wxString Packet::GetSourceIP() const 
{
	char src[INET6_ADDRSTRLEN];
	if(protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
		inet_ntop(AF_INET, &network.ip4.saddr, src, INET_ADDRSTRLEN);
	}
	else {
		inet_ntop(AF_INET6, &network.ip6.saddr, src, INET6_ADDRSTRLEN);
	}

	return wxString::FromAscii(src);
}

wxString Packet::GetDestIP() const
{
	char dst[INET6_ADDRSTRLEN];
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
    	inet_ntop(AF_INET, &network.ip4.daddr, dst, INET_ADDRSTRLEN);
    } else {
        inet_ntop(AF_INET6, &network.ip6.daddr, dst, INET6_ADDRSTRLEN);
    }
    return wxString::FromAscii(dst);
}

wxString Packet::GetProtocol() const {
	switch(protocol) {
		case IPPROTO_TCP : return "TCP";
		case IPPROTO_UDP : return "UDP";
		default: return "OTHER";
	}
}
wxString Packet::GetTimestamp() const {
    time_t timestamp = static_cast<time_t>(timestamp_sec);
    struct tm *tm_info = localtime(&timestamp);
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%d/%m/%Y %H:%M:%S", tm_info);
    return wxString::Format("%s.%03lu", time_buf, timestamp_nsec / 1000000);
}

bool PacketReader::OnInit()
{
	PacketReaderWindow *window = new PacketReaderWindow(wxT("Packet sniffer"));
	window->Show(true);
	return true;
}

BEGIN_EVENT_TABLE(PacketReaderWindow, wxFrame)
	EVT_MENU(wxID_ABOUT, PacketReaderWindow::OnAbout)
	EVT_MENU(wxID_EXIT, PacketReaderWindow::OnQuit)
END_EVENT_TABLE()

void PacketReaderWindow::OnAbout(wxCommandEvent& event)
{
	wxString msg;
	msg.Printf(wxT("Packet sniffer and analyser"));

	wxMessageBox(msg, wxT("About"), wxOK | wxICON_INFORMATION, this);	
}

void PacketReaderWindow::OnQuit(wxCommandEvent& event)
{	
	running = false;
	Close();
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
		std::lock_guard<std::mutex> lock(packetMutex);
		const Packet& pkt = packets.back();
		long index = listCtrl->InsertItem(listCtrl->GetItemCount(), pkt.GetSourceIP());
		listCtrl->SetItem(index, 1, pkt.GetDestIP());
		listCtrl->SetItem(index, 2, pkt.GetTimestamp());
		listCtrl->SetItem(index, 3, pkt.GetProtocol());	
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

	listCtrl = new wxListCtrl(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLC_REPORT | wxLC_SINGLE_SEL);
	listCtrl->InsertColumn(0, "Source IP", wxLIST_FORMAT_LEFT, 150);
	listCtrl->InsertColumn(2, "Destination IP", wxLIST_FORMAT_LEFT, 150);
	listCtrl->InsertColumn(3, "Timestamp", wxLIST_FORMAT_LEFT, 200);
	listCtrl->InsertColumn(4, "Protocol", wxLIST_FORMAT_LEFT, 80);

	wxBoxSizer *info = new wxBoxSizer(wxVERTICAL);
	
	wxListCtrl *infoList = new wxListCtrl(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLC_REPORT);
	infoList->InsertColumn(0, "Info Test", wxLIST_FORMAT_LEFT, 250);
	
	
	box->Add(listCtrl, 1, wxEXPAND | wxALL, 5);
	box->Add(infoList, 1, wxEXPAND | wxALL, 5);

	SetSizer(box);

	StartPacketReader();
}


