#ifndef PACKET_READER_H
#define PACKET_READER_H

#include <wx/wx.h>
#include <wx/listctrl.h>
#include <wx/colour.h>

#include <tuple>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <thread>
#include <vector>
#include <mutex>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>    
#include <linux/udp.h>

#include "packet_sniffer.h"

#define HTTP_METHOD_SIZE 8
#define HTTP_BODY_SIZE   1024
#define HOSTNAME_SIZE    256


class PacketReader : public wxApp
{
public:
	// application startup, Wx
	virtual bool OnInit();
};

class PacketReaderWindow : public wxFrame
{
public:
	PacketReaderWindow(const wxString& title);
	//~PacketReaderWindow();

	void OnQuit(wxCommandEvent& event);
	void OnAbout(wxCommandEvent& event);
	void OnSize(wxCommandEvent& event);
	void OnMouseDownEvent(wxListEvent& event);
private:
	void StartPacketReader();

	wxListCtrl *listCtrl;
	wxListCtrl *infoList;    

	std::vector<net_packet> packets;
    std::mutex packetMutex;
    std::thread readerThread;
    bool running;
    
	// Defined as an event class
    DECLARE_EVENT_TABLE()
};

BEGIN_EVENT_TABLE(PacketReaderWindow, wxFrame)
	EVT_MENU(wxID_ABOUT, PacketReaderWindow::OnAbout)
	EVT_MENU(wxID_EXIT, PacketReaderWindow::OnQuit)
END_EVENT_TABLE()

DECLARE_APP(PacketReader);
IMPLEMENT_APP(PacketReader); // PacketReader object created by wxWidgets

#endif
