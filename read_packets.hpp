#ifndef PACKET_READER_H
#define PACKET_READER_H

#include "wx/wx.h"
#include <wx/listctrl.h>
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

#define HTTP_METHOD_SIZE 8
#define HTTP_BODY_SIZE   1024
#define HOSTNAME_SIZE    256

class Packet {
public:
    uint64_t timestamp_sec;
    uint64_t timestamp_nsec;
	
	union {
		struct iphdr ip4;
		struct ipv6hdr ip6;
    } network;
	

	union {
		struct tcphdr tcp;
		struct udphdr udp;
	} transport;

	int protocol;
	char http_method[HTTP_METHOD_SIZE];
    char http_body[HTTP_BODY_SIZE];
    char hostname[HOSTNAME_SIZE];
    int length;
    int skb_len;
	
	Packet(const struct net_packet& packet);

	wxString GetLength() const;
	wxString GetSourceIP() const;
	wxString GetDestIP() const;
	wxString GetProtocol() const;
	uint16_t GetSourcePort() const;
	uint16_t GetDestPort() const;
	wxString GetTimestamp() const;
	wxString GetRequestMethod() const;
};


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

	std::vector<Packet> packets;
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
