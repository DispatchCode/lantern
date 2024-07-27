#include <ncurses.h>
#include <panel.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/ip.h>
#include <time.h>
#include "packet_sniffer.h"

#define DEVICE_FILE "/dev/packet_sniffer"
#define MAX_PACKETS 58

struct net_packet packets[MAX_PACKETS];
int packet_count = 0;
int selected_packet = 0;
int running = 1;

pthread_mutex_t packet_mutex = PTHREAD_MUTEX_INITIALIZER;

void initialize_colors();
void draw_packets(WINDOW *win);
void draw_panel(WINDOW *win, const char *label);
void handle_input(WINDOW *main_window);
void* read_packets(void *arg);
void add_packet(struct net_packet *new_packet);

inline static char *net_decode_protocol(uint8_t protocol) {
	switch(protocol) {
		case IPPROTO_TCP:
			return "TCP";
		case IPPROTO_UDP:
			return "UDP";
		case IPPROTO_ICMP:
			return "ICMP";
		default:
			return "unknown";
	}
}

int main() {
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    mousemask(ALL_MOUSE_EVENTS, NULL);
    curs_set(0);

    initialize_colors();

    // Get terminal size
    int term_height, term_width;
    getmaxyx(stdscr, term_height, term_width);

    // Create windows for the panels
    WINDOW *main_window = newwin(term_height - 3, term_width, 0, 0);
    WINDOW *bottom_window = newwin(3, term_width, term_height - 3, 0);

    // Create panels for the windows
    PANEL *main_panel = new_panel(main_window);
    PANEL *bottom_panel = new_panel(bottom_window);

    // Draw initial content
    draw_packets(main_window);
    draw_panel(bottom_window, "Press 'q' to quit");

    // Update the screen
    update_panels();
    doupdate();

    // Create threads
    pthread_t packet_thread;
    pthread_create(&packet_thread, NULL, read_packets, (void *)main_window);

    // Handle user input in the main thread
    handle_input(main_window);

    // Wait for threads to finish
    running = 0;
    pthread_join(packet_thread, NULL);

    // Clean up
    endwin();
    return 0;
}

void initialize_colors() {
    start_color();
    init_pair(1, COLOR_BLACK, COLOR_BLACK);
    init_pair(2, COLOR_WHITE, COLOR_BLUE);
    init_pair(3, COLOR_BLACK, COLOR_WHITE);
    bkgd(COLOR_PAIR(1));
    attron(COLOR_PAIR(1));
}

void draw_packets(WINDOW *win) {
    werase(win);
    box(win, 0, 0);

    mvwprintw(win, 1, 1, "Source           Destination      Timestamp                     Protocol Source Port Destination Port");
    pthread_mutex_lock(&packet_mutex);
    for (int i = 0; i < packet_count-1; i++) {
        char time_buff[64] = {0};
		struct tm *tm_info;

		if (i == selected_packet) {
            wattron(win, COLOR_PAIR(2));
        } else {
            wattron(win, COLOR_PAIR(3));
        }

		tm_info = localtime((time_t*)&packets[i].timestamp_sec);
		strftime(time_buff, sizeof(time_buff), "%d/%m/%Y %H:%M:%S", tm_info);
		
        mvwprintw(win, i + 2, 1, "%-16s %-16s %s.%03lu   %-6s    %-11u %-13u",
                  packets[i].src, packets[i].dst, time_buff, packets[i].timestamp_nsec, 
                  net_decode_protocol(packets[i].protocol), packets[i].src_port, packets[i].dst_port);
        wattroff(win, COLOR_PAIR(2));
        wattroff(win, COLOR_PAIR(3));
    }
    pthread_mutex_unlock(&packet_mutex);
    wrefresh(win);
}

void draw_panel(WINDOW *win, const char *label) {
    box(win, 0, 0);
    mvwprintw(win, 1, 1, "%s", label);
    wrefresh(win);
}

void add_packet(struct net_packet *new_packet) {
    pthread_mutex_lock(&packet_mutex);
    if (packet_count >= MAX_PACKETS-1) {
        // Shift packets up to make room for the new packet
        memmove(packets, packets + 1, (MAX_PACKETS - 1) * sizeof(struct net_packet));
        packets[MAX_PACKETS - 1] = *new_packet;
    } else {
        packets[packet_count++] = *new_packet;
    }
    pthread_mutex_unlock(&packet_mutex);
}

void* read_packets(void *arg) {
	char buffer[BUFFER_SIZE] = {0};
    WINDOW *main_window = (WINDOW *)arg;
    int fd = open(DEVICE_FILE, O_RDONLY);

    if (fd < 0) {
        mvwprintw(main_window, 1, 1, "Failed to open device file: %s", strerror(errno));
        wrefresh(main_window);
        return NULL;
    }

    struct net_packet *packet;
    while (running) {
        ssize_t bytes_reads = read(fd, buffer, BUFFER_SIZE-1);

        if (bytes_reads > 0) {
			packet = (struct net_packet*) buffer;

			for(int i=0; i<bytes_reads / sizeof(struct net_packet); i++) {
				packet = (struct net_packet*) buffer;
 
            	add_packet(packet);
           		draw_packets(main_window);
           		update_panels();
           	 	doupdate();
			}
        }
    }
    close(fd);
    return NULL;
}

void handle_input(WINDOW *main_window) {
    int ch;
    while ((ch = getch()) != 'q') {
        switch (ch) {
            case KEY_DOWN:
                if (selected_packet < packet_count - 1) {
                    selected_packet++;
                }
                break;
            case KEY_UP:
                if (selected_packet > 0) {
                    selected_packet--;
                }
                break;
            case KEY_MOUSE: {
                MEVENT event;
                if (getmouse(&event) == OK) {
                    if (event.bstate & BUTTON1_CLICKED) {
                        // Check if the click is within the packet list area
                        if (event.y > 1 && event.y < packet_count + 2) {
                            selected_packet = event.y - 2;
                        }
                    }
                }
                break;
            }
        }
        draw_packets(main_window);
        update_panels();
        doupdate();
    }
}

