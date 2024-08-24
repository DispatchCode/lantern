<p align="center"><img src="https://github.com/user-attachments/assets/ddf2a8fe-4e77-468f-b514-c18a27736141"></p>

___

*Lantern* is a lightweight packet analyzer that also supports blocking source and destination IP addresses. 
This is achieved through the interaction between a kernel module and a GUI application

## Features
✅ IPv4 & IPv6 <br>
✅ TCP & UDP <br>
✅ ICMPv6 & IGMP <br>
❌ All other protocols not mentioned above <br>

## Planned feature / changes
🎯 Block/unblock IPs (currently only a context menu and message box are available) <br> 
🎯 Implement proper multithreading in the user-mode application (using thread pools) <br>
🎯 Support for additional protocols <br> 
🎯 Display more detailed information when a packet is selected <br>

![packet_sniffer](https://github.com/user-attachments/assets/fa0c6bae-a591-4f17-821b-b4e540faf3f7)

> The column "CPU #" shows the cpu that called the hook function (`capture()`, in the driver source code)

## How it works?
The driver, currently named packet_sniffer.c, is responsible for reading network packets using a Netfilter hook. This hook, called NF_INET_PRE_ROUTING, is triggered right after packets enter the kernel's network stack. With this hook, it's possible to re-route, accept, or drop the packet.

Each packet is collected in a buffer, which is then copied to a user-space buffer using device_read (via a character device).

The user-mode application reads a specified number of bytes from the character device, with the kernel driver ensuring that only a fixed maximum amount of data is copied.

## Let's *make* it!
- Tested on Linux v6.9 and v6.10 (atm)
- You will also need to have [wxWidget](https://www.wxwidgets.org/downloads/) installed

Compile and execute with:

```bash
make && make run
```
Each action requires `sudo` privileges - at least for now.

You can also remove the generated files:
```bash
make clean
```

The kernel module will be compiled, loaded and automatically unloaded when the application exits.
