<p align="center"><img src="https://github.com/user-attachments/assets/ddf2a8fe-4e77-468f-b514-c18a27736141"></p>

___

*Lantern* is a (toy) packet analyzer that also support blocking source / destination IP addresses.
This is achived due to the interaction between a kernel module and a GUI application.

## Features
✅ IPv4 & IPv6 <br>
✅ TCP & UDP <br>
✅  ICMPv6 & IGMP <br>
❌ What's not mentioned above <br>

## Planned feature / changes
🎯 Block / unblock IPs (only a context menu will be displayed, followed by a message box, now) <br>
🎯 Decent multithread on the user-mode application (by using thread-pools) <br>
🎯 Support of other protocols <br>
🎯 Add more details when a packet is selected <br>

![packet_sniffer](https://github.com/user-attachments/assets/fa0c6bae-a591-4f17-821b-b4e540faf3f7)

> The column "CPU #" shows the cpu that called the hook function (`capture()`, in the driver source code)

## How it works?
The driver - currently named `packer_sniffer.c` - is responsible to read the network packet using a Netfilter hook; this hook is called `NF_INET_PRE_ROUTING`, and is called right after the packets enter the kernel network stack.
Using this hook is possibile re-route the packet, accept it, or also drop it.

Each packet is collected in a buffer that will be copied to a user-space buffer using `device_read` (using a character device).

The user-mode application reads from the character device a certain amount of bytes (checked by the kernel driver, so that only a fixed amount of bytes will be copied at most). 

## Let's *make* it!
- Tested on Linux v6.9 and v6.10 (atm)
- You will also need [wxWidget](https://www.wxwidgets.org/downloads/) installed

Compile and execute with:

```bash
make && make run
```
You must be `sudo` in order to load the module, run the program and unload the module; that's why your password is needed.

You can also remove the generated files:
```bash
make clean
```

The kernel module will be compiled, loaded and unloaded when the application exits.
