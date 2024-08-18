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

## Let's *make* it!
- Tested on Linux v6.9 and v6.10 (atm)
- You will also need [wxWidget](https://www.wxwidgets.org/downloads/) installed

Be sure to be...
```bash
su -
```
...then, compile and execute:

```bash
make && make run
```
You can also remove the generated files:
```bash
make clean
```

The kernel module will be compiled, loaded and unloaded when the application exits.
