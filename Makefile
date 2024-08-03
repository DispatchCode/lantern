# Kernel module
obj-m += packet_sniffer.o

PWD := $(CURDIR)
KERNEL_BUILD := /lib/modules/$(shell uname -r)/build

# User-space application
USER_APP := read_packets
USER_APP_SRC := read_packets.cpp
CFLAGS := `wx-config --cxxflags` `wx-config --libs`

all: module user_app

module:
	make -C $(KERNEL_BUILD) M=$(PWD) modules

user_app: $(USER_APP_SRC)
	$(CXX) $(CFLAGS) $(USER_APP_SRC) -o $(USER_APP)

clean:
	make -C $(KERNEL_BUILD) M=$(PWD) clean
	$(RM) $(USER_APP)
