# Kernel module
obj-m += packet_sniffer.o

PWD := $(CURDIR)
KERNEL_BUILD := /lib/modules/$(shell uname -r)/build

# User-space application
USER_APP := read_packets
USER_APP_SRC := read_packets.cpp
CFLAGS := -O2 `wx-config --cxxflags` `wx-config --libs`

all: module user_app

module:
	make -C $(KERNEL_BUILD) M=$(PWD) modules

user_app: $(USER_APP_SRC)
	$(CXX) $(CFLAGS) $(USER_APP_SRC) -o $(USER_APP)

run:
ifneq ($(shell id -u), 0)
	@echo "You must run 'su -' in order to perform this action"
else	
	@printf "Change current directory...\n\r"
	@cd $(PWD)
	@printf "Load kernel module..."
	@insmod packet_sniffer.ko
	@printf " Ok\n\r"
	@printf "Start user-space application...\n\r"
	@./read_packets
	@printf "Remove kernel module..."
	@rmmod packet_sniffer
	@printf " Ok\n\r"
endif

clean:
	make -C $(KERNEL_BUILD) M=$(PWD) clean
	$(RM) $(USER_APP)
