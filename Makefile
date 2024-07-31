# Kernel module
obj-m += packet_sniffer.o

PWD := $(CURDIR)
KERNEL_BUILD := /lib/modules/$(shell uname -r)/build

# User-space application
USER_APP := read_packets
USER_APP_SRC := read_packets.c
USER_INCLUDE := /usr/include/ncurses
CFLAGS := -lncurses -lpanel -lmenu

all: module user_app

module:
	make -C $(KERNEL_BUILD) M=$(PWD) modules

user_app: $(USER_APP_SRC)
	$(CC) -I $(USER_INCLUDE) -g -o $(USER_APP) $(USER_APP_SRC) $(CFLAGS)

clean:
	make -C $(KERNEL_BUILD) M=$(PWD) clean
	$(RM) $(USER_APP)
