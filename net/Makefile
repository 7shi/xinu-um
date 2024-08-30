TARGET  = a.out
SOURCES = _main.o \
          arp.c arp_dump.c dhcp.c dhcp_dump.c dns.c dot2ip.c hexdump.c \
          icmp.c ip.c net.c pdump.c pxe.c tftp.c udp.c \
          ../shell/xsh_ping.c
OBJECTS = $(SOURCES:.c=.o)
CC      = gcc
CFLAGS  = -g -I../include -I../config -nostdinc -fno-builtin -D_USER_MODE

all: $(TARGET)

clean:
	rm -f $(TARGET) $(OBJECTS)

$(LIB): $(OBJECTS)
	rm -f $@
	ar r $@ $^

_main.o: _main.c
	gcc -g -c $<

$(TARGET): $(OBJECTS)
	gcc -o $@ $^
