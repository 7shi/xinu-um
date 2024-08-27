TARGET  = a.out
SOURCES = _main.o \
          arp.c arp_dump.c dhcp.c dhcp_dump.c dns.c dot2ip.c hexdump.c \
          icmp.c ip.c net.c pdump.c pxe.c tftp.c udp.c
OBJECTS = $(SOURCES:.c=.o)
CC      = gcc
CFLAGS  = -I../include -I../config -nostdinc -fno-builtin -D_USER_MODE

all: $(TARGET)

clean:
	rm -f $(TARGET) $(OBJECTS)

$(LIB): $(OBJECTS)
	rm -f $@
	ar r $@ $^

_main.o: _main.c
	gcc -c $<

$(TARGET): $(OBJECTS)
	gcc -o $@ $^
