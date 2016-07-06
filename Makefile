CFLAGS += -Wall -Wextra -Wwrite-strings -std=c99 -D_BSD_SOURCE -D_DEFAULT_SOURCE

LDLIBS := -lev

NET_OBJS := src/client.o src/server.o
OBJS := src/udpastcp.o src/checksum.o $(NET_OBJS)

udpastcp: $(OBJS)
	$(LINK.c) $^ $(LOADLIBES) $(LDLIBS) -o $@

# networking code needs aliasing to be efficient
$(NET_OBJS): CFLAGS+=-fno-strict-aliasing -Wno-sign-compare

clean:
	$(RM) $(OBJS)
