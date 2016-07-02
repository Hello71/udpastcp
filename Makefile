CFLAGS += -Wall -Wextra -flto

LDLIBS := -lev

NET_OBJS := src/client.o src/server.o
OBJS := src/udpastcp.o $(NET_OBJS)

udpastcp: $(OBJS)
	$(LINK.c) $^ $(LOADLIBES) $(LDLIBS) -o $@

# networking code needs aliasing to be efficient
$(NET_OBJS): CFLAGS+=-fno-strict-aliasing -Wno-sign-compare

clean:
	$(RM) $(OBJS)
