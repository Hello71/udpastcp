CFLAGS += -Wall -Wextra -Wwrite-strings -Wno-missing-field-initializers -std=c99 -D_BSD_SOURCE -D_DEFAULT_SOURCE
CPPFLAGS += -MMD -MP
LDLIBS := -lev

TARGET := udpastcp
NET_SRC := src/checksum.c src/client.c src/server.c
SRC := src/udpastcp.c $(NET_SRC)
OBJ := $(SRC:%.c=%.o)
DEP := $(SRC:%.c=%.d)

$(TARGET): $(OBJ)
	$(LINK.c) $^ $(LOADLIBES) $(LDLIBS) -o $@

# networking code needs aliasing to work at all
$(NET_SRC:%.c=%.o): CFLAGS+=-fno-strict-aliasing -Wno-sign-compare

-include $(DEP)

clean:
	$(RM) $(TARGET) $(OBJ) $(DEP)
