INCS += -I..
LIBS += -L. -lev -lm

CLIENT_BIN = ltun_c

CFLAGS += -Werror -std=gnu99

HDRS = ltun.h
CLIENT_SRCS = ltun_client.c

.SUFFIXES: .c .o

.c.o: $(HDRS)
	$(CC) -c $^ -o $@ $(CFLAGS) $(INCS)

default: $(CLIENT_BIN)

$(CLIENT_BIN): $(CLIENT_SRCS:.c=.o)
	$(CC) $^ -o $@ $(CFLAGS) $(LDFLAGS) $(LIBS)

clean:
	$(RM) $(CLIENT_BIN) $(CLIENT_SRCS:.c=.o)
