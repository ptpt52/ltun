INCS += -I..
LIBS += -L. -lev -lm

CLIENT_BIN = ltun_c
SERVER_BIN = ltun_s

CFLAGS += -Werror -std=gnu99

HDRS = ltun.h ikcp.h
CLIENT_SRCS = ltun_client.c ikcp.c
SERVER_SRCS = ltun_server.c ikcp.c

.SUFFIXES: .c .o

.c.o: $(HDRS)
	$(CC) -c $^ -o $@ $(CFLAGS) $(INCS)

default: $(CLIENT_BIN) $(SERVER_BIN)

$(CLIENT_BIN): $(CLIENT_SRCS:.c=.o)
	$(CC) $^ -o $@ $(CFLAGS) $(LDFLAGS) $(LIBS)

$(SERVER_BIN): $(SERVER_SRCS:.c=.o)
	$(CC) $^ -o $@ $(CFLAGS) $(LDFLAGS) $(LIBS)

clean:
	$(RM) $(CLIENT_BIN) $(CLIENT_SRCS:.c=.o) $(SERVER_BIN) $(SERVER_SRCS:.c=.o)
