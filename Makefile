INCS += -I.
LIBS += -L. -lev -lm

LTUN_BIN = ltun

CFLAGS += -g -Wall -Werror -std=gnu99

HDRS = ltun.h ikcp.h
LTUN_SRCS = ltun.c ikcp.c rawkcp.c endpoint.c

.SUFFIXES: .c .o

.c.o: $(HDRS)
	$(CC) -c $^ -o $@ $(CFLAGS) $(INCS)

default: $(LTUN_BIN)

$(LTUN_BIN): $(LTUN_SRCS:.c=.o)
	$(CC) $^ -o $@ $(CFLAGS) $(LDFLAGS) $(LIBS)

clean:
	$(RM) $(LTUN_BIN) $(LTUN_SRCS:.c=.o)
