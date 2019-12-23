INCS += -I.
LIBS += -L. -lev -lm

LTUN_BIN = ltun
LTUN_LIB = libltun.so

CFLAGS += -g -Wall -Werror -std=gnu99

HDRS = ltun.h ikcp.h endpoint.h jhash.h list.h rawkcp.h
LTUN_SRCS = ltun.c ikcp.c rawkcp.c endpoint.c

.SUFFIXES: .c .o .obj

.c.o: $(HDRS)
	$(CC) -c $^ -o $@ $(CFLAGS) $(INCS)

.c.obj: $(HDRS)
	$(CC) -c $^ -o $@ -fPIC -DLTUN_LIB $(CFLAGS) $(INCS)

default: $(LTUN_BIN) $(LTUN_LIB)

$(LTUN_BIN): $(LTUN_SRCS:.c=.o)
	$(CC) $^ -o $@ $(CFLAGS) $(LDFLAGS) $(LIBS)

$(LTUN_LIB): $(LTUN_SRCS:.c=.obj)
	$(CC) $^ -o $@ -fPIC -shared -DLTUN_LIB $(CFLAGS) $(LDFLAGS) $(LIBS)

clean:
	$(RM) $(LTUN_BIN) $(LTUN_SRCS:.c=.o) $(LTUN_LIB) $(LTUN_SRCS:.c=.obj)
