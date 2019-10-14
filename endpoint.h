/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Mon, 14 Oct 2019 14:23:15 +0800
 */
#ifndef _ENDPOINT_H_
#define _ENDPOINT_H_

#include <stddef.h>
#include <time.h>
#include <ev.h>
#include <sys/types.h>

# if __BYTE_ORDER == __LITTLE_ENDIAN

#define NIPV4_ARG(i) (0xff&(((i)>>0))), (0xff&(((i)>>8))), (0xff&(((i)>>16))), (0xff&(((i)>>24)))

# elif __BYTE_ORDER == __BIG_ENDIAN

#define NIPV4_ARG(i) (0xff&(((i)>>24))), (0xff&(((i)>>16))), (0xff&(((i)>>8))), (0xff&(((i)>>0)))

# else
# error "Adjust your <bits/endian.h> defines"
# endif

typedef unsigned short __be16;
typedef unsigned int __be32;

typedef struct endpoint_ctx {
	ev_io io;
	int status;

	buffer_t *buf;

	struct endpoint *endpoint;
} endpoint_ctx_t;

typedef struct endpoint {
	ev_timer watcher;

	int fd;
	int conv;
	__be32 local_addr;
	__be16 local_port;
	__be32 remote_addr;
	__be16 remote_port;
	__be32 ktun_addr;
	__be16 ktun_port;

	unsigned char smac[6];
	unsigned char dmac[6];

	struct endpoint_ctx *recv_ctx;
	struct endpoint_ctx *send_ctx;
} endpoint_t;

static inline unsigned char get_byte1(const unsigned char *p)
{
    return p[0];
}

static inline unsigned short get_byte2(const unsigned char *p)
{
    unsigned short v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static inline unsigned int get_byte4(const unsigned char *p)
{
    unsigned int v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static inline void set_byte1(unsigned char *p, unsigned char v)
{
    p[0] = v;
}

static inline void set_byte2(unsigned char *p, unsigned short v)
{
    memcpy(p, &v, sizeof(v));
}

static inline void set_byte4(unsigned char *p, unsigned int v)
{
    memcpy(p, &v, sizeof(v));
}

static inline void set_byte6(unsigned char *p, const unsigned char *pv)
{
    memcpy(p, pv, 6);
}

static inline void get_byte6(const unsigned char *p, unsigned char *pv)
{
    memcpy(pv, p, 6);
}

#define KTUN_P_MAGIC 0xfffb0099


extern endpoint_t *endpoint_new(int fd);
extern int endpoint_create_fd(const char *host, const char *port);
extern int endpoint_getaddrinfo(const char *host, const char *port, __be32 *real_addr, __be16 *real_port);

#endif /* _ENDPOINT_H_ */
