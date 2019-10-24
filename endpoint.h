/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Mon, 14 Oct 2019 14:23:15 +0800
 */
#ifndef _ENDPOINT_H_
#define _ENDPOINT_H_

#include <string.h>
#include <stddef.h>
#include <time.h>
#include <ev.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include "list.h"

# if __BYTE_ORDER == __LITTLE_ENDIAN

#define NIPV4_ARG(i) (0xff&(((i)>>0))), (0xff&(((i)>>8))), (0xff&(((i)>>16))), (0xff&(((i)>>24)))

# elif __BYTE_ORDER == __BIG_ENDIAN

#define NIPV4_ARG(i) (0xff&(((i)>>24))), (0xff&(((i)>>16))), (0xff&(((i)>>8))), (0xff&(((i)>>0)))

# else
# error "Adjust your <bits/endian.h> defines"
# endif

typedef unsigned short __be16;
typedef unsigned int __be32;

struct endpoint_t;

typedef struct buffer_t {
	int idx;
	int len;
#define BUF_SIZE 2040
	unsigned char data[BUF_SIZE];
} buffer_t;

typedef struct endpoint_ctx {
	ev_io io;
	buffer_t *buf;

	struct endpoint_t *endpoint;
	struct list_head buf_list;
} endpoint_ctx_t;

typedef struct endpoint_t {
	ev_timer watcher;

	int fd;
	int stage;
	unsigned char id[6];

	__be32 ktun_addr;
	__be16 ktun_port;

	struct endpoint_ctx *recv_ctx;
	struct endpoint_ctx *send_ctx;
#define RAWKCP_MAX_PENDING 64
	int rawkcp_count;
	struct hlist_head rawkcp_head;
} endpoint_t;

#define ENDPOINT_INIT        0
#define ENDPOINT_SYN_SENT    1
#define ENDPOINT_ESTABLISHED 2
#define ENDPOINT_CLOSED      3

typedef struct peer_t {
	struct hlist_node hnode;
#define PEER_INIT 0
#define PEER_CONNECTED 1
#define PEER_CLOSE -1
	int stage;
	unsigned char id[6];
	__be32 addr;
	__be16 port;
} peer_t;

typedef struct endpoint_buffer_t {
	struct list_head head;
	__be32 addr;
	__be16 port;
	struct buffer_t buf;
} endpoint_buffer_t;

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

static inline int id_is_gt(const unsigned char *id1, const unsigned char *id2)
{
	unsigned int ai, bi;
	unsigned short as, bs;

	ai = get_byte4(id1);
	bi = get_byte4(id2);
	if (ntohl(ai) > ntohl(bi)) {
		return 1;
	}
	as = get_byte2(id1 + 4);
	bs = get_byte2(id2 + 4);
	if (ntohs(as) > ntohs(bs)) {
		return 1;
	}

	return 0;
}

static inline int id_is_lt(const unsigned char *id1, const unsigned char *id2)
{
	return id_is_gt(id2, id1);
}

static inline int id_is_eq(const unsigned char *id1, const unsigned char *id2)
{
	return memcmp(id1, id2, 6);
}

#define KTUN_P_MAGIC 0xfffb0099


extern endpoint_t *endpoint_new(int fd);
extern int endpoint_create_fd(const char *host, const char *port);
extern int endpoint_getaddrinfo(const char *host, const char *port, __be32 *real_addr, __be16 *real_port);

extern peer_t *endpoint_peer_lookup(unsigned char *id);
extern int endpoint_connect_to_peer(EV_P_ endpoint_t *ep, unsigned char *id);

#endif /* _ENDPOINT_H_ */
