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
#include "ikcp.h"

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

	struct endpoint_t *endpoint;
	struct dlist_head buf_head;
} endpoint_ctx_t;

typedef struct endpoint_t {
	ev_timer watcher;

	IUINT32 active_ts;
	int stage;

	int fd;
	int broadcast_fd;
	int ticks;
	unsigned char id[6];

	__be32 ktun_addr;
	__be16 ktun_port;
	__be32 broadcast_addr;
	__be16 broadcast_port;

	buffer_t *buf;

	struct endpoint_ctx *broadcast_recv_ctx;
	struct endpoint_ctx *recv_ctx;
	struct endpoint_ctx *send_ctx;
	struct dlist_head watcher_send_buf_head;
#define RAWKCP_MAX_PENDING 64
	int rawkcp_count;
	struct hlist_head rawkcp_head;
} endpoint_t;

typedef struct peer_t {
	struct hlist_node hnode;
	unsigned int use;
	unsigned char id[6];
	struct pipe_t *pipe[3];
	struct endpoint_t *endpoint;
} peer_t;

typedef struct pipe_t {
	ev_timer watcher;
	struct hlist_node hnode;
	int stage;
	__be32 addr;
	__be16 port;
	struct peer_t *peer;
	struct endpoint_buffer_t *eb;
} pipe_t;

typedef struct endpoint_buffer_t {
	struct dlist_head list;
	endpoint_t *endpoint;
	void (*recycle)(EV_P_ endpoint_t *endpoint, struct endpoint_buffer_t *eb);
	unsigned char dmac[6];
	int ptype;
	int repeat;
	int interval;
	__be32 addr;
	__be16 port;
	int buf_len;
	struct buffer_t buf;
} endpoint_buffer_t;

static inline peer_t *get_peer(peer_t *peer)
{
	peer->use++;
	return peer;
}

static inline void put_peer(peer_t *peer)
{
	peer->use--;
	if (peer->use == 0) {
		free(peer);
	}
}

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
extern int endpoint_connect_to_peer(EV_P_ endpoint_t *endpoint, unsigned char *id);

extern void endpoint_ktun_start(endpoint_t *endpoint);


extern int endpoint_peer_init(void);
extern void endpoint_peer_exit(void);

extern int endpoint_peer_insert(peer_t *peer);

extern int endpoint_peer_pipe_init(void);
extern void endpoint_peer_pipe_exit(void);
extern pipe_t *endpoint_peer_pipe_select(peer_t *peer);
extern pipe_t *endpoint_peer_pipe_lookup(__be32 addr, __be16 port);
extern int endpoint_peer_pipe_insert(pipe_t *pipe);

extern endpoint_t *endpoint_init(EV_P_ const unsigned char *id, const char *ktun, const char *ktun_port, const char *bktun, const char *bktun_port);
extern void close_and_free_endpoint(EV_P_ endpoint_t *endpoint);

#endif /* _ENDPOINT_H_ */
