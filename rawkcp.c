/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Thu, 10 Oct 2019 14:20:09 +0800
 */
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stdio.h>
#include "jhash.h"
#include "list.h"
#include "rawkcp.h"

void itimeofday(long *sec, long *usec)
{
	struct timeval time;
	gettimeofday(&time, NULL);
	if (sec) *sec = time.tv_sec;
	if (usec) *usec = time.tv_usec;
}

/* get clock in millisecond 64 */
IINT64 iclock64(void)
{
	long s, u;
	IINT64 value;
	itimeofday(&s, &u);
	value = ((IINT64)s) * 1000 + (u / 1000);
	return value;
}

IUINT32 iclock()
{
	return (IUINT32)(iclock64() & 0xfffffffful);
}

struct hlist_head *rawkcp_hash = NULL;
unsigned int rawkcp_hash_size = 1024;
static unsigned int rawkcp_rnd = 0;

#define PAGE_SIZE 4096
#define UINT_MAX    (~0U)
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)

void *rawkcp_alloc_hashtable(unsigned int *sizep)
{
	struct hlist_head *hash;
	unsigned int nr_slots, i;

	if (*sizep > (UINT_MAX / sizeof(struct hlist_head)))
		return NULL;

	nr_slots = *sizep = round_up(*sizep,  PAGE_SIZE / sizeof(struct hlist_head));

	hash = malloc(sizeof(struct hlist_head) * nr_slots);

	if (hash) {
		for (i = 0; i < nr_slots; i++)
			INIT_HLIST_HEAD(&hash[i]);
	}

	return hash;
}

int __rawkcp_init(void)
{
	rawkcp_rnd = random();
	rawkcp_hash = rawkcp_alloc_hashtable(&rawkcp_hash_size);

	if (!rawkcp_hash)
		return -1;

	return 0;
}

static void rawkcp_watcher_cb(EV_P_ ev_timer *watcher, int revents)
{
	rawkcp_t *rkcp = (rawkcp_t *)watcher;

	if (rkcp->kcp) {
		ikcp_update(rkcp->kcp, iclock());
	}

	ev_timer_again(EV_A_ & rkcp->watcher);
}

rawkcp_t *rawkcp_new(unsigned int conv)
{
	rawkcp_t *rkcp = malloc(sizeof(rawkcp_t));
	if (!rkcp)
		return NULL;

	INIT_HLIST_NODE(&rkcp->hnode);

	rkcp->conv = conv;
	rkcp->kcp = ikcp_create(rkcp->conv, rkcp);
	if (!rkcp->kcp) {
		free(rkcp);
		return NULL;
	}
	rkcp->remote_addr = 0;
	rkcp->remote_port = 0;

	rkcp->kcp->output = rawkcp_output;
	ikcp_wndsize(rkcp->kcp, 128, 128);
	ikcp_nodelay(rkcp->kcp, 0, 10, 0, 0);

	ev_timer_init(&rkcp->watcher, rawkcp_watcher_cb, 0.1, 0.1);

	return rkcp;
}

void rawkcp_free(rawkcp_t *rkcp)
{
	if (rkcp->kcp) {
		ikcp_release(rkcp->kcp);
	}

	free(rkcp);
}

int rawkcp_insert(rawkcp_t *rkcp)
{
	unsigned int hash;
	rawkcp_t *pos;
	struct hlist_head *head;
	
	hash = jhash_3words(rkcp->conv, rkcp->remote_addr, rkcp->remote_port, rawkcp_rnd) % rawkcp_hash_size;
	head = &rawkcp_hash[hash];

	hlist_for_each_entry(pos, head, hnode) {
		if (pos->conv == rkcp->conv && pos->remote_addr == rkcp->remote_addr && pos->remote_port == rkcp->remote_port) {
			//found
			return -1;
		}
	}

	hlist_add_head(&rkcp->hnode, head);

	return 0;
}

rawkcp_t *rawkcp_lookup(unsigned int conv, unsigned int remote_addr, unsigned short remote_port)
{
	unsigned int hash;
	rawkcp_t *pos;
	struct hlist_head *head;
	
	hash = jhash_3words(conv, remote_addr, remote_port, rawkcp_rnd) % rawkcp_hash_size;
	head = &rawkcp_hash[hash];

	hlist_for_each_entry(pos, head, hnode) {
		if (pos->conv == conv && pos->remote_addr == remote_addr && pos->remote_port == remote_port) {
			return pos;
		}
	}

	return NULL;
}

int rawkcp_output(const char *buf, int len, ikcpcb *kcp, void *user)
{
	rawkcp_t *rkcp = (rawkcp_t *)user;

	printf("rawkcp_output() \n");

	if (rkcp->peer == NULL)
		return -1;
	if (rkcp->endpoint == NULL)
		return -1;

	do {
		struct sockaddr_in addr;
		ssize_t s;

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = rkcp->peer->port;
		addr.sin_addr.s_addr = rkcp->peer->addr;

		s = sendto(rkcp->endpoint->fd, buf, len, 0, (const struct sockaddr *)&addr, sizeof(addr));

		if (s == -1) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				//TODO connection error
				return -1;
			}
		}
	} while(0);

	return 0;
}
