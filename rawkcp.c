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
#include "ltun.h"

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

void __rawkcp_exit(EV_P)
{
	int i;
	for (i = 0; i < rawkcp_hash_size; i++) {
		rawkcp_t *pos;
		struct hlist_node *n;
		hlist_for_each_entry_safe(pos, n, &rawkcp_hash[i], hnode) {
			hlist_del(&pos->hnode);
			pos->send_stage = STAGE_ERROR;
			close_and_free_rawkcp(EV_A_ pos);
		}
	}
}

int rawkcp_insert(rawkcp_t *rkcp)
{
	unsigned int hash;
	rawkcp_t *pos;
	struct hlist_head *head;
	
	hash = jhash_3words(rkcp->conv, get_byte4(&rkcp->remote_id[0]), get_byte2(&rkcp->remote_id[4]), rawkcp_rnd) % rawkcp_hash_size;
	head = &rawkcp_hash[hash];

	hlist_for_each_entry(pos, head, hnode) {
		if (pos->conv == rkcp->conv && memcmp(pos->remote_id, rkcp->remote_id, 6) == 0) {
			//found
			return -1;
		}
	}

	hlist_add_head(&rkcp->hnode, head);

	return 0;
}

rawkcp_t *rawkcp_lookup(unsigned int conv, const unsigned char *remote_id)
{
	unsigned int hash;
	rawkcp_t *pos;
	struct hlist_head *head;
	
	hash = jhash_3words(conv, get_byte4(&remote_id[0]), get_byte2(&remote_id[4]), rawkcp_rnd) % rawkcp_hash_size;
	head = &rawkcp_hash[hash];

	hlist_for_each_entry(pos, head, hnode) {
		if (pos->conv == conv && memcmp(pos->remote_id, remote_id, 6) == 0) {
			return pos;
		}
	}

	return NULL;
}

int rawkcp_output(const char *buf, int len, ikcpcb *kcp, void *user)
{
	rawkcp_t *rkcp = (rawkcp_t *)user;
	pipe_t *pipe;

	if (rkcp->peer == NULL)
		return -1;
	if (rkcp->endpoint == NULL)
		return -1;

	//printf("rawkcp_output len=%u\n", len);

	pipe = endpoint_peer_pipe_select(rkcp->peer);
	if (pipe == NULL) {
		printf("no pipe available\n");
		return -1;
	}

	//TODO
	//return pipe->output();

	do {
		struct sockaddr_in addr;
		ssize_t s;

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = pipe->port;
		addr.sin_addr.s_addr = pipe->addr;

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
