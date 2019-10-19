/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Thu, 10 Oct 2019 14:20:09 +0800
 */
#include <stdlib.h>
#include "jhash.h"
#include "list.h"
#include "rawkcp.h"

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

rawkcp *rawkcp_new(void)
{
	static int conv = 1;
	rawkcp *rkcp = malloc(sizeof(rawkcp));
	if (!rkcp)
		return NULL;

	INIT_HLIST_NODE(&rkcp->hnode);

	rkcp->conv = conv++;
	rkcp->kcp = ikcp_create(rkcp->conv, rkcp);
	if (!rkcp->kcp) {
		free(rkcp);
		return NULL;
	}
	rkcp->remote_addr = 0;
	rkcp->remote_port = 0;

	return rkcp;
}

void rawkcp_free(rawkcp *rkcp)
{
	if (rkcp->kcp) {
		ikcp_release(rkcp->kcp);
	}

	free(rkcp);
}

int rawkcp_in(rawkcp *rkcp)
{
	unsigned int hash;
	rawkcp *pos;
	struct hlist_head *head;
	
	hash = jhash_3words(rkcp->conv, rkcp->remote_addr, rkcp->remote_port, rawkcp_rnd) % rawkcp_hash_size;
	head = &rawkcp_hash[hash];

	hlist_for_each_entry(pos, head, hnode) {
		if (pos->conv == rkcp->conv && pos->remote_addr == rkcp->remote_addr && pos->remote_port == rkcp->remote_port) {
			//found
			return 0;
		}
	}

	hlist_add_head(&rkcp->hnode, head);

	return 0;
}

rawkcp *rawkcp_lookup(unsigned int conv, unsigned int remote_addr, unsigned short remote_port)
{
	unsigned int hash;
	rawkcp *pos;
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
