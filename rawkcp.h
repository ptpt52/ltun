/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Thu, 10 Oct 2019 14:08:39 +0800
 */
#ifndef _RAWKCP_H_
#define _RAWKCP_H_

#include <stddef.h>
#include <stdlib.h>
#include "list.h"
#include "ikcp.h"
#include "endpoint.h"

typedef struct rawkcp_t {
	ev_timer watcher;

	struct hlist_node hnode;

	ikcpcb *kcp;
	unsigned int conv;
	__be32 remote_addr;
	__be16 remote_port;

	unsigned char remote_id[6];

	peer_t *peer;
	endpoint_t *endpoint;
	struct remote_t *remote;
	struct local_t *local;//fake local
} rawkcp_t;

extern int __rawkcp_init(void);
extern rawkcp_t *rawkcp_new(unsigned int conv);
extern void rawkcp_free(rawkcp_t *rkcp);
extern int rawkcp_insert(rawkcp_t *rkcp);

extern int rawkcp_output(const char *buf, int len, ikcpcb *kcp, void *user);

#endif /* _RAWKCP_H_ */
