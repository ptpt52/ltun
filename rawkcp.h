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
	IUINT32 close_ts;
	int send_stage;
	int recv_stage;
	unsigned int send_bytes;
	unsigned int recv_bytes;
	unsigned int expect_recv_bytes;

	ikcpcb *kcp;
	unsigned int conv;
	unsigned char remote_id[6];

	peer_t *peer;
	endpoint_t *endpoint;
	struct server_t *server;
	struct local_t *local;//fake local
	buffer_t *buf;
	void (*handshake)(EV_P_ struct rawkcp_t *rkcp);
} rawkcp_t;

extern int __rawkcp_init(void);
extern int rawkcp_insert(rawkcp_t *rkcp);

extern int rawkcp_output(const char *buf, int len, ikcpcb *kcp, void *user);

extern rawkcp_t *rawkcp_lookup(unsigned int conv, const unsigned char *remote_id);

extern IUINT32 iclock();

#endif /* _RAWKCP_H_ */
