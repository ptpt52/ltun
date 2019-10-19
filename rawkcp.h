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

typedef struct RAWKCP {
	struct hlist_node hnode;

	unsigned int conv;
	unsigned int remote_addr;
	unsigned short remote_port;

	ikcpcb *kcp;
	endpoint_t *endpoint;
} rawkcp;

extern int __rawkcp_init(void);
extern rawkcp *rawkcp_new(void);
extern void rawkcp_free(rawkcp *rkcp);
extern int rawkcp_in(rawkcp *rkcp);

#endif /* _RAWKCP_H_ */
