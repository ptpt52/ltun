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

typedef struct RAWKCP {
	struct hlist_node hnode;

	unsigned int conv;
	unsigned int remote_addr;
	unsigned short remote_port;

	ikcpcb *kcp;
} rawkcp;

extern rawkcp *rawkcp_new(void);

#endif /* _RAWKCP_H_ */
