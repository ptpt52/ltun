#ifndef _LTUN_H
#define _LTUN_H

#include <unistd.h>
#include <fcntl.h>
#include <stddef.h>
#include <time.h>
#include <ev.h>
#include "endpoint.h"
#include "rawkcp.h"

typedef struct listen_ctx_t {
	ev_io io;
	int fd;
	int timeout;
	struct ev_loop *loop;
} listen_ctx_t;

typedef struct server_ctx_t {
	ev_io io;
	int connected;
	struct server_t *server;
} server_ctx_t;

typedef struct server_t {
	ev_timer watcher;
	int fd;
	int stage;

	buffer_t *buf;

	struct server_ctx_t *recv_ctx;
	struct server_ctx_t *send_ctx;
	struct listen_ctx_t *listen_ctx;
	struct remote_t *remote;
} server_t;

typedef struct local_ctx_t {
	ev_io io;
	int connected;
	struct local_t *local;
} local_ctx_t;

typedef struct local_t {
	int fd;
	int stage;

	buffer_t *buf;

	struct local_ctx_t *recv_ctx;
	struct local_ctx_t *send_ctx;
	rawkcp_t *rkcp;
} local_t;

typedef struct remote_ctx_t {
	ev_io io;
	int connected;
	struct remote_t *remote;
} remote_ctx_t;

typedef struct remote_t {
	rawkcp_t *rkcp;
	buffer_t *buf;

	struct remote_ctx_t *recv_ctx;
	struct remote_ctx_t *send_ctx;
	struct server_t *server;
	void (*handshake)(EV_P_ struct remote_t *remote);
} remote_t;

#define STAGE_ERROR     -1  /* Error detected                   */
#define STAGE_INIT       0  /* Initial stage                    */
#define STAGE_HANDSHAKE  1  /* Handshake with client            */
#define STAGE_PARSE      2  /* Parse the header                 */
#define STAGE_RESOLVE    4  /* Resolve the hostname             */
#define STAGE_WAIT       5  /* Wait for more data               */
#define STAGE_STREAM     6  /* Stream between client and server */

#ifndef container_of
#define container_of(ptr, type, member) ({                      \
		const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
		(type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

#define MAX_REQUEST_TIMEOUT 30
#define MAX_REMOTE_NUM 10

static inline void FATAL(const char *msg)
{
	fprintf(stderr, "%s", msg);
	exit(-1);
}

static inline int setnonblocking(int fd)
{
	int flags;
	if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
		flags = 0;
	}
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

local_t *connect_to_local(EV_P_ struct addrinfo *res);

#endif // _LTUN_H
