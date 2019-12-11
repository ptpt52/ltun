#ifndef _LTUN_H
#define _LTUN_H

#include <unistd.h>
#include <fcntl.h>
#include <stddef.h>
#include <time.h>
#include <ev.h>
#include "endpoint.h"
#include "rawkcp.h"

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

#ifndef TCP_KEEPIDLE
#define TCP_KEEPIDLE TCP_KEEPALIVE
#endif

#define HS_TARGET_HOST 0x0001
#define HS_TARGET_PORT 0x0002
#define HS_TARGET_IP   0x0003

typedef struct listen_ctx_t {
	ev_io io;
	int fd;
	struct ev_loop *loop;
} listen_ctx_t;

typedef struct server_ctx_t {
	ev_io io;
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
	struct rawkcp_t *rkcp;
} server_t;

typedef struct local_ctx_t {
	ev_io io;
	int connected;
	struct local_t *local;
} local_ctx_t;

typedef struct local_t {
	ev_timer watcher;
	int fd;
	int stage;

	buffer_t *buf;

	struct local_ctx_t *recv_ctx;
	struct local_ctx_t *send_ctx;
	rawkcp_t *rkcp;
} local_t;

#define STAGE_ERROR     -1  /* Error detected                   */
#define STAGE_INIT       0  /* Initial stage                    */
#define STAGE_PAUSE      2  /* Pause data stream                */
#define STAGE_POLL       3  /* Poll data stream                 */
#define STAGE_STREAM     6  /* Stream between client and server */
#define STAGE_CLOSE      7  /* Stream closed                    */

#ifndef container_of
#define container_of(ptr, type, member) ({                      \
		const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
		(type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

#define MAX_REQUEST_TIMEOUT 30
#define MAX_REMOTE_NUM 10

extern int verbose;

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

static inline long itimediff(IUINT32 later, IUINT32 earlier)
{
	return ((IINT32)(later - earlier));
}

extern local_t *connect_to_local(EV_P_ __be32 ip, __be16 port);

extern void close_and_free_server(EV_P_ server_t *server);
extern void close_and_free_local(EV_P_ local_t *local);
extern void close_and_free_rawkcp(EV_P_ rawkcp_t *rkcp);

extern rawkcp_t *new_rawkcp(unsigned int conv, const unsigned char *remote_id);

#endif // _LTUN_H
