#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <math.h>

#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <sys/un.h>

#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/netfilter_ipv4.h>
#include "list.h"
#include "endpoint.h"
#include "rawkcp.h"
#include "ltun.h"

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#ifndef MAXCONN
#define MAXCONN 1024
#endif

static void signal_cb(EV_P_ ev_signal *w, int revents);
static void accept_cb(EV_P_ ev_io *w, int revents);
static void rawkcp_send_handshake(EV_P_ rawkcp_t *rkcp);
static void server_send_cb(EV_P_ ev_io *w, int revents);
static void server_recv_cb(EV_P_ ev_io *w, int revents);
static void server_timeout_cb(EV_P_ ev_timer *watcher, int revents);

static server_t *new_server(int fd, listen_ctx_t *listener);
static rawkcp_t *connect_to_rawkcp(EV_P_ unsigned char *remote_id);

static void free_server(server_t *server);
static void close_and_free_server(EV_P_ server_t *server);

endpoint_t *default_endpoint = NULL;

int endpoint_attach_rawkcp(EV_P_ endpoint_t *endpoint, rawkcp_t *rkcp)
{
	if (endpoint->rawkcp_count < RAWKCP_MAX_PENDING) {
		hlist_add_head(&rkcp->hnode, &endpoint->rawkcp_head);
		endpoint->rawkcp_count++;
		endpoint_connect_to_peer(EV_A_ endpoint, rkcp->remote_id);
		return 0;
	}

	return -1;
}

int rawkcp_attach_endpoint(EV_P_ rawkcp_t *rkcp, endpoint_t *endpoint)
{
	int ret = 0;
	peer_t *peer;

	peer = endpoint_peer_lookup(rkcp->remote_id);

	if (peer != NULL ) {
		rkcp->peer = peer;
		rkcp->endpoint = endpoint;
		ret = rawkcp_insert(rkcp);
		if (ret != 0) {
			return ret;
		}

		printf("endpoint_peer_lookup found\n");
	}

	return endpoint_attach_rawkcp(EV_A_ endpoint, rkcp);
}

int ito = 0;
int verbose = 0;
int reuse_port = 0;

static int set_reuseport(int socket)
{
	int opt = 1;
	return setsockopt(socket, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
}

static int server_conn = 0;

uint64_t tx                  = 0;
uint64_t rx                  = 0;

static struct ev_signal sigint_watcher;
static struct ev_signal sigterm_watcher;
static struct ev_signal sigchld_watcher;

int create_and_bind(const char *host, const char *port)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s, listen_sock;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family   = AF_INET;                 /* Return IPv4 only */
	hints.ai_socktype = SOCK_STREAM;             /* We want a TCP socket */
	hints.ai_flags    = AI_PASSIVE | AI_ADDRCONFIG; /* For wildcard IP address */
	hints.ai_protocol = IPPROTO_TCP;

	result = NULL;

	for (int i = 1; i < 8; i++) {
		s = getaddrinfo(host, port, &hints, &result);
		if (s == 0) {
			break;
		} else {
			sleep(pow(2, i));
			printf("failed to resolve server name, wait %.0f seconds\n", pow(2, i));
		}
	}

	if (s != 0) {
		printf("getaddrinfo: %s\n", gai_strerror(s));
		return -1;
	}

	if (result == NULL) {
		printf("Could not bind\n");
		return -1;
	}

	rp = result;

	for (/*rp = result*/; rp != NULL; rp = rp->ai_next) {
		listen_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (listen_sock == -1) {
			continue;
		}

		int opt = 1;
		setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
		setsockopt(listen_sock, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
		if (reuse_port) {
			int err = set_reuseport(listen_sock);
			if (err == 0) {
				printf("tcp port reuse enabled\n");
			}
		}

		s = bind(listen_sock, rp->ai_addr, rp->ai_addrlen);
		if (s == 0) {
			/* We managed to bind successfully! */
			break;
		} else {
			perror("bind");
		}

		close(listen_sock);
		listen_sock = -1;
	}

	freeaddrinfo(result);

	return listen_sock;
}

static int ltun_select_remote_id(unsigned char *remote_id)
{
	static unsigned char id[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0xAA};
	memcpy(remote_id, id, 6);
	return 0;
}

static unsigned int rawkcp_conv_alloc(int type)
{
	/* conv low range [1,0x7fffffff]
	 * conv high range [0x80000001,0xffffffff]
	 */
	static unsigned int conv_low  = 0x00000001;
	static unsigned int conv_high = 0x80000001;
	unsigned int conv;

	if (type != 0) {
		conv = conv_high;
		conv_high = (conv_high + 1) % 0x80000000 + 0x80000000;
		if (conv_high == 0x80000000 || conv_high == KTUN_P_MAGIC)
			conv_high++;
		return conv;
	}

	conv = conv_low;
	conv_low = (conv_low + 1) % 0x80000000;
	if (conv_low == 0 || conv_high == KTUN_P_MAGIC)
		conv_low++;
	return conv;
}

static void close_and_free_local(EV_P_ local_t *local)
{
}

static void local_recv_cb(EV_P_ ev_io *w, int revents)
{
	local_ctx_t *local_recv_ctx = (local_ctx_t *)w;
	local_t *local              = local_recv_ctx->local;
	rawkcp_t *rkcp              = local->rkcp;

	if (rkcp == NULL) {
		printf("invalid rkcp\n");
		close_and_free_local(EV_A_ local);
		return;
	}

	ssize_t r = recv(local->fd, rkcp->buf->data, BUF_SIZE, 0);
	if (r == 0) {
		// connection closed
		close_and_free_local(EV_A_ local);
		return;
	} else if (r == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		} else {
			close_and_free_local(EV_A_ local);
			return;
		}
	}

	rkcp->buf->len = r;

	if (local->stage == STAGE_STREAM) {
		ev_timer_again(EV_A_ & local->watcher);

		int s = ikcp_send(rkcp->kcp, (const char *)rkcp->buf->data, rkcp->buf->len);
		if (s < 0) {
			perror("local_recv_send");
			close_and_free_local(EV_A_ local);
		}
		return;
	} else if (local->stage == STAGE_INIT) {
		// waiting on remote connected event
		ev_io_stop(EV_A_ & local_recv_ctx->io);
		return;
	}
}

static void local_send_cb(EV_P_ ev_io *w, int revents)
{
	local_ctx_t *local_send_ctx = (local_ctx_t *)w;
	local_t *local              = local_send_ctx->local;
	rawkcp_t *rkcp            = local->rkcp;

	if (rkcp == NULL) {
		printf("invalid rkcp\n");
		close_and_free_local(EV_A_ local);
		return;
	}

	if (local->buf->len == 0) {
		// close and free
		close_and_free_local(EV_A_ local);
		return;
	} else {
		// has data to send
		ssize_t s = send(local->fd, local->buf->data + local->buf->idx, local->buf->len, 0);
		if (s == -1) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				perror("local_send_send");
				close_and_free_local(EV_A_ local);
			}
			return;
		} else if (s < local->buf->len) {
			// partly sent, move memory, wait for the next time to send
			local->buf->len -= s;
			local->buf->idx += s;
			return;
		} else {
			// all sent out, wait for reading
			local->buf->len = 0;
			local->buf->idx = 0;
			ev_io_stop(EV_A_ & local_send_ctx->io);
			local->recv_ctx->stage = STAGE_STREAM; //start stream
		}
	}
}

static local_t *new_local(int fd)
{
	local_t *local = malloc(sizeof(local_t));
	memset(local, 0, sizeof(local_t));

	local->recv_ctx = malloc(sizeof(local_ctx_t));
	local->send_ctx = malloc(sizeof(local_ctx_t));
	local->buf = malloc(sizeof(buffer_t));
	local->buf->len = 0;
	local->buf->idx = 0;
	memset(local->recv_ctx, 0, sizeof(local_ctx_t));
	memset(local->send_ctx, 0, sizeof(local_ctx_t));
	local->fd                  = fd;
	local->recv_ctx->local    = local;
	local->recv_ctx->stage = STAGE_INIT;
	local->send_ctx->local    = local;
	local->send_ctx->stage = STAGE_INIT;

	ev_io_init(&local->recv_ctx->io, local_recv_cb, fd, EV_READ);
	ev_io_init(&local->send_ctx->io, local_send_cb, fd, EV_WRITE);

	return local;
}

local_t *connect_to_local(EV_P_ struct addrinfo *res)
{
	int sockfd;

	sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sockfd == -1) {
		perror("socket");
		return NULL;
	}

	int opt = 1;
	setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
	setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	if (setnonblocking(sockfd) == -1)
		perror("setnonblocking");

	local_t *local = new_local(sockfd);
	int r = connect(sockfd, res->ai_addr, res->ai_addrlen);
	if (r == -1 && errno != EINPROGRESS) {
		perror("connect");
		close_and_free_local(EV_A_ local);
		return NULL;
	}

	return local;
}

static rawkcp_t *connect_to_rawkcp(EV_P_ unsigned char *remote_id)
{
	unsigned int conv;
	int conv_type;
	rawkcp_t *rkcp;

	conv_type = id_is_gt(default_endpoint->id, remote_id);
	conv = rawkcp_conv_alloc(conv_type);

	rkcp = rawkcp_new(conv, remote_id);
	if (!rkcp)
		return NULL;

	if (rawkcp_attach_endpoint(EV_A_ rkcp, default_endpoint) != 0) {
		rawkcp_free(rkcp);
		return NULL;
	}
	rkcp->handshake = rawkcp_send_handshake;

	return rkcp;
}

static void rawkcp_send_handshake(EV_P_ rawkcp_t *rkcp)
{
	rkcp->buf->len = 4 + 4 + 2;
	set_byte4(rkcp->buf->data, htonl(KTUN_P_MAGIC));
	set_byte4(rkcp->buf->data + 4, htonl((192<<24)|(168<<16)|(16<<8)|(1<<0)));
	set_byte2(rkcp->buf->data + 4 + 4, htons(80));
	int s = ikcp_send(rkcp->kcp, (const char *)rkcp->buf->data, rkcp->buf->len);
	if (s < 0) {
		perror("server_recv_send");
		//TODO
	}

	ev_timer_start(EV_A_ & rkcp->watcher);
}

static void server_recv_cb(EV_P_ ev_io *w, int revents)
{
	server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
	server_t *server = server_recv_ctx->server;
	rawkcp_t *rkcp = server->rkcp;

	if (rkcp == NULL) {
		printf("invalid rkcp\n");
		close_and_free_server(EV_A_ server);
		return;
	}

	ssize_t r = recv(server->fd, rkcp->buf->data, BUF_SIZE, 0);
	if (r == 0) {
		// connection closed
		if (verbose) {
			printf("server_recv close the connection\n");
		}
		//TODO
		close_and_free_server(EV_A_ server);
		return;
	} else if (r == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			// no data
			// continue to wait for recv
			return;
		} else {
			//perror("server recv");
			//TODO
			close_and_free_server(EV_A_ server);
			return;
		}
	}
	tx += r;
	rkcp->buf->len = r;

	if (server->stage == STAGE_STREAM) {
		ev_timer_again(EV_A_ & server->watcher);

		int s = ikcp_send(rkcp->kcp, (const char *)rkcp->buf->data, rkcp->buf->len);
		if (s < 0) {
			perror("server_recv_send");
			//TODO
			close_and_free_server(EV_A_ server);
		}
		return;
	} else {
		// waiting on rkcp connected event
		ev_io_stop(EV_A_ & server_recv_ctx->io);
		return;
	}
}

static void server_send_cb(EV_P_ ev_io *w, int revents)
{
	server_ctx_t *server_send_ctx = (server_ctx_t *)w;
	server_t *server              = server_send_ctx->server;
	rawkcp_t *rkcp              = server->rkcp;

	if (rkcp == NULL) {
		printf("invalid server\n");
		close_and_free_server(EV_A_ server);
		return;
	}

	if (server->buf->len == 0) {
		// close and free
		if (verbose) {
			printf("server_send close the connection\n");
		}
		//TODO
		close_and_free_server(EV_A_ server);
		return;
	} else {
		// has data to send
		ssize_t s = send(server->fd, server->buf->data + server->buf->idx, server->buf->len, 0);
		if (s == -1) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				perror("server_send_send");
				//TODO
				close_and_free_server(EV_A_ server);
			}
			return;
		} else if (s < server->buf->len) {
			// partly sent, move memory, wait for the next time to send
			server->buf->len -= s;
			server->buf->idx += s;
			return;
		} else {
			// all sent out, wait for reading
			server->buf->len = 0;
			server->buf->idx = 0;
			ev_io_stop(EV_A_ & server_send_ctx->io);
			server->send_ctx->stage = STAGE_STREAM;
		}
	}
}

static void server_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
	server_t *server = container_of(watcher, server_t, watcher);

	if (verbose) {
		printf("TCP connection timeout\n");
	}

	//TODO
	close_and_free_server(EV_A_ server);
}

static server_t *new_server(int fd, listen_ctx_t *listener)
{
	if (verbose) {
		server_conn++;
	}

	server_t *server;
	server = malloc(sizeof(server_t));

	memset(server, 0, sizeof(server_t));

	server->recv_ctx   = malloc(sizeof(server_ctx_t));
	server->send_ctx   = malloc(sizeof(server_ctx_t));
	memset(server->recv_ctx, 0, sizeof(server_ctx_t));
	memset(server->send_ctx, 0, sizeof(server_ctx_t));
	server->buf = malloc(sizeof(buffer_t));
	server->buf->len = 0;
	server->buf->idx = 0;
	server->fd                  = fd;
	server->recv_ctx->server    = server;
	server->recv_ctx->stage = 0;
	server->send_ctx->server    = server;
	server->send_ctx->stage = 0;
	server->stage               = STAGE_INIT;
	server->listen_ctx          = listener;
	server->rkcp              = NULL;

	int request_timeout = min(MAX_REQUEST_TIMEOUT, listener->timeout)
	                      + rand() % MAX_REQUEST_TIMEOUT;

	ev_io_init(&server->recv_ctx->io, server_recv_cb, fd, EV_READ);
	ev_io_init(&server->send_ctx->io, server_send_cb, fd, EV_WRITE);
	ev_timer_init(&server->watcher, server_timeout_cb, request_timeout, listener->timeout);

	return server;
}

static void free_server(server_t *server)
{
	if (server->rkcp != NULL) {
		server->rkcp->server = NULL;
	}
	if (server->buf != NULL) {
		free(server->buf);
	}

	free(server->recv_ctx);
	free(server->send_ctx);
	free(server);
}

static void close_and_free_server(EV_P_ server_t *server)
{
	if (server != NULL) {
		ev_io_stop(EV_A_ & server->send_ctx->io);
		ev_io_stop(EV_A_ & server->recv_ctx->io);
		ev_timer_stop(EV_A_ & server->watcher);
		close(server->fd);
		free_server(server);
		if (verbose) {
			server_conn--;
			printf("current server connection: %d\n", server_conn);
		}
	}
}

static void signal_cb(EV_P_ ev_signal *w, int revents)
{
	if (revents & EV_SIGNAL) {
		switch (w->signum) {
		case SIGCHLD:
			return;
		case SIGINT:
		case SIGTERM:
			ev_signal_stop(EV_DEFAULT, &sigint_watcher);
			ev_signal_stop(EV_DEFAULT, &sigterm_watcher);
			ev_signal_stop(EV_DEFAULT, &sigchld_watcher);
			ev_unloop(EV_A_ EVUNLOOP_ALL);
		}
	}
}

static void accept_cb(EV_P_ ev_io *w, int revents)
{
	listen_ctx_t *listener = (listen_ctx_t *)w;
	int serverfd           = accept(listener->fd, NULL, NULL);
	if (serverfd == -1) {
		perror("accept");
		return;
	}

	int opt = 1;
	setsockopt(serverfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
	setsockopt(serverfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
	setnonblocking(serverfd);

	if (verbose) {
		printf("accept a connection\n");
	}

	server_t *server = new_server(serverfd, listener);
	//ev_io_start(EV_A_ & server->recv_ctx->io);
	ev_timer_start(EV_A_ & server->watcher);

	if (server->stage == STAGE_INIT) {
		unsigned char remote_id[6];
		if (ltun_select_remote_id(remote_id) != 0) {
			printf("not remote_id found\n");
			close_and_free_server(EV_A_ server);
			return;
		}
		rawkcp_t *rkcp = connect_to_rawkcp(EV_A_ remote_id);
		if (rkcp == NULL) {
			printf("connect error\n");
			close_and_free_server(EV_A_ server);
			return;
		} else {
			server->rkcp = rkcp;
			rkcp->server = server;
			//TODO
			if (rkcp->peer && rkcp->handshake) {
				rkcp->handshake(EV_A_ rkcp);
			}
		}
	}
}

static void parse_optarg_mac(unsigned char *mac, const char *optarg)
{
	int n;
	unsigned int a, b, c, d, e, f;
	n = sscanf(optarg, "%02x:%02x:%02x:%02x:%02x:%02x", &a, &b, &c, &d, &e, &f);
	if (n != 6)
		n = sscanf(optarg, "%02x-%02x-%02x-%02x-%02x-%02x", &a, &b, &c, &d, &e, &f);
	if (n == 6) {
		if ((a & 0xff) == a &&
				(b & 0xff) == b &&
				(c & 0xff) == c &&
				(d & 0xff) == d &&
				(e & 0xff) == e &&
				(f & 0xff) == f) {
			mac[0] = a;
			mac[1] = b;
			mac[2] = c;
			mac[3] = d;
			mac[4] = e;
			mac[5] = f;
		}
	}
}

void usage()
{
	printf("\n");
	printf("ltun %s\n\n", "1.0");
	printf("  Q2hlbiBNaW5xaWFuZyA8cHRwdDUyQGdtYWlsLmNvbT4=\n\n");
	printf("  usage:\n\n");
	printf("       [-s <server_host>]         Local IP address to bind\n");
	printf("       [-l <local_port>]          Port number of your local server.\n");
	printf("       [-t <timeout>]             Socket timeout in seconds.\n");
	printf("       [-k <ktun>]                Ktun server\n");
	printf("       [-m <mac>]                 Mac address\n");
	printf("       [-v]                       Verbose mode.\n");
	printf("       [-h, --help]               Print this message.\n");
	printf("\n");
}

int main(int argc, char **argv)
{
	endpoint_t *endpoint;
	int fd;
	int c;
	char *timeout   = NULL;
	char *server_port = "1080";

	int server_num = 0;
	const char *server_host[MAX_REMOTE_NUM];
	unsigned char mac[6] = {0,0,0,0,0,0};
	char *ktun = NULL;

	opterr = 0;

	while ((c = getopt_long(argc, argv, "s:l:t:m:k:hv", NULL, NULL)) != -1) {
		switch (c) {
			case 's':
				if (server_num < MAX_REMOTE_NUM) {
					server_host[server_num++] = optarg;
				}
				break;
			case 'l':
				server_port = optarg;
				break;
			case 't':
				timeout = optarg;
				break;
			case 'v':
				verbose = 1;
				break;
			case 'm':
				parse_optarg_mac(mac, optarg);
				break;
			case 'k':
				ktun = optarg;
				break;
			case 'h':
				usage();
				exit(EXIT_SUCCESS);
			case '?':
				// The option character is not recognized.
				opterr = 1;
				break;
		}
	}

	if (opterr) {
		usage();
		exit(EXIT_FAILURE);
	}

	if (server_num == 0) {
		server_host[server_num++] = "0.0.0.0";
	}

	if (timeout == NULL) {
		timeout = "60";
	}

	if (ktun == NULL) {
		ktun = "ec1ns.ptpt52.com";
	}

	if (mac[0] == 0 && mac[1] == 0 && mac[2] == 0 && mac[3] == 0 && mac[4] == 0 && mac[5] == 0) {
		usage();
		exit(EXIT_FAILURE);
	}

	// ignore SIGPIPE
	signal(SIGPIPE, SIG_IGN);
	signal(SIGABRT, SIG_IGN);

	ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
	ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
	ev_signal_init(&sigchld_watcher, signal_cb, SIGCHLD);
	ev_signal_start(EV_DEFAULT, &sigint_watcher);
	ev_signal_start(EV_DEFAULT, &sigterm_watcher);
	ev_signal_start(EV_DEFAULT, &sigchld_watcher);

	// initialize ev loop
	struct ev_loop *loop = EV_DEFAULT;

	// initialize listen context
	listen_ctx_t listen_ctx_list[server_num];

	// bind to each interface
	for (int i = 0; i < server_num; i++) {
		const char *host = server_host[i];

		// Bind to port
		int listenfd;
		listenfd = create_and_bind(host, server_port);
		if (listenfd == -1) {
			FATAL("bind() error");
		}
		if (listen(listenfd, MAXCONN) == -1) {
			FATAL("listen() error");
		}
		setnonblocking(listenfd);
		listen_ctx_t *listen_ctx = &listen_ctx_list[i];

		// Setup proxy context
		listen_ctx->timeout = atoi(timeout);
		listen_ctx->fd      = listenfd;
		listen_ctx->loop    = loop;

		ev_io_init(&listen_ctx->io, accept_cb, listenfd, EV_READ);
		ev_io_start(loop, &listen_ctx->io);

		printf("tcp server listening at %s:%s\n", host ? host : "0.0.0.0", server_port);
	}

	__rawkcp_init();
	endpoint_peer_init();
	endpoint_peer_pipe_init();

	fd = endpoint_create_fd("0.0.0.0", "0");
	if (fd == -1) {
		FATAL("endpoint_create_fd error");
	}
	setnonblocking(fd);
	
	endpoint = endpoint_new(fd);
	if (endpoint == NULL) {
		FATAL("endpoint_new error");
	}

	memcpy(endpoint->id, mac, 6);
	printf("mac: %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	if (endpoint_getaddrinfo(ktun, "910", &endpoint->ktun_addr, &endpoint->ktun_port) != 0) {
		FATAL("endpoint_getaddrinfo error");
	}
	printf("ktun_addr=%u.%u.%u.%u ktun_port=%u\n",
			NIPV4_ARG(endpoint->ktun_addr), ntohs(endpoint->ktun_port));

	endpoint_ktun_start(endpoint);

	default_endpoint = endpoint;

	if (geteuid() == 0) {
		printf("running from root user\n");
	}

	// start ev loop
	ev_io_start(loop, &endpoint->recv_ctx->io);
	ev_timer_start(EV_A_ & endpoint->watcher);

	ev_run(loop, 0);

	if (verbose) {
		printf("closed gracefully\n");
	}

	// Clean up
	for (int i = 0; i < server_num; i++) {
		listen_ctx_t *listen_ctx = &listen_ctx_list[i];
		ev_io_stop(loop, &listen_ctx->io);
		close(listen_ctx->fd);
	}

	return 0;
}
