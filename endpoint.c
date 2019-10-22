/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Mon, 14 Oct 2019 14:23:15 +0800
 */
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

#include "ltun.h"
#include "endpoint.h"

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#define P2POOL_DEFAULT_PORT 9102

static void endpoint_recv_cb(EV_P_ ev_io *w, int revents)
{
	struct sockaddr_in addr;
	int addr_len = sizeof(addr);

	endpoint_ctx_t *endpoint_recv_ctx = (endpoint_ctx_t *)w;
	endpoint_t *endpoint = endpoint_recv_ctx->endpoint;

	ssize_t r = recvfrom(endpoint->fd, endpoint_recv_ctx->buf->data, BUF_SIZE, 0, (struct sockaddr*) &addr, (socklen_t *) &addr_len);

	if (r == 0) {
		ev_io_stop(EV_A_ & endpoint_recv_ctx->io);
		return;
	} else if (r == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		} else {
			ev_io_stop(EV_A_ & endpoint_recv_ctx->io);
			return;
		}
	}

	endpoint_recv_ctx->buf->len = r;

	if (endpoint_recv_ctx->buf->len >= 8 && get_byte4(endpoint_recv_ctx->buf->data) == htonl(KTUN_P_MAGIC)) {
		printf("ktun: recv msg: code=0x%08x from=%u.%u.%u.%u:%u\n", ntohl(get_byte4(endpoint_recv_ctx->buf->data + 4)), NIPV4_ARG(addr.sin_addr.s_addr), htons(addr.sin_port));
		if (get_byte4(endpoint_recv_ctx->buf->data + 4) == htonl(0x10020001)) {
			//0x10020001: resp=1, ret=002, code=0001 listen ok:   smac, ip, port
			unsigned char smac[6];
			__be32 ip;
			__be16 port;

			get_byte6(endpoint_recv_ctx->buf->data + 4 + 4, smac);
			ip   = get_byte4(endpoint_recv_ctx->buf->data + 4 + 4 + 6);
			port = get_byte2(endpoint_recv_ctx->buf->data + 4 + 4 + 6 + 4);

			printf("listen ok: smac=%02X:%02X:%02X:%02X:%02X:%02X ip=%u.%u.%u.%u port=%u\n",
					smac[0], smac[1], smac[2], smac[3], smac[4], smac[5], NIPV4_ARG(ip), ntohs(port));

		} else if(get_byte4(endpoint_recv_ctx->buf->data + 4) == htonl(0x10020002)) {
			//0x10020002: resp=1, ret=002, code=0002 connect ready but not found: smac, dmac, sip, sport, 0, 0
			unsigned char smac[6], dmac[6];
			__be32 sip;
			__be16 sport;

			get_byte6(endpoint_recv_ctx->buf->data + 4 + 4, smac);
			get_byte6(endpoint_recv_ctx->buf->data + 4 + 4 + 6, dmac);
			sip   = get_byte4(endpoint_recv_ctx->buf->data + 4 + 4 + 6 + 6);
			sport = get_byte2(endpoint_recv_ctx->buf->data + 4 + 4 + 6 + 6 + 4);

			printf("connect ready but not found: smac=%02X:%02X:%02X:%02X:%02X:%02X dmac=%02X:%02X:%02X:%02X:%02X:%02X sip=%u.%u.%u.%u sport=%u\n",
					smac[0], smac[1], smac[2], smac[3], smac[4], smac[5],
					dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5],
					NIPV4_ARG(sip), ntohs(sport));

		} else if(get_byte4(endpoint_recv_ctx->buf->data + 4) == htonl(0x10030002)) {
			//0x10030002: resp=1, ret=003, code=0002 connect ready and found:     smac, dmac, sip, sport, dip, dport
			unsigned char smac[6], dmac[6];
			__be32 sip, dip;
			__be16 sport, dport;

			get_byte6(endpoint_recv_ctx->buf->data + 4 + 4, smac);
			get_byte6(endpoint_recv_ctx->buf->data + 4 + 4 + 6, dmac);
			sip   = get_byte4(endpoint_recv_ctx->buf->data + 4 + 4 + 6 + 6);
			sport = get_byte2(endpoint_recv_ctx->buf->data + 4 + 4 + 6 + 6 + 4);
			dip   = get_byte4(endpoint_recv_ctx->buf->data + 4 + 4 + 6 + 6 + 4 + 2);
			dport = get_byte2(endpoint_recv_ctx->buf->data + 4 + 4 + 6 + 6 + 4 + 2 + 4);

			printf("connect ready and found: smac=%02X:%02X:%02X:%02X:%02X:%02X dmac=%02X:%02X:%02X:%02X:%02X:%02X sip=%u.%u.%u.%u sport=%u dip=%u.%u.%u.%u dport=%u\n",
					smac[0], smac[1], smac[2], smac[3], smac[4], smac[5],
					dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5],
					NIPV4_ARG(sip), ntohs(sport), NIPV4_ARG(dip), ntohs(dport));

			endpoint->remote_addr = dip;
			endpoint->remote_port = dport;
			set_byte6(endpoint->dmac, dmac);
			endpoint->status = 1;
			ev_timer_set(&endpoint->watcher, 0.1, 3.0);
		} else if(get_byte4(endpoint_recv_ctx->buf->data + 4) == htonl(0x00000003)) {
		}
	}
}

static void endpoint_send_cb(EV_P_ ev_io *w, int revents)
{
	endpoint_ctx_t *endpoint_send_ctx = (endpoint_ctx_t *)w;
	endpoint_t *endpoint = endpoint_send_ctx->endpoint;

	if (endpoint_send_ctx->buf->len == 0) {
		ev_io_stop(EV_A_ & endpoint_send_ctx->io);
		return;
	} else {
		struct sockaddr_in addr;
		ssize_t s;

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = endpoint->remote_port;
		addr.sin_addr.s_addr = endpoint->remote_addr;

		s = sendto(endpoint->fd, endpoint_send_ctx->buf->data + endpoint_send_ctx->buf->idx, endpoint_send_ctx->buf->len, 0,
				(const struct sockaddr *)&addr, sizeof(addr));
		if (s == -1) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				perror("remote_send_send");
				ev_io_stop(EV_A_ & endpoint_send_ctx->io);
			}
		} else if (s < endpoint_send_ctx->buf->len) {
			endpoint_send_ctx->buf->len -= s;
			endpoint_send_ctx->buf->idx += s;
		} else {
			endpoint_send_ctx->buf->len = 0;
			endpoint_send_ctx->buf->idx = 0;
			ev_io_stop(EV_A_ & endpoint_send_ctx->io);
		}
	}
}

static void endpoint_repeat_send_to_ktun(EV_P_ ev_timer *watcher, int revents)
{
	unsigned char dmac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
	endpoint_t *endpoint = (endpoint_t *)watcher;

	if (endpoint->status == 0) {
		endpoint->remote_addr = endpoint->ktun_addr;
		endpoint->remote_port = endpoint->ktun_port;

		printf("sendding to ktun %u.%u.%u.%u:%u\n", NIPV4_ARG(endpoint->ktun_addr), ntohs(endpoint->ktun_port));

		endpoint->send_ctx->buf->idx = 0;
		endpoint->send_ctx->buf->len = 4 + 4 + 6 + 6;
		set_byte4(endpoint->send_ctx->buf->data, htonl(KTUN_P_MAGIC));
		set_byte4(endpoint->send_ctx->buf->data + 4, htonl(0x00000002));
		set_byte6(endpoint->send_ctx->buf->data + 4 + 4, endpoint->id);
		set_byte6(endpoint->send_ctx->buf->data + 4 + 4 + 6, dmac);
	} else if (endpoint->status == 1) {
		printf("sendding to remote %u.%u.%u.%u:%u\n", NIPV4_ARG(endpoint->remote_addr), ntohs(endpoint->remote_port));

		endpoint->send_ctx->buf->idx = 0;
		endpoint->send_ctx->buf->len = 4 + 4 + 6 + 6;
		set_byte4(endpoint->send_ctx->buf->data, htonl(KTUN_P_MAGIC));
		set_byte4(endpoint->send_ctx->buf->data + 4, htonl(0x00000003));
		set_byte6(endpoint->send_ctx->buf->data + 4 + 4, endpoint->id);
		set_byte6(endpoint->send_ctx->buf->data + 4 + 4 + 6, endpoint->dmac);
	}

	ev_io_start(EV_A_ & endpoint->send_ctx->io);
	ev_timer_again(EV_A_ & endpoint->watcher);
}

int endpoint_getaddrinfo(const char *host, const char *port, __be32 *real_addr, __be16 *real_port)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	struct sockaddr_in *addr;
	int s;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family   = AF_INET;                 /* Return IPv4 only */
	hints.ai_socktype = SOCK_DGRAM;             /* We want a UDP socket */
	hints.ai_flags    = 0;
	hints.ai_protocol = IPPROTO_UDP;

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
		printf("Could not \n");
		return -1;
	}

	rp = result;

	addr = (struct sockaddr_in *)rp->ai_addr;

	*real_addr = addr->sin_addr.s_addr;
	*real_port = addr->sin_port;

	freeaddrinfo(result);

	return 0;
}

int endpoint_create_fd(const char *host, const char *port)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s, listen_sock = -1;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family   = AF_INET;                 /* Return IPv4 only */
	hints.ai_socktype = SOCK_DGRAM;             /* We want a UDP socket */
	hints.ai_flags    = AI_PASSIVE | AI_ADDRCONFIG; /* For wildcard IP address */
	hints.ai_protocol = IPPROTO_UDP;

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

endpoint_t *endpoint_new(int fd)
{
	endpoint_t *endpoint = malloc(sizeof(endpoint_t));
	memset(endpoint, 0, sizeof(endpoint_t));

	endpoint->recv_ctx = malloc(sizeof(endpoint_ctx_t));
	memset(endpoint->recv_ctx, 0, sizeof(endpoint_ctx_t));
	endpoint->recv_ctx->buf = malloc(sizeof(buffer_t));
	endpoint->recv_ctx->buf->len = 0;
	endpoint->recv_ctx->buf->idx = 0;

	endpoint->send_ctx = malloc(sizeof(endpoint_ctx_t));
	memset(endpoint->send_ctx, 0, sizeof(endpoint_ctx_t));
	endpoint->send_ctx->buf = malloc(sizeof(buffer_t));
	endpoint->send_ctx->buf->len = 0;
	endpoint->send_ctx->buf->idx = 0;

	endpoint->fd = fd;
	endpoint->recv_ctx->endpoint = endpoint;
	endpoint->send_ctx->endpoint = endpoint;
	
	ev_io_init(&endpoint->recv_ctx->io, endpoint_recv_cb, endpoint->fd, EV_READ);
	ev_io_init(&endpoint->send_ctx->io, endpoint_send_cb, endpoint->fd, EV_WRITE);

	ev_timer_init(&endpoint->watcher, endpoint_repeat_send_to_ktun, 0.1, 2.0);

	return endpoint;
}

peer_t *endpoint_peer_lookup(unsigned char *id)
{
	return NULL;
}
