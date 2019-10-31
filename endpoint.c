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

#include "endpoint.h"

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#define P2POOL_DEFAULT_PORT 9102

void default_eb_recycle(EV_P_ endpoint_t *endpoint, struct endpoint_buffer_t *eb)
{
	if (eb->repeat > 0) {
		eb->repeat--;
		list_add_tail(&eb->list, &endpoint->watcher_send_buf_head);
	} else {
		free(eb);
	}
}

void endpoint_buffer_recycle(EV_P_ endpoint_t *endpoint, endpoint_buffer_t *eb)
{
	if (eb->recycle) {
		eb->recycle(EV_A_ endpoint, eb);
	} else {
		free(eb);
	}
}

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

			//TODO check endpoint->id ==? dmac;

			//send to peer to get connection
			do {
				endpoint_buffer_t *eb;

				eb = malloc(sizeof(endpoint_buffer_t));
				memset(eb, 0, sizeof(endpoint_buffer_t));

				eb->addr = dip;
				eb->port = dport;

				printf("make connection to peer=%u.%u.%u.%u:%u\n", NIPV4_ARG(eb->addr), ntohs(eb->port));

				eb->buf.idx = 0;
				eb->buf.len = 4 + 4 + 6 + 6;
				set_byte4(eb->buf.data, htonl(KTUN_P_MAGIC));
				set_byte4(eb->buf.data + 4, htonl(0x00000003));
				set_byte6(eb->buf.data + 4 + 4, endpoint->id); //smac
				set_byte6(eb->buf.data + 4 + 4 + 6, smac); //dmac

				list_add_tail(&eb->list, &endpoint->send_ctx->buf_head);

				ev_io_start(EV_A_ & endpoint->send_ctx->io);
			} while (0);

		} else if(get_byte4(endpoint_recv_ctx->buf->data + 4) == htonl(0x00000003)) {
		}
	}
}

static void endpoint_send_cb(EV_P_ ev_io *w, int revents)
{
	int count = 0;
	endpoint_ctx_t *endpoint_send_ctx = (endpoint_ctx_t *)w;
	endpoint_t *endpoint = endpoint_send_ctx->endpoint;
	endpoint_buffer_t *pos, *n;

	list_for_each_entry_safe(pos, n, &endpoint_send_ctx->buf_head, list) {
		ssize_t s;
		struct sockaddr_in addr;

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = pos->addr;
		addr.sin_port = pos->port;

		s = sendto(endpoint->fd, endpoint_send_ctx->buf->data + endpoint_send_ctx->buf->idx, endpoint_send_ctx->buf->len, 0,
				(const struct sockaddr *)&addr, sizeof(addr));
		if (s == -1) {
			//send fail
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				perror("remote_send_send");
				ev_io_stop(EV_A_ & endpoint_send_ctx->io);
				//send error
			}
			break;
		} else if (s < endpoint_send_ctx->buf->len) {
			endpoint_send_ctx->buf->len -= s;
			endpoint_send_ctx->buf->idx += s;
			//send part out
			break;
		} else {
			endpoint_send_ctx->buf->len = 0;
			endpoint_send_ctx->buf->idx = 0;
			//send out ok
		}

		list_del(&pos->list);
		endpoint_buffer_recycle(EV_A_ endpoint, pos);
		if (++count == 16)
			break;
	}

	if (list_empty(&endpoint_send_ctx->buf_head)) {
		//no buff to send
		ev_io_stop(EV_A_ & endpoint_send_ctx->io);
	}
}

static void endpoint_watcher_send_cb(EV_P_ ev_timer *watcher, int revents)
{
	int need_send = 0;
	endpoint_buffer_t *pos, *n;
	endpoint_t *endpoint = (endpoint_t *)watcher;

	list_for_each_entry_safe(pos, n, &endpoint->watcher_send_buf_head, list) {
		list_del(&pos->list);
		list_add_tail(&pos->list, &endpoint->send_ctx->buf_head);
		need_send = 1;
	}

	if (need_send) {
		ev_io_start(EV_A_ & endpoint->send_ctx->io);
	}
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
	INIT_LIST_HEAD(&endpoint->watcher_send_buf_head);
	INIT_HLIST_HEAD(&endpoint->rawkcp_head);

	endpoint->recv_ctx = malloc(sizeof(endpoint_ctx_t));
	memset(endpoint->recv_ctx, 0, sizeof(endpoint_ctx_t));
	endpoint->recv_ctx->buf = malloc(sizeof(buffer_t));
	endpoint->recv_ctx->buf->len = 0;
	endpoint->recv_ctx->buf->idx = 0;
	INIT_LIST_HEAD(&endpoint->recv_ctx->buf_head);

	endpoint->send_ctx = malloc(sizeof(endpoint_ctx_t));
	memset(endpoint->send_ctx, 0, sizeof(endpoint_ctx_t));
	endpoint->send_ctx->buf = malloc(sizeof(buffer_t));
	endpoint->send_ctx->buf->len = 0;
	endpoint->send_ctx->buf->idx = 0;
	INIT_LIST_HEAD(&endpoint->send_ctx->buf_head);

	endpoint->fd = fd;
	endpoint->recv_ctx->endpoint = endpoint;
	endpoint->send_ctx->endpoint = endpoint;
	
	ev_io_init(&endpoint->recv_ctx->io, endpoint_recv_cb, endpoint->fd, EV_READ);
	ev_io_init(&endpoint->send_ctx->io, endpoint_send_cb, endpoint->fd, EV_WRITE);

	ev_timer_init(&endpoint->watcher, endpoint_watcher_send_cb, 1.0, 1.0);

	return endpoint;
}

peer_t *endpoint_peer_lookup(unsigned char *id)
{
	//TODO
	return NULL;
}

int endpoint_connect_to_peer(EV_P_ endpoint_t *endpoint, unsigned char *id)
{
	endpoint_buffer_t *eb;

	eb = malloc(sizeof(endpoint_buffer_t));
	memset(eb, 0, sizeof(endpoint_buffer_t));

	eb->endpoint = endpoint;
	eb->repeat = 30;
	eb->addr = endpoint->ktun_addr;
	eb->port = endpoint->ktun_port;

	printf("endpoint_connect_peer() send to ktun=%u.%u.%u.%u:%u\n", NIPV4_ARG(eb->addr), ntohs(eb->port));

	eb->buf.idx = 0;
	eb->buf.len = 4 + 4 + 6 + 6;
	set_byte4(eb->buf.data, htonl(KTUN_P_MAGIC));
	set_byte4(eb->buf.data + 4, htonl(0x00000002));
	set_byte6(eb->buf.data + 4 + 4, endpoint->id); //smac
	set_byte6(eb->buf.data + 4 + 4 + 6, id); //dmac

	eb->recycle = default_eb_recycle;
	list_add_tail(&eb->list, &endpoint->send_ctx->buf_head);

	ev_io_start(EV_A_ & endpoint->send_ctx->io);

	return 0;
}
