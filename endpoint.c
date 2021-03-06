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

#include "jhash.h"
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

void peer_attach_pipe(peer_t *peer, pipe_t *pipe, int ptype);
void peer_detach_pipe(peer_t *peer, pipe_t *pipe);

void pipe_timeout_call(EV_P_ pipe_t *pipe);
void close_and_free_pipe(EV_P_ pipe_t *pipe);
pipe_t *new_pipe(__be32 ip, __be16 port, peer_t *peer);
int endpoint_connect_to_peer(EV_P_ endpoint_t *endpoint, unsigned char *id);

void default_eb_recycle(EV_P_ endpoint_t *endpoint, struct endpoint_buffer_t *eb)
{
	if (eb->repeat > 0) {
		peer_t *peer = endpoint_peer_lookup(eb->dmac);
		if (peer && peer->pipe[eb->ptype]) {
			//printf("default_eb_recycle found peer\n");
			free(eb);
			return;
		}
		eb->repeat--;
		eb->buf.idx = 0;
		eb->buf.len = eb->buf_len;
		dlist_add_tail(&eb->list, &endpoint->watcher_send_buf_head);
	} else if (eb->repeat == -1) {
		eb->buf.idx = 0;
		eb->buf.len = eb->buf_len;
		dlist_add_tail(&eb->list, &endpoint->watcher_send_buf_head);
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


static void endpoint_ktun_recv_cb(EV_P_ ev_io *w, int revents)
{
	struct sockaddr_in addr;
	int addr_len = sizeof(addr);

	endpoint_ctx_t *recv_ctx = (endpoint_ctx_t *)w;
	endpoint_t *endpoint = recv_ctx->endpoint;

	ssize_t r = recvfrom(endpoint->ktun_fd, endpoint->buf->data, BUF_SIZE, 0, (struct sockaddr*) &addr, (socklen_t *) &addr_len);

	if (r == 0) {
		ev_io_stop(EV_A_ w);
		endpoint->stage = STAGE_ERROR;
		return;
	} else if (r == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		} else {
			ev_io_stop(EV_A_ w);
			endpoint->stage = STAGE_ERROR;
			return;
		}
	}

	endpoint->buf->len = r;

	if (endpoint->buf->len >= 8 && get_byte4(endpoint->buf->data) == htonl(KTUN_P_MAGIC)) {
		int cmd = get_byte4(endpoint->buf->data + 4);
		if (cmd == htonl(0x00000001)) {
			//reply
			//0x10010001: resp=1, ret=001, code=0001 listen fail: smac, ip, port
			//0x10020001: resp=1, ret=002, code=0001 listen ok:   smac, ip, port
			peer_t *peer;
			unsigned char smac[6];

			get_byte6(endpoint->buf->data + 4 + 4, smac);

			peer = endpoint_peer_lookup(smac);
			if (peer == NULL) {
				int ret;
				peer = malloc(sizeof(peer_t));
				memset(peer, 0, sizeof(peer_t));
				INIT_HLIST_NODE(&peer->hnode);
				memcpy(peer->id, smac, 6);
				peer->endpoint = endpoint;

				if (verbose) {
					printf("[endpoint]: peer=%02X:%02X:%02X:%02X:%02X:%02X @=%u.%u.%u.%u:%u create peer\n",
							peer->id[0], peer->id[1], peer->id[2], peer->id[3], peer->id[4], peer->id[5],
							NIPV4_ARG(addr.sin_addr.s_addr), ntohs(addr.sin_port));
				}
				get_peer(peer);
				ret = endpoint_peer_insert(peer);
				if (ret != 0) {
					put_peer(peer);
					return;
				}
			}
			if (peer->addr != addr.sin_addr.s_addr)
				peer->addr = addr.sin_addr.s_addr;
			if (peer->port != addr.sin_port)
				peer->port = addr.sin_port;

			do {
				endpoint->buf->idx = 0;
				endpoint->buf->len = 4 + 4 + 6 + 4 + 2;
				set_byte4(endpoint->buf->data, htonl(KTUN_P_MAGIC));
				set_byte4(endpoint->buf->data + 4, htonl(0x10020001));
				set_byte6(endpoint->buf->data + 4 + 4, peer->id); //smac
				set_byte4(endpoint->buf->data + 4 + 4 + 6, peer->addr);
				set_byte2(endpoint->buf->data + 4 + 4 + 6 + 4, peer->port);

				ssize_t s = sendto(endpoint->ktun_fd, endpoint->buf->data, endpoint->buf->len, 0, (const struct sockaddr *)&addr, sizeof(addr));
				if (s == -1) {
					//send fail
					if (errno != EAGAIN && errno != EWOULDBLOCK) {
						perror("ktun_send_send");
					}
				}
			} while (0);
		} else if (cmd == htonl(0x00000006)) {
			peer_t *peer, *d_peer;
			unsigned char smac[6];
			unsigned char dmac[6];
			unsigned char relay_id[6] = {0,0,0,0,0,0};

			get_byte6(endpoint->buf->data + 4 + 4, smac);
			get_byte6(endpoint->buf->data + 4 + 4 + 6, dmac);

			peer = endpoint_peer_lookup(smac);
			if (peer == NULL) {
				int ret;
				peer = malloc(sizeof(peer_t));
				memset(peer, 0, sizeof(peer_t));
				INIT_HLIST_NODE(&peer->hnode);
				memcpy(peer->id, smac, 6);
				peer->endpoint = endpoint;

				if (verbose) {
					printf("[endpoint]: peer=%02X:%02X:%02X:%02X:%02X:%02X @=%u.%u.%u.%u:%u create peer\n",
							peer->id[0], peer->id[1], peer->id[2], peer->id[3], peer->id[4], peer->id[5],
							NIPV4_ARG(addr.sin_addr.s_addr), ntohs(addr.sin_port));
				}
				get_peer(peer);
				ret = endpoint_peer_insert(peer);
				if (ret != 0) {
					put_peer(peer);
					return;
				}
			}
			if (peer->addr != addr.sin_addr.s_addr)
				peer->addr = addr.sin_addr.s_addr;
			if (peer->port != addr.sin_port)
				peer->port = addr.sin_port;

			d_peer = endpoint_peer_lookup(dmac);
			endpoint_select_relay_id(smac, dmac, relay_id);
			if (d_peer && d_peer->addr && d_peer->port) {
				do {
					endpoint->buf->idx = 0;
					endpoint->buf->len = 4 + 4 + 6 + 6 + 6;
					set_byte4(endpoint->buf->data, htonl(KTUN_P_MAGIC));
					set_byte4(endpoint->buf->data + 4, htonl(0x10000006));
					set_byte6(endpoint->buf->data + 4 + 4, smac); //smac
					set_byte6(endpoint->buf->data + 4 + 4 + 6, dmac); //dmac
					set_byte6(endpoint->buf->data + 4 + 4 + 6 + 6, relay_id);

					ssize_t s = sendto(endpoint->ktun_fd, endpoint->buf->data, endpoint->buf->len, 0, (const struct sockaddr *)&addr, sizeof(addr));
					if (s == -1) {
						//send fail
						if (errno != EAGAIN && errno != EWOULDBLOCK) {
							perror("ktun_send_send");
						}
					}
				} while (0);
				do {
					endpoint->buf->idx = 0;
					endpoint->buf->len = 4 + 4 + 6 + 6 + 4 + 2 + 4 + 2;
					set_byte4(endpoint->buf->data, htonl(KTUN_P_MAGIC));
					set_byte4(endpoint->buf->data + 4, htonl(0x10000006));
					set_byte6(endpoint->buf->data + 4 + 4, dmac); //smac
					set_byte6(endpoint->buf->data + 4 + 4 + 6, smac); //dmac
					set_byte6(endpoint->buf->data + 4 + 4 + 6 + 6, relay_id);

					addr.sin_addr.s_addr = d_peer->addr;
					addr.sin_port = d_peer->port;
					ssize_t s = sendto(endpoint->ktun_fd, endpoint->buf->data, endpoint->buf->len, 0, (const struct sockaddr *)&addr, sizeof(addr));
					if (s == -1) {
						//send fail
						if (errno != EAGAIN && errno != EWOULDBLOCK) {
							perror("ktun_send_send");
						}
					}
				} while (0);
			}
		} else if (cmd == htonl(0x00000002)) {
			peer_t *peer, *d_peer;
			unsigned char smac[6];
			unsigned char dmac[6];

			get_byte6(endpoint->buf->data + 4 + 4, smac);
			get_byte6(endpoint->buf->data + 4 + 4 + 6, dmac);

			peer = endpoint_peer_lookup(smac);
			if (peer == NULL) {
				int ret;
				peer = malloc(sizeof(peer_t));
				memset(peer, 0, sizeof(peer_t));
				INIT_HLIST_NODE(&peer->hnode);
				memcpy(peer->id, smac, 6);
				peer->endpoint = endpoint;

				if (verbose) {
					printf("[endpoint]: peer=%02X:%02X:%02X:%02X:%02X:%02X @=%u.%u.%u.%u:%u create peer\n",
							peer->id[0], peer->id[1], peer->id[2], peer->id[3], peer->id[4], peer->id[5],
							NIPV4_ARG(addr.sin_addr.s_addr), ntohs(addr.sin_port));
				}
				get_peer(peer);
				ret = endpoint_peer_insert(peer);
				if (ret != 0) {
					put_peer(peer);
					return;
				}
			}
			if (peer->addr != addr.sin_addr.s_addr)
				peer->addr = addr.sin_addr.s_addr;
			if (peer->port != addr.sin_port)
				peer->port = addr.sin_port;

			d_peer = endpoint_peer_lookup(dmac);
			if (d_peer && d_peer->addr && d_peer->port) {
				do {
					endpoint->buf->idx = 0;
					endpoint->buf->len = 4 + 4 + 6 + 6 + 4 + 2 + 4 + 2;
					set_byte4(endpoint->buf->data, htonl(KTUN_P_MAGIC));
					set_byte4(endpoint->buf->data + 4, htonl(0x10030002));
					set_byte6(endpoint->buf->data + 4 + 4, smac); //smac
					set_byte6(endpoint->buf->data + 4 + 4 + 6, dmac); //dmac
					set_byte4(endpoint->buf->data + 4 + 4 + 6 + 6, peer->addr);
					set_byte2(endpoint->buf->data + 4 + 4 + 6 + 6 + 4, peer->port);
					set_byte4(endpoint->buf->data + 4 + 4 + 6 + 6 + 4 + 2, d_peer->addr);
					set_byte2(endpoint->buf->data + 4 + 4 + 6 + 6 + 4 + 2 + 4, d_peer->port);

					ssize_t s = sendto(endpoint->ktun_fd, endpoint->buf->data, endpoint->buf->len, 0, (const struct sockaddr *)&addr, sizeof(addr));
					if (s == -1) {
						//send fail
						if (errno != EAGAIN && errno != EWOULDBLOCK) {
							perror("ktun_send_send");
						}
					}
				} while (0);
				do {
					endpoint->buf->idx = 0;
					endpoint->buf->len = 4 + 4 + 6 + 6 + 4 + 2 + 4 + 2;
					set_byte4(endpoint->buf->data, htonl(KTUN_P_MAGIC));
					set_byte4(endpoint->buf->data + 4, htonl(0x10030002));
					set_byte6(endpoint->buf->data + 4 + 4, dmac); //smac
					set_byte6(endpoint->buf->data + 4 + 4 + 6, smac); //dmac
					set_byte4(endpoint->buf->data + 4 + 4 + 6 + 6, d_peer->addr);
					set_byte2(endpoint->buf->data + 4 + 4 + 6 + 6 + 4, d_peer->port);
					set_byte4(endpoint->buf->data + 4 + 4 + 6 + 6 + 4 + 2, peer->addr);
					set_byte2(endpoint->buf->data + 4 + 4 + 6 + 6 + 4 + 2 + 4, peer->port);

					addr.sin_addr.s_addr = d_peer->addr;
					addr.sin_port = d_peer->port;
					ssize_t s = sendto(endpoint->ktun_fd, endpoint->buf->data, endpoint->buf->len, 0, (const struct sockaddr *)&addr, sizeof(addr));
					if (s == -1) {
						//send fail
						if (errno != EAGAIN && errno != EWOULDBLOCK) {
							perror("ktun_send_send");
						}
					}
				} while (0);
			} else {
				do {
					endpoint->buf->idx = 0;
					endpoint->buf->len = 4 + 4 + 6 + 6 + 4 + 2 + 4 + 2;
					set_byte4(endpoint->buf->data, htonl(KTUN_P_MAGIC));
					set_byte4(endpoint->buf->data + 4, htonl(0x10020002));
					set_byte6(endpoint->buf->data + 4 + 4, smac); //smac
					set_byte6(endpoint->buf->data + 4 + 4 + 6, dmac); //dmac
					set_byte4(endpoint->buf->data + 4 + 4 + 6 + 6, peer->addr);
					set_byte2(endpoint->buf->data + 4 + 4 + 6 + 6 + 4, peer->port);
					set_byte4(endpoint->buf->data + 4 + 4 + 6 + 6 + 4 + 2, htonl(0));
					set_byte2(endpoint->buf->data + 4 + 4 + 6 + 6 + 4 + 2 + 4, htons(0));

					ssize_t s = sendto(endpoint->ktun_fd, endpoint->buf->data, endpoint->buf->len, 0, (const struct sockaddr *)&addr, sizeof(addr));
					if (s == -1) {
						//send fail
						if (errno != EAGAIN && errno != EWOULDBLOCK) {
							perror("ktun_send_send");
						}
					}
				} while (0);
			}
		} else {
			//unknown KTUN code
			printf("unknown KTUN code=0x%08x\n", cmd);
			//TODO
		}
	}
	//end KTUN_P_MAGIC
}

static void endpoint_recv_cb(EV_P_ ev_io *w, int revents)
{
	struct sockaddr_in addr;
	int addr_len = sizeof(addr);
	int fd;

	endpoint_ctx_t *recv_ctx = (endpoint_ctx_t *)w;
	endpoint_t *endpoint = recv_ctx->endpoint;

	fd = endpoint->fd;
	if ((&endpoint->broadcast_recv_ctx->io) == w) {
		fd = endpoint->broadcast_fd;
	}

	ssize_t r = recvfrom(fd, endpoint->buf->data, BUF_SIZE, 0, (struct sockaddr*) &addr, (socklen_t *) &addr_len);

	if (r == 0) {
		ev_io_stop(EV_A_ w);
		endpoint->stage = STAGE_ERROR;
		return;
	} else if (r == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		} else {
			ev_io_stop(EV_A_ w);
			endpoint->stage = STAGE_ERROR;
			return;
		}
	}

	endpoint->buf->len = r;

	if (endpoint->buf->len >= 8 && get_byte4(endpoint->buf->data) == htonl(KTUN_P_MAGIC)) {
		int cmd = get_byte4(endpoint->buf->data + 4);
		if (cmd == htonl(0x10020001)) {
			//0x10020001: resp=1, ret=002, code=0001 listen ok:   smac, ip, port
			unsigned char smac[6];
			__be32 ip;
			__be16 port;

			get_byte6(endpoint->buf->data + 4 + 4, smac);
			ip   = get_byte4(endpoint->buf->data + 4 + 4 + 6);
			port = get_byte2(endpoint->buf->data + 4 + 4 + 6 + 4);

			if (verbose) {
				printf("[endpoint]: smac=%02X:%02X:%02X:%02X:%02X:%02X src=%u.%u.%u.%u:%u listen ok\n",
						smac[0], smac[1], smac[2], smac[3], smac[4], smac[5], NIPV4_ARG(ip), ntohs(port));
			}

			endpoint->active_ts = iclock();
		} else if (cmd == htonl(0x10000006)) {
			//
			unsigned char smac[6], dmac[6];
			unsigned char relay_id[6];

			get_byte6(endpoint->buf->data + 4 + 4, smac);
			get_byte6(endpoint->buf->data + 4 + 4 + 6, dmac);
			get_byte6(endpoint->buf->data + 4 + 4 + 6 + 6, relay_id);
			endpoint_connect_to_peer(EV_A_ endpoint, relay_id);
		} else if (cmd == htonl(0x10020002)) {
			//0x10020002: resp=1, ret=002, code=0002 connect ready but not found: smac, dmac, sip, sport, 0, 0
			unsigned char smac[6], dmac[6];
			__be32 sip;
			__be16 sport;

			get_byte6(endpoint->buf->data + 4 + 4, smac);
			get_byte6(endpoint->buf->data + 4 + 4 + 6, dmac);
			sip   = get_byte4(endpoint->buf->data + 4 + 4 + 6 + 6);
			sport = get_byte2(endpoint->buf->data + 4 + 4 + 6 + 6 + 4);

			if (verbose) {
				printf("[endpoint]: smac=%02X:%02X:%02X:%02X:%02X:%02X dmac=%02X:%02X:%02X:%02X:%02X:%02X src=%u.%u.%u.%u:%u dst= not found\n",
						smac[0], smac[1], smac[2], smac[3], smac[4], smac[5],
						dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5],
						NIPV4_ARG(sip), ntohs(sport));
			}
		} else if (cmd == htonl(0x10030002)) {
			//0x10030002: resp=1, ret=003, code=0002 connect ready and found:     smac, dmac, sip, sport, dip, dport
			unsigned char smac[6], dmac[6];
			__be32 sip, dip;
			__be16 sport, dport;

			get_byte6(endpoint->buf->data + 4 + 4, smac);
			get_byte6(endpoint->buf->data + 4 + 4 + 6, dmac);
			sip   = get_byte4(endpoint->buf->data + 4 + 4 + 6 + 6);
			sport = get_byte2(endpoint->buf->data + 4 + 4 + 6 + 6 + 4);
			dip   = get_byte4(endpoint->buf->data + 4 + 4 + 6 + 6 + 4 + 2);
			dport = get_byte2(endpoint->buf->data + 4 + 4 + 6 + 6 + 4 + 2 + 4);

			if (verbose) {
				printf("[endpoint]: smac=%02X:%02X:%02X:%02X:%02X:%02X dmac=%02X:%02X:%02X:%02X:%02X:%02X src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u found\n",
						smac[0], smac[1], smac[2], smac[3], smac[4], smac[5],
						dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5],
						NIPV4_ARG(sip), ntohs(sport), NIPV4_ARG(dip), ntohs(dport));
			}

			//send to peer to get connection
			do {
				endpoint_buffer_t *eb;

				eb = malloc(sizeof(endpoint_buffer_t));
				memset(eb, 0, sizeof(endpoint_buffer_t));

				eb->addr = dip;
				eb->port = dport;

				if (verbose) {
					printf("[endpoint]: connect to dst=%u.%u.%u.%u:%u\n", NIPV4_ARG(eb->addr), ntohs(eb->port));
				}

				//[KTUN_P_MAGIC|0x00000003|smac|dmac] smac tell dmac I am connecting to dmac
				eb->buf.idx = 0;
				eb->buf_len = eb->buf.len = 4 + 4 + 6 + 6;
				set_byte4(eb->buf.data, htonl(KTUN_P_MAGIC));
				set_byte4(eb->buf.data + 4, htonl(0x00000003));
				set_byte6(eb->buf.data + 4 + 4, endpoint->id); //smac
				set_byte6(eb->buf.data + 4 + 4 + 6, dmac); //dmac

				dlist_add_tail(&eb->list, &endpoint->send_ctx->buf_head);

				ev_io_start(EV_A_ & endpoint->send_ctx->io);
			} while (0);
		} else if (cmd == htonl(0x00000003) || cmd == htonl(0x10000003) ||
				cmd == htonl(0x00000005) || cmd == htonl(0x10000005)) {
			//got 0x00000003 connection ready.
			//got 0x00000005 someone broadcast want to connect, direct connect ok
			//or got 0x10000003/0x10000005 connection reply
			//0x00000003: in-comming connection: smac, dmac
			int ptype = 0;
			unsigned char smac[6], dmac[6];

			if (cmd == htonl(0x00000005) || cmd == htonl(0x10000005)) {
				ptype = 0;
			} else {
				ptype = 1;
			}

			get_byte6(endpoint->buf->data + 4 + 4, smac);
			get_byte6(endpoint->buf->data + 4 + 4 + 6, dmac);
			if (memcmp(endpoint->id, dmac, 6) == 0) {
				rawkcp_t *pos;
				struct hlist_node *n;
				peer_t *peer = NULL;
				pipe_t *pipe = NULL;

				if (verbose) {
					printf("[endpoint]: smac=%02X:%02X:%02X:%02X:%02X:%02X dmac=%02X:%02X:%02X:%02X:%02X:%02X from=%u.%u.%u.%u:%u new connection in\n",
							smac[0], smac[1], smac[2], smac[3], smac[4], smac[5],
							dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5],
							NIPV4_ARG(addr.sin_addr.s_addr), ntohs(addr.sin_port));
				}

				peer = endpoint_peer_lookup(smac);
				if (peer == NULL) {
					int ret;
					peer = malloc(sizeof(peer_t));
					memset(peer, 0, sizeof(peer_t));
					INIT_HLIST_NODE(&peer->hnode);
					memcpy(peer->id, smac, 6);
					peer->endpoint = endpoint;

					if (verbose) {
						printf("[endpoint]: peer=%02X:%02X:%02X:%02X:%02X:%02X @=%u.%u.%u.%u:%u create peer\n",
								peer->id[0], peer->id[1], peer->id[2], peer->id[3], peer->id[4], peer->id[5],
								NIPV4_ARG(addr.sin_addr.s_addr), ntohs(addr.sin_port));
					}
					get_peer(peer);
					ret = endpoint_peer_insert(peer);
					if (ret != 0) {
						put_peer(peer);
						return;
					}
				}

				pipe = endpoint_peer_pipe_lookup(addr.sin_addr.s_addr, addr.sin_port);
				if (pipe == NULL) {
					int ret;
					pipe = new_pipe(addr.sin_addr.s_addr, addr.sin_port, peer);
					peer_attach_pipe(peer, pipe, ptype);

					if (verbose) {
						printf("[endpoint]: peer=%02X:%02X:%02X:%02X:%02X:%02X @=%u.%u.%u.%u:%u create pipe\n",
								peer->id[0], peer->id[1], peer->id[2], peer->id[3], peer->id[4], peer->id[5],
								NIPV4_ARG(pipe->addr), ntohs(pipe->port));
					}

					ret = endpoint_peer_pipe_insert(pipe);
					if (ret != 0) {
						peer_detach_pipe(peer, pipe);
						close_and_free_pipe(EV_A_ pipe);
						return;
					}

					//trigger keepalive for pipe
					do {
						endpoint_buffer_t *eb;

						eb = malloc(sizeof(endpoint_buffer_t));
						memset(eb, 0, sizeof(endpoint_buffer_t));

						eb->repeat = -1;
						eb->interval = 10;
						eb->recycle = default_eb_recycle;
						eb->addr = pipe->addr;
						eb->port = pipe->port;

						if (verbose) {
							printf("[endpoint]: trigger keepalive for pipe @=%u.%u.%u.%u:%u\n", NIPV4_ARG(eb->addr), ntohs(eb->port));
						}

						//[KTUN_P_MAGIC|0x10000004|smac|dmac] smac reply to dmac connection ok
						eb->buf.idx = 0;
						eb->buf_len = eb->buf.len = 4 + 4 + 6 + 6;
						set_byte4(eb->buf.data, htonl(KTUN_P_MAGIC));
						set_byte4(eb->buf.data + 4, htonl(0x00000004));
						set_byte6(eb->buf.data + 4 + 4, endpoint->id); //smac
						set_byte6(eb->buf.data + 4 + 4 + 6, peer->id); //dmac

						dlist_add_tail(&eb->list, &endpoint->send_ctx->buf_head);

						pipe->eb = eb;
						ev_io_start(EV_A_ & endpoint->send_ctx->io);
					} while (0);

					pipe->stage = STAGE_STREAM;
					ev_timer_start(EV_A_ & pipe->watcher);
				}

				hlist_for_each_entry_safe(pos, n, &endpoint->rawkcp_head, hnode) {
					int ret;
					if (memcmp(pos->remote_id, smac, 6) == 0) {
						hlist_del(&pos->hnode);
						pos->peer = get_peer(peer);
						pos->endpoint = endpoint;
						ret = rawkcp_insert(pos);
						if (ret != 0) {
							close_and_free_rawkcp(EV_A_ pos);
							break;
						}
						if (pos->server && pos->handshake) {
							pos->handshake(EV_A_ pos);
						}
					}
				}

				//reply to smac
				if (cmd == htonl(0x00000003) || cmd == htonl(0x00000005)) {
					endpoint_buffer_t *eb;

					eb = malloc(sizeof(endpoint_buffer_t));
					memset(eb, 0, sizeof(endpoint_buffer_t));

					eb->addr = addr.sin_addr.s_addr;
					eb->port = addr.sin_port;

					if (verbose) {
						printf("[endpoint]: send reply to @=%u.%u.%u.%u:%u\n", NIPV4_ARG(eb->addr), ntohs(eb->port));
					}

					//[KTUN_P_MAGIC|0x10000003|smac|dmac] smac reply to dmac connection ok
					eb->buf.idx = 0;
					eb->buf_len = eb->buf.len = 4 + 4 + 6 + 6;
					set_byte4(eb->buf.data, htonl(KTUN_P_MAGIC));
					set_byte4(eb->buf.data + 4, htonl(ntohl(cmd) | 0x10000000));
					set_byte6(eb->buf.data + 4 + 4, endpoint->id); //smac
					set_byte6(eb->buf.data + 4 + 4 + 6, smac); //dmac

					dlist_add_tail(&eb->list, &endpoint->send_ctx->buf_head);

					ev_io_start(EV_A_ & endpoint->send_ctx->io);
				}
			} else if (memcmp(endpoint->id, smac, 6) == 0) {
				//silence
			} else {
				//TODO dmac no me
				if (verbose) {
					printf("[endpoint]: smac=%02X:%02X:%02X:%02X:%02X:%02X dmac=%02X:%02X:%02X:%02X:%02X:%02X from=%u.%u.%u.%u:%u unknown packet in\n",
							smac[0], smac[1], smac[2], smac[3], smac[4], smac[5],
							dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5],
							NIPV4_ARG(addr.sin_addr.s_addr), ntohs(addr.sin_port));
				}
			}
		} else if (cmd == htonl(0x00000004)) {
			//got 0x00000004 keep alive
			unsigned char smac[6], dmac[6];

			get_byte6(endpoint->buf->data + 4 + 4, smac);
			get_byte6(endpoint->buf->data + 4 + 4 + 6, dmac);
			if (memcmp(endpoint->id, dmac, 6) == 0) {
				peer_t *peer = NULL;
				pipe_t *pipe = NULL;

				peer = endpoint_peer_lookup(smac);
				pipe = endpoint_peer_pipe_lookup(addr.sin_addr.s_addr, addr.sin_port);
				if (pipe && peer) {
					ev_timer_again(EV_A_ & pipe->watcher);
					if (verbose) {
						printf("[endpoint]: keepalive from pipe @=%u.%u.%u.%u:%u peer=%02X:%02X:%02X:%02X:%02X:%02X\n",
								NIPV4_ARG(addr.sin_addr.s_addr), ntohs(addr.sin_port),
								peer->id[0], peer->id[1], peer->id[2], peer->id[3], peer->id[4], peer->id[5]);
					}
				}
			}
		} else if (cmd == htonl(0x306b6370)) {
			//KTUN_P_MAGIC|0x306b6370|conv|smac|dmac
			//got kcp forward reply
			int ret;
			int conv;
			pipe_t *pipe;
			peer_t *s_peer;
			rawkcp_t *rkcp;
			unsigned char smac[6], dmac[6];

			conv = get_byte4(endpoint->buf->data + 8);
			conv = ntohl(conv);

			pipe = endpoint_peer_pipe_lookup(addr.sin_addr.s_addr, addr.sin_port);
			if (pipe == NULL) {
				return;
			}
			rkcp = rawkcp_lookup(conv, pipe->peer->id);
			if (rkcp == NULL) {
				return;
			}

			if (rkcp->rawkcp) {
				set_byte4(endpoint->buf->data + 8, htonl(rkcp->rawkcp->conv));
				rkcp->rawkcp->kcp->output((const char*)endpoint->buf->data, endpoint->buf->len, rkcp->rawkcp->kcp, rkcp->rawkcp->kcp->user);
				return;
			}

			get_byte6(endpoint->buf->data + 12, smac);
			get_byte6(endpoint->buf->data + 12 + 6, dmac);

			if (id_is_eq(endpoint->id, dmac)) {
				s_peer = endpoint_peer_lookup(smac);
				if (s_peer == NULL) {
					//create s_peer
					s_peer = malloc(sizeof(peer_t));
					memset(s_peer, 0, sizeof(peer_t));
					INIT_HLIST_NODE(&s_peer->hnode);
					memcpy(s_peer->id, smac, 6);
					s_peer->endpoint = endpoint;

					if (verbose) {
						printf("[endpoint]: peer=%02X:%02X:%02X:%02X:%02X:%02X @=%u.%u.%u.%u:%u create s_peer\n",
								s_peer->id[0], s_peer->id[1], s_peer->id[2], s_peer->id[3], s_peer->id[4], s_peer->id[5],
								NIPV4_ARG(addr.sin_addr.s_addr), ntohs(addr.sin_port));
					}
					get_peer(s_peer);
					ret = endpoint_peer_insert(s_peer);
					if (ret != 0) {
						put_peer(s_peer);
						return;
					}
				}
				peer_attach_pipe(s_peer, pipe, 2);

				rkcp->peer = get_peer(s_peer);
				rkcp->endpoint = endpoint;
				ret = rawkcp_insert(rkcp);
				if (ret != 0) {
					close_and_free_rawkcp(EV_A_ rkcp);
					return;
				}
				ev_timer_start(EV_A_ & rkcp->watcher);
			}

		} else if (cmd == htonl(0x206b6370)) {
			//KTUN_P_MAGIC|0x206b6370|conv|smac|dmac
			//got kcp forward request
			//new forward rawkcp
			int conv;
			unsigned char smac[6], dmac[6];
			rawkcp_t *rkcp, *d_rkcp;
			pipe_t *pipe;
			peer_t *s_peer, *d_peer;

			conv = get_byte4(endpoint->buf->data + 8);
			conv = ntohl(conv);

			get_byte6(endpoint->buf->data + 12, smac);
			get_byte6(endpoint->buf->data + 12 + 6, dmac);

			pipe = endpoint_peer_pipe_lookup(addr.sin_addr.s_addr, addr.sin_port);
			if (pipe == NULL) {
				return;
			}
			rkcp = rawkcp_lookup(conv, pipe->peer->id);
			if (rkcp == NULL) {
				int ret;
				s_peer = endpoint_peer_lookup(smac);
				d_peer = endpoint_peer_lookup(dmac);
				if (id_is_eq(endpoint->id, dmac)) {
					if (s_peer == NULL) {
						//create s_peer
						s_peer = malloc(sizeof(peer_t));
						memset(s_peer, 0, sizeof(peer_t));
						INIT_HLIST_NODE(&s_peer->hnode);
						memcpy(s_peer->id, smac, 6);
						s_peer->endpoint = endpoint;

						if (verbose) {
							printf("[endpoint]: peer=%02X:%02X:%02X:%02X:%02X:%02X @=%u.%u.%u.%u:%u create s_peer\n",
									s_peer->id[0], s_peer->id[1], s_peer->id[2], s_peer->id[3], s_peer->id[4], s_peer->id[5],
									NIPV4_ARG(addr.sin_addr.s_addr), ntohs(addr.sin_port));
						}
						get_peer(s_peer);
						ret = endpoint_peer_insert(s_peer);
						if (ret != 0) {
							put_peer(s_peer);
							return;
						}
					}
					peer_attach_pipe(s_peer, pipe, 2);

					rkcp = new_rawkcp(conv, pipe->peer->id);
					if (rkcp == NULL) {
						return;
					}
					rkcp->peer = get_peer(s_peer);
					rkcp->endpoint = endpoint;
					ret = rawkcp_insert(rkcp);
					if (ret != 0) {
						close_and_free_rawkcp(EV_A_ rkcp);
						return;
					}
					ev_timer_start(EV_A_ & rkcp->watcher);

					//TODO send reply
					do {
						endpoint->buf->idx = 0;
						endpoint->buf->len = 4 + 4 + 4 + 6 + 6;
						set_byte4(endpoint->buf->data, htonl(KTUN_P_MAGIC));
						set_byte4(endpoint->buf->data + 4, htonl(0x306b6370));
						set_byte4(endpoint->buf->data + 4 + 4, htonl(rkcp->conv)); //conv
						set_byte6(endpoint->buf->data + 4 + 4 + 4, endpoint->id); //smac
						set_byte6(endpoint->buf->data + 4 + 4 + 4 + 6, s_peer->id); //dmac

						ssize_t s = sendto(endpoint->fd, endpoint->buf->data, endpoint->buf->len, 0, (const struct sockaddr *)&addr, sizeof(addr));
						if (s == -1) {
							//send fail
							if (errno != EAGAIN && errno != EWOULDBLOCK) {
								perror("ktun_send_send");
							}
						}
					} while (0);
					return;
				}

				if (s_peer == NULL || s_peer != pipe->peer || d_peer == NULL) {
					//cannot forward
					return;
				}

				rkcp = new_rawkcp(conv, s_peer->id);
				if (rkcp == NULL) {
					return;
				}
				rkcp->peer = get_peer(s_peer);
				rkcp->endpoint = endpoint;
				ret = rawkcp_insert(rkcp);
				if (ret != 0) {
					close_and_free_rawkcp(EV_A_ rkcp);
					return;
				}

				//need forward
				int conv_type = id_is_gt(endpoint->id, d_peer->id);
				conv = rawkcp_conv_alloc(conv_type);
				d_rkcp = new_rawkcp(conv, d_peer->id);
				if (d_rkcp == NULL) {
					close_and_free_rawkcp(EV_A_ rkcp);
					return;
				}
				d_rkcp->peer = get_peer(d_peer);
				d_rkcp->endpoint = endpoint;
				ret = rawkcp_insert(d_rkcp);
				if (ret != 0) {
					close_and_free_rawkcp(EV_A_ d_rkcp);
					close_and_free_rawkcp(EV_A_ rkcp);
					return;
				}

				rkcp->rawkcp = d_rkcp;
				d_rkcp->rawkcp = rkcp;
			}

			if (rkcp->rawkcp) {
				set_byte4(endpoint->buf->data + 8, htonl(rkcp->rawkcp->conv));
				rkcp->rawkcp->kcp->output((const char*)endpoint->buf->data, endpoint->buf->len, rkcp->rawkcp->kcp, rkcp->rawkcp->kcp->user);
				return;
			}

		} else if (cmd == htonl(0x106b6370)) {
			//got reset-kcp-pipe from remote
			int conv;
			rawkcp_t *rkcp;
			pipe_t *pipe;

			conv = get_byte4(endpoint->buf->data + 8);
			conv = ntohl(conv);

			pipe = endpoint_peer_pipe_lookup(addr.sin_addr.s_addr, addr.sin_port);
			if (pipe == NULL) {
				return;
			}
			rkcp = rawkcp_lookup(conv, pipe->peer->id);
			if (rkcp == NULL) {
				return;
			}

			if (rkcp->rawkcp) {
				set_byte4(endpoint->buf->data + 8, htonl(rkcp->rawkcp->conv));
				rkcp->rawkcp->kcp->output((const char*)endpoint->buf->data, endpoint->buf->len, rkcp->rawkcp->kcp, rkcp->rawkcp->kcp->user);
				//TODO close rkcp?
				return;
			}

			pipe_timeout_call(EV_A_ pipe);
		} else if (cmd == htonl(0x006b6370)) {
			//got close msg from remote, kcp need close
			int conv;
			unsigned int nbytes;
			rawkcp_t *rkcp;
			pipe_t *pipe;

			conv = get_byte4(endpoint->buf->data + 8);
			conv = ntohl(conv);

			pipe = endpoint_peer_pipe_lookup(addr.sin_addr.s_addr, addr.sin_port);
			if (pipe == NULL) {
				return;
			}
			rkcp = rawkcp_lookup(conv, pipe->peer->id);
			if (rkcp == NULL) {
				return;
			}

			if (rkcp->rawkcp) {
				set_byte4(endpoint->buf->data + 8, htonl(rkcp->rawkcp->conv));
				rkcp->rawkcp->kcp->output((const char*)endpoint->buf->data, endpoint->buf->len, rkcp->rawkcp->kcp, rkcp->rawkcp->kcp->user);
				//TODO close rkcp?
				return;
			}

			nbytes = get_byte4(endpoint->buf->data + 12);
			rkcp->expect_recv_bytes = ntohl(nbytes);

			if (verbose) {
				printf("[close]: %s: conv[%u] get close fin rx_nbytes=%u\n", __func__, conv, rkcp->expect_recv_bytes);
			}

			if (rkcp->server) {
				server_t *server = rkcp->server;
				if (server->stage == STAGE_CLOSE) {
					return;
				}
				server->stage = STAGE_CLOSE;
				if (rkcp->expect_recv_bytes == rkcp->recv_bytes) {
					if (verbose) {
						printf("[close]: %s: conv[%u] tx:%u rx:%u @server\n", __func__, rkcp->conv, rkcp->send_bytes, rkcp->recv_bytes);
					}
					close_and_free_server(EV_A_ server);
					close_and_free_rawkcp(EV_A_ rkcp);
				} else {
					rkcp->send_stage = STAGE_RESET; //wait to close
					close_and_free_rawkcp(EV_A_ rkcp);
				}
				return;
			}
			if (rkcp->local) {
				local_t *local = rkcp->local;
				if (local->stage == STAGE_CLOSE) {
					return;
				}
				local->stage = STAGE_CLOSE;
				if (rkcp->expect_recv_bytes == rkcp->recv_bytes) {
					if (verbose) {
						printf("[close]: %s: conv[%u] tx:%u rx:%u @local\n", __func__, rkcp->conv, rkcp->send_bytes, rkcp->recv_bytes);
					}
					close_and_free_local(EV_A_ local);
					close_and_free_rawkcp(EV_A_ rkcp);
				} else {
					rkcp->send_stage = STAGE_RESET; //wait to close
					close_and_free_rawkcp(EV_A_ rkcp);
				}
				return;
			}
		} else {
			//unknown KTUN code
			printf("unknown KTUN code=0x%08x\n", cmd);
			//TODO
		}
	//end KTUN_P_MAGIC
	} else {
		int conv;
		rawkcp_t *rkcp;
		pipe_t *pipe;

		conv = ikcp_getconv(endpoint->buf->data);

		//printf("endpoint: recv msg: conv=%u from=%u.%u.%u.%u:%u\n", conv, NIPV4_ARG(addr.sin_addr.s_addr), ntohs(addr.sin_port));

		pipe = endpoint_peer_pipe_lookup(addr.sin_addr.s_addr, addr.sin_port);
		if (pipe == NULL) {
			if (verbose) {
				printf("[kcp] %s: conv[%u] endpoint_peer_pipe_lookup fail @=%u.%u.%u.%u:%u\n",
						__func__, conv, NIPV4_ARG(addr.sin_addr.s_addr), ntohs(addr.sin_port));
			}
			//send pipe reset
			do {
				endpoint_buffer_t *eb;

				eb = malloc(sizeof(endpoint_buffer_t));
				memset(eb, 0, sizeof(endpoint_buffer_t));

				eb->addr = addr.sin_addr.s_addr;
				eb->port = addr.sin_port;

				//[KTUN_P_MAGIC|0x10000003|reset-kcp-pipe|conv] reply reset-kcp
				eb->buf.idx = 0;
				eb->buf_len = eb->buf.len = 4 + 4 + 4;
				set_byte4(eb->buf.data, htonl(KTUN_P_MAGIC));
				set_byte4(eb->buf.data + 4, htonl(0x106b6370)); // reset kcp pipe
				set_byte4(eb->buf.data + 4 + 4, htonl(conv)); //conv

				dlist_add_tail(&eb->list, &endpoint->send_ctx->buf_head);

				ev_io_start(EV_A_ & endpoint->send_ctx->io);
			} while (0);
			return;
		}
		rkcp = rawkcp_lookup(conv, pipe->peer->id);
		if (rkcp == NULL) {
			int ret;
			rkcp = new_rawkcp(conv, pipe->peer->id);
			if (rkcp == NULL) {
				return;
			}
			rkcp->peer = get_peer(pipe->peer);
			rkcp->endpoint = endpoint;
			ret = rawkcp_insert(rkcp);
			if (ret != 0) {
				close_and_free_rawkcp(EV_A_ rkcp);
				return;
			}
			ev_timer_start(EV_A_ & rkcp->watcher);
		}

		if (rkcp->rawkcp) {
			//TODO forward rawkcp
			//conv NAT
			set_byte4(endpoint->buf->data, ikcp_encode32u_value(rkcp->rawkcp->conv));
			rkcp->rawkcp->kcp->output((const char*)endpoint->buf->data, endpoint->buf->len, rkcp->rawkcp->kcp, rkcp->rawkcp->kcp->user);
			return;
		}

		int ret = ikcp_input(rkcp->kcp, (const char *)endpoint->buf->data, endpoint->buf->len);
		if (ret < 0) {
			if (verbose) {
				printf("[kcp]: %s: conv[%u] ikcp_input failed [%d]\n", __func__, conv, ret);
			}
			return;
		}

		if (rkcp->server) {
			server_t *server = rkcp->server;
			if (rkcp->recv_stage == STAGE_INIT) {
				int len = ikcp_recv(rkcp->kcp, (char *)server->buf->data + server->buf->len, BUF_SIZE - server->buf->len);
				if (len < 0) {
					return;
				}
				server->buf->len += len;
				rkcp->recv_bytes += len;
				ev_timer_again(EV_A_ & server->watcher);

				if (server->buf->len >= 4) {
					if (get_byte4(server->buf->data) == htonl(KTUN_P_MAGIC)) {
						int opt = 0;
						setsockopt(server->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt)); //Disable TCP_NODELAY after the first response

						rkcp->recv_stage = STAGE_STREAM;
						server->buf->idx += 4;
						server->buf->len -= 4;
						rkcp->recv_bytes -= 4;
						if (server->buf->len > 0) {
							rkcp->recv_stage = STAGE_PAUSE;
							ev_io_start(EV_A_ & server->send_ctx->io); //start send_ctx
						} else {
							server->buf->idx = 0; //clear
						}
						rkcp->send_stage = STAGE_STREAM; //rkcp handshake ack ok, ready to send
						ev_io_start(EV_A_ & server->recv_ctx->io);
					} else {
						if (verbose) {
							printf("[close]: %s: conv[%u] tx:%u rx:%u @server: unexpected\n", __func__, rkcp->conv, rkcp->send_bytes, rkcp->recv_bytes);
						}
						close_and_free_server(EV_A_ server);
						close_and_free_rawkcp(EV_A_ rkcp);
						return;
					}
				} else {
					//wait for more data
					return;
				}
			}
			if (rkcp->recv_stage == STAGE_PAUSE || rkcp->recv_stage == STAGE_POLL) {
				return;
			}

			int n_recv = 0;
			do {
				int len = ikcp_recv(rkcp->kcp, (char *)server->buf->data + server->buf->len, BUF_SIZE - server->buf->len);
				if (len < 0) {
					return;
				}
				server->buf->len += len;
				rkcp->recv_bytes += len;
				ev_timer_again(EV_A_ & server->watcher);

				if (server->stage == STAGE_CLOSE) {
					if (rkcp->expect_recv_bytes == rkcp->recv_bytes) {
						rkcp->recv_stage = STAGE_CLOSE;
					}
				}
				if (++n_recv >= rkcp->kcp_max_poll) {
					rkcp->recv_stage = rkcp->recv_stage == STAGE_CLOSE ? STAGE_CLOSE : STAGE_PAUSE; //pause stream
					ev_io_start(EV_A_ & server->send_ctx->io); //start send_ctx
					return;
				}

				// has data to send
				ssize_t s = send(server->fd, server->buf->data + server->buf->idx, server->buf->len, 0);
				if (s == -1) {
					if (errno != EAGAIN && errno != EWOULDBLOCK) {
						if (verbose) {
							fprintf(stderr, "[close]: %s: conv[%u] tx:%u rx:%u @server on send: %s\n",
									__func__, rkcp->conv, rkcp->send_bytes, rkcp->recv_bytes, strerror(errno));
						}
						close_and_free_server(EV_A_ server);
						rkcp->send_stage = STAGE_CLOSE; //flush rkcp and close
						close_and_free_rawkcp(EV_A_ rkcp);
					} else {
						rkcp->recv_stage = rkcp->recv_stage == STAGE_CLOSE ? STAGE_CLOSE : STAGE_PAUSE; //pause stream
						ev_io_start(EV_A_ & server->send_ctx->io); //start send_ctx
					}
					return;
				} else if (s < server->buf->len) {
					// partly sent, move memory, wait for the next time to send
					server->buf->len -= s;
					server->buf->idx += s;
					rkcp->recv_stage = rkcp->recv_stage == STAGE_CLOSE ? STAGE_CLOSE : STAGE_PAUSE; //pause stream
					ev_io_start(EV_A_ & server->send_ctx->io); //start send_ctx
					return;
				} else {
					// all sent out, wait for reading
					server->buf->len = 0;
					server->buf->idx = 0;
				}
				if (rkcp->recv_stage == STAGE_CLOSE) {
					if (verbose) {
						printf("[close]: %s: conv[%u] tx:%u rx:%u @server stage close\n", __func__, rkcp->conv, rkcp->send_bytes, rkcp->recv_bytes);
					}
					close_and_free_server(EV_A_ server);
					close_and_free_rawkcp(EV_A_ rkcp);
				}
			} while (1);
			return;
		}

		if (rkcp->local) {
			local_t *local = rkcp->local;
			if (rkcp->recv_stage == STAGE_PAUSE || rkcp->recv_stage == STAGE_POLL) {
				return;
			}

			int n_recv = 0;
			do {
				int len = ikcp_recv(rkcp->kcp, (char *)local->buf->data + local->buf->len, BUF_SIZE - local->buf->len);
				if (len < 0) {
					return;
				}
				local->buf->len += len;
				rkcp->recv_bytes += len;
				ev_timer_again(EV_A_ & local->watcher);

				if (rkcp->recv_stage == STAGE_INIT || !local->send_ctx->connected) {
					rkcp->recv_stage = STAGE_PAUSE;
					ev_io_start(EV_A_ & local->send_ctx->io); //start send_ctx
					return;
				}
				if (local->stage == STAGE_CLOSE) {
					if (rkcp->expect_recv_bytes == rkcp->recv_bytes) {
						rkcp->recv_stage = STAGE_CLOSE;
					}
				}
				if (++n_recv >= rkcp->kcp_max_poll) {
					rkcp->recv_stage = rkcp->recv_stage == STAGE_CLOSE ? STAGE_CLOSE : STAGE_PAUSE; //pause stream
					ev_io_start(EV_A_ & local->send_ctx->io); //start send_ctx
					return;
				}

				// has data to send
				ssize_t s = send(local->fd, local->buf->data + local->buf->idx, local->buf->len, 0);
				if (s == -1) {
					if (errno != EAGAIN && errno != EWOULDBLOCK) {
						if (verbose) {
							fprintf(stderr, "[close]: %s: conv[%u] tx:%u rx:%u @local on send: %s\n",
									__func__, rkcp->conv, rkcp->send_bytes, rkcp->recv_bytes, strerror(errno));
						}
						close_and_free_local(EV_A_ local);
						rkcp->send_stage = STAGE_CLOSE; //flush rkcp and close
						close_and_free_rawkcp(EV_A_ rkcp);
					} else {
						rkcp->recv_stage = rkcp->recv_stage == STAGE_CLOSE ? STAGE_CLOSE : STAGE_PAUSE; //pause stream
						ev_io_start(EV_A_ & local->send_ctx->io); //start send_ctx
					}
					return;
				} else if (s < local->buf->len) {
					// partly sent, move memory, wait for the next time to send
					local->buf->len -= s;
					local->buf->idx += s;
					rkcp->recv_stage = rkcp->recv_stage == STAGE_CLOSE ? STAGE_CLOSE : STAGE_PAUSE; //pause stream
					ev_io_start(EV_A_ & local->send_ctx->io); //start send_ctx
					return;
				} else {
					// all sent out, wait for reading
					local->buf->len = 0;
					local->buf->idx = 0;
				}
				if (rkcp->recv_stage == STAGE_CLOSE) {
					if (verbose) {
						printf("[close]: %s: conv[%u] tx:%u rx:%u @local stage close\n", __func__, rkcp->conv, rkcp->send_bytes, rkcp->recv_bytes);
					}
					close_and_free_local(EV_A_ local);
					close_and_free_rawkcp(EV_A_ rkcp);
				}
			} while (1);
			return;
		}

		//new rkcp
		do {
			if (rkcp->buf->len >= BUF_SIZE) {
				return;
			}

			int len = ikcp_recv(rkcp->kcp, (char *)rkcp->buf->data + rkcp->buf->len, BUF_SIZE - rkcp->buf->len);
			if (len < 0) {
				return;
			}
			rkcp->buf->len += len;

			if (rkcp->buf->len >= 4 && get_byte4(rkcp->buf->data) == htonl(KTUN_P_MAGIC)) {
				__be32 remote_ip = 0;
				__be16 remote_port = 0;
				int n = 4;

				if (rkcp->buf->len >= n + 4 && get_byte2(rkcp->buf->data + n) == htons(HS_TARGET_IP)) {
					int len = ntohs(get_byte2(rkcp->buf->data + n + 2));
					if (len >= 4 && rkcp->buf->len >= n + len) {
						remote_ip = get_byte4(rkcp->buf->data + n + 4);
						n += (((len + 3)>>2)<<2);
					}
				}

				if (remote_ip == 0)
					return;

				if (rkcp->buf->len >= n + 4 && get_byte2(rkcp->buf->data + n) == htons(HS_TARGET_PORT)) {
					int len = ntohs(get_byte2(rkcp->buf->data + n + 2));
					if (len >= 4 && rkcp->buf->len >= n + len) {
						remote_port = get_byte2(rkcp->buf->data + n + 4);
						n += (((len + 3)>>2)<<2);
						rkcp->buf->idx += n; //eat the HS data
					}
				}

				if (remote_port != 0) {
					if (verbose) {
						printf("[handshake]: %s: conv[%u] @local new ip=%u.%u.%u.%u port=%u\n", __func__, conv, NIPV4_ARG(remote_ip), ntohs(remote_port));
					}
					local_t *local = connect_to_local(EV_A_ remote_ip, remote_port);
					if (local == NULL) {
						//printf("connect error\n");
						//TODO send close back?
						return;
					}
					local->rkcp = rkcp;
					rkcp->local = local;
					ev_timer_start(EV_A_ & local->watcher);

					//eat the data
					if (rkcp->buf->idx != rkcp->buf->len) {
						rkcp->recv_stage = STAGE_PAUSE; //pause stream
						memcpy(local->buf->data + local->buf->idx, rkcp->buf->data + rkcp->buf->idx, rkcp->buf->len - rkcp->buf->idx);
						local->buf->len += len;
						rkcp->buf->idx = 0;
						rkcp->buf->len = 0;
						ev_io_start(EV_A_ & local->send_ctx->io); //start send_ctx
					}

					//handshake send reply
					do {
						rkcp->buf->len = 0;
						set_byte4(rkcp->buf->data + rkcp->buf->len, htonl(KTUN_P_MAGIC));
						rkcp->buf->len += 4;

						int s = ikcp_send(rkcp->kcp, (const char *)rkcp->buf->data, rkcp->buf->len);
						rkcp->buf->len = 0; //clear after use
						if (s < 0) {
							perror("ikcp_send");
						}
					} while (0);

					//now ready to send
					//rkcp->send_stage = STAGE_STREAM;
					//ev_io_start(EV_A_ & local->recv_ctx->io);
				}
			}
		} while(0);
	}
}

static void endpoint_send_cb(EV_P_ ev_io *w, int revents)
{
	int count = 0;
	endpoint_ctx_t *endpoint_send_ctx = (endpoint_ctx_t *)w;
	endpoint_t *endpoint = endpoint_send_ctx->endpoint;
	endpoint_buffer_t *pos, *n;

	dlist_for_each_entry_safe(pos, n, &endpoint_send_ctx->buf_head, list) {
		ssize_t s;
		struct sockaddr_in addr;

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = pos->addr;
		addr.sin_port = pos->port;

		s = sendto(endpoint->fd, pos->buf.data + pos->buf.idx, pos->buf.len, 0, (const struct sockaddr *)&addr, sizeof(addr));
		if (s == -1) {
			//send fail
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				perror("remote_send_send");
				ev_io_stop(EV_A_ & endpoint_send_ctx->io);
				//send error
			}
			break;
		} else if (s < pos->buf.len) {
			pos->buf.len -= s;
			pos->buf.idx += s;
			//send part out
			break;
		} else {
			pos->buf.len = 0;
			pos->buf.idx = 0;
			//send out ok
		}

		dlist_del(&pos->list);
		endpoint_buffer_recycle(EV_A_ endpoint, pos);
		if (++count == 64)
			break;
	}

	if (dlist_empty(&endpoint_send_ctx->buf_head)) {
		//no buff to send
		ev_io_stop(EV_A_ & endpoint_send_ctx->io);
	}
}

static void endpoint_watcher_send_cb(EV_P_ ev_timer *watcher, int revents)
{
	IINT32 slap;
	int need_send = 0;
	endpoint_buffer_t *pos, *n;
	endpoint_t *endpoint = (endpoint_t *)watcher;

	if (endpoint->stage == STAGE_ERROR) {
		ltun_call_exit(EV_A);
		return;
	}

	slap = itimediff(iclock(), endpoint->active_ts);
	if (slap >= 40000 || slap <= -40000) {
		if ( (slap/1000 > -60 && slap/1000 < 60) || ((int)(slap/1000)%10 == 0)) {
			printf("[endpoint] no respose from ktun for %ds\n", slap/1000);
		}
	}

	dlist_for_each_entry_safe(pos, n, &endpoint->watcher_send_buf_head, list) {
		if (pos->interval > 0 && (endpoint->ticks % pos->interval) != 0) {
			continue;
		}
		dlist_del(&pos->list);
		dlist_add_tail(&pos->list, &endpoint->send_ctx->buf_head);
		need_send = 1;
	}

	endpoint->ticks++;

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
	struct sockaddr_in sa;
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

	if (s != 0 || result == NULL) {
		printf("getaddrinfo: %s\n", gai_strerror(s));
		goto try_inet_pton;
	}

	rp = result;

	addr = (struct sockaddr_in *)rp->ai_addr;

	*real_addr = addr->sin_addr.s_addr;
	*real_port = addr->sin_port;

	freeaddrinfo(result);

	return 0;

try_inet_pton:
	if (1 != inet_pton(AF_INET, host, &(sa.sin_addr))) {
		printf("inet_pton: fail to convert %s\n", host);
		return -1;
	}

	s = atoi(port);
	*real_port = htons(s);
	*real_addr = sa.sin_addr.s_addr;

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
		//setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
		setsockopt(listen_sock, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
		/* Set socket to allow broadcast */
		s = setsockopt(listen_sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
		if (s < 0) {
			perror("broadcast permission");
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

endpoint_t *new_endpoint(int fd, int broadcast_fd, int ktun_fd)
{
	endpoint_t *endpoint = malloc(sizeof(endpoint_t));
	memset(endpoint, 0, sizeof(endpoint_t));
	INIT_DLIST_HEAD(&endpoint->watcher_send_buf_head);
	INIT_HLIST_HEAD(&endpoint->rawkcp_head);

	endpoint->buf = malloc(sizeof(buffer_t));
	endpoint->buf->len = 0;
	endpoint->buf->idx = 0;

	endpoint->broadcast_recv_ctx = malloc(sizeof(endpoint_ctx_t));
	memset(endpoint->broadcast_recv_ctx, 0, sizeof(endpoint_ctx_t));
	INIT_DLIST_HEAD(&endpoint->broadcast_recv_ctx->buf_head);

	endpoint->recv_ctx = malloc(sizeof(endpoint_ctx_t));
	memset(endpoint->recv_ctx, 0, sizeof(endpoint_ctx_t));
	INIT_DLIST_HEAD(&endpoint->recv_ctx->buf_head);

	endpoint->send_ctx = malloc(sizeof(endpoint_ctx_t));
	memset(endpoint->send_ctx, 0, sizeof(endpoint_ctx_t));
	INIT_DLIST_HEAD(&endpoint->send_ctx->buf_head);

	endpoint->ktun_fd = ktun_fd;
	endpoint->broadcast_fd = broadcast_fd;
	endpoint->fd = fd;
	endpoint->broadcast_recv_ctx->endpoint = endpoint;
	endpoint->recv_ctx->endpoint = endpoint;
	endpoint->send_ctx->endpoint = endpoint;

	endpoint->active_ts = iclock();
	
	if (endpoint->ktun_fd != -1) {
		endpoint->ktun_recv_ctx = malloc(sizeof(endpoint_ctx_t));
		memset(endpoint->ktun_recv_ctx, 0, sizeof(endpoint_ctx_t));
		INIT_DLIST_HEAD(&endpoint->ktun_recv_ctx->buf_head);
		endpoint->ktun_recv_ctx->endpoint = endpoint;
		ev_io_init(&endpoint->ktun_recv_ctx->io, endpoint_ktun_recv_cb, endpoint->ktun_fd, EV_READ);
	}
	ev_io_init(&endpoint->broadcast_recv_ctx->io, endpoint_recv_cb, endpoint->broadcast_fd, EV_READ);
	ev_io_init(&endpoint->recv_ctx->io, endpoint_recv_cb, endpoint->fd, EV_READ);
	ev_io_init(&endpoint->send_ctx->io, endpoint_send_cb, endpoint->fd, EV_WRITE);

	ev_timer_init(&endpoint->watcher, endpoint_watcher_send_cb, 1.0, 1.0);

	return endpoint;
}

static void free_endpoint(endpoint_t *endpoint)
{
	if (endpoint->buf) {
		free(endpoint->buf);
	}
	free(endpoint->send_ctx);
	free(endpoint->recv_ctx);
	free(endpoint->broadcast_recv_ctx);
	if (endpoint->ktun_fd != -1) {
		free(endpoint->ktun_recv_ctx);
	}
	free(endpoint);
}

void close_and_free_endpoint(EV_P_ endpoint_t *endpoint)
{
	if (endpoint != NULL) {
		ev_io_stop(EV_A_ & endpoint->send_ctx->io);
		ev_io_stop(EV_A_ & endpoint->recv_ctx->io);
		ev_io_stop(EV_A_ & endpoint->broadcast_recv_ctx->io);
		ev_timer_stop(EV_A_ & endpoint->watcher);
		close(endpoint->fd);
		close(endpoint->broadcast_fd);
		if (endpoint->ktun_fd != -1) {
			ev_io_stop(EV_A_ & endpoint->ktun_recv_ctx->io);
			close(endpoint->ktun_fd);
		}
		do {
			endpoint_buffer_t *pos, *n;
			dlist_for_each_entry_safe(pos, n, &endpoint->watcher_send_buf_head, list) {
				dlist_del(&pos->list);
				free(pos);
			}
		} while (0);
		do {
			rawkcp_t *pos;
			struct hlist_node *n;
			hlist_for_each_entry_safe(pos, n, &endpoint->rawkcp_head, hnode) {
				hlist_del_init(&pos->hnode);
				pos->send_stage = STAGE_ERROR;
				close_and_free_rawkcp(EV_A_ pos);
			}
		} while (0);
		do {
			endpoint_buffer_t *pos, *n;
			/* XXX: we never use recv_ctx->buf_head
			dlist_for_each_entry_safe(pos, n, &endpoint->broadcast_recv_ctx->buf_head, list) {
				dlist_del(&pos->list);
				free(pos);
			}
			dlist_for_each_entry_safe(pos, n, &endpoint->recv_ctx->buf_head, list) {
				dlist_del(&pos->list);
				free(pos);
			}
			*/
			dlist_for_each_entry_safe(pos, n, &endpoint->send_ctx->buf_head, list) {
				dlist_del(&pos->list);
				free(pos);
			}
		} while (0);
		free_endpoint(endpoint);
	}
}

struct hlist_head *peer_hash = NULL;
unsigned int peer_hash_size = 1024;
static unsigned int peer_rnd = 0;

#define PAGE_SIZE 4096
#define UINT_MAX    (~0U)
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)

void *peer_alloc_hashtable(unsigned int *sizep)
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

int endpoint_peer_init(void)
{
	peer_rnd = random();
	peer_hash = peer_alloc_hashtable(&peer_hash_size);

	if (!peer_hash)
		return -1;

	return 0;
}

void endpoint_peer_exit(void)
{
	int i;
	for (i = 0; i < peer_hash_size; i++) {
		peer_t *pos;
		struct hlist_node *n;
		hlist_for_each_entry_safe(pos, n, &peer_hash[i], hnode) {
			hlist_del(&pos->hnode);
			free(pos);
		}
	}
}

peer_t *endpoint_peer_lookup(unsigned char *id)
{
	unsigned int hash;
	peer_t *pos;
	struct hlist_head *head;
	
	hash = jhash_2words(*(unsigned int *)&id[0], *(unsigned short *)&id[4], peer_rnd) % peer_hash_size;
	head = &peer_hash[hash];

	hlist_for_each_entry(pos, head, hnode) {
		if (memcmp(pos->id, id, 6) == 0) {
			return pos;
		}
	}

	return NULL;
}

int endpoint_peer_insert(peer_t *peer)
{
	unsigned int hash;
	peer_t *pos;
	struct hlist_head *head;
	
	hash = jhash_2words(get_byte4(&peer->id[0]), get_byte2(&peer->id[4]), peer_rnd) % peer_hash_size;
	head = &peer_hash[hash];

	hlist_for_each_entry(pos, head, hnode) {
		if (memcmp(pos->id, peer->id, 6) == 0) {
			//found
			return -1;
		}
	}

	hlist_add_head(&peer->hnode, head);

	return 0;
}

int endpoint_select_relay_id(const unsigned char *smac, const unsigned char *dmac, unsigned char *relay_id)
{
	int i;
	for (i = 0; i < peer_hash_size; i++) {
		peer_t *pos;
		struct hlist_node *n;
		hlist_for_each_entry_safe(pos, n, &peer_hash[i], hnode) {
			if (!id_is_eq(pos->id, smac) && !id_is_eq(pos->id, dmac)) {
				//TODO random select
				memcpy(relay_id, pos->id, 6);
				return 0;
			}
		}
	}

	return -1;
}

int endpoint_relay_to_peer(EV_P_ endpoint_t *endpoint, unsigned char *id)
{
	endpoint_buffer_t *eb;

	//send to ktun
	eb = malloc(sizeof(endpoint_buffer_t));
	memset(eb, 0, sizeof(endpoint_buffer_t));

	memcpy(eb->dmac, id, 6);
	eb->ptype = 2;
	eb->endpoint = endpoint;
	eb->repeat = 30;
	eb->addr = endpoint->ktun_addr;
	eb->port = endpoint->ktun_port;

	//[KTUN_P_MAGIC|0x00000006|smac|dmac] smac tell ktun I want relay to dmac
	eb->buf.idx = 0;
	eb->buf_len = eb->buf.len = 4 + 4 + 6 + 6;
	set_byte4(eb->buf.data, htonl(KTUN_P_MAGIC));
	set_byte4(eb->buf.data + 4, htonl(0x00000006));
	set_byte6(eb->buf.data + 4 + 4, endpoint->id); //smac
	set_byte6(eb->buf.data + 4 + 4 + 6, id); //dmac

	eb->recycle = default_eb_recycle;
	dlist_add_tail(&eb->list, &endpoint->send_ctx->buf_head);

	ev_io_start(EV_A_ & endpoint->send_ctx->io);

	return 0;
}

int endpoint_connect_to_peer(EV_P_ endpoint_t *endpoint, unsigned char *id)
{
	endpoint_buffer_t *eb;

	//send to ktun
	eb = malloc(sizeof(endpoint_buffer_t));
	memset(eb, 0, sizeof(endpoint_buffer_t));

	memcpy(eb->dmac, id, 6);
	eb->ptype = 1;
	eb->endpoint = endpoint;
	eb->repeat = 30;
	eb->addr = endpoint->ktun_addr;
	eb->port = endpoint->ktun_port;

	//[KTUN_P_MAGIC|0x00000002|smac|dmac] smac tell ktun I want to connect dmac
	eb->buf.idx = 0;
	eb->buf_len = eb->buf.len = 4 + 4 + 6 + 6;
	set_byte4(eb->buf.data, htonl(KTUN_P_MAGIC));
	set_byte4(eb->buf.data + 4, htonl(0x00000002));
	set_byte6(eb->buf.data + 4 + 4, endpoint->id); //smac
	set_byte6(eb->buf.data + 4 + 4 + 6, id); //dmac

	eb->recycle = default_eb_recycle;
	dlist_add_tail(&eb->list, &endpoint->send_ctx->buf_head);

	//send to broadcast
	eb = malloc(sizeof(endpoint_buffer_t));
	memset(eb, 0, sizeof(endpoint_buffer_t));

	memcpy(eb->dmac, id, 6);
	eb->ptype = 0;
	eb->endpoint = endpoint;
	eb->repeat = 30;
	eb->addr = endpoint->broadcast_addr;
	eb->port = endpoint->broadcast_port;

	//[KTUN_P_MAGIC|0x00000005|smac|dmac] smac broadcast I want to connect dmac
	eb->buf.idx = 0;
	eb->buf_len = eb->buf.len = 4 + 4 + 6 + 6;
	set_byte4(eb->buf.data, htonl(KTUN_P_MAGIC));
	set_byte4(eb->buf.data + 4, htonl(0x00000005));
	set_byte6(eb->buf.data + 4 + 4, endpoint->id); //smac
	set_byte6(eb->buf.data + 4 + 4 + 6, id); //dmac

	eb->recycle = default_eb_recycle;
	dlist_add_tail(&eb->list, &endpoint->send_ctx->buf_head);

	ev_io_start(EV_A_ & endpoint->send_ctx->io);

	return 0;
}

void endpoint_ktun_start(endpoint_t *endpoint)
{
	endpoint_buffer_t *eb;

	eb = malloc(sizeof(endpoint_buffer_t));
	memset(eb, 0, sizeof(endpoint_buffer_t));

	eb->endpoint = endpoint;
	eb->repeat = -1;
	eb->interval = 10;
	eb->recycle = default_eb_recycle;
	eb->addr = endpoint->ktun_addr;
	eb->port = endpoint->ktun_port;

	printf("init send to ktun=%u.%u.%u.%u:%u\n", NIPV4_ARG(eb->addr), ntohs(eb->port));

	//[KTUN_P_MAGIC|0x00000001|smac] smac tell ktun I ready here
	eb->buf.idx = 0;
	eb->buf_len = eb->buf.len = 4 + 4 + 6;
	set_byte4(eb->buf.data, htonl(KTUN_P_MAGIC));
	set_byte4(eb->buf.data + 4, htonl(0x00000001));
	set_byte6(eb->buf.data + 4 + 4, endpoint->id); //smac

	dlist_add_tail(&eb->list, &endpoint->watcher_send_buf_head);
}


struct hlist_head *peer_pipe_hash = NULL;
unsigned int peer_pipe_hash_size = 1024;
static unsigned int peer_pipe_rnd = 0;

#define PAGE_SIZE 4096
#define UINT_MAX    (~0U)
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)

void *peer_pipe_alloc_hashtable(unsigned int *sizep)
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

static void free_pipe(pipe_t *pipe)
{
	hlist_del_init(&pipe->hnode);
	free(pipe);
}

void close_and_free_pipe(EV_P_ pipe_t *pipe)
{
	if (pipe != NULL) {
		put_peer(pipe->peer);
		ev_timer_stop(EV_A_ & pipe->watcher);
		free_pipe(pipe);
	}
}

void peer_attach_pipe(peer_t *peer, pipe_t *pipe, int ptype)
{
	peer->pipe[ptype] = pipe;
}

void peer_detach_pipe(peer_t *peer, pipe_t *pipe)
{
	int ptype;
	for (ptype = 0; ptype <= 2; ptype++) {
		if (peer->pipe[ptype] == pipe) {
			peer->pipe[ptype] = NULL;
		}
	}
}

void pipe_timeout_call(EV_P_ pipe_t *pipe)
{
	if (pipe->stage == STAGE_STREAM) {
		peer_t *peer = pipe->peer;
		pipe->stage = STAGE_CLOSE;
		hlist_del_init(&pipe->hnode);
		peer_detach_pipe(peer, pipe);
		pipe->eb->repeat = 0;
		pipe->eb->interval = 0;

		if (verbose) {
			printf("[endpoint]: %s: pipe @=%u.%u.%u.%u:%u peer=%02X:%02X:%02X:%02X:%02X:%02X timeout detach\n",
					__func__,
					NIPV4_ARG(pipe->addr), ntohs(pipe->port),
					peer->id[0], peer->id[1], peer->id[2], peer->id[3], peer->id[4], peer->id[5]);
		}

		endpoint_connect_to_peer(EV_A_ peer->endpoint, peer->id);
		ev_timer_again(EV_A_ & pipe->watcher);
	} else {
		close_and_free_pipe(EV_A_ pipe);
	}
}

static void pipe_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
	pipe_t *pipe = container_of(watcher, pipe_t, watcher);
	pipe_timeout_call(EV_A_ pipe);
}

pipe_t *new_pipe(__be32 ip, __be16 port, peer_t *peer)
{
	pipe_t *pipe;

	pipe = malloc(sizeof(pipe_t));
	memset(pipe, 0, sizeof(pipe_t));
	INIT_HLIST_NODE(&pipe->hnode);
	pipe->addr = ip;
	pipe->port = port;
	pipe->peer = get_peer(peer);
	peer->use++;

	ev_timer_init(&pipe->watcher, pipe_timeout_cb, 30, 30);

	return pipe;
}

int endpoint_peer_pipe_init(void)
{
	peer_pipe_rnd = random();
	peer_pipe_hash = peer_pipe_alloc_hashtable(&peer_pipe_hash_size);

	if (!peer_pipe_hash)
		return -1;

	return 0;
}

void endpoint_peer_pipe_exit(void)
{
	int i;
	for (i = 0; i < peer_pipe_hash_size; i++) {
		pipe_t *pos;
		struct hlist_node *n;
		hlist_for_each_entry_safe(pos, n, &peer_pipe_hash[i], hnode) {
			hlist_del(&pos->hnode);
			free(pos);
		}
	}
}

pipe_t *endpoint_peer_pipe_select(peer_t *peer)
{
	int ptype = 0;
	do {
		if (peer->pipe[ptype])
			return peer->pipe[ptype];
	} while (++ptype <= 2);

	return NULL;
}

pipe_t *endpoint_peer_pipe_lookup(__be32 addr, __be16 port)
{
	unsigned int hash;
	pipe_t *pos;
	struct hlist_head *head;
	
	hash = jhash_2words(addr, port, peer_pipe_rnd) % peer_pipe_hash_size;
	head = &peer_pipe_hash[hash];

	hlist_for_each_entry(pos, head, hnode) {
		if (pos->addr == addr && pos->port == port) {
			return pos;
		}
	}

	return NULL;
}

int endpoint_peer_pipe_insert(pipe_t *pipe)
{
	unsigned int hash;
	pipe_t *pos;
	struct hlist_head *head;
	
	hash = jhash_2words(pipe->addr, pipe->port, peer_pipe_rnd) % peer_pipe_hash_size;
	head = &peer_pipe_hash[hash];

	hlist_for_each_entry(pos, head, hnode) {
		if (pos->addr == pipe->addr && pos->port == pipe->port) {
			//found
			return -1;
		}
	}

	hlist_add_head(&pipe->hnode, head);

	return 0;
}

endpoint_t *endpoint_init(EV_P_ const unsigned char *id,
		const char *ktun, const char *ktun_port,
		const char *bktun, const char *bktun_port,
		int ktun_sever)
{
	int fd;
	int bktun_fd;
	int ktun_fd = -1;
	endpoint_t *endpoint;

	fd = endpoint_create_fd("0.0.0.0", "0");
	if (fd == -1) {
		return NULL;
	}
	setnonblocking(fd);

	bktun_fd = endpoint_create_fd("0.0.0.0", bktun_port);
	if (bktun_fd == -1) {
		close(fd);
		return NULL;
	}
	setnonblocking(bktun_fd);

	if (ktun_sever) {
		ktun_fd = endpoint_create_fd("0.0.0.0", ktun_port);
		if (ktun_fd == -1) {
			close(bktun_fd);
			close(fd);
			return NULL;
		}
		setnonblocking(ktun_fd);
	}

	endpoint = new_endpoint(fd, bktun_fd, ktun_fd);
	if (endpoint == NULL) {
		close(bktun_fd);
		close(fd);
		return NULL;
	}

	memcpy(endpoint->id, id, 6);

	if (endpoint_getaddrinfo(ktun, ktun_port, &endpoint->ktun_addr, &endpoint->ktun_port) != 0) {
		close_and_free_endpoint(EV_A_ endpoint);
		return NULL;
	}
	if (endpoint_getaddrinfo(bktun, bktun_port, &endpoint->broadcast_addr, &endpoint->broadcast_port) != 0) {
		close_and_free_endpoint(EV_A_ endpoint);
		return NULL;
	}
	endpoint_ktun_start(endpoint);

	return endpoint;
}
