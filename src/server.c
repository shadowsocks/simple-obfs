/*
 * server.c - Provide simple-obfs service
 *
 * Copyright (C) 2013 - 2016, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the simple-obfs.
 *
 * simple-obfs is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * simple-obfs is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with simple-obfs; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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

#ifndef __MINGW32__
#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/un.h>
#endif

#include <libcork/core.h>

#ifdef __MINGW32__
#include "win32.h"
#endif

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include "netutils.h"
#include "utils.h"
#include "obfs_http.h"
#include "obfs_tls.h"
#include "options.h"
#include "server.h"

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#ifndef BUF_SIZE
#define BUF_SIZE 16384
#endif

#ifndef SSMAXCONN
#define SSMAXCONN 1024
#endif

static void signal_cb(EV_P_ ev_signal *w, int revents);
static void accept_cb(EV_P_ ev_io *w, int revents);
static void server_send_cb(EV_P_ ev_io *w, int revents);
static void server_recv_cb(EV_P_ ev_io *w, int revents);
static void remote_recv_cb(EV_P_ ev_io *w, int revents);
static void remote_send_cb(EV_P_ ev_io *w, int revents);
static void server_timeout_cb(EV_P_ ev_timer *watcher, int revents);

static void perform_handshake(EV_P_ server_t *server);
static remote_t *new_remote(int fd);
static server_t *new_server(int fd, listen_ctx_t *listener);
static remote_t *connect_to_remote(EV_P_ struct addrinfo *res,
                                   server_t *server);

static void free_remote(remote_t *remote);
static void close_and_free_remote(EV_P_ remote_t *remote);
static void free_server(server_t *server);
static void close_and_free_server(EV_P_ server_t *server);

int verbose = 0;

static int ipv6first = 0;
static int reverse_proxy = 0;
static int fast_open = 0;

static obfs_para_t *obfs_para = NULL;

#ifdef HAVE_SETRLIMIT
static int nofile = 0;
#endif
static int remote_conn = 0;
static int server_conn = 0;

static char *bind_address    = NULL;
static char *server_port     = NULL;
uint64_t tx                  = 0;
uint64_t rx                  = 0;

static struct cork_dllist connections;

#ifndef __MINGW32__
static void
parent_watcher_cb(EV_P_ ev_timer *watcher, int revents)
{
    static int ppid = -1;

    int cur_ppid = getppid();
    if (ppid != -1) {
        if (ppid != cur_ppid) {
            ev_unloop(EV_A_ EVUNLOOP_ALL);
        }
    }

    ppid = cur_ppid;
}
#endif

static void
free_connections(struct ev_loop *loop)
{
    struct cork_dllist_item *curr, *next;
    cork_dllist_foreach_void(&connections, curr, next) {
        server_t *server = cork_container_of(curr, server_t, entries);
        remote_t *remote = server->remote;
        close_and_free_server(loop, server);
        close_and_free_remote(loop, remote);
    }
}

int
setfastopen(int fd)
{
    int s = 0;
#ifdef TCP_FASTOPEN
    if (fast_open) {
#if defined(__APPLE__) || defined(__MINGW32__)
        int opt = 1;
#else
        int opt = 5;
#endif
        s = setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &opt, sizeof(opt));

        if (s == -1) {
            if (errno == EPROTONOSUPPORT || errno == ENOPROTOOPT) {
                LOGE("fast open is not supported on this platform");
                fast_open = 0;
            } else {
                ERROR("setsockopt");
            }
        }
    }
#endif
    return s;
}

#ifndef __MINGW32__
int
setnonblocking(int fd)
{
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

#endif

int
create_and_bind(const char *host, const char *port, int mptcp)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp, *ipv4v6bindall;
    int s, listen_sock;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_UNSPEC;               /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM;             /* We want a TCP socket */
    hints.ai_flags    = AI_PASSIVE | AI_ADDRCONFIG; /* For wildcard IP address */
    hints.ai_protocol = IPPROTO_TCP;

    for (int i = 1; i < 8; i++) {
        s = getaddrinfo(host, port, &hints, &result);
        if (s == 0) {
            break;
        } else {
            sleep(pow(2, i));
            LOGE("failed to resolve server name, wait %.0f seconds", pow(2, i));
        }
    }

    if (s != 0) {
        LOGE("getaddrinfo: %s", gai_strerror(s));
        return -1;
    }

    rp = result;

    /*
     * On Linux, with net.ipv6.bindv6only = 0 (the default), getaddrinfo(NULL) with
     * AI_PASSIVE returns 0.0.0.0 and :: (in this order). AI_PASSIVE was meant to
     * return a list of addresses to listen on, but it is impossible to listen on
     * 0.0.0.0 and :: at the same time, if :: implies dualstack mode.
     */
    if (!host) {
        ipv4v6bindall = result;

        /* Loop over all address infos found until a IPV6 address is found. */
        while (ipv4v6bindall) {
            if (ipv4v6bindall->ai_family == AF_INET6) {
                rp = ipv4v6bindall; /* Take first IPV6 address available */
                break;
            }
            ipv4v6bindall = ipv4v6bindall->ai_next; /* Get next address info, if any */
        }
    }

    for (/*rp = result*/; rp != NULL; rp = rp->ai_next) {
        listen_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listen_sock == -1) {
            continue;
        }

        if (rp->ai_family == AF_INET6) {
            int ipv6only = host ? 1 : 0;
            setsockopt(listen_sock, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only));
        }

        int opt = 1;
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
        setsockopt(listen_sock, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
        int err = set_reuseport(listen_sock);
        if (err == 0) {
            LOGI("tcp port reuse enabled");
        }

        if (mptcp == 1) {
            int err = setsockopt(listen_sock, SOL_TCP, MPTCP_ENABLED, &opt, sizeof(opt));
            if (err == -1) {
                ERROR("failed to enable multipath TCP");
            }
        }

        s = bind(listen_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            /* We managed to bind successfully! */
            break;
        } else {
            ERROR("bind");
        }

        close(listen_sock);
    }

    if (rp == NULL) {
        LOGE("Could not bind");
        return -1;
    }

    freeaddrinfo(result);

    return listen_sock;
}

static remote_t *
connect_to_remote(EV_P_ struct addrinfo *res,
                  server_t *server)
{
    int sockfd;
#ifdef SET_INTERFACE
    const char *iface = server->listen_ctx->iface;
#endif

    // initialize remote socks
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd == -1) {
        ERROR("socket");
        close(sockfd);
        return NULL;
    }

    int opt = 1;
    setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // setup remote socks

    if (setnonblocking(sockfd) == -1)
        ERROR("setnonblocking");

    if (bind_address != NULL)
        if (bind_to_address(sockfd, bind_address) == -1) {
            ERROR("bind_to_address");
            close(sockfd);
            return NULL;
        }

#ifdef SET_INTERFACE
    if (iface) {
        if (setinterface(sockfd, iface) == -1) {
            ERROR("setinterface");
            close(sockfd);
            return NULL;
        }
    }
#endif

    remote_t *remote = new_remote(sockfd);

#ifdef TCP_FASTOPEN
    if (fast_open) {
#ifdef __APPLE__
        ((struct sockaddr_in *)(res->ai_addr))->sin_len = sizeof(struct sockaddr_in);
        sa_endpoints_t endpoints;
        memset((char *)&endpoints, 0, sizeof(endpoints));
        endpoints.sae_dstaddr    = res->ai_addr;
        endpoints.sae_dstaddrlen = res->ai_addrlen;

        struct iovec iov;
        iov.iov_base = server->buf->data + server->buf->idx;
        iov.iov_len  = server->buf->len;
        size_t len;
        int s = connectx(sockfd, &endpoints, SAE_ASSOCID_ANY, CONNECT_DATA_IDEMPOTENT,
                         &iov, 1, &len, NULL);
        if (s == 0) {
            s = len;
        }
#elif defined(TCP_FASTOPEN_WINSOCK)
        DWORD s = -1;
        DWORD err = 0;
        do {
            int optval = 1;
            // Set fast open option
            if (setsockopt(sockfd, IPPROTO_TCP, TCP_FASTOPEN,
                           &optval, sizeof(optval)) != 0) {
                ERROR("setsockopt");
                break;
            }
            // Load ConnectEx function
            LPFN_CONNECTEX ConnectEx = winsock_getconnectex();
            if (ConnectEx == NULL) {
                LOGE("Cannot load ConnectEx() function");
                err = WSAENOPROTOOPT;
                break;
            }
            // ConnectEx requires a bound socket
            if (winsock_dummybind(sockfd, res->ai_addr) != 0) {
                ERROR("bind");
                break;
            }
            // Call ConnectEx to send data
            memset(&remote->olap, 0, sizeof(remote->olap));
            remote->connect_ex_done = 0;
            if (ConnectEx(sockfd, res->ai_addr, res->ai_addrlen,
                          server->buf->data, server->buf->len,
                          &s, &remote->olap)) {
                remote->connect_ex_done = 1;
                break;
            };
            // XXX: ConnectEx pending, check later in remote_send
            if (WSAGetLastError() == ERROR_IO_PENDING) {
                err = CONNECT_IN_PROGRESS;
                break;
            }
            ERROR("ConnectEx");
        } while(0);
        // Set error number
        if (err) {
            SetLastError(err);
        }
#else
        ssize_t s = sendto(sockfd, server->buf->data + server->buf->idx,
                           server->buf->len, MSG_FASTOPEN, res->ai_addr,
                           res->ai_addrlen);
#endif
        if (s == -1) {
            if (errno == CONNECT_IN_PROGRESS || errno == EAGAIN
                || errno == EWOULDBLOCK) {
                // The remote server doesn't support tfo or it's the first connection to the server.
                // It will automatically fall back to conventional TCP.
            } else if (errno == EOPNOTSUPP || errno == EPROTONOSUPPORT ||
                       errno == ENOPROTOOPT) {
                // Disable fast open as it's not supported
                fast_open = 0;
                LOGE("fast open is not supported on this platform");
            } else {
                ERROR("sendto");
            }
        } else if (s <= server->buf->len) {
            server->buf->idx += s;
            server->buf->len -= s;
        } else {
            server->buf->idx = 0;
            server->buf->len = 0;
        }
    }
#endif

    if (!fast_open) {
        int r = connect(sockfd, res->ai_addr, res->ai_addrlen);

        if (r == -1 && errno != CONNECT_IN_PROGRESS) {
            ERROR("connect");
            close_and_free_remote(EV_A_ remote);
            return NULL;
        }
    }

    return remote;
}

static void
perform_handshake(EV_P_ server_t *server)
{
    // Copy back the saved first packet
    server->buf->len = server->header_buf->len;
    server->buf->idx = server->header_buf->idx;
    memcpy(server->buf->data, server->header_buf->data, server->header_buf->len);
    server->header_buf->idx = server->header_buf->len = 0;

    struct addrinfo info;
    struct sockaddr_storage storage;
    memset(&info, 0, sizeof(struct addrinfo));
    memset(&storage, 0, sizeof(struct sockaddr_storage));

    // Domain name
    size_t name_len = strlen(server->listen_ctx->dst_addr->host);
    char *host = server->listen_ctx->dst_addr->host;
    uint16_t port = htons((uint16_t)atoi(server->listen_ctx->dst_addr->port));

    if (obfs_para == NULL || !obfs_para->is_enable(server->obfs)) {
        if (server->listen_ctx->failover->host != NULL
                && server->listen_ctx->failover->port != NULL) {
            name_len = strlen(server->listen_ctx->failover->host);
            host = server->listen_ctx->failover->host;
            port = htons((uint16_t)atoi(server->listen_ctx->failover->port));
        }
    }

    struct cork_ip ip;
    if (cork_ip_init(&ip, host) != -1) {
        if (ip.version == 4) {
            struct sockaddr_in *addr = (struct sockaddr_in *)&storage;
            inet_pton(AF_INET, host, &(addr->sin_addr));
            addr->sin_port   = port;
            addr->sin_family = AF_INET;
        } else if (ip.version == 6) {
            struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&storage;
            inet_pton(AF_INET6, host, &(addr->sin6_addr));
            addr->sin6_port   = port;
            addr->sin6_family = AF_INET6;
        }
    } else {
        if (!validate_hostname(host, name_len)) {
            LOGE("invalid host name");
            close_and_free_server(EV_A_ server);
            return;
        }
        char tmp_port[16];
        snprintf(tmp_port, 16, "%d", ntohs(port));
        if (get_sockaddr(host, tmp_port, &storage, 0, ipv6first) == -1) {
            LOGE("failed to resolve the provided hostname");
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    info.ai_socktype = SOCK_STREAM;
    info.ai_protocol = IPPROTO_TCP;

    if (storage.ss_family == AF_INET) {
        info.ai_family   = AF_INET;
        info.ai_addrlen  = sizeof(struct sockaddr_in);
        info.ai_addr     = (struct sockaddr *)&storage;
    } else if (storage.ss_family == AF_INET6) {
        info.ai_family   = AF_INET6;
        info.ai_addrlen  = sizeof(struct sockaddr_in6);
        info.ai_addr     = (struct sockaddr *)&storage;
    } else {
        LOGE("failed to resolve the provided hostname");
        close_and_free_server(EV_A_ server);
        return;
    }

    if (verbose) {
        LOGI("connect to %s:%d", host, ntohs(port));
    }

    remote_t *remote = connect_to_remote(EV_A_ & info, server);

    if (remote == NULL) {
        LOGE("connect error");
        close_and_free_server(EV_A_ server);
        return;
    } else {
        server->remote = remote;
        remote->server = server;

        // XXX: should handle buffer carefully
        if (server->buf->len > 0) {
            memcpy(remote->buf->data, server->buf->data, server->buf->len);
            remote->buf->len = server->buf->len;
            remote->buf->idx = 0;
            server->buf->len = 0;
            server->buf->idx = 0;
        }

        // waiting on remote connected event
        ev_io_start(EV_A_ & remote->send_ctx->io);
    }

    return;
}

static void
server_recv_cb(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server              = server_recv_ctx->server;
    remote_t *remote              = NULL;

    int len       = server->buf->len;
    buffer_t *buf = server->buf;

    if (server->stage > STAGE_PARSE) {
        remote = server->remote;
        buf    = remote->buf;
        len    = 0;

        ev_timer_again(EV_A_ & server->recv_ctx->watcher);
    }

    if (len > BUF_SIZE) {
        ERROR("out of recv buffer");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    }

    ssize_t r = recv(server->fd, buf->data + len, BUF_SIZE - len, 0);

    if (r == 0) {
        // connection closed
        if (verbose) {
            LOGI("server_recv close the connection");
        }
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("server recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    tx += r;

    // handle incomplete header part 1
    if (server->stage == STAGE_INIT) {
        buf->len += r;

        if (obfs_para && obfs_para->is_enable(server->obfs)) {
            int ret = obfs_para->check_obfs(buf);
            if (ret == OBFS_NEED_MORE) {
                return;
            } else if (ret == OBFS_OK) {
                // obfs is enabled
                ret = obfs_para->deobfs_request(buf, BUF_SIZE, server->obfs);
                if (ret == OBFS_NEED_MORE)
                    return;
                else if (ret == OBFS_ERROR)
                    obfs_para->disable(server->obfs);
            } else {
                obfs_para->disable(server->obfs);
            }
        }

        server->stage = STAGE_HANDSHAKE;
        ev_io_stop(EV_A_ & server->recv_ctx->io);

        // Copy the first packet to the currently unused header_buf.
        server->header_buf->len = server->buf->len - server->buf->idx;
        server->header_buf->idx = 0;
        memcpy(server->header_buf->data, server->buf->data + server->buf->idx, server->header_buf->len);
        if (reverse_proxy && obfs_para->send_empty_response_upon_connection) {
            // Clear the buffer to make an empty packet.
            server->buf->len = 0;

            if (obfs_para) {
                obfs_para->obfs_response(server->buf, BUF_SIZE, server->obfs);
            }

            int s = send(server->fd, server->buf->data, server->buf->len, 0);

            if (s == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // no data, wait for send
                    server->buf->idx = 0;
                    ev_io_start(EV_A_ & server->send_ctx->io);
                    return;
                } else {
                    ERROR("send_inital_response");
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                }
            } else if (s < server->buf->len) {
                server->buf->len -= s;
                server->buf->idx  = s;
                ev_io_start(EV_A_ & server->send_ctx->io);
                return;
            } else {
                server->buf->len = 0;
                server->buf->idx = 0;
            }
        }

        perform_handshake(EV_A_ server);
        return;
    } else {
        buf->len = r;
        if (obfs_para) {
            int ret = obfs_para->deobfs_request(buf, BUF_SIZE, server->obfs);
            if (ret) LOGE("invalid obfuscating");
        }
    }

    // handshake and transmit data
    if (server->stage == STAGE_STREAM) {

        int s = send(remote->fd, remote->buf->data, remote->buf->len, 0);
        if (s == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // no data, wait for send
                remote->buf->idx = 0;
                ev_io_stop(EV_A_ & server_recv_ctx->io);
                ev_io_start(EV_A_ & remote->send_ctx->io);
            } else {
                ERROR("server_recv_send");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
        } else if (s < remote->buf->len) {
            remote->buf->len -= s;
            remote->buf->idx  = s;
            ev_io_stop(EV_A_ & server_recv_ctx->io);
            ev_io_start(EV_A_ & remote->send_ctx->io);
        }
        return;

    }
    // should not reach here
    FATAL("server context error");
}

static void
server_send_cb(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_send_ctx = (server_ctx_t *)w;
    server_t *server              = server_send_ctx->server;
    remote_t *remote              = server->remote;

    if (remote == NULL) {
        LOGE("invalid server");
        close_and_free_server(EV_A_ server);
        return;
    }

    if (server->buf->len == 0) {
        // close and free
        if (verbose) {
            LOGI("server_send close the connection");
        }
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(server->fd, server->buf->data + server->buf->idx,
                         server->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("server_send_send");
                close_and_free_remote(EV_A_ remote);
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

            // If handshaking
            if (server->stage == STAGE_HANDSHAKE) {
                perform_handshake(EV_A_ server);
                return;
            } else { // If streaming
                if (remote != NULL) {
                    ev_io_start(EV_A_ & remote->recv_ctx->io);
                    return;
                } else {
                    LOGE("invalid remote");
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                }
            }
        }
    }
}

static void
server_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
    server_ctx_t *server_ctx
        = cork_container_of(watcher, server_ctx_t, watcher);
    server_t *server = server_ctx->server;
    remote_t *remote = server->remote;

    if (verbose) {
        LOGI("TCP connection timeout");
    }

    close_and_free_remote(EV_A_ remote);
    close_and_free_server(EV_A_ server);
}

static void
remote_recv_cb(EV_P_ ev_io *w, int revents)
{
    remote_ctx_t *remote_recv_ctx = (remote_ctx_t *)w;
    remote_t *remote              = remote_recv_ctx->remote;
    server_t *server              = remote->server;

    if (server == NULL) {
        LOGE("invalid server");
        close_and_free_remote(EV_A_ remote);
        return;
    }

    ev_timer_again(EV_A_ & server->recv_ctx->watcher);

    ssize_t r = recv(remote->fd, server->buf->data, BUF_SIZE, 0);

    if (r == 0) {
        // connection closed
        if (verbose) {
            LOGI("remote_recv close the connection");
        }
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("remote recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    rx += r;

    server->buf->len = r;

    if (obfs_para) {
        obfs_para->obfs_response(server->buf, BUF_SIZE, server->obfs);
    }

    int s = send(server->fd, server->buf->data, server->buf->len, 0);

    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            server->buf->idx = 0;
            ev_io_stop(EV_A_ & remote_recv_ctx->io);
            ev_io_start(EV_A_ & server->send_ctx->io);
        } else {
            ERROR("remote_recv_send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    } else if (s < server->buf->len) {
        server->buf->len -= s;
        server->buf->idx  = s;
        ev_io_stop(EV_A_ & remote_recv_ctx->io);
        ev_io_start(EV_A_ & server->send_ctx->io);
    }

    // Disable TCP_NODELAY after the first response are sent
    if (!remote->recv_ctx->connected) {
        int opt = 0;
        setsockopt(server->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
        setsockopt(remote->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
        remote->recv_ctx->connected = 1;
    }
}

static void
remote_send_cb(EV_P_ ev_io *w, int revents)
{
    remote_ctx_t *remote_send_ctx = (remote_ctx_t *)w;
    remote_t *remote              = remote_send_ctx->remote;
    server_t *server              = remote->server;

    if (server == NULL) {
        LOGE("invalid server");
        close_and_free_remote(EV_A_ remote);
        return;
    }

    if (!remote_send_ctx->connected) {
#ifdef TCP_FASTOPEN_WINSOCK
        if (fast_open) {
            // Check if ConnectEx is done
            if (!remote->connect_ex_done) {
                DWORD numBytes;
                DWORD flags;
                // Non-blocking way to fetch ConnectEx result
                if (WSAGetOverlappedResult(remote->fd, &remote->olap,
                                           &numBytes, FALSE, &flags)) {
                    remote->buf->len -= numBytes;
                    remote->buf->idx  = numBytes;
                    remote->connect_ex_done = 1;
                } else if (WSAGetLastError() == WSA_IO_INCOMPLETE) {
                    // XXX: ConnectEx still not connected, wait for next time
                    return;
                } else {
                    ERROR("WSAGetOverlappedResult");
                    // not connected
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                };
            }

            // Make getpeername work
            if (setsockopt(remote->fd, SOL_SOCKET,
                           SO_UPDATE_CONNECT_CONTEXT, NULL, 0) != 0) {
                ERROR("setsockopt");
            }
        }
#endif
        struct sockaddr_storage addr;
        socklen_t len = sizeof(struct sockaddr_storage);
        memset(&addr, 0, len);
        int r = getpeername(remote->fd, (struct sockaddr *)&addr, &len);
        if (r == 0) {
            if (verbose) {
                LOGI("remote connected");
            }
            remote_send_ctx->connected = 1;

            if (remote->buf->len == 0) {
                server->stage = STAGE_STREAM;
                ev_io_stop(EV_A_ & remote_send_ctx->io);
                ev_io_start(EV_A_ & server->recv_ctx->io);
                ev_io_start(EV_A_ & remote->recv_ctx->io);
                return;
            }
        } else {
            ERROR("getpeername");
            // not connected
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    if (remote->buf->len == 0) {
        // close and free
        if (verbose) {
            LOGI("remote_send close the connection");
        }
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(remote->fd, remote->buf->data + remote->buf->idx,
                         remote->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("remote_send_send");
                // close and free
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < remote->buf->len) {
            // partly sent, move memory, wait for the next time to send
            remote->buf->len -= s;
            remote->buf->idx += s;
            return;
        } else {
            // all sent out, wait for reading
            remote->buf->len = 0;
            remote->buf->idx = 0;
            ev_io_stop(EV_A_ & remote_send_ctx->io);
            if (server != NULL) {
                ev_io_start(EV_A_ & server->recv_ctx->io);
                if (server->stage != STAGE_STREAM) {
                    server->stage = STAGE_STREAM;
                    ev_io_start(EV_A_ & remote->recv_ctx->io);
                }
            } else {
                LOGE("invalid server");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        }
    }
}

static remote_t *
new_remote(int fd)
{
    if (verbose) {
        remote_conn++;
    }

    remote_t *remote = ss_malloc(sizeof(remote_t));
    memset(remote, 0, sizeof(remote_t));

    remote->recv_ctx = ss_malloc(sizeof(remote_ctx_t));
    remote->send_ctx = ss_malloc(sizeof(remote_ctx_t));
    remote->buf      = ss_malloc(sizeof(buffer_t));
    balloc(remote->buf, BUF_SIZE);
    memset(remote->recv_ctx, 0, sizeof(remote_ctx_t));
    memset(remote->send_ctx, 0, sizeof(remote_ctx_t));
    remote->fd                  = fd;
    remote->recv_ctx->remote    = remote;
    remote->recv_ctx->connected = 0;
    remote->send_ctx->remote    = remote;
    remote->send_ctx->connected = 0;
    remote->server              = NULL;

    ev_io_init(&remote->recv_ctx->io, remote_recv_cb, fd, EV_READ);
    ev_io_init(&remote->send_ctx->io, remote_send_cb, fd, EV_WRITE);

    return remote;
}

static void
free_remote(remote_t *remote)
{
    if (remote->server != NULL) {
        remote->server->remote = NULL;
    }
    if (remote->buf != NULL) {
        bfree(remote->buf);
        ss_free(remote->buf);
    }
    ss_free(remote->recv_ctx);
    ss_free(remote->send_ctx);
    ss_free(remote);
}

static void
close_and_free_remote(EV_P_ remote_t *remote)
{
    if (remote != NULL) {
        ev_io_stop(EV_A_ & remote->send_ctx->io);
        ev_io_stop(EV_A_ & remote->recv_ctx->io);
        close(remote->fd);
        free_remote(remote);
        if (verbose) {
            remote_conn--;
            LOGI("current remote connection: %d", remote_conn);
        }
    }
}

static server_t *
new_server(int fd, listen_ctx_t *listener)
{
    if (verbose) {
        server_conn++;
    }

    server_t *server;
    server = ss_malloc(sizeof(server_t));

    memset(server, 0, sizeof(server_t));

    server->recv_ctx   = ss_malloc(sizeof(server_ctx_t));
    server->send_ctx   = ss_malloc(sizeof(server_ctx_t));
    server->buf        = ss_malloc(sizeof(buffer_t));
    server->header_buf = ss_malloc(sizeof(buffer_t));
    memset(server->recv_ctx, 0, sizeof(server_ctx_t));
    memset(server->send_ctx, 0, sizeof(server_ctx_t));
    balloc(server->buf, BUF_SIZE);
    balloc(server->header_buf, BUF_SIZE);
    server->fd                  = fd;
    server->recv_ctx->server    = server;
    server->recv_ctx->connected = 0;
    server->send_ctx->server    = server;
    server->send_ctx->connected = 0;
    server->stage               = STAGE_INIT;
    server->listen_ctx          = listener;
    server->remote              = NULL;

    if (obfs_para != NULL) {
        server->obfs = (obfs_t *)ss_malloc(sizeof(obfs_t));
        memset(server->obfs, 0, sizeof(obfs_t));
    }

    int request_timeout = min(MAX_REQUEST_TIMEOUT, listener->timeout)
                          + rand() % MAX_REQUEST_TIMEOUT;

    ev_io_init(&server->recv_ctx->io, server_recv_cb, fd, EV_READ);
    ev_io_init(&server->send_ctx->io, server_send_cb, fd, EV_WRITE);
    ev_timer_init(&server->recv_ctx->watcher, server_timeout_cb,
                  request_timeout, listener->timeout);

    cork_dllist_add(&connections, &server->entries);

    return server;
}

static void
free_server(server_t *server)
{
    cork_dllist_remove(&server->entries);

    if (server->obfs != NULL) {
        bfree(server->obfs->buf);
        if (server->obfs->extra != NULL)
            ss_free(server->obfs->extra);
        ss_free(server->obfs);
    }
    if (server->remote != NULL) {
        server->remote->server = NULL;
    }
    if (server->buf != NULL) {
        bfree(server->buf);
        ss_free(server->buf);
    }
    if (server->header_buf != NULL) {
        bfree(server->header_buf);
        ss_free(server->header_buf);
    }

    ss_free(server->recv_ctx);
    ss_free(server->send_ctx);
    ss_free(server);
}

static void
close_and_free_server(EV_P_ server_t *server)
{
    if (server != NULL) {
        ev_io_stop(EV_A_ & server->send_ctx->io);
        ev_io_stop(EV_A_ & server->recv_ctx->io);
        ev_timer_stop(EV_A_ & server->recv_ctx->watcher);
        close(server->fd);
        free_server(server);
        if (verbose) {
            server_conn--;
            LOGI("current server connection: %d", server_conn);
        }
    }
}

static void
signal_cb(EV_P_ ev_signal *w, int revents)
{
    if (revents & EV_SIGNAL) {
        switch (w->signum) {
        case SIGINT:
        case SIGTERM:
            ev_unloop(EV_A_ EVUNLOOP_ALL);
        }
    }
}

static void
accept_cb(EV_P_ ev_io *w, int revents)
{
    listen_ctx_t *listener = (listen_ctx_t *)w;
    int serverfd           = accept(listener->fd, NULL, NULL);
    if (serverfd == -1) {
        ERROR("accept");
        return;
    }

    int opt = 1;
    setsockopt(serverfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(serverfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
    setnonblocking(serverfd);

    if (verbose) {
        LOGI("accept a connection");
    }

    server_t *server = new_server(serverfd, listener);
    ev_io_start(EV_A_ & server->recv_ctx->io);
    ev_timer_start(EV_A_ & server->recv_ctx->watcher);
}

int
main(int argc, char **argv)
{
    int i, c;
    int pid_flags   = 0;
    int mptcp       = 0;
    char *user      = NULL;
    char *timeout   = NULL;
    char *pid_path  = NULL;
    char *conf_path = NULL;
    char *iface     = NULL;

    int server_num = 0;
    const char *server_host[MAX_REMOTE_NUM];

    char *nameservers = NULL;

    ss_addr_t dst_addr = { .host = NULL, .port = NULL };
    char *dst_addr_str = NULL;
    ss_addr_t failover = { .host = NULL, .port = NULL };
    char *failover_str = NULL;
    char *obfs_host = NULL;

    char *ss_remote_host = getenv("SS_REMOTE_HOST");
    char *ss_remote_port = getenv("SS_REMOTE_PORT");
    char *ss_local_host  = getenv("SS_LOCAL_HOST");
    char *ss_local_port  = getenv("SS_LOCAL_PORT");
    char *ss_plugin_opts = getenv("SS_PLUGIN_OPTIONS");

    if (ss_remote_host != NULL) {
        ss_remote_host = strdup(ss_remote_host);
        char *delim = "|";
        char *p = strtok(ss_remote_host, delim);
        do {
            server_host[server_num++] = p;
        } while ((p = strtok(NULL, delim)));
    }

    if (ss_remote_port != NULL) {
        server_port = ss_remote_port;
    }

    if (ss_local_host != NULL) {
        dst_addr.host = ss_local_host;
    }

    if (ss_local_port != NULL) {
        dst_addr.port =  ss_local_port;
    }

    if (ss_plugin_opts != NULL) {
        ss_plugin_opts = strdup(ss_plugin_opts);
        options_t opts;
        int opt_num = parse_options(ss_plugin_opts,
                strlen(ss_plugin_opts), &opts);
        for (i = 0; i < opt_num; i++) {
            char *key = opts.keys[i];
            char *value = opts.values[i];
            if (key == NULL) continue;
            size_t key_len = strlen(key);
            if (key_len == 0) continue;
            if (key_len == 1) {
                char c = key[0];
                switch (c) {
                    case 'b':
                        bind_address = value;
                        break;
                    case 't':
                        timeout = value;
                        break;
                    case 'c':
                        conf_path = value;
                        break;
                    case 'i':
                        iface = value;
                        break;
                    case 'a':
                        user = value;
                        break;
                    case 'v':
                        verbose = 1;
                        break;
                    case '6':
                        ipv6first = 1;
                        break;
                    }
            } else {
                if (strcmp(key, "fast-open") == 0) {
                    fast_open = 1;
                } else if (strcmp(key, "obfs") == 0) {
                    if (strcmp(value, obfs_http->name) == 0)
                        obfs_para = obfs_http;
                    else if (strcmp(value, obfs_tls->name) == 0)
                        obfs_para = obfs_tls;
                } else if (strcmp(key, "obfs-host") == 0) {
                    obfs_host = value;
                } else if (strcmp(key, "failover") == 0) {
                    failover_str = value;
                } else if (strcmp(key, "reverse_proxy") == 0) {
                    reverse_proxy = 1;
#ifdef __linux__
                } else if (strcmp(key, "mptcp") == 0) {
                    mptcp = 1;
                    LOGI("enable multipath TCP");
#endif
                }
            }
        }
    }

    int option_index                    = 0;
    static struct option long_options[] = {
        { "fast-open",       no_argument,       0, 0 },
        { "help",            no_argument,       0, 0 },
        { "obfs",            required_argument, 0, 0 },
        { "obfs-host",       required_argument, 0, 0 },
        { "failover",        required_argument, 0, 0 },
#ifdef __linux__
        { "mptcp",           no_argument,       0, 0 },
#endif
        { "reverse_proxy",   no_argument,       0, 0 },
        { 0,                 0,                 0, 0 }
    };

    opterr = 0;

    USE_TTY();

    while ((c = getopt_long(argc, argv, "f:s:p:l:t:b:c:i:d:r:a:n:hv6",
                            long_options, &option_index)) != -1) {
        switch (c) {
        case 0:
            if (option_index == 0) {
                fast_open = 1;
            } else if (option_index == 1) {
                usage();
                exit(EXIT_SUCCESS);
            } else if (option_index == 2) {
                if (strcmp(optarg, obfs_http->name) == 0)
                    obfs_para = obfs_http;
                else if (strcmp(optarg, obfs_tls->name) == 0)
                    obfs_para = obfs_tls;
            } else if (option_index == 3) {
                obfs_host = optarg;
            } else if (option_index == 4) {
                failover_str = optarg;
            } else if (option_index == 5) {
                mptcp = 1;
                LOGI("enable multipath TCP");
            } else if (option_index == 6) {
                reverse_proxy = 1;
                LOGI("enable reverse proxy");
            }
            break;
        case 's':
            if (server_num < MAX_REMOTE_NUM) {
                server_host[server_num++] = optarg;
            }
            break;
        case 'b':
            bind_address = optarg;
            break;
        case 'p':
            server_port = optarg;
            break;
        case 'r':
            dst_addr_str = optarg;
            break;
        case 'f':
            pid_flags = 1;
            pid_path  = optarg;
            break;
        case 't':
            timeout = optarg;
            break;
        case 'c':
            conf_path = optarg;
            break;
        case 'i':
            iface = optarg;
            break;
        case 'd':
            nameservers = optarg;
            break;
        case 'a':
            user = optarg;
            break;
#ifdef HAVE_SETRLIMIT
        case 'n':
            nofile = atoi(optarg);
            break;
#endif
        case 'v':
            verbose = 1;
            break;
        case 'h':
            usage();
            exit(EXIT_SUCCESS);
        case '6':
            ipv6first = 1;
            break;
        case '?':
            // The option character is not recognized.
            LOGE("Unrecognized option: %s", optarg);
            opterr = 1;
            break;
        }
    }

    if (opterr) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (conf_path != NULL) {
        jconf_t *conf = read_jconf(conf_path);
        if (server_num == 0) {
            server_num = conf->remote_num;
            for (i = 0; i < server_num; i++)
                server_host[i] = conf->remote_addr[i].host;
        }
        if (server_port == NULL) {
            server_port = conf->remote_port;
        }
        if (timeout == NULL) {
            timeout = conf->timeout;
        }
        if (user == NULL) {
            user = conf->user;
        }
        if (dst_addr_str == NULL) {
            dst_addr_str = conf->dst_addr;
        }
        if (failover_str == NULL) {
            failover_str = conf->failover;
        }
        if (obfs_para == NULL && conf->obfs != NULL) {
            if (strcmp(conf->obfs, obfs_http->name) == 0)
                obfs_para = obfs_http;
            else if (strcmp(conf->obfs, obfs_tls->name) == 0)
                obfs_para = obfs_tls;
        }
        if (obfs_host == NULL) {
            obfs_host = conf->obfs_host;
        }
        if (mptcp == 0) {
            mptcp = conf->mptcp;
        }
#ifdef TCP_FASTOPEN
        if (fast_open == 0) {
            fast_open = conf->fast_open;
        }
#endif
#ifdef HAVE_SETRLIMIT
        if (nofile == 0) {
            nofile = conf->nofile;
        }
#endif
        if (nameservers == NULL) {
            nameservers = conf->nameserver;
        }
        if (ipv6first == 0) {
            ipv6first = conf->ipv6_first;
        }
        if (reverse_proxy == 0) {
            reverse_proxy = conf->reverse_proxy;
        }
    }

    if (server_num == 0) {
        server_host[server_num++] = NULL;
    }

    if (server_num == 0 || server_port == NULL) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (dst_addr_str != NULL) {
        // parse dst addr
        parse_addr(dst_addr_str, &dst_addr);
    }

    if (dst_addr.host == NULL || dst_addr.port == NULL) {
        FATAL("forwarding destination is not defined");
    }

    if (failover_str != NULL) {
        // parse failover addr
        parse_addr(failover_str, &failover);
    }

    if (timeout == NULL) {
        timeout = "600";
    }

#ifdef HAVE_SETRLIMIT
    /*
     * no need to check the return value here since we will show
     * the user an error message if setrlimit(2) fails
     */
    if (nofile > 1024) {
        if (verbose) {
            LOGI("setting NOFILE to %d", nofile);
        }
        set_nofile(nofile);
    }
#endif

    if (pid_flags) {
        USE_SYSLOG(argv[0]);
        daemonize(pid_path);
    }

    if (ipv6first) {
        LOGI("resolving hostname to IPv6 address first");
    }

    if (fast_open == 1) {
#ifdef TCP_FASTOPEN
        LOGI("using tcp fast open");
#else
        LOGE("tcp fast open is not supported by this environment");
        fast_open = 0;
#endif
    }

    if (obfs_para) {
        obfs_para->host = obfs_host;
        LOGI("obfuscating enabled");
        if (obfs_host)
            LOGI("obfuscating hostname: %s", obfs_host);
    }

#ifdef __MINGW32__
    winsock_init();
#else
    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGABRT, SIG_IGN);
#endif

    struct ev_signal sigint_watcher;
    struct ev_signal sigterm_watcher;
    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_start(EV_DEFAULT, &sigint_watcher);
    ev_signal_start(EV_DEFAULT, &sigterm_watcher);

    // initialize ev loop
    struct ev_loop *loop = EV_DEFAULT;

    if (nameservers != NULL)
        LOGI("using nameserver: %s", nameservers);

    // initialize listen context
    listen_ctx_t listen_ctx_list[server_num];

    // bind to each interface
    while (server_num > 0) {
        int index        = --server_num;
        const char *host = server_host[index];

        // Bind to port
        int listenfd;
        listenfd = create_and_bind(host, server_port, mptcp);
        if (listenfd == -1) {
            FATAL("bind() error");
        }
        if (listen(listenfd, SSMAXCONN) == -1) {
            FATAL("listen() error");
        }
        setfastopen(listenfd);
        setnonblocking(listenfd);
        listen_ctx_t *listen_ctx = &listen_ctx_list[index];

        // Setup proxy context
        listen_ctx->timeout = atoi(timeout);
        listen_ctx->fd      = listenfd;
        listen_ctx->iface   = iface;
        listen_ctx->loop    = loop;

        listen_ctx->dst_addr = &dst_addr;
        listen_ctx->failover = &failover;

        ev_io_init(&listen_ctx->io, accept_cb, listenfd, EV_READ);
        ev_io_start(loop, &listen_ctx->io);

        if (host && strcmp(host, ":") > 0)
            LOGI("listening at [%s]:%s", host, server_port);
        else
            LOGI("listening at %s:%s", host ? host : "*", server_port);
    }

    // setuid
    if (user != NULL && !run_as(user)) {
        FATAL("failed to switch user");
    }

#ifndef __MINGW32__
    if (geteuid() == 0) {
        LOGI("running from root user");
    }
#endif

    // Init connections
    cork_dllist_init(&connections);

#ifndef __MINGW32__
    ev_timer parent_watcher;
    ev_timer_init(&parent_watcher, parent_watcher_cb, 0, UPDATE_INTERVAL);
    ev_timer_start(EV_DEFAULT, &parent_watcher);
#endif

    // start ev loop
    ev_run(loop, 0);

    if (verbose) {
        LOGI("closed gracefully");
    }

    // Clean up
    for (int i = 0; i <= server_num; i++) {
        listen_ctx_t *listen_ctx = &listen_ctx_list[i];
        ev_io_stop(loop, &listen_ctx->io);
        close(listen_ctx->fd);
    }

    free_connections(loop);

#ifdef __MINGW32__
    winsock_cleanup();
#endif

    ev_signal_stop(EV_DEFAULT, &sigint_watcher);
    ev_signal_stop(EV_DEFAULT, &sigterm_watcher);

    return 0;
}
