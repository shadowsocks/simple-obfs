/*
 * local.c - Setup a tunneling proxy through remote simple-obfs server
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
#include <unistd.h>
#include <getopt.h>

#ifndef __MINGW32__
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#endif

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include <libcork/core.h>

#ifdef __MINGW32__
#include "win32.h"
#define __ev_io_init(a, b, c, d) ev_io_init(a, b, _open_osfhandle(c, 0), d)
#else
#define __ev_io_init(a, b, c, d) ev_io_init(a, b, c, d)
#endif

#include "netutils.h"
#include "utils.h"
#include "obfs_http.h"
#include "obfs_tls.h"
#include "options.h"
#include "local.h"

#ifdef __APPLE__
#include <AvailabilityMacros.h>
#if defined(MAC_OS_X_VERSION_10_10) && MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_10
#include <launch.h>
#define HAVE_LAUNCHD
#endif
#endif

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#ifndef BUF_SIZE
#define BUF_SIZE 2048
#endif

int verbose        = 0;
int keep_resolving = 1;

#ifdef ANDROID
int vpn        = 0;
uint64_t tx    = 0;
uint64_t rx    = 0;
ev_tstamp last = 0;
#endif

static int ipv6first = 0;
static int fast_open = 0;

static obfs_para_t *obfs_para  = NULL;

#ifdef HAVE_SETRLIMIT
static int nofile = 0;
#endif

static void server_recv_cb(EV_P_ ev_io *w, int revents);
static void server_send_cb(EV_P_ ev_io *w, int revents);
static void remote_recv_cb(EV_P_ ev_io *w, int revents);
static void remote_send_cb(EV_P_ ev_io *w, int revents);
static void accept_cb(EV_P_ ev_io *w, int revents);
#ifndef __MINGW32__
static void signal_cb(EV_P_ ev_signal *w, int revents);
#endif

static int create_and_bind(const char *addr, const char *port);
#ifdef HAVE_LAUNCHD
static int launch_or_create(const char *addr, const char *port);
#endif
static remote_t *create_remote(listen_ctx_t *listener, struct sockaddr *addr);
static void free_remote(remote_t *remote);
static void close_and_free_remote(EV_P_ remote_t *remote);
static void free_server(server_t *server);
static void close_and_free_server(EV_P_ server_t *server);

static remote_t *new_remote(int fd, int timeout);
static server_t *new_server(int fd);

static struct cork_dllist connections;

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

static void
parent_watcher_cb(EV_P_ ev_timer *watcher, int revents)
{
    static int ppid = -1;

    int cur_ppid = getppid();
    if (ppid != -1) {
        if (ppid != cur_ppid) {
            keep_resolving = 0;
            ev_unloop(EV_A_ EVUNLOOP_ALL);
        }
    }

    ppid = cur_ppid;
}
#endif

int
create_and_bind(const char *addr, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, listen_sock;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_UNSPEC;   /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */

    s = getaddrinfo(addr, port, &hints, &result);
    if (s != 0) {
        LOGE("getaddrinfo (%s:%s), error %s", addr, port, gai_strerror(s));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        listen_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listen_sock == -1) {
            continue;
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

#ifdef HAVE_LAUNCHD
int
launch_or_create(const char *addr, const char *port)
{
    int *fds;
    size_t cnt;
    int error = launch_activate_socket("Listeners", &fds, &cnt);
    if (error == 0) {
        if (cnt == 1) {
            return fds[0];
        } else {
            FATAL("please don't specify multi entry");
        }
    } else if (error == ESRCH || error == ENOENT) {
        /* ESRCH:  The calling process is not managed by launchd(8).
         * ENOENT: The socket name specified does not exist
         *          in the caller's launchd.plist(5).
         */
        if (port == NULL) {
            usage();
            exit(EXIT_FAILURE);
        }
        return create_and_bind(addr, port);
    } else {
        FATAL("launch_activate_socket() error");
    }
    return -1;
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

static void
server_recv_cb(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server              = server_recv_ctx->server;
    remote_t *remote              = server->remote;
    buffer_t *buf;
    ssize_t r;

    if (remote == NULL) {
        buf = server->buf;
    } else {
        buf = remote->buf;
    }

    r = recv(server->fd, buf->data + buf->len, BUF_SIZE - buf->len, 0);

    if (r == 0) {
        // connection closed
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            if (verbose)
                ERROR("server_recv_cb_recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    buf->len += r;

    while (1) {
        // local socks5 server
        if (server->stage == STAGE_STREAM) {
            if (remote == NULL) {
                LOGE("invalid remote");
                close_and_free_server(EV_A_ server);
                return;
            }

#ifdef ANDROID
            tx += remote->buf->len;
#endif
            if (obfs_para)
                obfs_para->obfs_request(remote->buf, BUF_SIZE, server->obfs);

            if (!remote->send_ctx->connected) {
#ifdef ANDROID
                if (vpn) {
                    int not_protect = 0;
                    if (remote->addr.ss_family == AF_INET) {
                        struct sockaddr_in *s = (struct sockaddr_in *)&remote->addr;
                        if (s->sin_addr.s_addr == inet_addr("127.0.0.1"))
                            not_protect = 1;
                    }
                    if (!not_protect) {
                        if (protect_socket(remote->fd) == -1) {
                            ERROR("protect_socket");
                            close_and_free_remote(EV_A_ remote);
                            close_and_free_server(EV_A_ server);
                            return;
                        }
                    }
                }
#endif
                remote->buf->idx = 0;

                if (!fast_open) {
                    // connecting, wait until connected
                    int r = connect(remote->fd, (struct sockaddr *)&(remote->addr), remote->addr_len);

                    if (r == -1 && errno != CONNECT_IN_PROGRESS) {
                        ERROR("connect");
                        close_and_free_remote(EV_A_ remote);
                        close_and_free_server(EV_A_ server);
                        return;
                    }

                    // wait on remote connected event
                    ev_io_stop(EV_A_ & server_recv_ctx->io);
                    ev_io_start(EV_A_ & remote->send_ctx->io);
                    ev_timer_start(EV_A_ & remote->send_ctx->watcher);
                } else {
#ifdef TCP_FASTOPEN
#ifdef __APPLE__
                    ((struct sockaddr_in *)&(remote->addr))->sin_len = sizeof(struct sockaddr_in);
                    sa_endpoints_t endpoints;
                    memset((char *)&endpoints, 0, sizeof(endpoints));
                    endpoints.sae_dstaddr    = (struct sockaddr *)&(remote->addr);
                    endpoints.sae_dstaddrlen = remote->addr_len;

                    int s = connectx(remote->fd, &endpoints, SAE_ASSOCID_ANY,
                                     CONNECT_RESUME_ON_READ_WRITE | CONNECT_DATA_IDEMPOTENT,
                                     NULL, 0, NULL, NULL);
                    if (s == 0) {
                        s = send(remote->fd, remote->buf->data, remote->buf->len, 0);
                    }
#else
                    int s = sendto(remote->fd, remote->buf->data, remote->buf->len, MSG_FASTOPEN,
                                   (struct sockaddr *)&(remote->addr), remote->addr_len);
#endif
                    if (s == -1) {
                        if (errno == CONNECT_IN_PROGRESS) {
                            // in progress, wait until connected
                            remote->buf->idx = 0;
                            ev_io_stop(EV_A_ & server_recv_ctx->io);
                            ev_io_start(EV_A_ & remote->send_ctx->io);
                            return;
                        } else {
                            ERROR("sendto");
                            if (errno == ENOTCONN) {
                                LOGE("fast open is not supported on this platform");
                                // just turn it off
                                fast_open = 0;
                            }
                            close_and_free_remote(EV_A_ remote);
                            close_and_free_server(EV_A_ server);
                            return;
                        }
                    } else if (s < (int)(remote->buf->len)) {
                        remote->buf->len -= s;
                        remote->buf->idx  = s;

                        ev_io_stop(EV_A_ & server_recv_ctx->io);
                        ev_io_start(EV_A_ & remote->send_ctx->io);
                        ev_timer_start(EV_A_ & remote->send_ctx->watcher);
                        return;
                    } else {
                        // Just connected
                        remote->buf->idx = 0;
                        remote->buf->len = 0;
#ifdef __APPLE__
                        ev_io_stop(EV_A_ & server_recv_ctx->io);
                        ev_io_start(EV_A_ & remote->send_ctx->io);
                        ev_timer_start(EV_A_ & remote->send_ctx->watcher);
#else
                        remote->send_ctx->connected = 1;
                        ev_timer_stop(EV_A_ & remote->send_ctx->watcher);
                        ev_timer_start(EV_A_ & remote->recv_ctx->watcher);
                        ev_io_start(EV_A_ & remote->recv_ctx->io);
                        return;
#endif
                    }
#else
                    // if TCP_FASTOPEN is not defined, fast_open will always be 0
                    FATAL("can't come here");
#endif
                }
            } else {
                int s = send(remote->fd, remote->buf->data, remote->buf->len, 0);
                if (s == -1) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        // no data, wait for send
                        remote->buf->idx = 0;
                        ev_io_stop(EV_A_ & server_recv_ctx->io);
                        ev_io_start(EV_A_ & remote->send_ctx->io);
                        return;
                    } else {
                        ERROR("server_recv_cb_send");
                        close_and_free_remote(EV_A_ remote);
                        close_and_free_server(EV_A_ server);
                        return;
                    }
                } else if (s < (int)(remote->buf->len)) {
                    remote->buf->len -= s;
                    remote->buf->idx  = s;
                    ev_io_stop(EV_A_ & server_recv_ctx->io);
                    ev_io_start(EV_A_ & remote->send_ctx->io);
                    return;
                } else {
                    remote->buf->idx = 0;
                    remote->buf->len = 0;
                }
            }

            // all processed
            return;

        } else if (server->stage == STAGE_INIT) {

            server->stage = STAGE_STREAM;

            remote = create_remote(server->listener, NULL);

            if (remote == NULL) {
                LOGE("invalid remote addr");
                close_and_free_server(EV_A_ server);
                return;
            }

            if (buf->len > 0) {
                memcpy(remote->buf->data, buf->data, buf->len);
                remote->buf->len = buf->len;
            }

            server->remote = remote;
            remote->server = server;
        }
    }
}

static void
server_send_cb(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_send_ctx = (server_ctx_t *)w;
    server_t *server              = server_send_ctx->server;
    remote_t *remote              = server->remote;
    if (server->buf->len == 0) {
        // close and free
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(server->fd, server->buf->data + server->buf->idx,
                         server->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("server_send_cb_send");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < (ssize_t)(server->buf->len)) {
            // partly sent, move memory, wait for the next time to send
            server->buf->len -= s;
            server->buf->idx += s;
            return;
        } else {
            // all sent out, wait for reading
            server->buf->len = 0;
            server->buf->idx = 0;
            ev_io_stop(EV_A_ & server_send_ctx->io);
            ev_io_start(EV_A_ & remote->recv_ctx->io);
            return;
        }
    }
}

static void
remote_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
    remote_ctx_t *remote_ctx
        = cork_container_of(watcher, remote_ctx_t, watcher);

    remote_t *remote = remote_ctx->remote;
    server_t *server = remote->server;

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

    ev_timer_again(EV_A_ & remote->recv_ctx->watcher);

    ssize_t r = recv(remote->fd, server->buf->data, BUF_SIZE, 0);

    if (r == 0) {
        // connection closed
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("remote_recv_cb_recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    server->buf->len = r;

    if (!remote->direct) {
#ifdef ANDROID
        rx += server->buf->len;
#endif
        if (obfs_para) {
            if (obfs_para->deobfs_response(server->buf, BUF_SIZE, server->obfs)) {
                LOGE("invalid obfuscating");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }
        }
    }

    int s = send(server->fd, server->buf->data, server->buf->len, 0);

    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            server->buf->idx = 0;
            ev_io_stop(EV_A_ & remote_recv_ctx->io);
            ev_io_start(EV_A_ & server->send_ctx->io);
        } else {
            ERROR("remote_recv_cb_send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    } else if (s < (int)(server->buf->len)) {
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

    if (!remote_send_ctx->connected) {
        struct sockaddr_storage addr;
        socklen_t len = sizeof addr;
        int r         = getpeername(remote->fd, (struct sockaddr *)&addr, &len);
        if (r == 0) {
            remote_send_ctx->connected = 1;
            ev_timer_stop(EV_A_ & remote_send_ctx->watcher);
            ev_timer_start(EV_A_ & remote->recv_ctx->watcher);
            ev_io_start(EV_A_ & remote->recv_ctx->io);

            // no need to send any data
            if (remote->buf->len == 0) {
                ev_io_stop(EV_A_ & remote_send_ctx->io);
                ev_io_start(EV_A_ & server->recv_ctx->io);
                return;
            }
        } else {
            // not connected
            ERROR("getpeername");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    if (remote->buf->len == 0) {
        // close and free
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(remote->fd, remote->buf->data + remote->buf->idx,
                         remote->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("remote_send_cb_send");
                // close and free
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < (ssize_t)(remote->buf->len)) {
            // partly sent, move memory, wait for the next time to send
            remote->buf->len -= s;
            remote->buf->idx += s;
            return;
        } else {
            // all sent out, wait for reading
            remote->buf->len = 0;
            remote->buf->idx = 0;
            ev_io_stop(EV_A_ & remote_send_ctx->io);
            ev_io_start(EV_A_ & server->recv_ctx->io);
        }
    }
}

static remote_t *
new_remote(int fd, int timeout)
{
    remote_t *remote;
    remote = ss_malloc(sizeof(remote_t));

    memset(remote, 0, sizeof(remote_t));

    remote->buf      = ss_malloc(sizeof(buffer_t));
    remote->recv_ctx = ss_malloc(sizeof(remote_ctx_t));
    remote->send_ctx = ss_malloc(sizeof(remote_ctx_t));
    balloc(remote->buf, BUF_SIZE);
    memset(remote->recv_ctx, 0, sizeof(remote_ctx_t));
    memset(remote->send_ctx, 0, sizeof(remote_ctx_t));
    remote->recv_ctx->connected = 0;
    remote->send_ctx->connected = 0;
    remote->fd                  = fd;
    remote->recv_ctx->remote    = remote;
    remote->send_ctx->remote    = remote;

    __ev_io_init(&remote->recv_ctx->io, remote_recv_cb, fd, EV_READ);
    __ev_io_init(&remote->send_ctx->io, remote_send_cb, fd, EV_WRITE);
    ev_timer_init(&remote->send_ctx->watcher, remote_timeout_cb,
                  min(MAX_CONNECT_TIMEOUT, timeout), 0);
    ev_timer_init(&remote->recv_ctx->watcher, remote_timeout_cb,
                  timeout, timeout);

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
        ev_timer_stop(EV_A_ & remote->send_ctx->watcher);
        ev_timer_stop(EV_A_ & remote->recv_ctx->watcher);
        ev_io_stop(EV_A_ & remote->send_ctx->io);
        ev_io_stop(EV_A_ & remote->recv_ctx->io);
        close(remote->fd);
        free_remote(remote);
    }
}

static server_t *
new_server(int fd)
{
    server_t *server;
    server = ss_malloc(sizeof(server_t));

    memset(server, 0, sizeof(server_t));

    server->recv_ctx = ss_malloc(sizeof(server_ctx_t));
    server->send_ctx = ss_malloc(sizeof(server_ctx_t));
    server->buf      = ss_malloc(sizeof(buffer_t));
    balloc(server->buf, BUF_SIZE);
    memset(server->recv_ctx, 0, sizeof(server_ctx_t));
    memset(server->send_ctx, 0, sizeof(server_ctx_t));
    server->stage               = STAGE_INIT;
    server->recv_ctx->connected = 0;
    server->send_ctx->connected = 0;
    server->fd                  = fd;
    server->recv_ctx->server    = server;
    server->send_ctx->server    = server;

    if (obfs_para != NULL) {
        server->obfs = (obfs_t *)ss_malloc(sizeof(obfs_t));
        memset(server->obfs, 0, sizeof(obfs_t));
    }

    __ev_io_init(&server->recv_ctx->io, server_recv_cb, fd, EV_READ);
    __ev_io_init(&server->send_ctx->io, server_send_cb, fd, EV_WRITE);

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
        close(server->fd);
        free_server(server);
    }
}

static remote_t *
create_remote(listen_ctx_t *listener,
              struct sockaddr *addr)
{
    struct sockaddr *remote_addr;

    int index = rand() % listener->remote_num;
    if (addr == NULL) {
        remote_addr = listener->remote_addr[index];
    } else {
        remote_addr = addr;
    }

    int remotefd = socket(remote_addr->sa_family, SOCK_STREAM, IPPROTO_TCP);

    if (remotefd == -1) {
        ERROR("socket");
        return NULL;
    }

    int opt = 1;
    setsockopt(remotefd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(remotefd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    if (listener->mptcp == 1) {
        int err = setsockopt(remotefd, SOL_TCP, MPTCP_ENABLED, &opt, sizeof(opt));
        if (err == -1) {
            ERROR("failed to enable multipath TCP");
        }
    }

    // Setup
    setnonblocking(remotefd);
#ifdef SET_INTERFACE
    if (listener->iface) {
        if (setinterface(remotefd, listener->iface) == -1)
            ERROR("setinterface");
    }
#endif

    remote_t *remote = new_remote(remotefd, listener->timeout);
    remote->addr_len = get_sockaddr_len(remote_addr);
    memcpy(&(remote->addr), remote_addr, remote->addr_len);

    return remote;
}

#ifndef __MINGW32__
static void
signal_cb(EV_P_ ev_signal *w, int revents)
{
    if (revents & EV_SIGNAL) {
        switch (w->signum) {
        case SIGINT:
        case SIGTERM:
        case SIGUSR1:
            keep_resolving = 0;
            ev_unloop(EV_A_ EVUNLOOP_ALL);
        }
    }
}
#endif

void
accept_cb(EV_P_ ev_io *w, int revents)
{
    listen_ctx_t *listener = (listen_ctx_t *)w;
    int serverfd           = accept(listener->fd, NULL, NULL);
    if (serverfd == -1) {
        ERROR("accept");
        return;
    }
    setnonblocking(serverfd);
    int opt = 1;
    setsockopt(serverfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(serverfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    server_t *server = new_server(serverfd);
    server->listener = listener;

    ev_io_start(EV_A_ & server->recv_ctx->io);
}

int
main(int argc, char **argv)
{
    int i, c;
    int pid_flags    = 0;
    int mptcp        = 0;
    char *user       = NULL;
    char *local_port = NULL;
    char *local_addr = NULL;
    char *timeout    = NULL;
    char *pid_path   = NULL;
    char *conf_path  = NULL;
    char *iface      = NULL;
    char *obfs_host   = NULL;

    srand(time(NULL));

    int remote_num = 0;
    ss_addr_t remote_addr[MAX_REMOTE_NUM];
    char *remote_port = NULL;

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
            remote_addr[remote_num].host = p;
            remote_addr[remote_num++].port = NULL;
        } while ((p = strtok(NULL, delim)));
    }

    if (ss_remote_port != NULL) {
        remote_port = ss_remote_port;
    }

    if (ss_local_host != NULL) {
        local_addr = ss_local_host;
    }

    if (ss_local_port != NULL) {
        local_port = ss_local_port;
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
#ifdef ANDROID
                    case 'V':
                        vpn = 1;
                        break;
#endif
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
#ifdef __linux__
                } else if (strcmp(key, "mptcp") == 0) {
                    mptcp = 1;
                    LOGI("enable multipath TCP");
#endif
                }
            }
        }
    }

    int option_index = 0;

    static struct option long_options[] = {
        { "fast-open", no_argument,       0, 0 },
        { "mptcp",     no_argument,       0, 0 },
        { "obfs",      required_argument, 0, 0 },
        { "obfs-host", required_argument, 0, 0 },
        { "help",      no_argument,       0, 0 },
        { 0,           0,                 0, 0 }
    };

    opterr = 0;

    USE_TTY();

#ifdef ANDROID
    while ((c = getopt_long(argc, argv, "f:s:p:l:t:i:c:b:a:n:hvV6",
                            long_options, &option_index)) != -1) {
#else
    while ((c = getopt_long(argc, argv, "f:s:p:l:t:i:c:b:a:n:hv6",
                            long_options, &option_index)) != -1) {
#endif
        switch (c) {
        case 0:
            if (option_index == 0) {
                fast_open = 1;
            } else if (option_index == 1) {
                mptcp = 1;
                LOGI("enable multipath TCP");
            } else if (option_index == 2) {
                if (strcmp(optarg, obfs_http->name) == 0)
                    obfs_para = obfs_http;
                else if (strcmp(optarg, obfs_tls->name) == 0)
                    obfs_para = obfs_tls;
            } else if (option_index == 3) {
                obfs_host = optarg;
            } else if (option_index == 4) {
                usage();
                exit(EXIT_SUCCESS);
            }
            break;
        case 's':
            if (remote_num < MAX_REMOTE_NUM) {
                remote_addr[remote_num].host   = optarg;
                remote_addr[remote_num++].port = NULL;
            }
            break;
        case 'p':
            remote_port = optarg;
            break;
        case 'l':
            local_port = optarg;
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
        case 'b':
            local_addr = optarg;
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
#ifdef ANDROID
        case 'V':
            vpn = 1;
            break;
#endif
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
        if (remote_num == 0) {
            remote_num = conf->remote_num;
            for (i = 0; i < remote_num; i++)
                remote_addr[i] = conf->remote_addr[i];
        }
        if (remote_port == NULL) {
            remote_port = conf->remote_port;
        }
        if (local_addr == NULL) {
            local_addr = conf->local_addr;
        }
        if (local_port == NULL) {
            local_port = conf->local_port;
        }
        if (timeout == NULL) {
            timeout = conf->timeout;
        }
        if (user == NULL) {
            user = conf->user;
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
        if (fast_open == 0) {
            fast_open = conf->fast_open;
        }
        if (mptcp == 0) {
            mptcp = conf->mptcp;
        }
#ifdef HAVE_SETRLIMIT
        if (nofile == 0) {
            nofile = conf->nofile;
        }
#endif
    }

    if (remote_num == 0 || remote_port == NULL ||
#ifndef HAVE_LAUNCHD
        local_port == NULL ||
#endif
        obfs_para == NULL) {
        usage();
        exit(EXIT_FAILURE);
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

    if (local_addr == NULL) {
        local_addr = "127.0.0.1";
    }

    if (pid_flags) {
        USE_SYSLOG(argv[0]);
        daemonize(pid_path);
    }

    if (fast_open == 1) {
#ifdef TCP_FASTOPEN
        LOGI("using tcp fast open");
#else
        LOGE("tcp fast open is not supported by this environment");
        fast_open = 0;
#endif
    }

    if (ipv6first) {
        LOGI("resolving hostname to IPv6 address first");
    }

    if (obfs_para) {
        if (obfs_host != NULL)
            obfs_para->host = obfs_host;
        else
            obfs_para->host = "cloudfront.net";
        obfs_para->port = atoi(remote_port);
        LOGI("obfuscating enabled");
        if (obfs_host)
            LOGI("obfuscating hostname: %s", obfs_host);
    }

#ifdef __MINGW32__
    winsock_init();
#else
    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);
#endif

    // Setup proxy context
    listen_ctx_t listen_ctx;
    listen_ctx.remote_num  = remote_num;
    listen_ctx.remote_addr = ss_malloc(sizeof(struct sockaddr *) * remote_num);
    memset(listen_ctx.remote_addr, 0, sizeof(struct sockaddr *) * remote_num);
    for (i = 0; i < remote_num; i++) {
        char *host = remote_addr[i].host;
        char *port = remote_addr[i].port == NULL ? remote_port :
                     remote_addr[i].port;
        struct sockaddr_storage *storage = ss_malloc(sizeof(struct sockaddr_storage));
        memset(storage, 0, sizeof(struct sockaddr_storage));
        if (get_sockaddr(host, port, storage, 1, ipv6first) == -1) {
            FATAL("failed to resolve the provided hostname");
        }
        listen_ctx.remote_addr[i] = (struct sockaddr *)storage;
    }
    listen_ctx.timeout = atoi(timeout);
    listen_ctx.iface   = iface;
    listen_ctx.mptcp   = mptcp;

#ifndef __MINGW32__
    // Setup signal handler
    struct ev_signal sigint_watcher;
    struct ev_signal sigterm_watcher;
    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_start(EV_DEFAULT, &sigint_watcher);
    ev_signal_start(EV_DEFAULT, &sigterm_watcher);
#endif

#ifndef __MINGW32__
    ev_timer parent_watcher;
    ev_timer_init(&parent_watcher, parent_watcher_cb, 0, UPDATE_INTERVAL);
    ev_timer_start(EV_DEFAULT, &parent_watcher);
#endif

    struct ev_loop *loop = EV_DEFAULT;

    // Setup socket
    int listenfd;
#ifdef HAVE_LAUNCHD
    listenfd = launch_or_create(local_addr, local_port);
#else
    listenfd = create_and_bind(local_addr, local_port);
#endif
    if (listenfd == -1) {
        FATAL("bind() error");
    }
    if (listen(listenfd, SOMAXCONN) == -1) {
        FATAL("listen() error");
    }
    setnonblocking(listenfd);

    listen_ctx.fd = listenfd;

    __ev_io_init(&listen_ctx.io, accept_cb, listenfd, EV_READ);
    ev_io_start(loop, &listen_ctx.io);

#ifdef HAVE_LAUNCHD
    if (local_port == NULL)
        LOGI("listening through launchd");
    else
#endif
    if (strcmp(local_addr, ":") > 0)
        LOGI("listening at [%s]:%s", local_addr, local_port);
    else
        LOGI("listening at %s:%s", local_addr, local_port);

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

    // Enter the loop
    ev_run(loop, 0);

    if (verbose) {
        LOGI("closed gracefully");
    }

    // Clean up
    ev_io_stop(loop, &listen_ctx.io);
    free_connections(loop);

    for (i = 0; i < remote_num; i++)
        ss_free(listen_ctx.remote_addr[i]);
    ss_free(listen_ctx.remote_addr);

#ifdef __MINGW32__
    winsock_cleanup();
#else
    ev_signal_stop(EV_DEFAULT, &sigint_watcher);
    ev_signal_stop(EV_DEFAULT, &sigterm_watcher);
#endif

    return 0;
}
