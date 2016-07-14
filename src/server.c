#include <assert.h>
#include <errno.h>
#include <ev.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common.h"
#include "checksum.h"
#include "server.h"
#include "uthash.h"

struct s_data {
    const struct common_data *common_data;
    struct sockaddr *s_addr;
    struct sockaddr_storage pkt_addr;
    struct o_s_sock *o_socks_by_caddr;
    int s_sock;
    socklen_t s_addrlen;
    uint16_t csum_p;
};

struct o_s_sock {
    struct s_data *s_data;
    struct sockaddr_storage c_addr;
    struct ev_timer tm_w;
    struct ev_io io_w;
    UT_hash_handle hh;
    int c_sock;
    uint16_t seq_num;
    uint16_t csum_p;
    uint8_t status;
};

struct s_data *global_s_data;

static inline void s_prep_c_addr(struct o_s_sock *sock, struct tcphdr *hdr) {
    hdr->th_sport = ((struct sockaddr_in *)sock->s_data->s_addr)->sin_port;
    hdr->th_dport = ((struct sockaddr_in *)&sock->c_addr)->sin_port;
    hdr->th_seq = htonl(sock->seq_num++);
    hdr->th_off = 5;
}

static void s_sock_cleanup(EV_P_ struct o_s_sock *sock, int stopping) {
    DBG("cleaning up socket %p", sock);

    if (sock->status == TCP_ESTABLISHED) {
        DBG("socket was ESTABLISHED, sending FIN");
        struct tcphdr buf = {
            .th_flags = TH_FIN
        };
        s_prep_c_addr(sock, &buf);
        ssize_t sz;
        // don't need to save the real port because we're deleting the sock anyways
        ((struct sockaddr_in *)&sock->c_addr)->sin_port = htons(0);
        if ((sz = sendto(sock->s_data->s_sock, &buf, sizeof(buf), 0, (struct sockaddr *)&sock->c_addr, sock->s_data->s_addrlen)) == -1) {
            perror("sendto");
            ev_break(EV_A_ EVBREAK_ONE);
            return;
        } else if (sz != sizeof(buf)) {
            fprintf(stderr, "sendto %s our packet: tried %lu, sent %zd\n", (size_t)sz > sizeof(buf) ? "expanded" : "truncated", sizeof(buf), sz);
        }
    }

    if (!stopping || free_mem_on_exit) {
        DBG("freeing associated resources");

        if (sock->c_sock != -1) {
            close(sock->c_sock);
        }

        ev_timer_stop(EV_A_ &sock->tm_w);
        if (sock->status == TCP_ESTABLISHED)
            ev_io_stop(EV_A_ &sock->io_w);

        HASH_DEL(sock->s_data->o_socks_by_caddr, sock);

        free(sock);
    }
}

static void s_tm_cb(EV_P_ ev_timer *w, int revents __attribute__((unused))) {
    DBG("timing out socket %p", w->data);
    s_sock_cleanup(EV_A_ w->data, 0);
}

static void sc_cb(EV_P_ ev_io *w, int revents __attribute__((unused))) {
    struct o_s_sock *sock = w->data;
    char rbuf[16384];
    ssize_t sz;

    DBG("-- entering sc_cb --");

    while ((sz = recv(w->fd, rbuf, sizeof(rbuf), 0)) > 0) {
        DBG("received %zd bytes matching socket %p", sz, sock);

        struct tcphdr hdr = {
            .th_win = htons(65535),
            .th_flags = TH_PUSH
        };
        s_prep_c_addr(sock, &hdr);

        struct iovec iovs[2] = {
            { .iov_base = &hdr, .iov_len = sizeof(hdr) },
            { .iov_base = rbuf, .iov_len = sz }
        };

        in_port_t c_port = ((struct sockaddr_in *)&sock->c_addr)->sin_port;
        ((struct sockaddr_in *)&sock->c_addr)->sin_port = 0;

        struct msghdr msghdr = {
            .msg_name = &sock->c_addr,
            .msg_namelen = sock->s_data->s_addrlen,
            .msg_iov = iovs,
            .msg_iovlen = sizeof(iovs) / sizeof(iovs[0])
        };

        size_t should_send_size = sizeof(hdr) + sz;

        uint16_t tsz = htons(sizeof(hdr) + sz);
        hdr.th_sum = ~csum_partial(rbuf, sz, csum_partial(&hdr.th_seq, 16, csum_partial(&tsz, sizeof(tsz), sock->csum_p)));

        assert(sock->status == TCP_ESTABLISHED);

        DBG("sending %zd bytes to client", should_send_size);
        sz = sendmsg(sock->s_data->s_sock, &msghdr, 0);

        ((struct sockaddr_in *)&sock->c_addr)->sin_port = c_port;

        if (sz < 0) {
            perror("sendmsg");
            ev_break(EV_A_ EVBREAK_ONE);
            return;
        } else if ((size_t)sz != should_send_size) {
            fprintf(stderr, "sendmsg %s our packet: tried %lu, sent %zd\n", (size_t)sz > should_send_size ? "expanded" : "truncated", should_send_size, sz);
        }

        ev_timer_again(EV_A_ &sock->tm_w);

        return;
    }

    if (sz == 0)
        abort();

    if (errno != EAGAIN) {
        perror("recv");
        ev_break(EV_A_ EVBREAK_ONE);
        return;
    }
}

static void ss_cb(EV_P_ ev_io *w, int revents __attribute__((unused))) {
    char rbuf[16384];
    ssize_t sz;
    struct s_data *s_data = w->data;
    socklen_t c_addrlen = s_data->s_addrlen;
    int r;

    DBG("-- entering ss_cb --");

    while ((sz = recvfrom(w->fd, rbuf, sizeof(rbuf), 0, (struct sockaddr *)&s_data->pkt_addr, &c_addrlen)) > 0) {
        if (c_addrlen != s_data->s_addrlen)
            abort();

        char *rptr = rbuf;

        if (s_data->s_addr->sa_family == AF_INET) {
            if ((size_t)sz < sizeof(struct iphdr)) {
                DBG("packet is smaller than IP header, ignoring");
                return;
            }

            if (((struct iphdr *)rbuf)->protocol != IPPROTO_TCP)
                abort();

            uint32_t ihl = ((struct iphdr *)rbuf)->ihl * 4;
            rptr = rbuf + ihl;
            sz -= ihl;
        }

#ifdef DEBUG
        char hbuf[NI_MAXHOST];
        r = getnameinfo((struct sockaddr *)&s_data->pkt_addr, c_addrlen, hbuf, sizeof(hbuf), NULL, 0, NI_NUMERICHOST);
        if (r) {
            fprintf(stderr, "getnameinfo: %s\n", gai_strerror(r));
            ev_break(EV_A_ EVBREAK_ONE);
            return;
        }
        DBG("received %zd payload bytes from %s", sz, hbuf);
#endif

        if ((size_t)sz < sizeof(struct tcphdr)) {
            DBG("packet is smaller than TCP header, ignoring");
            return;
        }

        struct tcphdr *tcphdr = (struct tcphdr *)rptr;

        DBG("packet received on port %hu", ntohs(tcphdr->th_dport));

        if (tcphdr->th_dport != ((struct sockaddr_in *)s_data->s_addr)->sin_port) {
            DBG("packet should be on port %hu, ignoring", ntohs(((struct sockaddr_in *)s_data->s_addr)->sin_port));
            return;
        }

        struct o_s_sock *sock;

        const uint8_t th_flags = tcphdr->th_flags;

        ((struct sockaddr_in *)&s_data->pkt_addr)->sin_port = tcphdr->th_sport;

        HASH_FIND(hh, s_data->o_socks_by_caddr, &s_data->pkt_addr, c_addrlen, sock);

        if (!sock) {
            DBG("could not locate matching socket for client addr");

            if (th_flags == TH_SYN) {
                sock = malloc(sizeof(*sock));

                DBG("packet was SYN, initializing new connection @ %p", sock);

                memcpy(&sock->c_addr, &s_data->pkt_addr, c_addrlen);

                sock->s_data = s_data;
                sock->seq_num = random();
                sock->c_sock = -1;
                sock->status = TCP_SYN_RECV;

                sock->csum_p = csum_sockaddr_partial((struct sockaddr *)&s_data->pkt_addr, 1, s_data->csum_p);

                struct tcphdr buf = {
                    .th_seq = htonl(sock->seq_num),
                    .th_ack = tcphdr->th_seq,
                    .th_flags = TH_SYN | TH_ACK
                };
                s_prep_c_addr(sock, &buf);

                uint16_t tsz = htons(sizeof(buf));
                buf.th_sum = ~csum_partial(&buf.th_seq, 16, csum_partial(&tsz, sizeof(tsz), sock->csum_p));

                HASH_ADD(hh, s_data->o_socks_by_caddr, c_addr, c_addrlen, sock);

                ((struct sockaddr_in *)&s_data->pkt_addr)->sin_port = htons(0);

                DBG("sending SYN/ACK");
                if ((sz = sendto(w->fd, &buf, sizeof(buf), 0, (struct sockaddr *)&s_data->pkt_addr, s_data->s_addrlen)) == -1) {
                    perror("sendto");
                    ev_break(EV_A_ EVBREAK_ONE);
                    return;
                } else if (sz != sizeof(buf)) {
                    fprintf(stderr, "sendto %s our packet: tried %lu, sent %zd\n", (size_t)sz > sizeof(buf) ? "expanded" : "truncated", sizeof(buf), sz);
                }

                ev_init(&sock->tm_w, s_tm_cb);
                sock->tm_w.repeat = 10. * 60.;
                sock->tm_w.data = sock;
                ev_timer_again(EV_A_ &sock->tm_w);
            } else {
                DBG("packet was not SYN, ignoring");
            }

            return;
        }

        if (tcphdr->th_off != 5) {
            DBG("TCP options were specified, dropping packet");
            return;
        }

        /*
        if (th_flags == TH_RST) {
            DBG("RST received, cleaning up socket");
            sock->status = TCP_CLOSE;
            s_sock_cleanup(EV_A_ sock);
        }
        */

        if (th_flags & ~(TH_PUSH | TH_ACK)) {
            DBG("TCP flags not PSH and/or ACK, dropping packet");
            return;
        }

        if (sock->status == TCP_SYN_RECV) {
            assert(sock->c_sock == -1);

            DBG("no UDP socket for this connection, shifting to ESTABLISHED");

            sock->status = TCP_ESTABLISHED;

            struct addrinfo *res;
            r = getaddrinfo(s_data->common_data->remote_host, s_data->common_data->remote_port, NULL, &res);
            if (r) {
                fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(r));
                ev_break(EV_A_ EVBREAK_ONE);
                return;
            }

            if ((sock->c_sock = socket(s_data->s_addr->sa_family, SOCK_DGRAM, 0)) == -1) {
                perror("socket");
                ev_break(EV_A_ EVBREAK_ONE);
                return;
            }

            if (connect(sock->c_sock, res->ai_addr, res->ai_addrlen)) {
                perror("connect");
                ev_break(EV_A_ EVBREAK_ONE);
                return;
            }

            if (fcntl(sock->c_sock, F_SETFL, O_NONBLOCK) == -1) {
                perror("fcntl");
                ev_break(EV_A_ EVBREAK_ONE);
                return;
            }

            freeaddrinfo(res);

            ev_timer_stop(EV_A_ &sock->tm_w);
            sock->tm_w.repeat = 60. * 60. * 3.;
            ev_timer_start(EV_A_ &sock->tm_w);

            ev_io_init(&sock->io_w, sc_cb, sock->c_sock, EV_READ);
            sock->io_w.data = sock;
            ev_io_start(EV_A_ &sock->io_w);
        }

        assert(sock->status == TCP_ESTABLISHED);

        DBG("sending %zu bytes to client", (size_t)(sz - tcphdr->th_off * 4));
        sz = send(sock->c_sock, rptr + tcphdr->th_off * 4, sz - tcphdr->th_off * 4, 0);
        if (sz < 0) {
            perror("send");
            ev_break(EV_A_ EVBREAK_ONE);
            return;
        }
        return;
    }

    if (sz == 0)
        abort();

    if (errno != EINVAL) {
        perror("recvfrom");
        ev_break(EV_A_ EVBREAK_ONE);
    }
}

/* atexit cleanup */
static void s_cleanup() {
    if (!global_s_data)
        return;

    DBG("cleaning up");
    struct o_s_sock *sock, *tmp;
    HASH_ITER(hh, global_s_data->o_socks_by_caddr, sock, tmp) {
        s_sock_cleanup(EV_DEFAULT, sock, 1);
    }

    global_s_data = NULL;
}

static void s_finish(EV_P_ ev_signal *w __attribute__((unused)), int revents __attribute__((unused))) {
    s_cleanup();
    ev_break(EV_A_ EVBREAK_ALL);
}

int start_server(const struct common_data *common_data) {
    struct addrinfo *res;
    int r = getaddrinfo(common_data->listen_host, common_data->listen_port, NULL, &res);
    if (r) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(r));
        return 1;
    }

    char proto[] = { 0, IPPROTO_TCP };

    struct s_data s_data = {
        .common_data = common_data,
        .s_addr = res->ai_addr,
        .s_addrlen = res->ai_addrlen,
        .csum_p = csum_sockaddr_partial(res->ai_addr, 1,
                csum_partial(&proto, sizeof(proto), 0))
    };

    s_data.s_sock = socket(s_data.s_addr->sa_family, SOCK_RAW, IPPROTO_TCP);
    if (s_data.s_sock == -1) {
        perror("socket");
        freeaddrinfo(res);
        return 1;
    }

    if (bind(s_data.s_sock, res->ai_addr, res->ai_addrlen) == -1) {
        perror("bind");
        return 2;
    }

    if (fcntl(s_data.s_sock, F_SETFL, O_NONBLOCK) == -1) {
        perror("fcntl");
        freeaddrinfo(res);
        return 1;
    }

    global_s_data = &s_data;

    struct ev_loop *loop = EV_DEFAULT;
    ev_io s_watcher;
    ev_signal iwatcher, twatcher;

    ev_io_init(&s_watcher, ss_cb, s_data.s_sock, EV_READ);
    ev_io_start(EV_A_ &s_watcher);
    ev_signal_init(&iwatcher, s_finish, SIGINT);
    ev_signal_start(loop, &iwatcher);
    ev_signal_init(&twatcher, s_finish, SIGTERM);
    ev_signal_start(loop, &twatcher);

    s_watcher.data = &s_data;

    DBG("initialization complete, starting event loop");
    r = ev_run(loop, 0);

    s_cleanup();

    if (free_mem_on_exit)
        ev_loop_destroy(loop);

    freeaddrinfo(res);

    return r;
}
