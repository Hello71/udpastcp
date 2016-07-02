#include <assert.h>
#include <ev.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "common.h"
#include "server.h"
#include "uthash.h"

struct o_s_sock {
    struct s_data *s_data;
    struct sockaddr_storage c_addr;
    struct ev_timer tm_w;
    struct ev_io io_w;
    UT_hash_handle hh;
    int c_sock;
    uint16_t seq_num;
    uint8_t status;
};

struct s_data {
    struct sockaddr *s_addr;
    struct sockaddr_storage pkt_addr;
    const char *r_host;
    const char *r_port;
    struct o_s_sock *o_socks_by_caddr;
    int s_sock;
    socklen_t s_addrlen;
};

static inline void s_prep_c_addr(struct o_s_sock *sock, struct tcphdr *hdr) {
    memset(hdr, 0, sizeof(*hdr));
    hdr->th_sport = ((struct sockaddr_in *)sock->s_data->s_addr)->sin_port;
    hdr->th_dport = ((struct sockaddr_in *)&sock->c_addr)->sin_port;
    hdr->th_seq = htonl(sock->seq_num++);
    hdr->th_off = 5;
}

static void s_sock_cleanup(EV_P_ struct o_s_sock *sock) {
    DBG("cleaning up socket %p", sock);

    if (sock->status == TCP_ESTABLISHED) {
        DBG("socket was ESTABLISHED, sending FIN");
        struct tcphdr buf;
        s_prep_c_addr(sock, &buf);
        buf.th_flags = TH_FIN;
        ssize_t sz;
        if ((sz = sendto(sock->s_data->s_sock, &buf, sizeof(buf), 0, (struct sockaddr *)&sock->s_data->pkt_addr, sock->s_data->s_addrlen)) == -1) {
            perror("sendto");
            ev_break(EV_A_ EVBREAK_ONE);
            return;
        } else if (sz != sizeof(buf)) {
            fprintf(stderr, "sendto %s our packet: tried %lu, sent %zd\n", (size_t)sz > sizeof(buf) ? "expanded" : "truncated", sizeof(buf), sz);
        }
    }

    if (sock->c_sock != -1) {
        close(sock->c_sock);
    }

    ev_timer_stop(EV_A_ &sock->tm_w);
    ev_io_stop(EV_A_ &sock->io_w);

    HASH_DEL(sock->s_data->o_socks_by_caddr, sock);

    free(sock);
}

static void s_tm_cb(EV_P_ ev_timer *w, int revents __attribute__((unused))) {
    DBG("timing out socket %p", w->data);
    s_sock_cleanup(EV_A_ w->data);
}

static void sc_cb(EV_P_ ev_io *w, int revents __attribute__((unused))) {
    struct o_s_sock *sock = w->data;
    char rbuf[16384];
    ssize_t sz;

    DBG("-- entering sc_cb --");

    if ((sz = recv(w->fd, rbuf, sizeof(rbuf), 0)) < 0) {
        perror("recv");
        ev_break(EV_A_ EVBREAK_ONE);
        return;
    }

    DBG("received %zd bytes matching socket %p", sz, sock);

    struct tcphdr hdr;
    s_prep_c_addr(sock, &hdr);
    hdr.th_off = 5;

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
}

static void ss_cb(EV_P_ ev_io *w, int revents __attribute__((unused))) {
    char rbuf[16384];
    ssize_t sz;
    struct s_data *s_data = w->data;
    socklen_t c_addrlen = s_data->s_addrlen;
    int r;

    DBG("-- entering ss_cb --");

    if ((sz = recvfrom(w->fd, rbuf, sizeof(rbuf), 0, (struct sockaddr *)&s_data->pkt_addr, &c_addrlen)) < 0) {
        perror("recvfrom");
        ev_break(EV_A_ EVBREAK_ONE);
        return;
    }

    if (c_addrlen != s_data->s_addrlen)
        abort();

#ifdef DEBUG
    char hbuf[NI_MAXHOST];
    r = getnameinfo((struct sockaddr *)&s_data->pkt_addr, c_addrlen, hbuf, sizeof(hbuf), NULL, 0, NI_NUMERICHOST);
    if (r) {
        fprintf(stderr, "getnameinfo: %s\n", gai_strerror(r));
        ev_break(EV_A_ EVBREAK_ONE);
        return;
    }
    DBG("received %zd bytes from %s", sz, hbuf);
#endif

    if ((size_t)sz < sizeof(struct tcphdr)) {
        DBG("packet is smaller than TCP header, ignoring");
        return;
    }

    struct tcphdr *tcphdr = (struct tcphdr *)rbuf;

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

            struct tcphdr buf = {
                .th_sport = tcphdr->th_dport,
                .th_dport = tcphdr->th_sport,
                .th_seq = htonl(sock->seq_num),
                .th_ack = tcphdr->th_seq,
                .th_flags = TH_SYN | TH_ACK,
                .th_off = 5
            };

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

    if (th_flags == TH_RST) {
        DBG("RST received, cleaning up socket");
        sock->status = TCP_CLOSE;
        s_sock_cleanup(EV_A_ sock);
    }

    if (th_flags & ~(TH_PUSH | TH_ACK)) {
        DBG("TCP flags not PSH and/or ACK, dropping packet");
        return;
    }

    if (sock->status == TCP_SYN_RECV) {
        assert(sock->c_sock == -1);

        DBG("no UDP socket for this connection, shifting to ESTABLISHED");

        sock->status = TCP_ESTABLISHED;

        struct addrinfo *res;
        r = getaddrinfo(s_data->r_host, s_data->r_port, NULL, &res);
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
    sz = send(sock->c_sock, rbuf + tcphdr->th_off * 4, sz - tcphdr->th_off * 4, 0);
    if (sz < 0) {
        perror("send");
        ev_break(EV_A_ EVBREAK_ONE);
        return;
    }
}

int start_server(const char *s_host, const char *s_port, const char *r_host, const char *r_port) {
    struct addrinfo *res;
    int r = getaddrinfo(s_host, s_port, NULL, &res);
    if (r) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(r));
        return 1;
    }

    struct s_data s_data = {
        .s_addr = res->ai_addr,
        .s_addrlen = res->ai_addrlen,
        .r_host = r_host,
        .r_port = r_port
    };

    s_data.s_sock = socket(s_data.s_addr->sa_family, SOCK_RAW, IPPROTO_TCP);
    if (s_data.s_sock == -1) {
        perror("socket");
        freeaddrinfo(res);
        return 1;
    }

    struct ev_loop *loop = EV_DEFAULT;
    ev_io s_watcher;

    ev_io_init(&s_watcher, ss_cb, s_data.s_sock, EV_READ);
    ev_io_start(EV_A_ &s_watcher);

    s_watcher.data = &s_data;

    DBG("initialization complete, starting event loop");
    r = ev_run(loop, 0);

    freeaddrinfo(res);

    return r;
}
