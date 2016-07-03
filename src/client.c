#include <ev.h>
#include <limits.h>
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
#include "checksum.h"
#include "client.h"
#include "uthash.h"

#define PORTS_IN_INT sizeof(int) * CHAR_BIT

struct o_c_rsock {
    struct sockaddr *r_addr;
    struct o_c_sock *o_socks_by_lport;
    struct c_data *c_data;
    unsigned int used_ports[32768 / PORTS_IN_INT];
    ev_io io_w;
    UT_hash_handle hh;
    int fd;
    uint16_t csum_a;
    socklen_t r_addrlen;
};

struct o_c_sock {
    struct sockaddr *c_address;
    struct o_c_rsock *rsock;
    char *pending_data;
    size_t pending_data_size;
    ev_timer tm_w;
    UT_hash_handle hh_lp;
    UT_hash_handle hh_ca;
    uint16_t seq_num;
    in_port_t l_port;
    uint8_t status;
    int8_t syn_retries;
};

struct c_data {
    const char *r_host;
    const char *r_port;
    struct o_c_sock *o_socks_by_caddr;
    struct o_c_rsock *o_rsocks;
    struct sockaddr_storage pkt_addr;
    socklen_t s_addrlen;
    int s_sock;
    int i_sock;
};

static struct c_data *global_c_data;

static const uint8_t tcp_syn_retry_timeouts[] = { 3, 6, 12, 24, 0 };

static inline int check_resv_poff(unsigned int *used_ports, uint16_t poff) {
    if (used_ports[poff / PORTS_IN_INT] & (1 << poff % PORTS_IN_INT)) {
        used_ports[poff / PORTS_IN_INT] |= 1 << poff % PORTS_IN_INT;
        return poff;
    }
    return 0;
}

/* reserve a local TCP port (local addr, remote addr, remote port are usually
 * fixed in the tuple) */
static uint16_t reserve_port(unsigned int *used_ports) {
    long r;

    // randomly try 16 places
    for (int i = 1; i <= 16; i++) {
        r = random();

        if (check_resv_poff(used_ports, r % 32768))
            return 32768 + r;

        if (check_resv_poff(used_ports, (r >> 16) % 32768))
            return 32768 + (r >> 16);
    }

    // give up and go sequentially

    uint16_t ioff, spoff = (r >> 16) + 1;
    size_t moff, smoff = spoff / PORTS_IN_INT;

    /* two step process:
     * +-----------------------------+-----------------------+
     * | 32768 32769 32770 32771 ... | 32800 32801 32802 ... |
     * +-----------------------------+-----------------------+
     * 1.            ^^^^^ ^^^^^ ...
     * 2.                        ffs:  ^^^^^ ^^^^^ ^^^^^ ...
     */

    // do the rest of the integer
    for (ioff = spoff % PORTS_IN_INT; ioff <= PORTS_IN_INT; ioff++) {
        if (used_ports[smoff] & (1 << ioff)) {
            used_ports[smoff] |= 1 << ioff;
            return 32768 + spoff + ioff;
        }
    }

    // go one integer at a time
    for (moff = smoff + 1; moff != smoff; moff++) {
        if ((ioff = ffs(~used_ports[moff]))) {
            used_ports[moff] |= 1 << (ioff - 1);
            return 32768 + smoff * PORTS_IN_INT + (ioff - 1);
        }
    }

    return 0;
}

static void free_port(unsigned int *used_ports, uint16_t port_num) {
    used_ports[port_num / PORTS_IN_INT] ^= 1 << (port_num % PORTS_IN_INT);
}

static void c_sock_cleanup(EV_P_ struct o_c_sock *sock, int stopping) {
    if (sock->status != TCP_SYN_SENT) {
        struct tcphdr buf = {
            .th_sport = sock->l_port,
            .th_dport = ((struct sockaddr_in *)sock->rsock->r_addr)->sin_port,
            .th_seq = htonl(sock->seq_num),
            .th_off = 5,
            .th_flags = sock->status == TCP_ESTABLISHED ? TH_FIN : TH_RST
        };

        ssize_t sz = send(sock->rsock->fd, &buf, sizeof(buf), 0);
        if (sz < 0) {
            perror("send");
            ev_break(EV_A_ EVBREAK_ONE);
            return;
        } else if ((size_t)sz != sizeof(buf)) {
            fprintf(stderr, "send %s our packet: tried %lu, sent %zd\n", (size_t)sz > sizeof(buf) ? "expanded" : "truncated", sizeof(buf), sz);
        }

        return;
    }

    if (!stopping) {
        free_port(sock->rsock->used_ports, sock->l_port);
        ev_timer_stop(EV_A_ &sock->tm_w);

        HASH_DELETE(hh_lp, sock->rsock->o_socks_by_lport, sock);

        if (!sock->rsock->o_socks_by_lport) {
            close(sock->rsock->fd);

            ev_io_stop(EV_A_ &sock->rsock->io_w);

            HASH_DEL(sock->rsock->c_data->o_rsocks, sock->rsock);

            free(sock->rsock->r_addr);
            free(sock->rsock);
        }

        free(sock);
    }
}

static void c_tm_cb(EV_P_ ev_timer *w, int revents __attribute__((unused))) {
    DBG("timing out socket %p", w->data);
    c_sock_cleanup(EV_A_ w->data, 0);
}

static int c_adv_syn_tm(EV_P_ struct o_c_sock *sock) {
    uint8_t next_retr = tcp_syn_retry_timeouts[sock->syn_retries++];
    if (next_retr) {
        ev_timer_set(&sock->tm_w, next_retr, 0.);
        ev_timer_start(EV_A_ &sock->tm_w);
    }
    return !!next_retr;
}

static void c_syn_tm_cb(EV_P_ ev_timer *w, int revents __attribute__((unused))) {
    if (c_adv_syn_tm(EV_A_ w->data)) {
        // resend SYN
    } else {
        DBG("connection timed out");
        c_sock_cleanup(EV_A_ w->data, 0);
    }
}

static void cc_cb(struct ev_loop *loop, ev_io *w, int revents __attribute__((unused))) {
    DBG("-- entering cc_cb --");

    struct o_c_rsock *rsock = w->data;
    char rbuf[65536];
    socklen_t pkt_addrlen = sizeof(struct sockaddr_in6);
    ssize_t should_ssz, rsz, ssz;

    if ((rsz = recvfrom(w->fd, rbuf, sizeof(rbuf), 0, (struct sockaddr *)&rsock->c_data->pkt_addr, &pkt_addrlen)) == -1) {
        perror("recvfrom");
        ev_break(EV_A_ EVBREAK_ONE);
        return;
    }

    DBG("received %zd raw bytes on client", rsz);

    if (pkt_addrlen > sizeof(struct sockaddr_in6))
        abort();

    if ((size_t)rsz < sizeof(struct tcphdr))
        return;

    struct tcphdr *rhdr = (struct tcphdr *)rbuf;

    struct o_c_sock *sock;

    HASH_FIND(hh_lp, rsock->o_socks_by_lport, &rhdr->th_dport, sizeof(in_port_t), sock);

    if (!sock) {
        DBG("could not find conn with lport %hu", ntohs(rhdr->th_dport));
        return;
    }

    if (sock->status == TCP_SYN_SENT && rhdr->th_flags == (TH_SYN | TH_ACK)) {
        DBG("SYN/ACK received, connection established");

        sock->status = TCP_ESTABLISHED;

        struct tcphdr shdr = {
            .th_sport = sock->l_port,
            .th_dport = ((struct sockaddr_in *)sock->rsock->r_addr)->sin_port,
            .th_seq = htonl(sock->seq_num),
            .th_ack = rhdr->th_seq,
            .th_win = 65535,
            .th_flags = TH_ACK,
            .th_off = 5
        };

        sock->seq_num += sock->pending_data_size;

        struct iovec iovs[2] = {
            { .iov_base = &shdr, .iov_len = sizeof(shdr) },
            { .iov_base = sock->pending_data, .iov_len = sock->pending_data_size }
        };

        struct msghdr msghdr = {
            .msg_name = NULL,
            .msg_namelen = 0,
            .msg_iov = iovs,
            .msg_iovlen = sizeof(iovs) / sizeof(iovs[0])
        };

        should_ssz = sizeof(shdr) + sock->pending_data_size;
        ssz = sendmsg(rsock->fd, &msghdr, 0);

        if (ssz < 0) {
            perror("sendmsg");
            ev_break(EV_A_ EVBREAK_ONE);
            return;
        } else if ((size_t)ssz != should_ssz) {
            fprintf(stderr, "sendmsg %s our packet: tried %lu, sent %zd\n", (size_t)ssz > should_ssz ? "expanded" : "truncated", should_ssz, ssz);
        }

        free(sock->pending_data);

        ev_timer_stop(EV_A_ &sock->tm_w);
        // this delay is not very important because one, it is OK if UDP
        // packets are lost, and two, they are only delayed until a new
        // connection is established. however, it is probably a good idea to
        // set this higher than the UDP ping delay if you are using one.
        ev_timer_init(&sock->tm_w, c_tm_cb, 10. * 60., 10. * 60.);
        ev_timer_start(EV_A_ &sock->tm_w);
    }

    should_ssz = rsz - rhdr->th_off * 32 / CHAR_BIT;
    if (should_ssz > 0) {
        DBG("sending %zd bytes to client", should_ssz);
        ssz = sendto(rsock->c_data->s_sock, rbuf + rhdr->th_off * 32 / CHAR_BIT, should_ssz, 0, sock->c_address, rsock->c_data->s_addrlen);

        if (ssz < 0) {
            perror("sendto");
            ev_break(EV_A_ EVBREAK_ONE);
            return;
        } else if ((size_t)ssz != should_ssz) {
            fprintf(stderr, "sendto %s our packet: tried %lu, sent %zd\n", (size_t)ssz > should_ssz ? "expanded" : "truncated", should_ssz, ssz);
        }
    }
}

#define SIX_OR_FOUR(sa, six, four, neither) \
    (((struct sockaddr *)(sa))->sa_family == AF_INET6 ? (six) : ((struct sockaddr *)(sa))->sa_family == AF_INET ? (four) : abort(), neither)

#define EXTRACT_IN_ADDR(sa) \
    SIX_OR_FOUR((struct sockaddr *)(sa), &(((struct sockaddr_in6 *)(sa))->sin6_addr), &(((struct sockaddr_in *)(sa))->sin_addr), NULL), \
    SIX_OR_FOUR((struct sockaddr *)(sa), sizeof(struct in6_addr), sizeof(in_addr_t), 0)

static int c_rsock_init(struct o_c_sock *sock, struct addrinfo *res) {
    sock->rsock = malloc(sizeof(*sock->rsock));
    memset(&sock->rsock->used_ports, 0, sizeof(sock->rsock->used_ports));
    sock->rsock->r_addr = malloc(res->ai_addrlen);

    memcpy(sock->rsock->r_addr, res->ai_addr, res->ai_addrlen);
    sock->rsock->r_addrlen = res->ai_addrlen;
    freeaddrinfo(res);
    sock->rsock->o_socks_by_lport = NULL;

    sock->rsock->fd = socket(sock->rsock->r_addr->sa_family, SOCK_RAW, IPPROTO_TCP);
    if (!sock->rsock->fd) {
        perror("socket");
        return 0;
    }

    if (connect(sock->rsock->fd, sock->rsock->r_addr, sock->rsock->r_addrlen) == -1) {
        perror("connect");
        return 0;
    }

    struct sockaddr_storage our_addr;
    socklen_t our_addr_len = sizeof(our_addr);
    int r = getsockname(sock->rsock->fd, (struct sockaddr *)&our_addr, &our_addr_len);
    if (r == -1) {
        perror("getsockname");
        return 0;
    }

    //sock->rsock->csum_a = csum_partial(EXTRACT_IN_ADDR(sock->rsock->r_addr), csum_partial(EXTRACT_IN_ADDR(&our_addr), 0));

    return 1;
}

static void cs_cb(EV_P_ ev_io *w, int revents __attribute__((unused))) {
    DBG("-- entering cs_cb --");
    struct c_data *c_data = w->data;
    socklen_t addresslen = c_data->s_addrlen;
    ssize_t sz;
    char rbuf[65536];

    if ((sz = recvfrom(w->fd, rbuf, sizeof(rbuf), 0, (struct sockaddr *)&c_data->pkt_addr, &addresslen)) == -1) {
        perror("recvfrom");
        ev_break(EV_A_ EVBREAK_ONE);
        return;
    }

    DBG("received %zd bytes on server", sz);

    if (addresslen != c_data->s_addrlen)
        abort();

    struct o_c_sock *sock;
    HASH_FIND(hh_ca, c_data->o_socks_by_caddr, &c_data->pkt_addr, addresslen, sock);

    if (!sock) {
        DBG("could not locate matching socket for client, initializing new connection");
        sock = calloc(1, sizeof(*sock));

        struct addrinfo *res;
        DBG("looking up %s:%s", c_data->r_host, c_data->r_port);
        // TODO: make this asynchronous
        int r = getaddrinfo(c_data->r_host, c_data->r_port, NULL, &res);
        if (r) {
            fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(r));
            ev_break(EV_A_ EVBREAK_ONE);
            return;
        }

        sock->c_address = malloc(addresslen);
        memcpy(sock->c_address, &c_data->pkt_addr, addresslen);

        HASH_FIND(hh, c_data->o_rsocks, res->ai_addr, res->ai_addrlen, sock->rsock);

        if (!sock->rsock) {
            DBG("could not locate remote socket to host, initializing new raw socket");
            if (!c_rsock_init(sock, res)) {
                ev_break(EV_A_ EVBREAK_ONE);
                return;
            }
            sock->rsock->c_data = c_data;

            ev_io_init(&sock->rsock->io_w, cc_cb, sock->rsock->fd, EV_READ);
            sock->rsock->io_w.data = sock->rsock;
            ev_io_start(EV_A_ &sock->rsock->io_w);

            HASH_ADD_KEYPTR(hh, c_data->o_rsocks, sock->rsock->r_addr, sock->rsock->r_addrlen, sock->rsock);
        }

        uint16_t l_port = reserve_port(sock->rsock->used_ports);
        DBG("using port %hu", l_port);
        if (!l_port) {
            fputs("we ran out of ports?\n", stderr);
            ev_break(EV_A_ EVBREAK_ONE);
            return;
        }
        sock->l_port = htons(l_port);

        HASH_ADD_KEYPTR(hh_ca, c_data->o_socks_by_caddr, sock->c_address, addresslen, sock);
        HASH_ADD(hh_lp, sock->rsock->o_socks_by_lport, l_port, sizeof(in_port_t), sock);

        sock->seq_num = random();

        struct tcphdr buf = {
            .th_sport = sock->l_port,
            .th_dport = ((struct sockaddr_in *)sock->rsock->r_addr)->sin_port,
            .th_seq = htonl(sock->seq_num++),
            .th_flags = TH_SYN,
            .th_off = 5
        };

        sock->pending_data = malloc(sz);
        memcpy(sock->pending_data, rbuf, sz);
        sock->pending_data_size = sz;

        DBG("sending SYN to remote");
        sz = send(sock->rsock->fd, &buf, sizeof(buf), 0);
        if (sz < 0) {
            perror("send");
            ev_break(EV_A_ EVBREAK_ONE);
            return;
        } else if ((size_t)sz != sizeof(buf)) {
            fprintf(stderr, "send %s our packet: tried %lu, sent %zd\n", (size_t)sz > sizeof(buf) ? "expanded" : "truncated", sizeof(buf), sz);
        }

        // resend SYN

        ev_timer_init(&sock->tm_w, c_syn_tm_cb, 0., tcp_syn_retry_timeouts[0]);
        sock->tm_w.data = sock;
        sock->syn_retries = 0;
        c_adv_syn_tm(EV_A_ sock);

        sock->status = TCP_SYN_SENT;

        return;
    }

    struct tcphdr tcp_hdr = {
        .th_sport = sock->l_port,
        .th_dport = ((struct sockaddr_in *)sock->rsock->r_addr)->sin_port,
        .th_seq = htonl(sock->seq_num),
        .th_off = 5,
        .th_win = 65535,
        .th_flags = TH_PUSH
    };

    sock->seq_num += sz;

    struct iovec iovs[2] = {
        { .iov_base = &tcp_hdr, .iov_len = sizeof(tcp_hdr) },
        { .iov_base = rbuf, .iov_len = sz }
    };

    struct msghdr msghdr = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_iov = iovs,
        .msg_iovlen = sizeof(iovs) / sizeof(iovs[0])
    };

    size_t should_send_size = sizeof(tcp_hdr) + sz;
    DBG("sending %zd raw bytes containing %zd bytes payload to remote", should_send_size, sz);
    sz = sendmsg(sock->rsock->fd, &msghdr, 0);
    if (sz < 0) {
        perror("sendmsg");
        ev_break(EV_A_ EVBREAK_ONE);
        return;
    } else if ((size_t)sz != should_send_size) {
        fprintf(stderr, "sendmsg %s our packet: tried %lu, sent %zd\n", (size_t)sz > should_send_size ? "expanded" : "truncated", should_send_size, sz);
    }
    ev_timer_again(EV_A_ &sock->tm_w);
}

static void c_cleanup() {
    if (!global_c_data)
        return;

    DBG("cleaning up");
    struct o_c_sock *sock;
    for (sock = global_c_data->o_socks_by_caddr; sock != NULL; sock = sock->hh_ca.next) {
        switch (sock->status) {
        case TCP_CLOSE:
            break;
        default:
            c_sock_cleanup(EV_DEFAULT, sock, 1);
        }
        // don't bother freeing anything because we're about to exit anyways
    }

    global_c_data = NULL;
}

int start_client(const char *s_host, const char *s_port, const char *r_host, const char *r_port) {
    struct addrinfo *res;
    int r = getaddrinfo(s_host, s_port, NULL, &res);
    if (r) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(r));
        return 3;
    }

    struct c_data c_data = {
        .s_addrlen = res->ai_addrlen,
        .r_host = r_host,
        .r_port = r_port
    };

    c_data.s_sock = socket(res->ai_family, SOCK_DGRAM, 0);
    if (c_data.s_sock == -1) {
        perror("socket");
        return 1;
    }

    if (bind(c_data.s_sock, res->ai_addr, res->ai_addrlen) == -1) {
        perror("bind");
        return 2;
    }

    freeaddrinfo(res);

    global_c_data = &c_data;
    atexit(c_cleanup);

    struct ev_loop *loop = EV_DEFAULT;
    ev_io s_watcher;

    s_watcher.data = &c_data;

    ev_io_init(&s_watcher, cs_cb, c_data.s_sock, EV_READ);
    ev_io_start(loop, &s_watcher);

    DBG("initialization complete, starting event loop");
    r = ev_run(loop, 0);

    c_cleanup();
    return r;
}
