#include <assert.h>
#include <errno.h>
#include <ev.h>
#include <fcntl.h>
#include <limits.h>
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
#include "client.h"
#include "uthash.h"

#define PORTS_IN_INT (sizeof(int) * CHAR_BIT)

struct c_data {
    const char *r_host;
    const char *r_port;
    struct o_c_sock *o_socks_by_caddr;
    struct o_c_rsock *o_rsocks;
    struct sockaddr_storage pkt_addr;
    int s_sock;
    int i_sock;
    socklen_t s_addrlen;
};

struct o_c_rsock {
    struct sockaddr_storage r_addr;
    struct o_c_sock *o_socks_by_lport;
    struct c_data *c_data;
    unsigned int used_ports[32768 / PORTS_IN_INT];
    ev_io io_w;
    UT_hash_handle hh;
    int fd;
    socklen_t r_addrlen;
    uint16_t csum_p;
};

struct o_c_sock {
    struct sockaddr_storage c_address;
    struct o_c_rsock *rsock;
    char *pending_data;
    size_t pending_data_size;
    ev_timer tm_w;
    UT_hash_handle hh_lp;
    UT_hash_handle hh_ca;
    uint16_t csum_p;
    uint16_t seq_num;
    in_port_t l_port;
    uint8_t status;
    int8_t syn_retries;
};

static struct c_data *global_c_data;

static const int8_t tcp_syn_retry_timeouts[] = { 0, 3, 6, 12, 24, -1 };

/* check if a port offset is set in a int */
static inline int check_resv_poff(unsigned int *used_ports, uint16_t poff) {
    if (used_ports[poff / PORTS_IN_INT] & (1 << (poff % PORTS_IN_INT)))
        return 0;
    used_ports[poff / PORTS_IN_INT] |= 1 << (poff % PORTS_IN_INT);
    return poff;
}

/* reserve a local TCP port */
static inline uint16_t reserve_port(unsigned int *used_ports) {
    long r;

    // randomly try some places, hope this will give us reasonably uniform distribution
    for (int i = 1; i <= 16; i++) {
        r = random();

        do {
            if (check_resv_poff(used_ports, r % 32768))
                return 32768 + (r % 32768);
        } while (r >>= 16);
    }

    // give up and go sequentially

    uint16_t ioff, spoff = random();
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

/* prepare server address in TCP header format */
static void c_prep_s_addr(struct o_c_sock *sock, struct tcphdr *hdr) {
    hdr->th_sport = sock->l_port;
    hdr->th_dport = IN_ADDR_PORT(&sock->rsock->r_addr);
    hdr->th_seq = htonl(sock->seq_num);
    hdr->th_off = 5;
}

/* clean up a socket, don't bother freeing anything if the program is stopping */
static void c_sock_cleanup(EV_P_ struct o_c_sock *sock, int stopping) {
    DBG("cleaning up sock @ %p", sock);
    if (sock->status != TCP_SYN_SENT) {
        struct tcphdr buf = {
            .th_flags = sock->status == TCP_ESTABLISHED ? TH_FIN : TH_RST
        };
        c_prep_s_addr(sock, &buf);

        ssize_t sz = send(sock->rsock->fd, &buf, sizeof(buf), 0);
        if (sz < 0) {
            perror("send");
            ev_break(EV_A_ EVBREAK_ONE);
            return;
        } else if ((size_t)sz != sizeof(buf)) {
            fprintf(stderr, "send %s our packet: tried %lu, sent %zd\n", (size_t)sz > sizeof(buf) ? "expanded" : "truncated", sizeof(buf), sz);
        }
    }

    if (!stopping || free_mem_on_exit) {
        DBG("freeing associated resources");
        free_port(sock->rsock->used_ports, sock->l_port);
        ev_timer_stop(EV_A_ &sock->tm_w);

        HASH_DELETE(hh_lp, sock->rsock->o_socks_by_lport, sock);
        HASH_DELETE(hh_ca, sock->rsock->c_data->o_socks_by_caddr, sock);

        if (!sock->rsock->o_socks_by_lport) {
            close(sock->rsock->fd);

            ev_io_stop(EV_A_ &sock->rsock->io_w);

            HASH_DEL(sock->rsock->c_data->o_rsocks, sock->rsock);

            free(sock->rsock);
        }

        free(sock);
    }
}

static void c_tm_cb(EV_P_ ev_timer *w, int revents __attribute__((unused))) {
    DBG("timing out socket %p", w->data);
    c_sock_cleanup(EV_A_ w->data, 0);
}

static int c_send_syn(struct o_c_sock *sock) {
    struct tcphdr buf = {
        .th_flags = TH_SYN
    };
    c_prep_s_addr(sock, &buf);
    sock->seq_num++;

    uint16_t tsz = htons(sizeof(buf));
    buf.th_sum = ~csum_partial(&buf.th_seq, 16, csum_partial(&tsz, sizeof(tsz), sock->csum_p));

    DBG("sending SYN to remote");
    ssize_t sz = send(sock->rsock->fd, &buf, sizeof(buf), 0);
    if (sz < 0) {
        perror("send");
        return 0;
    } else if ((size_t)sz != sizeof(buf)) {
        fprintf(stderr, "send %s our packet: tried %lu, sent %zd\n", (size_t)sz > sizeof(buf) ? "expanded" : "truncated", sizeof(buf), sz);
    }

    return 1;
}

static int c_adv_syn_tm(EV_P_ struct o_c_sock *sock) {
    int8_t next_retr = tcp_syn_retry_timeouts[sock->syn_retries++];

    if (next_retr < 0 || !c_send_syn(sock))
        return 0;

    if (next_retr) {
        ev_timer_set(&sock->tm_w, next_retr, 0.);
        ev_timer_start(EV_A_ &sock->tm_w);
    }

    return 1;
}

static void c_syn_tm_cb(EV_P_ ev_timer *w, int revents __attribute__((unused))) {
    if (!c_adv_syn_tm(EV_A_ w->data)) {
        DBG("connection timed out");
        c_sock_cleanup(EV_A_ w->data, 0);
    }
}

/* client raw socket callback */
static void cc_cb(struct ev_loop *loop, ev_io *w, int revents __attribute__((unused))) {
    DBG("-- entering cc_cb --");

    struct o_c_rsock *rsock = w->data;
    char rbuf[65536];
    socklen_t pkt_addrlen = sizeof(struct sockaddr_in6);
    ssize_t should_ssz, rsz, ssz;

    while ((rsz = recvfrom(w->fd, rbuf, sizeof(rbuf), 0, (struct sockaddr *)&rsock->c_data->pkt_addr, &pkt_addrlen)) != -1) {
        DBG("received %zd raw bytes on client", rsz);
        DBG("%u %zu", pkt_addrlen, sizeof(struct sockaddr_in6));

        if (pkt_addrlen > sizeof(struct sockaddr_in6))
            abort();

        char *rptr = rbuf;

        if (rsock->r_addr.ss_family == AF_INET) {
            if ((size_t)rsz < sizeof(struct iphdr)) {
                DBG("packet is smaller than IP header, ignoring");
                return;
            }

            if (((struct iphdr *)rptr)->protocol != IPPROTO_TCP)
                abort();

            uint32_t ihl = ((struct iphdr *)rptr)->ihl * 4;
            rptr = rptr + ihl;
            rsz -= ihl;
        }

        if ((size_t)rsz < sizeof(struct tcphdr))
            return;

        struct tcphdr *rhdr = (struct tcphdr *)rptr;

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
                .th_ack = rhdr->th_seq,
                .th_win = 65535,
                .th_flags = TH_ACK
            };
            c_prep_s_addr(sock, &shdr);

            uint16_t tsz = htons(sizeof(shdr) + sock->pending_data_size);
            shdr.th_sum = ~csum_partial(sock->pending_data, sock->pending_data_size, csum_partial(&shdr.th_seq, 16, csum_partial(&tsz, sizeof(tsz), sock->csum_p)));

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

        if (rhdr->th_flags & ~(TH_PUSH | TH_ACK)) {
            DBG("packet has strange flags, dropping");
            return;
        }

        if (sock->status == TCP_ESTABLISHED) {
            should_ssz = rsz - rhdr->th_off * 32 / CHAR_BIT;
            if (should_ssz > 0) {
                DBG("sending %zd bytes to client", should_ssz);
                ssz = sendto(rsock->c_data->s_sock, rptr + rhdr->th_off * 32 / CHAR_BIT, should_ssz, 0, (struct sockaddr *)&sock->c_address, rsock->c_data->s_addrlen);

                if (ssz < 0) {
                    perror("sendto");
                    ev_break(EV_A_ EVBREAK_ONE);
                    return;
                } else if ((size_t)ssz != should_ssz) {
                    fprintf(stderr, "sendto %s our packet: tried %lu, sent %zd\n", (size_t)ssz > should_ssz ? "expanded" : "truncated", should_ssz, ssz);
                }
            }
        }
    }

    if (errno != EAGAIN) {
        perror("recvfrom");
        ev_break(EV_A_ EVBREAK_ONE);
    }
}

/* initialize new raw socket */
static inline struct o_c_rsock * c_rsock_init(struct addrinfo *res) {
    struct o_c_rsock *rsock;
    rsock = malloc(sizeof(*rsock));
    memset(&rsock->used_ports, 0, sizeof(rsock->used_ports));

    memcpy(&rsock->r_addr, res->ai_addr, res->ai_addrlen);
    rsock->r_addrlen = res->ai_addrlen;
    freeaddrinfo(res);
    rsock->o_socks_by_lport = NULL;

    rsock->fd = socket(rsock->r_addr.ss_family, SOCK_RAW, IPPROTO_TCP);
    if (!rsock->fd) {
        perror("socket");
        return NULL;
    }

    if (connect(rsock->fd, (struct sockaddr *)&rsock->r_addr, rsock->r_addrlen) == -1) {
        perror("connect");
        return NULL;
    }

    if (fcntl(rsock->fd, F_SETFL, O_NONBLOCK) == -1) {
        perror("fcntl");
        return NULL;
    }

    struct sockaddr_storage our_addr;
    socklen_t our_addr_len = sizeof(our_addr);
    int r = getsockname(rsock->fd, (struct sockaddr *)&our_addr, &our_addr_len);
    if (r == -1) {
        perror("getsockname");
        return NULL;
    }

    char proto[] = { 0, IPPROTO_TCP };

    if (rsock->r_addr.ss_family != our_addr.ss_family)
        abort();

    rsock->csum_p = csum_partial(proto, sizeof(proto),
            csum_sockaddr_partial((struct sockaddr *)&our_addr, 0,
            csum_sockaddr_partial((struct sockaddr *)&rsock->r_addr, 1, 0)));

    return rsock;
}

/* client UDP socket callback */
static void cs_cb(EV_P_ ev_io *w, int revents __attribute__((unused))) {
    DBG("-- entering cs_cb --");
    struct c_data *c_data = w->data;
    socklen_t addresslen = c_data->s_addrlen;
    ssize_t sz;
    char rbuf[65536];

    while ((sz = recvfrom(w->fd, rbuf, sizeof(rbuf), 0, (struct sockaddr *)&c_data->pkt_addr, &addresslen)) != -1) {
        DBG("received %zd bytes on server", sz);

        if (addresslen != c_data->s_addrlen)
            abort();

        struct o_c_sock *sock;
        HASH_FIND(hh_ca, c_data->o_socks_by_caddr, &c_data->pkt_addr, addresslen, sock);

        if (!sock) {
            DBG("could not locate matching socket for client, initializing new connection");
            sock = calloc(1, sizeof(*sock));

            struct addrinfo *res;
            DBG("looking up [%s]:%s", c_data->r_host, c_data->r_port);
            // TODO: make this asynchronous
            int r = getaddrinfo(c_data->r_host, c_data->r_port, NULL, &res);
            if (r) {
                fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(r));
                ev_break(EV_A_ EVBREAK_ONE);
                return;
            }

            memcpy(&sock->c_address, &c_data->pkt_addr, addresslen);

            HASH_FIND(hh, c_data->o_rsocks, res->ai_addr, res->ai_addrlen, sock->rsock);

            if (!sock->rsock) {
                DBG("could not locate remote socket to host, initializing new raw socket");
                sock->rsock = c_rsock_init(res);
                if (!sock->rsock) {
                    ev_break(EV_A_ EVBREAK_ONE);
                    return;
                }
                sock->rsock->c_data = c_data;

                ev_io_init(&sock->rsock->io_w, cc_cb, sock->rsock->fd, EV_READ);
                sock->rsock->io_w.data = sock->rsock;
                ev_io_start(EV_A_ &sock->rsock->io_w);

                HASH_ADD(hh, c_data->o_rsocks, r_addr, sock->rsock->r_addrlen, sock->rsock);
            }

            uint16_t l_port = reserve_port(sock->rsock->used_ports);
            assert(l_port >= 32768);
            DBG("using port %hu", l_port);
            if (!l_port) {
                fputs("we ran out of ports?\n", stderr);
                ev_break(EV_A_ EVBREAK_ONE);
                return;
            }
            sock->l_port = htons(l_port);

            sock->csum_p = csum_partial(&sock->l_port, sizeof(in_port_t), sock->rsock->csum_p);

            HASH_ADD(hh_ca, c_data->o_socks_by_caddr, c_address, addresslen, sock);
            HASH_ADD(hh_lp, sock->rsock->o_socks_by_lport, l_port, sizeof(in_port_t), sock);

            sock->seq_num = random();

            sock->pending_data = malloc(sz);
            memcpy(sock->pending_data, rbuf, sz);
            sock->pending_data_size = sz;

            ev_init(&sock->tm_w, c_syn_tm_cb);
            sock->tm_w.data = sock;

            sock->syn_retries = 0;
            c_adv_syn_tm(EV_A_ sock);

            sock->status = TCP_SYN_SENT;

            return;
        }

        struct tcphdr tcp_hdr = {
            .th_win = 65535,
            .th_flags = TH_PUSH
        };
        c_prep_s_addr(sock, &tcp_hdr);

        uint16_t tsz = htons(sizeof(tcp_hdr) + sz);
        tcp_hdr.th_sum = ~csum_partial(rbuf, sz, csum_partial(&tcp_hdr.th_seq, 16, csum_partial(&tsz, sizeof(tsz), sock->csum_p)));

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
            if (errno == ENOBUFS) {
                fprintf(stderr, "sendmsg: out of buffer space\n");
                return;
            }
            perror("sendmsg");
            ev_break(EV_A_ EVBREAK_ONE);
            return;
        } else if ((size_t)sz != should_send_size) {
            fprintf(stderr, "sendmsg %s our packet: tried %lu, sent %zd\n", (size_t)sz > should_send_size ? "expanded" : "truncated", should_send_size, sz);
        }
        ev_timer_again(EV_A_ &sock->tm_w);
    }
    if (errno != EAGAIN) {
        perror("recvfrom");
        ev_break(EV_A_ EVBREAK_ONE);
    }
}

/* atexit cleanup */
static void c_cleanup() {
    if (!global_c_data)
        return;

    DBG("cleaning up");
    struct o_c_sock *sock, *tmp;
    HASH_ITER(hh_ca, global_c_data->o_socks_by_caddr, sock, tmp) {
        c_sock_cleanup(EV_DEFAULT, sock, 1);
    }

    global_c_data = NULL;
}

static void c_finish(EV_P_ ev_signal *w __attribute__((unused)), int revents __attribute__((unused))) {
    c_cleanup();
    ev_break(EV_A_ EVBREAK_ALL);
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

    if (fcntl(c_data.s_sock, F_SETFL, O_NONBLOCK) == -1) {
        perror("fcntl");
        return 4;
    }

    global_c_data = &c_data;
    atexit(c_cleanup);

    struct ev_loop *loop = EV_DEFAULT;
    ev_io s_watcher;
    ev_signal iwatcher, twatcher;

    s_watcher.data = &c_data;

    ev_io_init(&s_watcher, cs_cb, c_data.s_sock, EV_READ);
    ev_io_start(loop, &s_watcher);
    ev_signal_init(&iwatcher, c_finish, SIGINT);
    ev_signal_start(loop, &iwatcher);
    ev_signal_init(&twatcher, c_finish, SIGTERM);
    ev_signal_start(loop, &twatcher);

    DBG("initialization complete, starting event loop");
    r = ev_run(loop, 0);

    c_cleanup();

    if (free_mem_on_exit)
        ev_loop_destroy(loop);

    return r;
}
