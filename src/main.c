/* sparrowd: one router per process. Single poll() event loop, two UDP sockets
 * (data + control), all state in static storage. No heap allocation anywhere in
 * this code; `make check-noheap` enforces that on the object files. */
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#include <mach/mach.h>
#endif

#include "proto.h"
#include "topo.h"

static router_t R;          /* the whole router lives in .bss */
static topo_t T;
static int data_fd = -1, ctl_fd = -1;
static uint16_t base_port = 20000;
static uint32_t loss_ppm;   /* injected packet loss on transmit */
static uint64_t rng_state = 0x9E3779B97F4A7C15ull;
static uint64_t dropped_tx;
static volatile sig_atomic_t stop;

static uint64_t wall_us(void *ctx) {
    (void)ctx;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts); /* shared across processes, so convergence can be timed */
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)ts.tv_nsec / 1000;
}

static uint32_t rnd(void) {
    rng_state ^= rng_state << 13; rng_state ^= rng_state >> 7; rng_state ^= rng_state << 17;
    return (uint32_t)(rng_state >> 11);
}

static void tx(void *ctx, uint16_t nbr, const uint8_t *buf, size_t len) {
    (void)ctx;
    if (loss_ppm && rnd() % 1000000u < loss_ppm) { dropped_tx++; return; }
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(0x7f000001u);
    a.sin_port = htons((uint16_t)(base_port + nbr));
    (void)sendto(data_fd, buf, len, 0, (struct sockaddr *)&a, sizeof a);
}

static int bind_udp(uint16_t port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(0x7f000001u);
    a.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) < 0) { close(fd); return -1; }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    return fd;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static long rss_kb(void) {
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
#ifdef __APPLE__
    return ru.ru_maxrss / 1024; /* bytes on macOS */
#else
    return ru.ru_maxrss;        /* kilobytes on Linux */
#endif
}

/* Current resident set size in KB, read by the process itself. */
static long rss_now_kb(void) {
#ifdef __APPLE__
    mach_task_basic_info_data_t info;
    mach_msg_type_number_t cnt = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info, &cnt) != KERN_SUCCESS) return -1;
    return (long)(info.resident_size / 1024);
#else
    FILE *f = fopen("/proc/self/statm", "r");
    long pages = -1, res = -1;
    if (!f) return -1;
    if (fscanf(f, "%ld %ld", &pages, &res) != 2) res = -1;
    fclose(f);
    return res < 0 ? -1 : res * (sysconf(_SC_PAGESIZE) / 1024);
#endif
}

static void control(const char *cmd, size_t n, struct sockaddr_in *from, socklen_t fl) {
    static char out[8192];
    size_t len = 0;
    char line[128];
    if (n >= sizeof line) n = sizeof line - 1;
    memcpy(line, cmd, n);
    line[n] = 0;
    unsigned v = 0;
    double pct = 0;
    if (!strncmp(line, "fib", 3)) len = router_fib_text(&R, out, sizeof out);
    else if (!strncmp(line, "stats", 5)) {
        len = router_stats_text(&R, out, sizeof out);
        int w = snprintf(out + len, sizeof out - len, "dropped_tx %llu\nmaxrss_kb %ld\nrss_kb %ld\n",
                         (unsigned long long)dropped_tx, rss_kb(), rss_now_kb());
        if (w > 0) len += (size_t)w;
    } else if (sscanf(line, "ifdown %u", &v) == 1) len = (size_t)snprintf(out, sizeof out, "%d\n", router_ifdown(&R, (uint16_t)v));
    else if (sscanf(line, "ifup %u", &v) == 1) len = (size_t)snprintf(out, sizeof out, "%d\n", router_ifup(&R, (uint16_t)v));
    else if (sscanf(line, "loss %lf", &pct) == 1) {
        loss_ppm = (uint32_t)(pct * 10000.0);
        len = (size_t)snprintf(out, sizeof out, "ok\n");
    } else if (!strncmp(line, "capture", 7)) {
        for (size_t i = 0; i < R.last_valid_len && len + 3 < sizeof out; i++)
            len += (size_t)snprintf(out + len, sizeof out - len, "%02x", R.last_valid[i]);
        out[len++] = '\n';
    } else if (!strncmp(line, "quit", 4)) { stop = 1; len = (size_t)snprintf(out, sizeof out, "bye\n"); }
    else len = (size_t)snprintf(out, sizeof out, "?\n");
    (void)sendto(ctl_fd, out, len, 0, (struct sockaddr *)from, fl);
}

static void on_sig(int s) { (void)s; stop = 1; }

static void usage(void) {
    fprintf(stderr, "usage: sparrowd -t topo -i id [-m ls|dv] [-k hexkey | -K keyfile] [-p baseport]\n"
                    "                [-H hello_ms] [-D dead_ms]\n");
    exit(2);
}

int main(int argc, char **argv) {
    const char *topo = NULL, *keyhex = NULL, *keyfile = NULL;
    static char keybuf[160];
    int id = -1, mode = MODE_LS;
    timers_t t = {.hello_ms = 50, .dead_ms = 200, .rxmt_ms = 100, .refresh_ms = 10000,
                  .maxage_s = 30, .dv_period_ms = 1000, .dv_trigger_ms = 20};
    int opt;
    while ((opt = getopt(argc, argv, "t:i:m:k:K:p:H:D:")) != -1) {
        switch (opt) {
        case 't': topo = optarg; break;
        case 'i': id = atoi(optarg); break;
        case 'm': mode = !strcmp(optarg, "dv") ? MODE_DV : MODE_LS; break;
        case 'k': keyhex = optarg; break;
        case 'K': keyfile = optarg; break; /* keeps the key out of ps / /proc/<pid>/cmdline */
        case 'p': base_port = (uint16_t)atoi(optarg); break;
        case 'H': t.hello_ms = (uint32_t)atoi(optarg); break;
        case 'D': t.dead_ms = (uint32_t)atoi(optarg); break;
        default: usage();
        }
    }
    if (!topo || id <= 0 || id >= MAX_ROUTERS) usage();
    if (topo_load(&T, topo) != 0) { fprintf(stderr, "bad topology %s\n", topo); return 1; }

    router_init(&R, (uint16_t)id, mode, &t, tx, NULL, wall_us, NULL);
    rng_state ^= (uint64_t)id * 0x2545F4914F6CDD1Dull ^ wall_us(NULL);
    if (keyfile) {
        FILE *kf = fopen(keyfile, "r");
        size_t n = 0;
        int ch;
        if (!kf) { perror(keyfile); return 1; }
        while ((ch = fgetc(kf)) != EOF && n + 1 < sizeof keybuf)
            if (hexval((char)ch) >= 0) keybuf[n++] = (char)ch; /* skip whitespace/newlines */
        fclose(kf);
        keybuf[n] = 0;
        if (n < 2) { fprintf(stderr, "empty key file %s\n", keyfile); return 1; }
        keyhex = keybuf;
    }
    if (keyhex) {
        uint8_t key[64];
        size_t kl = 0, hl = strlen(keyhex);
        for (size_t i = 0; i + 1 < hl && kl < sizeof key; i += 2) {
            int a = hexval(keyhex[i]), b = hexval(keyhex[i + 1]);
            if (a < 0 || b < 0) usage();
            key[kl++] = (uint8_t)(a * 16 + b);
        }
        router_set_key(&R, key, kl);
    }
    for (int i = 0; i < T.nlinks; i++) {
        if (T.links[i].a == id) router_add_nbr(&R, T.links[i].b, T.links[i].cost);
        else if (T.links[i].b == id) router_add_nbr(&R, T.links[i].a, T.links[i].cost);
    }

    data_fd = bind_udp((uint16_t)(base_port + id));
    ctl_fd = bind_udp((uint16_t)(base_port + 1000 + id));
    if (data_fd < 0 || ctl_fd < 0) { perror("bind"); return 1; }
    signal(SIGTERM, on_sig);
    signal(SIGINT, on_sig);

    struct pollfd pfd[2] = {{.fd = data_fd, .events = POLLIN}, {.fd = ctl_fd, .events = POLLIN}};
    static uint8_t buf[2048];
    while (!stop) {
        int n = poll(pfd, 2, 5); /* 5 ms timer granularity */
        if (n < 0 && errno != EINTR) break;
        if (n > 0 && (pfd[0].revents & POLLIN)) {
            for (;;) {
                ssize_t got = recv(data_fd, buf, sizeof buf, 0);
                if (got < 0) break;
                router_rx(&R, buf, (size_t)got);
            }
        }
        if (n > 0 && (pfd[1].revents & POLLIN)) {
            struct sockaddr_in from;
            socklen_t fl = sizeof from;
            ssize_t got = recvfrom(ctl_fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
            if (got > 0) control((const char *)buf, (size_t)got, &from, fl);
        }
        router_tick(&R);
    }
    close(data_fd);
    close(ctl_fd);
    return 0;
}
