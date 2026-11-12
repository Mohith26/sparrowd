/* Deterministic mutation fuzzer for fuzz_rx.c (used where libFuzzer's runtime is
 * not available, e.g. Apple clang). Builds a seed corpus of valid packets, then
 * applies bit flips, interesting-byte writes, truncation, extension, chunk
 * duplication and frame splicing. Run under ASan+UBSan: any memory or UB error
 * aborts the process, so a clean exit means zero sanitizer findings.
 * usage: fuzz_driver <iterations> <seed>   (prints one JSON line) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "proto.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern uint64_t fuzz_rx_counts[RX__COUNT];
extern uint64_t fuzz_lsa_installed;
extern const uint8_t fuzz_key[17];

static uint64_t s_rng;
static uint32_t rnd(void) {
    s_rng ^= s_rng << 13; s_rng ^= s_rng >> 7; s_rng ^= s_rng << 17;
    return (uint32_t)(s_rng >> 16);
}

static uint64_t sd_us = 1000000;
static uint64_t sd_clock(void *c) { (void)c; return sd_us++; }
static void sd_send(void *c, uint16_t t, const uint8_t *b, size_t l) { (void)c; (void)t; (void)b; (void)l; }

#define NSEED 8
static uint8_t seeds[NSEED][4096];
static size_t seed_len[NSEED];

static size_t frame(uint8_t *out, const uint8_t *pkt, size_t len) {
    put16(out, (uint16_t)len);
    memcpy(out + 2, pkt, len);
    return len + 2;
}

static void build_seeds(void) {
    static const timers_t T = {.hello_ms = 50, .dead_ms = 200, .rxmt_ms = 100, .refresh_ms = 10000,
                               .maxage_s = 30, .dv_period_ms = 1000, .dv_trigger_ms = 20};
    for (int s = 0; s < NSEED; s++) {
        int auth = s & 1;
        int dv = (s >> 1) & 1;
        router_t src;
        router_init(&src, 2, dv ? MODE_DV : MODE_LS, &T, sd_send, NULL, sd_clock, NULL);
        if (auth) router_set_key(&src, fuzz_key, 16);
        uint8_t *o = seeds[s];
        size_t off = 0;
        o[off++] = (uint8_t)((dv ? 1 : 0) | (auth ? 2 : 0) | ((s >> 2) ? 4 : 0));
        uint8_t pl[1200], pkt[MAX_PKT];
        size_t n;
        uint8_t h[8];
        put16(h, 50); put16(h + 2, 200); put16(h + 4, 1); put16(h + 6, 1);
        n = pkt_build(&src, PKT_HELLO, h, sizeof h, pkt);
        off += frame(o + off, pkt, n);
        if (!dv) {
            size_t p = 2;
            for (int k = 0; k < 4; k++) {
                lsa_t l = {.valid = 1, .origin = (uint16_t)(2 + k), .seq = (uint32_t)(5 + k), .nlinks = 3};
                l.links[0] = (lsa_link){1, 10}; l.links[1] = (lsa_link){(uint16_t)(3 + k), 4};
                l.links[2] = (lsa_link){(uint16_t)(9 + k), 2};
                p += lsa_encode(&l, (uint16_t)k, pl + p, sizeof pl - p);
            }
            put16(pl, 4);
            n = pkt_build(&src, PKT_LSU, pl, p, pkt);
            off += frame(o + off, pkt, n);
            put16(pl, 2); put16(pl + 2, 1); put32(pl + 4, 3); put16(pl + 8, 3); put32(pl + 10, 6);
            n = pkt_build(&src, PKT_ACK, pl, 14, pkt);
            off += frame(o + off, pkt, n);
        } else {
            size_t p = 2;
            for (int d = 1; d < 12; d++) { put16(pl + p, (uint16_t)d); put16(pl + p + 2, (uint16_t)(d * 3)); p += 4; }
            put16(pl, 11);
            n = pkt_build(&src, PKT_DV, pl, p, pkt);
            off += frame(o + off, pkt, n);
        }
        seed_len[s] = off;
    }
}

static size_t mutate(uint8_t *buf, size_t len, size_t cap) {
    int nmut = 1 + (int)(rnd() % 6);
    static const uint8_t interesting[] = {0x00, 0x01, 0x02, 0x10, 0x3f, 0x40, 0x7f, 0x80, 0xfe, 0xff};
    for (int m = 0; m < nmut; m++) {
        if (len < 2) break;
        size_t pos = 1 + rnd() % (len - 1); /* keep the config byte mostly stable */
        switch (rnd() % 8) {
        case 0: buf[pos] ^= (uint8_t)(1u << (rnd() % 8)); break;
        case 1: buf[pos] = interesting[rnd() % sizeof interesting]; break;
        case 2: buf[pos] = (uint8_t)rnd(); break;
        case 3: len = pos; break; /* truncate */
        case 4: { /* extend with random bytes */
            size_t add = rnd() % 64;
            if (len + add > cap) add = cap - len;
            for (size_t i = 0; i < add; i++) buf[len + i] = (uint8_t)rnd();
            len += add;
        } break;
        case 5: { /* duplicate a chunk */
            size_t from = rnd() % len, cl = 1 + rnd() % 32;
            if (from + cl > len) cl = len - from;
            if (len + cl <= cap) {
                uint8_t chunk[32];
                memcpy(chunk, buf + from, cl);
                memmove(buf + pos + cl, buf + pos, len - pos);
                memcpy(buf + pos, chunk, cl);
                len += cl;
            }
        } break;
        case 6: if (pos + 1 < len) put16(buf + pos, (uint16_t)(rnd() % 80)); break; /* small 16-bit counts */
        case 7: buf[0] = (uint8_t)(rnd() & 7); break;
        }
    }
    return len;
}

int main(int argc, char **argv) {
    long iters = argc > 1 ? atol(argv[1]) : 100000;
    s_rng = argc > 2 ? (uint64_t)atoll(argv[2]) * 0x9E3779B97F4A7C15ull + 1 : 1;
    build_seeds();
    static uint8_t buf[8192];
    clock_t t0 = clock();
    for (int s = 0; s < NSEED; s++) LLVMFuzzerTestOneInput(seeds[s], seed_len[s]);
    for (long i = 0; i < iters; i++) {
        int s = (int)(rnd() % NSEED);
        memcpy(buf, seeds[s], seed_len[s]);
        size_t len = mutate(buf, seed_len[s], sizeof buf);
        if (rnd() % 4 == 0) { /* splice: append frames from another seed */
            int s2 = (int)(rnd() % NSEED);
            size_t add = seed_len[s2] - 1;
            if (len + add <= sizeof buf) { memcpy(buf + len, seeds[s2] + 1, add); len += add; }
        }
        LLVMFuzzerTestOneInput(buf, len);
    }
    double secs = (double)(clock() - t0) / CLOCKS_PER_SEC;
    static const char *names[RX__COUNT] = {"ok", "short", "bad_version", "bad_len", "unknown_src", "admin_down",
                                           "auth_fail", "replay", "bad_type", "bad_payload", "not_adjacent"};
    uint64_t pk = 0;
    for (int i = 0; i < RX__COUNT; i++) pk += fuzz_rx_counts[i];
    printf("{\"iterations\": %ld, \"packets\": %llu, \"cpu_seconds\": %.2f, \"lsa_installed\": %llu, \"outcomes\": {",
           iters, (unsigned long long)pk, secs, (unsigned long long)fuzz_lsa_installed);
    for (int i = 0; i < RX__COUNT; i++)
        printf("%s\"%s\": %llu", i ? ", " : "", names[i], (unsigned long long)fuzz_rx_counts[i]);
    printf("}}\n");
    return 0;
}
