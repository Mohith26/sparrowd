/* Fuzz target for the whole receive path: header checks, HMAC verification,
 * replay window, hello/LSU/ack/DV parsers, LSDB install, flooding and SPF.
 * Works as a libFuzzer target (LLVMFuzzerTestOneInput) and is also driven by
 * fuzz_driver.c, a deterministic mutation fuzzer for toolchains without libFuzzer.
 *
 * Input layout: byte 0 = config (bit0 DV mode, bit1 auth on, bit2 fix up header
 * length/version so mutations reach the deeper parsers), then a sequence of
 * frames [u16 len][len bytes], each delivered as one packet followed by a tick. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "proto.h"

uint64_t fuzz_rx_counts[RX__COUNT];
uint64_t fuzz_lsa_installed;

static uint64_t fz_us;
static uint64_t fz_clock(void *c) { (void)c; return fz_us; }
static void fz_send(void *c, uint16_t to, const uint8_t *b, size_t l) { (void)c; (void)to; (void)b; (void)l; }

static router_t FR;
static const timers_t FT = {.hello_ms = 50, .dead_ms = 200, .rxmt_ms = 100, .refresh_ms = 10000,
                            .maxage_s = 30, .dv_period_ms = 1000, .dv_trigger_ms = 20};
const uint8_t fuzz_key[17] = "fuzz-key-0123456";

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    uint8_t cfg = data[0];
    fz_us = 1000000;
    router_init(&FR, 1, (cfg & 1) ? MODE_DV : MODE_LS, &FT, fz_send, NULL, fz_clock, NULL);
    if (cfg & 2) router_set_key(&FR, fuzz_key, 16);
    router_add_nbr(&FR, 2, 10);
    router_add_nbr(&FR, 3, 7);
    router_add_nbr(&FR, 4, 1);
    for (int i = 0; i < FR.nnbr; i++) { FR.nbr[i].state = NBR_FULL; FR.nbr[i].last_heard_ms = fz_us / 1000; }
    size_t off = 1;
    uint8_t pkt[MAX_PKT + 64];
    while (size - off >= 2) {
        size_t len = (size_t)((data[off] << 8) | data[off + 1]);
        off += 2;
        if (len > size - off) len = size - off;
        if (len > sizeof pkt) len = sizeof pkt;
        memcpy(pkt, data + off, len);
        off += len;
        if ((cfg & 4) && len >= 4) { pkt[0] = PROTO_VERSION; put16(pkt + 2, (uint16_t)len); }
        int rc = router_rx(&FR, pkt, len);
        fuzz_rx_counts[rc]++;
        fz_us += 7000;
        router_tick(&FR);
    }
    fuzz_lsa_installed += FR.st.lsa_installed;
    return 0;
}
