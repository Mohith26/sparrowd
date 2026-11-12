/* Unit and in-process network tests for the Sparrow protocol core.
 * Built and run under AddressSanitizer + UBSan (see Makefile). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "proto.h"
#include "sha256.h"

static int failures, checks;
#define CHECK(c)                                                                  \
    do {                                                                          \
        checks++;                                                                 \
        if (!(c)) { failures++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } \
    } while (0)

static void hex(const uint8_t *b, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) snprintf(out + 2 * i, 3, "%02x", b[i]);
}

static void test_sha256(void) {
    uint8_t d[32];
    char h[65];
    sha256("abc", 3, d); hex(d, 32, h);
    CHECK(!strcmp(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    sha256("", 0, d); hex(d, 32, h);
    CHECK(!strcmp(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    const char *m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha256(m, strlen(m), d); hex(d, 32, h);
    CHECK(!strcmp(h, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
    /* one million 'a' (FIPS 180-2 appendix), fed in uneven chunks */
    sha256_ctx c; sha256_init(&c);
    char a[1001]; memset(a, 'a', sizeof a);
    for (int i = 0; i < 1000; i++) sha256_update(&c, a, (i % 2) ? 999 : 1001);
    sha256_final(&c, d); hex(d, 32, h);
    CHECK(!strcmp(h, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
}

static void test_hmac(void) {
    uint8_t d[32];
    char h[65];
    uint8_t k1[20]; memset(k1, 0x0b, sizeof k1);
    hmac_sha256(k1, sizeof k1, "Hi There", 8, d); hex(d, 32, h);
    CHECK(!strcmp(h, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    const char *m2 = "what do ya want for nothing?";
    hmac_sha256((const uint8_t *)"Jefe", 4, m2, strlen(m2), d); hex(d, 32, h);
    CHECK(!strcmp(h, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
    uint8_t k6[131]; memset(k6, 0xaa, sizeof k6);
    const char *m6 = "Test Using Larger Than Block-Size Key - Hash Key First";
    hmac_sha256(k6, sizeof k6, m6, strlen(m6), d); hex(d, 32, h);
    CHECK(!strcmp(h, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
    CHECK(ct_equal((const uint8_t *)"abcd", (const uint8_t *)"abcd", 4));
    CHECK(!ct_equal((const uint8_t *)"abcd", (const uint8_t *)"abce", 4));
}

/* ---------- in-process network simulator ---------- */

#define SIM_N 12
#define QCAP 4096
typedef struct { uint16_t to; size_t len; uint8_t buf[MAX_PKT]; } qpkt;
static qpkt Q[QCAP];
static int qn;
static uint64_t fake_us = 1000000;
static router_t RT[SIM_N + 1];
static int alive[SIM_N + 1];
static uint32_t drop_pct; /* simulated loss */
static uint32_t sim_rng = 12345;
static uint16_t lk_a[64], lk_b[64], lk_c[64];
static int nlk;
static int lk_up[64];

static uint64_t fclock(void *ctx) { (void)ctx; return fake_us; }
static void fsend(void *ctx, uint16_t to, const uint8_t *buf, size_t len) {
    (void)ctx;
    sim_rng = sim_rng * 1103515245u + 12345u;
    if (drop_pct && (sim_rng >> 16) % 100 < drop_pct) return;
    if (qn >= QCAP) return;
    Q[qn].to = to; Q[qn].len = len; memcpy(Q[qn].buf, buf, len); qn++;
}

static const timers_t TM = {.hello_ms = 50, .dead_ms = 200, .rxmt_ms = 100, .refresh_ms = 10000,
                            .maxage_s = 30, .dv_period_ms = 1000, .dv_trigger_ms = 20};
static const uint8_t KEY[] = "sparrow-test-key";

static void sim_build(int n, int mode, int auth) {
    qn = 0;
    for (int i = 1; i <= n; i++) {
        router_init(&RT[i], (uint16_t)i, mode, &TM, fsend, NULL, fclock, NULL);
        if (auth) router_set_key(&RT[i], KEY, sizeof KEY - 1);
        alive[i] = 1;
    }
    for (int k = 0; k < nlk; k++) {
        router_add_nbr(&RT[lk_a[k]], lk_b[k], lk_c[k]);
        router_add_nbr(&RT[lk_b[k]], lk_a[k], lk_c[k]);
        lk_up[k] = 1;
    }
}

static void sim_run(int n, int ms) {
    for (int step = 0; step < ms / 5; step++) {
        fake_us += 5000;
        static qpkt cur[QCAP];
        int cn = qn;
        memcpy(cur, Q, sizeof(qpkt) * (size_t)cn);
        qn = 0;
        for (int i = 0; i < cn; i++)
            if (cur[i].to >= 1 && cur[i].to <= n && alive[cur[i].to]) router_rx(&RT[cur[i].to], cur[i].buf, cur[i].len);
        for (int i = 1; i <= n; i++)
            if (alive[i]) router_tick(&RT[i]);
    }
}

/* Oracle: Floyd-Warshall over live links and live routers. */
static uint32_t D[SIM_N + 1][SIM_N + 1];
static void oracle(int n) {
    for (int i = 1; i <= n; i++)
        for (int j = 1; j <= n; j++) D[i][j] = i == j ? 0 : COST_INF;
    for (int k = 0; k < nlk; k++)
        if (lk_up[k] && alive[lk_a[k]] && alive[lk_b[k]]) {
            D[lk_a[k]][lk_b[k]] = lk_c[k];
            D[lk_b[k]][lk_a[k]] = lk_c[k];
        }
    for (int k = 1; k <= n; k++)
        for (int i = 1; i <= n; i++)
            for (int j = 1; j <= n; j++)
                if (D[i][k] != COST_INF && D[k][j] != COST_INF && D[i][k] + D[k][j] < D[i][j])
                    D[i][j] = D[i][k] + D[k][j];
}

static uint32_t link_cost(int a, int b) {
    for (int k = 0; k < nlk; k++)
        if (lk_up[k] && ((lk_a[k] == a && lk_b[k] == b) || (lk_a[k] == b && lk_b[k] == a))) return lk_c[k];
    return COST_INF;
}

/* Every live router's FIB must match the oracle and forwarding must reach each
 * destination with no loops and no black holes. Returns number of bad pairs. */
static int fib_errors(int n) {
    oracle(n);
    int bad = 0;
    for (int s = 1; s <= n; s++) {
        if (!alive[s]) continue;
        for (int d = 1; d <= n; d++) {
            if (d == s) continue;
            const fib_ent *e = &RT[s].fib[d];
            if (!alive[d] || D[s][d] == COST_INF) { if (e->nh) bad++; continue; }
            if (!e->nh || e->cost != D[s][d]) { bad++; continue; }
            int cur = s, hops = 0;
            uint32_t tot = 0;
            while (cur != d && hops <= n) {
                uint16_t nh = RT[cur].fib[d].nh;
                if (!nh || !alive[nh]) break;
                uint32_t c = link_cost(cur, nh);
                if (c == COST_INF) break;
                tot += c; cur = nh; hops++;
            }
            if (cur != d || tot != D[s][d]) bad++;
        }
    }
    return bad;
}

static void topo_mesh(void) {
    /* 12 routers: a ring plus chords, mixed costs */
    static const uint16_t L[][3] = {{1, 2, 10}, {2, 3, 10}, {3, 4, 5},  {4, 5, 10}, {5, 6, 1},
                                    {6, 7, 10}, {7, 8, 4},  {8, 9, 10}, {9, 10, 2}, {10, 11, 10},
                                    {11, 12, 3}, {12, 1, 10}, {1, 7, 40}, {3, 9, 25}, {5, 11, 18},
                                    {2, 8, 30}};
    nlk = (int)(sizeof L / sizeof L[0]);
    for (int k = 0; k < nlk; k++) { lk_a[k] = L[k][0]; lk_b[k] = L[k][1]; lk_c[k] = L[k][2]; }
}

static void set_link(int a, int b, int up) {
    for (int k = 0; k < nlk; k++)
        if ((lk_a[k] == a && lk_b[k] == b) || (lk_a[k] == b && lk_b[k] == a)) lk_up[k] = up;
    if (!up) { router_ifdown(&RT[a], (uint16_t)b); router_ifdown(&RT[b], (uint16_t)a); }
    else { router_ifup(&RT[a], (uint16_t)b); router_ifup(&RT[b], (uint16_t)a); }
}

static void test_ls_converges(int auth) {
    topo_mesh();
    sim_build(SIM_N, MODE_LS, auth);
    sim_run(SIM_N, 1500);
    CHECK(fib_errors(SIM_N) == 0);
    set_link(5, 6, 0);
    sim_run(SIM_N, 500);
    CHECK(fib_errors(SIM_N) == 0);
    set_link(5, 6, 1);
    sim_run(SIM_N, 1000);
    CHECK(fib_errors(SIM_N) == 0);
    alive[7] = 0; /* crash: neighbors find out from the dead interval */
    sim_run(SIM_N, 1000);
    CHECK(fib_errors(SIM_N) == 0);
    /* restart with a fresh LSA sequence: neighbors still hold the old one */
    uint32_t old_seq = RT[1].lsdb[7].seq;
    router_init(&RT[7], 7, MODE_LS, &TM, fsend, NULL, fclock, NULL);
    if (auth) router_set_key(&RT[7], KEY, sizeof KEY - 1);
    for (int k = 0; k < nlk; k++) {
        if (lk_a[k] == 7) router_add_nbr(&RT[7], lk_b[k], lk_c[k]);
        if (lk_b[k] == 7) router_add_nbr(&RT[7], lk_a[k], lk_c[k]);
    }
    alive[7] = 1;
    sim_run(SIM_N, 1500);
    CHECK(fib_errors(SIM_N) == 0);
    CHECK(RT[7].my_seq >= old_seq); /* never fell behind its previous incarnation */
    CHECK(RT[1].lsdb[7].seq == RT[7].my_seq);
}

static void test_ls_under_loss(void) {
    topo_mesh();
    sim_build(SIM_N, MODE_LS, 1);
    drop_pct = 20;
    sim_run(SIM_N, 3000);
    set_link(3, 4, 0);
    sim_run(SIM_N, 3000);
    drop_pct = 0;
    /* stop retransmitting garbage: loss off, a little more time, still correct */
    sim_run(SIM_N, 200);
    CHECK(fib_errors(SIM_N) == 0);
    uint64_t rx = 0;
    for (int i = 1; i <= SIM_N; i++) rx += RT[i].st.retransmits;
    CHECK(rx > 0); /* loss really exercised the retransmit path */
}

static void test_dv_converges(void) {
    topo_mesh();
    sim_build(SIM_N, MODE_DV, 0);
    sim_run(SIM_N, 3000);
    CHECK(fib_errors(SIM_N) == 0);
    set_link(5, 6, 0);
    sim_run(SIM_N, 3000);
    CHECK(fib_errors(SIM_N) == 0);
}

static void test_auth_and_replay(void) {
    topo_mesh();
    sim_build(SIM_N, MODE_LS, 1);
    sim_run(SIM_N, 1500);
    CHECK(fib_errors(SIM_N) == 0);
    /* capture a packet router 2 sent to router 1, then replay it */
    uint8_t cap[MAX_PKT];
    size_t clen = RT[1].last_valid_len;
    memcpy(cap, RT[1].last_valid, clen);
    CHECK(clen >= HDR_LEN);
    CHECK(router_rx(&RT[1], cap, clen) == RX_REPLAY);
    /* tamper one payload byte */
    cap[clen - 1] ^= 1;
    CHECK(router_rx(&RT[1], cap, clen) == RX_AUTH_FAIL);
    /* forge: attacker without the key claims to be router 2 and advertises a
     * cost-1 link to everyone (a black-hole attack) */
    router_t evil;
    router_init(&evil, 2, MODE_LS, &TM, fsend, NULL, fclock, NULL);
    router_set_key(&evil, (const uint8_t *)"wrong-key", 9);
    uint8_t pl[512], pkt[MAX_PKT];
    lsa_t l = {.valid = 1, .origin = 2, .seq = 0xFFFFFFFF, .nlinks = 0};
    for (int d = 1; d <= SIM_N; d++)
        if (d != 2) { l.links[l.nlinks].nbr = (uint16_t)d; l.links[l.nlinks].cost = 1; l.nlinks++; }
    put16(pl, 1);
    size_t w = lsa_encode(&l, 0, pl + 2, sizeof pl - 2);
    size_t plen = pkt_build(&evil, PKT_LSU, pl, w + 2, pkt);
    uint32_t before = RT[1].lsdb[2].seq;
    CHECK(router_rx(&RT[1], pkt, plen) == RX_AUTH_FAIL);
    CHECK(RT[1].lsdb[2].seq == before);
    /* unauthenticated packet to an authenticating router */
    evil.auth = 0;
    plen = pkt_build(&evil, PKT_LSU, pl, w + 2, pkt);
    CHECK(router_rx(&RT[1], pkt, plen) == RX_AUTH_FAIL);
    sim_run(SIM_N, 200);
    CHECK(fib_errors(SIM_N) == 0);

    /* baseline: the same forged LSA against routers running with auth off */
    sim_build(SIM_N, MODE_LS, 0);
    sim_run(SIM_N, 1500);
    CHECK(fib_errors(SIM_N) == 0);
    plen = pkt_build(&evil, PKT_LSU, pl, w + 2, pkt);
    CHECK(router_rx(&RT[1], pkt, plen) == RX_OK);
    CHECK(RT[1].lsdb[2].seq == 0xFFFFFFFF);
    sim_run(SIM_N, 300);
    CHECK(fib_errors(SIM_N) > 0); /* routing is poisoned without authentication */
}

static void test_parser_rejects(void) {
    router_t r;
    router_init(&r, 1, MODE_LS, &TM, fsend, NULL, fclock, NULL);
    router_add_nbr(&r, 2, 10);
    uint8_t b[MAX_PKT];
    memset(b, 0, sizeof b);
    CHECK(router_rx(&r, b, 10) == RX_SHORT);
    b[0] = 9; put16(b + 2, HDR_LEN);
    CHECK(router_rx(&r, b, HDR_LEN) == RX_BAD_VERSION);
    b[0] = PROTO_VERSION; put16(b + 2, 999);
    CHECK(router_rx(&r, b, HDR_LEN) == RX_BAD_LEN);
    put16(b + 2, HDR_LEN); put16(b + 4, 33);
    CHECK(router_rx(&r, b, HDR_LEN) == RX_UNKNOWN_SRC);
    put16(b + 4, 2); b[1] = 77;
    CHECK(router_rx(&r, b, HDR_LEN) == RX_BAD_TYPE);
    b[1] = PKT_HELLO;
    CHECK(router_rx(&r, b, HDR_LEN + 3) == RX_BAD_LEN);
    put16(b + 2, HDR_LEN + 3);
    CHECK(router_rx(&r, b, HDR_LEN + 3) == RX_BAD_PAYLOAD);
    /* hello claiming 200 neighbors in a short packet */
    put16(b + 2, HDR_LEN + 6); put16(b + HDR_LEN, 50); put16(b + HDR_LEN + 2, 200); put16(b + HDR_LEN + 4, 200);
    CHECK(router_rx(&r, b, HDR_LEN + 6) == RX_BAD_PAYLOAD);
    /* LSU before adjacency is ignored */
    b[1] = PKT_LSU;
    CHECK(router_rx(&r, b, HDR_LEN + 6) == RX_NOT_ADJACENT);
    /* bring adjacency up, then send an LSU whose link count overruns the packet */
    uint8_t h[6 + 2];
    put16(h, 50); put16(h + 2, 200); put16(h + 4, 1); put16(h + 6, 1);
    router_t two;
    router_init(&two, 2, MODE_LS, &TM, fsend, NULL, fclock, NULL);
    size_t n = pkt_build(&two, PKT_HELLO, h, sizeof h, b);
    CHECK(router_rx(&r, b, n) == RX_OK);
    CHECK(r.nbr[0].state == NBR_FULL);
    uint8_t pl[2 + LSA_HDR_LEN];
    put16(pl, 1); put16(pl + 2, 2); put32(pl + 4, 5); put16(pl + 8, 0); put16(pl + 10, 15);
    n = pkt_build(&two, PKT_LSU, pl, sizeof pl, b);
    CHECK(router_rx(&r, b, n) == RX_BAD_PAYLOAD);
    CHECK(!r.lsdb[2].valid);
    /* LSA with 17 links (over MAX_NBRS) */
    put16(pl + 10, MAX_NBRS + 1);
    n = pkt_build(&two, PKT_LSU, pl, sizeof pl, b);
    CHECK(router_rx(&r, b, n) == RX_BAD_PAYLOAD);
}

static void test_spf_two_way_check(void) {
    router_t r;
    router_init(&r, 1, MODE_LS, &TM, fsend, NULL, fclock, NULL);
    /* 1 -- 2 -- 3, but 3's LSA does not list 2: the 2->3 edge must not be used */
    r.lsdb[1] = (lsa_t){.valid = 1, .origin = 1, .seq = 1, .nlinks = 1, .links = {{2, 1}}};
    r.lsdb[2] = (lsa_t){.valid = 1, .origin = 2, .seq = 1, .nlinks = 2, .links = {{1, 1}, {3, 1}}};
    r.lsdb[3] = (lsa_t){.valid = 1, .origin = 3, .seq = 1, .nlinks = 0};
    router_spf(&r);
    CHECK(r.fib[2].nh == 2 && r.fib[2].cost == 1);
    CHECK(r.fib[3].nh == 0);
    r.lsdb[3].nlinks = 1; r.lsdb[3].links[0] = (lsa_link){2, 1};
    router_spf(&r);
    CHECK(r.fib[3].nh == 2 && r.fib[3].cost == 2);
}

int main(void) {
    test_sha256();
    test_hmac();
    test_spf_two_way_check();
    test_parser_rejects();
    test_ls_converges(0);
    test_ls_converges(1);
    test_ls_under_loss();
    test_dv_converges();
    test_auth_and_replay();
    printf("%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
