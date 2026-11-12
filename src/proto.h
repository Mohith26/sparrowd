/* Sparrow protocol core: neighbor state machine, LSDB, reliable flooding, SPF,
 * and a distance-vector baseline. Pure logic: no sockets, no heap, no globals.
 * The caller supplies a clock and a send callback, which is what lets the same
 * code run in the daemon, the unit tests and the fuzz harness. */
#ifndef SPARROW_PROTO_H
#define SPARROW_PROTO_H

#include <stddef.h>
#include <stdint.h>

#define MAX_ROUTERS 64 /* router ids 1..63 */
#define MAX_NBRS 16
#define MAX_PKT 1400
#define HDR_LEN 48
#define HMAC_OFF 16
#define LSA_HDR_LEN 10
#define LSA_LINK_LEN 4
#define COST_INF 0xFFFFFFFFu
#define DV_INF 2048u /* smallest power of two above the GEANT diameter (1310) */
#define PROTO_VERSION 1
#define FLAG_AUTH 0x0001

enum { PKT_HELLO = 1, PKT_LSU = 2, PKT_ACK = 3, PKT_DV = 4 };
enum { NBR_DOWN = 0, NBR_INIT = 1, NBR_FULL = 2 };
enum { MODE_LS = 0, MODE_DV = 1 };

/* Result of router_rx, also used as fuzz/telemetry buckets. */
enum {
    RX_OK = 0, RX_SHORT, RX_BAD_VERSION, RX_BAD_LEN, RX_UNKNOWN_SRC, RX_ADMIN_DOWN,
    RX_AUTH_FAIL, RX_REPLAY, RX_BAD_TYPE, RX_BAD_PAYLOAD, RX_NOT_ADJACENT, RX__COUNT
};

typedef struct {
    uint16_t nbr;
    uint16_t cost;
} lsa_link;

typedef struct {
    uint8_t valid;
    uint16_t origin;
    uint32_t seq;
    uint16_t age_at_rx; /* seconds */
    uint64_t rx_ms;
    uint16_t nlinks;
    lsa_link links[MAX_NBRS];
} lsa_t;

typedef struct {
    uint16_t id;
    uint16_t cost;
    uint8_t state;
    uint8_t admin_down;
    uint64_t last_heard_ms;
    uint64_t last_rx_cseq;          /* highest authenticated crypto sequence seen */
    uint32_t pend_seq[MAX_ROUTERS]; /* LSA (origin -> seq) awaiting ack, 0 = none */
    uint64_t pend_tx_ms[MAX_ROUTERS];
    uint32_t dv_metric[MAX_ROUTERS]; /* last vector heard from this neighbor */
} nbr_t;

typedef struct {
    uint16_t nh; /* 0 = no route */
    uint32_t cost;
} fib_ent;

typedef struct {
    uint64_t rx[RX__COUNT];
    uint64_t tx_pkts, rx_pkts;
    uint64_t lsa_installed, lsa_stale, lsa_dup, lsa_rejected;
    uint64_t retransmits, originations, adj_up, adj_down;
} stats_t;

typedef void (*send_fn)(void *ctx, uint16_t nbr_id, const uint8_t *buf, size_t len);
typedef uint64_t (*clock_fn)(void *ctx); /* microseconds */

typedef struct {
    uint32_t hello_ms, dead_ms, rxmt_ms, refresh_ms, maxage_s;
    uint32_t dv_period_ms, dv_trigger_ms;
} timers_t;

typedef struct {
    uint16_t self;
    int mode;
    int auth;
    uint8_t key[64];
    size_t key_len;
    timers_t t;

    int nnbr;
    nbr_t nbr[MAX_NBRS];
    lsa_t lsdb[MAX_ROUTERS];
    uint32_t my_seq;
    uint64_t tx_cseq;

    uint64_t last_hello_ms, last_orig_ms, last_dv_ms;
    int need_orig, spf_dirty, dv_dirty;

    fib_ent fib[MAX_ROUTERS];
    uint64_t fib_change_us;
    uint32_t spf_runs, fib_changes;
    uint32_t dv_metric[MAX_ROUTERS];
    uint16_t dv_nh[MAX_ROUTERS];

    uint8_t last_valid[MAX_PKT]; /* last accepted packet, for capture/replay tests */
    size_t last_valid_len;

    stats_t st;
    send_fn send;
    void *send_ctx;
    clock_fn clock;
    void *clock_ctx;
} router_t;

void router_init(router_t *r, uint16_t self, int mode, const timers_t *t, send_fn s, void *sctx,
                 clock_fn c, void *cctx);
void router_set_key(router_t *r, const uint8_t *key, size_t len); /* len 0 disables auth */
int router_add_nbr(router_t *r, uint16_t id, uint16_t cost);
int router_rx(router_t *r, const uint8_t *buf, size_t len);
void router_tick(router_t *r);
int router_ifdown(router_t *r, uint16_t nbr_id);
int router_ifup(router_t *r, uint16_t nbr_id);
size_t router_fib_text(const router_t *r, char *out, size_t cap);
size_t router_stats_text(const router_t *r, char *out, size_t cap);
void router_spf(router_t *r);
int lsa_seq_newer(uint32_t a, uint32_t b);

/* Packet construction (used by the daemon, tests and fuzz seeds). Returns total
 * length or 0 if it does not fit. Signs the packet when auth is on. */
size_t pkt_build(router_t *r, uint8_t type, const uint8_t *payload, size_t plen, uint8_t *out);
size_t lsa_encode(const lsa_t *l, uint16_t age, uint8_t *out, size_t cap);

static inline void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static inline void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}
static inline void put64(uint8_t *p, uint64_t v) { put32(p, (uint32_t)(v >> 32)); put32(p + 4, (uint32_t)v); }
static inline uint16_t get16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static inline uint32_t get32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static inline uint64_t get64(const uint8_t *p) { return ((uint64_t)get32(p) << 32) | get32(p + 4); }

#endif
