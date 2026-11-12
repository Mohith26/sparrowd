/* Sparrow protocol core. See proto.h and SPEC.md for the wire format. */
#include "proto.h"

#include <stdio.h>
#include <string.h>

#include "sha256.h"

static uint64_t now_us(router_t *r) { return r->clock(r->clock_ctx); }
static uint64_t now_ms(router_t *r) { return now_us(r) / 1000; }

int lsa_seq_newer(uint32_t a, uint32_t b) { return a > b; }

static int nbr_index(const router_t *r, uint16_t id) {
    for (int i = 0; i < r->nnbr; i++)
        if (r->nbr[i].id == id) return i;
    return -1;
}

void router_init(router_t *r, uint16_t self, int mode, const timers_t *t, send_fn s, void *sctx,
                 clock_fn c, void *cctx) {
    memset(r, 0, sizeof *r);
    r->self = self;
    r->mode = mode;
    r->t = *t;
    r->send = s;
    r->send_ctx = sctx;
    r->clock = c;
    r->clock_ctx = cctx;
    for (int d = 0; d < MAX_ROUTERS; d++) r->dv_metric[d] = DV_INF;
    if (self < MAX_ROUTERS) r->dv_metric[self] = 0;
    r->need_orig = 1;
    r->spf_dirty = 1;
}

void router_set_key(router_t *r, const uint8_t *key, size_t len) {
    if (len > sizeof r->key) len = sizeof r->key;
    memcpy(r->key, key, len);
    r->key_len = len;
    r->auth = len > 0;
}

int router_add_nbr(router_t *r, uint16_t id, uint16_t cost) {
    if (r->nnbr >= MAX_NBRS || id == 0 || id >= MAX_ROUTERS || id == r->self || cost == 0) return -1;
    if (nbr_index(r, id) >= 0) return -1;
    nbr_t *n = &r->nbr[r->nnbr++];
    memset(n, 0, sizeof *n);
    n->id = id;
    n->cost = cost;
    for (int d = 0; d < MAX_ROUTERS; d++) n->dv_metric[d] = DV_INF;
    return 0;
}

/* ---------- packet build / send ---------- */

size_t pkt_build(router_t *r, uint8_t type, const uint8_t *payload, size_t plen, uint8_t *out) {
    size_t len = HDR_LEN + plen;
    if (len > MAX_PKT) return 0;
    out[0] = PROTO_VERSION;
    out[1] = type;
    put16(out + 2, (uint16_t)len);
    put16(out + 4, r->self);
    put16(out + 6, r->auth ? FLAG_AUTH : 0);
    /* Crypto sequence is strictly increasing and seeded from the wall clock, so a
     * restarted router never reuses a value its neighbors have already seen. */
    uint64_t cs = now_us(r);
    if (cs <= r->tx_cseq) cs = r->tx_cseq + 1;
    r->tx_cseq = cs;
    put64(out + 8, cs);
    memset(out + HMAC_OFF, 0, SHA256_DIGEST_LEN);
    if (plen) memcpy(out + HDR_LEN, payload, plen);
    if (r->auth) {
        uint8_t mac[SHA256_DIGEST_LEN];
        hmac_sha256(r->key, r->key_len, out, len, mac);
        memcpy(out + HMAC_OFF, mac, SHA256_DIGEST_LEN);
    }
    return len;
}

static void send_pkt(router_t *r, uint16_t nbr_id, uint8_t type, const uint8_t *payload, size_t plen) {
    uint8_t buf[MAX_PKT];
    size_t len = pkt_build(r, type, payload, plen, buf);
    if (!len) return;
    r->st.tx_pkts++;
    r->send(r->send_ctx, nbr_id, buf, len);
}

size_t lsa_encode(const lsa_t *l, uint16_t age, uint8_t *out, size_t cap) {
    size_t need = LSA_HDR_LEN + (size_t)l->nlinks * LSA_LINK_LEN;
    if (need > cap) return 0;
    put16(out, l->origin);
    put32(out + 2, l->seq);
    put16(out + 6, age);
    put16(out + 8, l->nlinks);
    for (int i = 0; i < l->nlinks; i++) {
        put16(out + LSA_HDR_LEN + 4 * i, l->links[i].nbr);
        put16(out + LSA_HDR_LEN + 4 * i + 2, l->links[i].cost);
    }
    return need;
}

static uint16_t lsa_age(const lsa_t *l, uint64_t nowms) {
    uint64_t a = l->age_at_rx + (nowms - l->rx_ms) / 1000;
    return a > 0xFFFF ? 0xFFFF : (uint16_t)a;
}

/* ---------- neighbor state ---------- */

static void dv_recompute(router_t *r);

static void nbr_down(router_t *r, int i) {
    nbr_t *n = &r->nbr[i];
    if (n->state == NBR_FULL) r->st.adj_down++;
    n->state = NBR_DOWN;
    memset(n->pend_seq, 0, sizeof n->pend_seq);
    for (int d = 0; d < MAX_ROUTERS; d++) n->dv_metric[d] = DV_INF;
    if (r->mode == MODE_LS) r->need_orig = 1;
    else dv_recompute(r);
}

static void nbr_full(router_t *r, int i) {
    nbr_t *n = &r->nbr[i];
    n->state = NBR_FULL;
    r->st.adj_up++;
    if (r->mode == MODE_LS) {
        r->need_orig = 1;
        /* Simplified database exchange: push our whole LSDB, reliably. */
        for (int o = 1; o < MAX_ROUTERS; o++)
            if (r->lsdb[o].valid) { n->pend_seq[o] = r->lsdb[o].seq; n->pend_tx_ms[o] = 0; }
    } else {
        r->dv_dirty = 1;
        r->last_dv_ms = 0; /* send our vector right away */
    }
}

int router_ifdown(router_t *r, uint16_t id) {
    int i = nbr_index(r, id);
    if (i < 0) return -1;
    r->nbr[i].admin_down = 1;
    nbr_down(r, i);
    return 0;
}

int router_ifup(router_t *r, uint16_t id) {
    int i = nbr_index(r, id);
    if (i < 0) return -1;
    r->nbr[i].admin_down = 0;
    r->last_hello_ms = 0; /* hello immediately */
    return 0;
}

/* ---------- link state ---------- */

static void flood(router_t *r, uint16_t origin, uint32_t seq, int except) {
    for (int i = 0; i < r->nnbr; i++) {
        if (i == except || r->nbr[i].state != NBR_FULL) continue;
        r->nbr[i].pend_seq[origin] = seq;
        r->nbr[i].pend_tx_ms[origin] = 0;
    }
}

static void originate(router_t *r) {
    uint64_t t = now_ms(r);
    lsa_t *l = &r->lsdb[r->self];
    if (r->my_seq != 0xFFFFFFFFu) r->my_seq++; /* no wrap; see SPEC.md limits */
    l->valid = 1;
    l->origin = r->self;
    l->seq = r->my_seq;
    l->age_at_rx = 0;
    l->rx_ms = t;
    l->nlinks = 0;
    for (int i = 0; i < r->nnbr; i++)
        if (r->nbr[i].state == NBR_FULL) {
            l->links[l->nlinks].nbr = r->nbr[i].id;
            l->links[l->nlinks].cost = r->nbr[i].cost;
            l->nlinks++;
        }
    r->last_orig_ms = t;
    r->need_orig = 0;
    r->spf_dirty = 1;
    r->st.originations++;
    flood(r, r->self, l->seq, -1);
}

static int lsa_lists(const lsa_t *l, uint16_t id, uint16_t *cost) {
    for (int i = 0; i < l->nlinks; i++)
        if (l->links[i].nbr == id) { if (cost) *cost = l->links[i].cost; return 1; }
    return 0;
}

/* Dijkstra over the LSDB with the OSPF two-way check: an edge u->v is used only
 * if v's own LSA also lists u. O(N^2) with N <= 63, no heap. Ties between equal
 * cost paths break toward the lowest first-hop id so every run is deterministic. */
void router_spf(router_t *r) {
    uint32_t dist[MAX_ROUTERS];
    uint16_t fh[MAX_ROUTERS];
    uint8_t done[MAX_ROUTERS];
    for (int i = 0; i < MAX_ROUTERS; i++) { dist[i] = COST_INF; fh[i] = 0; done[i] = 0; }
    dist[r->self] = 0;
    for (;;) {
        int u = -1;
        for (int i = 1; i < MAX_ROUTERS; i++)
            if (!done[i] && dist[i] != COST_INF && (u < 0 || dist[i] < dist[u])) u = i;
        if (u < 0) break;
        done[u] = 1;
        const lsa_t *lu = &r->lsdb[u];
        if (!lu->valid) continue;
        for (int k = 0; k < lu->nlinks; k++) {
            uint16_t v = lu->links[k].nbr;
            if (v == 0 || v >= MAX_ROUTERS || done[v]) continue;
            if (!r->lsdb[v].valid || !lsa_lists(&r->lsdb[v], (uint16_t)u, NULL)) continue;
            uint32_t nd = dist[u] + lu->links[k].cost;
            uint16_t nf = (u == r->self) ? v : fh[u];
            if (nd < dist[v] || (nd == dist[v] && nf < fh[v])) { dist[v] = nd; fh[v] = nf; }
        }
    }
    int changed = 0;
    for (int d = 0; d < MAX_ROUTERS; d++) {
        fib_ent e = {0, 0};
        if (d != r->self && dist[d] != COST_INF) { e.nh = fh[d]; e.cost = dist[d]; }
        if (e.nh != r->fib[d].nh || e.cost != r->fib[d].cost) { r->fib[d] = e; changed = 1; }
    }
    r->spf_runs++;
    r->spf_dirty = 0;
    if (changed) { r->fib_change_us = now_us(r); r->fib_changes++; }
}

static void send_lsus(router_t *r, uint64_t t) {
    uint8_t pl[MAX_PKT - HDR_LEN];
    for (int i = 0; i < r->nnbr; i++) {
        nbr_t *n = &r->nbr[i];
        if (n->state != NBR_FULL) continue;
        size_t off = 2;
        uint16_t cnt = 0;
        for (int o = 1; o < MAX_ROUTERS; o++) {
            if (!n->pend_seq[o]) continue;
            if (n->pend_tx_ms[o] && t - n->pend_tx_ms[o] < r->t.rxmt_ms) continue;
            const lsa_t *l = &r->lsdb[o];
            if (!l->valid || l->seq != n->pend_seq[o]) {
                /* Our copy moved on; send whatever we hold now. */
                if (!l->valid) { n->pend_seq[o] = 0; continue; }
                n->pend_seq[o] = l->seq;
            }
            size_t w = lsa_encode(l, lsa_age(l, t), pl + off, sizeof pl - off);
            if (!w) { /* packet full: ship it and start another */
                put16(pl, cnt);
                send_pkt(r, n->id, PKT_LSU, pl, off);
                off = 2; cnt = 0;
                w = lsa_encode(l, lsa_age(l, t), pl + off, sizeof pl - off);
                if (!w) continue;
            }
            if (n->pend_tx_ms[o]) r->st.retransmits++;
            n->pend_tx_ms[o] = t;
            off += w;
            cnt++;
        }
        if (cnt) { put16(pl, cnt); send_pkt(r, n->id, PKT_LSU, pl, off); }
    }
}

static int handle_lsu(router_t *r, int ni, const uint8_t *p, size_t len) {
    nbr_t *n = &r->nbr[ni];
    if (n->state != NBR_FULL) return RX_NOT_ADJACENT;
    if (len < 2) return RX_BAD_PAYLOAD;
    uint16_t cnt = get16(p);
    size_t off = 2;
    uint8_t ack[MAX_PKT - HDR_LEN];
    size_t aoff = 2;
    uint16_t acnt = 0;
    uint64_t t = now_ms(r);
    int rc = RX_OK;
    for (uint16_t k = 0; k < cnt; k++) {
        if (len - off < LSA_HDR_LEN) { rc = RX_BAD_PAYLOAD; break; }
        lsa_t in;
        memset(&in, 0, sizeof in);
        in.origin = get16(p + off);
        in.seq = get32(p + off + 2);
        uint16_t age = get16(p + off + 6);
        in.nlinks = get16(p + off + 8);
        off += LSA_HDR_LEN;
        if (in.nlinks > MAX_NBRS || (size_t)in.nlinks * LSA_LINK_LEN > len - off) { rc = RX_BAD_PAYLOAD; break; }
        int ok = in.origin > 0 && in.origin < MAX_ROUTERS && in.seq != 0 && age < r->t.maxage_s;
        for (int i = 0; i < in.nlinks; i++) {
            in.links[i].nbr = get16(p + off + 4 * i);
            in.links[i].cost = get16(p + off + 4 * i + 2);
            if (in.links[i].nbr == 0 || in.links[i].nbr >= MAX_ROUTERS || in.links[i].cost == 0) ok = 0;
        }
        off += (size_t)in.nlinks * LSA_LINK_LEN;
        if (!ok) { r->st.lsa_rejected++; continue; }

        lsa_t *have = &r->lsdb[in.origin];
        if (in.origin == r->self) {
            /* A copy of our own LSA. If it is newer than what we think we sent, it
             * survived from a previous incarnation: jump past it and re-originate. */
            const lsa_t *mine = &r->lsdb[r->self];
            int differs = in.nlinks != mine->nlinks ||
                          memcmp(in.links, mine->links, sizeof(lsa_link) * in.nlinks) != 0;
            if (in.seq > r->my_seq || (in.seq == r->my_seq && differs)) { r->my_seq = in.seq; r->need_orig = 1; }
            else if (in.seq < r->my_seq) { n->pend_seq[in.origin] = r->my_seq; n->pend_tx_ms[in.origin] = 0; }
            else if (n->pend_seq[in.origin] == in.seq) n->pend_seq[in.origin] = 0;
        } else if (!have->valid || lsa_seq_newer(in.seq, have->seq)) {
            in.valid = 1;
            in.age_at_rx = age;
            in.rx_ms = t;
            *have = in;
            r->st.lsa_installed++;
            r->spf_dirty = 1;
            flood(r, in.origin, in.seq, ni);
            n->pend_seq[in.origin] = 0;
        } else if (in.seq == have->seq) {
            r->st.lsa_dup++;
            if (n->pend_seq[in.origin] == in.seq) n->pend_seq[in.origin] = 0; /* implicit ack */
        } else {
            r->st.lsa_stale++; /* sender is behind: give it our newer copy */
            n->pend_seq[in.origin] = have->seq;
            n->pend_tx_ms[in.origin] = 0;
            continue;
        }
        if (aoff + 6 <= sizeof ack) {
            put16(ack + aoff, in.origin);
            put32(ack + aoff + 2, in.seq);
            aoff += 6;
            acnt++;
        }
    }
    if (acnt) { put16(ack, acnt); send_pkt(r, n->id, PKT_ACK, ack, aoff); }
    return rc;
}

static int handle_ack(router_t *r, int ni, const uint8_t *p, size_t len) {
    nbr_t *n = &r->nbr[ni];
    if (len < 2) return RX_BAD_PAYLOAD;
    uint16_t cnt = get16(p);
    if ((size_t)cnt * 6 > len - 2) return RX_BAD_PAYLOAD;
    for (uint16_t k = 0; k < cnt; k++) {
        uint16_t o = get16(p + 2 + 6 * k);
        uint32_t s = get32(p + 2 + 6 * k + 2);
        if (o == 0 || o >= MAX_ROUTERS) continue;
        if (n->pend_seq[o] && s >= n->pend_seq[o]) n->pend_seq[o] = 0;
    }
    return RX_OK;
}

/* ---------- distance vector baseline ---------- */

static void dv_recompute(router_t *r) {
    int changed = 0;
    for (int d = 1; d < MAX_ROUTERS; d++) {
        if (d == r->self) continue;
        uint32_t best = DV_INF;
        uint16_t nh = 0;
        for (int i = 0; i < r->nnbr; i++) {
            const nbr_t *n = &r->nbr[i];
            if (n->state != NBR_FULL) continue;
            uint32_t m = n->dv_metric[d] + n->cost;
            if (m > DV_INF) m = DV_INF;
            if (m < best || (m == best && m < DV_INF && n->id < nh)) { best = m; nh = n->id; }
        }
        if (best >= DV_INF) { best = DV_INF; nh = 0; }
        if (best != r->dv_metric[d] || nh != r->dv_nh[d]) {
            r->dv_metric[d] = best;
            r->dv_nh[d] = nh;
            changed = 1;
        }
        fib_ent e = {0, 0};
        if (nh) { e.nh = nh; e.cost = best; }
        if (e.nh != r->fib[d].nh || e.cost != r->fib[d].cost) {
            r->fib[d] = e;
            r->fib_change_us = now_us(r);
            r->fib_changes++;
        }
    }
    if (changed) r->dv_dirty = 1;
}

static void dv_send(router_t *r) {
    uint8_t pl[2 + 4 * MAX_ROUTERS];
    for (int i = 0; i < r->nnbr; i++) {
        const nbr_t *n = &r->nbr[i];
        if (n->state == NBR_DOWN || n->admin_down) continue;
        size_t off = 2;
        uint16_t cnt = 0;
        for (int d = 1; d < MAX_ROUTERS; d++) {
            uint32_t m = r->dv_metric[d];
            /* unreachable destinations are advertised at infinity, never omitted:
             * silence would leave stale routes in the neighbor's table */
            if (r->dv_nh[d] == n->id) m = DV_INF; /* split horizon, poisoned reverse */
            put16(pl + off, (uint16_t)d);
            put16(pl + off + 2, (uint16_t)m);
            off += 4;
            cnt++;
        }
        put16(pl, cnt);
        send_pkt(r, n->id, PKT_DV, pl, off);
    }
}

static int handle_dv(router_t *r, int ni, const uint8_t *p, size_t len) {
    nbr_t *n = &r->nbr[ni];
    if (n->state != NBR_FULL) return RX_NOT_ADJACENT;
    if (len < 2) return RX_BAD_PAYLOAD;
    uint16_t cnt = get16(p);
    if ((size_t)cnt * 4 > len - 2) return RX_BAD_PAYLOAD;
    for (uint16_t k = 0; k < cnt; k++) {
        uint16_t d = get16(p + 2 + 4 * k);
        uint16_t m = get16(p + 2 + 4 * k + 2);
        if (d == 0 || d >= MAX_ROUTERS) continue;
        n->dv_metric[d] = m > DV_INF ? DV_INF : m;
    }
    dv_recompute(r);
    return RX_OK;
}

/* ---------- hello ---------- */

static void send_hellos(router_t *r) {
    uint8_t pl[6 + 2 * MAX_NBRS];
    put16(pl, (uint16_t)r->t.hello_ms);
    put16(pl + 2, (uint16_t)r->t.dead_ms);
    uint16_t cnt = 0;
    for (int i = 0; i < r->nnbr; i++)
        if (r->nbr[i].state != NBR_DOWN) { put16(pl + 6 + 2 * cnt, r->nbr[i].id); cnt++; }
    put16(pl + 4, cnt);
    for (int i = 0; i < r->nnbr; i++)
        if (!r->nbr[i].admin_down) send_pkt(r, r->nbr[i].id, PKT_HELLO, pl, 6 + 2 * (size_t)cnt);
}

static int handle_hello(router_t *r, int ni, const uint8_t *p, size_t len) {
    nbr_t *n = &r->nbr[ni];
    if (len < 6) return RX_BAD_PAYLOAD;
    uint16_t cnt = get16(p + 4);
    if (cnt > MAX_NBRS || (size_t)cnt * 2 > len - 6) return RX_BAD_PAYLOAD;
    if (get16(p) != r->t.hello_ms || get16(p + 2) != r->t.dead_ms) return RX_BAD_PAYLOAD; /* timer mismatch */
    int seen_me = 0;
    for (uint16_t k = 0; k < cnt; k++)
        if (get16(p + 6 + 2 * k) == r->self) seen_me = 1;
    n->last_heard_ms = now_ms(r);
    if (seen_me) {
        if (n->state != NBR_FULL) nbr_full(r, ni);
    } else {
        if (n->state == NBR_FULL) nbr_down(r, ni); /* neighbor restarted: one-way again */
        n->state = NBR_INIT;
        r->last_hello_ms = 0; /* answer quickly so the adjacency forms fast */
    }
    return RX_OK;
}

/* ---------- receive path ---------- */

int router_rx(router_t *r, const uint8_t *buf, size_t len) {
    int rc;
    r->st.rx_pkts++;
    if (len < HDR_LEN) { rc = RX_SHORT; goto out; }
    if (buf[0] != PROTO_VERSION) { rc = RX_BAD_VERSION; goto out; }
    if (get16(buf + 2) != len || len > MAX_PKT) { rc = RX_BAD_LEN; goto out; }
    int ni = nbr_index(r, get16(buf + 4));
    if (ni < 0) { rc = RX_UNKNOWN_SRC; goto out; }
    nbr_t *n = &r->nbr[ni];
    if (n->admin_down) { rc = RX_ADMIN_DOWN; goto out; }
    if (r->auth) {
        if (!(get16(buf + 6) & FLAG_AUTH)) { rc = RX_AUTH_FAIL; goto out; }
        uint8_t tmp[MAX_PKT];
        memcpy(tmp, buf, len);
        memset(tmp + HMAC_OFF, 0, SHA256_DIGEST_LEN);
        uint8_t mac[SHA256_DIGEST_LEN];
        hmac_sha256(r->key, r->key_len, tmp, len, mac);
        if (!ct_equal(mac, buf + HMAC_OFF, SHA256_DIGEST_LEN)) { rc = RX_AUTH_FAIL; goto out; }
        uint64_t cs = get64(buf + 8);
        if (cs <= n->last_rx_cseq) { rc = RX_REPLAY; goto out; }
        n->last_rx_cseq = cs; /* only advanced after the MAC verifies */
    }
    memcpy(r->last_valid, buf, len);
    r->last_valid_len = len;
    const uint8_t *p = buf + HDR_LEN;
    size_t plen = len - HDR_LEN;
    switch (buf[1]) {
    case PKT_HELLO: rc = handle_hello(r, ni, p, plen); break;
    case PKT_LSU: rc = r->mode == MODE_LS ? handle_lsu(r, ni, p, plen) : RX_BAD_TYPE; break;
    case PKT_ACK: rc = r->mode == MODE_LS ? handle_ack(r, ni, p, plen) : RX_BAD_TYPE; break;
    case PKT_DV: rc = r->mode == MODE_DV ? handle_dv(r, ni, p, plen) : RX_BAD_TYPE; break;
    default: rc = RX_BAD_TYPE;
    }
out:
    r->st.rx[rc]++;
    return rc;
}

/* ---------- timers ---------- */

void router_tick(router_t *r) {
    uint64_t t = now_ms(r);
    if (!r->last_hello_ms || t - r->last_hello_ms >= r->t.hello_ms) {
        send_hellos(r);
        r->last_hello_ms = t;
    }
    for (int i = 0; i < r->nnbr; i++) {
        nbr_t *n = &r->nbr[i];
        if (n->state != NBR_DOWN && t - n->last_heard_ms > r->t.dead_ms) nbr_down(r, i);
    }
    if (r->mode == MODE_LS) {
        if (r->need_orig || t - r->last_orig_ms >= r->t.refresh_ms) originate(r);
        for (int o = 1; o < MAX_ROUTERS; o++) {
            lsa_t *l = &r->lsdb[o];
            if (l->valid && o != r->self && lsa_age(l, t) >= r->t.maxage_s) {
                l->valid = 0;
                r->spf_dirty = 1;
            }
        }
        send_lsus(r, t);
        if (r->spf_dirty) router_spf(r);
    } else {
        int periodic = !r->last_dv_ms || t - r->last_dv_ms >= r->t.dv_period_ms;
        int trig = r->dv_dirty && t - r->last_dv_ms >= r->t.dv_trigger_ms;
        if (periodic || trig) {
            dv_send(r);
            r->last_dv_ms = t;
            r->dv_dirty = 0;
        }
    }
}

/* ---------- introspection ---------- */

size_t router_fib_text(const router_t *r, char *out, size_t cap) {
    size_t off = 0;
    int w = snprintf(out, cap, "fib %u %llu %u %u\n", r->self, (unsigned long long)r->fib_change_us,
                     r->spf_runs, r->fib_changes);
    if (w < 0 || (size_t)w >= cap) return 0;
    off = (size_t)w;
    for (int d = 1; d < MAX_ROUTERS; d++) {
        if (!r->fib[d].nh) continue;
        w = snprintf(out + off, cap - off, "%d %u %u\n", d, r->fib[d].nh, r->fib[d].cost);
        if (w < 0 || (size_t)w >= cap - off) break;
        off += (size_t)w;
    }
    return off;
}

size_t router_stats_text(const router_t *r, char *out, size_t cap) {
    static const char *names[RX__COUNT] = {"rx_ok", "rx_short", "rx_bad_version", "rx_bad_len",
                                           "rx_unknown_src", "rx_admin_down", "rx_auth_fail",
                                           "rx_replay", "rx_bad_type", "rx_bad_payload", "rx_not_adjacent"};
    size_t off = 0;
    for (int i = 0; i < RX__COUNT; i++) {
        int w = snprintf(out + off, cap - off, "%s %llu\n", names[i], (unsigned long long)r->st.rx[i]);
        if (w < 0 || (size_t)w >= cap - off) return off;
        off += (size_t)w;
    }
    int w = snprintf(out + off, cap - off,
                     "tx_pkts %llu\nrx_pkts %llu\nlsa_installed %llu\nlsa_stale %llu\nlsa_dup %llu\n"
                     "lsa_rejected %llu\nretransmits %llu\noriginations %llu\nadj_up %llu\nadj_down %llu\n"
                     "my_seq %u\nsizeof_router %zu\n",
                     (unsigned long long)r->st.tx_pkts, (unsigned long long)r->st.rx_pkts,
                     (unsigned long long)r->st.lsa_installed, (unsigned long long)r->st.lsa_stale,
                     (unsigned long long)r->st.lsa_dup, (unsigned long long)r->st.lsa_rejected,
                     (unsigned long long)r->st.retransmits, (unsigned long long)r->st.originations,
                     (unsigned long long)r->st.adj_up, (unsigned long long)r->st.adj_down, r->my_seq,
                     sizeof(router_t));
    if (w > 0 && (size_t)w < cap - off) off += (size_t)w;
    return off;
}
