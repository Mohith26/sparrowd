# Sparrow: spec

## Problem

A router's control plane has to do three things under pressure: notice when a link or a
neighbor dies, agree with every other router on the new topology, and rebuild its
forwarding table before packets start looping or vanishing. It has to do that on a box
with a fixed memory budget, against inputs it cannot trust, and without ever crashing.

Sparrow is a link-state routing daemon (OSPF-style, written from scratch in C) built the
way embedded network software is built: one process per router, one `poll()` event loop,
no heap, fixed tables, authenticated control traffic, and a parser that has been fuzzed
under sanitizers. A Python harness runs a whole network of these daemons on one machine,
breaks it on purpose, and checks every forwarding table against an oracle.

## Why it matters to the target team

Cisco's embedded intern teams (Common Hardware Group, Network Product Eng, Infrastructure
and Security) work on operating systems, firmware and networking stacks. The posting asks
for C, embedded Linux and OS fundamentals, routing protocols, Python/Bash automation,
CI/CD with GitHub Actions, and DevSecOps, with security protocols preferred. This project
touches each of those directly: a routing protocol in C, socket and process level OS
work, HMAC-authenticated control packets with replay protection, sanitizer and fuzz
testing, and a GitHub Actions pipeline (gcc and clang matrix, ASan/UBSan, libFuzzer,
CodeQL).

## Design

* **Process model.** `sparrowd -t topo -i <id>`: one OS process per router. Each router
  binds UDP `127.0.0.1:(base+id)` for protocol traffic and `127.0.0.1:(base+1000+id)` for a
  text control channel (`fib`, `stats`, `ifdown N`, `ifup N`, `loss PCT`, `capture`,
  `quit`). The topology file lists links and costs; each router only uses its own links,
  like an interface config.
* **Event loop.** A single `poll()` over the two sockets with a 5 ms timer tick. No
  threads, no signals beyond SIGTERM.
* **Memory.** The entire router (neighbor table, retransmit lists, LSDB, FIB) is one
  statically allocated `router_t` (25.6 KB). There is no `malloc` anywhere in the daemon
  code; `make check-noheap` fails the build if any daemon object file imports an allocator
  symbol.
* **Protocol core** (`src/proto.c`) is pure logic: it takes a clock and a send callback,
  which lets the same code run in the daemon, in an in-process network simulator for unit
  tests, and inside the fuzzer.
  * Hello / dead interval neighbor discovery with a two-way check (50 ms / 200 ms, scaled
    down from OSPF's 10 s / 40 s so experiments run quickly).
  * Router LSAs with 32-bit sequence numbers and aging (refresh 10 s, MaxAge 30 s). A
    restarted router that hears an older incarnation of its own LSA jumps its sequence
    past it and re-originates.
  * Reliable flooding: per-neighbor retransmit lists, explicit acks, implicit acks on
    duplicates, newer-copy-back on stale LSAs, 100 ms retransmit timer.
  * Dijkstra SPF (O(N^2), N <= 63) with the OSPF two-way link check and deterministic
    tie-breaking, producing a FIB of (destination, next hop, cost).
  * Simplified database exchange: when an adjacency comes up each side reliably pushes
    its whole LSDB instead of OSPF's DBD/LSR exchange.
* **Security.** Every packet carries a 64-bit crypto sequence number and an HMAC-SHA256
  over the whole packet (RFC 5709 / RFC 7474 style). SHA-256 and HMAC are implemented
  from FIPS 180-4 and RFC 2104 and checked against NIST and RFC 4231 vectors. The receiver
  verifies the MAC in constant time, then requires the crypto sequence to strictly
  increase per neighbor, so captured packets cannot be replayed. The sequence is seeded
  from the wall clock so a rebooted router never reuses old values.
* **Baseline protocol.** The same binary runs a distance-vector mode (`-m dv`):
  RIP-style Bellman-Ford with split horizon and poisoned reverse, triggered updates
  (20 ms minimum gap), 1 s periodic updates, infinity 2048. Same hello/dead timers, same
  sockets, same harness.

## Data

The network is GEANT 2012 (40 routers, 61 links) from the Internet Topology Zoo
(`data/Geant2012.graphml`, mirrored from github.com/sk2/topologyzoo). Link costs follow
OSPF auto-cost: 100 Gbps / capacity. 22 edges have no capacity label and are assumed to be
10 Gbps, the network's most common capacity. The topology is real; the links are emulated
with UDP on one machine, so propagation delay is not modeled.

## Metrics and how they are measured (`harness/bench.py` -> `results/results.json`)

1. **Convergence time** after a link failure (`ifdown` on both ends, like loss of carrier)
   and after a router failure (`SIGKILL`, so neighbors only learn from the dead interval).
   Convergence = latest FIB change on any router minus the failure time, accepted only if
   every FIB then matches the oracle and stays correct for a 0.5 s settle window.
   Reported as p50/p90/p99 over many trials.
   *Baseline:* the distance-vector mode on the identical fault sequence.
2. **Routing correctness.** After every trial, every router's FIB (40 x 39 = 1560
   entries) is checked against an oracle Dijkstra: right cost, next hop on a shortest
   path, and a hop-by-hop forwarding walk that counts loops and black holes. Also run with
   5% injected packet loss on every router.
3. **Security.** Forged (wrong key), unsigned, replayed (captured then re-sent) and
   stale-but-validly-signed LSAs are injected at every router; count how many are
   rejected and whether any FIB changes. *Baseline:* the same forged max-sequence LSA
   against a network with authentication off.
4. **Footprint.** Stripped binary size, static router state, resident memory per daemon.
5. **Fuzzing.** Inputs executed, crashes found, under ASan + UBSan.

## Limits (stated up front)

* Single area, point-to-point links only, no DR/BDR, no LSA checksums, simplified DB exchange.
* Scaled timers; absolute convergence numbers depend on them (router failure time is
  dominated by the 200 ms dead interval).
* All routers on one host share a clock, which is what makes cross-process convergence
  timing possible; a real network would need synchronized clocks.
* No OSPF MaxSequenceNumber flush: a forged max-sequence LSA is stopped by authentication,
  not by sequence-number recovery (the baseline experiment shows why that matters).
