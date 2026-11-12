# Sparrow

I built a link-state routing daemon in C, from scratch, the way embedded network software
gets built: one OS process per router, a single `poll()` event loop, no heap allocation,
fixed-size tables, HMAC-SHA256 authenticated control packets with replay protection, and a
packet parser that has been fuzzed under AddressSanitizer and UBSan.

To test it I run the real 40-router GEANT 2012 research backbone (from the Internet
Topology Zoo) as 40 `sparrowd` processes on one machine, with UDP sockets on localhost as
the links. A Python harness then breaks the network on purpose (cuts links, `kill -9`s
routers, drops 5% of packets, injects forged and replayed packets) and checks every
router's forwarding table against an oracle shortest-path computation after every fault.

The same binary also runs a distance-vector mode (RIP-style, split horizon with poisoned
reverse, triggered updates), so every link-state number below has a baseline measured on
the identical topology, timers and fault sequence.

## Results

All numbers come from `results/results.json`, produced by `python3 harness/bench.py`
(macOS arm64, 40 daemons on one laptop) unless marked CI, which are copied from the
GitHub Actions run linked in that file.

**Convergence** (time from fault to the last forwarding-table change on any router,
counted only if all 1,560 FIB entries then match the oracle and stay correct for 0.5 s)

| Fault | Protocol | Trials | Correct | p50 | p90 | p99 |
|---|---|---|---|---|---|---|
| Link down (carrier loss) | link-state | 200 | 200 | 3.05 ms | 5.79 ms | 9.22 ms |
| Same 60 link faults | link-state | 60 | 60 | 2.41 ms | 5.44 ms | 8.46 ms |
| Same 60 link faults | distance-vector baseline | 60 | 60 | 23.15 ms | 2,791.53 ms | 4,115.21 ms |
| Router `kill -9` (200 ms dead interval) | link-state | 60 | 60 | 188.46 ms | 206.78 ms | 299.34 ms |
| Router `kill -9` | distance-vector baseline | 30 | 30 | 533.05 ms | 3,540.26 ms | 4,283.97 ms |
| Link down, 5% packet loss on every router | link-state | 50 | 50 | 3.14 ms | 337.82 ms | 498.41 ms |

The distance-vector tail is count-to-infinity: when a failure cuts off a destination
(GEANT has several single-homed routers), neighbors keep bouncing stale routes off each
other until the metric reaches infinity. Link-state does not have that failure mode.
Router failures are dominated by the 200 ms dead interval, as they are in real OSPF. Under
5% loss, the tail comes from 1,274 LSA retransmissions recovering 7,650 dropped packets.

**Correctness.** 400 of 400 fault trials ended with every FIB matching the oracle, with 0
forwarding loops and 0 black holes in the final states.

**Security** (authentication on, attacks injected at all 40 routers)

| Attack | Sent | Blocked | How |
|---|---|---|---|
| Forged LSU, wrong key | 40 | 40 | HMAC-SHA256 mismatch |
| Unsigned LSU | 40 | 40 | auth flag missing |
| Captured packet replayed 3x | 120 | 120 | per-neighbor crypto sequence |
| Stale LSA signed with the real key | 40 | 40 | LSA sequence number check |
| **Total** | **240** | **240** | FIBs unchanged (0 wrong of 1,560) |

Baseline: the same forged max-sequence LSA against a network with authentication off
poisoned routing in 10 of 10 attacks (mean 55.2 wrong FIB entries and 46.4 black-holed
source/destination pairs 2 s later, because the victim cannot out-sequence the forgery).

**Footprint and testing**

| Metric | Value |
|---|---|
| Stripped binary, Linux x86-64 (CI, gcc / clang) | 22,760 B / 22,976 B |
| Stripped binary, macOS arm64 | 52,576 B (Mach-O page padding) |
| Entire router state (`sizeof(router_t)`, static) | 25,608 B |
| Resident memory per daemon, macOS (40 of 40 measured) | 1,904 KB |
| Heap allocations in daemon code | 0 (`make check-noheap`) |
| Mutation fuzzing, ASan + UBSan | 20,000,000 inputs, 69.5M packets, 0 crashes |
| libFuzzer in CI, ASan + UBSan | 353,118 execs in 61 s, 217 edges, 0 crashes |
| CodeQL (c-cpp) | 0 open alerts |
| Unit checks (ASan + UBSan) | 56 of 56 |

## How it works

* `src/proto.c` is the protocol core and contains no sockets: it takes a clock and a send
  callback. That lets the same code run in the daemon, in an in-process network simulator
  (`tests/test_unit.c`) and inside the fuzzer.
* Neighbors: hellos every 50 ms, dead after 200 ms, two-way check before an adjacency is
  used. These are OSPF's 10 s / 40 s timers scaled down so experiments are quick.
* LSAs carry a 32-bit sequence number and an age. A router that restarts and hears an older
  copy of its own LSA jumps its sequence past it and re-originates.
* Flooding is reliable: per-neighbor retransmit lists, explicit acks, implicit acks on
  duplicates, and a newer copy sent back to any neighbor that offers a stale one.
* SPF is Dijkstra over the LSDB with the two-way link check and deterministic tie-breaking.
* Every packet has a 64-bit crypto sequence (seeded from the wall clock so reboots never
  reuse values) and an HMAC-SHA256 over the whole packet. The MAC is checked in constant
  time before the sequence window advances. SHA-256 and HMAC are my own implementation from
  FIPS 180-4 and RFC 2104, tested against NIST and RFC 4231 vectors.

## Run it

```sh
make                      # build/sparrowd and build/sparrowd.stripped
make test                 # unit tests + fuzz smoke + no-heap check + 40-router integration test (ASan)
python3 harness/bench.py  # every number above, about 10 minutes -> results/results.json
python3 harness/bench.py --quick
```

Run one router by hand:

```sh
./build/sparrowd -t data/geant2012.topo -i 3 -k 73706172726f772d6c61622d6b65792d31
echo fib | nc -u -w1 127.0.0.1 21003
```

The topology comes from `tools/zoo2topo.py data/Geant2012.graphml data/geant2012.topo`
(cost = 100 Gbps / link capacity; 22 unlabeled edges assumed 10 Gbps).

CI (`.github/workflows/ci.yml`) builds with `-Wall -Wextra -Werror -Wconversion` on gcc and
clang, runs the unit, fuzz-smoke, no-heap and integration tests under sanitizers, runs
libFuzzer for 60 s, and runs CodeQL.

## Limits

* Single area, point-to-point links only: no DR/BDR election, no LSA checksums, and the
  database exchange is simplified (each side pushes its whole LSDB reliably instead of
  OSPF's DBD/LSR handshake).
* Timers are scaled down, so absolute convergence numbers depend on them. Links are UDP on
  localhost, so there is no propagation delay, and all routers share one clock (which is
  what makes cross-process timing possible).
* No MaxSequenceNumber flush: a forged max-sequence LSA is stopped by authentication, not
  by sequence recovery, which is exactly what the unauthenticated baseline shows.
* The replay window is per neighbor and assumes in-order delivery, which holds on localhost.
* Resident memory is reported by each daemon itself; on macOS most of the 1.9 MB is the
  shared system libraries, not Sparrow's 25.6 KB of state.
* The fuzzer found no crashes in the daemon. ASan did catch an overlapping `memcpy` in my
  own mutation driver, which I fixed; I am not counting that as a daemon bug.
