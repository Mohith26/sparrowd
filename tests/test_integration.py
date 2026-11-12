#!/usr/bin/env python3
"""End-to-end test: 40 real sparrowd processes (AddressSanitizer + UBSan build) on the
GEANT topology. Fails on any wrong FIB entry, loop, black hole, accepted forgery or
replay, or sanitizer report from any daemon."""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "harness"))
from net import DEFAULT_KEY, PKT_LSU, Net, build_packet, lsa_bytes  # noqa: E402

TOPO = "data/geant2012.topo"
BIN = os.environ.get("SPARROWD", "build/sparrowd.asan")
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what, flush=True)
    if not cond:
        failures.append(what)


def run_ls():
    net = Net(TOPO, binary=BIN, mode="ls", base=25000)
    net.start()
    ok, _ = net.wait_correct(30)
    check(ok, "link-state: initial convergence, all 1560 FIB entries match oracle")
    links = sorted(net.all_links)
    for (a, b) in [links[0], links[17], links[33], links[50]]:
        t0 = time.time()
        net.link_down(a, b)
        ms = net.measure(t0, timeout=10, settle=0.3)
        check(ms is not None, f"link-state: link {a}-{b} down, reconverged ({ms and round(ms, 1)} ms)")
        net.link_up(a, b)
        check(net.wait_correct(10)[0], f"link-state: link {a}-{b} restored")
    t0 = time.time()
    net.kill(3)
    ms = net.measure(t0, timeout=10, settle=0.3)
    check(ms is not None, f"link-state: router 3 SIGKILL, reconverged ({ms and round(ms, 1)} ms)")
    net.start_router(3)
    check(net.wait_correct(10)[0], "link-state: router 3 restarted with fresh sequence numbers")

    # attacks
    victim, nbr = 5, 4
    s0 = net.stats(victim)
    pl = (1).to_bytes(2, "big") + lsa_bytes(nbr, 0xFFFFFFFF, 0, [])
    net.inject(victim, build_packet(PKT_LSU, nbr, pl, key_hex="11" * 16))
    net.inject(victim, build_packet(PKT_LSU, nbr, pl, key_hex=None))
    cap = bytes.fromhex(net.ctl(victim, "capture").strip())
    net.inject(victim, cap)
    time.sleep(0.5)
    s1 = net.stats(victim)
    check(s1["rx_auth_fail"] - s0["rx_auth_fail"] == 2, "forged and unsigned LSUs rejected by HMAC check")
    check(s1["rx_replay"] - s0["rx_replay"] == 1, "captured packet replay rejected")
    e = net.errors()
    check(e["wrong"] == 0 and e["loops"] == 0 and e["blackholes"] == 0, "routing intact after attacks")
    errs = net.stop()
    check(not errs, f"no sanitizer reports from link-state daemons ({len(errs)})")
    for r, err in list(errs.items())[:2]:
        print(err[-3000:])


def run_dv():
    net = Net(TOPO, binary=BIN, mode="dv", base=26000, key=None)
    net.start()
    check(net.wait_correct(30)[0], "distance-vector: initial convergence")
    t0 = time.time()
    net.link_down(5, 6)
    ms = net.measure(t0, timeout=30, settle=0.3)
    check(ms is not None, f"distance-vector: link 5-6 down, reconverged ({ms and round(ms, 1)} ms)")
    errs = net.stop()
    check(not errs, "no sanitizer reports from distance-vector daemons")


def run_noauth_forgery():
    net = Net(TOPO, binary=BIN, mode="ls", base=27000, key=None)
    net.start()
    check(net.wait_correct(30)[0], "unauthenticated network converges")
    pl = (1).to_bytes(2, "big") + lsa_bytes(4, 0xFFFFFFFF, 0, [])
    net.inject(5, build_packet(PKT_LSU, 4, pl, key_hex=None))
    time.sleep(1.5)
    e = net.errors()
    check(e["wrong"] > 0, f"baseline: without auth one forged LSA poisons routing ({e['wrong']} wrong entries)")
    net.stop()


if __name__ == "__main__":
    run_ls()
    run_dv()
    run_noauth_forgery()
    print(f"{len(failures)} failures")
    sys.exit(1 if failures else 0)
