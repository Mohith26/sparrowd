#!/usr/bin/env python3
"""Reproduce every number in results/results.json.

Runs the 40-router GEANT 2012 network (real topology from the Internet Topology
Zoo) as 40 sparrowd processes on localhost and measures:
  1. convergence after link and router failures, link-state vs the distance-vector
     baseline built into the same daemon (same timers, same topology, same faults)
  2. routing correctness against an oracle Dijkstra (wrong entries, loops, black holes)
  3. security: forged, unsigned and replayed packets against HMAC-SHA256 auth, plus
     the same forged LSA against an unauthenticated network as the baseline
  4. footprint: stripped binary size, static state, resident memory per daemon
  5. fuzzing: deterministic mutation fuzzer under ASan+UBSan
usage: python3 harness/bench.py [--quick]
"""
import json
import os
import platform
import random
import statistics
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from net import (DEFAULT_KEY, PKT_LSU, Net, build_packet, load_topo, lsa_bytes,  # noqa: E402
                 shortest_paths)

TOPO = "data/geant2012.topo"
QUICK = "--quick" in sys.argv
N_LINK_LS, N_LINK_DV, N_ROUTER_LS, N_ROUTER_DV, N_LOSS = (
    (20, 8, 8, 4, 8) if QUICK else (200, 60, 60, 30, 50))
FUZZ_ITERS, FUZZ_SEEDS = (200000, 2) if QUICK else (2000000, 10)
SEED = 2026


def pct(xs, p):
    xs = sorted(xs)
    if not xs:
        return None
    k = (len(xs) - 1) * p / 100.0
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return round(xs[lo] + (xs[hi] - xs[lo]) * (k - lo), 2)


def summarize(times, trials, timeouts):
    return {"trials": trials, "converged_correct": len(times), "timeouts_or_incorrect": timeouts,
            "p50_ms": pct(times, 50), "p90_ms": pct(times, 90), "p99_ms": pct(times, 99),
            "max_ms": round(max(times), 2) if times else None,
            "mean_ms": round(statistics.mean(times), 2) if times else None}


def affecting_links(nodes, links):
    """Links whose failure changes at least one shortest-path distance."""
    base = shortest_paths(nodes, links)
    out = []
    for k in sorted(links):
        rest = {x: c for x, c in links.items() if x != k}
        if shortest_paths(nodes, rest) != base:
            out.append(k)
    return out


def link_trials(mode, faults, loss=0.0, timeout=30.0):
    net = Net(TOPO, mode=mode)
    net.start()
    ok, _ = net.wait_correct(30)
    assert ok, "initial convergence failed"
    if loss:
        net.set_loss(loss)
    times, bad, totals, per = [], 0, {"wrong": 0, "loops": 0, "blackholes": 0}, []
    for (a, b) in faults:
        t0 = time.time()
        net.link_down(a, b)
        ms = net.measure(t0, timeout=timeout)
        e = net.errors()
        for k in totals:
            totals[k] += e[k]
        per.append(ms)
        if ms is None:
            bad += 1
        else:
            times.append(ms)
        net.link_up(a, b)
        net.wait_correct(timeout)
        time.sleep(0.2)
    stats = [net.stats(r) for r in sorted(net.alive)]
    errs = net.stop()
    res = summarize(times, len(faults), bad)
    res["final_state_errors_summed"] = totals
    res["retransmits_total"] = sum(s["retransmits"] for s in stats)
    res["dropped_tx_total"] = sum(s["dropped_tx"] for s in stats)
    res["sanitizer_errors"] = len(errs)
    return res, per


def router_trials(mode, victims, timeout=30.0):
    net = Net(TOPO, mode=mode)
    net.start()
    ok, _ = net.wait_correct(30)
    assert ok
    times, bad, totals = [], 0, {"wrong": 0, "loops": 0, "blackholes": 0}
    for v in victims:
        t0 = time.time()
        net.kill(v)  # SIGKILL: neighbors only learn from the dead interval
        ms = net.measure(t0, timeout=timeout)
        e = net.errors()
        for k in totals:
            totals[k] += e[k]
        if ms is None:
            bad += 1
        else:
            times.append(ms)
        net.start_router(v)
        net.wait_correct(timeout)
        time.sleep(0.3)
    net.stop()
    res = summarize(times, len(victims), bad)
    res["final_state_errors_summed"] = totals
    return res, times


def security_trials():
    nodes, links = load_topo(TOPO)
    nbrs = {n: [] for n in nodes}
    for a, b in links:
        nbrs[a].append(b)
        nbrs[b].append(a)
    wrong_key = "00" * 17
    out = {}

    # --- authenticated network ---
    net = Net(TOPO, mode="ls", key=DEFAULT_KEY)
    net.start()
    assert net.wait_correct(30)[0]
    before = {r: net.stats(r) for r in nodes}
    sent = {"forged_wrong_key": 0, "unsigned": 0, "replayed": 0, "stale_lsa_valid_key": 0}
    for r in nodes:
        n = nbrs[r][0]
        bogus = lsa_bytes(n, 0xFFFFFFFF, 0, [])  # max-sequence withdrawal: n vanishes
        pl = (1).to_bytes(2, "big") + bogus
        net.inject(r, build_packet(PKT_LSU, n, pl, key_hex=wrong_key))
        sent["forged_wrong_key"] += 1
        net.inject(r, build_packet(PKT_LSU, n, pl, key_hex=None))
        sent["unsigned"] += 1
        cap = bytes.fromhex(net.ctl(r, "capture").strip())
        for _ in range(3):
            net.inject(r, cap)
            sent["replayed"] += 1
        # an insider with the key replays an old LSA (seq 1) for a real router:
        # authentication passes, the LSA sequence check must refuse to install it
        stale = (1).to_bytes(2, "big") + lsa_bytes(n, 1, 0, [])
        net.inject(r, build_packet(PKT_LSU, n, stale, key_hex=DEFAULT_KEY))
        sent["stale_lsa_valid_key"] += 1
    time.sleep(1.0)
    after = {r: net.stats(r) for r in nodes}
    e = net.errors()
    net.stop()
    d = lambda k: sum(after[r][k] - before[r][k] for r in nodes)  # noqa: E731
    out["auth_on"] = {
        "attack_packets_sent": sent,
        "auth_failures_counted": d("rx_auth_fail"),
        "replays_counted": d("rx_replay"),
        "forged_or_unsigned_rejected": d("rx_auth_fail"),
        "forged_or_unsigned_sent": sent["forged_wrong_key"] + sent["unsigned"],
        "replays_rejected": d("rx_replay"),
        "stale_lsas_refused": d("lsa_stale"),
        "fib_errors_after_attacks": e,
    }

    # --- baseline: the same forged LSA, unauthenticated network ---
    rnd = random.Random(SEED)
    victims = rnd.sample(nodes, 10)
    poisoned = []
    for v in victims:
        netb = Net(TOPO, mode="ls", key=None, base=23000)
        netb.start()
        assert netb.wait_correct(30)[0]
        r = nbrs[v][0]
        pl = (1).to_bytes(2, "big") + lsa_bytes(v, 0xFFFFFFFF, 0, [])
        netb.inject(r, build_packet(PKT_LSU, v, pl, key_hex=None))
        time.sleep(2.0)  # long enough for flooding and for the victim to try to fight back
        e = netb.errors()
        poisoned.append(e)
        netb.stop()
        time.sleep(0.3)
    out["auth_off_baseline"] = {
        "victims": victims,
        "attacks": len(victims),
        "attacks_that_poisoned_routing": sum(1 for e in poisoned if e["wrong"] > 0),
        "mean_wrong_fib_entries_2s_after": round(statistics.mean(e["wrong"] for e in poisoned), 1),
        "mean_blackholed_pairs_2s_after": round(statistics.mean(e["blackholes"] for e in poisoned), 1),
        "pairs_per_check": poisoned[0]["pairs"],
    }
    return out


def footprint():
    net = Net(TOPO, mode="ls")
    net.start()
    assert net.wait_correct(30)[0]
    time.sleep(1.0)
    sts = [net.stats(r) for r in sorted(net.alive)]
    rss = [s["rss_kb"] for s in sts]
    peak = [s["maxrss_kb"] for s in sts]
    st = sts[0]
    net.stop()
    size_out = subprocess.run(["size", "build/sparrowd"], capture_output=True, text=True).stdout.strip()
    return {
        "platform": f"{platform.system()} {platform.machine()}",
        "binary_bytes_stripped": os.path.getsize("build/sparrowd.stripped"),
        "binary_bytes_unstripped": os.path.getsize("build/sparrowd"),
        "size_output": size_out,
        "router_state_bytes_static": st["sizeof_router"],
        "rss_kb_median": statistics.median(rss),
        "rss_kb_max": max(rss),
        "peak_rss_kb_max": max(peak),
        "rss_source": "task_info (macOS) or /proc/self/statm (Linux), read by each daemon itself",
        "routers_measured": len(rss),
        "heap_allocations_in_daemon_code": 0,
        "heap_check": "make check-noheap: nm -u on daemon objects shows no malloc/calloc/realloc/free",
    }


def nodes_first(net):
    return sorted(net.alive)[0]


def fuzz():
    runs = []
    for s in range(1, FUZZ_SEEDS + 1):
        p = subprocess.run(["./build/fuzz_driver", str(FUZZ_ITERS), str(s)], capture_output=True, text=True,
                           env=dict(os.environ, ASAN_OPTIONS="detect_leaks=0"))
        if p.returncode != 0:
            runs.append({"seed": s, "crashed": True, "stderr_tail": p.stderr[-2000:]})
        else:
            j = json.loads(p.stdout.strip().splitlines()[-1])
            j["seed"] = s
            j["crashed"] = False
            runs.append(j)
    ok = [r for r in runs if not r["crashed"]]
    outcomes = {}
    for r in ok:
        for k, v in r["outcomes"].items():
            outcomes[k] = outcomes.get(k, 0) + v
    return {
        "harness": "deterministic mutation fuzzer (fuzz/fuzz_driver.c) over the full receive path, ASan+UBSan",
        "inputs_executed": sum(r["iterations"] for r in ok),
        "packets_parsed": sum(r["packets"] for r in ok),
        "cpu_seconds": round(sum(r["cpu_seconds"] for r in ok), 1),
        "lsas_installed_from_fuzzed_input": sum(r["lsa_installed"] for r in ok),
        "runs": len(runs),
        "crashing_runs": sum(1 for r in runs if r["crashed"]),
        "outcomes": outcomes,
        "crash_details": [r for r in runs if r["crashed"]],
    }


def add_summary(res):
    """Totals derived from the sections above, so every headline number lives in this file."""
    ls_keys = ["link_failure_ls", "router_failure_ls", "link_failure_ls_5pct_loss"]
    all_keys = ls_keys + ["link_failure_dv", "router_failure_dv"]
    sec = res["security"]["auth_on"]
    sent = sec["attack_packets_sent"]
    res["summary"] = {
        "ls_fault_trials": sum(res[k]["trials"] for k in ls_keys),
        "ls_fault_trials_correct": sum(res[k]["converged_correct"] for k in ls_keys),
        "all_fault_trials": sum(res[k]["trials"] for k in all_keys),
        "all_fault_trials_correct": sum(res[k]["converged_correct"] for k in all_keys),
        "ls_loops_in_final_states": sum(res[k]["final_state_errors_summed"]["loops"] for k in ls_keys),
        "ls_blackholes_in_final_states": sum(res[k]["final_state_errors_summed"]["blackholes"] for k in ls_keys),
        "loops_in_final_states": sum(res[k]["final_state_errors_summed"]["loops"] for k in all_keys),
        "blackholes_in_final_states": sum(res[k]["final_state_errors_summed"]["blackholes"] for k in all_keys),
        "fib_entries_checked_per_trial": res["security"]["auth_on"]["fib_errors_after_attacks"]["pairs"],
        "link_failure_p99_ms_ls_vs_dv_same_faults": [res["link_failure_ls_same_faults_as_dv"]["p99_ms"],
                                                     res["link_failure_dv"]["p99_ms"]],
        "link_failure_p50_ms_ls_vs_dv_same_faults": [res["link_failure_ls_same_faults_as_dv"]["p50_ms"],
                                                     res["link_failure_dv"]["p50_ms"]],
        "attack_packets_sent": sum(sent.values()),
        "attack_packets_blocked": sec["auth_failures_counted"] + sec["replays_counted"] + sec["stale_lsas_refused"],
        "forged_lsas_poisoning_routing_without_auth": [res["security"]["auth_off_baseline"]["attacks_that_poisoned_routing"],
                                                       res["security"]["auth_off_baseline"]["attacks"]],
    }
    return res


def main():
    out = "results/results_quick.json" if QUICK else "results/results.json"
    if "--summarize" in sys.argv:  # recompute the summary block of an existing run
        with open(out) as f:
            res = add_summary(json.load(f))
        with open(out, "w") as f:
            json.dump(res, f, indent=2)
        print(json.dumps(res["summary"], indent=2))
        return
    os.makedirs("results", exist_ok=True)
    prior = {}
    if os.path.exists(out):
        with open(out) as f:
            prior = {k: v for k, v in json.load(f).items() if k.startswith("ci_")}
    nodes, links = load_topo(TOPO)
    rnd = random.Random(SEED)
    cand = affecting_links(nodes, links)
    link_faults = [rnd.choice(cand) for _ in range(N_LINK_LS)]
    victims = [rnd.choice(nodes) for _ in range(N_ROUTER_LS)]
    t_start = time.time()
    res = {"topology": {"name": "GEANT 2012 (Internet Topology Zoo)", "routers": len(nodes),
                        "links": len(links), "links_whose_failure_changes_routing": len(cand),
                        "cost_rule": "100 Gbps / link capacity (OSPF auto-cost style)"},
           "timers": {"hello_ms": 50, "dead_ms": 200, "lsa_retransmit_ms": 100, "dv_periodic_ms": 1000,
                      "dv_triggered_min_gap_ms": 20, "dv_infinity": 2048, "poll_granularity_ms": 5},
           "quick": QUICK}

    print("link failures, link-state ...", flush=True)
    res["link_failure_ls"], ls_per = link_trials("ls", link_faults)
    print("link failures, distance-vector baseline ...", flush=True)
    res["link_failure_dv"], _ = link_trials("dv", link_faults[:N_LINK_DV])
    sub = ls_per[:N_LINK_DV]
    res["link_failure_ls_same_faults_as_dv"] = summarize([x for x in sub if x is not None], len(sub),
                                                         sum(1 for x in sub if x is None))
    print("router failures (SIGKILL), link-state ...", flush=True)
    res["router_failure_ls"], _ = router_trials("ls", victims)
    print("router failures (SIGKILL), distance-vector baseline ...", flush=True)
    res["router_failure_dv"], _ = router_trials("dv", victims[:N_ROUTER_DV])
    print("link failures under 5% packet loss, link-state ...", flush=True)
    res["link_failure_ls_5pct_loss"], _ = link_trials("ls", link_faults[:N_LOSS], loss=5.0)
    print("security ...", flush=True)
    res["security"] = security_trials()
    print("footprint ...", flush=True)
    res["footprint"] = footprint()
    print("fuzzing ...", flush=True)
    res["fuzz"] = fuzz()
    res["wall_seconds"] = round(time.time() - t_start, 1)
    res.update(prior)  # keep numbers copied from CI runs (see README)
    add_summary(res)
    with open(out, "w") as f:
        json.dump(res, f, indent=2)
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
