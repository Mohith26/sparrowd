"""Launch a network of sparrowd processes on localhost, inject faults and attacks,
and check every router's forwarding table against an oracle shortest-path
computation. Standard library only."""
import atexit
import heapq
import hmac
import hashlib
import os
import shlex
import signal
import socket
import struct
import subprocess
import time

HDR = struct.Struct(">BBHHHQ")
HDR_LEN = 48
PKT_LSU = 2
DEFAULT_KEY = "73706172726f772d6c61622d6b65792d31"  # "sparrow-lab-key-1"


def load_topo(path):
    nodes, links = set(), {}
    with open(path) as f:
        for line in f:
            p = line.split()
            if not p or p[0].startswith("#"):
                continue
            if p[0] == "node":
                nodes.add(int(p[1]))
            elif p[0] == "link":
                a, b, c = int(p[1]), int(p[2]), int(p[3])
                nodes.update((a, b))
                links[(min(a, b), max(a, b))] = c
    return sorted(nodes), links


def shortest_paths(nodes, links):
    """All-pairs Dijkstra. Returns dist[s][d] (missing = unreachable)."""
    adj = {n: [] for n in nodes}
    for (a, b), c in links.items():
        if a in adj and b in adj:
            adj[a].append((b, c))
            adj[b].append((a, c))
    dist = {}
    for s in nodes:
        d = {s: 0}
        pq = [(0, s)]
        while pq:
            du, u = heapq.heappop(pq)
            if du > d[u]:
                continue
            for v, c in adj[u]:
                if du + c < d.get(v, 1 << 60):
                    d[v] = du + c
                    heapq.heappush(pq, (d[v], v))
        dist[s] = d
    return dist


def check_fibs(fibs, nodes, links):
    """fibs: {router: {dest: (nh, cost)}}. A FIB entry is correct if its cost is the
    true shortest distance and its next hop is a live neighbor on some shortest
    path. Then forwarding is walked hop by hop for every (src, dst) pair to count
    loops and black holes. Returns dict of error counts."""
    dist = shortest_paths(nodes, links)
    cost = {}
    for (a, b), c in links.items():
        cost[(a, b)] = cost[(b, a)] = c
    wrong = loops = holes = 0
    pairs = 0
    for s in nodes:
        fib = fibs.get(s, {})
        for d in nodes:
            if d == s:
                continue
            pairs += 1
            want = dist[s].get(d)
            ent = fib.get(d)
            if want is None:
                if ent:
                    wrong += 1
                continue
            if not ent or ent[1] != want or (s, ent[0]) not in cost or \
                    cost[(s, ent[0])] + dist[ent[0]].get(d, 1 << 60) != want:
                wrong += 1
            # walk the forwarding path
            cur, seen = s, set()
            while cur != d:
                if cur in seen:
                    loops += 1
                    break
                seen.add(cur)
                e = fibs.get(cur, {}).get(d)
                if not e or (cur, e[0]) not in cost:
                    holes += 1
                    break
                cur = e[0]
    return {"pairs": pairs, "wrong": wrong, "loops": loops, "blackholes": holes}


def build_packet(ptype, src, payload, key_hex=None, cseq=None):
    if cseq is None:
        cseq = time.time_ns() // 1000
    flags = 1 if key_hex else 0
    length = HDR_LEN + len(payload)
    pkt = bytearray(HDR.pack(1, ptype, length, src, flags, cseq) + bytes(32) + payload)
    if key_hex:
        mac = hmac.new(bytes.fromhex(key_hex), bytes(pkt), hashlib.sha256).digest()
        pkt[16:48] = mac
    return bytes(pkt)


def lsa_bytes(origin, seq, age, links):
    out = struct.pack(">HIHH", origin, seq, age, len(links))
    for nbr, c in links:
        out += struct.pack(">HH", nbr, c)
    return out


class Net:
    def __init__(self, topo, binary="build/sparrowd", mode="ls", key=DEFAULT_KEY, base=20000,
                 hello_ms=50, dead_ms=200):
        self.topo = topo
        self.nodes, self.all_links = load_topo(topo)
        self.binary, self.mode, self.key, self.base = binary, mode, key, base
        self.hello_ms, self.dead_ms = hello_ms, dead_ms
        self.procs = {}
        self.alive = set()
        self.down_links = set()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.inj = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        atexit.register(self._cleanup)

    def _cleanup(self):
        for p in self.procs.values():
            if p.poll() is None:
                p.kill()

    # ----- process control -----
    def start_router(self, r):
        # SPARROWD_EXEC lets CI run a cross-compiled binary under an emulator,
        # e.g. SPARROWD_EXEC=qemu-aarch64-static
        args = shlex.split(os.environ.get("SPARROWD_EXEC", "")) + [self.binary, "-t", self.topo, "-i", str(r), "-m", self.mode, "-p", str(self.base),
                "-H", str(self.hello_ms), "-D", str(self.dead_ms)]
        if self.key:
            args += ["-k", self.key]
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:abort_on_error=1")
        self.procs[r] = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env)
        self.alive.add(r)

    def start(self):
        for r in self.nodes:
            self.start_router(r)
        time.sleep(0.2)
        for r, p in self.procs.items():
            if p.poll() is not None:
                raise RuntimeError(f"router {r} exited: {p.stderr.read().decode()}")

    def kill(self, r, sig=signal.SIGKILL):
        self.procs[r].send_signal(sig)
        self.procs[r].wait()
        self.alive.discard(r)

    def stop(self):
        for r, p in self.procs.items():
            if p.poll() is None:
                p.terminate()
        errs = {}
        for r, p in self.procs.items():
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
            err = p.stderr.read().decode()
            if "ERROR: AddressSanitizer" in err or "runtime error" in err:
                errs[r] = err
            p.stderr.close()
        self.sock.close()
        self.inj.close()
        return errs

    # ----- control channel -----
    def ctl(self, r, cmd, timeout=0.5, retries=4):
        for _ in range(retries):
            self.sock.settimeout(timeout)
            self.sock.sendto(cmd.encode(), ("127.0.0.1", self.base + 1000 + r))
            try:
                data, _ = self.sock.recvfrom(65536)
                return data.decode()
            except socket.timeout:
                continue
        raise TimeoutError(f"router {r} did not answer {cmd!r}")

    def fib(self, r):
        lines = self.ctl(r, "fib").strip().split("\n")
        hdr = lines[0].split()
        table = {}
        for ln in lines[1:]:
            d, nh, c = map(int, ln.split())
            table[d] = (nh, c)
        return {"changed_us": int(hdr[2]), "spf_runs": int(hdr[3]), "table": table}

    def stats(self, r):
        out = {}
        for ln in self.ctl(r, "stats").strip().split("\n"):
            k, v = ln.split()
            out[k] = int(v)
        return out

    def live_links(self):
        return {k: c for k, c in self.all_links.items()
                if k not in self.down_links and k[0] in self.alive and k[1] in self.alive}

    def link_down(self, a, b):
        self.down_links.add((min(a, b), max(a, b)))
        self.ctl(a, f"ifdown {b}")
        self.ctl(b, f"ifdown {a}")

    def link_up(self, a, b):
        self.down_links.discard((min(a, b), max(a, b)))
        self.ctl(a, f"ifup {b}")
        self.ctl(b, f"ifup {a}")

    def set_loss(self, pct):
        for r in self.alive:
            self.ctl(r, f"loss {pct}")

    # ----- verification -----
    def snapshot(self):
        fibs = {r: self.fib(r) for r in sorted(self.alive)}
        return fibs

    def errors(self, fibs=None):
        fibs = fibs or self.snapshot()
        return check_fibs({r: f["table"] for r, f in fibs.items()}, sorted(self.alive), self.live_links())

    def wait_correct(self, timeout=10.0, poll=0.01):
        t0 = time.time()
        while time.time() - t0 < timeout:
            fibs = self.snapshot()
            e = check_fibs({r: f["table"] for r, f in fibs.items()}, sorted(self.alive), self.live_links())
            if e["wrong"] == 0 and e["loops"] == 0 and e["blackholes"] == 0:
                return True, fibs
            time.sleep(poll)
        return False, fibs

    def measure(self, t0, timeout=20.0, settle=0.5):
        """After a fault injected at wall time t0: wait until every FIB is correct,
        hold for `settle` seconds, confirm it is still correct, and return the
        convergence time = latest FIB change on any router minus t0."""
        ok, _ = self.wait_correct(timeout)
        if not ok:
            return None
        time.sleep(settle)
        ok, fibs = self.wait_correct(1.0)
        if not ok:
            return None
        changes = [f["changed_us"] for f in fibs.values() if f["changed_us"] / 1e6 >= t0]
        if not changes:
            return 0.0
        return (max(changes) / 1e6 - t0) * 1000.0  # ms

    def inject(self, r, pkt):
        self.inj.sendto(pkt, ("127.0.0.1", self.base + r))
