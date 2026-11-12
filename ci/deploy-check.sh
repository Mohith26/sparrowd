#!/usr/bin/env bash
# Exercise the embedded-Linux style deployment files on a real systemd host (CI):
#   * shellcheck the BusyBox init script and run it under `busybox sh`
#   * `systemd-analyze verify` the unit and print its offline security exposure score
#   * start router 1 as the hardened systemd service and routers 2 and 3 through the
#     BusyBox init script, then check the three form adjacencies and install routes
# Needs root (sudo) and systemd as PID 1. Prints one DEPLOY_RESULT line at the end.
set -euo pipefail

if [[ "${CI:-}" == "true" ]]; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq --no-install-recommends busybox-static shellcheck >/dev/null
fi

mkdir -p dist
make all
sudo install -m 0755 build/sparrowd /usr/sbin/sparrowd
sudo install -d -m 0755 /etc/sparrowd
printf 'link 1 2 10\nlink 2 3 10\nlink 1 3 30\n' | sudo tee /etc/sparrowd/topo >/dev/null
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' | sudo tee /etc/sparrowd/key >/dev/null
sudo chmod 0600 /etc/sparrowd/key
printf 'TOPO=/etc/sparrowd/topo\nID=1\n' | sudo tee /etc/default/sparrowd >/dev/null

shellcheck -s sh deploy/S50sparrowd
echo "shellcheck: clean"

sudo systemd-analyze verify deploy/sparrowd.service
echo "systemd-analyze verify: clean"
score_line=$(sudo systemd-analyze security --offline=true deploy/sparrowd.service | grep -i 'overall exposure' || true)
echo "$score_line" | tee dist/systemd-security.txt

sudo install -m 0644 deploy/sparrowd.service /etc/systemd/system/sparrowd.service
sudo systemctl daemon-reload
sudo systemctl start sparrowd
for id in 2 3; do
    printf 'TOPO=/etc/sparrowd/topo\nID=%s\nKEYFILE=/etc/sparrowd/key\nPIDFILE=/tmp/sparrowd%s.pid\nLOG=/tmp/sparrowd%s.log\n' \
        "$id" "$id" "$id" >"/tmp/sparrowd$id.conf"
    sudo SPARROWD_CONF="/tmp/sparrowd$id.conf" busybox sh deploy/S50sparrowd start
done

# Router 1 (systemd) must learn routes to 2 and 3 from the BusyBox-started routers.
python3 - <<'EOF'
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.5)
deadline = time.time() + 10
want = {1: {2: (2, 10), 3: (2, 20)}, 2: {1: (1, 10), 3: (3, 10)}, 3: {1: (2, 20), 2: (2, 10)}}
while True:
    got = {}
    for r in (1, 2, 3):
        try:
            s.sendto(b"fib", ("127.0.0.1", 21000 + r))
            lines = s.recvfrom(4096)[0].decode().strip().split("\n")[1:]
            got[r] = {int(d): (int(nh), int(c)) for d, nh, c in (ln.split() for ln in lines)}
        except (socket.timeout, ValueError):
            got[r] = None
    if got == want:
        print("three-router FIBs correct:", got)
        break
    if time.time() > deadline:
        print("FIB mismatch:", got, file=sys.stderr)
        sys.exit(1)
    time.sleep(0.2)
EOF

systemctl show sparrowd -p ActiveState -p MainPID -p User -p DynamicUser -p NoNewPrivileges --no-pager
pid=$(systemctl show sparrowd -p MainPID --value)
user=$(ps -o user= -p "$pid")
rss=$(ps -o rss= -p "$pid" | tr -d ' ')
if sudo cat "/proc/$pid/cmdline" | tr '\0' ' ' | grep -Eq '[0-9a-f]{64}'; then
    echo "key visible on command line" >&2
    exit 1
fi
echo "key not visible in /proc/$pid/cmdline"

for id in 2 3; do
    sudo SPARROWD_CONF="/tmp/sparrowd$id.conf" busybox sh deploy/S50sparrowd status
    sudo SPARROWD_CONF="/tmp/sparrowd$id.conf" busybox sh deploy/S50sparrowd stop
done
sudo systemctl stop sparrowd
echo "DEPLOY_RESULT shellcheck=clean systemd_verify=clean service_user=$user service_rss_kb=$rss three_router_fibs=correct security=\"$score_line\""
