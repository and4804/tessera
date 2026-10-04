#!/usr/bin/env bash
# Egress-denied proof (§10). Brings the stack up on the `internal: true` network, plays the smoke scenario, then asserts from INSIDE
# the app containers that outbound TCP and DNS fail, and that the compose file really marks the network internal.
# Exit 0 only if every assertion holds. With --static-only, run just the compose-file assertions (no docker daemon needed beyond `config`).
set -uo pipefail
cd "$(dirname "$0")/.."
FAIL=0
ok()  { echo "PASS  $*"; }
bad() { echo "FAIL  $*"; FAIL=1; }
FILES=(-f docker/compose.yml)
STATIC=0; [ "${1:-}" = "--static-only" ] && STATIC=1

# --- static assertions on the resolved compose model -------------------------------------------------------------------
CFG=$(docker compose -f docker/compose.yml -f docker/compose.siem.yml -f docker/compose.ai.yml --profile "*" config --format json 2>/dev/null) || { echo "cannot resolve compose config" >&2; exit 2; }
python3 - "$CFG" <<'PY' || FAIL=1
import json, sys
c = json.loads(sys.argv[1]); bad = []
nets = c.get("networks", {})
if not nets.get("internal", {}).get("internal"): bad.append("network `internal` is not internal: true")
for name, s in c["services"].items():
    extra = set(s.get("networks", {})) - {"internal"}
    if name == "gateway":                      # the single forwarder allowed to touch the non-internal `edge` network
        if extra != {"edge"}: bad.append(f"gateway: expected networks internal+edge, got {sorted(extra)}")
    elif extra: bad.append(f"{name}: attached to a non-internal network {sorted(extra)}")
    for p in s.get("ports", []):
        pub = int(p.get("published", 0)); host = p.get("host_ip", "")
        if name != "gateway": bad.append(f"{name}: publishes a port ({pub}); only gateway may")
        if pub not in (8080, 5601, 5140): bad.append(f"{name}: unexpected published port {pub}")
        if host not in ("127.0.0.1", ""): bad.append(f"{name}: port {pub} bound to {host}")
if bad: print("\n".join("FAIL  "+b for b in bad)); sys.exit(1)
print("PASS  compose: app services internal-only; only `gateway` is on `edge` and publishes UI/syslog ports")
PY
[ $STATIC = 1 ] && exit $FAIL

# --- dynamic assertions ------------------------------------------------------------------------------------------------
trap 'docker compose "${FILES[@]}" down -v >/dev/null 2>&1' EXIT
docker compose "${FILES[@]}" up -d --build --wait || { echo "stack failed to start"; exit 2; }

if command -v ulpf >/dev/null 2>&1; then
  # wait for the gateway to forward to a healthy API, then play a short scenario through the published port and check conservation
  ulpf demo --url http://127.0.0.1:8080 --eps 20 >/tmp/ulpf-airgap-demo.log 2>&1 && ok "smoke scenario played through the gateway" || bad "smoke scenario failed (see /tmp/ulpf-airgap-demo.log)"
  sleep 15
  LED=$(curl -fsS --noproxy '*' http://127.0.0.1:8080/api/v1/ledger 2>/dev/null) || LED=""
  python3 -c 'import json,sys; d=json.loads(sys.argv[1]); t=d.get("totals",d); sys.exit(0 if d.get("conserved") and t.get("ingested",0)>0 and d.get("lost",0)==0 else 1)' "$LED" 2>/dev/null \
    && ok "ledger conserved, lost=0, ingested>0" || bad "ledger not conserved or empty: ${LED:0:200}"
else
  echo "SKIP  ulpf CLI not on PATH: scenario not played (egress assertions still run)"
fi

for svc in api ingest worker; do   # redis:alpine has no python to probe with; it shares the same internal-only network
  # control: the probe itself works (it can reach redis on the internal network), so a failed external connect is not a broken probe
  if docker compose "${FILES[@]}" exec -T "$svc" python -c "import socket;socket.create_connection(('redis',6379),3)" >/dev/null 2>&1
  then ok "$svc: control - internal service reachable"; else bad "$svc: control probe cannot reach redis (probe unusable)"; fi
  # raw TCP to a public IP must fail (no route / refused); python is always present in the image, curl may not be
  if docker compose "${FILES[@]}" exec -T "$svc" python - <<'PY' >/dev/null 2>&1
import socket, sys
s = socket.socket(); s.settimeout(3)
try: s.connect(("1.1.1.1", 443)); sys.exit(0)
except OSError: sys.exit(1)
PY
  then bad "$svc: connected to 1.1.1.1:443"; else ok "$svc: TCP to 1.1.1.1:443 blocked"; fi
  if docker compose "${FILES[@]}" exec -T "$svc" python -c "import socket;socket.setdefaulttimeout(3);socket.gethostbyname('example.com')" >/dev/null 2>&1
  then bad "$svc: external DNS resolved"; else ok "$svc: external DNS lookup failed"; fi
  # no ESTABLISHED socket to a non-private address
  EST=$(docker compose "${FILES[@]}" exec -T "$svc" sh -c "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null" | python3 -c '
import sys, ipaddress
bad = 0
for ln in sys.stdin:
    f = ln.split()
    if len(f) < 4 or f[3] != "01" or ":" not in f[2]: continue
    h = f[2].split(":")[0]
    if len(h) == 8:
        ip = ipaddress.ip_address(bytes.fromhex(h)[::-1])
        if not (ip.is_private or ip.is_loopback): bad += 1
print(bad)')
  [ "${EST:-0}" = "0" ] && ok "$svc: no non-local established connections" || bad "$svc: $EST non-local established connections"
done
exit $FAIL
