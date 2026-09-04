#!/usr/bin/env python3
"""
SOAR host-isolation blocker with built-in safety controls.
Called by n8n. Adds an IP to the pfSense soar_blocklist alias — but ONLY
after passing the infrastructure allowlist and circuit-breaker checks.

Usage: soar-block.py <src_ip>
Env:   PF_API_KEY (required)
"""
import sys, os, json, time, fcntl, contextlib, ipaddress, urllib3, requests
from datetime import datetime, timedelta

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---- CONFIG ----
PF_HOST      = "10.10.10.1"
ALIAS_ID     = 7                     # soar_blocklist
API_KEY      = os.environ.get("PF_API_KEY", "")
STATE_FILE   = "/opt/soar/block-state.json"

# --- SAFETY CONTROL 1: infrastructure allowlist (NEVER block these) ---
ALLOWLIST = {
    "10.10.10.1":   "pfSense gateway",
    "10.10.10.10":  "siem (SIEM + n8n)",
    "10.10.10.2":   "ThinkPad host",
}
# Networks that are never blocked, checked alongside the host allowlist above.
# Deliberately empty: the obvious candidate, 10.10.10.0/24, is the network the
# monitored endpoint sits on, and protecting it wholesale would refuse every
# block this path is built to perform. The check is wired up so a future
# range - a server segment, a management VLAN - is one entry away.
PROTECTED_NETS = []

# --- SAFETY CONTROL 2: circuit breaker ---
CB_MAX_BLOCKS = 5        # max blocks
CB_WINDOW_MIN = 10       # within this many minutes

def normalize(addr):
    """Parse an address into a comparable form.

    IPv4-mapped IPv6 is unwrapped to its IPv4 form. Python treats
    IPv6Address('::ffff:10.10.10.1') and IPv4Address('10.10.10.1') as unequal,
    so without this an allowlisted address written in its mapped form - in
    either dotted-quad or hex notation - compares as a different host and
    passes the one gate built to protect it.
    """
    obj = ipaddress.ip_address(addr)
    if isinstance(obj, ipaddress.IPv6Address) and obj.ipv4_mapped:
        obj = obj.ipv4_mapped
    return obj


def _parseable(addr):
    """True if addr is a bare IP. Alias entries can also be CIDR ranges or
    hostnames, which are not comparable to a single address and are skipped."""
    try:
        normalize(addr)
        return True
    except ValueError:
        return False


def log(msg):
    print(f"[{datetime.utcnow().isoformat()}] {msg}")

LOCK_FILE = STATE_FILE + ".lock"


@contextlib.contextmanager
def state_lock():
    """Serialise the whole read-decide-write path across concurrent runs.

    n8n can invoke this script several times at once during an alert burst -
    exactly when the circuit breaker matters most. Without a lock, two runs
    read the same block count, both find room under the limit, and both write
    it back: the breaker permits more blocks than its ceiling allows.

    The same window covers the alias read-modify-write. A PATCH replaces the
    whole address array rather than appending to it, so two runs interleaving
    there would silently drop one of the two blocks.

    A separate lock file is used rather than the state file itself, so the
    lock survives the state file being rewritten.
    """
    with open(LOCK_FILE, "w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {"blocks": []}   # list of ISO timestamps

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

def check_circuit_breaker(state):
    """Return (ok, count) — ok=False if too many recent blocks."""
    now = datetime.utcnow()
    window_start = now - timedelta(minutes=CB_WINDOW_MIN)
    recent = [t for t in state["blocks"]
              if datetime.fromisoformat(t) > window_start]
    state["blocks"] = recent  # prune old
    return (len(recent) < CB_MAX_BLOCKS, len(recent))

def api_get_alias():
    r = requests.get(f"https://{PF_HOST}/api/v2/firewall/aliases",
                     headers={"X-API-Key": API_KEY}, verify=False, timeout=10)
    r.raise_for_status()
    for a in r.json()["data"]:
        if a["id"] == ALIAS_ID:
            return a
    return None

def api_add_ip(current, ip):
    new_addr = list(current.get("address", []))
    if ip not in new_addr:
        new_addr.append(ip)
    r = requests.patch(f"https://{PF_HOST}/api/v2/firewall/alias",
                       headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
                       json={"id": ALIAS_ID, "address": new_addr}, verify=False, timeout=10)
    r.raise_for_status()
    return r.json()

def api_apply():
    """Apply the pending firewall change.

    The response is checked rather than discarded. Without this the script
    reports BLOCKED whether or not pfSense accepted the change, and the
    ticket would claim a containment that never happened - the one failure
    mode this whole path exists to avoid.
    """
    r = requests.post(f"https://{PF_HOST}/api/v2/firewall/apply",
                      headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
                      json={}, verify=False, timeout=15)
    r.raise_for_status()

def main():
    if len(sys.argv) < 2:
        log("ERROR: no IP provided"); sys.exit(2)
    ip = sys.argv[1].strip()

    if not API_KEY:
        log("ERROR: PF_API_KEY not set"); sys.exit(2)

    # validate IP format
    try:
        ip_obj = normalize(ip)
    except ValueError:
        log(f"ERROR: invalid IP '{ip}'"); sys.exit(2)

    # ---- SAFETY 1: allowlist ----
    # Compared as normalised addresses, not strings, so alternate spellings of a
    # protected address cannot slip past the gate.
    protected = None
    for allowed, label in ALLOWLIST.items():
        if ip_obj == normalize(allowed):
            protected = label
            break
    if protected is None:
        for net in PROTECTED_NETS:
            if ip_obj in net:
                protected = f"inside protected network {net}"
                break

    if protected is not None:
        log(f"BLOCKED-BY-SAFETY: {ip} is protected infra ({protected}) — REFUSING to block")
        print(json.dumps({"action": "refused", "reason": "allowlist", "ip": ip, "detail": protected}))
        sys.exit(0)

    # Everything from here to the final save runs under one lock: the breaker
    # decision, the alias read-modify-write, and the record of the block.
    with state_lock():
        state = load_state()

        # ---- SAFETY 2: circuit breaker ----
        ok, count = check_circuit_breaker(state)
        if not ok:
            log(f"CIRCUIT-BREAKER TRIPPED: {count} blocks in last {CB_WINDOW_MIN}min (max {CB_MAX_BLOCKS}) — REFUSING")
            save_state(state)
            print(json.dumps({"action": "refused", "reason": "circuit_breaker", "ip": ip, "recent_blocks": count}))
            sys.exit(0)

        # ---- passed safety → block ----
        alias = api_get_alias()
        if alias is None:
            log("ERROR: soar_blocklist alias not found"); sys.exit(3)

        # Normalised for the same reason as the allowlist: a differently
        # spelled entry already in the alias would read as absent and be
        # appended a second time.
        already = any(ip_obj == normalize(a)
                      for a in alias.get("address", [])
                      if _parseable(a))
        if already:
            log(f"already blocked: {ip}")
            print(json.dumps({"action": "already_blocked", "ip": ip}))
            sys.exit(0)

        try:
            api_add_ip(alias, ip)
            api_apply()
        except requests.RequestException as exc:
            log(f"BLOCK FAILED: pfSense rejected the change for {ip} ({type(exc).__name__})")
            print(json.dumps({"action": "block_failed", "ip": ip,
                              "reason": type(exc).__name__}))
            sys.exit(4)

        # Recorded only on success: a failed block must not consume breaker budget.
        state["blocks"].append(datetime.utcnow().isoformat())
        save_state(state)

    log(f"BLOCKED: {ip} added to soar_blocklist (recent blocks: {count+1})")
    print(json.dumps({"action": "blocked", "ip": ip, "recent_blocks": count+1}))

if __name__ == "__main__":
    main()
