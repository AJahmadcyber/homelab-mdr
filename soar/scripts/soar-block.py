#!/usr/bin/env python3
"""
SOAR host-isolation blocker with built-in safety controls.
Called by n8n. Adds an IP to the pfSense soar_blocklist alias — but ONLY
after passing the infrastructure allowlist and circuit-breaker checks.

Usage: soar-block.py <src_ip>
Env:   PF_API_KEY (required)
"""
import sys, os, json, time, ipaddress, urllib3, requests
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
# Also never block the entire lab subnet's critical infra range if desired:
PROTECTED_NETS = [ipaddress.ip_network("10.10.10.0/24")]  # warn-only, see logic

# --- SAFETY CONTROL 2: circuit breaker ---
CB_MAX_BLOCKS = 5        # max blocks
CB_WINDOW_MIN = 10       # within this many minutes

def log(msg):
    print(f"[{datetime.utcnow().isoformat()}] {msg}")

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
    return r.json()

def api_apply():
    requests.post(f"https://{PF_HOST}/api/v2/firewall/apply",
                  headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
                  json={}, verify=False, timeout=15)

def main():
    if len(sys.argv) < 2:
        log("ERROR: no IP provided"); sys.exit(2)
    ip = sys.argv[1].strip()

    if not API_KEY:
        log("ERROR: PF_API_KEY not set"); sys.exit(2)

    # validate IP format
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        log(f"ERROR: invalid IP '{ip}'"); sys.exit(2)

    # ---- SAFETY 1: allowlist ----
    if ip in ALLOWLIST:
        log(f"BLOCKED-BY-SAFETY: {ip} is protected infra ({ALLOWLIST[ip]}) — REFUSING to block")
        print(json.dumps({"action": "refused", "reason": "allowlist", "ip": ip, "detail": ALLOWLIST[ip]}))
        sys.exit(0)

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

    if ip in alias.get("address", []):
        log(f"already blocked: {ip}")
        print(json.dumps({"action": "already_blocked", "ip": ip}))
        sys.exit(0)

    resp = api_add_ip(alias, ip)
    api_apply()

    # record for circuit breaker
    state["blocks"].append(datetime.utcnow().isoformat())
    save_state(state)

    log(f"BLOCKED: {ip} added to soar_blocklist (recent blocks: {count+1})")
    print(json.dumps({"action": "blocked", "ip": ip, "recent_blocks": count+1}))

if __name__ == "__main__":
    main()
