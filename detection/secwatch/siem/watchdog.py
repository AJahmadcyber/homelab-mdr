#!/usr/bin/env python3
"""
Endpoint watchdog - the surviving channel.

Wazuh fires on events that arrive; it cannot fire on one that never came. This
script closes that gap by asking the opposite question every 30 seconds: when
did each agent last speak?

Silence alone is not an incident. A machine that was shut down properly is
silent too. So the last heartbeat carries a marker (shutdown=pending) written
by a Windows shutdown script - which runs only on a graceful stop. An agent
that was killed never reaches that script, so the marker is absent and the
silence becomes an alert.

The decision runs HERE, on the SIEM, not on the endpoint. An attacker holding
the endpoint's kernel cannot suppress a calculation happening on a host they do
not own - the most they can do is stop sending, which is precisely the trigger.

Emits alerts to a log the Wazuh manager reads. Stateless between runs except
for a small JSON file, so nothing accumulates.
"""
import json, os, subprocess, time
from datetime import datetime, timezone

ARCHIVE = "/var/ossec/logs/archives/archives.json"
CONTAINER = "single-node-wazuh.manager-1"
STATE = "/opt/secwatch/state.json"
OUT = "/var/log/secwatch/watchdog.log"

STALE_SECONDS = 90      # 3 missed heartbeats at 30s

# Off-host liveness source. The endpoint can lie about itself once an attacker
# owns its kernel, but it cannot hide traffic from a sensor it does not control.
# DNS is the right channel to read: it is the one protocol that MUST traverse
# the gateway, so pfSense sees it even for same-subnet hosts whose other traffic
# never reaches the firewall (verified: mTLS to 10.10.10.2 is invisible, DNS to
# 10.10.10.1 is fully visible).
DNS_STREAM = "/var/log/dns-analyzer/dns-queries.stream"
AGENT_IPS = {"win-ep": "10.10.10.20"}
NET_LOOKBACK_SECONDS = 180
MONITORED = ["win-ep"]

def read_tail(n=400):
    """Pull recent archive lines from inside the manager container."""
    try:
        r = subprocess.run(
            ["docker", "exec", CONTAINER, "sh", "-c",
             f"grep -hE 'SECWATCH |SECWATCH-SHUTDOWN' {ARCHIVE} 2>/dev/null | tail -{n}"],
            capture_output=True, text=True, timeout=30)
        return r.stdout.splitlines()
    except Exception:
        return []

def parse(lines):
    """Latest heartbeat per agent, with its parsed fields."""
    latest = {}
    shutdowns = {}
    for ln in lines:
        try:
            d = json.loads(ln)
        except Exception:
            continue
        log = d.get("full_log", "")
        agent = (d.get("agent") or {}).get("name")
        if not agent:
            continue
        if "SECWATCH-SHUTDOWN" in log:
            # A graceful-shutdown marker. Record when it arrived so a later
            # silence can be attributed to a planned stop rather than a kill.
            shutdowns[agent] = d.get("timestamp", "")
            continue
        # Only accept the agent's own command output. PowerShell Script Block
        # Logging (4104) records the TEXT of this heartbeat script, which contains
        # the literal line "SECWATCH seq=$seq" - a plain substring match reads
        # those as heartbeats. Not cosmetic: script-block noise makes a killed
        # agent look alive, silencing the exact detection this watchdog exists
        # for, and it produced a false SECWATCH_KILLED at 72455s.
        if not log.startswith("ossec: output: 'secwatch'"):
            continue
        if "SECWATCH " not in log:
            continue
        fields = {}
        for tok in log.split():
            if "=" in tok:
                k, _, v = tok.partition("=")
                fields[k] = v
        ts = d.get("timestamp", "")
        latest[agent] = {"ts": ts, "fields": fields}
    for agent, ts in shutdowns.items():
        if agent in latest:
            latest[agent]["shutdown_ts"] = ts
    return latest

def to_epoch(ts):
    """Wazuh emits +0000 (no colon); fromisoformat needs +00:00 before 3.11."""
    if not ts:
        return 0
    t = ts.replace("Z", "+00:00")
    if len(t) > 5 and (t[-5] in "+-") and ":" not in t[-5:]:
        t = t[:-2] + ":" + t[-2:]
    try:
        return datetime.fromisoformat(t).timestamp()
    except Exception:
        return 0

def network_alive(ip, since_epoch):
    """Did this host generate DNS traffic after `since_epoch`?

    Reads the tail of the DNS stream rather than the whole file - the question
    is only ever about the last few minutes, and the stream grows to tens of MB.
    Returns (alive, last_query_name, seconds_ago) or (False, None, None).
    """
    try:
        out = subprocess.run(["tail", "-n", "400", DNS_STREAM],
                             capture_output=True, text=True, timeout=15).stdout
    except Exception:
        return (False, None, None)

    newest = None
    for ln in out.splitlines():
        if f'"src_ip":"{ip}"' not in ln:
            continue
        try:
            q = json.loads(ln)
        except Exception:
            continue
        ts = to_epoch(q.get("timestamp", ""))
        if ts > since_epoch and (newest is None or ts > newest[0]):
            newest = (ts, (q.get("dns") or {}).get("rrname"))

    if newest:
        return (True, newest[1], int(time.time() - newest[0]))
    return (False, None, None)


def emit(payload):
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "a") as f:
        f.write(json.dumps(payload) + "\n")

def main():
    now = time.time()
    latest = parse(read_tail())
    state = {}
    if os.path.exists(STATE):
        try:
            state = json.load(open(STATE))
        except Exception:
            state = {}

    for agent in MONITORED:
        hb = latest.get(agent)
        if not hb:
            continue

        age = now - to_epoch(hb["ts"])
        # Graceful when a shutdown marker arrived no earlier than the last
        # heartbeat: the endpoint announced its own stop before going quiet.
        sd = to_epoch(hb.get("shutdown_ts", ""))
        graceful = sd > 0 and sd >= to_epoch(hb["ts"]) - 60
        alerted = state.get(agent, {}).get("alerted", False)

        if age > STALE_SECONDS and not graceful and not alerted:
            # Silence alone is ambiguous: a powered-off machine is silent too.
            # The discriminator is whether the NETWORK still sees the host. Quiet
            # on both channels = switched off. Quiet only on the endpoint channel
            # while still generating traffic = something silenced the agent.
            ip = AGENT_IPS.get(agent)
            alive, last_q, q_ago = (False, None, None)
            if ip:
                alive, last_q, q_ago = network_alive(
                    ip, now - max(NET_LOOKBACK_SECONDS, age))

            payload = {
                "event": "SECWATCH_KILLED" if alive else "SECWATCH_SILENT",
                "agent": agent,
                "last_seen": hb["ts"],
                "silent_seconds": int(age),
                "last_seq": hb["fields"].get("seq"),
                "graceful_shutdown": False,
                "network_alive": alive,
            }
            if alive:
                payload["last_dns_query"] = last_q
                payload["last_dns_seconds_ago"] = q_ago
                payload["note"] = (
                    "endpoint telemetry stopped while the host is still generating "
                    "network traffic - the agent was silenced, the machine is running")
            else:
                payload["note"] = (
                    "heartbeat stopped and no network activity observed - "
                    "consistent with the host being powered off, but unconfirmed")
            emit(payload)
            state.setdefault(agent, {})["alerted"] = True

        elif age > STALE_SECONDS and graceful and not alerted:
            emit({
                "event": "SECWATCH_GRACEFUL",
                "agent": agent,
                "last_seen": hb["ts"],
                "note": "silence expected - endpoint reported a graceful shutdown",
            })
            state.setdefault(agent, {})["alerted"] = True

        elif age <= STALE_SECONDS and alerted:
            emit({
                "event": "SECWATCH_RECOVERED",
                "agent": agent,
                "last_seq": hb["fields"].get("seq"),
            })
            state[agent]["alerted"] = False

    json.dump(state, open(STATE, "w"))

if __name__ == "__main__":
    main()
