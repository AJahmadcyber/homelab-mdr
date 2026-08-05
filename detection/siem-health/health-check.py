#!/usr/bin/env python3
"""
SIEM self-health monitor.

A single malformed rule file takes wazuh-analysisd down entirely - CRITICAL
(1220) - and the container stays "Up" because Docker only watches PID 1. On
2026-08-05 that cost six and a half hours of silent blindness: every rule was
loaded, every regex was correct, and nothing was being evaluated.

Container state is not service state. This checks the services themselves.

Three things happen here:
  1. detect  - which core daemons are down
  2. alert   - write to a log Wazuh reads, so the outage becomes a ticket
  3. recover - restart once, then stop trying and escalate instead

Deliberately does NOT restart in a loop. A rule file that kills analysisd will
kill it again; retrying forever hides the cause and produces a service that
looks alive in samples. One attempt, then the alert stands.
"""
import json, os, subprocess, time

CONTAINER = "single-node-wazuh.manager-1"
OUT = "/var/log/secwatch/siem-health.log"
STATE = "/opt/siem-health/state.json"

# Daemons whose absence means detection has stopped. Others (clusterd, maild,
# csyslogd, dbd, agentlessd) are intentionally unused in this lab.
CRITICAL = ["wazuh-analysisd", "wazuh-remoted", "wazuh-db", "wazuh-logcollector"]


def service_status():
    """Returns {daemon: running_bool} from wazuh-control, not from docker."""
    try:
        r = subprocess.run(
            ["docker", "exec", CONTAINER, "/var/ossec/bin/wazuh-control", "status"],
            capture_output=True, text=True, timeout=60)
    except Exception:
        return None
    out = {}
    for line in r.stdout.splitlines():
        line = line.strip()
        if " is running" in line:
            out[line.split(" is running")[0]] = True
        elif " not running" in line:
            out[line.split(" not running")[0]] = False
    return out or None


def last_rule_error():
    """The CRITICAL line analysisd leaves when a rule file kills it."""
    try:
        r = subprocess.run(
            ["docker", "exec", CONTAINER, "sh", "-c",
             "grep -i 'CRITICAL' /var/ossec/logs/ossec.log | tail -1"],
            capture_output=True, text=True, timeout=30)
        return r.stdout.strip() or None
    except Exception:
        return None


def emit(payload):
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    payload["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    with open(OUT, "a") as f:
        f.write(json.dumps(payload) + "\n")


def main():
    state = {}
    if os.path.exists(STATE):
        try:
            state = json.load(open(STATE))
        except Exception:
            state = {}

    status = service_status()
    if status is None:
        if not state.get("unreachable"):
            emit({"event": "SIEM_UNREACHABLE",
                  "note": "cannot query wazuh-control - the manager container "
                          "may be down or not responding"})
            state["unreachable"] = True
        json.dump(state, open(STATE, "w"))
        return
    state["unreachable"] = False

    down = [d for d in CRITICAL if status.get(d) is False]

    if not down:
        if state.get("degraded"):
            emit({"event": "SIEM_HEALTHY",
                  "note": "all core services running again"})
            state["degraded"] = False
            state["restart_attempted"] = False
        json.dump(state, open(STATE, "w"))
        return

    # Something core is down.
    if not state.get("degraded"):
        err = last_rule_error()
        emit({
            "event": "SIEM_DEGRADED",
            "services_down": down,
            "last_critical": err,
            "note": "core SIEM services are not running - detection has stopped "
                    "while the container still reports Up",
        })
        state["degraded"] = True

    # One recovery attempt, never a loop.
    if not state.get("restart_attempted"):
        state["restart_attempted"] = True
        json.dump(state, open(STATE, "w"))
        try:
            subprocess.run(
                ["docker", "exec", CONTAINER, "/var/ossec/bin/wazuh-control", "restart"],
                capture_output=True, text=True, timeout=180)
        except Exception:
            pass
        time.sleep(25)
        after = service_status() or {}
        still = [d for d in CRITICAL if after.get(d) is False]
        emit({
            "event": "SIEM_RECOVERED" if not still else "SIEM_RECOVERY_FAILED",
            "services_down": still,
            "note": ("automatic restart restored the services"
                     if not still else
                     "automatic restart did not help - manual investigation "
                     "required, check the last CRITICAL rule error"),
        })
        if not still:
            state["degraded"] = False
            state["restart_attempted"] = False

    json.dump(state, open(STATE, "w"))


if __name__ == "__main__":
    main()
