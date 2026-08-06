# SecWatch - the surviving channel (Phase 7, L4)

Detects that security tooling was killed, and tells that apart from a machine
being shut down normally.

## Why this exists

Every other rule in this lab watches what an attacker *does*: a driver loading,
a registry key being written, a scan crossing the firewall. Those rules key on
the method, and the method keeps changing - a new BYOVD variant, a fresh kernel
bug, a technique nobody has published yet.

SecWatch watches something that does not change: whether the defender is still
talking.

## The problem it solves

A SIEM fires on events that arrive. It cannot fire on an event that never came.
So the endpoint states its own health every 30 seconds, and absence becomes
measurable:

    SECWATCH seq=42 uptime=3780 shutdown=no MsMpEng=UP Sysmon64=UP wazuh-agent=UP

Silence alone is not an incident - a machine that was powered off is silent too.
So a graceful shutdown announces itself first:

    SECWATCH-SHUTDOWN seq=42 reason=graceful host=WIN-EP

A killed agent never sends that line. The absence of the announcement is what
separates a planned stop from a kill.

## Where the decision happens

On the SIEM, not on the endpoint. An attacker holding the endpoint's kernel
cannot suppress a calculation running on a host they do not own. Their only
move is to stop sending - which is exactly the trigger.

## Components

**Endpoint** (`agent/`)

| File | Role |
|---|---|
| `secwatch.ps1` | Heartbeat, every 30s via the agent's `full_command` localfile |
| `secwatch-shutdown.ps1` | Graceful-shutdown announcement, fired by a Scheduled Task on System event 1074 |

**SIEM** (`siem/`)

| File | Role |
|---|---|
| `watchdog.py` | Reads the last heartbeat per agent, decides silent vs graceful |
| `secwatch.service` / `secwatch.timer` | Runs the watchdog every 30s |

**Rules**: `detection/wazuh-rules/9990-secwatch.xml` (100359-100365)

| Rule | Condition | Level |
|---|---|---|
| 100360 | A heartbeat arrives reporting `=DOWN` | 12 |
| 100363 | Heartbeats stopped, no shutdown announcement | 12 |
| 100364 | Heartbeats stopped after an announcement | 3 |
| 100365 | Heartbeats resumed | 3 |

## Dependency — read this before changing archive settings

The watchdog reads heartbeats from `/var/ossec/logs/archives/archives.json`, so
**`<logall_json>` must stay `yes`**. It was turned off during a disk-space
cleanup in the same session this layer was built, which silently cut the
watchdog's only data source: heartbeats kept arriving, the archive stopped
recording them, and the last entry it could see aged until it raised a false
`SECWATCH_KILLED` at 72,577 seconds.

Measured cost of keeping it on: roughly 225 MB/day raw, rotated and compressed
daily. Against 75 GB free that is years of headroom — the cleanup traded a
working detection layer for a saving that did not matter.

## Setup notes that cost time

- **The agent holds `events.log` open.** `Add-Content` fails with a sharing
  violation; the shutdown script opens the file with `FileShare::ReadWrite`.
  This only breaks during a real shutdown, where nobody is watching.
- **`log_format syslog`, not the heartbeat.** The announcement is tailed and
  ships within seconds. Routing it through the 30s heartbeat would lose the race
  against a fast shutdown.
- **Scheduled Task, not a GPO shutdown script.** The GPO path was configured
  correctly and still never ran - `gpt.ini` version tracking makes it silently
  skippable. The task on event 1074 is explicit and verifiable.
- **`Restart-Service` on the agent is unreliable.** It failed and succeeded in
  the same session; `sc.exe stop` / `sc.exe start` is the dependable path. Always
  verify a config change actually took effect rather than trusting the exit code.
- **A stale shutdown marker would mask a kill.** The heartbeat clears any marker
  written before the current boot.
- **Filter heartbeats by source, not by substring.** PowerShell Script Block
  Logging (4104) records the *text* of the heartbeat script, which contains the
  literal line `SECWATCH seq=$seq`. A plain `"SECWATCH " in log` match reads
  those as heartbeats — so a killed agent looks alive purely from PowerShell
  noise, silencing the one detection this layer exists for. The parser now
  requires the line to start with `ossec: output: 'secwatch'`, which only the
  agent's own command output produces. The symptom that exposed it was
  `last_seq: "$seq"` appearing literally in an alert.
- **systemd timer, not `Restart=always`.** A crash-looping service reports
  `active`. A timer running a `oneshot` records each run's success or failure.

## Verified behaviour

| Scenario | How it was produced | Result |
|---|---|---|
| Agent killed | `Stop-Service WazuhSvc -Force` | `SECWATCH_SILENT` -> rule 100363, level 12 |
| Graceful shutdown | `Stop-Computer -Force`, off ~3 min | `SECWATCH_GRACEFUL` -> rule 100364, level 3 |
| Service restored | `Start-Service WazuhSvc` | `SECWATCH_RECOVERED` -> rule 100365, level 3 |

## Limits

An attacker with kernel control **can forge the heartbeat** and keep reporting
`UP` while owning the host. Nothing an endpoint says about itself survives an
attacker who owns that endpoint.

That is why this layer is paired with an off-host liveness source: Suricata runs
on the firewall, not the endpoint. The host can lie about itself, but it cannot
hide traffic from a sensor it does not control. The strongest signal is not the
heartbeat - it is the contradiction between what the host claims and what the
network sees.

Forging also is not free. It requires noticing the heartbeat, matching its
format, timing and identity, and doing all of it before the first missed
interval. Seconds of delay are enough: one missing heartbeat reaches the SIEM
and cannot be recalled.

The three watched processes are the ones installed here. Coverage is not claimed
for products that are absent from this lab.
