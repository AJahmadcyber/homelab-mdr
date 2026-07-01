# Phase Progress Log

Chronological build log of the lab. Each phase produces a working, verified milestone.

## Phase 1 — Foundation

**Goal:** Functional SIEM with Wazuh stack on isolated VM.

- Ubuntu Server 22.04 on VirtualBox (9 GB RAM, 120 GB disk, host-only + NAT)
- Docker CE 29.5.3 + Compose v2
- Wazuh 4.9.0 single-node deployment (Manager + Indexer + Dashboard)
- `vm.max_map_count=262144` set for OpenSearch
- Pre-allocated disk for I/O performance

**Verified:** 3 healthy containers, Dashboard reachable at `https://192.168.56.10`.

## Phase 2 — Hardening

**Goal:** Lock down the SIEM host and tune storage growth.

- UFW default-deny inbound, explicit allow on management interface only
- fail2ban with sshd jail (5 retries, 1h ban)
- SSH hardening: no root login, MaxAuthTries 3, ClientAlive timeouts
- DOCKER-USER iptables rule on NAT interface (closes Docker UFW bypass)
- ISM policy: wazuh-alerts-* and wazuh-archives-* retain 90 days then delete
- number_of_replicas: 0 on all wazuh-* indices (single-node optimization)

**Verified:** Host scan from external interface returns no open ports. Disk growth contained.

## Phase 3 — Windows Endpoint Telemetry

**Goal:** Full detection-grade telemetry from a Windows endpoint, end-to-end into Wazuh.

### Completed
- Windows 10 VM (2 GB RAM, 60 GB disk, host-only + NAT, static IP 192.168.56.20)
- Wazuh agent 4.9.0 installed via MSI with parameterized enrollment
- Agent registered, ID 001, status Active
- Sysmon 15.21 installed with sysmon-modular consolidated config (Olaf Hartong)
- PowerShell Script Block Logging enabled (Event ID 4104)
- PowerShell Module Logging enabled (Event ID 4103)
- Windows Defender Operational log channel ingested
- 3 ASR rules enforced in block mode:
  - `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` — Block credential stealing from LSASS (T1003.001)
  - `d4f940ab-401b-4efc-aadc-ad5f3c50688a` — Block Office child processes (T1566.001)
  - `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` — Block executable content from email/web (T1566)
- Centralized agent config via `/var/ossec/etc/shared/default/agent.conf`

### Verified in Dashboard
- Sysmon events (process create, file create, pipe create, network connect) — 100+ events
- PowerShell 4104 events with `scriptBlockText` field populated
- Defender 1150 platform health events

### Coverage achieved
- T1003.001 (LSASS) — Sysmon Event 10 + ASR rule (preventive)
- T1059.001 (Obfuscated PowerShell) — Event 4104 with de-obfuscated content
- T1218 (Living-off-the-land) — Sysmon process creation visibility
- T1486 (Ransomware) — Sysmon Event 11/23 + FIM (rule logic in Phase 5)
- T1566 / T1566.001 (Phishing payload execution) — ASR rules (preventive)

### Known issues
- Wazuh agent 4.9.0 `syscollector.dll` crashes intermittently (vendor bug, auto-recovers, non-blocking)

## Phase 4 — Network Re-Architecture (pfSense in-path)

**Goal:** Introduce a stateful perimeter firewall between the lab VMs and the outside world, matching a realistic SOC network topology and unlocking future Suricata IDS + SOAR auto-block workflows.

### Topology delivered

- Two host-only networks on the hypervisor:
  - `vboxnet0` (192.168.56.0/24) — unused management legacy.
  - `vboxnet1` (10.10.10.0/24) — new isolated LAN behind pfSense.
- pfSense 2.7.2 VM with two interfaces:
  - WAN (em0) — attached to VirtualBox NAT (10.0.2.15) for outbound internet.
  - LAN (em1) — 10.10.10.1/24, gateway for the SOC lab subnet.
- VMs migrated onto the LAN behind pfSense:
  - siem — 10.10.10.10 (Wazuh Manager + Indexer + Dashboard).
  - win-ep — 10.10.10.20 (Windows endpoint, Wazuh agent).
- ThinkPad host reachable on the LAN at 10.10.10.2 for Dashboard access.

### Firewall rules deployed (LAN interface)

Aliases created for readability and future reuse:

- `siem_host` (10.10.10.10)
- `win_ep` (10.10.10.20)
- `thinkpad_host` (10.10.10.2)
- `wazuh_ports` (1514, 1515, 55000)

Explicit allow rules:

1. `win_ep` → `siem_host` on `wazuh_ports` (agent enrollment + comms).
2. `thinkpad_host` → `siem_host` on 443 (Wazuh Dashboard HTTPS).
3. Default `LAN → any` allow retained for outbound internet.
4. Default deny on WAN inbound retained (system default).

Logging enabled on both explicit rules for future audit and Suricata correlation.

### Key lessons

- Rule load order in pfSense depends on filename prefix; custom firewall rules that reference default gateways must load after the default policy is established.
- Static WAN gateway config remained after switching to NAT-backed WAN; had to `route delete` the stale gateway and force `dhclient` renewal to obtain the correct default route.
- Windows endpoints migrated onto a new subnet default to the Public network profile — ICMP and file/print discovery blocked. Changed to Private for lab connectivity.
- Wazuh agent 4.9 remembers its manager address in `ossec.conf`; a `.NET WriteAllLines` write with UTF-8 no-BOM was required to update it cleanly.

### Verified end-to-end

- Wazuh agent on win-ep reconnected automatically to Manager after IP change.
- Dashboard reachable from ThinkPad at https://10.10.10.10 through the LAN.
- Alert pipeline confirmed: Sysmon + PowerShell 4104 + Defender events flowing from win-ep through pfSense to the Manager (343 alerts logged during Phase 4 validation window).
- Custom rules 100100-100102 from Phase 3 continue to fire on obfuscated PowerShell test patterns.

### Evidence

Screenshots documenting Phase 4 completion are in `docs/evidence/phase4/`:

- `01a-pfsense-dashboard-top.png` — pfSense 2.7.2 Dashboard: System Information + Interfaces (WAN 10.0.2.15, LAN 10.10.10.1, both up)
- `01b-pfsense-dashboard-bottom.png` — Resource utilization: uptime, CPU, memory, disk
- `02-firewall-rules-lan.png` — LAN interface rules: Anti-Lockout + 2 explicit allow rules (Wazuh comms, Dashboard) + defaults, with logging enabled on custom rules
- `03a-firewall-aliases-ip.png` — Host aliases (siem_host, thinkpad_host, win_ep)
- `03b-firewall-aliases-ports.png` — Port alias (wazuh_ports: 1514, 1515, 55000)
- `04-wazuh-dashboard-overview.png` — Wazuh Overview after migration: 1 agent Active, 343 alerts in last 24h
- `05-discover-winep-sysmon.png` — Discover view: 140 Sysmon events in 30 min from `agent.ip: 10.10.10.20`, confirming end-to-end pipeline through the firewall

### Snapshots

- `pfsense` — phase4-baseline (fresh install + WAN NAT + LAN 10.10.10.1/24)
- `siem` — phase4-migrated-to-lan (Wazuh stack running on 10.10.10.10)
- `win-ep` — phase4-migrated-to-lan (Sysmon + agent Active on 10.10.10.20)

## Phase 4.5 — SIEM Self-Monitoring

**Goal:** Give the SIEM host visibility into itself. In real SOCs the SIEM is a high-value target — attackers often try to disable logging or tamper with the Manager before broader lateral movement. A blind SIEM cannot report its own compromise.

### What was deployed

- Wazuh agent 4.9.0 installed on siem VM (agent ID 002, name `siem-self`), self-enrolled to the local Manager on 10.10.10.10.
- `auditd` installed with a custom ruleset at `/etc/audit/rules.d/siem-monitoring.rules` covering:
  - Docker socket + daemon binaries + config directory (T1611, T1610)
  - Wazuh config file + agent binaries (T1562.001)
  - SSH server configuration (T1098)
  - `/etc/sudoers` and drop-in directory (T1548.003)
  - `/etc/passwd`, `/etc/shadow`, `/etc/group` (T1136, T1098)
  - Cron and systemd unit files (T1053.003, T1543.002)
  - UFW and iptables config (T1562.004)
  - `execve` syscalls for netcat, wget, curl (download and post-exploitation tools)
- Wazuh agent extended with two additional `localfile` blocks:
  - `<log_format>audit</log_format>` on `/var/log/audit/audit.log`
  - `<log_format>journald</log_format>` filtered on `_SYSTEMD_UNIT=docker.service`
- Custom Wazuh rules `100200-100205` deployed at `/var/ossec/etc/rules/9998-siem-self-monitoring.xml`, each keyed to an audit rule and mapped to a MITRE technique.

### Custom rules

| Rule ID | Level | audit.key | MITRE technique |
| --- | --- | --- | --- |
| 100200 | 7 | wazuh_config_change | T1562.001 Disable or Modify Tools |
| 100201 | 10 | docker_socket_access | T1611 Escape to Host / T1610 Deploy Container |
| 100202 | 9 | sudoers_change | T1548.003 Sudo and Sudo Caching |
| 100203 | 9 | credential_change | T1098 Account Manipulation |
| 100204 | 8 | systemd_change | T1543.002 Systemd Service |
| 100205 | 8 | firewall_change | T1562.004 Disable or Modify System Firewall |

Filename prefix `9998-` chosen so the file loads after Wazuh's default `0365-auditd_rules.xml`, so the `if_sid` reference to the base `80700` decoder is resolvable at load time.

### Key lessons

- The Wazuh service user on Ubuntu is `wazuh` and is not in the `adm` group by default; without `usermod -aG adm wazuh` the agent silently fails to read `/var/log/audit/audit.log` and only journald ingestion appears to work.
- A stale second `wazuh-logcollector` process can hang from an earlier `apt install`; if audit ingestion "should" work but nothing arrives, kill leftover Wazuh processes with `pkill -9 -f wazuh-` before restarting the agent.
- After adding custom rules on the Manager, a container restart via `docker compose restart` is more reliable than `/var/ossec/bin/wazuh-control restart` — the latter occasionally leaves daemons in a half-stopped state where `wazuh-analysisd` never comes back up.

### Verified end-to-end

- `agent_control -lc` shows both agents Active: 001 (win-ep) and 002 (siem-self).
- Test: `sudo touch /var/ossec/etc/ossec.conf` → auditd logs `key=wazuh_config_change` → Wazuh Manager fires rule 100200 (level 7, T1562.001) → alert visible in Discover with full auditd metadata (auid, uid, exe, command, cwd).
- MITRE ATT&CK dashboard now shows Defense Evasion / Privilege Escalation / Persistence coverage across both agents.

### Evidence

Screenshots documenting Phase 4.5 completion are in `docs/evidence/phase4.5/`:

- `06-siem-self-audit-rule-100200.png` — Discover: alert from siem-self, rule 100200, T1562.001, full auditd event data
- `07-wazuh-agents-two-active.png` — Endpoints Summary: 2 agents Active (win-ep on Windows 10, siem-self on Ubuntu 22.04.5 LTS)
- `08-mitre-attack-coverage.png` — MITRE ATT&CK dashboard showing tactic coverage: Defense Evasion, Privilege Escalation, Persistence, Execution, Initial Access

### Snapshots

- `siem` — phase4.5-self-monitoring-complete (Wazuh agent 002 running, auditd rules loaded, custom rules 100200-100205 firing)

## Phase 5 — Suricata IDS Integration (planned)

Suricata deployed on pfSense in inline or IPS mode. Alerts forwarded via syslog to the Wazuh Manager and normalized through custom decoders. Focus areas: network-level detection for lateral movement (T1021), port scanning (T1046), and C2 beaconing patterns.

## Phase 6 — Case Management and SOAR (planned)

TheHive 5 + Cassandra + Cortex + n8n. Wazuh alerts of level 7 or higher trigger case creation with observable enrichment through Cortex analyzers (VirusTotal, AbuseIPDB, MISP). n8n workflows implement automated response actions, including pfSense API-driven auto-block for high-confidence indicators.

## Phase 7 — GentleKiller Ransomware Test Case (planned)

Full-stack detection-and-response exercise against a modern ransomware profile. Threat intelligence research, MITRE ATT&CK mapping (T1486, T1490, T1489 and related), simulated behavior on win-ep, and end-to-end validation across Sysmon telemetry, Suricata network signatures, Wazuh custom rules, TheHive case handling, and n8n auto-block workflows. Deliberately scheduled last so it exercises the complete stack.
