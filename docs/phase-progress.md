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

## Phase 4 — Case Management & SOAR (planned)

TheHive 5 + Cassandra + Cortex + n8n. Wazuh alerts (level >= 7) trigger case creation with observable enrichment via Cortex (VirusTotal, AbuseIPDB).

## Phase 5 — Network IDS & Detection Engineering (planned)

pfSense + Suricata in-path. Custom Wazuh rules with MITRE ATT&CK Navigator export.
