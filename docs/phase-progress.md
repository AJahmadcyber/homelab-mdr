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

## Phase 3 — Windows Endpoint Telemetry (in progress)

**Goal:** Full detection-grade telemetry from a Windows endpoint.

### Completed
- Windows 10 VM (2 GB RAM, 60 GB disk, host-only + NAT, static IP 192.168.56.20)
- Wazuh agent 4.9.0 installed via MSI with parameterized enrollment
- Agent registered, ID 001, status Active

### In progress
- Sysmon + sysmon-modular (consolidated config)
- PowerShell Script Block Logging (Event ID 4104)
- ASR rules: LSASS credential theft, Office child processes, executable email/web content
- Defender Operational log channel

### Coverage when complete
- T1003.001 (LSASS) via Sysmon Event 10 + ASR
- T1059.001 (Obfuscated PowerShell) via Event 4104
- T1218 (Living-off-the-land) via Sysmon process creation
- T1486 (Ransomware) via Sysmon Event 23 + FIM

## Phase 4 — Case Management & SOAR (planned)

TheHive 5 + Cassandra + Cortex + n8n. Wazuh alerts (level >= 7) trigger case creation with observable enrichment via Cortex (VirusTotal, AbuseIPDB).

## Phase 5 — Network IDS & Detection Engineering (planned)

pfSense + Suricata in-path. Custom Wazuh rules with MITRE ATT&CK Navigator export.
