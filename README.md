# Open MDR Home Lab

> An open-source Managed Detection & Response stack built as a personal home lab — Wazuh SIEM, n8n SOAR, pfSense + Suricata integration, behavioural detection mapped to MITRE ATT&CK, and automated bilingual alerting.

![Architecture](docs/architecture.svg)

---

## About this project

A self-built SOC home lab demonstrating end-to-end detection engineering using open-source tools: log collection, behavioural analysis, MITRE ATT&CK mapping, case management, automated enrichment, and SOAR-driven response. Built as part of professional development in cybersecurity operations.

Everything runs locally on a single hypervisor host. All attack simulations target only lab VMs you control.

---

## Stack

| Layer | Tool | Role |
| --- | --- | --- |
| SIEM | Wazuh 4.9 (Manager + Indexer + Dashboard) | Log aggregation, correlation, FIM, vulnerability scanning |
| Search / index | OpenSearch (Wazuh Indexer) | Indexed alert and event storage |
| Windows telemetry | Sysmon (sysmon-modular) + Wazuh agent + ASR rules | Process, network, file, registry, DNS, LSASS access |
| Case management | TheHive 5 + Cassandra | Alert to Case lifecycle |
| Threat enrichment | Cortex + analyzers (VirusTotal, AbuseIPDB) + custom analyzer | IOC enrichment |
| SOAR | n8n | Alert routing, auto-response orchestration |
| Network IDS / firewall | pfSense + Suricata | L3/L4 detection, automated blocking via API |
| Detection rules | Wazuh + Sigma + YARA | Custom + community |

---

## Build status

| Phase | Component | Status |
| --- | --- | --- |
| 1 | siem VM + Ubuntu 22.04 base | ✅ Done |
| 1 | Docker + Wazuh stack (Manager + Indexer + Dashboard) | ✅ Done |
| 2 | Host hardening (UFW, fail2ban, SSH, DOCKER-USER iptables) | ✅ Done |
| 2 | ISM retention (90d hot → delete) + replica tuning | ✅ Done |
| 3 | Windows endpoint VM + Wazuh agent enrollment | ✅ Done |
| 3 | Sysmon + sysmon-modular config | ✅ Done |
| 3 | PowerShell Script Block Logging (4104) | ✅ Done |
| 3 | ASR rules (LSASS, Office, web/email) | ✅ Done |
| 3 | Defender Operational log ingestion | ✅ Done |
| 4 | TheHive 5 + Cassandra + Cortex + n8n | ⏳ Planned |
| 5 | pfSense + Suricata + custom detection rules | ⏳ Planned |

Current state: **1 Windows endpoint actively reporting to Wazuh Manager**. Agent ID 001, status Active.

---

## Detection coverage

Every rule maps to a MITRE ATT&CK technique.

| Threat | Detection method | MITRE technique |
| --- | --- | --- |
| Ransomware | FIM mass-encryption + entropy spike + known extensions + Sysmon ID 23 | T1486 |
| Brute force (RDP / SSH) | Auth-failure correlation (4625 / sshd) | T1110 |
| Credential dumping (LSASS) | Sysmon ID 10 + ASR rule | T1003.001 |
| Obfuscated PowerShell | Script Block Logging (Event 4104) | T1059.001 |
| Living-off-the-land | certutil / wmic / mshta abuse | T1218 |
| Persistence | Scheduled tasks (4698), run keys, cron | T1053 / T1547 |
| Lateral movement | Internal SMB / PsExec patterns | T1021 |
| Privilege escalation | sudo misuse, token abuse | T1068 |
| Data exfiltration | Large outbound transfers | T1041 |
| Vulnerability exposure | Wazuh vulnerability detector (NVD feed) | - |

---

## Lab environment

| VM | OS | RAM | vCPU | Disk | Role |
| --- | --- | --- | --- | --- | --- |
| siem | Ubuntu Server 22.04 | 9 GB | 4 | 120 GB | Wazuh + n8n + TheHive + Cortex |
| win-ep | Windows 10 | 2 GB | 2 | 60 GB | Endpoint with Sysmon + ASR |
| fw | pfSense 2.7 | 512 MB | 1 | 16 GB | Gateway + Suricata IDS |

Host: 16 GB RAM, VirtualBox 7.x, Windows 11.

---

## License

MIT
