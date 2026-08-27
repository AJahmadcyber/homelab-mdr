# Repository layout

Annotated tree. The numeric prefix on a rule file is its load order; the
comment beside it gives the rule IDs it carries.

```
homelab-mdr/
├── README.md
├── LICENSE
├── .github/
│   └── workflows/validate.yml       # CI: rule XML, compose YAML, link and index checks
├── detection/
│   ├── wazuh-rules/                     # custom Wazuh XML rules (numeric prefix = load order)
│   │   ├── 9985-impact.xml               # 100400–100415 (impact: recovery destruction, encryption, log clearing)
│   │   ├── 9986-lateral-movement.xml    # 100210–100211 (unauthorized SIEM login, allowlist)
│   │   ├── 9987-siem-health.xml         # 100395–100399 (engine availability)
│   │   ├── 9988-ci-tampering.xml        # 100380/100381 (HVCI, blocklist, PPL)
│   │   ├── 9989-edr-killer.xml          # 100370/100371 (security tooling killed)
│   │   ├── 9990-secwatch.xml            # 100359–100366 (L4 surviving channel)
│   │   ├── 9991-byovd-detection.xml     # 100340–100343 (driver load)
│   │   ├── 9992-fp-suppression.xml      # 100390 (surgical FP tuning)
│   │   ├── 9993-persistence-detection.xml # 100333–100338 (ASEP, writer-agnostic)
│   │   ├── 9994-fileless-c2-detection.xml # 100330–100332 (in-memory loader, beaconing)
│   │   ├── 9995-credential-access.xml   # 100310–100313 (LSASS / Mimikatz / stealer)
│   │   ├── 9996-endpoint-discovery.xml  # 100320 (scanner cmdline)
│   │   ├── 9997-suricata-mitre.xml      # 100300–100308 (Suricata + DNS + edge CVE)
│   │   ├── 9998-siem-self-monitoring.xml# 100200–100208 (SIEM tampering)
│   │   ├── 9999-windows-powershell.xml  # 100100–100102 (PowerShell 4104)
│   │   └── lists/siem-ssh-allowlist     # CDB allowlist — admin-jump sources (100211 lookup)
│   ├── suricata-rules/                  # custom Suricata signatures
│   │   ├── custom.rules                 # sid 1000001/1000002 (T1046), 1000003 (T1048), 100350 (CVE-2024-55591)
│   │   └── disablesid.conf              # sid 26470 (broken community rule)
│   ├── secwatch/                        # L4 — the surviving channel
│   │   ├── agent/                       # endpoint heartbeat + shutdown announce
│   │   ├── siem/                        # watchdog + systemd timer
│   │   └── README.md                    # design, limits, verified behaviour
│   ├── siem-health/                     # detects the engine dying silently
│   ├── sysmon/                          # DriverLoad override + rationale
│   ├── dns-analyzer/                    # behavioral C2 analyzer
│   │   └── c2-detect.py                 # rate-based DNS beaconing detector
│   └── pipeline/                        # collectors
│       ├── suricata-collector.sh        # alert PULL collector (systemd)
│       ├── suricata-collector.service   # systemd unit (Restart=always)
│       ├── dns-pull.sh                  # DNS query batch pull (cron)
│       ├── dns-pull.cron                # 1-min schedule
│       └── dns-analyzer.logrotate       # stream + alert retention
├── soar/                                # Phase 6 SOAR (triage + containment)
│   ├── n8n/
│   │   ├── docker-compose.yml           # n8n container (isolated)
│   │   ├── wazuh-soar-triage.json       # alert → enrich → contain → classified ticket
│   │   └── phishing-triage-cortex-enrichment.json  # .eml → enrich → signal scoring
│   ├── cortex/                          # Cortex + Elasticsearch (secrets redacted)
│   │   ├── docker-compose.yml
│   │   ├── application.conf             # pinned secret key (HOCON mount)
│   │   └── README.md                    # analyzer setup + org/user bootstrap
│   ├── thehive/                         # TheHive 5 (local mode: bdb + Lucene)
│   │   ├── docker-compose.yml
│   │   └── application.conf
│   ├── wazuh-integration/
│   │   ├── custom-n8n                   # Wazuh → n8n forwarder script
│   │   └── ossec-integration-block.xml  # <integration> block (level>=10)
│   └── scripts/                         # 6-B containment
│       ├── soar-block.py                # host-isolation blocker (allowlist + circuit breaker)
│       └── cron-dns-pipeline            # cron: pull && analyze, every minute
├── docs/
│   ├── architecture.png                  # lab architecture: network, hosts, traffic paths
│   ├── phase7-attack-scenario.md        # Phase 7 design doc: threat profile, stage plan, rule sources
│   ├── session-log.md                   # phase-by-phase build journal
│   ├── references.md                    # sources that shaped detection content, and what came from each
│   ├── phase-progress.md                # phase-by-phase completion tracker
│   ├── phase5-session2-pipeline.md      # Suricata -> Wazuh pipeline build notes
│   ├── phase5-stream-stability-pull-model.md  # why the collector pulls instead of pushes
│   ├── known-issues/                    # documented defects (agent 4.9.0 syscollector crash)
│   └── evidence/                        # screenshots per phase
└── testing/                             # per-technique test cases with evidence
    ├── README.md
    └── T001-T1059.001-obfuscated-powershell.md
```

---
