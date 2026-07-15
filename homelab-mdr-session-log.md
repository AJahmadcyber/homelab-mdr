# Homelab MDR — Session Log

> Build journal: SOC Detection Engineering Lab. From idea to full detection stack.
> **GitHub:** https://github.com/AJahmadcyber/homelab-mdr

**Last updated:** July 15, 2026 — Phase 6-B core complete (automated host isolation via pfSense REST API + safety controls + professional investigation tickets, validated end-to-end with a real multi-stage APT attack chain). Remaining in 6-B: TTL auto-unblock, Cortex enrichment, domain/subdomain block.

---

## Phase Order (Locked — do not reorder or skip)

| Phase | Description | Status |
|---|---|---|
| 1 | Foundation (VMs, network, Docker, Wazuh stack) | ✅ Done |
| 2 | Hardening (UFW, fail2ban, SSH, ISM retention) | ✅ Done |
| 3 | Windows Endpoint Telemetry (Sysmon, 4104, ASR, Defender) | ✅ Done |
| 4 | pfSense in-path network re-architecture | ✅ Done |
| 4.5 | SIEM Self-Monitoring (agent 002 + auditd + rules 100200–100205) | ✅ Done |
| 5 | Suricata IDS on pfSense + Wazuh integration + DNS-layer detection | ✅ **Done** |
| 6-A | n8n SOAR: Wazuh → n8n triage pipeline (high-sev alerts) | ✅ **Done** |
| 6-B | Host isolation via pfSense REST API + allowlist + circuit breaker + investigation tickets | ✅ **Core done** (TTL/Cortex/domain-block remain) |
| 6-C | TheHive 5 + Cassandra case management (needs RAM planning) | ⏳ Planned |
| 7 | GentleKiller ransomware threat profile (T1486+) | ⏳ Planned last |

---

## Current Topology (post Phase 5) — GROUND TRUTH

**pfSense 2.7.2 in-path:** WAN em0 via VirtualBox NAT `10.0.2.15`; LAN em1 `10.10.10.1/24`; hostname `pfSense.lab.local`. Suricata 7.0.8.

**VMs (all on LAN 10.10.10.0/24):**

| VM | IP | RAM | Role |
|---|---|---|---|
| siem (Ubuntu 22.04) | 10.10.10.10 | 7 GB | Wazuh 4.9.0 Manager + Indexer + Dashboard (Docker Compose) |
| win-ep (Windows 10) | 10.10.10.20 | 2 GB | Windows endpoint (Sysmon + ASR + Wazuh agent 001) |
| pfSense | 10.10.10.1 | 2 GB | Gateway + Suricata 7.0.8 IDS |
| ThinkPad (host) | 10.10.10.2 | 16 GB total | VirtualBox host |

> **VirtualBox VM names (exact):** `"siem  "` (note trailing spaces — use UUID `8d29472a-f476-4087-833c-bb6411d195df`), `"win-ep"`, `"pfsense"`.
> **VBoxManage path:** `C:\Program Files\Oracle\VirtualBox\VBoxManage.exe` (not in PATH — call with full path via `&`).

> **Obsolete:** old `192.168.56.0/24` Host-only topology + siem 9 GB — replaced in Phase 4. All current work is on `10.10.10.0/24`.

**Memory ceiling:** 16 GB total, fully allocated. Any new VM requires explicit rebalancing (relevant for Phase 6 TheHive/Cortex/Cassandra).

---

## East-West vs North-South — CONFIRMED empirically (this session)

Tested win-ep → ThinkPad (10.10.10.2) reachability:
- `Get-NetNeighbor 10.10.10.2` → `NextHop: 0.0.0.0`, MAC resolved (`0A-00-27-00-00-0A`), State `Reachable`.
- **Conclusion:** win-ep treats ThinkPad as on-link (same segment) → ARP direct → **L2-switched, never crosses pfSense.** Suricata is blind to it.
- ICMP ping fails (Windows host firewall drops ICMP) — the ARP entry, not ping, is the truth.

**Implication for C2:** any device inside 10.10.10.0/24 = east-west. A realistic *external* C2 listener would need to sit outside the /24 (WAN side). Deferred to Phase 7 (ransomware chain). **DNS is the one C2 channel that IS routed** — win-ep DNS resolver = `10.10.10.1` (pfSense) primary, `1.1.1.1` fallback, so every query crosses pfSense and is Suricata-visible. This is why DNS-layer detection is the right realistic C2 story for this topology.

---

## Active Components

**Wazuh agents:** 001 (win-ep), 002 (siem-self)

**auditd on siem:** 20+ rules (Docker socket, Wazuh config/binary tampering, SSH, sudoers, /etc/shadow, crontab, systemd, UFW/iptables, execve).

**Custom Wazuh rules:**
- 100100–100102 (Phase 3, PowerShell/4104) → T1059.001
- 100200–100205 in `9998-siem-self-monitoring.xml` → T1562.001, T1611, T1610, T1548.003, T1098, T1543.002, T1562.004
- 100300–100304 in `9997-suricata-mitre.xml` → Suricata alerts → MITRE (T1046, severity escalation; 100304 preserves T1046 on high-sev ET SCAN)
- **100305** → DNS tunneling / exfil (T1048), chains `if_sid 100300` on Suricata sid 1000003
- **100306** (level 10) / **100307** (level 12) → DNS C2 beaconing (T1071.004), sourced from custom dns-analyzer (NOT Suricata) via `decoded_as json` + `field name="analyzer"`
- 100310–100313 (credential access, Jul 12, commits `d63101d`+`b04c0fd`) in `9998-credential-access.xml` → T1003.001 (LSASS via comsvcs), Mimikatz 4104, browser stealer

**pfSense firewall:** aliases `siem_host`, `win_ep`, `thinkpad_host`, `wazuh_ports`, `github_egress`; explicit LAN allow rules with logging; default-deny egress.

**Suricata (Phase 5):**
- LAN (em1) instance, IDS mode, AutoFP, Medium profile (~28,510 rules)
- ET Open + Snort GPLv2 Community; JA3 enabled
- `custom.rules`: 1000001 (internal SYN scan T1046), 1000002 (external→internal T1046), **1000003 (DNS long-subdomain tunneling T1048)**
- SID Mgmt disablesid: `26470` (broken Snort Community Zeus rule)
- EVE JSON FILE output at `/var/log/suricata/suricata_em14846/eve.json` (includes DNS query + answer records)

---

## Pipelines (Phase 5)

### Pipeline 1 — Suricata alerts → Wazuh (PULL model, systemd)
```
Suricata eve.json (pfSense)
  → edge filter: grep '"event_type":"alert"'   (alerts only)
  → siem PULLs: suricata-collector.sh (systemd, Restart=always) — persistent SSH tail
  → /var/log/suricata-pfsense/eve-alerts.json
  → Docker bind mount into wazuh.manager (:ro)
  → Wazuh localfile (json) → built-in JSON decoder → rules 100300–100305 → MITRE
```
- Service: `/usr/local/bin/suricata-collector.sh` + `suricata-collector.service` (User=root, Restart=always, RestartSec=5).
- **`pkill -x tail` inside the SSH command** — kills stale remote tails by exact name only (see Learnings). Verified: 1 real tail steady-state, auto-recovers in <12s after ssh kill, delivery resumes with no tail leak.

### Pipeline 2 — DNS queries → behavioral C2 analyzer → Wazuh (NEW this session)
```
Suricata eve.json (pfSense)
  → dns-pull.sh (batch, byte-offset, cron every 1 min) — pulls only NEW bytes,
    filters event_type=dns AND type=query (answers dropped at edge)
  → siem: /var/log/dns-analyzer/dns-queries.stream
  → c2-detect.py (rate-based beaconing analyzer)
        tldextract-free eTLD+1 approximation (last-2 + multi-TLD list)
        groups by (src_ip, eTLD+1) over 300s window
        THRESH=40 queries → alert; allowlist for legit high-volume parents
        emits SOAR-ready JSON: parent_domain + src_ip + count + mitre
  → /var/log/dns-analyzer/alerts.json
  → Docker bind mount into wazuh.manager (:ro)
  → Wazuh localfile (json) → rules 100306/100307 → T1071.004
```
- `dns-pull.sh`: **batch, NOT a persistent tail** — opens SSH, reads new bytes via `tail -c +offset`, closes. Zero tail leak, zero collision with Pipeline 1. Byte offset in `/var/log/dns-analyzer/.last_size`; rotation guard resets if remote file shrank.
- `c2-detect.py`: runs on-demand (cron can invoke, or manual). In-memory state, volatile by design (restart = clean).
- cron: `/etc/cron.d/dns-pull` — `* * * * * root /usr/local/bin/dns-pull.sh >> /var/log/dns-analyzer/pull.log 2>&1`
- logrotate: `/etc/logrotate.d/dns-analyzer` — stream (daily, rotate 3) + alerts (daily, rotate 7), copytruncate.
- Service user `dnsanalyzer` (uid 998, nologin) created for least-privilege; **but the pull runs as root** (needs `/root/.ssh` key), so `/var/log/dns-analyzer` is `root:dnsanalyzer 770`.

**Design rationale (portfolio):** Signature matching is the weakest tier of the Pyramid of Pain — an attacker rewrites the tool and evades. Rate-based beaconing targets an *intrinsic property of the C2 channel* (repetition) that is costly to hide without breaking the C2. Behavioral analysis lives in the SIEM layer (clean separation: Suricata = wire, analyzer = behavior, Wazuh = correlation). Blocking is deferred to Phase 6 SOAR (block TTL + RFC1918 allowlist + circuit breaker) — never inline IPS on the single gateway.

---

## Snapshots (latest)

- `siem@phase5-dns-c2-detection-complete` (this session, final)
- `siem@pre-dns-wazuh-wiring` (this session, before docker-compose recreate)
- `siem@phase5-session2-complete`, `pfsense@phase5-suricata-session1`
- `siem@phase4.5-self-monitoring-complete`, `win-ep@phase4-migrated-to-lan`

## Commits (chronological, Phase 5)

- `d2e3267` (Phase 4), `de9fb16` (Phase 4.5)
- `7979e47` (Jul 3 — Phase 5 Session 1: Suricata IDS, custom T1046 SYN-scan rule)
- `d48ad09` (Jul 4 — Phase 5 Session 2: Suricata→Wazuh stream + rules 100300–100303, T1046)
- `e3d3971` (Jul 4 — Phase 5 S2 docs: pipeline config reference + session log)
- `02ba5e7` (Jul 8 — replace PUSH stream with PULL + systemd Restart=always)
- `d4761ef` (Jul 9 — rule 100304: preserve T1046 on high-sev ET SCAN)
- `d63101d` (Jul 12 — T1003.001 LSASS credential dumping, rules 100310/100311)
- `b04c0fd` (Jul 12 — Mimikatz 100312 + browser cred theft 100313; FP-tune 100310)
- `56efcdb` (Jul 13 — fix: pkill -x tail in collector, prevent stale tail accumulation)
- **`73e0ea1`** (Jul 13 — DNS-layer detection: 100305 T1048 + DNS C2 pipeline + rules 100306/100307 T1071.004)

---

## Phase 5 — Full Record

### Session 1 (DONE ✅)
- Suricata package; hardware offloading disabled (checksum/TSO/LRO) + reboot
- LAN instance, IDS mode, EVE JSON (file); ET Open + Snort Community categories
- Custom T1046 SYN-scan rules (1000001/1000002) verified firing
- 6 evidence screenshots + commit + snapshot

### Session 2 (DONE ✅)
- Edge-filtered streaming pipeline — verified end-to-end
- Docker bind mount for eve-alerts.json; Wazuh localfile (json) + rules 100300–100303
- Persistent auto-reconnect stream + logrotate + fail2ban whitelist
- Commit `d48ad09` + snapshot `phase5-session2-complete`

### Session 3 (DONE ✅ — this session, July 13)
**Collector hardening (PULL model finalized):**
- Confirmed root cause of tail accumulation: old `pkill -f 'tail -F ...'` matched its OWN wrapper shell (`/bin/sh -c "pkill...; tail -F..."`) → corrupted cleanup → tail leak on every reconnect.
- Fix: `pkill -x tail` (exact process name only; the Capsicum `system.fileargs` helper and wrapper shell are not matched). Verified real tails = 1 steady-state.
- Resilience verified: killed collector's ssh → systemd `Restart=always` recovered in <12s → delivery resumed, still 1 tail (no leak).
- Committed the fixed `suricata-collector.sh` to repo.

**Phase 5 detection scenarios verified:**
- Port scan T1046: `nmap -sS` win-ep → 10.10.10.1 (must target across pfSense, not east-west). Confirmed Suricata sid 1000001 → Wazuh rule 100301, level 7, T1046, live on dashboard.
- DNS tunneling T1048: Suricata sid 1000003 firing; **Wazuh rule 100305 already present** (level 7, T1048) — mapped correctly.

**DNS C2 beaconing detection (T1071.004) — the main build:**
- Confirmed Suricata writes DNS query + answer records to eve.json; designed edge filter to keep query-only (answers are heavy CNAME chains).
- Chose SIEM-layer behavioral analysis (path 2) over Suricata Lua (path 1) — avoids pfSense package-regeneration risk, cleaner separation of concerns, natural Phase 6 SOAR extension.
- **Avoided an over-engineering spiral:** initial persistent-tail DNS collector collided with the alert collector's `pkill -x tail` (they'd kill each other). Tested `-tt` (breaks under background/systemd — job Stopped on SIGTTIN). Root discovery: **remote tail does NOT die when the SSH session is killed from the siem side** — it stays alive under a detached shell (not orphan ppid=1), which is exactly what caused historical accumulation. Resolution: abandon the persistent DNS tail entirely; use **batch byte-offset pull via cron** (no persistent process, no collision).
- Built `dns-pull.sh` (batch), `c2-detect.py` (rate-based analyzer), cron (1-min), logrotate, `dnsanalyzer` service user.
- Wired into Wazuh: added `/var/log/dns-analyzer` bind mount to docker-compose.yml (`docker compose up -d` to recreate), localfile block, rules 100306/100307.
- **Verified end-to-end:** win-ep beacon (60 × `beacon-c2-test.example.com` @ 300ms) → pfSense → pull → analyzer alert (parent=example.com, count=60, medium) → Wazuh rule 100306 level 10 T1071.004, live in alerts.json / dashboard.
- Commit `73e0ea1` + snapshot `phase5-dns-c2-detection-complete`.

---

## Key Learnings & Principles

**DNS C2 analyzer — the hard-won bugs (this session)**
- **Py3.10 `datetime.fromisoformat()` rejects Suricata timestamps.** Suricata writes `+0300` (no colon); Py3.10 needs `+03:00`. Symptom was silent: `parse_ts()` returned None inside a try/except → every query filtered → zero alerts, exit 0 (looked like it "worked"). Fix: regex-insert colon in the tz offset before parsing. (Py3.11+ handles it natively.)
- **heredoc-within-heredoc destroys regex escaping.** Writing `\\d` through a bash heredoc into Python produced `\\d` (literal backslash-d) in the file, not `\d`. The regex silently never matched. Fix: write the Python file with a clean heredoc where the Python string literal `'\\d'` collapses to `\d` on disk; verify the on-disk byte with `grep`, and unit-test `parse_ts` on a real timestamp before trusting it.
- **Verify before assuming timing.** Repeated "empty alert" results were partly a real bug (above) and partly a 300s-window timing issue (beacon queries aged out before the analyzer ran). Always run the analyzer immediately after the beacon; use `wazuh-logtest` for a timing-independent rule check.

**Wazuh rule-file ownership inside the container (critical, silent)**
- Custom rule files live in the **`single-node_wazuh_etc` Docker volume**, NOT bind-mounted from the repo. The repo is a working copy; changes must be `docker cp`'d into `/var/ossec/etc/rules/` in the container, then reload.
- **Ownership/permissions must match the working rule files exactly: `wazuh:wazuh`, mode `644`.** A `chown 1000:1000` + `chmod 660` made the file unreadable by wazuh-logtest/analysisd → `WARNING (1103): Could not open file ... Permission denied` → rule silently not loaded → no match. Same class of silent-permission failure as `usermod -aG adm wazuh` for auditd.
- Diagnose with `wazuh-logtest` (shows `Could not open file` if perms are wrong) and confirm the rule is present: `docker exec ... grep -c 'id="100306"' /var/ossec/etc/rules/9997-suricata-mitre.xml`.

**Wazuh custom-rule authoring**
- JSON-decoded fields referenced **without `data.` prefix** (`analyzer`, `severity`, `parent_domain`); `data.` only appears in alert OUTPUT.
- A non-Suricata JSON source (our analyzer) needs its own root rule with `<decoded_as>json</decoded_as>` + a distinguishing `<field>` (here `analyzer=dns-c2-ratebased`) — it does NOT chain off the Suricata base rule 100300.
- Wazuh reads only **newly appended** lines after it starts watching a localfile; pre-existing lines are not re-read. Generate a fresh alert to test live delivery (logtest works on old lines for rule-logic checks).

**Docker / bind mounts**
- New host log paths need a **volume bind mount** in docker-compose.yml; mount changes → `docker compose up -d` (recreate). Config-only changes → `restart`.
- Bind-mount the **directory** (`/var/log/dns-analyzer`), not a single file — single-file mounts break with logrotate/recreate.
- `docker compose config` validates YAML before recreate.

**Remote tail / SSH collection (FreeBSD/pfSense)**
- **A remote `tail -F` does NOT die when the SSH session is killed from the collector side** — it survives under a detached shell (not orphan ppid=1). This is the real cause of tail accumulation, and why cleanup (`pkill -x tail`) is required for persistent-tail models.
- `pkill -x tail` matches exact process name only — but with TWO persistent tail-based collectors on the same file, they'd kill each other. Resolved by making the DNS collector a **batch cron pull** (no persistent process) instead of a second tail.
- `ssh -tt` is NOT a fix here: under background/systemd (no controlling terminal) the job is Stopped (SIGTTIN).
- FreeBSD `tail` spawns a Capsicum `system.fileargs` helper that also shows as "tail" in `pgrep -x tail` (false +1). Count real tails with `ps -axo command= | grep -c '^tail -F'`.

**pfSense / FreeBSD ops (carried forward)**
- Default shell tcsh: `>!` force-clobber, `>&` combined redirect; no rsync (use scp / `ssh 'cat'`).
- Script ssh must use explicit `-i /root/.ssh/id_ed25519_pfsense -o IdentitiesOnly=yes`.
- Suricata config dir `.../suricata_4846_em1/`, log dir `/var/log/suricata/suricata_em14846/` (naming differs).
- config.xml is source of truth; stale `<defaultgw4>` → edit `/conf/config.xml` + reload.

**Wazuh in Docker (carried forward)**
- Manager container `single-node-wazuh.manager-1`. ossec.conf = `config/wazuh_cluster/wazuh_manager.conf`.
- Insert localfile before the LAST `</ossec_config>` (Python rfind) to avoid duplicating across blocks.
- `9997-` rules load before `9998/9999`.
- `docker compose restart` more reliable than `wazuh-control restart` after rule changes (latter can half-stop analysisd) — though `wazuh-control restart` worked cleanly this session for a rules-only reload.

**Security-in-practice (carried forward)**
- fail2ban `ignoreip` includes `10.10.10.0/24` (prevents self-ban from stream reconnects).
- Default-deny egress: siem→github needs `github_egress` alias + LAN pass rule.
- VBoxManage not in PATH; VM name `"siem  "` has trailing spaces → use UUID.

---

## Approach & Patterns

- Strict phase sequencing: infra before detection before threat sims.
- Each session ends with: snapshots, commit + evidence, README/architecture updates.
- Custom rules MITRE-mapped; ID namespacing by phase (Wazuh 100xxx; Suricata local 100000x).
- Snapshot before risky steps (recreate, mounts); memory + disk are hard constraints.
- Python heredoc scripts over manual nano; verify on-disk bytes before trusting.
- **Empirical over assumption:** test the actual behavior (ARP, remote-tail survival, logtest) rather than reasoning from expectations — repeatedly the decisive move this session.
- **Resist over-engineering:** the behavioral DNS engine is a Phase 6-scale project; this session shipped a light, verified rate-based detector and deferred entropy/cardinality/PSL to Phase 6.
- Communication: Levantine Arabic + technical English.

---

## Phase 6 hooks (what this session set up for SOAR)

- `c2-detect.py` alerts are **SOAR-ready JSON**: `parent_domain` + `src_ip` + `query_count` + `mitre`. Phase 6 flow: Wazuh alert → n8n → Cortex enrichment (domain reputation / passive DNS on `parent_domain`) → scoring → pfSense API block (TTL + RFC1918 allowlist + circuit breaker).
- DNS behavioral engine extensions reserved for Phase 6: Shannon entropy on labels, unique-subdomain cardinality per eTLD+1, proper PSL (tldextract), real-time stream instead of 1-min batch.
- Memory planning required before Phase 6 (TheHive + Cassandra + Cortex + n8n) — 16 GB ceiling is fully allocated.

---

## Phase 6-A — SOAR Pipeline (n8n) — Full Record (July 14)

**Goal:** first SOAR automation layer — Wazuh forwards high-severity alerts to n8n, which triages and tags them for response. Detection → orchestration wired end to end. Automated *containment* deferred to Phase 6-B (conscious decision, not laziness — blocking without enrichment + safety controls is dangerous on a single gateway).

### RAM reality check (decided the phased approach)
- Host: 15.9 GB total, ~3 GB free at rest. siem assigned 7 GB but **actual `available` inside siem = 4.3 GB** (Wazuh stack uses only ~2.6 GB: indexer 1.37 + manager 1.13 + dashboard 0.18).
- **Do NOT raise siem RAM from host free pool** — would choke Windows host (only ~3 GB free). If ever needed, swap from win-ep (saved state, 2 GB) — never from host free.
- n8n fits comfortably in siem's headroom (~0.7 GB). **Full TheHive+Cassandra+Cortex stack does NOT fit** → phased: 6-A (n8n only) now, 6-B (Cortex, JVM-tuned or on-demand), 6-C (TheHive, needs RAM planning).

### What was built
- **n8n** (`/opt/homelab-mdr/n8n/docker-compose.yml`) — separate compose, own network + volume, **NOT** touching the Wazuh stack. Bound to LAN interface only (`10.10.10.10:5678`), `N8N_SECURE_COOKIE=false` (HTTP on LAN), `WEBHOOK_URL` set so generated webhooks use the siem IP.
- **Wazuh integration** — `custom-n8n` script in `/var/ossec/integrations/` (sh + curl, POSTs raw alert JSON to the n8n production webhook). `<integration>` block in ossec.conf: `level>=10`, `alert_format=json`.
- **n8n workflow** "Wazuh SOAR triage": `Webhook → IF (rule.level >= 10) → true: Edit Fields (HIGH_PRIORITY, enrich+block placeholder) / false: Edit Fields (LOW_PRIORITY, logged)`.

### Pipeline
```
Wazuh alert (level >= 10)
  → integratord runs /var/ossec/integrations/custom-n8n
  → curl POST → http://10.10.10.10:5678/webhook/wazuh-alert
  → n8n: IF rule.level>=10 → HIGH_PRIORITY tag / LOW_PRIORITY tag
```

### Validated end-to-end with REAL attacks (not synthetic — this was the key insight)
Synthetic tests (Write-Output of a signature string) do NOT fire the endpoint rules — those chain off Sysmon **EID1 process creation**, so they need a real process with the malicious command line. Confirmed the rules are precise (won't match on mere text). Ran real commands on win-ep (Defender real-time already off; snapshot `pre-atomic-6a-validation` taken first):

| Threat | Rule(s) | Level | MITRE | Test |
|---|---|---|---|---|
| DNS C2 beaconing | 100306 | 10 | T1071.004 | 60× beacon to example.com |
| Mimikatz | 100312 | 13 | T1003 | 4104 script-block signature |
| LSASS dump | 100310 + 100311 | 12 | T1003.001 | real `rundll32 comsvcs.dll MiniDump <lsass pid>` |
| Browser cred theft | 100313 | 12 | T1555.003 | real `esentutl /y /vss` on Chrome + Edge Login Data |

All four fired in Wazuh **and** produced n8n executions → the SOAR layer is **threat-category-agnostic** (level-based), not C2-specific. LSASS fired **two** rules (100310 access-level + 100311 comsvcs cmdline) = layered detection. Dump file + stolen DBs deleted after (contained real credentials).

### Key learnings (Phase 6-A)
- **`level` filter ≠ per-rule filter.** `<integration><level>10</level>` forwards *any* alert ≥ 10 — no need to enumerate rule IDs. New high-sev detections flow to SOAR automatically. Per-category branching belongs *inside* n8n (Phase 6-B: C2 → domain block, credential → host isolate), not at the Wazuh filter.
- **n8n workflow name is cosmetic** — every execution shows the workflow name regardless of alert content. Renamed to "Wazuh SOAR triage" (was "DNS C2 triage") since it handles all categories.
- **n8n Publish = save + activate.** Production webhook (`/webhook/...`) only works after Publish; test webhook (`/webhook-test/...`) only during "Listen for test event".
- **Real vs synthetic tests:** EID1-chained rules (LSASS/stealer) need a real process; a synthetic 4104 string fires only the 4104-based rule (Mimikatz). Test at the layer the rule watches.
- **Docker Hub blocked by default-deny egress** — pulling n8n required a TEMP egress rule on pfSense (siem → any:443). Left OPEN intentionally for the upcoming Cortex/analyzer pulls in 6-B; **must be disabled after 6-B image pulls** (back to default-deny).

### Snapshots / commit
- siem snapshot `phase6a-soar-validated` (replaced `phase5-complete-documented`, which was merged/deleted to reclaim space). win-ep `pre-atomic-6a-validation`.
- Commit `15712aa` — `feat(soar): Phase 6-A — Wazuh → n8n SOAR pipeline`.

### Phase 6-B hooks (next)
- HIGH_PRIORITY branch in n8n is the insertion point: → Cortex enrichment (VirusTotal / AbuseIPDB / passive DNS on `parent_domain` or `src_ip`) → scoring → pfSense API block with **TTL + RFC1918 allowlist + circuit breaker**.
- Cortex is JVM-heavy — tune heap or run on-demand (RAM ceiling). TEMP egress already open for image pulls.

---

## Phase 6-B — SOAR Containment + Investigation Tickets — Full Record (July 15)

**Goal:** turn the SOAR layer from alert-triage into automated *containment* — high-severity alerts drive automated host isolation through the pfSense REST API, gated by safety controls, and every alert produces a professional SOC investigation ticket (the training-value core; TheHive-ready).

### RAM upgrade (this session)
- siem raised 7 -> 8 GB (win-ep lowered 2 -> 1.5 GB to compensate; taken from win-ep's saved allocation, NOT the host free pool). Verified: siem total 7.8Gi, available ~4.8Gi, swap clean. Host stays ~1-2 GB free with 3 VMs — tight but stable; win-ep kept powered off except during live attack tests.

### pfSense REST API (the firewall-automation foundation)
- Installed **pfSense-pkg-RESTAPI v2.4.3** (`pfrest/pfSense-pkg-RESTAPI`, the repo moved from jaredhendrickson13). Latest releases dropped 2.7.2 support; v2.4.3 is the newest **stable** that ships a 2.7.2 CE package. Clean install.
- **Security:** Enabled, Auth = API Key, Login Protection ON, Read-Only OFF, **Allowed Interfaces = LAN only** (WAN removed — never expose the firewall API to WAN). Key = SHA256/24-byte.
- **API key stored as an n8n credential** (Header Auth, name `X-API-Key`) — NOT written into the workflow, so the exported JSON is safe for the public repo (verified: no key in export, only a credential id/name reference).
- **API mechanics learned (documented in soar/pfsense-api/README.md):**
  - Base `https://10.10.10.1/api/v2/`, header `X-API-Key: <key>`, `-k` for self-signed.
  - **`Accept: application/json` is REQUIRED** — pfSense rejects the default multi-value Accept header ("No content handler exists").
  - PATCH/DELETE need the object `id` **in the JSON body**, not the query string.
  - `apply` is async: POST /firewall/apply returns `applied:false` immediately, then `True` after ~seconds (not an error).
  - Endpoints: /firewall/rules, /firewall/rule, /firewall/alias, /firewall/aliases, /firewall/apply.
- **Blocking objects:** alias `soar_blocklist` (id 7, host) + block rule (id 12: source=soar_blocklist, dest=any, lan, log=true). Rule kept **DISABLED (dry-run)** by default; enabled only during live containment tests, disabled again after.

### Safety controls — built first, before any real block (soar/scripts/soar-block.py + mirrored inline in n8n)
- **Infrastructure allowlist** — NEVER block 10.10.10.1 (gateway), 10.10.10.10 (siem), 10.10.10.2 (ThinkPad). Verified: all three REFUSED with a logged reason.
- **Circuit breaker** — max 5 blocks / 10-min window, state-tracked in /opt/soar/block-state.json. Verified: 6th rapid block TRIPPED and was refused.
- IP-format validation + dedupe (`already_blocked`). All controls tested with harmless TEST-NET IPs (192.0.2.x) before any live use.

### n8n containment flow
`Webhook -> IF(level>=10) -> HIGH_PRIORITY(Edit Fields) -> Code(extract src_ip + allowlist decision) -> IF(action==allow_block) -> HTTP Request(PATCH soar_blocklist, add IP) -> HTTP Request(POST apply) -> Code(build investigation ticket)`; false branch -> Edit Fields (logged, no block). The allowlist/decision logic is visible as n8n nodes (good for portfolio review), and also enforced in the standalone script.

### Investigation ticket (the training-value core — TheHive-ready)
Professional SOC/Jira-grade JSON produced per alert: `ticket_key` (SOC-YYYYMMDD-HHMMSS), `summary`, `priority`+`sla_due_utc` (Critical=1h/High=4h/Medium=24h), `tlp`, MITRE technique(s), detection details, **observables** (TheHive-style ip/domain with ioc flag), **timeline**, `automated_response`, **Cortex enrichment placeholders** (virustotal/abuseipdb — pending, filled in later 6-B), a 7-step **L1 investigation checklist**, `work_notes`, `disposition` (TruePositive/FalsePositive/Escalated), and a PICERL playbook line. This is what an L1 analyst will actually investigate; it lands in TheHive as a case in 6-C.

### DNS pipeline root-cause fix (important)
- **Bug found:** the cron ran `dns-pull.sh` only — the analyzer `c2-detect.py` was NOT in cron. Beacons were pulled into the stream but never analyzed, so 100306 never fired automatically (we'd been running the analyzer by hand). This was why the first attack-chain run didn't auto-block.
- **Fix:** cron now runs `dns-pull.sh && c2-detect.py` every minute — the DNS C2 pipeline is now fully automatic end to end.
- Also: the analyzer reads the whole stream each run and filters by a 300s window (there is no offset in the analyzer itself — the `.last_size` belongs to dns-pull); the dns-pull rotation guard resets the offset if the stream shrinks (logrotate copytruncate).

### Validated end-to-end with a REAL multi-stage APT attack chain (win-ep)
Ran a 5-stage chain (Discovery -> Credential Access -> Persistence -> Defense Evasion -> C2):
- **15 unique detection rules fired across 13 MITRE techniques / 6 tactics.** Highlights: LSASS comsvcs dump (100311, T1003.001), Mimikatz (100312), SAM/SYSTEM/SECURITY hive dump (92026, T1003.002), browser theft (100313, T1555.003), executable dropped in malware folder (92213, T1105, L15), FodHelper UAC bypass (92055, T1548.002), Run-key + scheduled-task persistence (92302/92154), Base64 registry (92041), and DNS C2 (100306/100307, T1071.004).
- **The DNS C2 detection auto-triggered containment:** 100306 fired -> integration -> n8n -> allowlist check (win-ep not protected) -> PATCH soar_blocklist -> apply. Confirmed `blocklist: ['10.10.10.20']` and `applied: True` — **win-ep isolated fully automatically, no manual step.** Ticket generated for the incident.
- This is effectively the first full attack-chain measurement — the basis for the future Phase 8 Coverage Engine.

### Cleanup / state
- After the live test: removed win-ep from blocklist, disabled rule 12 (back to dry-run), reset circuit-breaker state. Confirmed clean.
- win-ep artifacts (dumps, hives, run-key, scheduled task, disabled Defender) remain on win-ep (powered off, network-isolated); to be cleaned or rolled back to snapshot `pre-atomic-6a-validation` next time it boots.
- Snapshots this session: pfSense `pre-rest-api-6b`; siem RAM change verified.

### Commit
- `8c3d40b` — `feat(soar): Phase 6-B — automated host isolation with safety controls + investigation tickets` (soar/scripts/soar-block.py, dns-pull.sh, c2-detect.py, cron-dns-pipeline; soar/pfsense-api/README.md; updated workflow export).

### Remaining in 6-B (next session)
- **TTL auto-unblock** (n8n Wait/schedule -> remove IP after N min -> apply).
- **Cortex** (JVM; VirusTotal + AbuseIPDB analyzers, need free API keys) -> n8n enriches the ticket's enrichment placeholders on the destination -> stronger, evidence-based block decision.
- **Domain/subdomain block** (DNS-level via Unbound/pfBlockerNG NXDOMAIN — separate path from firewall IP block; after Cortex, higher FP risk).
- **TEMP egress rule on pfSense is still OPEN** (for Cortex image pulls) — disable it (back to default-deny) after the Cortex pulls.

---

## Files Reference

```
siem:
  /opt/homelab-mdr/wazuh/single-node/docker-compose.yml   # bind mounts: suricata-pfsense + dns-analyzer
  .../config/wazuh_cluster/wazuh_manager.conf             # ossec.conf (+ localfile blocks)
  /var/log/suricata-pfsense/eve-alerts.json               # Pipeline 1 (alerts), logrotate
  /var/log/dns-analyzer/dns-queries.stream                # Pipeline 2 raw DNS queries, logrotate
  /var/log/dns-analyzer/alerts.json                       # Pipeline 2 C2 alerts → Wazuh
  /var/log/dns-analyzer/.last_size                        # byte offset for batch pull
  /usr/local/bin/suricata-collector.sh                    # Pipeline 1 (systemd, pkill -x tail)
  /usr/local/bin/dns-pull.sh                              # Pipeline 2 batch pull (cron)
  /opt/dns-analyzer/c2-detect.py                          # rate-based C2 analyzer
  /etc/cron.d/dns-pull                                    # 1-min pull schedule
  /etc/logrotate.d/dns-analyzer
  /etc/logrotate.d/suricata-pfsense
  /etc/fail2ban/jail.local                                # ignoreip 10.10.10.0/24
  ~/projects/homelab-mdr/                                 # GitHub repo
    detection/wazuh-rules/9997-suricata-mitre.xml         # 100300-100307
    detection/wazuh-rules/9998-siem-self-monitoring.xml
    detection/wazuh-rules/9998-credential-access.xml      # 100310-100313
    detection/wazuh-rules/9999-windows-powershell.xml
    detection/suricata-rules/custom.rules                 # 1000001/1000002/1000003
    detection/suricata-rules/disablesid.conf              # 26470
    detection/dns-analyzer/c2-detect.py
    detection/pipeline/suricata-collector.sh + .service
    detection/pipeline/dns-pull.sh + dns-pull.cron + dns-analyzer.logrotate
    docs/evidence/phase5/

pfSense:
  /usr/local/etc/suricata/suricata_4846_em1/              # Suricata config/rules
  /var/log/suricata/suricata_em14846/eve.json             # EVE output (alerts + dns)
  /root/.ssh/id_ed25519_pfsense                           # collector key
```
