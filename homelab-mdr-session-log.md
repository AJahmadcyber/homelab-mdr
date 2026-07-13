# Homelab MDR — Session Log

> Build journal: SOC Detection Engineering Lab. From idea to full detection stack.
> **GitHub:** https://github.com/AJahmadcyber/homelab-mdr

**Last updated:** July 13, 2026 — Phase 5 complete (Suricata IDS + Suricata→Wazuh pipeline + DNS-layer detection: tunneling T1048 + rate-based C2 beaconing T1071.004).

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
| 6 | TheHive 5 + Cassandra + Cortex + n8n SOAR | ⏳ **Next** |
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
