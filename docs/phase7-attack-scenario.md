# Phase 7 — GentleKiller Kill-Chain: Attack Scenario & Detection Design

> **Homelab MDR — SOC Detection Engineering Lab**
> Design document for Phase 7: a full-lifecycle ransomware intrusion modeled on **The Gentlemen RaaS / GentleKiller** (ESET, June 2026), emulated stage-by-stage against the lab's detection → SOAR → TheHive pipeline.
>
> **Repo:** https://github.com/AJahmadcyber/homelab-mdr
> **Status:** Design/reference document. All eight stages (0–7) are implemented, as are the **L4 resilient layer** and the **L0 SIEM self-health** monitor. Remaining: the deepening items only (1a reflective ImageLoad, 1b process hollowing, X LOLBin-out-of-context).

---

## 1. Purpose & guiding principle

This document is the single reference for Phase 7. It defines the attack scenario A–Z, the layered defense we build against it, the tooling we use to emulate each stage, and the detection sources we build each rule from.

**The guiding principle — learned from the real breaches, not invented here:** early detection without automated response is worthless. In documented Gentlemen intrusions, Microsoft Defender logged malicious activity days before impact, and the initial-access CVE had been patchable for months — *"the audit log waved them through."* The lab's answer is that **every detection produces a ticket** (SOAR → TheHive), so no signal is silently buried. That response layer — not any single clever rule — is the north star.

A second principle: **behavioral detection outranks signatures.** GentleKiller ships 8+ swappable BYOVD variants, uses Go and fileless in-memory execution, and abuses signed living-off-the-land binaries. Signature and blocklist approaches are always a step behind. The rules that matter are the ones keying on *behavior* and *sequence*, which catch a variant nobody has seen yet.

---

## 2. Threat profile — The Gentlemen / GentleKiller

**Actor.** The Gentlemen (Microsoft: *Storm-2697*; also *LARVA-368*) — a Russian-speaking, financially motivated RaaS that split from a Qilin affiliate in mid-2025 and became publicly known in September 2025. By the end of Q1 2026 it ranked #2 globally by published victim volume. Lead operators: *hastalamuerte* and *zeta88*.

**What makes it distinctive.** Unlike most RaaS, the operators centrally build and maintain a full EDR-killer suite and hand it to affiliates, anchored by the in-house **GentleKiller** framework: 8+ variants, each impersonating a legitimate security product and abusing a different vulnerable kernel driver via **BYOVD** (Bring Your Own Vulnerable Driver) to reach Ring 0 and terminate 400+ security processes across 48 vendors, defeating user-mode tamper protection. Evasion treatment: Enigma/Themida packing, spoofed vendor version info, copied certificates and icons. Staging directory artifact: `GentlemenCollection`. Companion tooling: **OxideHarvest** (Rust credential stealer), plus external EDR killers (HexKiller, HavocKiller, ThrottleBlood).

**Initial access — the real root cause.** Primary vector was **Fortinet edge exploitation** — CVE-2024-55591 (FortiOS/FortiProxy auth bypass, CVSS 9.8), disclosed January 2025 with PoC circulating quickly. Attackers also used brute-forced VPN credentials (with reused brand-name passwords like `gentlemen25`) and access purchased from Initial Access Brokers. A seized SystemBC C2 server held a database of ~14,700 compromised FortiGate devices and 969 validated brute-forced VPN credentials — access catalogued and held for later deployment. One case used an SFTP credential stolen in 2023 in a 2026 intrusion.

**Full-lifecycle chain:** edge access → credential harvest → domain-wide lateral movement (via GPO) → EDR elimination (GentleKiller) → NAS/backup destruction → exfiltration → encryption. The encryptor is Go-based, cross-platform (Windows/Linux/ESXi/NAS/BSD), with worm-like self-propagation.

**The key defensive insight (ESET's own):** signature blocklists FAIL against 8 swappable variants. The strongest signal is behavioral — **correlate a process-termination burst with a kernel-driver-install event**, plus a driver load that doesn't match host inventory.

---

## 3. Attack scenario A–Z (stages + cross-cutting threads)

Eight stages, each mapped to ATT&CK. Three techniques cut *across* stages rather than sitting in one — LOLBins abuse, fileless/in-memory execution, and the SOAR ticket response — and are tracked as columns.

| # | Stage | ATT&CK | What happens | LOLBins (thread A) | Fileless (thread B) | SOAR ticket (thread C) |
|---|---|---|---|---|---|---|
| 0 | Initial Access | T1190, T1133 | Exploit exposed edge (Fortinet-style auth bypass) or use IAB-purchased / brute-forced credentials | — | — | ✅ |
| 1 | Execution + Persistence | T1059.001, T1055, T1547.001 | Payload loaded into RAM (reflective loader / beacon), no disk write; establishes foothold, profiles the host, then plants an autostart entry — written from inside the implant via the Registry API, not `reg.exe` — so the beacon survives reboot | `powershell`, `csc.exe`, `reg` | ✅ in-memory, diskless | ✅ |
| 2 | Discovery | T1046, T1018, T1082 | Network / system / target reconnaissance | `net`, `nltest`, `wmic`, `systeminfo` | — | ✅ |
| 3 | Credential Access | T1003.001 | LSASS dump + OxideHarvest; privilege escalation | `comsvcs.dll`, `esentutl`, `reg save` | ✅ in-memory dump | ✅ |
| 4 | Defense Evasion / BYOVD | T1562.001, T1543.003, T1068 | Load signed-but-vulnerable driver → Ring 0 → terminate EDR/AV (400+ processes) | `sc`, `reg`, `fltmc` | — | ✅ |
| 5 | Lateral Movement | T1021, T1570, T1484 | Domain-wide spread via GPO; here win-ep → siem | `wmic`, `schtasks`, PsExec-style | ✅ remote injection | ✅ |
| 6 | C2 | T1071.004 | Go backdoor + DNS beaconing | `nslookup`, `curl` | — | ✅ |
| 7 | Impact | T1486, T1490, T1489, T1070.001, T1082 | Volume enumeration → recovery destruction (shadow copies, backup catalogue, System Restore, boot recovery) → mass encryption → event-log clearing | `vssadmin`, `wbadmin`, `wmic`, `bcdedit`, `schtasks`, `wevtutil` | ✅ controlled PowerShell encryptor | ✅ |

**Why the cross-cutting threads matter.** LOLBins work *because* they are signed and trusted — the same reason "the audit log waved them through." Fileless execution is now the single most prevalent technique family (process injection T1055 leads across 1.1M+ malware samples per Picus Red Report 2026) precisely because malicious code runs under a trusted, signed process that defenders can't simply kill. Both reinforce the same lesson: **behavior over signature.**

---

## 4. Attack tooling — best source per stage

Not everything comes from Atomic Red Team (which runs isolated single techniques, not chained campaigns). Professional-grade emulation uses the right tool per stage.

| # | Stage | Chosen tool | Source | Why |
|---|---|---|---|---|
| 0 | Initial Access | ✅ **nmap** (scan) + **Nuclei** (vuln probe) + manual `curl` (CVE-2024-55591 auth-bypass URI) | manual + ProjectDiscovery | Atomic doesn't cover edge exploitation; a crafted request is cleaner, safer and reproducible. Implemented (rules 100300/301/303/304 + 100350) |
| 1 | Execution + Persistence (fileless) | ✅ **Sliver** in-memory loader (`Add-Type` → `csc.exe`) + **Sliver** `registry write` for the autostart entry | Bishop Fox | Sliver's beacon is professional in-memory execution; two different writers for the Run key on purpose, to prove the rule is writer-agnostic. Implemented (rules 100330–100332, 100333–100336 + 100338) |
| 2 | Discovery | ✅ Atomic T1046 (done) + Sliver recon | Atomic + Sliver | Implemented (rule 100320) |
| 3 | Credential Access | ✅ Atomic T1003.001 (done) | Atomic | Implemented (rules 100310/311/313) |
| 4 | Defense Evasion / BYOVD | `sc create` + a benign signed driver + **LOLDrivers** sample (load only, **no exploit**) | loldrivers.io | Safe simulation of the detectable sequence; real PoC = Ring 0 risk with zero added detection value |
| 5 | Lateral Movement | **Sliver** pivoting / **Impacket** wmiexec | Sliver / Impacket | Multiplayer + pivot far stronger than an isolated atomic |
| 6 | C2 | ✅ existing rules + **Sliver DNS C2** | existing + Sliver | Sliver's real DNS C2 exercises rules 100306/100307 for real |
| 7 | Impact | ✅ **controlled PowerShell encryptor** (throwaway directory) + **Atomic Red Team T1490 series** as an independent second tool | manual + Atomic | Two tools on purpose: the encryptor proves the *sequence*, Atomic's independent implementations exposed seven recovery-destruction binaries the first pass never invoked. Implemented (rules 100400–100415) |

**Attacker infrastructure (as built).** All offensive tooling runs on the **ThinkPad host, 10.10.10.2** — the VirtualBox host, architecturally *external* to the pfSense LAN. Nothing offensive is installed on a lab VM, so the victim's telemetry stays clean.

| Tool | Version | Role |
|---|---|---|
| Sliver C2 | v1.7.3 | C2 framework, in-memory implant, persistence via Registry API — mTLS listener on `10.10.10.2:8443`, HTTP stager on `:8080` |
| nmap | 7.95 | Port / service discovery (connect mode — no Npcap on the host) |
| Nuclei | v3.11.0 | Vulnerability probing, 5106+ templates |
| curl | native | Targeted CVE-2024-55591 auth-bypass request |

**Cross-cutting tooling:** LOLBins → native Windows binaries, with the **LOLBAS project** as the reference catalog. Fileless → **Sliver** in-memory abilities (and, for verification from the defender side, **pe-sieve / hollows_hunter** by hasherezade, which detect in-memory implants and confirm our fileless rules actually fire).

**Headline upgrade — Sliver C2 (Bishop Fox).** Professionally engineered, Go-based (same language family as GentleKiller's own encryptor), supporting DNS / HTTP(S) / mTLS / WireGuard transports, process injection, pivoting, and per-binary keys to reduce static detection. It lifts the lab from "isolated atomics" to full adversary emulation at the level real red teams operate. RAM note: the Sliver server is relatively light but should be started only when needed on this memory-tight host.

> **Safety rule for Stage 4 (BYOVD).** We never run a real BYOVD exploit. Writing our own kernel driver is also off the table — any Ring-0 code we author risks BSOD/VM corruption for zero added detection value (the detection keys on the driver-*load* event, not the exploit). We load a benign or known-listed signed driver via `sc create ... type=kernel` purely to generate the real Sysmon EID 6 telemetry, then `sc stop` + `sc delete` immediately. Prevention against real vulnerable drivers is delegated to the OS layer (see §6, L1).

---

## 5. Detection design — rules + build sources (checklist)

Each rule has a deliberately chosen *type* (behavioral / correlation / frequency / signature-hash) matched to the technique, and a global source to build from rather than reinventing.

| # | Rule | Type | Best source to build from | Status |
|---|---|---|---|---|
| 0a | Edge auth-bypass | Signature | **rule 100350 — implemented** (CVE-2024-55591 URI) | ✅ |
| 0b | Edge scan / vuln-probe (pre-exploitation recon) | Behavioral / Signature | **rules 100300 / 100301 / 100303 / 100304 — implemented** (Go-binary fingerprint, horizontal SYN scan, ET EXPLOIT attempts, nmap User-Agent) | ✅ |
| 1a | Reflective ImageLoad (unusual path) | Behavioral | elastic/protections-artifacts + Sigma `image_load` | ⏳ |
| 1b | Process hollowing (EID 1+8+10) | Correlation | SigmaHQ T1055 | ⏳ |
| 1c | Fileless loader (csc.exe from PowerShell) | Behavioral | **rule 100330 — implemented** (T1055/T1059.001) | ✅ |
| 1d | LOLBin outbound + beaconing confirm | Behavioral / Frequency | **rules 100331/100332 — implemented** | ✅ |
| 1e | Persistence: ASEP write, writer-agnostic | Behavioral | **rules 100333–100336 + 100338 — implemented** (SigmaHQ ASEP + Elastic); inherits 92300/92302 to survive Registry-API writes. 100337 reserved for persistence-correlated-with-active-C2 | ✅ |
| 1f | FP suppression: benign Base64-like reg add | Tuning | **rule 100390 — implemented** (drops 92041 on plain exe path) | ✅ |
| 2 | Scanner cmdline | Behavioral | **rule 100320 — implemented** | ✅ |
| 3 | LSASS dump | Behavioral | **rules 100310/311/313 — implemented** | ✅ |
| 4a | Driver load, unusual path/signer | Behavioral | **rules 100340–100343 — implemented** (path-anchored, NOT signer-anchored: a validly signed vulnerable driver is the technique) | ✅ |
| 4b | Kernel service install (7045) | Behavioral | **covered by Wazuh default rule 61138** — no custom rule needed | ✅ |
| 4c | Process-kill burst | Frequency | **rules 100370/100371 — implemented**; single kill is already rare here (measured 8 terminations/hour), so 100370 fires on one and 100371 catches the mass-kill shape | ✅ |
| **4d** | **BYOVD correlation (driver-load + kill-burst)** | **Correlation** | **implemented in the SOAR layer** — `if_matched_*` is built for repetition, not for chaining events of different kinds; five in-engine attempts failed and one broke the atomic rules | ✅ |
| 4e | Blocklist hash match | Hash | **dropped by decision** — the behavioural rules catch the load regardless of driver identity; a hash list only ever covers what is already catalogued | ➖ |
| 4f | Tampering with blocklist / HVCI / Credential Guard | Behavioral | **rules 100380/100381 — implemented**; fires one step *earlier* than the driver load | ✅ |
| 5 | Lateral exec inbound to siem | Behavioral | SigmaHQ T1021 + agent 002 | ⏳ |
| 6 | DNS beaconing | Rate-based | **rules 100306/307 — implemented** | ✅ |
| 7a | Recovery destruction (all paths) | Behavioral | **rules 100401/100402 + 100409–100415 — implemented**; nine rules, one per documented path (`vssadmin` delete and resize, `wmic`, PowerShell WMI, `wbadmin`, `bcdedit`, System Restore registry and scheduled task, `diskshadow`) | ✅ |
| 7b | Mass file encryption | Frequency | **rules 100405–100407 — implemented**; FIM base rule feeds a frequency rule (15 changes / 120s) plus an artifact rule on the ransom note and encrypted extension — shape and artifact, not hash | ✅ |
| 7c | Event-log clearing | Behavioral | **rule 100404 — implemented** (`wevtutil cl`, T1070.001); ticket playbook pivots the analyst to the off-host SIEM copy the local wipe cannot reach | ✅ |
| 7d | Volume enumeration | Behavioral | **rules 100400/100408 — implemented**; two channels because the same `Win32_Volume` recon surfaces as Sysmon EID 1 or PowerShell module logging (EID 4103) depending on invocation | ✅ |
| X | LOLBin out of context | Behavioral | SigmaHQ LOLBAS + GTFOBins→Wazuh | ⏳ |
| **L4** | **Resilient: agent-silence + network-alive** | **Correlation** | **rules 100359–100366 — implemented**; DNS is the liveness channel because it is the one protocol that must traverse the gateway (mTLS to the C2 host is same-subnet and invisible to the sensor — verified) | ✅ |

**The two original rules (4d and L4) are the differentiators** — they have no ready-made source because they are advanced correlation ideas:

- **4d — BYOVD correlation.** Ties a kernel driver-load (EID 6) to a process-termination burst (EID 5) inside a time window. This is the signal ESET itself named as strongest, and it catches all 8 variants because it keys on *behavior*, not driver identity.
- **L4 — Resilient detection (the surviving channel).** If the win-ep Wazuh agent goes suddenly silent *while* Suricata on pfSense still sees the host generating network traffic, that mismatch is a BYOVD-kill signature: the host is alive but the endpoint eye went dark. A powered-off machine goes quiet on both channels; a compromised one goes quiet only on the endpoint channel and stays network-alive. Crucially, Suricata lives on pfSense — **off the endpoint** — so a Ring-0 attacker on win-ep cannot touch it. This is "the detection that survives is the one with nothing to kill," and the lab topology already provides the surviving channel by design.

**Detail others miss (found in research, added here):** recent rules (Feb 2026) detect adversaries *disabling the Vulnerable Driver Blocklist / HVCI / Credential Guard themselves* via registry edits — i.e. turning off the defense **before** loading the driver. Rule **4f** covers this; it was not in the original plan.

---

## 6. Defense-in-depth — four layers

| Layer | Type | Components | Note |
|---|---|---|---|
| **L0 — Availability** | Build (unplanned) | Service-level health check outside the container, one-shot recovery, pre-flight rule validation | Added after a real 6.5-hour silent outage — a bad rule file kills the engine while the container reports healthy |
| **L1 — Prevention** | Enable, don't build | Patch management; HVCI / Memory Integrity; Microsoft Vulnerable Driver Blocklist; ASR rule "Block abuse of exploited vulnerable signed drivers"; credential hygiene | Already exists in Windows — we enable it, we don't write kernel hooks. HVCI enforces blocklist decisions in a virtualization-isolated layer a Ring-0 attacker can't disable. |
| **L2 — Detection** | Build | The behavioral rules of §5 + the cross-cutting threads | The core of our work |
| **L3 — Response** | Exists | SOAR → TheHive ticket for every detection | The layer the real victims lacked |
| **L4 — Resilient** | Build | Agent-silence + network-alive correlation (surviving channel) | Catches the kill even if L1–L3 are defeated |

### L0 — Detection availability (unplanned, added 2026-08-05)

Not in the original four-layer model, and it should have been. A malformed rule
file took `wazuh-analysisd` down entirely (CRITICAL 1220) while the container
kept reporting **Up** — Docker only supervises PID 1. Detection was down for
roughly 6.5 hours and was found by accident, not by an alert.

The engine that evaluates rules cannot alert on its own absence. So the check
runs outside the container on a 60-second timer, alerts through a log the
manager reads once healthy, and attempts exactly one restart — never a loop,
because a rule file that killed analysisd will kill it again and retrying hides
the cause.

This is the same argument as L4 applied one level down: **the layer that watches
must itself be watched from somewhere it does not control.** L4 asks whether the
endpoint agent is alive; L0 asks whether the engine consuming its telemetry is.
Rules 100395–100399, `detection/siem-health/`.

A standing procedure came with it: every rule file is validated with
`wazuh-analysisd -t` *before* the restart that would load it. It caught a syntax
error on its first use.

**Why L1 is "enable, don't build."** The idea of intercepting driver loads at the kernel and blocking unknown drivers before Ring 0 is exactly what HVCI + WDAC + the Driver Blocklist already do — proven, tested, no Ring-0 code from us. Writing our own kernel filter would be a weaker, more dangerous re-implementation. But the blocklist only catches *known* drivers; it does not stop advanced actors who weaponize a freshly disclosed PoC within days. That gap is precisely why L2 (behavioral, catches the unknown) and L4 (resilient, catches the kill) exist. Prevention is a control we *recommend in the ticket* as remediation — not something the SIEM enforces.

---

## 7. Architectural lessons (from the real breaches)

1. **Early detection without response = zero.** Defender logged the Gentlemen's activity days before impact and nothing happened — *"the audit log waved them through."* The SOAR-ticket-per-detection design is the direct countermeasure.
2. **BYOVD is a late symptom, not the disease.** It fires just before encryption, after the attacker already moved laterally and reached domain admin. Discovery and Credential Access are *earlier and more valuable* detection points — and the lab already covers them (stages 2, 3).
3. **Go + fileless + LOLBins → behavioral beats signature.** Three stacked layers of camouflage (new language, memory-only, signed system tools) blind signature-based tooling. Behavioral rules on sequence and context are the only reliable answer.
4. **The blocklist is always late.** Attackers operationalize a public PoC in days; the blocklist updates later. Hence the behavioral (4d) + resilient (L4) layers are mandatory, not optional.
5. **The failure was operational, not technical.** The initial-access CVE was patchable for months. Detection engineering complements — it does not replace — patch management and credential hygiene.

---

## 8. Implementation status

**Done:**

- Stage 0 — Initial Access: rules **100300 / 100301 / 100303 / 100304** (scan and vuln-probe detection at the edge) + **100350** (CVE-2024-55591 auth-bypass URI, Suricata→Wazuh).
- Stage 1a — Execution (fileless): rules **100330 / 100331 / 100332** (csc.exe loader, LOLBin outbound, beaconing confirm; T1055/T1059.001/T1071.001). Proven end-to-end via Sliver C2.
- Stage 1b — Persistence: rules **100333–100336 + 100338** (ASEP autostart, writer-agnostic via 92300/92302 inheritance; T1547.001). Proven against Sliver Registry-API write (image=powershell.exe, not reg.exe) — catches persistence that Wazuh's reg.exe-bound rules miss. Encoded-payload path fires 100334 (L13). FP suppression **100390** drops benign Base64-like reg-add noise (92041).
- Stage 2 — Discovery: rule **100320** (behavioral scanner-cmdline, T1046).
- Stage 3 — Credential Access: rules **100310 / 100311 / 100313** (LSASS dump, comsvcs, LOLBAS esentutl).
- Stage 4 — Defense Evasion / BYOVD: rules **100340–100343** (kernel driver load from a user-writable path — keyed on path, not signer), **100370 / 100371** (security-tooling termination, single and mass-kill shape), **100380 / 100381** (HVCI / vulnerable-driver-blocklist / Credential Guard tampering, one step earlier than the load). The driver-load↔kill **correlation (4d)** lives in the SOAR layer, not the rule engine.
- Stage 5 — Lateral Movement: rules **100210 / 100211** (successful SSH publickey login to the SIEM from outside the admin-jump allowlist; CDB `address_match_key`, detect-only on the management plane). Cross-host SOAR correlation ties it to the source host's prior high-severity alert. Root cause of the earlier "never reaches Wazuh" gap: built-in rule 5715 fires at level 3, below threshold — a classification gap, not a collection one.
- Stage 6 — C2: rules **100306 / 100307** (DNS beaconing, rate-based + allowlist).
- Stage 7 — Impact: rules **100400–100415** across five techniques — volume enumeration on two channels (**100400** Sysmon EID 1, **100408** PowerShell EID 4103), recovery destruction on nine paths (**100401 / 100402 / 100409–100415**), service stop (**100403**), event-log clearing (**100404**), and mass encryption via FIM base → frequency → artifact (**100405–100407**). Validated by two independent tools; **100411** (diskshadow) is written but untested — the binary ships only with Windows Server.
- L4 — Resilient detection: rules **100359–100366** (endpoint silence correlated with off-host network liveness — a killed agent told apart from a powered-off host).
- L0 — SIEM self-health: rules **100395–100399** (the rule engine itself stops evaluating while the container still reports Up; detected and auto-recovered).
- Response thread: SOAR → TheHive ticket per detection (all stages).

**To build (Phase 7):**
- Stage 1 (advanced) — remaining: 1a (reflective ImageLoad) + 1b (hollowing EID 1+8+10 correlation). Core fileless + persistence done; these deepen coverage.
- Cross-cutting: X (LOLBin out of context).
- L1 prevention: enable HVCI / Driver Blocklist / ASR on win-ep (recommend-in-ticket, not enforced by SIEM).

**Remaining work is deepening only.** The kill chain is closed end to end; what is left (1a, 1b, X) adds depth to stages already covered rather than opening new ground. Phase 8 — the detection-coverage engine — will measure this chain as its first subject.

---

## 9. References

**Threat intelligence — The Gentlemen / GentleKiller**
- ESET (WeLiveSecurity), *Killing me gently: Inside Gentlemen's EDR killer framework* — https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/
- The Hacker News, *The Gentlemen RaaS Uses GentleKiller EDR Framework* — https://thehackernews.com/2026/06/the-gentlemen-raas-uses-gentlekiller.html
- Huntress, *The Gentlemen Ransomware — Defense Evasion TTPs* — https://www.huntress.com/blog/the-gentlemen-ransomware-defense-evasion-ttps
- Unit 42 (Palo Alto), *No Manners Here: The Ruthless Rise of The Gentlemen* — https://unit42.paloaltonetworks.com/the-gentlemen-ransomware/
- Trend Micro, *Unmasking The Gentlemen Ransomware* — https://www.trendmicro.com/en_us/research/25/i/unmasking-the-gentlemen-ransomware.html
- Group-IB, *How Hastalamuerte Operates* — https://www.group-ib.com/blog/hastalamuerte-gentlemen-raas-ttps/
- Securonix (community), *The "Gentlemen" RaaS and the GentleKiller EDR-Killer Framework* — https://connect.securonix.com/threat-research-intelligence-62/
- Vectra AI, *From Conti to The Gentlemen: tooling evolved, gaps didn't* — https://www.vectra.ai/blog/from-conti-to-the-gentlemen-tooling-evolved-gaps-didnt

**BYOVD & EDR evasion**
- Veil Framework, *BYOVD: The Latest EDR-Killer Strategy* — https://www.veil-framework.com/byovd-bring-your-own-vulnerable-driver-the-latest-edr-killer-strategy/
- ThreatIntelReport, *BYOVD in 2026: the signed-driver loophole* — https://www.threatintelreport.com/articles/byovd-in-2026-the-signed-driver-loophole-powering-edr-bypass-at-scale/
- Deepwatch, *Building Resilient Telemetry Against EDR Silencing* — https://www.deepwatch.com/blog/when-the-lights-go-out-building-resilient-telemetry-against-edr-silencing-a-new-year-for-defense-in-depth/
- Vectra AI, *EDR evasion: techniques, breaches, defenses* — https://www.vectra.ai/topics/edr-evasion
- Elastic Security Labs, *Stopping Vulnerable Driver Attacks* — https://www.elastic.co/security-labs/stopping-vulnerable-driver-attacks
- Microsoft Learn, *Recommended driver block rules* — https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules

**Fileless / in-memory**
- Picus Security, *What Is Fileless Malware?* — https://www.picussecurity.com/resource/blog/what-is-fileless-malware
- CyberDefenders, *Fileless Malware SOC Detection* — https://cyberdefenders.org/blog/fileless-malware-soc-detection/
- Trend Micro, *Reflective Loading Runs Netwalker Fileless Ransomware* — https://www.trendmicro.com/en_us/research/20/e/netwalker-fileless-ransomware-injected-via-reflective-loading.html

**Red Team tooling**
- Bishop Fox, Sliver C2 — https://github.com/BishopFox/sliver
- Bishop Fox, *Top Red Team Tools & C2 Frameworks* — https://bishopfox.com/blog/2025-red-team-tools-c2-frameworks-active-directory-network-exploitation
- Atomic Red Team — https://github.com/redcanaryco/atomic-red-team
- MITRE CALDERA — https://github.com/mitre/caldera
- LOLBAS project — https://lolbas-project.github.io/
- hasherezade, pe-sieve / hollows_hunter — https://github.com/hasherezade/pe-sieve

**Blue Team / detection sources**
- SigmaHQ/sigma (Florian Roth) — https://github.com/SigmaHQ/sigma
- Elastic protections-artifacts — https://github.com/elastic/protections-artifacts
- Splunk security_content — https://github.com/splunk/security-content
- magicsword-io/LOLDrivers — https://www.loldrivers.io/ · https://github.com/magicsword-io/LOLDrivers
- Neo23x0/signature-base (YARA) — https://github.com/Neo23x0/signature-base
- st0pp3r/awesome-detection-engineer — https://github.com/st0pp3r/awesome-detection-engineer
- TrustedSec, Sysmon Community Guide (driver loading) — https://github.com/trustedsec/SysmonCommunityGuide

**Wazuh-specific detection references**
- Wazuh, *Ransomware protection on Windows* (rules 100615–100629) — https://wazuh.com/blog/ransomware-protection-on-windows-with-wazuh/
- Wazuh, *Detecting and responding to Funklocker ransomware* — https://wazuh.com/blog/detecting-and-responding-to-funklocker-ransomware-with-wazuh/
- Wazuh, *Detecting Gunra ransomware* — https://wazuh.com/blog/detecting-gunra-ransomware-with-wazuh/
- Wazuh, *Adversary emulation with CALDERA and Wazuh* — https://wazuh.com/blog/adversary-emulation-with-caldera-and-wazuh/

---

*Document maintained as part of the homelab-mdr project. Update as Phase 7 stages are implemented; move rows from ⏳ to ✅ with the committing rule ID.*
