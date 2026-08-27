# References

Two kinds of source appear below, and the distinction is deliberate.

The first section lists sources that **shaped detection content in this
repository** — for each one, what was taken from it and which rule or file the
result lives in. Those entries are traceable: open the rule, open the source,
and the relationship is visible.

The second section lists sources consulted during research that did not end up
driving a specific rule. They are recorded because they are the right places to
continue from, not because work here derives from them.

---

## Sources this repository builds on

### Threat intelligence — The Gentlemen / GentleKiller (Storm-2697)

The Phase 7 attack chain is not invented. Every stage is modelled on reporting
about a real 2026 ransomware operation, which is why the emulation sequence has
the shape it does rather than a shape chosen for convenience.

| Source | What was taken | Where it lives |
| --- | --- | --- |
| ESET (WeLiveSecurity), *Killing me gently: inside Gentlemen's EDR killer framework* | The central defensive finding — that a blocklist cannot hold against eight swappable driver variants, and that the strongest available signal is a **kernel driver load correlated with a process-termination burst**. This is the reason the BYOVD detection is a correlation in the SOAR layer rather than a driver-identity rule. | n8n BYOVD correlation node; `9991-byovd-detection.xml`, `9989-edr-killer.xml` |
| ESET; Huntress, *The Gentlemen ransomware — defense evasion TTPs* | Initial access via Fortinet edge exploitation (CVE-2024-55591), and the operators' habit of staging tooling in user-writable paths. The driver rule keys on **path, not signer**, because of this. | Suricata sid `100350` → `100308`; `9991-byovd-detection.xml` (100340–100343) |
| Microsoft Security (Storm-2697); AttackIQ, *Emulating the Gentlemen*; Trend Micro; Unit 42 | The Impact sequence in execution order: volume enumeration via `Win32_Volume` → shadow-copy deletion by **two** distinct paths (`vssadmin` and `wmic`) → service stop → in-place encryption → `wevtutil cl`. The controlled encryptor reproduces this order step by step, each step as its own process so Sysmon records a real command line. | `9985-impact.xml` (100400–100408); Phase 7-F attack script |
| Same reporting | Artifacts used as detection anchors: the `.umc16h` encrypted extension and the `README-GENTLEMEN.txt` ransom note. Note these are the *weakest* tier of the detection — they are there as a fast confirmation signal beside the frequency rule, which is the one that survives an actor changing both. | `9985-impact.xml` (100406, 100407) |

### Detection content

| Source | What was taken | Where it lives |
| --- | --- | --- |
| Wazuh, *Ransomware protection on Windows* (official rules 100615–100629) | The starting structure for the Impact ruleset — specifically the FIM-frequency approach to mass encryption (a burst of modifications in a window) rather than per-file matching. Adapted, not copied: thresholds were set against measured behaviour in this lab, and the recovery-destruction coverage was extended well past the original. | `9985-impact.xml` (100405 frequency rule) |
| Wazuh, *Detecting Funklocker* and *Detecting Gunra ransomware* | Confirmation that the same detection shape generalises across ransomware families, which is why the Impact rules key on behaviour common to the class rather than on GentleKiller specifics. | `9985-impact.xml` design |
| Red Canary, **Atomic Red Team** — T1490 series | Used as an **independent second implementation** of techniques already covered, not as a source of rules. Replaying T1490 through Atomic's binaries invoked six recovery-destruction paths the hand-written encryptor never touched — `wbadmin delete catalog`, `bcdedit` recovery disable, PowerShell WMI shadow deletion, System Restore scheduled-task and registry disable, and `vssadmin resize shadowstorage`. Every one was undetected on first run. | `9985-impact.xml` (100409–100415) — these seven rules exist only because a second tool was used |
| **LOLBAS project** | The catalogue that identified `comsvcs.dll` MiniDump and `esentutl` as credential-access paths through signed, trusted binaries — the reason those detections key on command line rather than on binary reputation. | `9995-credential-access.xml` (100311, 100313) |
| **magicsword-io / LOLDrivers** | The reference list of known-abusable signed drivers, used to select a realistic driver sample for the BYOVD stage. The driver is **loaded only** — never exploited — because the detection keys on the load event, and running real Ring-0 exploit code would add risk without adding signal. | Phase 7-D staging; `detection/sysmon/` DriverLoad override |
| **Bishop Fox — Sliver C2** | The C2 framework used for Phases 7-B, 7-C and 7-E. The important detail for detection: Sliver's `registry write` persists through the Windows Registry API from inside the implant, so Sysmon records `image=powershell.exe` and every built-in Run-key rule bound to `reg.exe` goes silent. The persistence rule was written to be **writer-agnostic** because of this. | `9993-persistence-detection.xml` (100334, 100336) |

---

## Consulted, not built on

These were read during research and are the natural places to extend from. No
rule in this repository is derived from them.

**Threat intelligence**
- The Hacker News — https://thehackernews.com/2026/06/the-gentlemen-raas-uses-gentlekiller.html
- Group-IB, *How Hastalamuerte operates* — https://www.group-ib.com/blog/hastalamuerte-gentlemen-raas-ttps/
- Securonix community write-up — https://connect.securonix.com/threat-research-intelligence-62/

**Detection rule repositories**
- SigmaHQ / sigma — https://github.com/SigmaHQ/sigma
- Elastic protections-artifacts — https://github.com/elastic/protections-artifacts
- Splunk security-content — https://github.com/splunk/security-content
- Neo23x0 / signature-base (YARA) — https://github.com/Neo23x0/signature-base
- st0pp3r / awesome-detection-engineer — https://github.com/st0pp3r/awesome-detection-engineer

**Platform and hardening documentation**
- Microsoft, recommended driver block rules — https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules
- TrustedSec, Sysmon Community Guide — https://github.com/trustedsec/SysmonCommunityGuide
- Elastic Security Labs, *Stopping vulnerable driver attacks* — https://www.elastic.co/security-labs/stopping-vulnerable-driver-attacks

**Adjacent tooling and technique background**
- MITRE CALDERA — https://github.com/mitre/caldera
- hasherezade, pe-sieve / hollows_hunter — https://github.com/hasherezade/pe-sieve
- Deepwatch, *Building resilient telemetry against EDR silencing* — https://www.deepwatch.com/blog/when-the-lights-go-out-building-resilient-telemetry-against-edr-silencing-a-new-year-for-defense-in-depth/
- CyberDefenders, *Fileless malware SOC detection* — https://cyberdefenders.org/blog/fileless-malware-soc-detection/
- Bishop Fox, *Top red team tools and C2 frameworks* — https://bishopfox.com/blog/2025-red-team-tools-c2-frameworks-active-directory-network-exploitation

---

The Phase 7 design document (`docs/phase7-attack-scenario.md`) carries the full
research bibliography from the planning stage, including sources evaluated and
rejected.
