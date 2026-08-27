# Custom Wazuh rules

72 rules across 15 files. Every one was written for this lab, mapped to a
technique, and verified firing against a real execution of that technique — not
adapted from a ruleset and left untested.

## Reading order

The numeric filename prefix is **load order**, counting down: `9999` loads
first, `9985` last. Wazuh evaluates in that order, which matters when one rule
inherits from another. Rule IDs are namespaced by area, so an ID tells you
where it lives.

| File | Rule IDs | Area |
| --- | --- | --- |
| `9985-impact.xml` | 100400–100415 | Impact: recovery destruction, encryption, log clearing |
| `9986-lateral-movement.xml` | 100210–100211 | Unauthorized SIEM login, allowlist-suppressed |
| `9987-siem-health.xml` | 100395–100399 | The detection engine dying silently |
| `9988-ci-tampering.xml` | 100380–100381 | HVCI, driver blocklist, Credential Guard |
| `9989-edr-killer.xml` | 100370–100371 | Security tooling terminated |
| `9990-secwatch.xml` | 100359–100366 | The surviving channel (agent silence vs network alive) |
| `9991-byovd-detection.xml` | 100340–100343 | Kernel driver load from a user-writable path |
| `9992-fp-suppression.xml` | 100390 | Surgical false-positive tuning |
| `9993-persistence-detection.xml` | 100333–100338 | ASEP autostart, writer-agnostic |
| `9994-fileless-c2-detection.xml` | 100330–100332 | In-memory loader, LOLBin outbound, beaconing |
| `9995-credential-access.xml` | 100310–100313 | LSASS, Mimikatz, browser credential stores |
| `9996-endpoint-discovery.xml` | 100320 | Scanner command line |
| `9997-suricata-mitre.xml` | 100300–100308 | Suricata alerts, DNS behaviour, edge CVE |
| `9998-siem-self-monitoring.xml` | 100200–100208 | Tampering with the monitoring stack |
| `9999-windows-powershell.xml` | 100100–100102 | PowerShell 4104 obfuscation |

`lists/siem-ssh-allowlist` is a CDB list, not a rule file. It is registered in
`ossec.conf` under `<ruleset>` and compiles on manager restart —
`wazuh-makelists` was removed in 4.9.

## How these are written

**Suppression, not omission.** The allowlist pattern in `9986` is the shape to
copy: one rule fires on the whole class of event at a high level, a second
drops it to level 0 when the source is expected. The alternative — narrowing
the first rule so it never sees expected traffic — hides the tuning decision
inside a condition. Here it is a visible, auditable list.

**Inheritance over duplication.** Rules chain from built-in ones with `if_sid`.
`100210` inherits `5715`, which already decodes `sshd` successful logins
correctly; the custom rule only changes the *level*, because the earlier gap
was a classification problem, not a collection one. Chain from a rule proven
to fire on real events — `decoded_as windows_eventchannel` does not match live
Sysmon events, and copying a working rule's chaining exactly is faster than
debugging why a plausible one is silent.

**Behaviour over identity where the technique allows it.** The BYOVD rules key
on driver *path*, not signer, because a validly signed vulnerable driver is the
technique rather than an exception to it. The encryption rule keys on the
modification burst, not on a file hash or extension alone.

## Deploying a change

The rules directory is a **named Docker volume**, not a bind mount. Editing a
file here does not change what the manager loads. Copy into the container, fix
ownership and mode, validate, restart — the full procedure with its failure
modes is in [`docs/build/INSTALL.md`](../../docs/build/INSTALL.md) §7.

Two things that will cost time if skipped: `wazuh-analysisd -t` exits `0` even
on a CRITICAL error, so read the output text rather than the exit code; and an
*empty* `-t` result means the file is not being read at all.
