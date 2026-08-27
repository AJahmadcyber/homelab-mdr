# Verified download sources

Every URL below was checked rather than recalled. Versions are the ones this
lab was actually built and validated on, not the newest available — the
detection content was written against these, and a newer build may behave
differently.

Anyone writing installation documentation from this repository should treat
this file as the only source of download URLs. Do not construct a plausible
URL from a version number; several of the projects below moved or restructured
their download paths, which is exactly why this file exists.

---

## pfSense CE 2.7.2 (amd64)

**Use this URL:**
https://atxfiles.netgate.com/mirror/downloads/pfSense-CE-2.7.2-RELEASE-amd64.iso.gz

Size 574,277,009 bytes. A matching `.sha256` file sits beside it in the same
directory — verify before installing.

**Do not send anyone to `pfsense.org/download`.** Since May 2024 that page
requires a store account and redirects to the Netgate Installer, which needs
internet access during installation and installs pfSense **Plus**, not CE. The
symptom is a file named `netgate-installer-*.iso` and a boot screen reading
"pfSense +". This is a documented and frequently reported trap, not an edge
case. The mirror above is hosted by Netgate themselves, so it is the official
source, not a third-party rehost.

Directory index (for other versions): https://atxfiles.netgate.com/mirror/downloads/

---

## Wazuh 4.9.0

Manager, indexer and dashboard are Docker images and need no download step —
see `siem/wazuh/docker-compose.yml`.

**Windows agent (endpoint, version 4.9.0 to match the manager):**
https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0-1.msi

Silent install, registering against the manager in one step:

```powershell
msiexec.exe /i wazuh-agent-4.9.0-1.msi /q WAZUH_MANAGER="10.10.10.10" WAZUH_AGENT_NAME="win-ep"
NET START WazuhSvc
```

Agent and manager should stay on the same minor version. The manager listens on
1514/TCP for agent traffic and 1515/TCP for enrollment; both must pass the
firewall between endpoint and SIEM.

Linux agent packages (for the SIEM self-monitoring agent, 002):
https://packages.wazuh.com/4.x/apt/ — see Wazuh's install guide for the repo
key and sources-list step.

---

## Sysmon

**Binary** — Sysinternals, always the current release:
https://download.sysinternals.com/files/Sysmon.zip

Validated on **v15.21**. Sysmon is backward compatible with older configuration
schemas, so a newer binary is normally safe, but the schema version declared at
the top of the config should be checked against `Sysmon64.exe -? config`.

**Configuration base** — olafhartong's sysmon-modular:
https://github.com/olafhartong/sysmon-modular

The compiled `sysmonconfig.xml` in `detection/sysmon/` is the file actually
loaded on the endpoint, including this lab's DriverLoad override. Use that file
directly rather than recompiling from upstream, or the override is lost. The
reasoning for the override is in `detection/sysmon/driverload-override.md`.

Install and verify:

```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
.\Sysmon64.exe -c        # prints the loaded config hash — compare it
```

---

## Suricata

Not downloaded. Installed as a pfSense package through the web interface:
**System → Package Manager → Available Packages → suricata**. Validated on
**7.0.8**, which is what the 2.7.2 package repository provides.

---

## Attack tooling (attacker host only — never on a lab VM)

| Tool | Version | Source |
| --- | --- | --- |
| Sliver C2 | v1.7.3 | https://github.com/BishopFox/sliver/releases |
| Ligolo-ng | 0.8.2 | https://github.com/nicocha30/ligolo-ng/releases |
| Atomic Red Team | atomics tree | https://github.com/redcanaryco/atomic-red-team |
| nmap | 7.95 | https://nmap.org/download.html |
| Nuclei | v3.11.0 | https://github.com/projectdiscovery/nuclei/releases |

Two operational notes that cost time to discover:

**Sliver on Windows** writes temporary files during implant compilation to a
protected directory and fails. Set `TMP` and `TEMP` to a writable path such as
`C:\tmp` before starting the server; `GOTMPDIR` is ignored, because the failure
is in a subprocess.

**Ligolo-ng** needs `wintun.dll` beside `proxy.exe`, Administrator rights, a
single agent process, and a route metric of 1 on the tunnel interface.

---

## What is not automatable

Recorded here so installation documentation does not promise it.

**pfSense** has no unattended installer, no Vagrant box and no container image.
Installation is interactive: interface assignment, LAN addressing, then the
REST API package. The resulting configuration is exported and committed, so it
can be restored, but the first install is manual.

**Windows 10** cannot be redistributed. A reader supplies their own licensed
image; Microsoft's evaluation VMs are the usual substitute for a lab.

Everything else — the SIEM stack, the SOAR stack, rule deployment, collectors
and the coverage engine — is scripted or declared in this repository.
