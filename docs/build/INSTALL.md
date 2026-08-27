# Installation

How to build this lab from nothing. It follows the order you would actually
build in: host and network first, then the firewall, then the SIEM, then the
endpoint, then the network IDS and its collectors, then the detection content,
then the SOAR stack, and finally the coverage engine.

This document does not re-explain the architecture, the topology, or why each
detection exists — that is in the [README](../../README.md). Read the README
first; this is the build procedure, not the design.

## Conventions

- **Where a command runs** is marked at the top of each block: `# on siem`,
  `# on win-ep`, `# on pfSense`, `# on host`.
- **Download URLs** come from one place only: [`sources.md`](sources.md). If a
  URL is not there, this guide does not give you one. Several of the upstream
  projects moved their download paths; that file exists so you do not guess.
- **Versions** are the ones the lab was built and validated on
  (see [`sources.md`](sources.md)). The detection content was written against
  them.
- Steps this repository does not document are marked
  **"not documented in this repository"** rather than filled in with a
  plausible guess.

Host names, IPs, RAM and roles are in the README architecture table. The short
version: LAN `10.10.10.0/24`, pfSense `10.10.10.1`, `siem` `10.10.10.10`,
`win-ep` `10.10.10.20`, hypervisor host `10.10.10.2`.

---

## 1. Prerequisites and host sizing

One hypervisor host runs everything. Per the README, the host is Windows 11 +
VirtualBox with 16 GB RAM, and it doubles as the attacker platform.

RAM is the binding constraint. The allocations are in the README architecture
table: `siem` 5.9 GB, `win-ep` 2 GB, `pfSense` 1.5 GB. The session log records
the ceiling bluntly — **16 GB total, fully allocated** — so a new VM requires
rebalancing an existing one, and the operational rule that came out of the
Phase 6 build is to close the browser on the host before powering on `win-ep`
for an attack test.

VirtualBox is not on the host `PATH`. The session log records the exact path,
and that it must be called with the full path:

```powershell
# on host
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
```

> **Known trap (session log):** the `siem` VM name has trailing spaces
> (`"siem  "`). Address it by UUID (`8d29472a-f476-4087-833c-bb6411d195df`),
> not by name, in any scripted `VBoxManage` call.

**Verification** — VirtualBox answers and the host can see its VMs:

```powershell
# on host
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" list vms
```

---

## 2. Network layout

LAN `10.10.10.0/24`. pfSense sits in-path as the gateway (WAN via VirtualBox
NAT), with default-deny egress. The four hosts and their addresses are in the
README architecture table; the design rationale (north-south vs east-west,
why DNS is the routed C2 channel) is in the README under "Key design
decisions" and is not repeated here.

One property of this topology matters for every later verification step: hosts
on the LAN are on the same L2 segment, so same-subnet traffic is switched and
**never crosses pfSense**. The session log established this empirically rather
than by assumption, and the command it used is the cleanest proof the segment
is wired the way the design intends — run it from the endpoint once it exists:

**Verification** — `win-ep` treats the host as on-link (same segment), which is
what makes it east-west and invisible to the gateway IDS:

```powershell
# on win-ep
Get-NetNeighbor 10.10.10.2
```

Expect a resolved MAC with `State: Reachable` and `NextHop: 0.0.0.0`. The
session log's note applies: ICMP ping to the host fails (host firewall drops
it), so the ARP entry, not ping, is the truth.

---

## 3. pfSense (interactive)

**This install is interactive. It cannot be automated.** [`sources.md`](sources.md)
records this explicitly: pfSense has no unattended installer, no Vagrant box and
no container image. You assign interfaces, set LAN addressing, and install
packages by hand. The resulting `config.xml` is the source of truth and can be
exported and restored, but the first install is manual.

**Get the ISO from the URL in [`sources.md`](sources.md)** — pfSense CE 2.7.2
(amd64), and verify it against the `.sha256` that sits beside it. Do **not** use
`pfsense.org/download`; `sources.md` documents in detail why that route gives
you the wrong product (Netgate Installer → pfSense Plus).

Install steps (interface assignment, LAN addressing) are the standard pfSense
console flow and are **not documented step-by-step in this repository**. The
target end-state, which is documented, is:

- WAN on `em0` (VirtualBox NAT).
- LAN on `em1`, address `10.10.10.1/24`.
- Default-deny egress with explicit LAN allow rules.

The firewall aliases the build relies on (`siem_host`, `win_ep`,
`thinkpad_host`, `wazuh_ports`, `github_egress`, and later `soar_blocklist`)
are listed in the session log. Two packages are added to pfSense later, in
their own sections: **Suricata** (§6) and the **REST API** (§8).

> [`sources.md`](sources.md) notes agent traffic must pass the firewall on
> `1514`/`1515` between endpoint and SIEM. In this VirtualBox topology `win-ep`
> and `siem` share the LAN segment, so that traffic is switched east-west (see
> §2) rather than routed through pfSense.

**Verification** — the pfSense console summary shows the LAN interface assigned
as designed:

```text
LAN (em1)  -> v4: 10.10.10.1/24
```

---

## 4. The SIEM stack (Wazuh 4.9.0)

Manager, indexer and dashboard are Docker images — nothing to download
separately. The stack is declared in
[`siem/wazuh/docker-compose.yml`](../../siem/wazuh/docker-compose.yml)
(all three services pinned to `4.9.0`), and
[`siem/wazuh/README.md`](../../siem/wazuh/README.md) is the authoritative build
and verification note for it — this section follows it.

From the repository, on the `siem` VM:

**1. Set the stack passwords.** Copy the example env file and change every
value before the first run — the indexer password in particular has to match
what certificate generation and the dashboard expect:

```bash
# on siem, in siem/wazuh/
cp .env.example .env
# then edit .env: INDEXER_PASSWORD, WAZUH_API_PASSWORD, DASHBOARD_PASSWORD
```

The keys and their default (unsafe) values are in
[`siem/wazuh/.env.example`](../../siem/wazuh/.env.example).

> **Known trap (`siem/wazuh/README.md`):** changing `.env` alone is not enough.
> Two of those passwords also exist as bcrypt hashes in
> [`config/wazuh_indexer/internal_users.yml`](../../siem/wazuh/config/wazuh_indexer/internal_users.yml),
> which ships with Wazuh's published default hashes. If you change `.env` but
> leave the hashes, the indexer still accepts the defaults. Regenerate the
> hashes with the tool inside the indexer container and replace them in that
> file at the same time.

**2. Generate the indexer certificates — before anything else starts.** Run the
generator compose file the repository ships
([`siem/wazuh/generate-indexer-certs.yml`](../../siem/wazuh/generate-indexer-certs.yml),
service `generator`, image `wazuh/wazuh-certs-generator:0.0.2`):

```bash
# on siem, in siem/wazuh/
docker compose -f generate-indexer-certs.yml run --rm generator
```

It reads
[`config/certs.yml`](../../siem/wazuh/config/certs.yml) (which names the three
nodes the certificates are issued for) and writes the certificates into
`./config/wazuh_indexer_ssl_certs/` (git-ignored — see `.gitignore`).

> **Ordering is not optional (`siem/wazuh/README.md`).** Certificates must
> exist before `docker compose up -d`. `docker-compose.yml` bind-mounts ten
> certificate files that do not exist until the generator has run, and Docker
> answers a missing bind-mount source by silently creating a **root-owned
> directory** in its place — so the stack starts, the indexer fails TLS, and
> the cause is two steps back.

**3. Bring the manager's read-only log mounts into existence.**
`docker-compose.yml` bind-mounts three host log directories into the manager
(`/var/log/secwatch`, `/var/log/suricata-pfsense`, `/var/log/dns-analyzer`, all
`:ro`). The last two are created in §6; create the directories before first
start so the mounts resolve — the same root-owned-directory trap as the
certificates above, applied to log paths instead.

**4. Start the stack:**

```bash
# on siem, in siem/wazuh/
docker compose up -d
```

The published ports come straight from `docker-compose.yml`: manager `1514`,
`1515`, `514/udp`, `55000`; indexer `9200`; dashboard `443` → container `5601`.
`sources.md` identifies the two that matter for the endpoint: `1514/TCP` for
agent traffic and `1515/TCP` for enrollment. The dashboard is therefore at
`https://10.10.10.10`.

> **Known failure mode (session log, and this is the important one):** the
> container reporting `Up` is **not** the same as the service being alive.
> `docker ps` watches PID 1 only; a bad rule file can take `wazuh-analysisd`
> down while the container still reads `Up`. The real check is
> `wazuh-control status` (below), not `docker compose ps`. This exact failure
> cost ~6.5 hours of silent detection downtime during the build and is what the
> SIEM health monitor ([`detection/siem-health/`](../../detection/siem-health/),
> whose own deployment is outside this guide) was written to catch.

**Verification** — all three containers up, the manager's daemons actually
running (not just PID 1), and the indexer answering over TLS. These are the
checks from [`siem/wazuh/README.md`](../../siem/wazuh/README.md):

```bash
# on siem, in siem/wazuh/
docker compose ps
CID=$(docker compose ps -q wazuh.manager)
docker exec "$CID" /var/ossec/bin/wazuh-control status
curl -sk -u admin:"$INDEXER_PASSWORD" https://localhost:9200/_cluster/health
```

A single-node cluster health of `yellow` is expected (replicas cannot be
assigned with one node) and is not a fault.

---

## 5. The Windows endpoint (agent + Sysmon)

Windows 10 cannot be redistributed; `sources.md` notes you supply your own
licensed image (Microsoft's evaluation VMs are the usual lab substitute). The
endpoint is `win-ep` at `10.10.10.20`.

### 5.1 Wazuh agent

Download the **4.9.0** Windows agent from the URL in [`sources.md`](sources.md)
(the agent and manager must stay on the same minor version). Install silently
and register against the manager in one step — the exact command is in
`sources.md`:

```powershell
# on win-ep
msiexec.exe /i wazuh-agent-4.9.0-1.msi /q WAZUH_MANAGER="10.10.10.10" WAZUH_AGENT_NAME="win-ep"
NET START WazuhSvc
```

This becomes agent `001` on the manager.

> **Known issue (documented in this repository):**
> [`docs/known-issues/wazuh-agent-4.9.0-syscollector-crash.md`](../known-issues/wazuh-agent-4.9.0-syscollector-crash.md)
> records that agent 4.9.0's `syscollector.dll` throws an access violation
> during inventory scans. It self-heals in ~10s with no data loss and the
> manager keeps the agent registered — accepted, non-blocking. Do not disable
> syscollector to "fix" it; that costs the inventory the vulnerability detector
> uses.

### 5.2 Sysmon (sysmon-modular + this lab's DriverLoad override)

Get the Sysmon binary from the URL in [`sources.md`](sources.md) (validated on
v15.21). **Do not recompile the config from upstream sysmon-modular.** The file
that is actually loaded on the endpoint is the compiled
[`detection/sysmon/sysmonconfig.xml`](../../detection/sysmon/sysmonconfig.xml)
in this repository, which carries the lab's DriverLoad override; recompiling
loses it. The commands are from `sources.md`:

```powershell
# on win-ep, alongside detection/sysmon/sysmonconfig.xml
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
.\Sysmon64.exe -c        # prints the loaded config hash — compare it
```

The reason the override exists — sysmon-modular excludes validly signed
Microsoft/Intel driver loads, which is exactly the class BYOVD abuses — is in
[`detection/sysmon/driverload-override.md`](../../detection/sysmon/driverload-override.md).
The applied change is `<DriverLoad onmatch="exclude">` with an empty body (log
every driver load); selection moves into rule `9991-byovd-detection.xml` in §7.

> **Known trap (session log):** a multi-line XML comment inside a Sysmon
> include list silently kills that whole section while `Sysmon64 -c` still
> reports "Configuration validated". EID 12/13 dropped to zero and the
> persistence rules went blind. Edit the config through the XML DOM, not by
> pasting text.

### 5.3 PowerShell Script Block Logging (4104) and ASR

The README lists Script Block Logging (Event 4104), PowerShell module logging
(4103), ASR and Defender as endpoint telemetry sources feeding the agent. The
Wazuh agent collects these channels once Windows is emitting them. **The
procedure to enable 4104/4103 and the ASR rules is not documented in this
repository** — supply it from your own Windows hardening baseline.

**Verification** — service up on the endpoint, and the agent shows Active on
the manager. The endpoint-side commands are from the known-issue doc:

```powershell
# on win-ep
Get-Service WazuhSvc
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 20 | Select-String "Connected to the server"
```

```bash
# on siem, in siem/wazuh/
CID=$(docker compose ps -q wazuh.manager)
docker exec "$CID" /var/ossec/bin/agent_control -l
```

Expect `win-ep` (agent `001`) listed **Active**. Sysmon: `.\Sysmon64.exe -c`
should print the config you loaded.

---

## 6. Suricata and the collector pipeline

### 6.1 Suricata on pfSense

Suricata is **not a download** — `sources.md` records it is installed as a
pfSense package through the web interface (**System → Package Manager →
Available Packages → suricata**), validated on 7.0.8 (what the 2.7.2 package
repo provides). Configure a LAN (`em1`) instance in IDS mode with EVE JSON file
output, per the README (Phase 5) and session log.

The custom Suricata signatures live in
[`detection/suricata-rules/custom.rules`](../../detection/suricata-rules/custom.rules):
sid `1000001`/`1000002` (T1046 SYN scan), `1000003` (T1048 DNS long-subdomain),
and `100350` (CVE-2024-55591 auth-bypass URI). The broken community rule to
disable is sid `26470`, in
[`detection/suricata-rules/disablesid.conf`](../../detection/suricata-rules/disablesid.conf).
These are applied through the Suricata package's own rule/SID-management UI;
the precise menu path for pasting custom rules and disabling a SID is **not
documented step-by-step in this repository**.

> **Known caveat (session log):** rule `100350` matches `http.uri`, which TLS
> encrypts. It fires on cleartext HTTP only; over HTTPS the URI is invisible to
> Suricata. Many URI-based rules fail silently on TLS — a real detection has to
> be tested over HTTP to prove it.

### 6.2 The collector pipeline (on siem)

Two pipelines pull from pfSense's `eve.json` to the SIEM. The full data-flow
diagrams are in the README ("The Suricata → Wazuh alert pipeline" and "The DNS
behavioral C2 detection"); this is the deployment.

Both pipelines SSH to pfSense as `admin@10.10.10.1` using a dedicated key at
`/root/.ssh/id_ed25519_pfsense` (referenced in both collector scripts). Create
that key and authorize it on pfSense first.

> **Known trap (session log):** the collector scripts hard-code the source path
> `/var/log/suricata/suricata_em14846/eve.json`. That `_em14846` suffix is
> specific to *this* build's Suricata instance — the session log records that
> Suricata's config and log directory names differ per instance. A fresh
> install will generate a different suffix, so adjust `SRC` in both
> `suricata-collector.sh` and `dns-pull.sh` to match your instance's actual
> path before enabling them.

**Pipeline 1 — Suricata alerts (systemd, PULL model).** Install
[`detection/pipeline/suricata-collector.sh`](../../detection/pipeline/suricata-collector.sh)
to `/usr/local/bin/suricata-collector.sh` and
[`detection/pipeline/suricata-collector.service`](../../detection/pipeline/suricata-collector.service)
as a systemd unit (`Restart=always`, `RestartSec=5`), then enable it. Output
lands in `/var/log/suricata-pfsense/eve-alerts.json`, which the manager
bind-mounts read-only (see §4).

**Pipeline 2 — DNS queries → behavioral C2 analyzer.** Install
[`detection/pipeline/dns-pull.sh`](../../detection/pipeline/dns-pull.sh) to
`/usr/local/bin/dns-pull.sh`, the analyzer
[`detection/dns-analyzer/c2-detect.py`](../../detection/dns-analyzer/c2-detect.py)
to `/opt/dns-analyzer/c2-detect.py`, and the logrotate policy
[`detection/pipeline/dns-analyzer.logrotate`](../../detection/pipeline/dns-analyzer.logrotate)
to `/etc/logrotate.d/dns-analyzer`. Output (`dns-queries.stream`, `alerts.json`)
lands in `/var/log/dns-analyzer`, also bind-mounted into the manager.

For the cron schedule, use
[`soar/scripts/cron-dns-pipeline`](../../soar/scripts/cron-dns-pipeline), **not**
[`detection/pipeline/dns-pull.cron`](../../detection/pipeline/dns-pull.cron):
the plain `dns-pull.cron` runs the pull only, and the SOAR-phase fix runs
`dns-pull.sh && c2-detect.py` together every minute. Install it to
`/etc/cron.d/`.

> **Known failure mode (session log):** the original cron ran the pull but not
> the analyzer, so beacons were collected and never scored and `100306` never
> fired automatically. That is exactly why `cron-dns-pipeline` chains both. A
> matching trap: the DNS analyzer state is a byte offset in
> `/var/log/dns-analyzer/.last_size`, and `dns-pull.sh` resets it if the remote
> file shrank (logrotate `copytruncate`).

> **Known failure mode (session log):** a remote `tail -F` does **not** die when
> the SSH session is killed from the siem side — it survives under a detached
> shell. That is the cause of stale-tail accumulation, which is why
> `suricata-collector.sh` runs `pkill -x tail` (exact name only) before
> starting its own tail. Two persistent-tail collectors on the same file would
> kill each other, which is why Pipeline 2 is a batch byte-offset pull, not a
> second tail.

> **Known trap (session log, DNS analyzer):** on Python 3.10,
> `datetime.fromisoformat()` rejects Suricata's `+0300` timezone offset (no
> colon), silently filtering every query to zero alerts while exiting 0. The
> shipped analyzer inserts the colon before parsing. If you port it, unit-test
> `parse_ts` on a real timestamp before trusting a "clean" run.

**Verification** — the alert collector is up and (the point of `pkill -x tail`)
exactly one real tail is running on pfSense:

```bash
# on siem
systemctl status suricata-collector
```

```sh
# on pfSense
ps -axo command= | grep -c '^tail -F'
```

Expect `active (running)` on the siem and a count of `1` on pfSense. To prove
alerts flow end to end, run an nmap scan from `win-ep` **across** pfSense (to
`10.10.10.1`, not east-west) and watch `/var/log/suricata-pfsense/eve-alerts.json`
grow — the session log confirms this fires Suricata sid `1000001` → Wazuh rule
`100301`.

---

## 7. Custom rule deployment

**This is the section most likely to silently not work, so read it carefully.**

The Wazuh manager's rules directory is a **named Docker volume (`wazuh_etc`,
declared in `docker-compose.yml`), not a host bind mount.** The repository is a
working copy. Editing the rule files in the repo, or writing them under the
host `config/wazuh_cluster/` path, does **not** put them in
`/var/ossec/etc/rules/` inside the container — that host path is only mounted
onto `ossec.conf`. Rules and CDB lists must be written **into the container**.

The custom rule files are in
[`detection/wazuh-rules/`](../../detection/wazuh-rules/); the numeric prefix is
load order, and the README repository-layout section maps each file to its rule
IDs. The CDB allowlist is
[`detection/wazuh-rules/lists/siem-ssh-allowlist`](../../detection/wazuh-rules/lists/siem-ssh-allowlist)
(contents: `10.10.10.2:` and `127.0.0.1:`).

### 7.1 Copy the rule files into the container and fix ownership

The session log is explicit that ownership must match the shipped rule files or
the file is silently unreadable by `analysisd`/`wazuh-logtest`
(`WARNING (1103): Could not open file ... Permission denied` → rule not loaded,
no match). Copy each file in, then `chown wazuh:wazuh`:

```bash
# on siem, in siem/wazuh/
CID=$(docker compose ps -q wazuh.manager)

# rules
docker cp ../../detection/wazuh-rules/9997-suricata-mitre.xml "$CID":/var/ossec/etc/rules/
docker exec "$CID" chown wazuh:wazuh /var/ossec/etc/rules/9997-suricata-mitre.xml
docker exec "$CID" chmod 660 /var/ossec/etc/rules/9997-suricata-mitre.xml
# ...repeat for every 99xx-*.xml in detection/wazuh-rules/
```

> **Mode is `660`, owner `wazuh:wazuh` — for both rules and lists.** Every
> deployed file in `/var/ossec/etc/rules/` and `/var/ossec/etc/lists/` is
> `-rw-rw---- wazuh:wazuh`, verified against the running manager. (The `644` in
> the Phase 5 session-log entry is an error.) Wrong ownership or mode makes the
> file silently unreadable by `analysisd` — the rule or list is not loaded and
> nothing matches. Confirm after copying:
>
> ```bash
> docker exec "$CID" ls -l /var/ossec/etc/rules/ /var/ossec/etc/lists/ | head -20
> ```

### 7.2 Install the CDB allowlist

The allowlist backs the SIEM-login suppression rule (`100211`). Copy it into
the container's lists directory and `chown` it the same way:

```bash
# on siem, in siem/wazuh/
docker cp ../../detection/wazuh-rules/lists/siem-ssh-allowlist "$CID":/var/ossec/etc/lists/
docker exec "$CID" chown wazuh:wazuh /var/ossec/etc/lists/siem-ssh-allowlist
docker exec "$CID" chmod 660 /var/ossec/etc/lists/siem-ssh-allowlist
```

The list must be **registered** in `ossec.conf`, and it already is:
[`siem/wazuh/config/wazuh_cluster/wazuh_manager.conf`](../../siem/wazuh/config/wazuh_cluster/wazuh_manager.conf)
carries `<list>etc/lists/siem-ssh-allowlist</list>` in its `<ruleset>` block.
The **registration** persists across restarts because `wazuh_manager.conf` is
bind-mounted from the host — the entrypoint copies it over the container's
`ossec.conf` on every start. The **list file itself does not**: it lives in the
named volume, which is exactly why the `docker cp` above is required, and a
container rebuild loses it and needs it re-copied. Note (session log):
`wazuh-makelists` no longer exists in 4.9; CDB compilation is folded into the
rule-load path, so the list compiles on the manager restart below.

### 7.3 Validate, then reload

Always validate before the restart that would load the files. The session log's
standing procedure — and its warning that the exit code lies:

```bash
# on siem, in siem/wazuh/
docker exec "$CID" /var/ossec/bin/wazuh-analysisd -t
```

> **Trap (session log):** `wazuh-analysisd -t` exits `0` even on a CRITICAL
> error — read the output text, not the exit code. An *empty* `-t` result means
> the rule file is not being read at all (wrong directory). And a single bad
> rule file takes down the whole engine, not just its own file.

Then reload. The session log found `docker compose restart` more reliable than
`wazuh-control restart` after rule changes:

```bash
# on siem, in siem/wazuh/
docker compose restart
```

**Verification** — the rule is present in the container (the exact check from
the session log), and validation is clean:

```bash
# on siem, in siem/wazuh/
docker exec "$CID" grep -c 'id="100306"' /var/ossec/etc/rules/9997-suricata-mitre.xml
docker exec "$CID" /var/ossec/bin/wazuh-analysisd -t
```

Expect a non-zero count for the rule and no error text from `-t`. For a
logic-level check on a specific rule, `wazuh-logtest` inside the container works
on the rule as loaded (it also surfaces the `Could not open file` permission
error if ownership is wrong).

---

## 8. The SOAR stack

Four pieces: n8n (workflows), the pfSense REST API (containment), Cortex
(enrichment), and TheHive (case management). Each runs from its own compose file
under [`soar/`](../../soar/); the pipeline design is in the README (Phase
6-A/6-B/6-C) and is not repeated here.

> **Known failure mode across this whole section (session log):** default-deny
> egress blocks Docker Hub, so pulling these images needs a temporary pfSense
> egress rule (siem → any:443), disabled again afterward. And Cortex fetches
> its analyzer catalog from StrangeBee over the internet **at boot** — a cold
> boot while egress is still choked silently empties the analyzer catalog; the
> fix was `docker compose restart cortex` once the network was healthy.

### 8.1 n8n and the Wazuh → n8n integration

Start n8n from
[`soar/n8n/docker-compose.yml`](../../soar/n8n/docker-compose.yml) (image
`n8nio/n8n:2.30.4`, bound to `10.10.10.10:5678` only):

```bash
# on siem, in soar/n8n/
docker compose up -d
```

Import the two workflows into n8n —
[`wazuh-soar-triage.json`](../../soar/n8n/wazuh-soar-triage.json) (alert →
enrich → contain → classified ticket) and
[`phishing-triage-cortex-enrichment.json`](../../soar/n8n/phishing-triage-cortex-enrichment.json).
The import is via the n8n UI; the precise UI steps are **not documented in this
repository**, but the session-log rule is: in n8n, **Publish = save + activate**,
and the production webhook (`/webhook/...`) only works after Publish.

Wire Wazuh to n8n: install the forwarder
[`soar/wazuh-integration/custom-n8n`](../../soar/wazuh-integration/custom-n8n)
into the manager at `/var/ossec/integrations/`, and add the `<integration>`
block from
[`soar/wazuh-integration/ossec-integration-block.xml`](../../soar/wazuh-integration/ossec-integration-block.xml)
to `ossec.conf`. It is **already present** in
[`wazuh_manager.conf`](../../siem/wazuh/config/wazuh_cluster/wazuh_manager.conf)
(name `custom-n8n`, `hook_url http://10.10.10.10:5678/webhook/wazuh-alert`,
`level 10`, `alert_format json`). The `level 10` filter forwards **any** alert
≥ 10 — new high-severity detections reach the SOAR automatically, with no
per-rule wiring.

### 8.2 pfSense REST API (containment path)

Install **pfSense-pkg-RESTAPI v2.4.3** on pfSense (session log: v2.4.3 is the
newest stable that ships a 2.7.2 CE package; later releases dropped 2.7.2). No
URL for it is in `sources.md`, so this guide does not give one. Configure per
the session log: Auth = API Key, Login Protection on, Read-Only off, **Allowed
Interfaces = LAN only** (never expose the firewall API to WAN). Create the
`soar_blocklist` alias (host type) and a block rule sourcing it, kept
**disabled (dry-run)** by default.

The blocker is
[`soar/scripts/soar-block.py`](../../soar/scripts/soar-block.py) — install it to
`/opt/soar/` and give it the API key via the `PF_API_KEY` environment variable
(the session log keeps the key as an n8n credential, never in the exported
workflow). Its built-in safety controls are the infrastructure allowlist
(`10.10.10.1`, `10.10.10.10`, `10.10.10.2` are never blockable) and a circuit
breaker (5 blocks / 10-minute window), both visible in the script.

> **API mechanics that cost time (session log):** the API rejects the default
> multi-value `Accept` header — you must send `Accept: application/json`
> ("No content handler exists" otherwise). PATCH/DELETE need the object `id` in
> the JSON body, not the query string. `POST /firewall/apply` is async: it
> returns `applied:false` immediately, then `true` after a few seconds — not an
> error.

### 8.3 Cortex + Elasticsearch

Start from [`soar/cortex/docker-compose.yml`](../../soar/cortex/docker-compose.yml)
(Cortex pinned by digest, Elasticsearch `7.17.28`, both heap-capped). Per
[`soar/cortex/README.md`](../../soar/cortex/README.md), **generate a real
`play.http.secret.key`** in
[`soar/cortex/application.conf`](../../soar/cortex/application.conf) first — the
committed value is the placeholder `CHANGE_ME_GENERATE_A_SECRET`:

```bash
# on siem, in soar/cortex/
# edit application.conf: replace CHANGE_ME_GENERATE_A_SECRET with a real key
docker compose up -d
```

Cortex UI is on `9001`. Two hard-won points from the Cortex README: the
`/opt/cortex/jobs` bind mount **must be identical host↔container** (Cortex hands
that path to the host Docker daemon when spawning analyzer containers), and a
super-admin cannot run analyzers — create an org and an org-admin, and enable
analyzers per-org. The nine enabled analyzers are listed in the Cortex README.

### 8.4 TheHive 5

Start from [`soar/thehive/docker-compose.yml`](../../soar/thehive/docker-compose.yml)
(`strangebee/thehive:5.4`, local mode: BerkeleyDB + Lucene, no Cassandra). The
config is [`soar/thehive/application.conf`](../../soar/thehive/application.conf).

> **Known failure mode (session log):** the named volumes are born root-owned
> and TheHive will not start on them. `chown -R 1000:1000` the volumes before
> the first start.

> **Known trap (session log):** the StrangeBee Community license allows 2 users
> / 1 org / 1 Cortex / 1 MISP. The n8n service account (`svc-n8n`) **must** be
> created as type **Service** so it does not consume a user seat. A separate,
> nastier one: VMs resumed from saved state froze the clock days behind, and
> TheHive rejected a valid license as "expired" while `timedatectl` still
> claimed it was synchronized. The rule the build adopted: **the SIEM always
> cold-boots**, with pfSense as the LAN NTP source, and time is verified
> empirically after every boot.

**Verification** — the SOAR services are up, and n8n's webhook answers on the
LAN interface:

```bash
# on siem
docker compose -f soar/n8n/docker-compose.yml ps
docker compose -f soar/cortex/docker-compose.yml ps
docker compose -f soar/thehive/docker-compose.yml ps
```

End-to-end (the way the session log validated it): trigger a real level ≥ 10
detection on `win-ep` and confirm it produces an n8n execution and a ticket —
the integration is threat-category-agnostic, so any high-severity rule proves
the path. Cortex UI on `9001`, TheHive UI on `9000`.

---

## 9. The coverage engine (Phase 8)

Measures what the detections actually catch by running techniques against the
live stack and grading what the SIEM produced. It runs from
[`detection/coverage-engine/`](../../detection/coverage-engine/); the
methodology and the five-outcome grading scale are in its
[README](../../detection/coverage-engine/README.md) and are not repeated here.

It drives `win-ep` over **WinRM**, so WinRM must be reachable on the endpoint.
Configure credentials by copying the example env file
([`detection/coverage-engine/.env.example`](../../detection/coverage-engine/.env.example),
git-ignored):

```bash
# on siem, in detection/coverage-engine/
cp .env.example .env
# then fill WINEP_HOST/USER/PASS and INDEXER_URL/USER/PASS
```

The four programs and their sequence come straight from the coverage-engine
README:

```bash
# on siem, in detection/coverage-engine/
python runner.py chains/atomic-automated.yml            # execute over WinRM
python scorer.py results/run-atomic-automated-<stamp>.json   # grade
python navigator.py results/score-atomic-automated-<stamp>.json   # ATT&CK layer
python report.py    results/score-atomic-automated-<stamp>.json   # scorecard
```

The chain that ships is
[`chains/atomic-automated.yml`](../../detection/coverage-engine/chains/atomic-automated.yml).
Execution and scoring are separate on purpose, so a chain can be re-graded after
a rule change without re-running the attack. **Python dependency installation
(WinRM client and friends) is not documented in this repository** — set up the
virtualenv and packages from the imports in the scripts.

**Verification** — a scored run renders an auditable scorecard:

```bash
# on siem, in detection/coverage-engine/
python report.py results/score-atomic-automated-<stamp>.json
```

The repository already contains a committed example run to compare against
([`results/scorecard-atomic-automated.md`](../../detection/coverage-engine/results/scorecard-atomic-automated.md)
and the SVG heatmap the README links).
