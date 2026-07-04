# Homelab MDR — Session Log (Day 1-2)

> Build journal: من الفكرة لـ Wazuh stack شغّال + أول endpoint متصل.

**Date range:** June 18-21, 2026
**Status:** Phase 1 + 2 done. Snapshots taken: `wazuh-stack-deployed`, `post-hardening`, `agent-connected`
**GitHub:** `https://github.com/AJahmadcyber/homelab-mdr`

---

## TL;DR — وين وصلنا

| Component | Status | Details |
|---|---|---|
| Host hardware | ✅ | 16 GB RAM، 263 GB free SSD، VirtualBox 7.x، Windows 11 |
| siem VM (Ubuntu 22.04) | ✅ | 9 GB RAM، 120 GB، 192.168.56.10 |
| win-ep VM (Windows 10) | ✅ | 2 GB RAM، 60 GB، 192.168.56.20 |
| Network topology | ✅ | Host-only `vboxnet0` (192.168.56.0/24) + NAT للإنترنت |
| Docker + Compose | ✅ | 29.5.3 + Compose v2.5.1.4 |
| Wazuh stack | ✅ | Manager + Indexer + Dashboard (v4.9.0) shealthy |
| Hardening | ✅ | UFW, fail2ban, SSH hardening, ISM 90d retention |
| GitHub repo | ✅ | README + architecture.svg + LICENSE + .gitignore |
| Wazuh agent (win-ep) | ✅ | Registered ID 001، Status: Active |

---

## القرارات الجوهرية (Locked Decisions)

| # | Decision | Rationale |
|---|---|---|
| 1 | **Branding** = "SOC Detection Engineering Lab" مش "MDR" | يفصل الـ portfolio عن الـ MDR Model A التجاري للشركة |
| 2 | **Public GitHub repo** | للـ scholarship applications + recruiters |
| 3 | **Stack chosen** = Wazuh + TheHive 5 + Cassandra + Cortex + n8n + pfSense + Suricata | Industry-standard MSSP equivalent، replicates $50K commercial stack |
| 4 | **No Telegram alerts** | personal lab، Dashboard + TheHive كافي |
| 5 | **No attacker VM** | الهجمات من الـ Windows host (WSL2 + nmap/hydra/etc) |
| 6 | **Kali** = Powered Off دائما | محفوظ للسيناريوهات اللي تحتاج adversary tools (Empire, BloodHound) |
| 7 | **Network** = Host-only adapter واحد للكل (192.168.56.0/24) | Internal Network كان buggy بإصدار VirtualBox عندي |
| 8 | **ISM retention** = 90 days hot → delete | يمنع امتلاء الـ disk من الـ 108GB/day self-monitoring writes |
| 9 | **DOCKER-USER iptables rule** | يبلوك inbound من NAT interface (enp0s8) — يمنع Docker bypass للـ UFW |
| 10 | **Wazuh agent enrollment** = IP literal بـ UTF-8 no-BOM | bug في 4.9.0 على Windows مع hostname resolution |

---

## Architecture (الحالي)

```
                          ThinkPad (Host - 16 GB)
                                  |
                  vboxnet0 (Host-only) 192.168.56.0/24
                          |                |
              ┌───────────┴────┐    ┌──────┴──────┐
              | siem VM         |    | win-ep VM   |
              | 192.168.56.10   |    | 192.168.56.20|
              |                 |    |             |
              | Wazuh Manager   |←───┤ Wazuh Agent |
              | + Indexer       |1514| (ID 001)    |
              | + Dashboard     |    |             |
              | Docker Compose  |    | Sysmon (TBD)|
              |                 |    | ASR  (TBD)  |
              | UFW + fail2ban  |    | 4104 (TBD)  |
              | enp0s3 + enp0s8 |    | NAT NIC2    |
              └─────────────────┘    └─────────────┘
                       |                    |
                     enp0s8                  Ethernet 2
                       └────────NAT─────────┘
                         (internet only)
```

---

## Stack الكامل (المخطط)

```
Layer              Tool                         Status
─────────────────────────────────────────────────────────
SIEM               Wazuh Manager 4.9.0          ✅ Running
Search             Wazuh Indexer (OpenSearch)   ✅ Running, 4GB heap
UI                 Wazuh Dashboard              ✅ Running, port 443
Win telemetry      Sysmon + sysmon-modular      ⏳ Phase 3
Win telemetry      PowerShell 4104 + ASR        ⏳ Phase 3
Win telemetry      Defender Operational log     ⏳ Phase 3
Case mgmt          TheHive 5 + Cassandra        ⏳ Phase 4
Enrichment         Cortex + analyzers           ⏳ Phase 4
SOAR               n8n                          ⏳ Phase 4
Network IDS        pfSense + Suricata           ⏳ Phase 5
Detection rules    Wazuh + Sigma + YARA         ⏳ Phase 5
```

---

## شغّال هلأ على siem (services)

```
- docker-ce 29.5.3 (auto-start enabled)
- single-node-wazuh.manager-1     (port 1514, 1515, 514/udp, 55000)
- single-node-wazuh.indexer-1     (port 9200)
- single-node-wazuh.dashboard-1   (port 443)
- ssh.service                     (port 22, hardened)
- fail2ban.service                (sshd jail, 1h ban, 5 retries)
- ufw                             (active، rules بـ enp0s3)
- iptables-persistent             (DOCKER-USER chain rule for enp0s8)
- netplan/networkd                (cloud-init disabled)
```

---

## Credentials

```
siem Linux:
  user:     ahmadj
  password: Ahmad@2026

Wazuh Dashboard / Indexer:
  URL:      https://192.168.56.10
  user:     admin
  password: SecretPassword

Wazuh internal API:
  user:     wazuh-wui
  password: MyS3cr37P450r.*-

win-ep Windows:
  user:     vboxuser  (default)
  password: changeme  (default)

GitHub PAT:
  ~/.github-token on siem
  expires: 90 days from creation
```

---

## Phase 1 — Foundation (Day 1)

### 1. Host validation

```powershell
# على Windows host (ThinkPad)
Get-Volume | ?{$_.DriveLetter} | Select DriveLetter, Size, SizeRemaining
# C: 476 GB total, 263 GB free
```

Cleaned up using `cleanmgr` to free additional space before VM creation.

### 2. siem VM creation (Ubuntu 22.04)

**VirtualBox settings:**
- Name: `siem` (note: created with trailing spaces by accident — use `"siem  "` in CLI)
- RAM: 9216 MB, CPU: 4
- Disk: 120 GB **pre-allocated** (critical for OpenSearch I/O)
- Network NIC1: Host-only Adapter
- Network NIC2: NAT
- System: I/O APIC ✅, Nested Paging ✅, PAE/NX ✅
- Skip Unattended Installation: ✅ (don't let VirtualBox auto-install — broke password setup)

**Ubuntu installation:**
- Type: Ubuntu Server (not minimized)
- Storage: full disk, no LVM
- User: `ahmadj` / `Ahmad@2026`
- SSH: enabled (password auth)
- No featured snaps

### 3. Network configuration

**Issue encountered:** cloud-init kept overwriting netplan after reboot.

**Final netplan (`/etc/netplan/50-cloud-init.yaml`):**

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      addresses: [192.168.56.10/24]
      nameservers:
        addresses: [1.1.1.1, 8.8.8.8]
    enp0s8:
      dhcp4: true
```

**Disable cloud-init network rewrite:**

```bash
echo 'network: {config: disabled}' | sudo tee /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
```

### 4. System update + tools

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget git vim nano htop net-tools \
    ca-certificates gnupg lsb-release software-properties-common \
    apt-transport-https tcpdump arping
```

### 5. Docker installation

```bash
# Docker official GPG + repo
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
    sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin

sudo usermod -aG docker $USER
sudo systemctl enable --now docker
```

Logout/login required after `usermod` for group membership.

### 6. Wazuh stack deployment

```bash
sudo mkdir -p /opt/homelab-mdr/{wazuh,thehive,n8n,backups,docs}
sudo chown -R $USER:$USER /opt/homelab-mdr

# Required sysctl for OpenSearch
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Clone official Wazuh Docker repo
cd /opt/homelab-mdr/wazuh
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.0 .

# Generate TLS certificates
cd single-node
docker compose -f generate-indexer-certs.yml run --rm generator
sudo chown -R $USER:$USER /opt/homelab-mdr/wazuh

# Deploy
docker compose up -d
```

**Result:** 3 healthy containers within ~3 minutes.

**Note:** Tried to change `SecretPassword` to custom value but Wazuh has internal users in the Indexer that don't pick up env-var changes. Workaround: kept default password and changed via Dashboard UI later (planned).

---

## Phase 2 — Hardening (Day 2)

### 1. ISM retention policy

```bash
curl -k -u admin:SecretPassword -X PUT "https://localhost:9200/_plugins/_ism/policies/wazuh_retention" \
  -H 'Content-Type: application/json' -d '{
  "policy": {
    "description": "Retain Wazuh alerts 90 days then delete",
    "default_state": "hot",
    "states": [
      {"name": "hot", "actions": [], "transitions": [{"state_name": "delete", "conditions": {"min_index_age": "90d"}}]},
      {"name": "delete", "actions": [{"delete": {}}], "transitions": []}
    ],
    "ism_template": [{"index_patterns": ["wazuh-alerts-*", "wazuh-archives-*"], "priority": 100}]
  }
}'

curl -k -u admin:SecretPassword -X POST "https://localhost:9200/_plugins/_ism/add/wazuh-alerts-*" \
  -H 'Content-Type: application/json' -d '{"policy_id": "wazuh_retention"}'
```

**Why:** Manager was writing 108 GB/day of self-monitoring data with no retention. ISM caps it at 90 days.

### 2. Disable replicas (single-node optimization)

```bash
curl -k -u admin:SecretPassword -X PUT "https://localhost:9200/_template/wazuh-no-replicas" \
  -H 'Content-Type: application/json' -d '{
  "index_patterns": ["wazuh-*"],
  "settings": {"number_of_replicas": 0}
}'

curl -k -u admin:SecretPassword -X PUT "https://localhost:9200/wazuh-*/_settings" \
  -H 'Content-Type: application/json' -d '{"index": {"number_of_replicas": 0}}'
```

### 3. UFW firewall

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow in on enp0s3 to any port 22 proto tcp comment 'SSH'
sudo ufw allow in on enp0s3 to any port 443 proto tcp comment 'Wazuh Dashboard'
sudo ufw allow in on enp0s3 to any port 55000 proto tcp comment 'Wazuh API'
sudo ufw allow in on enp0s3 to any port 1514 proto tcp comment 'Wazuh agent comms'
sudo ufw allow in on enp0s3 to any port 1515 proto tcp comment 'Wazuh agent enrollment'
sudo ufw --force enable
```

### 4. Docker iptables bypass closure

Docker injects rules into iptables that **bypass UFW**. Plug it:

```bash
sudo iptables -I DOCKER-USER -i enp0s8 -j DROP
sudo iptables -I DOCKER-USER -i enp0s8 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo apt install -y iptables-persistent
sudo netfilter-persistent save
```

**Effect:** External traffic from NAT interface (enp0s8) can't reach Docker containers. Only outbound (for image pulls + updates).

### 5. fail2ban + SSH hardening

```bash
sudo apt install -y fail2ban
sudo tee /etc/fail2ban/jail.local > /dev/null <<'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = 22
EOF
sudo systemctl enable --now fail2ban

sudo tee /etc/ssh/sshd_config.d/99-hardening.conf > /dev/null <<'EOF'
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
EOF
sudo systemctl reload ssh
```

---

## Phase 2.5 — GitHub Repo

```bash
git config --global user.name "Ahmad Jehad"
git config --global user.email "AJahmadcyber@users.noreply.github.com"
git config --global init.defaultBranch main
git config --global credential.helper store

mkdir -p ~/projects/homelab-mdr/docs
cd ~/projects/homelab-mdr
git init
```

**Files added:**
- `README.md` (rewritten to be portfolio-friendly, no MDR commercial framing)
- `docs/architecture.svg` (light/dark mode supported)
- `.gitignore` (excludes certs, credentials, runtime data)
- `LICENSE` (MIT, from GitHub UI)

```bash
git remote add origin https://github.com/AJahmadcyber/homelab-mdr.git
git pull origin main --allow-unrelated-histories
git push -u origin main
# Authenticate with PAT (classic, scope: repo)
```

**Important branding decision:**
- Original "About this project" section had defensive language about "not commercial product, not academic capstone" — replaced with positive framing focusing on detection engineering skills.

---

## Phase 3 — Windows Endpoint (Day 2 — Started)

### 1. win-ep VM creation

**Important:** The original `Windows10-MITM-Lab` VM had its password lost. Deleted and recreated from scratch.

**Settings:**
- Name: `win-ep`
- RAM: 2048 MB (initially 3072 caused HostMemoryLow)
- CPU: 2
- Disk: 60 GB
- NIC 1: Host-only (192.168.56.0/24)
- NIC 2: NAT
- Guest Additions: installed

**Local account password:** Choose "I don't have internet" during setup to force local account creation (avoid Microsoft account).

### 2. Network configuration (Windows)

```powershell
$if = "Ethernet"
Set-NetIPInterface -InterfaceAlias $if -Dhcp Disabled
Get-NetIPAddress -InterfaceAlias $if -AddressFamily IPv4 -EA SilentlyContinue | Remove-NetIPAddress -Confirm:$false
New-NetIPAddress -InterfaceAlias $if -IPAddress 192.168.56.20 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias $if -ServerAddresses ("1.1.1.1","8.8.8.8")
```

**Verify:**
```powershell
Test-NetConnection 192.168.56.10 -Port 1514
# Expected: TcpTestSucceeded: True
```

### 3. Wazuh agent installation

```powershell
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0-1.msi" -OutFile "$env:TEMP\wazuh-agent.msi"

Start-Process msiexec.exe -Wait -ArgumentList "/i $env:TEMP\wazuh-agent.msi /q WAZUH_MANAGER='192.168.56.10' WAZUH_AGENT_NAME='win-ep' WAZUH_REGISTRATION_SERVER='192.168.56.10'"

NET START WazuhSvc
```

### 4. Critical fix: hostname resolution bug

**Bug:** Wazuh agent 4.9.0 on Windows fails to resolve IP literals via `gethostbyname` (returns `'192.168.56.10'` with double quotes).

**Cause:** When `Set-Content` was used to edit `ossec.conf` with `-Encoding UTF8`, it added BOM characters and inadvertently wrapped IPs in extra quotes.

**Fix:** Use `.NET WriteAllLines` with UTF8 no-BOM encoding:

```powershell
Stop-Service WazuhSvc -Force

$conf = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$lines = Get-Content $conf
$lines = $lines -replace "<address>['""]?192\.168\.56\.10['""]?</address>", "<address>192.168.56.10</address>"
$lines = $lines -replace "<manager_address>['""]?192\.168\.56\.10['""]?</manager_address>", "<manager_address>192.168.56.10</manager_address>"
[System.IO.File]::WriteAllLines($conf, $lines, (New-Object System.Text.UTF8Encoding $false))

Start-Service WazuhSvc
```

**Result:** Agent connects, registers, and starts sending events.

### 5. Verification

```bash
# On siem
sudo docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
# ID: 001, Name: win-ep, IP: ..., Active
```

**Dashboard:** `https://192.168.56.10` → Agents → **win-ep Active** 🟢

---

## شغلات معلقة في مكان آخر

### Wazuh credentials
- لسه Default `SecretPassword` — لازم نغيرها من Dashboard UI:
  - Indexer Management → Security → Internal users → admin → Reset password
- ثم نحدث `docker-compose.yml` لتطابق

### Snapshots
- `wazuh-stack-deployed` (post Phase 1)
- `post-hardening` (post Phase 2)
- `agent-connected` (post agent enrollment) ← **هاد اللي بناخده الآن**

### Documentation TBD
- `docs/lab-setup.md` (step-by-step)
- `docs/detection-coverage.md` (MITRE mapping table)
- `docs/attack-scenarios/` (will be populated phase 5)

---

## Phase 3 — Sysmon + Detection Telemetry (Next Session)

### المهام

1. **Sysmon installation with sysmon-modular config**
   - Download from sysinternals/sysmon-modular
   - Use Olaf Hartong's MITRE-mapped config (high fidelity, low noise)
   - Verify Sysmon events appearing in Wazuh (event IDs 1, 3, 7, 10, 22, 23)

2. **PowerShell Script Block Logging (4104)**
   - Enable via GPO or registry
   - Catches obfuscated PowerShell after de-obfuscation

3. **ASR (Attack Surface Reduction) rules**
   - Block credential stealing from LSASS (GUID: 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2)
   - Block Office child processes
   - Block executable content from email/web

4. **Defender Operational log ingestion**
   - Add Windows Event Log channel to Wazuh agent config
   - Path: `Microsoft-Windows-Windows Defender/Operational`

5. **Sysmon-modular ASR rules deployment**
   - GitHub: olafhartong/sysmon-modular
   - Choose `sysmonconfig.xml` (consolidated)

### Reference commands (للجلسة الجاية)

```powershell
# Sysmon download
$sysmonZip = "$env:TEMP\sysmon.zip"
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $sysmonZip
Expand-Archive $sysmonZip -DestinationPath "$env:TEMP\sysmon" -Force

# sysmon-modular config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml" -OutFile "$env:TEMP\sysmon\sysmonconfig.xml"

# Install
& "$env:TEMP\sysmon\Sysmon64.exe" -accepteula -i "$env:TEMP\sysmon\sysmonconfig.xml"

# Verify
Get-Service Sysmon64
Get-WinEvent -ProviderName "Microsoft-Windows-Sysmon" -MaxEvents 5
```

```bash
# على siem — ضيف Sysmon channel للـ agent config (centralized)
sudo docker exec -it single-node-wazuh.manager-1 \
    nano /var/ossec/etc/shared/default/agent.conf
```

Add inside `<agent_config>`:
```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>Microsoft-Windows-Windows Defender/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Then restart Manager:
```bash
sudo docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

---

## Phase 4 — Case Management Stack (Next Sessions)

### Plan

1. New Docker Compose: `/opt/homelab-mdr/thehive/docker-compose.yml`
2. Cassandra single-node (1.5 GB heap)
3. TheHive 5 (1 GB heap)
4. Cortex (800 MB)
5. n8n (300 MB)

### Resource check
- Current siem usage: ~2.5 GB used (Manager 1.7, Indexer 1.4, Dashboard 0.2)
- Adding TheHive stack: +3.5 GB
- Total expected: ~6 GB / 9 GB → ~3 GB headroom ✅

### Workflow design (Wazuh → TheHive)

```
Wazuh alert (level >= 7)
    ↓
n8n webhook (Wazuh integration)
    ↓
TheHive case creation (with observables)
    ↓
Cortex enrichment (VirusTotal, AbuseIPDB)
    ↓
Enrichment results back to case
    ↓
[If score > 70] → pfSense API block (later)
```

---

## Phase 5 — pfSense + Detection Engineering (Future)

### High-level plan

1. **pfSense VM** activation (already exists from previous attempts)
2. Re-architect network with pfSense in path
3. Suricata IDS configuration
4. Suricata alerts → syslog → Wazuh integration
5. Custom Wazuh rules for:
   - RDP brute force (T1110.001)
   - Port scan (T1046)
   - PowerShell obfuscation (T1059.001)
   - LSASS dump (T1003.001)
   - Ransomware simulation (T1486)
   - Living-off-the-land (T1218)

### MITRE ATT&CK Navigator
- Enable MITRE module in Wazuh Dashboard
- Custom mapping for each rule
- Export navigator JSON for portfolio screenshot

---

## Troubleshooting Notes (للمرجع)

### Issue: VirtualBox Internal Network not actually connecting VMs

**Symptom:** Two VMs on same Internal Network can't ARP each other.

**Resolution:** Switched everything to Host-only Adapter (same vboxnet0). Single subnet 192.168.56.0/24 for both siem and win-ep. NAT NIC for internet.

### Issue: nano YAML indentation breaks netplan

**Symptom:** `Error in network definition: unknown renderer 'networked'`

**Resolution:** YAML standard is 2 spaces per indent level. Use inline arrays `[1.1.1.1, 8.8.8.8]` to avoid nested indentation. Use `sed -i 's/networked/networkd/' file.yaml` for fixes.

### Issue: Wazuh agent on Windows can't resolve IP literal

**Symptom:** `Could not resolve hostname '192.168.56.10'` despite the IP being correct.

**Resolution:** PowerShell `Set-Content -Encoding UTF8` adds BOM. Use `.NET WriteAllLines` with `UTF8Encoding $false` (no BOM).

### Issue: cloud-init keeps overwriting netplan

**Symptom:** enp0s9 (or any new interface) disappears after reboot.

**Resolution:** Disable cloud-init network management:
```bash
echo 'network: {config: disabled}' > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
```

### Issue: HostMemoryLow when starting win-ep

**Symptom:** VirtualBox pauses VM with "Unable to allocate and lock memory".

**Resolution:** Lowered win-ep RAM from 3072 to 2048 MB. siem (9 GB) + win-ep (2 GB) + Windows host (~5 GB) = 16 GB fits.

### Issue: Manager bytes written 108 GB in 2 days

**Symptom:** Disk usage growing rapidly even without endpoints.

**Resolution:** Self-monitoring traffic with no retention. ISM 90-day retention + `number_of_replicas: 0` fixed it.

### Issue: Docker bypasses UFW

**Symptom:** UFW rules ignored for Docker-exposed ports.

**Resolution:** Add explicit DOCKER-USER iptables rule. Save with `iptables-persistent`.

---

## شو لازم نتذكر في الجلسة الجاية

1. **siem trailing spaces:** اسم الـ VM في VirtualBox = `"siem  "` (مع مسافتين). Important for `VBoxManage` CLI.
2. **Wazuh password ما اتغير** - لسه `SecretPassword` افتراضي.
3. **Hostname resolution bug** - أي تعديل على `ossec.conf` لازم يكون UTF-8 **no BOM**. استخدم `.NET WriteAllLines`.
4. **Sysmon-modular** هو الـ config اللي رح نستخدمه (مش Olaf's individual modules).
5. **agent.conf** centralized — التعديلات هناك تطبق على كل الـ agents تلقائيا.
6. **GitHub PAT** stored at `~/.github-token` على siem. Expires 90 days.
7. **Cassandra heap** = 1.5 GB لما نضيف TheHive — already budgeted.
8. **pfSense VM** موجود بس بـ password قديم — نحتاج reset أو reinstall.

---

## Files location reference

```
On siem:
  /opt/homelab-mdr/wazuh/single-node/docker-compose.yml   # main wazuh stack
  /opt/homelab-mdr/wazuh/single-node/config/              # certs and config
  ~/projects/homelab-mdr/                                  # GitHub repo
  ~/.github-token                                          # PAT
  /etc/netplan/50-cloud-init.yaml                          # network config
  /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg     # cloud-init disable
  /etc/fail2ban/jail.local                                 # fail2ban config
  /etc/ssh/sshd_config.d/99-hardening.conf                 # ssh hardening
  /etc/ufw/                                                # ufw rules

On win-ep:
  C:\Program Files (x86)\ossec-agent\ossec.conf            # agent config
  C:\Program Files (x86)\ossec-agent\ossec.log             # agent log
  C:\Windows\System32\drivers\etc\hosts                    # hosts file
```

---

## Commands quick-ref (للجلسة الجاية)

### SSH للـ siem
```powershell
ssh ahmadj@192.168.56.10
```

### Docker stats
```bash
docker stats --no-stream
```

### Wazuh logs
```bash
sudo docker logs single-node-wazuh.manager-1 --tail 50
sudo docker logs single-node-wazuh.indexer-1 --tail 50
sudo docker logs single-node-wazuh.dashboard-1 --tail 50
```

### Agent control
```bash
sudo docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
sudo docker exec single-node-wazuh.manager-1 /var/ossec/bin/manage_agents -l
```

### Restart Wazuh stack
```bash
cd /opt/homelab-mdr/wazuh/single-node
docker compose restart
```

### Git push (PAT في `~/.github-token`)
```bash
cd ~/projects/homelab-mdr
git add .
git commit -m "..."
git push
```

---

## End of Session Log
