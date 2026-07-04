# Phase 5 Session 2 — Suricata → Wazuh Pipeline

## Flow
Suricata eve.json (pfSense) → edge filter (event_type:alert) → SSH stream → siem → Docker mount → Wazuh JSON decoder → custom rules 100300-100303 → MITRE T1046

## docker-compose.yml (wazuh.manager volumes — added line)
    - /var/log/suricata-pfsense:/var/log/suricata-pfsense:ro

## ossec.conf (wazuh_manager.conf) localfile block
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata-pfsense/eve-alerts.json</location>
  </localfile>

## logrotate (/etc/logrotate.d/suricata-pfsense)
/var/log/suricata-pfsense/eve-alerts.json {
    daily
    rotate 3
    compress
    missingok
    notifempty
    copytruncate
}

## fail2ban (/etc/fail2ban/jail.local)
ignoreip = 127.0.0.1/8 10.10.10.0/24

## pfSense
- /root/stream-eve.sh (Shellcmd at boot: `/root/stream-eve.sh &`, type shellcmd)
- ssh uses: -i /root/.ssh/id_ed25519 -o IdentitiesOnly=yes -o ServerAliveInterval=30
