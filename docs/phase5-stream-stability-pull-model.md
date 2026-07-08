# Phase 5 — Stream Stability: PULL Model + systemd

## Problem
The PUSH model (pfSense runs stream-eve.sh, ships to siem) did not survive a multi-day
VM saved/frozen state: SSH went half-open, tail became a zombie, the auto-reconnect loop
did not recover. Result: no Suricata alerts reached Wazuh for 3 days, undetected.

## Solution — PULL + systemd
siem PULLS from pfSense via SSH, managed by a systemd service with Restart=always.
systemd supervises and auto-restarts on any failure (RestartSec=5).

Flow:
  siem systemd service -> ssh admin@pfSense "tail -F eve.json | grep alert"
    -> >> /var/log/suricata-pfsense/eve-alerts.json -> Wazuh localfile -> 100300-100303 -> T1046

## Why better
- systemd Restart=always: true supervision, auto-recovery from stop/freeze/crash.
- ServerAliveInterval=15 + CountMax=3: detects dead SSH in ~45s, exits, systemd restarts
  -> solves the half-open hang that broke the old PUSH model.
- Service management on Linux (siem) vs a manual loop on FreeBSD (pfSense).

## Files
- detection/pipeline/suricata-collector.sh      (/usr/local/bin on siem)
- detection/pipeline/suricata-collector.service (/etc/systemd/system on siem)

## SSH
siem -> pfSense key /root/.ssh/id_ed25519_pfsense; public key on pfSense admin user
(User Manager). Old PUSH script + pfSense Shellcmd entry removed.
