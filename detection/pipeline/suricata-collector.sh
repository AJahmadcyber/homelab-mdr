#!/bin/bash
PFSENSE="admin@10.10.10.1"
KEY="/root/.ssh/id_ed25519_pfsense"
SRC="/var/log/suricata/suricata_em14846/eve.json"
DEST="/var/log/suricata-pfsense/eve-alerts.json"
# pkill -x tail: kill stale remote tail(s) by exact name only (avoids matching own shell)
exec ssh -i "$KEY" -o IdentitiesOnly=yes \
  -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
  -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new \
  "$PFSENSE" \
  "pkill -x tail; sleep 1; tail -F $SRC | grep --line-buffered '\"event_type\":\"alert\"'" \
  >> "$DEST"
