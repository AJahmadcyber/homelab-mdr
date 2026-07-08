#!/bin/bash
# Pull Suricata eve alerts from pfSense -> local file (PULL model)
PFSENSE="admin@10.10.10.1"
KEY="/root/.ssh/id_ed25519_pfsense"
SRC="/var/log/suricata/suricata_em14846/eve.json"
DEST="/var/log/suricata-pfsense/eve-alerts.json"

exec ssh -i "$KEY" -o IdentitiesOnly=yes \
  -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
  -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=accept-new \
  "$PFSENSE" "tail -F $SRC | grep --line-buffered '\"event_type\":\"alert\"'" \
  >> "$DEST"
