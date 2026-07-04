#!/bin/sh
EVE="/var/log/suricata/suricata_em14846/eve.json"
DEST="ahmadj@10.10.10.10"
DESTFILE="/var/log/suricata-pfsense/eve-alerts.json"
while true; do
  tail -F "$EVE" | grep --line-buffered '"event_type":"alert"' | ssh -i /root/.ssh/id_ed25519 -o IdentitiesOnly=yes -o ServerAliveInterval=30 "$DEST" "cat >> $DESTFILE"
  echo "$(date) stream dropped, reconnecting" >> /var/log/stream-eve.log
  sleep 5
done
