#!/bin/bash
# Batch DNS-query pull — no persistent tail, no collision with alert collector.
# Runs from cron; reads only lines newer than last run via a byte offset.
KEY="/root/.ssh/id_ed25519_pfsense"
PF="admin@10.10.10.1"
SRC="/var/log/suricata/suricata_em14846/eve.json"
DEST="/var/log/dns-analyzer/dns-queries.stream"
OFFSET_FILE="/var/log/dns-analyzer/.last_size"

# current size of remote file
CUR=$(ssh -i "$KEY" -o IdentitiesOnly=yes -o ConnectTimeout=10 "$PF" "wc -c < $SRC" 2>/dev/null | tr -d ' ')
[ -z "$CUR" ] && exit 0
LAST=$(cat "$OFFSET_FILE" 2>/dev/null || echo 0)

# rotation guard: if file shrank, reset
[ "$CUR" -lt "$LAST" ] && LAST=0

if [ "$CUR" -gt "$LAST" ]; then
  ssh -i "$KEY" -o IdentitiesOnly=yes -o ConnectTimeout=10 "$PF" \
    "tail -c +$((LAST+1)) $SRC" 2>/dev/null \
    | grep '"event_type":"dns"' | grep '"type":"query"' >> "$DEST"
  echo "$CUR" > "$OFFSET_FILE"
fi
