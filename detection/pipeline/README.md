# Collector pipeline

Two independent paths carry Suricata data from pfSense to the SIEM. They read
the same `eve.json` and deliberately do not share a mechanism, because they
have different requirements.

| Path | Mechanism | Destination |
| --- | --- | --- |
| Alerts | persistent SSH tail, systemd service | `/var/log/suricata-pfsense/eve-alerts.json` |
| DNS queries | byte-offset batch pull, cron every minute | `/var/log/dns-analyzer/dns-queries.stream` |

Both destinations are bind-mounted into the Wazuh manager container.

## Why the SIEM pulls instead of pfSense pushing

An earlier design pushed from pfSense. FreeBSD offers no supervision for that
process, so when it died the alert stream stopped and nothing said so — the
worst failure a detection pipeline can have, because a silent SIEM looks
exactly like a quiet network.

Pulling moves the process onto the SIEM, where systemd supervises it.
`suricata-collector.service` sets `Restart=always` and recovers within about
ten seconds of a dropped connection, a firewall reboot or a host suspend.

## Alerts: `suricata-collector.sh` + `.service`

Filtering happens at the sensor: only `event_type=alert` crosses the link, so
protocol logs never leave pfSense and never consume SIEM storage.

The `pkill -x tail` at the start of the remote command is not cosmetic.
Reconnecting leaves the previous remote `tail` running, and those accumulate
until the firewall is carrying a dozen orphans reading the same file. The `-x`
is what makes it safe — an exact name match, so the command does not match the
shell wrapper that is running it and kill itself.

Restart the collector after **any** Suricata restart: the old `tail` is holding
a file handle that no longer receives writes.

## DNS: `dns-pull.sh` + `.cron` + `.logrotate`

A second persistent tail on the same file would collide with the first, so this
path batches instead. Each run reads the remote file size, pulls only the bytes
added since the last run, and records the new offset. If the file shrank, the
offset resets — that is the log-rotation guard, without which a rotation would
skip everything until the file grew past the old size.

Output feeds `detection/dns-analyzer/c2-detect.py`, which groups queries by
`(src_ip, eTLD+1)` and flags anomalous volume. `dns-analyzer.logrotate` bounds
both the stream and the alert file.

## Installing

Destination paths, ownership and the SSH key setup are covered in
[`docs/build/INSTALL.md`](../../docs/build/INSTALL.md) section 6. The key path
the scripts expect is `/root/.ssh/id_ed25519_pfsense`; the collector runs as
root because it writes into a directory the container reads.

The Suricata instance directory in both scripts (`suricata_em14846`) is
specific to this build — the suffix is generated per interface at package
install. Check the real path on your firewall before deploying.
