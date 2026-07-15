#!/usr/bin/env python3
"""
Lightweight DNS C2 (beaconing) detector — rate-based.
Reads the DNS query stream, groups by (src_ip, eTLD+1) over a time window,
flags parents whose query volume exceeds a threshold. SOAR-ready JSON alerts.
Phase 5 (light). Entropy + cardinality + PSL = Phase 6.
"""
import json, sys, time, datetime, collections, re

STREAM   = "/var/log/dns-analyzer/dns-queries.stream"
ALERTS   = "/var/log/dns-analyzer/alerts.json"
WINDOW_S = 300          # look back 5 minutes
THRESH   = 40           # queries to same parent from same src in window => suspicious
SAMPLE_N = 5            # sample queries to attach as evidence

# eTLD+1 approximation: known multi-part public suffixes
MULTI_TLD = {"co.uk","org.uk","gov.uk","ac.uk","com.au","net.au","org.au",
             "co.jp","com.jo","edu.jo","gov.jo","co.nz","com.br","com.tr"}

# legitimate high-volume parents observed in baseline (tune as needed)
ALLOWLIST = {"microsoft.com","windowsupdate.com","windows.com","msftncsi.com",
             "microsoftonline.com","office.com","live.com","bing.com",
             "akamaiedge.net","akamai.net","akadns.net","edgekey.net",
             "google.com","gstatic.com","googleapis.com","cloudflare.com",
             "in-addr.arpa","ip6.arpa","lab.local","localdomain"}

def etld1(name):
    name = name.rstrip(".").lower()
    parts = name.split(".")
    if len(parts) < 2:
        return name
    last2 = ".".join(parts[-2:])
    if last2 in MULTI_TLD and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last2

def parse_ts(ts):
    # Suricata: 2026-07-13T19:03:42.150111+0300
    # Py3.10 fromisoformat rejects +0300 (no colon); insert colon in tz offset.
    try:
        m = re.match(r"^(.*[+-]\d{2})(\d{2})$", ts)
        if m:
            ts = m.group(1) + ":" + m.group(2)
        return datetime.datetime.fromisoformat(ts).timestamp()
    except Exception:
        return None

def main():
    now = time.time()
    cutoff = now - WINDOW_S
    # (src_ip, parent) -> [count, [samples]]
    agg = collections.defaultdict(lambda: [0, []])
    try:
        with open(STREAM, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                if ev.get("event_type") != "dns":
                    continue
                dns = ev.get("dns", {})
                if dns.get("type") != "query":
                    continue
                ts = parse_ts(ev.get("timestamp",""))
                if ts is None or ts < cutoff:
                    continue
                rrname = dns.get("rrname","")
                parent = etld1(rrname)
                if parent in ALLOWLIST:
                    continue
                src = ev.get("src_ip","?")
                key = (src, parent)
                agg[key][0] += 1
                if len(agg[key][1]) < SAMPLE_N:
                    agg[key][1].append(rrname)
    except FileNotFoundError:
        return

    ts_iso = datetime.datetime.now().astimezone().isoformat()
    with open(ALERTS, "a") as out:
        for (src, parent), (count, samples) in agg.items():
            if count >= THRESH:
                alert = {
                    "timestamp": ts_iso,
                    "analyzer": "dns-c2-ratebased",
                    "rule": "dns_c2_beaconing",
                    "severity": "high" if count >= THRESH*2 else "medium",
                    "src_ip": src,
                    "parent_domain": parent,
                    "query_count": count,
                    "window_seconds": WINDOW_S,
                    "mitre": ["T1071.004"],
                    "sample_queries": samples,
                }
                out.write(json.dumps(alert) + "\n")

if __name__ == "__main__":
    main()
