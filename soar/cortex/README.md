# Cortex — Observable Enrichment Engine (Phase 6-C)

Cortex 4.0 + Elasticsearch 7.17, providing analyzer-based enrichment for the SOAR
pipeline (Wazuh alert observables) and phishing email analysis.

## Deploy
`docker compose up -d` from this directory. Cortex UI on port 9001.
Before first run: generate a real `play.http.secret.key` in application.conf
(the committed value is a placeholder).

## Enabled analyzers (9) — professional phishing + enrichment stack
- **EmlParser** — parse .eml, extract URLs / sender / headers (the core for phishing)
- **Urlscan_io_Scan** — live URL sandbox (screenshot, redirects) — the differentiator
- **Pulsedive_GetIndicator** — threat-intel context for IOCs
- **EmailRep** — sender address reputation (breaches, phishing kits)
- **VirusTotal_GetReport** — file/hash/domain/URL reputation
- **URLhaus** — malicious URL database (abuse.ch)
- **AbuseIPDB** — IP reputation
- **Abuse_Finder** — abuse contacts
- **GoogleDNS_resolve** — DNS resolution

## Hard-won learnings
- **jobs bind-mount**: `/opt/cortex/jobs:/opt/cortex/jobs` MUST be identical host↔container —
  Cortex passes that path to the host Docker daemon when spawning analyzer containers.
- **API file upload temp path**: uploads via the REST API land in Play's temp dir
  (`/tmp/playtemp...`), which isn't shared with analyzer containers → `NoSuchFileException`.
  Fix: point Play/JVM temp into the shared mount via JVM_OPTS
  `-Dplay.temporaryFile.dir=/opt/cortex/jobs/tmp -Djava.io.tmpdir=/opt/cortex/jobs/tmp`.
- **secret key**: Cortex entrypoint generates a random secret each start unless you mount
  your own application.conf at /etc/cortex/application.conf and pin play.http.secret.key.
- super-admin cannot run analyzers — need an org + org-admin; analyzers are enabled per-org.
- ES heap capped at 1g, container mem_limit 2g; single-node ES yellow status is normal.

## Credentials
Never committed. super-admin and org-admin API keys are stored outside the repo.
The org-admin key is what n8n/TheHive use to run analyzers.
