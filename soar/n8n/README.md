# n8n workflows

Two exported workflows. Both end at a TheHive alert, and both share the same
Cortex enrichment engine.

## Import and what you must set afterwards

Import through the n8n UI (Workflows -> Import from File). An import brings the
nodes but **not the credentials**, so nothing runs until these are supplied:

| What | Where it is used | Note |
| --- | --- | --- |
| Cortex organisation API key | the enrichment Code nodes | redacted in the export as a placeholder; must be an **org-admin** key, not super-admin, which cannot run analyzers |
| pfSense API credential | the two firewall HTTP Request nodes | held as an n8n credential, never written into the export |
| TheHive API key | `Create TheHive Alert` nodes | organisation-scoped |
| IMAP mailbox | `Email Trigger (IMAP)` | phishing workflow only |

Addresses in the exported nodes are this lab's (`10.10.10.1` gateway,
`10.10.10.10` SIEM). Change them to match your own network.

## `wazuh-soar-triage.json` — 15 nodes

Node names in the export are n8n defaults (`If1`, `Edit Fields1`), which is a
known readability cost of exporting rather than renaming. What each one does:

| Node | Role |
| --- | --- |
| `Webhook` | receives the alert on `/wazuh-alert`; the Wazuh side is `soar/wazuh-integration/` |
| `If` | severity gate, and drops vulnerability findings |
| `Edit Fields1`, `HIGH_PRIORITY`, `Edit Fields` | field normalisation between stages |
| `allowlist` | infrastructure protection — the gateway, SIEM and analyst host are never blockable |
| `Cortex enrichment` | capability-routed analyzer dispatch, deduplication, bounded parallelism, taxonomy rollup |
| `If1` | containment decision |
| `HTTP Request`, `HTTP Request1` | pfSense API: add to the `soar_blocklist` alias, then apply |
| `BYOVD correlation` | ties a driver load to a security-tooling kill on the same host inside a window |
| `Lateral Movement correlation` | cross-host: matches a SIEM login against a recent high-severity alert from the login's *source* |
| `SOC Investigation Ticket` | the classifier — maps technique to tactic, derives severity, selects the investigation plan |
| `TheHive Alert Builder`, `Create TheHive Alert` | shape and post the alert |

**Order matters.** Enrichment runs *before* the containment branch, so an alert
that cannot be blocked is still enriched and still produces a ticket. An
earlier layout had containment first, which silently dropped every alert on
protected infrastructure — exactly the alerts that need the most analysis.

## `phishing-triage-cortex-enrichment.json` — 6 nodes

A user-reported `.eml` arrives by IMAP, is parsed into observables, routed
through Cortex, and scored on signals that need no prior reputation:
lookalike domains (homoglyph normalisation plus edit distance), display-name
mismatch, SPF/DKIM/DMARC, anchor-text deception, credential-capture paths and
lure language.

That scoring is the point of the workflow. On a test sample where every
reputation source returned clean, it still reached high risk on seven
independent signals — targeted phishing uses domains too new to have any
reputation, so a pipeline that only asks VirusTotal will pass it.

## Two things that cost time

The n8n Code node sandbox cannot do multipart file upload; file submissions
need a dedicated HTTP Request node with `formData`.

Cortex returns per-field taxonomy entries with colours, and a colour is not a
verdict. An informational metric such as a domain's resolution count is
excluded from the verdict rollup while staying visible as context — without
that, a clean domain that merely resolves reads as malicious.
