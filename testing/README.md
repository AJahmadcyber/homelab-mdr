# Detection testing records

**Superseded by the coverage engine.** This directory is the manual stage of
detection validation: one Markdown record per technique, written by hand after
running the attack. It produced exactly one complete record before the approach
was replaced, and it is kept because the replacement is the interesting part.

Hand-written records do not scale and cannot be re-run. Every conclusion in
them is a claim about a moment that has passed, and re-validating after a rule
change means repeating the whole thing by hand. That is why
[`detection/coverage-engine/`](../detection/coverage-engine/) exists: it
executes the attack, records exactly when each step ran, queries the Indexer
for the window that follows, and grades the result — so coverage is re-derived
from a command rather than remembered.

Read this directory as history. Current coverage is measured, not recorded
here.

Note: the convention below mentions a `tuning-rules/` directory that was never
created; tuning rules live in `detection/wazuh-rules/` with the detections they
correct.

---

Each file in this directory documents one test case used to validate the detection pipeline end-to-end.

## Naming convention

    T<NNN>-<MITRE-ID>-<short-name>.md

Examples:

    T001-T1059.001-obfuscated-powershell.md
    T002-T1003.001-lsass-dump-attempt.md
    T003-T1110.001-rdp-brute-force.md

## Required sections per test

Each test record contains:

1. **Objective** — what telemetry / rule we are validating.
2. **Pre-conditions** — agent status, rules loaded, ASR state.
3. **Steps to reproduce** — exact commands run on the endpoint.
4. **Expected telemetry** — event IDs, fields, sample values.
5. **Expected alert** — Wazuh rule ID and level (or `none` if telemetry only).
6. **Result** — pass / partial / fail with screenshots.
7. **Evidence** — terminal output and Dashboard screenshots in `evidence/<test-id>/`.
8. **Tuning actions** — links to rule files in `tuning-rules/` if changes resulted.
9. **MITRE mapping** — technique ID, tactic, sub-technique notes.

## Status legend

| Symbol | Meaning |
| --- | --- |
| Pass | Expected alert fired at expected level |
| Partial | Telemetry collected but alert missing, wrong level, or noisy |
| Fail | Telemetry not collected |
| Tuned | Originally partial / fail; resolved by a rule in `tuning-rules/` |
