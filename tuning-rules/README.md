# Custom Wazuh Detection Rules

This directory holds custom Wazuh XML rules added or modified during detection engineering work in this lab.

## Layout

    tuning-rules/
    ├── README.md                  (this file)
    ├── 0100-windows-powershell.xml
    ├── 0101-windows-sysmon.xml
    ├── 0102-windows-asr.xml
    └── disabled-rules.xml         (rules silenced due to noise, with justification)

Rules are deployed to the Wazuh Manager at `/var/ossec/etc/rules/` and applied after a Manager restart.

## Rule numbering

| Range | Purpose |
| --- | --- |
| 100000-100099 | PowerShell behavioural detections |
| 100100-100199 | Sysmon process / file / network detections |
| 100200-100299 | Windows Defender + ASR detections |
| 100300-100399 | Linux auditd detections (future) |
| 100900-100999 | False-positive suppression |

Each rule includes a comment header with: MITRE technique ID, rationale, false-positive risk, and the test case in `testing/` that validates it.

## Workflow

1. Identify gap from a test case (telemetry visible but no alert, or wrong severity).
2. Write rule with conservative match conditions.
3. Deploy to Manager, reload.
4. Re-run the test case from `testing/`.
5. Update the corresponding test record with new alert level + rule ID.
6. Commit rule and test record together.
