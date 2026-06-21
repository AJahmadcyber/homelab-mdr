# Wazuh Agent 4.9.0 — syscollector.dll Crash

**Status:** Accepted — auto-recovers, non-blocking. Awaiting upstream fix.
**Affected:** win-ep (Windows 10, agent 4.9.0)
**Reported:** Phase 3, June 2026

## Symptom

Windows Application event log records a BEX (Buffer Execution) crash of `wazuh-agent.exe`:

    P1: wazuh-agent.exe
    P2: 4.9.0.0
    P4: syscollector.dll_unloaded
    P8: c0000005    (Access Violation)

Agent log shows brief disconnect followed by auto-reconnect within 10 seconds:

    ERROR: (1137): Lost connection with manager. Setting lock.
    INFO: Trying to connect to server ([192.168.56.10]:1514/tcp).
    INFO: (4102): Connected to the server ([192.168.56.10]:1514/tcp).
    INFO: Agent is now online. Process unlocked, continuing...

## Impact

- Brief gap in event collection (~10 seconds) during agent recovery.
- No data loss for already-queued events (Wazuh agent buffers locally).
- Sysmon, PowerShell, and Defender event channels continue functioning after recovery.
- Manager keeps the agent registered; no re-enrollment required.

## Root cause

Known vendor bug in Wazuh agent 4.9.0. The syscollector module accesses unloaded DLL memory during periodic inventory scans, triggering an Access Violation. Most often observed during system inventory cycles.

## Workarounds considered

| Option | Decision | Reasoning |
| --- | --- | --- |
| Disable syscollector via ossec.conf | Rejected | Loses package, hardware, and process inventory used by Wazuh vulnerability detector |
| Downgrade to 4.8.x | Rejected | Would require re-enrollment and lose 4.9 features |
| Upgrade to 4.10 when released | Selected (planned) | Vendor patch expected to address syscollector stability |
| Accept and monitor | Selected (interim) | Auto-recovery is fast, no operational impact |

## Mitigation in place

None required. Agent self-heals. Manager-side reports the agent as Active throughout.

## Verification commands

On win-ep:

    Get-Service WazuhSvc
    Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 20 | Select-String "Connected to the server"

On siem:

    sudo docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l

## References

- Wazuh issue tracker keyword: syscollector crash windows 4.9
- Windows Error Reporting bucket: 1687476559154832442
