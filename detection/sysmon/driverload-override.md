# Sysmon DriverLoad override (Phase 7, Stage 4)

Applies to `sysmonconfig.xml` (sysmon-modular) on the Windows endpoint.
Everything else in that config is upstream; only this block is changed.

## What shipped

sysmon-modular excludes driver loads by signer: an `and` rule for
`Signature begin with "Intel "` + `SignatureStatus is Valid`, and a second for
`Signature contains "Microsoft"` + `SignatureStatus is Valid`.

## Why that is wrong here

BYOVD works by loading a driver that is *legitimately signed* and vulnerable.
Excluding validly signed Microsoft and Intel drivers therefore filters out the
exact class the technique relies on. Both signers appear in real attacks: Intel
network drivers are long-standing BYOVD staples, and in 2026 a Microsoft-signed
driver was used to terminate a PPL-protected EDR sensor.

The exclusion was justified by log volume. That justification did not survive
measurement: this host produces **9 driver-load events per full boot**, matching
the 10-50/day figure in TrustedSec's Sysmon Community Guide. Filtering saved no
meaningful volume and cost the entire detection surface.

## What is applied

`<DriverLoad onmatch="exclude">` with an empty body - log every driver load.
An empty `exclude` list logs everything; an empty `include` list would log
nothing. The two are easy to confuse and the difference is total.

Selection moved from the sensor into the rules (`9991-byovd-detection.xml`),
where it is version-controlled, reviewable and testable. A sensor-side exclusion
is invisible: nothing records what was never generated.

## Verification

| Test | Driver | Path | Result |
|---|---|---|---|
| Baseline | `storqosflt.sys` | `System32\drivers\` | EID 6 logged |
| BYOVD pattern | `evilqos.sys` (byte-identical copy) | `C:\Windows\Temp\` | EID 6 logged -> rule **100341**, level 12 |

The BYOVD test reports `Signature: Microsoft Windows` / `SignatureStatus: Valid`
and is still caught, because the rule keys on **path**, not signer. Under the
shipped config this event did not exist at all.

Staged with the same sequence a real intrusion uses: copy a signed driver into
`C:\Windows\Temp\`, register it with `sc create <name> type= kernel binPath=
\??\<path>`, then `sc start`.

## Notes

- `CheckRevocation` was trialled and reverted. It is sound guidance where CRL
  endpoints are reachable, but is left off here rather than carried as an
  unverified setting. Signature resolution failures observed during the trial
  were not conclusively attributed to it.
- `SignatureStatus` is not used as a detection signal. Sysmon resolves
  signatures asynchronously, so rapid manual loads legitimately report
  `Unavailable`; alerting on that would be a false-positive generator.
- Kernel service paths must use the `\??\` prefix. A plain `C:\` path fails with
  `StartService FAILED 2` and generates no driver-load event.
