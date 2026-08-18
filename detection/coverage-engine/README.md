# Coverage engine - Phase 8

Measures what the lab's detections actually catch, by running techniques
against the live stack and reading what the SIEM produced.

The engine exists because a rule inventory is not coverage. A rule can exist,
be syntactically valid, and still never fire on the procedure an adversary
picks - and the only way to know is to run the procedure and look.

## Components

| Script | Role |
| --- | --- |
| `runner.py` | Executes a chain over WinRM, records exactly when each step ran |
| `scorer.py` | Queries the Wazuh Indexer per step window and grades the result |
| `navigator.py` | Emits an ATT&CK Navigator layer (format v4.5, ATT&CK v16) |
| `report.py` | Renders an auditable markdown scorecard |

Execution and scoring are separate on purpose: a chain can be re-scored after
a rule change without re-running the attack. During this build that separation
paid for itself repeatedly - the same execution record was re-scored six times
while measurement bugs were found and fixed.

## Usage

```bash
# execute
python runner.py chains/atomic-automated.yml

# grade (reads the run file the previous command printed)
python scorer.py results/run-atomic-automated-<stamp>.json

# publish
python navigator.py results/score-atomic-automated-<stamp>.json
python report.py    results/score-atomic-automated-<stamp>.json
```

`--only A1,A2` runs a subset. `--cleanup` runs Atomic's cleanup after each
step; it is off by default because cleanup generates its own telemetry and
pollutes the next step's window.

## The grading scale

Five outcomes, not the conventional three:

| Grade | Meaning |
| --- | --- |
| **Prevented** | Stopped before execution by ASR/Defender. Nothing to investigate - the best possible outcome, and the conventional green/yellow/red scale has no place for it because it assumes the attack ran. |
| **Detected** | A custom rule fired *and* maps to the technique executed. |
| **Generic only** | Only a built-in rule fired: an alert with no technique mapping, no priority, no ticket. Neither coverage nor a blind spot, and collapsing it into either neighbour hides the most actionable finding a run can produce. |
| **Logged only** | Telemetry reached the SIEM; nothing alerted. The distinction from *Blind* is diagnostic: it says the problem is the rules, not the logging. |
| **Blind** | Nothing at all. |

`Not run` is reported separately and excluded from the score. A step whose
attack never executed cannot be a detection gap, and counting a setup failure
as a blind spot inflates the gap list with fiction.

## Coverage belongs to the procedure, not the technique

T1046 in the baseline is **Partial**: detected when run through nmap, blind
when run as a native PowerShell socket loop. Rule 100320 keys on a scanner
command line, so it covers one procedure and cannot see the other. Publishing
the best outcome would hide a real gap behind a working rule; publishing the
worst would deny a detection that demonstrably fires. The layer therefore
gives mixed techniques their own colour, and the comment names which procedure
failed.

## Measurement notes

**Latency** is measured from the *end* of attack execution to the first
matching alert. Measuring from the start of the tool invocation would make a
two-minute subnet scan look like a two-minute detection delay.

**Detection latency depends on load.** An isolated step alerts in 5-45s; seven
steps back to back queue the manager and push the same detections to 106-133s.
That is why `settle_s` is 180s: the scorer clips each step's window at the next
step's start time so two adjacent steps sharing a technique cannot be credited
with each other's late alerts, and clipping is only safe when the gap between
steps exceeds detection latency.

**Harness noise is excluded by technique match.** The runner drives Atomic
through PowerShell, so the harness itself trips rules 100100-100102 on nearly
every step. An alert inside the window is not enough; it must map to the
technique under test.

**WinRM changes the parent process** to `wsmprovhost.exe`. The rules in this
lab key on command line and are unaffected, but any future rule keyed on
`ParentImage` must be validated manually as well.

## Credentials

`.env` holds the endpoint and Indexer credentials and is git-ignored. See
`.env.example` for the required keys.
