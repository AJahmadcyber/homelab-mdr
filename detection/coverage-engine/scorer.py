#!/usr/bin/env python3
"""
Coverage engine - detection scorer.

Reads an execution record produced by runner.py, queries the Wazuh Indexer
for the window following each step, and grades the result.

The grading scale is four levels, not the conventional three, because a
technique that reaches only a generic community rule is neither covered nor
a blind spot - it produces an alert with no technique mapping, no priority
and no ticket. Collapsing that into either neighbour hides the most
actionable finding a coverage run can produce.

  3  DETECTED   a custom rule fired and maps to the technique
  2  GENERIC    only a community/built-in rule fired - alert without meaning
  1  LOGGED     telemetry reached the SIEM but nothing alerted
  0  BLIND      nothing at all

Custom rules are identified by ID range: this lab namespaces its own rules
at 100000+, everything below is Wazuh's shipped ruleset.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HERE = os.path.dirname(os.path.abspath(__file__))
CUSTOM_RULE_FLOOR = 100000

# Alerts are matched on WHEN THE ENDPOINT LOGGED THE EVENT, not when the
# manager ingested it. Measured on this lab: ingest lag min -2s, median
# 449s, max 645s over 118 alerts. Scoring on @timestamp mixes pipeline
# backlog into detection coverage and reports a rule that fired as BLIND.
# The indexer range filter is still on @timestamp, so the query window is
# widened by this much and the real window is applied in memory.
MAX_INGEST_LAG_S = 900

# win-ep has no working time sync: w32time cannot use pfSense (root dispersion
# never settles) and VBoxService syncs on a 20-minute threshold, so a skew of
# seconds is never corrected. Measured 2026-09-10: win-ep is 15.25s behind the
# SIEM, round-trip 1.45s. Endpoint event times therefore arrive slightly in the
# PAST relative to the step's own t0, and a real detection falls outside its
# window. This is a known lab constraint, not a scorer behaviour: fixing the
# clock is the real repair and this margin should shrink to a few seconds once
# it is done. Set to roughly twice the measured skew, well under the ~185s gap
# between steps, so it can never pull a neighbouring step's alert into scope.
CLOCK_SKEW_SLACK_S = 30

# Endpoint event time is only trustworthy while the endpoint clock is. On this
# lab win-ep has no stable sync (w32time cannot use pfSense, and VBoxService
# fights whatever else touches the clock), and measured skew moved between
# -41s and +48s inside one hour. Ingest lag, by contrast, collapsed to under a
# second once the manager's vulnerability-detector stopped burning a core, so
# @timestamp is now the more accurate of the two. USE_EVENT_TIME exists so this
# can be flipped back the moment the clock is fixed - the endpoint clock is the
# right basis in principle, and this is a measured concession, not a rewrite.
USE_EVENT_TIME = False

GRADE = {4: 'PREVENTED', 3: 'DETECTED', 2: 'GENERIC', 1: 'LOGGED', 0: 'BLIND'}

# PREVENTED is not on the conventional green/yellow/red scale, because that
# scale assumes the attack ran and asks only whether it was seen. A technique
# stopped by ASR or Defender before execution is a better outcome than one
# detected after the fact: there is nothing to investigate. Scoring it as a
# detection gap - or excluding it - would misrepresent the strongest control
# in the stack.
#
# Prevention is credited only on positive evidence: an execution failure
# together with a Defender/ASR detection in the same window. A bare
# "Access is denied" could be a permissions problem, which is a setup fault.
PREVENTION_MARKERS = (
    'Access is denied',
    'Operation did not complete successfully because the file contains a virus',
    'This program is blocked by group policy',
)

# A step counts as "did not run" only when the EXECUTION output shows a hard
# failure AND carries no evidence of the test completing. Prereq output is
# excluded on purpose: Atomic reports "Failed to meet prereq" for setup steps
# that are irrelevant on this host (creating a shadow copy needs Server), then
# runs the test anyway - and the command line still reaches Sysmon, which is
# all the detection needs.
EXEC_FAILURE_MARKERS = (
    'Access is denied',
    'Unable to connect to the remote server',
    'is not recognized as the name of a cmdlet',
)

# Atomic prints "Done executing test" unconditionally - even when the test
# threw and nothing ran - so it cannot be used as proof of execution. A hard
# failure in the execution output is therefore decisive on its own.


def load_env(path):
    env = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                env[k] = v
    return env


def parse_ts(s):
    return datetime.fromisoformat(s.replace('Z', '+00:00'))


# A window that overflows this many alerts stops being paginated and the run
# warns rather than silently dropping the tail. It is a backstop against an
# unbounded query, not an expected size: the baseline sees 33-70 per window.
ALERT_PAGE_SIZE = 500
ALERT_HARD_CAP = 10000


def event_ts(alert):
    """When the endpoint recorded the event, falling back to ingest time.

    Sysmon carries utcTime ('2026-09-10 08:35:00.588') and systemTime
    ('...T08:35:00.6270505Z' - seven fractional digits, which strptime %f
    rejects, hence the truncation). Suricata and auditd alerts carry neither,
    so those fall back to @timestamp: for them ingest time is the only time
    there is, and silently dropping them would be worse than a small bias.
    """
    if not USE_EVENT_TIME:
        return parse_ts(alert['@timestamp'])
    win = (alert.get('data') or {}).get('win') or {}
    raw = ((win.get('eventdata') or {}).get('utcTime')
           or (win.get('system') or {}).get('systemTime'))
    if raw:
        txt = raw.strip().replace('T', ' ').rstrip('Z')
        if '.' in txt:
            head, frac = txt.split('.', 1)
            txt = '%s.%s' % (head, frac[:6])
            fmt = '%Y-%m-%d %H:%M:%S.%f'
        else:
            fmt = '%Y-%m-%d %H:%M:%S'
        try:
            return datetime.strptime(txt, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return parse_ts(alert['@timestamp'])


def alerts_in_window(alerts, t0, t1, slack_s=CLOCK_SKEW_SLACK_S):
    """Keep alerts whose EVENT time falls in the step window.

    The indexer range filter runs on @timestamp and is deliberately widened by
    MAX_INGEST_LAG_S, so this is what actually bounds the step: without it a
    late-ingested alert from a LATER step would be credited to this one.
    slack_s allows an alert stamped microseconds before t0 (see the latency
    clamp in score_step).
    """
    lo = t0 - timedelta(seconds=slack_s)
    return [a for a in alerts if lo <= event_ts(a) <= t1]


def query_alerts(env, t0, t1, agent_id, step_id=None):
    """Every alert from the target agent inside the step's window.

    Paginates with search_after so a noisy window is read in full rather than
    truncated at a fixed page. track_total_hits reports the true count; if it
    ever exceeds what we retrieve (only possible past ALERT_HARD_CAP), the run
    warns on stderr naming the step and both counts, because a coverage tool
    that silently under-reports would score a real detection as BLIND.
    """
    base = {
        'size': ALERT_PAGE_SIZE,
        'track_total_hits': True,
        # _id breaks ties so search_after is a total order and never re-reads
        # or skips alerts that share a millisecond timestamp.
        'sort': [{'@timestamp': {'order': 'asc'}}, {'_id': {'order': 'asc'}}],
        '_source': ['@timestamp', 'rule.id', 'rule.level',
                    'rule.description', 'rule.mitre.id', 'agent.name',
                    'data.win.eventdata.utcTime',
                    'data.win.system.systemTime'],
        'query': {
            'bool': {
                'filter': [
                    {'range': {'@timestamp': {
                        'gte': t0.isoformat(), 'lte': t1.isoformat()}}},
                    {'term': {'agent.id': agent_id}},
                ]
            }
        },
    }

    collected = []
    total = None
    search_after = None
    while len(collected) < ALERT_HARD_CAP:
        body = dict(base)
        if search_after is not None:
            body['search_after'] = search_after
        r = requests.post(
            '%s/wazuh-alerts-*/_search' % env['INDEXER_URL'],
            auth=(env['INDEXER_USER'], env['INDEXER_PASS']),
            headers={'Content-Type': 'application/json'},
            json=body, verify=False, timeout=30)
        r.raise_for_status()
        data = r.json()
        if total is None:
            total = data['hits']['total']['value']
        hits = data['hits']['hits']
        if not hits:
            break
        collected.extend(h['_source'] for h in hits)
        search_after = hits[-1]['sort']
        if len(hits) < ALERT_PAGE_SIZE:
            break

    if total is not None and total > len(collected):
        print('WARNING: step %s window holds %d alerts but only %d were '
              'retrieved (cap %d) - a detection may be under-reported as BLIND'
              % (step_id, total, len(collected), ALERT_HARD_CAP),
              file=sys.stderr)

    return collected


def query_archives(env, t0, t1, agent_id, evidence_match):
    """Count archived events in the window that satisfy a step's evidence
    contract, returning (total_hits, sample_doc).

    Substring matching is delegated to the Indexer: an event qualifies if it
    contains ANY of the `contains` substrings, optionally scoped to a Windows
    event ID. Only the count and a single sample document come back - the
    count decides the grade, the sample makes that grade auditable.

    allow_no_indices=false turns a missing wazuh-archives-* index into a hard
    error instead of a silent empty result. logall_json is on but Filebeat's
    archives shipping may be off, so the index can be absent; when it is, the
    caller must hear about it rather than read 0 hits as 'no evidence' and
    quietly leave a step BLIND that was in fact only a RULE gap.
    """
    contains = evidence_match.get('contains') or []
    event_id = evidence_match.get('event_id')

    filters = [
        {'range': {'@timestamp': {'gte': t0.isoformat(), 'lte': t1.isoformat()}}},
        {'term': {'agent.id': agent_id}},
    ]
    if event_id is not None:
        filters.append({'term': {'data.win.system.eventID': str(event_id)}})

    # One should-clause per substring; minimum_should_match=1 means ANY match
    # qualifies. Field choice is measured, not assumed: PowerShell module
    # logging (4103) carries no scriptBlockText at all - its eventdata is
    # contextInfo and payload, and the executed command line turns up inside
    # contextInfo's Host Application. Script block logging (4104) is the one
    # with scriptBlockText. Searching all three plus full_log covers both
    # channels; searching only scriptBlockText would have missed 1,113 of the
    # 1,121 matching events in the baseline window.
    should = [
        {'query_string': {
            'query': '*%s*' % s,
            'fields': ['full_log',
                       'data.win.eventdata.scriptBlockText',
                       'data.win.eventdata.contextInfo',
                       'data.win.eventdata.payload'],
            'analyze_wildcard': True,
        }}
        for s in contains
    ]

    body = {
        'size': 1,
        'track_total_hits': True,
        '_source': ['@timestamp', 'agent.id', 'data.win.system.eventID',
                    'data.win.eventdata.scriptBlockText',
                    'data.win.eventdata.contextInfo',
                    'data.win.eventdata.payload', 'full_log'],
        'query': {'bool': {
            'filter': filters,
            'should': should,
            'minimum_should_match': 1,
        }},
    }
    r = requests.post(
        '%s/wazuh-archives-*/_search' % env['INDEXER_URL'],
        params={'allow_no_indices': 'false'},
        auth=(env['INDEXER_USER'], env['INDEXER_PASS']),
        headers={'Content-Type': 'application/json'},
        json=body, verify=False, timeout=30)
    r.raise_for_status()
    data = r.json()
    total = data['hits']['total']['value']
    hits = data['hits']['hits']
    sample = hits[0]['_source'] if hits else None
    return total, sample


def make_archive_probe(env, agent_id):
    """Build the archive probe passed to score_step.

    The probe is the only path from BLIND (0) to LOGGED (1). It queries the
    archives for a step's own evidence contract and returns the finding, or
    None when the index is unreachable. It emits at most one notice per run:
    a missing index degrades the whole run's LOGGED grading, and repeating
    that per step would bury the signal.
    """
    state = {'notified': False}

    def probe(step, t0, t1):
        em = step.get('evidence_match') or {}
        try:
            count, sample = query_archives(env, t0, t1, agent_id, em)
        except (requests.RequestException, KeyError, ValueError) as exc:
            if not state['notified']:
                print('notice: wazuh-archives-* is not queryable (%s); the '
                      'LOGGED grade is unavailable this run - steps that scored '
                      'BLIND stay BLIND rather than being upgraded on a guess'
                      % type(exc).__name__, file=sys.stderr)
                state['notified'] = True
            return None
        if count and count > 0:
            return {
                'contains': em.get('contains', []),
                'event_id': em.get('event_id'),
                'event_count': count,
                'sample': sample,
            }
        return {'event_count': count or 0}

    return probe


def score_step(step, alerts, archive_probe=None):
    """Grade one step against the alerts observed in its window.

    archive_probe, when supplied, is a callable(step, t0, t1) -> finding|None.
    It is consulted ONLY for a step that scored 0 and carries an evidence_match
    with substrings, and it upgrades to 1 (LOGGED) only on a positive event
    count. A step with no evidence_match, or unrelated telemetry, stays BLIND.
    """
    t0 = parse_ts(step['t0_utc'])
    t1 = parse_ts(step.get('t1_utc', step['t0_utc']))
    expect_rules = {str(r) for r in step.get('expect_rules', [])}
    expect_mitre = set(step.get('expect_mitre', []))

    matched, custom, generic, unrelated = [], [], [], []

    for a in alerts:
        rid = str(a.get('rule', {}).get('id', ''))
        mitre = a.get('rule', {}).get('mitre', {}).get('id', []) or []
        ets = event_ts(a)
        entry = {
            'rule_id': rid,
            'level': a.get('rule', {}).get('level'),
            'description': a.get('rule', {}).get('description', '')[:110],
            'mitre': mitre,
            'ts': a.get('@timestamp'),
            'event_ts': ets.isoformat(),
            # kept separate on purpose: a slow pipeline is an operational
            # finding, not a detection gap, and collapsing the two was the
            # bug this field exists to prevent recurring.
            'ingest_lag_s': round((parse_ts(a['@timestamp']) - ets).total_seconds(), 2),
            'latency_s': round((ets - t1).total_seconds(), 2),
            'latency_from_call_s': round((ets - t0).total_seconds(), 2),
        }
        is_custom = rid.isdigit() and int(rid) >= CUSTOM_RULE_FLOOR
        on_technique = bool(set(mitre) & expect_mitre)

        if rid in expect_rules:
            matched.append(entry)
        elif is_custom and on_technique:
            # a custom rule we did not name, but mapped to the right
            # technique - still real coverage, worth surfacing
            custom.append(entry)
        elif on_technique:
            generic.append(entry)
        else:
            # fired inside the window but describes a different technique.
            # The runner drives Atomic through PowerShell, so the harness
            # itself trips 100100-100102 on almost every step; counting that
            # as coverage would report a detection the lab does not have.
            unrelated.append(entry)

    if matched or custom:
        grade = 3
    elif generic:
        grade = 2
    else:
        grade = 0

    # BLIND -> LOGGED refinement. A step with no rule hit is only upgraded on
    # its OWN evidence: telemetry proving the technique reached the SIEM even
    # though nothing alerted. This separates a RULE gap (logged, unseen) from a
    # true blind spot. It fires only for grade 0, only with a non-empty
    # evidence contract, and only on a positive count - so background noise
    # (the secwatch heartbeat, the runner's own PowerShell) can never upgrade a
    # step, and a missing archives index leaves the grade untouched.
    logged_evidence = None
    em = step.get('evidence_match')
    if grade == 0 and archive_probe is not None and em and em.get('contains'):
        finding = archive_probe(step, t0, t1)
        if finding and finding.get('event_count', 0) > 0:
            grade = 1
            logged_evidence = finding

    detect_latency = None
    pool = matched or custom or generic  # never `unrelated`
    if pool:
        detect_latency = min(e['latency_s'] for e in pool)
        # An alert can be stamped microseconds BEFORE t1: the event is logged
        # the instant the command runs, while t1 marks the end of the whole
        # PowerShell invocation wrapping it. A small negative value means
        # immediate detection, not a broken clock - clamp it rather than
        # publish a negative latency.
        if -2.0 < detect_latency < 0:
            detect_latency = 0.0

    return {
        'grade': grade,
        'grade_label': GRADE[grade],
        'expected_rules': sorted(expect_rules),
        'expected_fired': sorted({e['rule_id'] for e in matched}),
        'expected_missing': sorted(expect_rules - {e['rule_id'] for e in matched}),
        'other_custom_rules': sorted({e['rule_id'] for e in custom}),
        'generic_rules': sorted({e['rule_id'] for e in generic}),
        'alert_count': len(matched) + len(custom) + len(generic),
        'unrelated_rules': sorted({e['rule_id'] for e in unrelated}),
        'unrelated_count': len(unrelated),
        'detection_latency_s': detect_latency,
        'latency_basis': 'seconds from end of attack execution to the first '
                         'matching alert, measured on endpoint event time',
        'max_ingest_lag_s': (max((e['ingest_lag_s'] for e in pool), default=None)
                             if pool else None),
        'matched_alerts': matched[:10],
        'generic_alerts': generic[:5],
        'logged_evidence': logged_evidence,
    }


def main():
    ap = argparse.ArgumentParser(description='Score a coverage chain run.')
    ap.add_argument('run_file', help='execution record from runner.py')
    ap.add_argument('--env', default=os.path.join(HERE, '.env'))
    args = ap.parse_args()

    env = load_env(args.env)
    run = json.load(open(args.run_file))
    agent_id = run['target']['agent_id']

    print('chain  : %s' % run['chain_id'])
    print('target : %s (agent %s)' % (run['target']['host'], agent_id))
    print()
    print('%-4s %-34s %-9s %-8s %s' % ('ID', 'STEP', 'GRADE', 'LATENCY', 'RULES FIRED'))
    print('-' * 92)

    probe = make_archive_probe(env, agent_id)

    scored = []
    for idx, step in enumerate(run['steps']):
        if 't0_utc' not in step or step.get('fatal_error'):
            print('%-4s %-34s %-9s' % (step['id'], step['name'][:34], 'RUNFAIL'))
            scored.append({**step, 'score': {'grade': None, 'grade_label': 'RUNFAIL'}})
            continue

        blob = step.get('output') or ''

        if step.get('defender_blocked') and any(m in blob for m in PREVENTION_MARKERS):
            print('%-4s %-34s %-9s %-8s %s' % (
                step['id'], step['name'][:34], 'PREVENTED', '-',
                'blocked pre-execution by Defender/ASR'))
            scored.append({**step, 'score': {
                'grade': 4, 'grade_label': 'PREVENTED',
                'reason': 'endpoint prevention stopped the technique before it ran',
                'evidence': step.get('defender_blocked')}})
            continue

        if any(m in blob for m in EXEC_FAILURE_MARKERS):
            print('%-4s %-34s %-9s %-8s %s' % (
                step['id'], step['name'][:34], 'NOTRUN', '-',
                'attack did not execute - setup failure, not a coverage gap'))
            scored.append({**step, 'score': {
                'grade': None, 'grade_label': 'NOTRUN',
                'reason': 'execution failed; nothing was generated to detect'}})
            continue

        exec_start = parse_ts(step['t0_utc'])
        exec_end = parse_ts(step.get('t1_utc', step['t0_utc']))
        win_end = exec_end + timedelta(seconds=step.get('window_s', 240))

        # never let a window run past the moment the next step began
        if idx + 1 < len(run['steps']):
            nxt = run['steps'][idx + 1]
            if 't0_utc' in nxt:
                win_end = min(win_end, parse_ts(nxt['t0_utc']))

        raw_alerts = query_alerts(
            env, exec_start, win_end + timedelta(seconds=MAX_INGEST_LAG_S),
            agent_id, step['id'])
        # 5s of slack: an alert can be stamped just before t0 (see the latency
        # clamp in score_step) without being outside the step.
        alerts = alerts_in_window(raw_alerts, exec_start, win_end)
        newest = max([parse_ts(a['@timestamp']) for a in raw_alerts],
                     default=None)
        if newest is not None and newest < win_end:
            sys.stderr.write(
                'warning: %s - newest ingested alert is %s, before this '
                'window ends (%s). The pipeline has not caught up; a BLIND '
                'grade here may be premature.\n'
                % (step['id'], newest.isoformat(), win_end.isoformat()))
        sc = score_step(step, alerts, archive_probe=probe)

        fired = sc['expected_fired'] or sc['other_custom_rules'] or sc['generic_rules']
        lat = '%.1fs' % sc['detection_latency_s'] if sc['detection_latency_s'] is not None else '-'
        if sc['grade'] == 1 and sc.get('logged_evidence'):
            detail = 'logged: %d archived events, no alert' % (
                sc['logged_evidence'].get('event_count', 0))
        else:
            detail = ','.join(fired[:6]) or '(none)'
        print('%-4s %-34s %-9s %-8s %s' % (
            step['id'], step['name'][:34], sc['grade_label'], lat, detail))

        scored.append({**step, 'score': sc})

    out_path = args.run_file.replace('run-', 'score-')
    graded = [s for s in scored if s['score'].get('grade') is not None]
    total = sum(min(s['score']['grade'], 3) for s in graded)
    maximum = 3 * len(graded)

    summary = {
        'chain_id': run['chain_id'],
        'scored_utc': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'steps_scored': len(graded),
        'coverage_points': total,
        'coverage_max': maximum,
        'coverage_pct': round(100.0 * total / maximum, 1) if maximum else 0.0,
        'by_grade': {GRADE[g]: sum(1 for s in graded if s['score']['grade'] == g)
                     for g in (4, 3, 2, 1, 0)},
    }

    json.dump({**run, 'summary': summary, 'steps': scored},
              open(out_path, 'w'), indent=2)

    print('-' * 92)
    print('coverage: %d/%d points (%.1f%%)   %s' % (
        total, maximum, summary['coverage_pct'],
        '  '.join('%s=%d' % (k, v) for k, v in summary['by_grade'].items())))
    print('score record: %s' % out_path)
    return 0


if __name__ == '__main__':
    sys.exit(main())
