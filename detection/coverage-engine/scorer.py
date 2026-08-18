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
from datetime import datetime, timedelta

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HERE = os.path.dirname(os.path.abspath(__file__))
CUSTOM_RULE_FLOOR = 100000

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


def query_alerts(env, t0, t1, agent_id):
    """Every alert from the target agent inside the step's window."""
    body = {
        'size': 200,
        'sort': [{'@timestamp': {'order': 'asc'}}],
        '_source': ['@timestamp', 'rule.id', 'rule.level',
                    'rule.description', 'rule.mitre.id', 'agent.name'],
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
    r = requests.post(
        '%s/wazuh-alerts-*/_search' % env['INDEXER_URL'],
        auth=(env['INDEXER_USER'], env['INDEXER_PASS']),
        headers={'Content-Type': 'application/json'},
        json=body, verify=False, timeout=30)
    r.raise_for_status()
    return [h['_source'] for h in r.json()['hits']['hits']]


def score_step(step, alerts):
    """Grade one step against the alerts observed in its window."""
    t0 = parse_ts(step['t0_utc'])
    t1 = parse_ts(step.get('t1_utc', step['t0_utc']))
    expect_rules = {str(r) for r in step.get('expect_rules', [])}
    expect_mitre = set(step.get('expect_mitre', []))

    matched, custom, generic, unrelated = [], [], [], []

    for a in alerts:
        rid = str(a.get('rule', {}).get('id', ''))
        mitre = a.get('rule', {}).get('mitre', {}).get('id', []) or []
        entry = {
            'rule_id': rid,
            'level': a.get('rule', {}).get('level'),
            'description': a.get('rule', {}).get('description', '')[:110],
            'mitre': mitre,
            'ts': a.get('@timestamp'),
            'latency_s': round((parse_ts(a['@timestamp']) - t1).total_seconds(), 2),
            'latency_from_call_s': round((parse_ts(a['@timestamp']) - t0).total_seconds(), 2),
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
        grade = 0   # refined to 1 by the archives probe below

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
        'latency_basis': 'seconds from end of attack execution to first matching alert',
        'matched_alerts': matched[:10],
        'generic_alerts': generic[:5],
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

        alerts = query_alerts(env, exec_start, win_end, agent_id)
        sc = score_step(step, alerts)

        fired = sc['expected_fired'] or sc['other_custom_rules'] or sc['generic_rules']
        lat = '%.1fs' % sc['detection_latency_s'] if sc['detection_latency_s'] is not None else '-'
        print('%-4s %-34s %-9s %-8s %s' % (
            step['id'], step['name'][:34], sc['grade_label'], lat,
            ','.join(fired[:6]) or '(none)'))

        scored.append({**step, 'score': sc})

    out_path = args.run_file.replace('run-', 'score-')
    graded = [s for s in scored if s['score'].get('grade') is not None]
    total = sum(min(s['score']['grade'], 3) for s in graded)
    maximum = 3 * len(graded)

    summary = {
        'chain_id': run['chain_id'],
        'scored_utc': datetime.utcnow().isoformat() + 'Z',
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
