#!/usr/bin/env python3
"""
Coverage engine - ATT&CK Navigator layer generator.

Turns a score record into a Navigator layer (format v4.5, ATT&CK v16) so the
result is a heatmap that reads in seconds rather than a table nobody opens.

Colour choices are deliberate. The conventional green/yellow/red scale
assumes the attack ran and asks only whether it was seen, so it has no place
for a technique that never got to execute. This layer uses five:

  PREVENTED  blue    stopped before execution - better than detected
  DETECTED   green   a custom rule fired, mapped to the technique
  GENERIC    yellow  only a built-in rule fired - alert without meaning
  LOGGED     orange  telemetry arrived, nothing alerted
  BLIND      red     nothing at all

Each technique carries a comment with the evidence: rules that fired, the
measured latency, and the step that produced it. A layer without provenance
is a claim; with it, it is a measurement.
"""

import argparse
import json
import os
import sys
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))

ATTACK_VERSION = '16'
NAVIGATOR_VERSION = '5.3.2'
LAYER_VERSION = '4.5'

COLOURS = {
    'PARTIAL':   '#fdae61',
    'PREVENTED': '#2166ac',
    'DETECTED':  '#1a9850',
    'GENERIC':   '#fee08b',
    'LOGGED':    '#f46d43',
    'BLIND':     '#d73027',
}

SCORES = {'PREVENTED': 4, 'DETECTED': 3, 'GENERIC': 2, 'LOGGED': 1, 'BLIND': 0}

# A technique is PARTIAL when its procedures disagree: T1046 is detected when
# run through nmap (rule 100320 keys on the scanner command line) and blind
# when run as a native PowerShell socket loop. Publishing the best outcome
# would hide a real gap behind a working rule; publishing the worst would
# deny a detection that demonstrably fires. Coverage belongs to the
# procedure, so a technique with mixed procedures gets its own colour and the
# comment names which procedure failed.
PARTIAL_SCORE = 2


def build_layer(record, name=None, description=None):
    chain_id = record['chain_id']
    summary = record.get('summary', {})

    # One technique can appear in several steps. Keep the best outcome, but
    # record every step that touched it, so a technique detected by one
    # procedure and missed by another is visible rather than averaged away.
    by_technique = {}

    for step in record['steps']:
        sc = step.get('score', {})
        label = sc.get('grade_label')
        if label not in SCORES:
            continue  # NOTRUN and RUNFAIL are not coverage statements

        for tech in step.get('expect_mitre', []):
            entry = by_technique.setdefault(tech, {
                'best': label, 'steps': [], 'rules': set(), 'latencies': [],
            })
            if SCORES[label] > SCORES[entry['best']]:
                entry['best'] = label
            entry.setdefault('outcomes', set()).add(label)
            entry['steps'].append('%s (%s)' % (step['id'], label))
            for r in sc.get('expected_fired', []) or []:
                entry['rules'].add(r)
            for r in sc.get('other_custom_rules', []) or []:
                entry['rules'].add(r)
            lat = sc.get('detection_latency_s')
            if lat is not None:
                entry['latencies'].append(lat)

    techniques = []
    for tech, e in sorted(by_technique.items()):
        outcomes = e.get('outcomes', {e['best']})
        covered = {'PREVENTED', 'DETECTED'}
        mixed = bool(outcomes & covered) and bool(outcomes - covered)

        if mixed:
            e['best'] = 'PARTIAL'
            bits = ['outcome: PARTIAL - covered for some procedures, blind for others']
        else:
            bits = ['outcome: %s' % e['best']]
        if e['rules']:
            bits.append('rules: %s' % ', '.join(sorted(e['rules'])))
        if e['latencies']:
            bits.append('detection latency: %.1fs' % min(e['latencies']))
        bits.append('steps: %s' % '; '.join(e['steps']))

        techniques.append({
            'techniqueID': tech,
            'score': PARTIAL_SCORE if e['best'] == 'PARTIAL' else SCORES[e['best']],
            'color': COLOURS[e['best']],
            'comment': ' | '.join(bits),
            'enabled': True,
            'showSubtechniques': False,
        })

    return {
        'name': name or 'Coverage - %s' % chain_id,
        'versions': {
            'attack': ATTACK_VERSION,
            'navigator': NAVIGATOR_VERSION,
            'layer': LAYER_VERSION,
        },
        'domain': 'enterprise-attack',
        'description': description or (
            'Measured detection coverage from the homelab-mdr coverage engine. '
            'Chain: %s. Scored %s. Coverage %s%% (%s/%s points). '
            'Every technique was executed against the live stack and graded on '
            'what the SIEM actually produced - not on rule inventory.' % (
                chain_id, summary.get('scored_utc', 'n/a'),
                summary.get('coverage_pct', '?'),
                summary.get('coverage_points', '?'),
                summary.get('coverage_max', '?'))
        ),
        'filters': {'platforms': ['Windows']},
        'sorting': 3,
        'layout': {
            'layout': 'side',
            'showID': True,
            'showName': True,
            'showAggregateScores': False,
        },
        'hideDisabled': False,
        'techniques': techniques,
        'gradient': {
            'colors': [COLOURS['BLIND'], COLOURS['DETECTED']],
            'minValue': 0,
            'maxValue': 4,
        },
        'legendItems': [
            {'label': 'Prevented before execution (ASR/Defender)', 'color': COLOURS['PREVENTED']},
            {'label': 'Partial - one procedure covered, another blind', 'color': COLOURS['PARTIAL']},
            {'label': 'Detected by a custom rule', 'color': COLOURS['DETECTED']},
            {'label': 'Generic rule only - no technique mapping', 'color': COLOURS['GENERIC']},
            {'label': 'Logged, never alerted', 'color': COLOURS['LOGGED']},
            {'label': 'Blind spot', 'color': COLOURS['BLIND']},
        ],
        'showTacticRowBackground': True,
        'tacticRowBackground': '#dddddd',
        'selectTechniquesAcrossTactics': True,
        'selectSubtechniquesWithParent': False,
        'selectVisibleTechniques': False,
        'metadata': [
            {'name': 'chain', 'value': chain_id},
            {'name': 'target', 'value': '%s (agent %s)' % (
                record['target']['host'], record['target']['agent_id'])},
            {'name': 'generated', 'value': datetime.utcnow().isoformat() + 'Z'},
            {'name': 'source', 'value': 'github.com/AJahmadcyber/homelab-mdr'},
        ],
    }


def main():
    ap = argparse.ArgumentParser(description='Generate an ATT&CK Navigator layer.')
    ap.add_argument('score_file', help='score record from scorer.py')
    ap.add_argument('--out', help='output path (default: results/layers/)')
    ap.add_argument('--name', help='layer name')
    args = ap.parse_args()

    record = json.load(open(args.score_file))
    layer = build_layer(record, name=args.name)

    if args.out:
        out_path = args.out
    else:
        out_dir = os.path.join(HERE, 'results', 'layers')
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, 'coverage-%s.json' % record['chain_id'])

    with open(out_path, 'w') as fh:
        json.dump(layer, fh, indent=2)

    print('layer      : %s' % out_path)
    print('techniques : %d' % len(layer['techniques']))
    print()
    for t in layer['techniques']:
        label = t['comment'].split('outcome: ')[1].split(' ')[0].rstrip('-').strip()
        print('  %-12s %-10s %s' % (t['techniqueID'], label, t['comment'][:70]))
    return 0


if __name__ == '__main__':
    sys.exit(main())
