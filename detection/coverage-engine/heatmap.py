#!/usr/bin/env python3
"""
Coverage engine - self-contained SVG heatmap.

A Navigator layer is the portable artefact, but it needs the Navigator app to
render. This produces an SVG that GitHub displays inline, so the coverage
result is visible in the repository itself rather than behind a tool.
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

COLOURS = {
    'PREVENTED': '#2166ac',
    'DETECTED':  '#1a9850',
    'PARTIAL':   '#fdae61',
    'GENERIC':   '#fee08b',
    'LOGGED':    '#f46d43',
    'BLIND':     '#d73027',
}
RANK = {'PREVENTED': 4, 'DETECTED': 3, 'GENERIC': 2, 'LOGGED': 1, 'BLIND': 0}

TACTIC = {
    'T1046': 'Discovery',
    'T1082': 'Discovery',
    'T1003.001': 'Credential Access',
    'T1059.001': 'Execution',
    'T1547.001': 'Persistence',
    'T1490': 'Impact',
    'T1486': 'Impact',
    'T1489': 'Impact',
    'T1070.001': 'Impact',
}
ORDER = ['Execution', 'Persistence', 'Credential Access', 'Discovery', 'Impact']

NAMES = {
    'T1046': 'Network Service Discovery',
    'T1003.001': 'LSASS Memory',
    'T1059.001': 'PowerShell',
    'T1547.001': 'Registry Run Keys',
    'T1490': 'Inhibit System Recovery',
    'T1070.001': 'Clear Windows Event Logs',
    'T1082': 'System Information Discovery',
    'T1486': 'Data Encrypted for Impact',
    'T1489': 'Service Stop',
}


def esc(s):
    return (s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;'))


def collect(rec):
    by = {}
    for step in rec['steps']:
        sc = step.get('score', {})
        label = sc.get('grade_label')
        if label not in RANK:
            continue
        for tech in step.get('expect_mitre', []):
            e = by.setdefault(tech, {'outcomes': set(), 'rules': set(), 'lat': []})
            e['outcomes'].add(label)
            for r in (sc.get('expected_fired') or []) + (sc.get('other_custom_rules') or []):
                e['rules'].add(r)
            if sc.get('detection_latency_s') is not None:
                e['lat'].append(sc['detection_latency_s'])

    out = {}
    for tech, e in by.items():
        covered = {'PREVENTED', 'DETECTED'}
        if (e['outcomes'] & covered) and (e['outcomes'] - covered):
            final = 'PARTIAL'
        else:
            final = max(e['outcomes'], key=lambda o: RANK[o])
        out[tech] = {
            'grade': final,
            'rules': sorted(e['rules']),
            'latency': min(e['lat']) if e['lat'] else None,
        }
    return out


def render(rec, data):
    s = rec.get('summary', {})
    cols = [t for t in ORDER if any(TACTIC.get(k) == t for k in data)]

    CW, CH, GAP = 165, 62, 10
    X0, Y0 = 24, 150
    W = X0 * 2 + len(cols) * (CW + GAP)
    rows = max(sum(1 for k in data if TACTIC.get(k) == c) for c in cols)
    H = Y0 + rows * (CH + GAP) + 108

    o = []
    a = o.append
    a('<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" '
      'viewBox="0 0 %d %d" font-family="-apple-system,Segoe UI,Helvetica,Arial,sans-serif">' % (W, H, W, H))
    a('<rect width="%d" height="%d" fill="#ffffff"/>' % (W, H))

    a('<text x="%d" y="42" font-size="21" font-weight="600" fill="#111">'
      'Detection coverage - measured, not inventoried</text>' % X0)
    a('<text x="%d" y="68" font-size="13" fill="#555">Chain: %s | Target: %s | %s</text>' % (
        X0, esc(rec['chain_id']), esc(rec['target']['host']),
        esc(str(s.get('scored_utc', ''))[:19])))
    a('<text x="%d" y="94" font-size="16" font-weight="600" fill="#111">'
      'Coverage %s%% (%s/%s points, %s steps)</text>' % (
          X0, s.get('coverage_pct'), s.get('coverage_points'),
          s.get('coverage_max'), s.get('steps_scored')))

    lx = X0
    for label in ['PREVENTED', 'DETECTED', 'PARTIAL', 'GENERIC', 'LOGGED', 'BLIND']:
        a('<rect x="%d" y="112" width="12" height="12" rx="2" fill="%s"/>' % (lx, COLOURS[label]))
        a('<text x="%d" y="122" font-size="11" fill="#444">%s</text>' % (lx + 17, label.title()))
        lx += 22 + len(label) * 7

    for ci, tac in enumerate(cols):
        cx = X0 + ci * (CW + GAP)
        a('<text x="%d" y="%d" font-size="12" font-weight="600" fill="#333" '
          'text-transform="uppercase">%s</text>' % (cx, Y0 - 12, esc(tac)))

        techs = sorted(k for k in data if TACTIC.get(k) == tac)
        for ri, tech in enumerate(techs):
            d = data[tech]
            cy = Y0 + ri * (CH + GAP)
            a('<rect x="%d" y="%d" width="%d" height="%d" rx="5" fill="%s"/>' % (
                cx, cy, CW, CH, COLOURS[d['grade']]))
            a('<text x="%d" y="%d" font-size="12" font-weight="700" fill="#fff">%s</text>' % (
                cx + 10, cy + 20, esc(tech)))
            a('<text x="%d" y="%d" font-size="10" fill="#ffffff" opacity="0.95">%s</text>' % (
                cx + 10, cy + 35, esc(NAMES.get(tech, '')[:26])))
            detail = d['grade'].title()
            if d['rules']:
                detail += '  ' + ','.join(d['rules'][:3])
            if d['latency'] is not None:
                detail += '  %.0fs' % d['latency']
            a('<text x="%d" y="%d" font-size="9" fill="#ffffff" opacity="0.9">%s</text>' % (
                cx + 10, cy + 50, esc(detail[:33])))

    fy = Y0 + rows * (CH + GAP) + 28
    a('<text x="%d" y="%d" font-size="11" fill="#555">'
      'Each cell was executed against the live stack; the grade reflects what the SIEM produced.</text>' % (X0, fy))
    a('<text x="%d" y="%d" font-size="11" fill="#555">'
      'Partial means one procedure is covered and another is blind - coverage belongs to the procedure, not the technique.</text>' % (X0, fy + 18))
    a('<text x="%d" y="%d" font-size="11" fill="#555">'
      'Latency is measured from the end of attack execution to the first matching alert.</text>' % (X0, fy + 36))
    a('<text x="%d" y="%d" font-size="10" fill="#888">github.com/AJahmadcyber/homelab-mdr</text>' % (X0, fy + 60))
    a('</svg>')
    return '\n'.join(o)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('score_file')
    ap.add_argument('--out')
    args = ap.parse_args()

    rec = json.load(open(args.score_file))
    svg = render(rec, collect(rec))

    out = args.out or os.path.join(HERE, 'results', 'layers',
                                   'coverage-%s.svg' % rec['chain_id'])
    open(out, 'w').write(svg)
    print('svg:', out)
    print('bytes:', len(svg))
    return 0


if __name__ == '__main__':
    sys.exit(main())
