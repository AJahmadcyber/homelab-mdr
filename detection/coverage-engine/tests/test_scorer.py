#!/usr/bin/env python3
"""
Unit tests for the coverage scorer's grading logic.

These exercise score_step() directly with hand-built fixtures. There are no
network calls, no Indexer and no endpoint: the archive probe is injected as a
plain callable, so every grade path - including the BLIND -> LOGGED upgrade -
is asserted deterministically. The point of the coverage engine is that grades
are measured, not asserted; these tests guard the measurement itself.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scorer  # noqa: E402

# A fixed window shared by the fixtures. t1 marks the end of execution; alert
# latency is measured from it.
T0 = '2026-01-01T00:00:00+00:00'
T1 = '2026-01-01T00:00:10+00:00'


def make_step(**overrides):
    step = {'id': 'X1', 'name': 'fixture step', 't0_utc': T0, 't1_utc': T1,
            'expect_mitre': ['T1046'], 'expect_rules': []}
    step.update(overrides)
    return step


def make_alert(rule_id, mitre, ts=T1, level=5, description='fixture alert'):
    return {'@timestamp': ts,
            'rule': {'id': rule_id, 'level': level,
                     'description': description, 'mitre': {'id': list(mitre)}}}


def test_custom_on_technique_rule_returns_detected():
    # A custom rule (>= 100000) mapped to the step's technique, but not named
    # in expect_rules, is still real coverage: grade 3.
    step = make_step(expect_rules=[])
    alerts = [make_alert(100999, ['T1046'])]
    sc = scorer.score_step(step, alerts)
    assert sc['grade'] == 3
    assert sc['grade_label'] == 'DETECTED'
    assert sc['other_custom_rules'] == ['100999']


def test_generic_on_technique_rule_returns_generic():
    # A community rule (below the custom floor) on the right technique reaches
    # only grade 2 - an alert with no technique mapping of our own.
    step = make_step(expect_rules=[])
    alerts = [make_alert(92052, ['T1046'])]
    sc = scorer.score_step(step, alerts)
    assert sc['grade'] == 2
    assert sc['grade_label'] == 'GENERIC'
    assert sc['generic_rules'] == ['92052']


def test_unrelated_rules_only_returns_blind():
    # Rules that fired in the window but describe a different technique are
    # noise (the runner's own PowerShell trips these); grade stays 0.
    step = make_step(expect_mitre=['T1046'], expect_rules=[])
    alerts = [make_alert(100100, ['T1059.001']),
              make_alert(92110, ['T1055'])]
    sc = scorer.score_step(step, alerts)
    assert sc['grade'] == 0
    assert sc['grade_label'] == 'BLIND'
    assert sc['unrelated_count'] == 2


def test_evidence_match_satisfied_returns_logged():
    # No rule fired, but the step's evidence contract is backed by archived
    # telemetry: BLIND -> LOGGED. The probe stands in for the archives query.
    step = make_step(expect_rules=[],
                     evidence_match={'contains': ['TcpClient', 'Net.Sockets'],
                                     'event_id': 4104})

    def probe(s, t0, t1):
        return {'contains': s['evidence_match']['contains'],
                'event_id': 4104, 'event_count': 1121,
                'sample': {'full_log': 'New-Object System.Net.Sockets.TcpClient'}}

    sc = scorer.score_step(step, [], archive_probe=probe)
    assert sc['grade'] == 1
    assert sc['grade_label'] == 'LOGGED'
    assert sc['logged_evidence']['event_count'] == 1121
    assert sc['logged_evidence']['sample'] is not None


def test_evidence_match_absent_stays_blind():
    # A step with no evidence_match is never upgraded, even if a probe would
    # have returned a positive count. LOGGED requires the step's own contract.
    step = make_step(expect_rules=[])

    def probe(s, t0, t1):
        raise AssertionError('probe must not be consulted without evidence_match')

    sc = scorer.score_step(step, [], archive_probe=probe)
    assert sc['grade'] == 0
    assert sc['grade_label'] == 'BLIND'
    assert sc['logged_evidence'] is None


def test_evidence_probe_with_zero_count_stays_blind():
    # The archives were queryable but held no matching evidence: no upgrade.
    step = make_step(expect_rules=[],
                     evidence_match={'contains': ['TcpClient']})
    sc = scorer.score_step(step, [], archive_probe=lambda s, a, b: {'event_count': 0})
    assert sc['grade'] == 0
    assert sc['logged_evidence'] is None


def test_missing_archive_index_leaves_grade_blind():
    # A probe returning None models an absent/unreachable index. The grade must
    # not move; a missing index can never silently alter a score.
    step = make_step(expect_rules=[],
                     evidence_match={'contains': ['TcpClient']})
    sc = scorer.score_step(step, [], archive_probe=lambda s, a, b: None)
    assert sc['grade'] == 0
    assert sc['logged_evidence'] is None


def test_small_negative_latency_is_clamped_to_zero():
    # An on-technique alert stamped just before t1 (logged the instant the
    # command ran) yields a small negative latency; it is clamped to 0.0, not
    # published as a negative number.
    step = make_step(expect_rules=[])
    alerts = [make_alert(100999, ['T1046'], ts='2026-01-01T00:00:09+00:00')]
    sc = scorer.score_step(step, alerts)
    assert sc['grade'] == 3
    assert sc['detection_latency_s'] == 0.0
