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


# The five tests below exercise event-time matching, so they pin USE_EVENT_TIME
# on regardless of the module default. The default is currently False - the
# endpoint clock is unstable on this lab - but the event-time path stays tested
# because it is the correct basis once the clock is fixed.
import pytest


@pytest.fixture(autouse=False)
def event_time_on(monkeypatch):
    monkeypatch.setattr(scorer, 'USE_EVENT_TIME', True)


# --- event_ts(): matching on endpoint event time, not ingest time ----------
#
# Measured on this lab: ingest lag median 449s over 118 alerts. Scoring on
# @timestamp graded rule 100416 BLIND while the alert existed and had fired
# 3.4s after execution. These guard the fix from regressing.

def win_alert(utc_time=None, system_time=None, ts='2026-01-01T00:10:00+00:00'):
    win = {'eventdata': {}, 'system': {}}
    if utc_time:
        win['eventdata']['utcTime'] = utc_time
    if system_time:
        win['system']['systemTime'] = system_time
    return {'@timestamp': ts, 'data': {'win': win},
            'rule': {'id': 100416, 'level': 14, 'description': 'fixture',
                     'mitre': {'id': ['T1490']}}}


def test_event_ts_prefers_sysmon_utctime_over_ingest(event_time_on):
    a = win_alert(utc_time='2026-01-01 00:00:12.588')
    assert scorer.event_ts(a).isoformat() == '2026-01-01T00:00:12.588000+00:00'


def test_event_ts_parses_seven_digit_fractional_systemtime(event_time_on):
    # strptime %f rejects seven fractional digits; systemTime always has them.
    a = win_alert(system_time='2026-01-01T00:00:12.6270505Z')
    assert scorer.event_ts(a).isoformat() == '2026-01-01T00:00:12.627050+00:00'


def test_event_ts_falls_back_to_ingest_time_without_windows_fields():
    # Suricata and auditd alerts carry no event time. Ingest time is the only
    # time there is; dropping them would be worse than a small bias.
    a = {'@timestamp': '2026-01-01T00:00:12+00:00', 'rule': {'id': 100300}}
    assert scorer.event_ts(a).isoformat() == '2026-01-01T00:00:12+00:00'


def test_event_ts_falls_back_on_unparseable_event_time():
    a = win_alert(utc_time='not a timestamp')
    assert scorer.event_ts(a).isoformat() == '2026-01-01T00:10:00+00:00'


def test_latency_measured_from_event_time_not_ingest_time(event_time_on):
    # The regression itself: event 2s after execution ends, ingested 344s
    # later. Latency must report the detection (2s), and the pipeline delay
    # must survive separately rather than being folded into it.
    step = make_step(expect_rules=[100416], expect_mitre=['T1490'])
    a = win_alert(utc_time='2026-01-01 00:00:12.000',
                  ts='2026-01-01T00:05:56+00:00')
    sc = scorer.score_step(step, [a])
    assert sc['grade'] == 3
    assert sc['detection_latency_s'] == 2.0
    assert sc['matched_alerts'][0]['ingest_lag_s'] == 344.0


def test_window_rejects_late_ingested_alert_from_another_step(event_time_on):
    # The dangerous case the lab cannot produce on demand: the query window is
    # widened by MAX_INGEST_LAG_S, so a neighbouring step's alert IS returned
    # by the indexer. Only event time keeps it out of this step's score.
    from datetime import datetime, timezone
    t0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 1, 1, 0, 4, 0, tzinfo=timezone.utc)
    inside = win_alert(utc_time='2026-01-01 00:00:12.000',
                       ts='2026-01-01T00:06:00+00:00')
    outside = win_alert(utc_time='2026-01-01 00:09:00.000',
                        ts='2026-01-01T00:06:00+00:00')
    kept = scorer.alerts_in_window([inside, outside], t0, t1)
    assert kept == [inside]


def test_window_keeps_alert_stamped_just_before_execution_start(event_time_on):
    from datetime import datetime, timezone
    t0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 1, 1, 0, 4, 0, tzinfo=timezone.utc)
    a = win_alert(utc_time='2025-12-31 23:59:58.000')
    assert scorer.alerts_in_window([a], t0, t1) == [a]
