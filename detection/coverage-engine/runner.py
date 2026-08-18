#!/usr/bin/env python3
"""
Coverage engine - execution runner.

Executes a chain definition against the target endpoint over WinRM and
records precisely when each step ran. It deliberately does NOT evaluate
anything: scoring is a separate stage that reads this file, so a chain can
be re-scored after a rule change without re-running the attack.

Timestamps are UTC because the Wazuh Indexer stores UTC; comparing a local
clock against indexed events is the classic source of a scorer that reports
zero coverage on a working detection.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

import yaml
from pypsrp.client import Client

HERE = os.path.dirname(os.path.abspath(__file__))


def load_env(path):
    env = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                env[k] = v
    return env


def utc_now():
    return datetime.now(timezone.utc)


def ps_quote(s):
    """Single-quote a string for PowerShell, escaping embedded quotes."""
    return "'" + s.replace("'", "''") + "'"


def build_atomic_ps(step, cleanup=False):
    tests = ','.join(str(n) for n in step['test_numbers'])
    verb = '-Cleanup' if cleanup else ''
    return (
        "Set-ExecutionPolicy Bypass -Scope Process -Force; "
        "Import-Module C:\\AtomicRedTeam\\invoke-atomicredteam\\"
        "Invoke-AtomicRedTeam.psd1 -Force; "
        "Invoke-AtomicTest %s -TestNumbers %s %s -Confirm:$false "
        "*>&1 | Out-String" % (step['atomic'], tests, verb)
    )


def build_prereq_ps(step):
    tests = ','.join(str(n) for n in step['test_numbers'])
    return (
        "Set-ExecutionPolicy Bypass -Scope Process -Force; "
        "Import-Module C:\\AtomicRedTeam\\invoke-atomicredteam\\"
        "Invoke-AtomicRedTeam.psd1 -Force; "
        "Invoke-AtomicTest %s -TestNumbers %s -GetPrereqs "
        "*>&1 | Out-String" % (step['atomic'], tests)
    )



DEFENDER_PROBE = (
    "$since = (Get-Date).AddSeconds(-%d); "
    "Get-MpThreatDetection -ErrorAction SilentlyContinue | "
    "Where-Object { $_.InitialDetectionTime -gt $since } | "
    "ForEach-Object { "
    "  '{0}|{1}|{2}' -f $_.InitialDetectionTime.ToUniversalTime()"
    ".ToString('yyyy-MM-ddTHH:mm:ss'), $_.ThreatID, "
    "($_.Resources -join ';') } "
)


def probe_defender(client, lookback_s):
    """Ask the endpoint whether it blocked anything during the step.

    Without this, a technique stopped by ASR looks identical to a technique
    that failed for lack of permissions - and the scorer would file the
    strongest control in the stack as a setup fault.
    """
    try:
        out, _, _ = client.execute_ps(DEFENDER_PROBE % int(lookback_s))
        rows = []
        for line in (out or '').strip().split('\n'):
            parts = line.strip().split('|', 2)
            if len(parts) == 3 and parts[0]:
                rows.append({'time_utc': parts[0], 'threat_id': parts[1],
                             'resources': parts[2][:300]})
        return rows or None
    except Exception:
        return None

def run_step(client, step, defaults, do_cleanup):
    settle = step.get('settle_s', defaults.get('settle_s', 10))
    record = {
        'id': step['id'],
        'name': step['name'],
        'atomic': step.get('atomic'),
        'mode': 'custom' if 'custom_command' in step else 'atomic',
        'test_numbers': step.get('test_numbers'),
        'expect_mitre': step.get('expect_mitre', []),
        'expect_rules': step.get('expect_rules', []),
        'window_s': step.get('window_s', defaults.get('window_s', 90)),
    }

    if 'custom_command' in step:
        inner = step['custom_command'].replace('cmd.exe /c ', '').replace("'", "''")
        ps = ("Start-Process -FilePath 'cmd.exe' -ArgumentList '/c %s' "
              "-Wait -WindowStyle Hidden; "
              "Write-Output 'custom step executed: %s'" % (inner, inner))
    else:
        # prereqs first - a missing dependency silently produces no telemetry,
        # which would be scored as a detection gap rather than a setup failure
        prereq_out, _, prereq_err = client.execute_ps(build_prereq_ps(step))
        record['prereq_error'] = prereq_err
        record['prereq_output'] = (prereq_out or '').strip()[:1500]
        ps = build_atomic_ps(step)

    t0 = utc_now()
    out, streams, had_err = client.execute_ps(ps)
    t1 = utc_now()

    record['t0_utc'] = t0.isoformat()
    record['t1_utc'] = t1.isoformat()
    record['duration_s'] = round((t1 - t0).total_seconds(), 2)
    record['exec_error'] = had_err
    record['output'] = (out or '').strip()[:3000]

    err_msgs = []
    try:
        for e in streams.error:
            err_msgs.append(str(e)[:300])
    except Exception:
        pass
    record['error_stream'] = err_msgs

    # ask before the settle window closes, using the step duration plus a
    # small margin so we only catch blocks belonging to THIS step
    record['defender_blocked'] = probe_defender(
        client, record['duration_s'] + 20)

    time.sleep(settle)

    if do_cleanup and record['mode'] == 'atomic':
        try:
            c_out, _, c_err = client.execute_ps(build_atomic_ps(step, cleanup=True))
            record['cleanup_error'] = c_err
        except Exception as exc:
            record['cleanup_error'] = str(exc)[:200]

    return record


def main():
    ap = argparse.ArgumentParser(description='Run a coverage chain over WinRM.')
    ap.add_argument('chain', help='path to chain YAML')
    ap.add_argument('--env', default=os.path.join(HERE, '.env'))
    ap.add_argument('--out-dir', default=os.path.join(HERE, 'results'))
    ap.add_argument('--cleanup', action='store_true',
                    help='run Atomic -Cleanup after each step')
    ap.add_argument('--only', help='comma-separated step ids to run')
    args = ap.parse_args()

    env = load_env(args.env)
    chain = yaml.safe_load(open(args.chain))
    meta = chain['chain']
    defaults = meta.get('defaults', {})

    steps = chain['steps']
    if args.only:
        wanted = {s.strip() for s in args.only.split(',')}
        steps = [s for s in steps if s['id'] in wanted]
        if not steps:
            print('no steps matched --only', file=sys.stderr)
            return 1

    print('chain   : %s' % meta['id'])
    print('target  : %s (%s)' % (meta['target']['host'], meta['target']['agent_ip']))
    print('steps   : %d' % len(steps))
    print('cleanup : %s' % ('yes' if args.cleanup else 'no'))
    print()

    def new_client():
        return Client(env['WINEP_HOST'], username=env['WINEP_USER'],
                      password=env['WINEP_PASS'], ssl=False, auth='ntlm',
                      cert_validation=False)

    run_start = utc_now()
    records = []
    for step in steps:
        label = '%s %s' % (step['id'], step['name'])
        print('  %-46s ' % label[:46], end='', flush=True)
        try:
            # fresh connection per step: see note above
            rec = run_step(new_client(), step, defaults, args.cleanup)
            flag = 'ERR' if rec['exec_error'] else 'ok '
            print('%s  %5.1fs' % (flag, rec['duration_s']))
        except Exception as exc:
            print('FAIL  %s' % str(exc)[:60])
            rec = {'id': step['id'], 'name': step['name'],
                   'fatal_error': str(exc)[:400],
                   't0_utc': utc_now().isoformat()}
        records.append(rec)

    run_end = utc_now()
    stamp = run_start.strftime('%Y%m%dT%H%M%SZ')
    os.makedirs(args.out_dir, exist_ok=True)
    out_path = os.path.join(args.out_dir, 'run-%s-%s.json' % (meta['id'], stamp))

    payload = {
        'chain_id': meta['id'],
        'chain_name': meta['name'],
        'target': meta['target'],
        'limitations': meta.get('limitations', []),
        'run_start_utc': run_start.isoformat(),
        'run_end_utc': run_end.isoformat(),
        'cleanup': args.cleanup,
        'steps': records,
    }
    with open(out_path, 'w') as fh:
        json.dump(payload, fh, indent=2)

    print()
    print('execution record: %s' % out_path)
    return 0


if __name__ == '__main__':
    sys.exit(main())
