"""Unit tests for the SOAR blocker's safety controls.

These exercise the decision logic only — no pfSense, no network. The safety
controls are the part that must hold when everything else is failing, so they
are tested independently of the API path that surrounds them.
"""
import importlib.util
import ipaddress
import json
import pathlib
import sys
from datetime import datetime, timedelta

import pytest

MODULE = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "soar-block.py"


def load_module(tmp_state=None):
    spec = importlib.util.spec_from_file_location("soar_block", MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if tmp_state is not None:
        mod.STATE_FILE = str(tmp_state)
        mod.LOCK_FILE = str(tmp_state) + ".lock"
    return mod


@pytest.fixture
def sb(tmp_path):
    return load_module(tmp_path / "block-state.json")


# --- address normalisation -------------------------------------------------

def test_dotted_quad_matches_allowlist(sb):
    assert sb.normalize("10.10.10.1") == sb.normalize("10.10.10.1")


def test_ipv4_mapped_ipv6_matches_its_dotted_quad(sb):
    """The gateway written as ::ffff:10.10.10.1 must not read as a different
    host: object comparison alone reports these as unequal."""
    assert sb.normalize("::ffff:10.10.10.1") == sb.normalize("10.10.10.1")


def test_hex_mapped_form_matches_too(sb):
    assert sb.normalize("::ffff:0a0a:0a01") == sb.normalize("10.10.10.1")


def test_unrelated_address_does_not_match(sb):
    assert sb.normalize("10.10.10.20") != sb.normalize("10.10.10.1")


def test_leading_zero_form_is_rejected(sb):
    with pytest.raises(ValueError):
        sb.normalize("10.10.10.010")


# --- alias entries that are not bare addresses -----------------------------

def test_parseable_accepts_a_bare_address(sb):
    assert sb._parseable("10.10.10.20") is True


def test_parseable_skips_cidr_and_hostnames(sb):
    assert sb._parseable("10.10.10.0/24") is False
    assert sb._parseable("host.lab.local") is False


# --- circuit breaker -------------------------------------------------------

def test_breaker_allows_when_under_the_limit(sb):
    now = datetime.utcnow()
    state = {"blocks": [(now - timedelta(minutes=1)).isoformat()]}
    ok, count = sb.check_circuit_breaker(state)
    assert ok is True and count == 1


def test_breaker_trips_at_the_ceiling(sb):
    now = datetime.utcnow()
    state = {"blocks": [(now - timedelta(minutes=i)).isoformat()
                        for i in range(sb.CB_MAX_BLOCKS)]}
    ok, count = sb.check_circuit_breaker(state)
    assert ok is False and count == sb.CB_MAX_BLOCKS


def test_breaker_ignores_blocks_outside_the_window(sb):
    old = datetime.utcnow() - timedelta(minutes=sb.CB_WINDOW_MIN + 5)
    state = {"blocks": [old.isoformat()] * 10}
    ok, count = sb.check_circuit_breaker(state)
    assert ok is True and count == 0


def test_breaker_prunes_expired_entries_from_state(sb):
    old = datetime.utcnow() - timedelta(minutes=sb.CB_WINDOW_MIN + 5)
    recent = datetime.utcnow() - timedelta(minutes=1)
    state = {"blocks": [old.isoformat(), recent.isoformat()]}
    sb.check_circuit_breaker(state)
    assert state["blocks"] == [recent.isoformat()]


# --- state persistence -----------------------------------------------------

def test_missing_state_file_reads_as_empty(sb):
    assert sb.load_state() == {"blocks": []}


def test_state_round_trips(sb):
    stamp = datetime.utcnow().isoformat()
    sb.save_state({"blocks": [stamp]})
    assert sb.load_state()["blocks"] == [stamp]


def test_lock_is_released_after_the_block(sb):
    """A held lock must not outlive its context, or the next invocation
    blocks forever."""
    with sb.state_lock():
        pass
    with sb.state_lock():
        pass
