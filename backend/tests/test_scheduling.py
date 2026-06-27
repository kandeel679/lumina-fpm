"""Scheduling tests — pure cron evaluator + next-run calculator (no DB, no Celery).

Run: `python backend/tests/test_scheduling.py`  (or via pytest).
"""
import os
import sys
from contextlib import contextmanager
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.scheduling import (  # noqa: E402
    compute_next_run,
    cron_matches,
    describe,
    next_cron_after,
    parse_cron,
)


@contextmanager
def assert_raises(exc_type):
    """Tiny pytest.raises stand-in so this module runs with or without pytest."""
    try:
        yield
    except exc_type:
        return
    raise AssertionError(f"expected {exc_type.__name__} to be raised")


# --- parse_cron validation --------------------------------------------------

def test_parse_cron_valid():
    p = parse_cron("0 2 * * *")
    assert 0 in p["minute"] and 2 in p["hour"]
    assert p["dom_restricted"] is False
    assert p["dow_restricted"] is False


def test_parse_cron_field_count():
    with assert_raises(ValueError):
        parse_cron("0 2 * *")          # 4 fields
    with assert_raises(ValueError):
        parse_cron("0 2 * * * *")      # 6 fields


def test_parse_cron_out_of_range():
    with assert_raises(ValueError):
        parse_cron("60 * * * *")       # minute 60 invalid
    with assert_raises(ValueError):
        parse_cron("* 24 * * *")       # hour 24 invalid


# --- cron_matches -----------------------------------------------------------

def test_daily_at_time():
    assert cron_matches("0 2 * * *", datetime(2024, 1, 1, 2, 0))
    assert not cron_matches("0 2 * * *", datetime(2024, 1, 1, 2, 1))
    assert not cron_matches("0 2 * * *", datetime(2024, 1, 1, 3, 0))


def test_step_minutes():
    expr = "*/15 * * * *"
    assert cron_matches(expr, datetime(2024, 1, 1, 10, 0))
    assert cron_matches(expr, datetime(2024, 1, 1, 10, 15))
    assert cron_matches(expr, datetime(2024, 1, 1, 10, 45))
    assert not cron_matches(expr, datetime(2024, 1, 1, 10, 7))


def test_step_hours():
    expr = "0 */6 * * *"
    for h in (0, 6, 12, 18):
        assert cron_matches(expr, datetime(2024, 1, 1, h, 0))
    assert not cron_matches(expr, datetime(2024, 1, 1, 5, 0))


def test_day_of_week():
    # 2024-01-01 is a Monday (Python weekday()==0 -> cron dow 1).
    monday = datetime(2024, 1, 1, 9, 0)
    tuesday = datetime(2024, 1, 2, 9, 0)
    assert cron_matches("0 9 * * 1", monday)
    assert not cron_matches("0 9 * * 1", tuesday)


def test_dom_dow_or_semantics():
    # "0 0 1 * 1" -> midnight on (day==1 OR Monday). Both fields restricted => OR.
    expr = "0 0 1 * 1"
    assert cron_matches(expr, datetime(2024, 3, 1, 0, 0))   # the 1st (a Friday)
    assert cron_matches(expr, datetime(2024, 1, 8, 0, 0))   # a Monday, not the 1st
    assert not cron_matches(expr, datetime(2024, 3, 2, 0, 0))  # neither


def test_list_values():
    expr = "0 9,17 * * *"
    assert cron_matches(expr, datetime(2024, 1, 1, 9, 0))
    assert cron_matches(expr, datetime(2024, 1, 1, 17, 0))
    assert not cron_matches(expr, datetime(2024, 1, 1, 13, 0))


# --- next_cron_after --------------------------------------------------------

def test_next_cron_same_day():
    nxt = next_cron_after("0 2 * * *", datetime(2024, 1, 1, 1, 30))
    assert nxt == datetime(2024, 1, 1, 2, 0)


def test_next_cron_wraps_to_next_day():
    nxt = next_cron_after("0 2 * * *", datetime(2024, 1, 1, 3, 0))
    assert nxt == datetime(2024, 1, 2, 2, 0)


def test_next_cron_strictly_after():
    # Exactly on a matching minute -> returns the NEXT occurrence, not this one.
    nxt = next_cron_after("*/15 * * * *", datetime(2024, 1, 1, 10, 0))
    assert nxt == datetime(2024, 1, 1, 10, 15)


# --- compute_next_run -------------------------------------------------------

def test_compute_next_run_interval():
    now = datetime(2024, 1, 1, 10, 0)
    assert compute_next_run("interval", 60, None, now) == now + timedelta(minutes=60)
    assert compute_next_run("interval", 360, None, now) == now + timedelta(hours=6)


def test_compute_next_run_interval_invalid():
    now = datetime(2024, 1, 1, 10, 0)
    assert compute_next_run("interval", None, None, now) is None
    assert compute_next_run("interval", 0, None, now) is None


def test_compute_next_run_cron():
    now = datetime(2024, 1, 1, 1, 0)
    assert compute_next_run("cron", None, "0 2 * * *", now) == datetime(2024, 1, 1, 2, 0)


def test_compute_next_run_unknown_mode():
    assert compute_next_run("nope", 60, None, datetime(2024, 1, 1)) is None


# --- describe ---------------------------------------------------------------

class _Row:
    def __init__(self, mode, interval_minutes=None, cron_expression=None):
        self.mode = mode
        self.interval_minutes = interval_minutes
        self.cron_expression = cron_expression


def test_describe():
    assert describe(_Row("interval", 360)) == "every 6h"
    assert describe(_Row("interval", 1440)) == "every 1d"
    assert describe(_Row("interval", 30)) == "every 30m"
    assert describe(_Row("cron", cron_expression="0 2 * * *")) == "cron 0 2 * * *"
    assert describe(_Row("interval")) == "unconfigured"


if __name__ == "__main__":
    # Standalone runner (mirrors the other test modules — no pytest required).
    import traceback

    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for fn in fns:
        try:
            fn()
            passed += 1
            print(f"  ok  {fn.__name__}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {fn.__name__}")
            traceback.print_exc()
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
