# SPDX-License-Identifier: Apache-2.0
"""EP-CURRENCY-v1 parity test (port of packages/verify/currency.test.js).

Asserts the two-valued verification result: authentic_as_of_commit is passed
through, and currency_at_T is the COMPUTED value offline verification cannot
supply. Covers 'unknown' (offline default), 'fresh', 'stale' (aged and revoked),
and the fail-safe branches. Same accepts/refuses and same reason strings as JS.

    pytest packages/python-verify/tests/test_currency.py
"""
import datetime
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from emilia_verify import (  # noqa: E402
    evaluate_currency,
    CURRENCY_STATUS,
    CURRENCY_REASON,
    CURRENCY_VERSION,
)

NOW = "2026-07-05T12:00:00.000Z"
ACTION_HASH = "sha256:" + "a" * 64
OTHER_HASH = "sha256:" + "b" * 64
receipt = {"action_hash": ACTION_HASH}


def head_at(sec, extra=None):
    """A head observed `sec` seconds before NOW, formatted as toISOString would."""
    now_ms = datetime.datetime.fromisoformat(NOW.replace("Z", "+00:00")).timestamp() * 1000
    obs_ms = now_ms - sec * 1000
    dt = datetime.datetime.fromtimestamp(obs_ms / 1000, datetime.timezone.utc)
    observed_at = dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(round(obs_ms)) % 1000:03d}Z"
    out = {"observed_at": observed_at}
    if extra:
        out.update(extra)
    return out


def test_enum_and_version():
    assert sorted(CURRENCY_STATUS) == ["fresh", "stale", "unknown"]
    assert CURRENCY_VERSION == "EP-CURRENCY-v1"


# ── status: 'unknown' — the fail-safe offline default ────────────────────────
def test_no_fresh_head_is_unknown():
    r = evaluate_currency({"receipt": receipt, "authentic_as_of_commit": True, "now": NOW})
    assert r["authentic_as_of_commit"] is True
    assert r["currency_at_T"]["status"] == "unknown"
    assert r["currency_at_T"]["reason"] == CURRENCY_REASON["offline_only_no_fresh_head"]
    assert r["currency_at_T"]["evaluated_at"] == NOW
    # Core honesty invariant: offline-only must NEVER report 'fresh'.
    assert r["currency_at_T"]["status"] != "fresh"


def test_null_fresh_head_same_as_absent():
    r = evaluate_currency({"receipt": receipt, "authentic_as_of_commit": True, "now": NOW, "freshHead": None})
    assert r["currency_at_T"]["status"] == "unknown"
    assert r["currency_at_T"]["reason"] == CURRENCY_REASON["offline_only_no_fresh_head"]


# ── status: 'fresh' ──────────────────────────────────────────────────────────
def test_recent_non_revoking_head_is_fresh():
    r = evaluate_currency({
        "receipt": receipt, "authentic_as_of_commit": True, "now": NOW,
        "maxStalenessSeconds": 300, "freshHead": head_at(60),
    })
    assert r["currency_at_T"]["status"] == "fresh"
    assert r["currency_at_T"]["reason"] == CURRENCY_REASON["fresh_head_within_window"]
    assert r["currency_at_T"]["evaluated_at"] == NOW


def test_fresh_independent_of_authenticity():
    r = evaluate_currency({
        "receipt": receipt, "authentic_as_of_commit": False, "now": NOW,
        "maxStalenessSeconds": 300, "freshHead": head_at(10),
    })
    assert r["authentic_as_of_commit"] is False
    assert r["currency_at_T"]["status"] == "fresh"


# ── status: 'stale' ──────────────────────────────────────────────────────────
def test_head_older_than_bound_is_stale():
    r = evaluate_currency({
        "receipt": receipt, "authentic_as_of_commit": True, "now": NOW,
        "maxStalenessSeconds": 300, "freshHead": head_at(600),
    })
    assert r["currency_at_T"]["status"] == "stale"
    assert r["currency_at_T"]["reason"] == CURRENCY_REASON["fresh_head_stale"]


def test_scalar_revoked_is_stale():
    r = evaluate_currency({
        "receipt": receipt, "authentic_as_of_commit": True, "now": NOW,
        "maxStalenessSeconds": 300, "freshHead": head_at(5, {"revoked": True}),
    })
    assert r["currency_at_T"]["status"] == "stale"
    assert r["currency_at_T"]["reason"] == CURRENCY_REASON["revoked_by_fresh_head"]


def test_status_list_revoking_this_receipt_is_stale():
    r = evaluate_currency({
        "receipt": receipt, "authentic_as_of_commit": True, "now": NOW,
        "maxStalenessSeconds": 300, "freshHead": head_at(5, {"revoked_target_hashes": [ACTION_HASH]}),
    })
    assert r["currency_at_T"]["status"] == "stale"
    assert r["currency_at_T"]["reason"] == CURRENCY_REASON["revoked_by_fresh_head"]


def test_status_list_revoking_different_target_stays_fresh():
    r = evaluate_currency({
        "receipt": receipt, "authentic_as_of_commit": True, "now": NOW,
        "maxStalenessSeconds": 300, "freshHead": head_at(5, {"revoked_target_hashes": [OTHER_HASH]}),
    })
    assert r["currency_at_T"]["status"] == "fresh"


# ── fail-safe branches ───────────────────────────────────────────────────────
def test_required_but_absent_is_stale():
    r = evaluate_currency({
        "receipt": receipt, "authentic_as_of_commit": True, "now": NOW, "freshHeadRequired": True,
    })
    assert r["currency_at_T"]["status"] == "stale"
    assert r["currency_at_T"]["reason"] == CURRENCY_REASON["fresh_head_required_but_absent"]


def test_fresh_head_no_policy_bound_is_stale():
    r = evaluate_currency({
        "receipt": receipt, "authentic_as_of_commit": True, "now": NOW, "freshHead": head_at(1),
    })
    assert r["currency_at_T"]["status"] == "stale"
    assert r["currency_at_T"]["reason"] == CURRENCY_REASON["max_staleness_invalid"]


def test_negative_bound_is_stale():
    r = evaluate_currency({
        "receipt": receipt, "authentic_as_of_commit": True, "now": NOW,
        "maxStalenessSeconds": -1, "freshHead": head_at(1),
    })
    assert r["currency_at_T"]["status"] == "stale"
    assert r["currency_at_T"]["reason"] == CURRENCY_REASON["max_staleness_invalid"]


def test_unparseable_now_is_unknown():
    r = evaluate_currency({
        "receipt": receipt, "authentic_as_of_commit": True, "now": "not-a-time",
        "maxStalenessSeconds": 300, "freshHead": head_at(1),
    })
    assert r["currency_at_T"]["status"] == "unknown"
    assert r["currency_at_T"]["reason"] == CURRENCY_REASON["now_invalid"]
    assert r["currency_at_T"]["evaluated_at"] is None


def test_malformed_head_is_unknown():
    r = evaluate_currency({
        "receipt": receipt, "authentic_as_of_commit": True, "now": NOW,
        "maxStalenessSeconds": 300, "freshHead": {"revoked": False},  # no observed_at/issued_at
    })
    assert r["currency_at_T"]["status"] == "unknown"
    assert r["currency_at_T"]["reason"] == CURRENCY_REASON["fresh_head_malformed"]


def test_authentic_passes_through_failsafe_non_true():
    r1 = evaluate_currency({"receipt": receipt, "authentic_as_of_commit": "yes", "now": NOW})
    assert r1["authentic_as_of_commit"] is False
    r2 = evaluate_currency({"receipt": receipt, "now": NOW})  # omitted
    assert r2["authentic_as_of_commit"] is False


def test_empty_args_yields_failsafe_default():
    r = evaluate_currency()
    assert r["authentic_as_of_commit"] is False
    assert r["currency_at_T"]["status"] == "unknown"
    assert r["currency_at_T"]["reason"] == CURRENCY_REASON["offline_only_no_fresh_head"]


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ALL PASS — EP-CURRENCY-v1 parity")
