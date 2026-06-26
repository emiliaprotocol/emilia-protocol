#!/usr/bin/env python3
# =============================================================================
# GRACE -- Proof-of-Curtailment reference demo
#
#   Run it:   pip install emilia-verify cryptography
#             python3 proof_of_curtailment.py
#   (No pip? This file falls back to the monorepo's packages/python-verify.)
#
# The verifiable receipt layer for grid-responsive AI compute (built for settlement), end to end:
#
#   1 AUTHORIZE  -> a named grid authority signs a bounded grid.curtailment order
#   2 VERIFY/GATE-> the facility controller verifies it OFFLINE, fail-closed
#   3 SHED       -> the scheduler drops compute (cache-first / cap clocks); watts fall
#   4 MEASURE    -> an attested meter signs the power telemetry (dual-key, like COSA L5/L7)
#   5 PROVE      -> delivered kWh = baseline - actual, against a PINNED baseline method
#   6 SETTLE     -> emit a Proof-of-Curtailment Bundle, verifiable by anyone, offline
#   7 ADVERSARIAL-> tamper telemetry -> FAIL; forged order -> REFUSED; expired -> REFUSED
#
# Everything verifies under the REAL published EMILIA verifier (emilia_verify,
# EP-RECEIPT-v1, Ed25519 over RFC-8785/JCS-canonical bytes) with zero new crypto.
# COSA moves the megawatts; EMILIA authorizes the move and proves it happened.
# =============================================================================
from __future__ import annotations

import base64
import hashlib
import os
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Use the published verifier; fall back to the in-repo copy so a fresh clone runs.
try:
    from emilia_verify import verify_receipt, canonicalize
except ModuleNotFoundError:  # pragma: no cover - convenience for repo clones
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "packages", "python-verify"))
    from emilia_verify import verify_receipt, canonicalize


# --- tiny helpers ------------------------------------------------------------
def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def spki_b64u(sk: Ed25519PrivateKey) -> str:
    return b64u(sk.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def issue(payload: dict, sk: Ed25519PrivateKey) -> dict:
    """Mint an EP-RECEIPT-v1: Ed25519 signature over the canonical payload."""
    sig = sk.sign(canonicalize(payload).encode("utf-8"))
    return {
        "@version": "EP-RECEIPT-v1",
        "payload": payload,
        "signature": {"algorithm": "Ed25519", "value": b64u(sig)},
    }


def line(s: str = "") -> None:
    print(s)


# --- keys (held by distinct parties) -----------------------------------------
AUTHORITY_SK = Ed25519PrivateKey.generate()   # the grid authority operator (L7 "who")
METER_SK = Ed25519PrivateKey.generate()       # the attested meter at the facility edge
FACILITY_SK = Ed25519PrivateKey.generate()    # the datacenter's acknowledgment key

AUTHORITY_PUB = spki_b64u(AUTHORITY_SK)        # PINNED by the controller out-of-band
METER_PUB = spki_b64u(METER_SK)
FACILITY_PUB = spki_b64u(FACILITY_SK)

# --- the scenario ------------------------------------------------------------
# The baseline METHOD is the ISO's, not ours. We pin its hash; we don't invent it.
BASELINE_METHOD = "ERCOT-large-load-CBL-weather-adjusted-v1"
BASELINE_METHOD_HASH = "sha256:" + sha256_hex(BASELINE_METHOD)
BASELINE_WATTS = 1000           # what the facility WOULD have drawn (per the ISO method)
WINDOW_START = 1_790_000_000    # epoch seconds (fixed so the demo is deterministic)
WINDOW_END = WINDOW_START + 600  # 10-minute window


def make_order() -> dict:
    return issue({
        "action_type": "grid.curtailment",
        "effect_class": "power_reduction",
        "facility": "erc-dc-07",
        "target_delta_w": 700,                 # shed 700 W
        "protected_lanes": ["life-safety", "contractual-slo"],
        "baseline_method_hash": BASELINE_METHOD_HASH,
        "telemetry_sources": ["meter:erc-dc-07/pdu-main"],
        "window": {"not_before": WINDOW_START, "not_after": WINDOW_END},
        "control_mode": "on_the_loop",
        "approver": "ep:approver:ercot-grid-authority-1",
        "expires_at": WINDOW_END,
    }, AUTHORITY_SK)


def gate(order: dict, trusted_pub: str, now: int) -> tuple[bool, str]:
    """Fail-closed: posture changes ONLY against a valid, in-scope, unexpired order."""
    res = verify_receipt(order, trusted_pub)          # offline Ed25519 over canonical payload
    if not res.valid:
        return False, "signature/version invalid (forged or wrong key)"
    p = order["payload"]
    if p.get("action_type") != "grid.curtailment":
        return False, "wrong action type"
    w = p["window"]
    if not (w["not_before"] <= now <= w["not_after"]):
        return False, "outside the authorized window"
    if now >= p["expires_at"]:
        return False, "order expired"
    return True, "authorized"


def measure_shed(target_delta_w: int) -> list[dict]:
    """COSA sheds compute; the attested meter records watts every 60s across the window.
    Simulated here: the facility holds ~target reduction once posture is entered."""
    samples = []
    for i in range(11):                     # 0..10 minutes inclusive
        t = WINDOW_START + i * 60
        actual = BASELINE_WATTS - (target_delta_w if i >= 1 else 0)  # ramps in after t0
        samples.append({"t": t, "w": actual})
    return samples


def attest_telemetry(samples: list[dict]) -> dict:
    """The meter signs the WHOLE telemetry payload -> any tampered sample breaks the sig."""
    return issue({
        "meter_id": "meter:erc-dc-07/pdu-main",
        "unit": "watt",
        "baseline_method_hash": BASELINE_METHOD_HASH,
        "samples": samples,
    }, METER_SK)


def delivered_kwh(samples: list[dict]) -> float:
    """Integral of (baseline - actual) over the window, from the signed samples."""
    wh = 0.0
    for a, b in zip(samples, samples[1:]):
        dt_h = (b["t"] - a["t"]) / 3600.0
        red = ((BASELINE_WATTS - a["w"]) + (BASELINE_WATTS - b["w"])) / 2.0  # trapezoid
        wh += red * dt_h
    return round(wh / 1000.0, 6)


def verify_bundle(bundle: dict) -> tuple[bool, dict]:
    """Anyone can run this, offline, with no account and no trust in the operator."""
    checks = {}
    checks["order"] = verify_receipt(bundle["order"], bundle["authority_pub"]).valid
    checks["acknowledgment"] = verify_receipt(bundle["acknowledgment"], bundle["facility_pub"]).valid
    checks["telemetry"] = verify_receipt(bundle["telemetry"], bundle["meter_pub"]).valid
    # the baseline method is the one the order pinned -- can't be silently swapped
    checks["method_pinned"] = (
        bundle["telemetry"]["payload"]["baseline_method_hash"]
        == bundle["order"]["payload"]["baseline_method_hash"]
    )
    # the claimed kWh must equal what the SIGNED samples actually integrate to
    recomputed = delivered_kwh(bundle["telemetry"]["payload"]["samples"])
    checks["kwh_matches_telemetry"] = abs(recomputed - bundle["delivered_kwh"]) < 1e-9
    return all(checks.values()), checks


# =============================================================================
def main() -> int:
    line("=" * 70)
    line("  GRACE -- Proof-of-Curtailment  (COSA x EMILIA)")
    line("=" * 70)

    # 1 AUTHORIZE
    order = make_order()
    p = order["payload"]
    line(f"\n  1. AUTHORIZE  grid authority signs grid.curtailment")
    line(f"     facility={p['facility']}  shed={p['target_delta_w']}W  window=10min  on_the_loop")

    # 2 VERIFY & GATE (offline, fail-closed)
    now = WINDOW_START + 1
    ok, why = gate(order, AUTHORITY_PUB, now)
    line(f"\n  2. VERIFY & GATE  offline verify against pinned authority key -> {('PASS' if ok else 'REFUSE')} ({why})")
    if not ok:
        return 1

    # 3 SHED + 4 MEASURE
    samples = measure_shed(p["target_delta_w"])
    line(f"\n  3. SHED       COSA enters curtailment posture (cache-first, cap clocks)")
    line(f"     watts: {samples[0]['w']}W (baseline) -> {samples[1]['w']}W ... -> {samples[-1]['w']}W")
    telemetry = attest_telemetry(samples)
    line(f"  4. MEASURE    attested meter signs {len(samples)} telemetry samples")

    # 5 PROVE
    kwh = delivered_kwh(samples)
    line(f"\n  5. PROVE      delivered = baseline - actual = {kwh} kWh   (method {BASELINE_METHOD_HASH[:23]}...)")

    # 6 SETTLE -- assemble + verify the bundle
    ack = issue({"acknowledges": "grid.curtailment", "facility": p["facility"],
                 "order_method_hash": p["baseline_method_hash"], "posture": "entered"}, FACILITY_SK)
    bundle = {
        "order": order, "authority_pub": AUTHORITY_PUB,
        "acknowledgment": ack, "facility_pub": FACILITY_PUB,
        "telemetry": telemetry, "meter_pub": METER_PUB,
        "delivered_kwh": kwh,
    }
    valid, checks = verify_bundle(bundle)
    line(f"\n  6. SETTLE     Proof-of-Curtailment Bundle -> {('VALID' if valid else 'INVALID')}  {checks}")
    line(f"     ISO pays against this, offline. No trust in the operator's logs.")

    # 7 ADVERSARIAL
    line(f"\n  7. ADVERSARIAL")

    bad = {**bundle, "telemetry": {**telemetry,
           "payload": {**telemetry["payload"],
                       "samples": [{**samples[5], "w": 100}] + samples[:5] + samples[6:]}}}
    v, _ = verify_bundle(bad)
    line(f"     a) tamper a watt reading after signing      -> {('VALID??' if v else 'INVALID (refused)')}")

    forged = issue(p, Ed25519PrivateKey.generate())   # attacker re-signs the same order
    ok2, why2 = gate(forged, AUTHORITY_PUB, now)
    line(f"     b) forged order (attacker key, pinned auth) -> {('PASS??' if ok2 else f'REFUSED ({why2})')}")

    ok3, why3 = gate(order, AUTHORITY_PUB, WINDOW_END + 1)   # after the window
    line(f"     c) replay after the window expires          -> {('PASS??' if ok3 else f'REFUSED ({why3})')}")

    line("\n" + "=" * 70)
    all_good = valid and not v and not ok2 and not ok3
    line(f"  RESULT: {'authorized, graceful, measured, reversible, tamper-evident.' if all_good else 'CHECK FAILED'}")
    line("=" * 70)
    return 0 if all_good else 1


if __name__ == "__main__":
    raise SystemExit(main())
