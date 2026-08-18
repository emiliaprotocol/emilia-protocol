# SPDX-License-Identifier: Apache-2.0
"""Python conformance runner for the EP hybrid post-quantum vector sets.

Consumes the SAME checked-in vector files the JavaScript side consumes:

  conformance/pq-agility/vectors.json
      EP-SIG-AGILITY-v1. JS consumer: packages/verify/pq-signature-agility.test.ts

  conformance/hybrid-receipts/vectors.json
      EP-RECEIPT-HYBRID-v1. JS consumer: conformance/hybrid-receipts/run.test.mts

  conformance/vectors/pq-hybrid-envelope.v1.json
      EP-HYBRID-v1. JS consumer: conformance/vectors/pq-hybrid-envelope.v1.generate.mjs
      (--check re-verifies every vector through the shipped verifyHybrid)

Run:
    python3 conformance/py/run_pq.py
    python3 conformance/py/run_pq.py --json      # machine-readable rows

BACKEND MODE. The ML-DSA-65 leg needs a real backend. When one is installed the
runner enforces every vector's recorded expectation exactly. When none is
installed it runs in DEGRADED mode: every vector whose outcome does not depend
on ML-DSA is still enforced exactly, and every vector that does must refuse with
pq_backend_unavailable. Nothing is ever skipped and nothing ever passes by
default. The mode is printed, so a green run that never touched a lattice cannot
be mistaken for one that did.

CI. This runner and conformance/py/test_ep_pq_verify.py both run in the
`conformance` job of .github/workflows/ci.yml, on every push and pull request to
main, in LIVE mode: that job installs the hash-pinned dilithium-py backend from
.github/workflow-requirements/pq-conformance.txt. Read the printed backend line
in the job log rather than assuming the mode.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ep_pq_verify import (  # noqa: E402
    load_default_mldsa_backend,
    verify_agile_signature,
    verify_agile_signature_set,
    verify_hybrid,
    verify_hybrid_receipt,
)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

AGILITY_VECTORS = os.path.join(REPO_ROOT, "conformance", "pq-agility", "vectors.json")
RECEIPT_VECTORS = os.path.join(REPO_ROOT, "conformance", "hybrid-receipts", "vectors.json")
ENVELOPE_VECTORS = os.path.join(REPO_ROOT, "conformance", "vectors", "pq-hybrid-envelope.v1.json")

NO_BACKEND = {"mldsa_backend_loader": lambda: None}


def _load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _options(backend):
    """Thread ONE backend decision through every call.

    When the runner has no backend it pins the absent path explicitly rather
    than leaving the options empty. An empty bag would let each call re-run
    lazy discovery and quietly find an installed implementation, so a
    --no-backend run would verify with live crypto while grading itself against
    degraded expectations. The mode the runner reports is the mode it runs.
    """
    return dict(NO_BACKEND) if backend is None else {"mldsa_backend": backend}


# ---------------------------------------------------------------------------
# EP-SIG-AGILITY-v1
# ---------------------------------------------------------------------------

def run_agility(backend):
    corpus = _load(AGILITY_VECTORS)
    message = corpus["canonical_payload"].encode("utf-8")
    keys = {
        "Ed25519": {
            "alg": "Ed25519",
            "public_key": corpus["keys"]["ed25519"]["public_key"],
            "key_id": corpus["keys"]["ed25519"]["key_id"],
        },
        "ML-DSA-65": {
            "alg": "ML-DSA-65",
            "public_key": corpus["keys"]["ml_dsa_65"]["public_key"],
            "key_id": corpus["keys"]["ml_dsa_65"]["key_id"],
        },
    }
    options = _options(backend)
    rows = []

    for vector in corpus["vectors"]:
        vid = vector["id"]
        expect = vector["expect"]
        if vector["kind"] == "single":
            alg = vector["signature"]["alg"]
            pq_touching = alg == "ML-DSA-65"
            result = verify_agile_signature(
                message, vector["signature"], keys.get(alg), options
            )
            got = {"verified": result["verified"], "reason": result["reason"]}
            if backend is None and pq_touching:
                want = {"verified": False, "reason": "pq_backend_unavailable"}
                note = "degraded: pq_backend_unavailable enforced in place of the recorded verdict"
            else:
                want = {"verified": expect["verified"], "reason": expect["reason"]}
                note = None
        else:
            policy = vector["policy"]
            key_list = [keys[a] for a in ("Ed25519", "ML-DSA-65")]
            result = verify_agile_signature_set(
                message, vector["signatures"], key_list, {**options, "policy": policy}
            )
            pq_presented = any(s["alg"] == "ML-DSA-65" for s in vector["signatures"])
            note = None

            if policy == "per_algorithm":
                # The top-level verdict is null in EVERY environment: verdicts
                # stay per-algorithm and are never collapsed. The recorded
                # expectation is the per-algorithm map, so compare that.
                per_alg_got = {
                    r["alg"]: (True if r["verified"] is True else r["reason"])
                    for r in result["results"]
                }
                per_alg_want = dict(expect["per_algorithm"])
                if backend is None and "ML-DSA-65" in per_alg_want:
                    per_alg_want["ML-DSA-65"] = "pq_backend_unavailable"
                    note = "degraded: the ML-DSA leg refuses for want of a backend"
                got = {"verified": result["verified"], "per_algorithm": per_alg_got}
                want = {"verified": expect["verified"], "per_algorithm": per_alg_want}
            else:
                got = {"verified": result["verified"], "reason": result["reason"]}
                want = {"verified": expect["verified"], "reason": expect["reason"]}
                # missing_required_algorithm is decided before any leg is
                # checked, so it holds with or without a backend.
                if (backend is None and pq_presented
                        and expect["reason"] != "missing_required_algorithm"):
                    # hybrid_all reports the first failing leg as "<alg>:<reason>".
                    want = {"verified": False, "reason": "ML-DSA-65:pq_backend_unavailable"}
                    note = "degraded: the ML-DSA leg refuses for want of a backend"

        rows.append({
            "suite": "EP-SIG-AGILITY-v1",
            "id": vid,
            "ok": got == want,
            "want": want,
            "got": got,
            "note": note,
        })
    return rows


# ---------------------------------------------------------------------------
# EP-RECEIPT-HYBRID-v1
# ---------------------------------------------------------------------------

# Vectors whose recorded verdict is decided structurally, before any signature
# is checked. These hold identically with or without an ML-DSA backend.
_RECEIPT_STRUCTURAL_REASONS = {
    "hybrid_leg_missing",
    "algorithm_set_mismatch",
    "unexpected_algorithm",
    "duplicate_algorithm",
    "unknown_profile",
    "malformed_receipt",
    "malformed_payload",
    "missing_key",
}


def run_hybrid_receipts(backend):
    corpus = _load(RECEIPT_VECTORS)
    keys = {
        "ed25519PublicKey": corpus["keys"]["Ed25519"]["public_key"],
        "ed25519KeyId": corpus["keys"]["Ed25519"]["key_id"],
        "mldsaPublicKey": corpus["keys"]["ML-DSA-65"]["public_key"],
        "mldsaKeyId": corpus["keys"]["ML-DSA-65"]["key_id"],
    }
    options = _options(backend)
    rows = []

    for vector in corpus["vectors"]:
        expect = vector["expect"]
        result = verify_hybrid_receipt(vector["receipt"], keys, options)
        got = {
            "verified": result["verified"],
            "reason": result["reason"],
            "failed_algorithm": result["failed_algorithm"],
        }
        want = {
            "verified": expect["verified"],
            "reason": expect["reason"],
            "failed_algorithm": expect["failed_algorithm"],
        }
        note = None
        structural = expect["reason"] in _RECEIPT_STRUCTURAL_REASONS
        if backend is None and not structural:
            # Reaching the signature set means the ML-DSA leg is consulted.
            # The Ed25519 leg is checked first, so a receipt whose classical leg
            # is already broken still refuses with signature_invalid.
            classical_already_broken = expect["failed_algorithm"] == "Ed25519"
            if not classical_already_broken:
                want = {
                    "verified": False,
                    "reason": "pq_backend_unavailable",
                    "failed_algorithm": "ML-DSA-65",
                }
                note = "degraded: the ML-DSA leg refuses for want of a backend"
        rows.append({
            "suite": "EP-RECEIPT-HYBRID-v1",
            "id": vector["id"],
            "ok": got == want,
            "want": want,
            "got": got,
            "note": note,
        })
    return rows


# ---------------------------------------------------------------------------
# EP-HYBRID-v1
# ---------------------------------------------------------------------------

# Refusals the EP-HYBRID-v1 verifier reaches before the post-quantum leg.
_ENVELOPE_PRE_PQ_REASONS = {
    "invalid_input",
    "invalid_envelope",
    "algo_set_mismatch",
    "missing_signature",
    "missing_key",
    "algorithm_key_mismatch",
    "signature_length_invalid",
    "public_key_length_invalid",
    "classical_signature_invalid",
}


def run_hybrid_envelope(backend):
    corpus = _load(ENVELOPE_VECTORS)
    key_table = corpus["keys"]
    rows = []

    for vector in corpus["vectors"]:
        expect = vector["expect"]
        keys = {
            "ed25519PublicKey": key_table[vector["keys"]["ed25519"]]["spki_b64url"],
            "mldsaPublicKey": key_table[vector["keys"]["mldsa"]]["public_key_b64url"],
        }
        # A vector may pin the backend-absent path itself; otherwise it follows
        # whatever this environment has.
        if vector["backend"] == "absent":
            options = NO_BACKEND
            want = {"verified": expect["verified"], "reason": expect["reason"]}
            note = None
        else:
            options = _options(backend)
            want = {"verified": expect["verified"], "reason": expect["reason"]}
            note = None
            if backend is None and expect["reason"] not in _ENVELOPE_PRE_PQ_REASONS:
                want = {"verified": False, "reason": "pq_backend_unavailable"}
                note = "degraded: the ML-DSA leg refuses for want of a backend"

        result = verify_hybrid(vector["message"], vector["envelope"], keys, options)
        got = {"verified": result["verified"], "reason": result["reason"]}
        rows.append({
            "suite": "EP-HYBRID-v1",
            "id": vector["id"],
            "ok": got == want,
            "want": want,
            "got": got,
            "note": note,
        })
    return rows


# ---------------------------------------------------------------------------
# Hostile inputs: fail-closed means a named reason, not a crash
# ---------------------------------------------------------------------------

def run_hostile(backend):
    """Attacker-shaped input must return a refusal with a reason, never raise."""
    options = _options(backend)
    cases = [
        ("agility-none-signature",
         lambda: verify_agile_signature(b"x", None, None, options), "malformed_input"),
        ("agility-signature-is-list",
         lambda: verify_agile_signature(b"x", [], None, options), "malformed_input"),
        ("agility-message-not-bytes",
         lambda: verify_agile_signature("x", {"alg": "Ed25519", "sig": "AA"}, None, options),
         "malformed_input"),
        ("agility-unknown-algorithm",
         lambda: verify_agile_signature(b"x", {"alg": "Ed448", "sig": "AA"}, {"alg": "Ed448"}, options),
         "unknown_algorithm"),
        ("agility-key-tagged-other-algorithm",
         lambda: verify_agile_signature(
             b"x", {"alg": "Ed25519", "sig": "AA"}, {"alg": "ML-DSA-65", "public_key": "AA"}, options),
         "algorithm_key_mismatch"),
        ("agility-signature-not-base64url",
         lambda: verify_agile_signature(
             b"x", {"alg": "Ed25519", "sig": "not base64!!"}, {"alg": "Ed25519", "public_key": "AA"}, options),
         "malformed_signature"),
        ("agility-signature-empty",
         lambda: verify_agile_signature(
             b"x", {"alg": "Ed25519", "sig": ""}, {"alg": "Ed25519", "public_key": "AA"}, options),
         "malformed_signature"),
        ("agility-set-not-a-list",
         lambda: verify_agile_signature_set(b"x", None, [], options), "malformed_input"),
        ("agility-set-empty",
         lambda: verify_agile_signature_set(b"x", [], [], options), "empty_signature_set"),
        ("agility-set-unknown-policy",
         lambda: verify_agile_signature_set(
             b"x", [{"alg": "Ed25519", "sig": "AA"}], [], {**options, "policy": "whatever"}),
         "unknown_policy"),
        ("agility-key-unparseable",
         lambda: verify_agile_signature(
             b"x", {"alg": "Ed25519", "sig": "A" * 86},
             {"alg": "Ed25519", "public_key": "AAAA"}, options),
         "malformed_key"),
        ("agility-ml-dsa-key-wrong-length",
         lambda: verify_agile_signature(
             b"x", {"alg": "ML-DSA-65", "sig": "A" * 4412},
             {"alg": "ML-DSA-65", "public_key": "AAAA"}, options),
         "malformed_key"),
        ("agility-set-duplicate-key-pin",
         lambda: verify_agile_signature_set(
             b"x", [{"alg": "Ed25519", "sig": "AA"}],
             [{"alg": "Ed25519", "public_key": "AA"}, {"alg": "Ed25519", "public_key": "AB"}], options),
         "duplicate_algorithm"),
        ("hybrid-envelope-none",
         lambda: verify_hybrid("x", None, None, options), "invalid_envelope"),
        ("hybrid-envelope-is-list",
         lambda: verify_hybrid("x", [], None, options), "invalid_envelope"),
        ("hybrid-message-not-string-or-bytes",
         lambda: verify_hybrid(42, {"alg": "EP-HYBRID-v1"}, None, options), "invalid_input"),
        ("hybrid-sigs-missing",
         lambda: verify_hybrid("x", {"alg": "EP-HYBRID-v1"}, None, options), "invalid_envelope"),
        ("hybrid-keys-missing",
         lambda: verify_hybrid(
             "x",
             {"alg": "EP-HYBRID-v1", "signature_algos": ["Ed25519", "ML-DSA-65"],
              "sigs": {"Ed25519": "AA", "ML-DSA-65": "AA"}},
             None, options),
         "missing_key"),
        ("receipt-none",
         lambda: verify_hybrid_receipt(None, None, options), "malformed_receipt"),
        ("receipt-is-list",
         lambda: verify_hybrid_receipt([], None, options), "malformed_receipt"),
        ("receipt-unknown-version",
         lambda: verify_hybrid_receipt({"@version": "EP-RECEIPT-v1"}, None, options), "unknown_profile"),
        ("receipt-profile-not-object",
         lambda: verify_hybrid_receipt(
             {"@version": "EP-RECEIPT-HYBRID-v1", "profile": "nope"}, None, options),
         "malformed_receipt"),
        # A structurally complete receipt with no payload at all. The legs and
        # the committed set pass; there is nothing to rebuild the signed bytes
        # from, which is malformed_payload rather than malformed_receipt.
        ("receipt-payload-absent",
         lambda: verify_hybrid_receipt(
             {
                 "@version": "EP-RECEIPT-HYBRID-v1",
                 "profile": {"id": "EP-RECEIPT-HYBRID-v1",
                             "required_algorithms": ["Ed25519", "ML-DSA-65"]},
                 "signatures": [{"alg": "Ed25519", "sig": "AA"},
                                {"alg": "ML-DSA-65", "sig": "AA"}],
             },
             None, options),
         "malformed_payload"),
    ]

    rows = []
    for case_id, thunk, want_reason in cases:
        try:
            result = thunk()
            got_reason = result.get("reason")
            raised = None
        except Exception as exc:  # a raise is a failure: fail-closed means a reason
            got_reason = None
            raised = f"{type(exc).__name__}: {exc}"
        rows.append({
            "suite": "fail-closed",
            "id": case_id,
            "ok": raised is None and got_reason == want_reason,
            "want": {"verified": False, "reason": want_reason},
            "got": {"verified": False, "reason": got_reason, "raised": raised},
            "note": None,
        })
    return rows


# ---------------------------------------------------------------------------

def run_all(backend):
    return (run_agility(backend)
            + run_hybrid_receipts(backend)
            + run_hybrid_envelope(backend)
            + run_hostile(backend))


def main() -> int:
    parser = argparse.ArgumentParser(description="EP hybrid post-quantum Python conformance runner")
    parser.add_argument("--json", action="store_true", help="emit result rows as JSON")
    parser.add_argument("--no-backend", action="store_true",
                        help="force the backend-absent path even if one is installed")
    args = parser.parse_args()

    backend = None if args.no_backend else load_default_mldsa_backend()
    mode = "live" if backend is not None else "degraded"
    backend_name = backend.name if backend is not None else "none"

    rows = run_all(backend)
    failures = [r for r in rows if not r["ok"]]

    if args.json:
        print(json.dumps({
            "mode": mode,
            "ml_dsa_backend": backend_name,
            "total": len(rows),
            "failed": len(failures),
            "rows": rows,
        }, indent=2, sort_keys=True))
    else:
        print(f"EP hybrid post-quantum Python conformance")
        print(f"  ML-DSA-65 backend: {backend_name} ({mode})")
        if backend is None:
            print("  DEGRADED: no ML-DSA backend installed. Structural checks are enforced")
            print("  exactly; every post-quantum leg must refuse with pq_backend_unavailable.")
            print("  Install one to run the cryptographic leg, for example: pip install dilithium-py")
        for row in rows:
            status = "ok  " if row["ok"] else "FAIL"
            suffix = f"   [{row['note']}]" if row["note"] else ""
            print(f"  {status} {row['suite']:22s} {row['id']}{suffix}")
            if not row["ok"]:
                print(f"       want {row['want']}")
                print(f"       got  {row['got']}")
        print(f"  {len(rows) - len(failures)}/{len(rows)} vectors and cases agree")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
