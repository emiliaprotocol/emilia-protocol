# SPDX-License-Identifier: Apache-2.0
#
# COSA L5 (broadcast/cache plane) + EMILIA L7 (Receipt Required) — manifest-driven.
#
# This is the wired reference for the COSA <-> EP integration: a realistic L5
# plane (compute-once / serve-N with a freshness-bounded cache) whose READ path
# is free and whose IRREVERSIBLE publish path is gated by a Receipt Required
# check driven by a /.well-known/agent-actions.json Action Risk Manifest.
#
#   pip install emilia-verify
#   python examples/cosa/cosa_l5_l7.py        # offline, no key, no account
#
# L5 attests an inference result is authentic; L7/EP attests an irreversible
# action was authorized. Two applications of one discipline — signed, canonical,
# offline-verifiable objects. The manifest decides which actions need a receipt;
# the gate enforces verify + action-binding + one-time consumption (replay).

import base64
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from emilia_verify import verify_receipt, canonicalize  # the real published verifier

HERE = Path(__file__).resolve().parent
MANIFEST = json.loads((HERE / "agent-actions.json").read_text())


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def find_requirement(manifest: dict, action_type: str):
    for entry in manifest.get("actions", []):
        if entry.get("action_type") == action_type:
            return entry
    return None


# ── L7 / EMILIA: issue + manifest-driven gate ────────────────────────────────

# The approver/issuer key. Pinned out of band — never trust a key inside a receipt.
_APPROVER_SK = Ed25519PrivateKey.generate()
TRUSTED_KEY = _b64u(_APPROVER_SK.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))


def issue_receipt(action_type: str, approver: str) -> dict:
    """A named human signs the EXACT action -> EP-RECEIPT-v1 (Ed25519, offline)."""
    payload = {
        "receipt_id": "rcpt_" + secrets.token_hex(6),
        "subject": "agent:cosa-l5-plane",
        "created_at": _now_iso(),
        "claim": {"action_type": action_type, "outcome": "allow_with_signoff", "approver": approver},
    }
    sig = _APPROVER_SK.sign(canonicalize(payload).encode("utf-8"))
    return {"@version": "EP-RECEIPT-v1", "payload": payload, "signature": {"algorithm": "Ed25519", "value": _b64u(sig)}}


class ReceiptRequired(Exception):
    """Raised when the L7 gate refuses an action (fail-closed). 428-equivalent."""


def guard(action_type: str, receipt: dict | None, consumed: set) -> str:
    """Manifest-driven L7 gate. Read-only actions pass; receipt-required actions
    run only with a valid, action-bound, not-yet-consumed receipt. Fail-closed."""
    req = find_requirement(MANIFEST, action_type)
    if req is None:
        raise ReceiptRequired(f"{action_type}: not declared in the manifest")
    if not req.get("receipt_required"):
        return "read-only (no receipt required per manifest)"
    if receipt is None:
        raise ReceiptRequired(f"428 Receipt Required: no receipt for '{action_type}'")
    res = verify_receipt(receipt, TRUSTED_KEY)              # offline Ed25519 over canonical payload
    if not res.valid:
        raise ReceiptRequired(f"receipt failed verification ({res.error or res.checks})")
    claim = (receipt.get("payload") or {}).get("claim") or {}
    if claim.get("action_type") != action_type:            # action-binding (no confused deputy)
        raise ReceiptRequired(f"receipt authorizes '{claim.get('action_type')}', not '{action_type}'")
    if claim.get("outcome") not in ("allow", "allow_with_signoff"):
        raise ReceiptRequired(f"outcome '{claim.get('outcome')}' is not an approval")
    rid = (receipt.get("payload") or {}).get("receipt_id")
    if rid in consumed:                                    # one-time consumption (replay refusal)
        raise ReceiptRequired(f"receipt {rid} already consumed (replay)")
    consumed.add(rid)
    return f"authorized by {claim.get('approver')}"


# ── L5 / COSA: a realistic broadcast plane (compute-once, serve-N) ────────────

class L5Plane:
    """Minimal COSA L5: a freshness-bounded cache. cache_read is free; broadcast
    publish is the irreversible action (N consumers will cache + trust it)."""

    def __init__(self, consumed: set):
        self._cache: dict[str, dict] = {}
        self._consumed = consumed

    def cache_read(self, key: str):
        guard("l5.cache.read", None, self._consumed)        # read-only -> always allowed, free
        hit = self._cache.get(key)
        return (hit, 0)  # (entry, tokens_spent) — a cache hit costs 0 tokens

    def broadcast_publish(self, key: str, cogobj: str, content: str, receipt: dict | None = None):
        who = guard("l5.broadcast.publish", receipt, self._consumed)  # irreversible -> Receipt Required
        self._cache[key] = {"cogobj": cogobj, "content": content, "published_at": _now_iso()}
        return who


# ── demo ─────────────────────────────────────────────────────────────────────

def line(s=""):
    print(s)


def main():
    consumed: set = set()
    plane = L5Plane(consumed)
    key, cogobj, content = "weather:NYC", "468b3a8a9427a8a8", "Ira, New York, US: sunny +66F"
    line()
    line("  COSA L5 plane + EMILIA L7 (Receipt Required) — manifest-driven")
    line("  " + "-" * 64)
    line(f"  manifest: {MANIFEST['service']['name']}  ({len(MANIFEST['actions'])} actions declared)")

    line("\n  0. L5 cache read (read-only) — free, no receipt")
    hit, tokens = plane.cache_read(key)
    line(f"     -> allowed; {'HIT' if hit else 'MISS'} (tokens={tokens})")

    line("\n  1. Agent tries to PUBLISH a broadcast with NO receipt")
    try:
        plane.broadcast_publish(key, cogobj, content)
    except ReceiptRequired as e:
        line(f"     -> REFUSED: {e}")

    line("\n  2. A named human signs the exact action -> EP-RECEIPT-v1")
    rcpt = issue_receipt("l5.broadcast.publish", "ep:approver:plane-operator (Face ID)")
    line(f"     receipt {rcpt['payload']['receipt_id']} - retrying publish:")
    who = plane.broadcast_publish(key, cogobj, content, receipt=rcpt)
    line(f"     -> PUBLISHED ({who}); N consumers will now trust COGOBJ {cogobj}")

    line("\n  3. L5 cache read again — served from cache, free (compute-once / serve-N)")
    hit, tokens = plane.cache_read(key)
    line(f"     -> HIT: {hit['content']}  (tokens={tokens})")

    line("\n  4. The SAME publish receipt, replayed")
    try:
        plane.broadcast_publish(key, cogobj, content, receipt=rcpt)
    except ReceiptRequired as e:
        line(f"     -> REFUSED: {e}")

    line("\n  5. A FORGED receipt (a signed field altered after signing)")
    forged = json.loads(json.dumps(issue_receipt("l5.broadcast.publish", "attacker")))
    forged["payload"]["subject"] = "agent:attacker"  # mutate a signed field -> signature breaks
    try:
        plane.broadcast_publish(key, cogobj, content, receipt=forged)
    except ReceiptRequired as e:
        line(f"     -> REFUSED: {e}")

    line("\n  6. A VALID receipt for a DIFFERENT action (confused-deputy)")
    wrong = issue_receipt("l5.cache.read", "ep:approver:plane-operator (Face ID)")
    try:
        plane.broadcast_publish(key, cogobj, content, receipt=wrong)
    except ReceiptRequired as e:
        line(f"     -> REFUSED: {e}")

    line("\n  L5 proves the object is authentic; L7/EP proves the action was authorized.")
    line("  Reads stay free; only the irreversible publish carries a receipt.")
    line()


if __name__ == "__main__":
    main()
