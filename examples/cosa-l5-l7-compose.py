# SPDX-License-Identifier: Apache-2.0
#
# COSA L5 + EMILIA L7 — one discipline, applied twice.
#
#   L5 (Justin Kintzele's COSA): a SIGNED, canonical object proves an inference
#       result is AUTHENTIC — trust it offline without re-deriving it.
#   L7 (EMILIA Protocol):        a SIGNED, canonical receipt proves an
#       irreversible action was AUTHORIZED — a named human signed THIS exact
#       action; verify it offline, trusting neither the agent nor EMILIA.
#
# This is the reference artifact for adopting EP as COSA's L7 governance layer:
# the irreversible L5 action `publish_broadcast` (N consumers will cache + trust
# it) refuses to run without a valid, action-bound EP authorization receipt.
#
#   pip install emilia-verify
#   python examples/cosa-l5-l7-compose.py        # fully offline, no API, no Node
#
# Cache reads stay free and fast; only the irreversible WRITE carries a receipt.

import base64
import functools
import secrets
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# The REAL published verifier (offline Ed25519 over canonical JSON) + the exact
# canonicalizer it checks against. We sign what it verifies — no custom crypto.
from emilia_verify import verify_receipt, canonicalize


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── L7 / EMILIA: issue + gate ────────────────────────────────────────────────

def issue_receipt(action_type: str, approver: str, signing_key: Ed25519PrivateKey) -> dict:
    """Mint an EP-RECEIPT-v1: a named human signs THIS exact action.

    In production the signature is a Face ID / passkey device signoff; here we
    sign locally so the demo is self-contained. The bytes are identical to what
    @emilia-protocol/verify checks (canonicalize(payload), RFC 8785 / JCS)."""
    payload = {
        "receipt_id": "rcpt_" + secrets.token_hex(6),
        "subject": "agent:cosa-l5-plane",
        "created_at": _now_iso(),
        "claim": {"action_type": action_type, "outcome": "allow_with_signoff", "approver": approver},
    }
    sig = signing_key.sign(canonicalize(payload).encode("utf-8"))
    return {
        "@version": "EP-RECEIPT-v1",
        "payload": payload,
        "signature": {"algorithm": "Ed25519", "value": _b64u(sig)},
    }


def require_receipt(action_type: str, trusted_key_b64u: str):
    """COSA L7 gate. Fail-closed: the wrapped (irreversible) action runs only if
    a presented receipt (1) verifies offline against the PINNED approver key,
    (2) is bound to THIS action_type (no confused deputy), and (3) carries an
    approval outcome. Pin the key out of band — never trust a key inside the
    receipt."""
    def wrap(fn):
        @functools.wraps(fn)
        def guarded(*args, receipt=None, **kwargs):
            if receipt is None:
                raise PermissionError(f"L7/EP: no receipt for '{action_type}' — refused")
            result = verify_receipt(receipt, trusted_key_b64u)        # offline Ed25519
            if not result.valid:
                raise PermissionError(f"L7/EP: receipt failed verification ({result.error or result.checks}) — refused")
            claim = (receipt.get("payload") or {}).get("claim") or {}
            if claim.get("action_type") != action_type:
                raise PermissionError(
                    f"L7/EP: receipt authorizes '{claim.get('action_type')}', not '{action_type}' — refused")
            if claim.get("outcome") not in ("allow", "allow_with_signoff"):
                raise PermissionError(f"L7/EP: outcome '{claim.get('outcome')}' is not an approval — refused")
            return fn(*args, **kwargs)   # verified: a named human authorized exactly this action, offline
        return guarded
    return wrap


# ── L5 (COSA): the irreversible action we now govern ─────────────────────────

# This trusted approver key would belong to whoever may authorize broadcasts.
_APPROVER_SK = Ed25519PrivateKey.generate()
TRUSTED_APPROVER_KEY = _b64u(_APPROVER_SK.public_key().public_bytes(
    Encoding.DER, PublicFormat.SubjectPublicKeyInfo))


@require_receipt("l5.broadcast.publish", TRUSTED_APPROVER_KEY)
def publish_broadcast(plane: str, cogobj: str) -> str:
    """IRREVERSIBLE: N consumers will cache and trust this broadcast. Gated by L7."""
    return f"[L5] published COGOBJ {cogobj} to '{plane}' — N consumers will now trust it"


# ── demo ─────────────────────────────────────────────────────────────────────

def _line(s=""):
    print(s)


def main():
    _line()
    _line("  COSA L5 + EMILIA L7 — no receipt, no irreversible broadcast")
    _line("  " + "-" * 64)
    plane, cogobj = "weather.broadcast.plane", "468b3a8a9427a8a8"

    _line("\n  1. L5 agent tries to publish a broadcast with NO receipt")
    try:
        publish_broadcast(plane, cogobj)
    except PermissionError as e:
        _line(f"     -> REFUSED: {e}")

    _line("\n  2. A named human signs the exact action -> EP-RECEIPT-v1")
    good = issue_receipt("l5.broadcast.publish", "ep:approver:plane-operator (Face ID)", _APPROVER_SK)
    _line(f"     receipt {good['payload']['receipt_id']} · outcome {good['payload']['claim']['outcome']}")
    _line("     agent retries WITH the receipt:")
    _line(f"     -> {publish_broadcast(plane, cogobj, receipt=good)}")

    _line("\n  3a. A FORGED receipt (a signed field altered after signing)")
    forged = {**good, "payload": {**good["payload"],
              "claim": {**good["payload"]["claim"], "action_type": "l5.broadcast.publish"}}}
    forged["payload"]["receipt_id"] = "rcpt_attacker"   # mutate a signed field
    try:
        publish_broadcast(plane, cogobj, receipt=forged)
    except PermissionError as e:
        _line(f"     -> REFUSED: {e}")

    _line("\n  3b. A VALID receipt for a DIFFERENT action (confused-deputy attempt)")
    wrong = issue_receipt("l5.cache.read", "ep:approver:plane-operator (Face ID)", _APPROVER_SK)
    try:
        publish_broadcast(plane, cogobj, receipt=wrong)
    except PermissionError as e:
        _line(f"     -> REFUSED: {e}")

    _line("\n  L5 proves the object is authentic; L7/EP proves the action was authorized.")
    _line("  Two applications of one discipline: signed, canonical, offline-verifiable.")
    _line()


if __name__ == "__main__":
    main()
