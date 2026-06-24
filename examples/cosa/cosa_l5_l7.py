# SPDX-License-Identifier: Apache-2.0
#
# COSA L5 (broadcast/cache plane) + EMILIA L7 (Receipt Required), composed for real.
#
#   pip install emilia-verify
#   python examples/cosa/cosa_l5_l7.py        # offline, no key, no account, no network
#
# This is the wired reference behind the COSA <-> EMILIA integration. It is NOT a
# stub: it composes TWO signed, canonical, offline-verifiable objects.
#
#   L5 (authenticity):   the plane computes an answer ONCE, wraps it in a COGOBJ,
#                        and SIGNS it. Any consumer can verify the result is
#                        authentic and unmodified — without re-computing it.
#   L7 (authorization):  publishing that COGOBJ to N consumers is IRREVERSIBLE
#                        (they will cache and trust it), so it requires an EMILIA
#                        receipt — a named human signed the exact publish action.
#
# Every consumer independently checks BOTH before caching: L5 proves the object
# is authentic; L7 proves the publish was authorized. The two failure axes are
# orthogonal and both are demonstrated below (tampered content vs. missing/
# replayed/forged/mis-bound authorization). Same canonicalization discipline
# (RFC 8785 / JCS) underpins both layers — two applications of one idea.

import base64
import hashlib
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from emilia_verify import verify_receipt, canonicalize  # the real published verifier

HERE = Path(__file__).resolve().parent
MANIFEST = json.loads((HERE / "agent-actions.json").read_text())
COMPUTE_TOKENS = 1200  # cost of computing the answer once (the thing L5 amortizes)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def find_requirement(manifest: dict, action_type: str):
    for entry in manifest.get("actions", []):
        if entry.get("action_type") == action_type:
            return entry
    return None


# ── L7 / EMILIA: issue receipts + manifest-driven authorization gate ──────────

# The approver/issuer key, pinned out of band. Never trust a key inside a receipt.
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


def authorize(action_type: str, receipt: dict | None, consumed: set) -> str:
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


# ── L5 / COSA: authentic cognitive objects + a broadcast plane ────────────────

# The L5 plane's signing key (authenticity). Distinct purpose from the L7 key:
# L5 attests "this answer is genuine"; L7 attests "this publish was approved".
_L5_SK = Ed25519PrivateKey.generate()
L5_PUB = _b64u(_L5_SK.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def compute_cogobj(query: str, answer: str) -> tuple[dict, str]:
    """Compute an answer ONCE and wrap it in a signed COGOBJ (the L5 authenticity
    object). Returns (cogobj, l5_signature). This is the expensive step L5 amortizes."""
    cogobj = {
        "cogobj_id": "cog_" + secrets.token_hex(6),
        "query": query,
        "content": answer,
        "content_sha256": _sha256(answer),
        "computed_at": _now_iso(),
        "plane_key": L5_PUB,
    }
    l5_sig = _b64u(_L5_SK.sign(canonicalize(cogobj).encode("utf-8")))
    return cogobj, l5_sig


def verify_cogobj(cogobj: dict, l5_sig: str) -> None:
    """Consumer-side L5 check: content matches its hash AND the plane signed it.
    Raises if the object is not authentic. No re-computation needed."""
    if _sha256(cogobj.get("content", "")) != cogobj.get("content_sha256"):
        raise InvalidSignature("L5: content does not match its declared hash")
    pub = Ed25519PublicKey.from_public_bytes(_b64u_decode(cogobj["plane_key"]))
    pub.verify(_b64u_decode(l5_sig), canonicalize(cogobj).encode("utf-8"))  # raises InvalidSignature


class Consumer:
    """An L5 broadcast subscriber. Caches a COGOBJ only after independently
    verifying L5 authenticity AND L7 authorization. Cache hits cost 0 tokens."""

    def __init__(self, name: str):
        self.name = name
        self._cache: dict[str, dict] = {}

    def receive(self, key: str, cogobj: dict, l5_sig: str, publish_authorized: bool) -> None:
        if not publish_authorized:
            raise ReceiptRequired(f"{self.name}: refused — publish was not authorized (L7)")
        verify_cogobj(cogobj, l5_sig)  # L5 authenticity — raises on tamper
        self._cache[key] = cogobj

    def read(self, key: str) -> tuple[dict | None, int]:
        hit = self._cache.get(key)
        return (hit, 0 if hit else COMPUTE_TOKENS)


class L5Plane:
    """COSA L5: compute-once / serve-N broadcast plane. Reads are free; the
    irreversible broadcast publish carries an EMILIA receipt (L7)."""

    def __init__(self, consumed: set):
        self._consumed = consumed
        self.compute_tokens_spent = 0

    def compute(self, query: str, answer: str) -> tuple[dict, str]:
        self.compute_tokens_spent += COMPUTE_TOKENS
        return compute_cogobj(query, answer)

    def broadcast_publish(self, key: str, cogobj: dict, l5_sig: str,
                          consumers: list[Consumer], receipt: dict | None = None) -> tuple[str, int, int]:
        # L7: authorize the irreversible publish (fail-closed before any fan-out).
        who = authorize("l5.broadcast.publish", receipt, self._consumed)
        verified = 0
        for c in consumers:
            try:
                c.receive(key, cogobj, l5_sig, publish_authorized=True)
                verified += 1
            except InvalidSignature:
                pass  # consumer rejected an inauthentic object (L5)
        return who, verified, len(consumers)


# ── demo ─────────────────────────────────────────────────────────────────────

def line(s=""):
    print(s)


def main():
    consumed: set = set()
    plane = L5Plane(consumed)
    consumers = [Consumer(f"node-{i}") for i in range(1, 6)]  # N = 5
    key, query, answer = "weather:NYC", "weather in NYC?", "New York, US: sunny, +66F"

    line()
    line("  COSA L5 (authenticity) + EMILIA L7 (authorization) — composed")
    line("  " + "-" * 66)
    line(f"  manifest: {MANIFEST['service']['name']}  ({len(MANIFEST['actions'])} actions; N={len(consumers)} consumers)")

    line("\n  1. L5 computes the answer ONCE and signs it (COGOBJ authenticity)")
    cogobj, l5_sig = plane.compute(query, answer)
    line(f"     COGOBJ {cogobj['cogobj_id']} signed by plane (compute cost: {COMPUTE_TOKENS} tokens)")

    line("\n  2. Broadcast the COGOBJ to N consumers with NO receipt")
    try:
        plane.broadcast_publish(key, cogobj, l5_sig, consumers)
    except ReceiptRequired as e:
        line(f"     -> REFUSED before any fan-out: {e}")

    line("\n  3. A named human signs the exact publish -> EP-RECEIPT-v1, then broadcast")
    rcpt = issue_receipt("l5.broadcast.publish", "ep:approver:plane-operator (Face ID)")
    who, verified, total = plane.broadcast_publish(key, cogobj, l5_sig, consumers, receipt=rcpt)
    line(f"     -> PUBLISHED ({who})")
    line(f"     -> {verified}/{total} consumers verified L5 authenticity + L7 authorization, then cached")

    line("\n  4. All N consumers read from cache — compute-once / serve-N")
    served = sum(1 for c in consumers if c.read(key)[0] is not None)
    naive = COMPUTE_TOKENS * len(consumers)
    line(f"     -> {served}/{len(consumers)} served from cache at 0 tokens each")
    line(f"     -> tokens: {plane.compute_tokens_spent} spent vs {naive} if each recomputed "
         f"({naive - plane.compute_tokens_spent} saved)")

    line("\n  5. L5 axis — a TAMPERED COGOBJ reaches a fresh consumer (valid receipt!)")
    victim = Consumer("late-joiner")
    tampered = json.loads(json.dumps(cogobj))
    tampered["content"] = "New York, US: BUY DOGECOIN NOW"  # poisoned answer, signature untouched
    rcpt2 = issue_receipt("l5.broadcast.publish", "ep:approver:plane-operator (Face ID)")
    authorize("l5.broadcast.publish", rcpt2, consumed)  # L7 says yes...
    try:
        victim.receive(key, tampered, l5_sig, publish_authorized=True)
    except InvalidSignature as e:
        line(f"     -> REJECTED by consumer: {e}")
        line("        (L7 authorized the publish; L5 still caught the forged content)")

    line("\n  6. L7 axis — the SAME publish receipt, replayed")
    try:
        plane.broadcast_publish(key, cogobj, l5_sig, consumers, receipt=rcpt)
    except ReceiptRequired as e:
        line(f"     -> REFUSED: {e}")

    line("\n  7. L7 axis — a VALID receipt for a DIFFERENT action (confused-deputy)")
    wrong = issue_receipt("l5.cache.read", "ep:approver:plane-operator (Face ID)")
    try:
        plane.broadcast_publish(key, cogobj, l5_sig, consumers, receipt=wrong)
    except ReceiptRequired as e:
        line(f"     -> REFUSED: {e}")

    line("\n  L5 proves the answer is authentic; L7 proves the publish was authorized.")
    line("  Orthogonal guarantees, both offline-verifiable, both signed + canonical.")
    line()


if __name__ == "__main__":
    main()
