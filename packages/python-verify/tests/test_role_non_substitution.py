# SPDX-License-Identifier: Apache-2.0
# Role non-substitution across the Python AEC verifier — mirror of the JS
# tests/role-non-substitution.test.js. A trusted MACHINE policy decision must
# not satisfy a human-authorization requirement, and each substitution attempt
# (label collision, version relabel, unsigned binding) fails closed.
import base64
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from emilia_verify import action_digest, canonicalize, verify_authorization_chain  # noqa: E402

AEC = "EP-AEC-v1"


def _pad(s):
    return s + "=" * (-len(s) % 4)


def _keypair():
    priv = Ed25519PrivateKey.generate()
    der = priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv, base64.urlsafe_b64encode(der).decode().rstrip("=")


def _sign(payload, priv):
    return base64.urlsafe_b64encode(priv.sign(canonicalize(payload).encode())).decode().rstrip("=")


ACTION = {"action_type": "wire.release", "target": "treasury.example/wire/8841",
          "amount": "25000.00", "currency": "USD"}
DIGEST = "sha256:" + action_digest(ACTION)

_machine_priv, MACHINE_PUB = _keypair()
_human_priv, HUMAN_PUB = _keypair()

_policy_payload = {"decision_id": "d1", "decision": "allow", "decision_maker": "policy-engine:gw7",
                   "tool": "wire.release", "approval_state": "granted", "action_digest": DIGEST,
                   "issued_at": "2026-07-11T12:00:00Z"}
POLICY_DOC = {"@version": "ACCESS-DECISION-RECORD-v1", "payload": _policy_payload,
              "signature": {"algorithm": "Ed25519", "value": _sign(_policy_payload, _machine_priv)}}


def _policy_verifier(ev, ctx):
    if not isinstance(ev, dict) or ev.get("@version") != "ACCESS-DECISION-RECORD-v1":
        return {"valid": False, "action_digest": None}
    try:
        pub = serialization.load_der_public_key(base64.urlsafe_b64decode(_pad(MACHINE_PUB)))
        pub.verify(base64.urlsafe_b64decode(_pad(ev["signature"]["value"])),
                   canonicalize(ev["payload"]).encode())
        ok = ev["payload"]["decision"] == "allow"
    except Exception:
        ok = False
    return {"valid": ok, "action_digest": ev["payload"]["action_digest"]}


VERIFIERS = {"policy_decision": _policy_verifier}
# Role-scoped pins: the human key is pinned ONLY for the ep-receipt role.
KEYS_BY_TYPE = {"ep-receipt": {HUMAN_PUB: HUMAN_PUB}}
BAR = "policy_decision AND ep-receipt"


def test_positive_policy_in_own_role():
    r = verify_authorization_chain(
        {"@version": AEC, "action": ACTION, "requirement": "policy_decision",
         "components": [{"type": "policy_decision", "evidence": POLICY_DOC}]},
        verifiers=VERIFIERS, keys_by_type=KEYS_BY_TYPE, requirement="policy_decision",
        expected_action_digest=DIGEST)
    assert r["allow"] is True
    assert r["components"][0]["valid"] and r["components"][0]["bound"]


def test_negative_label_collision():
    r = verify_authorization_chain(
        {"@version": AEC, "action": ACTION, "requirement": "policy_decision",
         "components": [{"type": "policy_decision", "label": "ep-receipt", "evidence": POLICY_DOC}]},
        verifiers=VERIFIERS, keys_by_type=KEYS_BY_TYPE, requirement=BAR)
    assert r["components"][0]["valid"] and r["components"][0]["bound"]
    assert r["allow"] is False


def test_negative_version_relabel_unpinned_key():
    smuggled = dict(POLICY_DOC)
    smuggled["@version"] = "EP-RECEIPT-v1"
    smuggled["operator_public_key"] = MACHINE_PUB  # not pinned
    smuggled["action_hash"] = DIGEST
    r = verify_authorization_chain(
        {"@version": AEC, "action": ACTION, "requirement": "ep-receipt",
         "components": [{"type": "ep-receipt", "evidence": smuggled}]},
        verifiers=VERIFIERS, keys_by_type=KEYS_BY_TYPE)
    assert r["components"][0]["valid"] is False
    assert r["allow"] is False


def test_negative_unsigned_binding():
    other = dict(ACTION)
    other["amount"] = "999999.00"
    other_payload = {"receipt_id": "evil", "issuer": "ep:approver:cfo", "subject": "x",
                     "action_digest": "sha256:" + action_digest(other), "created_at": "2026-07-11T12:00:00Z"}
    spoofed = {"@version": "EP-RECEIPT-v1", "payload": other_payload,
               "signature": {"algorithm": "Ed25519", "value": _sign(other_payload, _human_priv)},
               "operator_public_key": HUMAN_PUB, "action_hash": DIGEST}  # unsigned top-level spoof
    r = verify_authorization_chain(
        {"@version": AEC, "action": ACTION, "requirement": "ep-receipt",
         "components": [{"type": "ep-receipt", "evidence": spoofed}]},
        verifiers=VERIFIERS, keys_by_type=KEYS_BY_TYPE)
    assert r["components"][0]["bound"] is False
    assert r["allow"] is False


def test_negative_cross_role_key_confusion():
    # The machine's policy key IS pinned, but only for the policy_decision role.
    # Relabeled EP-RECEIPT-v1 with a payload binding this action, it must not fill
    # the human role: role-scoped pins refuse a key trusted for another role.
    smuggled = dict(POLICY_DOC)
    smuggled["@version"] = "EP-RECEIPT-v1"
    smuggled["operator_public_key"] = MACHINE_PUB
    keys = {"ep-receipt": {HUMAN_PUB: HUMAN_PUB}, "policy_decision": {MACHINE_PUB: MACHINE_PUB}}
    r = verify_authorization_chain(
        {"@version": AEC, "action": ACTION, "requirement": "ep-receipt",
         "components": [{"type": "ep-receipt", "evidence": smuggled}]},
        verifiers=VERIFIERS, keys_by_type=keys)
    assert r["components"][0]["valid"] is False
    assert r["allow"] is False


def test_negative_forged_quorum_unpinned_keys():
    # verify_quorum checks only internal consistency against the quorum's OWN
    # declared keys, so an attacker forges an entire distinct-human quorum under
    # keys it generated. The ep-quorum leg must refuse it: no member key is pinned
    # under keysByType['ep-quorum'].
    _a, a_pub = _keypair()
    _b, b_pub = _keypair()
    forged = {
        "@type": "ep.quorum", "action_hash": DIGEST,
        "policy": {"mode": "threshold", "required": 2, "distinct_humans": True, "window_sec": 172800,
                   "approvers": [{"role": "a", "approver": "ep:approver:attacker-a"},
                                 {"role": "b", "approver": "ep:approver:attacker-b"}]},
        "members": [{"role": "a", "approver_public_key": a_pub, "signoff": {}},
                    {"role": "b", "approver_public_key": b_pub, "signoff": {}}],
    }
    r = verify_authorization_chain(
        {"@version": AEC, "action": ACTION, "requirement": "ep-quorum",
         "components": [{"type": "ep-quorum", "evidence": forged}]},
        keys_by_type={"ep-quorum": {HUMAN_PUB: HUMAN_PUB}})
    assert r["components"][0]["valid"] is False
    assert r["allow"] is False


def test_negative_bare_operator_receipt_is_not_human():
    receipt_payload = {"receipt_id": "r1", "issuer": "ep:approver:cfo", "subject": "wire-8841",
                       "action_digest": DIGEST, "created_at": "2026-07-11T12:00:02Z"}
    receipt = {"@version": "EP-RECEIPT-v1", "payload": receipt_payload,
               "signature": {"algorithm": "Ed25519", "value": _sign(receipt_payload, _human_priv)},
               "operator_public_key": HUMAN_PUB}
    r = verify_authorization_chain(
        {"@version": AEC, "action": ACTION, "requirement": "policy_decision",
         "components": [{"type": "policy_decision", "evidence": POLICY_DOC},
                        {"type": "ep-receipt", "evidence": receipt}]},
        verifiers=VERIFIERS, keys_by_type=KEYS_BY_TYPE, requirement=BAR,
        expected_action_digest=DIGEST)
    assert r["allow"] is False
    assert r["components"][1]["valid"] is False


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
