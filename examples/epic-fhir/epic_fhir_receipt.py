# SPDX-License-Identifier: Apache-2.0
"""
EMILIA Protocol x Epic (FHIR) reference integration.

Demonstrates the accountability hook a health system or Epic-shop vendor builds
on the FREE open.epic.com FHIR tier: when an agent (or clinician) takes a
high-risk clinical action, a named clinician's device-bound signoff produces an
offline-verifiable EP receipt over the EXACT action, and the receipt is surfaced
back into the chart as a FHIR Provenance resource so it is discoverable from the
Epic record.

Design rule: the receipt is PHI-FREE. It carries references and hashes (the FHIR
resource id and a content hash that lives in Epic), the action type, and the
authorizing clinician identifier -- never patient data. The receipt verifies with
math alone, by any third party, without contacting Epic, EMILIA, or any server.

Same primitives as the rest of EMILIA: Ed25519 (pynacl) + RFC 8785 / JCS
canonicalization (jcs). Maps onto the controls Epic customers already run -- the
ISMP / Joint Commission high-alert-medication independent double-check, and
segregation of duties.

Run:  python epic_fhir_receipt.py    (deps: pip install pynacl jcs)
"""
import base64, hashlib
import jcs
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError


def b64u(b):      return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def b64u_dec(s):  return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def canon(obj):   return jcs.canonicalize(obj)            # RFC 8785 -> bytes
def sha256_hex(b): return hashlib.sha256(b).hexdigest()


# --- The clinician's enrolled signing key (in production: a WebAuthn / Face ID
#     platform authenticator). APPROVER_PUB is published out of band and PINNED
#     by the verifier -- never the key carried inside the receipt. ----------------
clinician_sk = SigningKey.generate()
APPROVER_PUB = b64u(clinician_sk.verify_key.encode())


def fhir_action(med_request):
    """The exact action requiring oversight, derived from an Epic FHIR resource.
    PHI-free: we reference the MedicationRequest by id and bind a content hash of
    the canonical resource (which stays in Epic), not the patient."""
    return {
        "action_type": "epic.high_alert_med.override",
        "effect_class": "clinical",
        "fhir_resource_type": "MedicationRequest",
        "fhir_resource_ref": med_request["id"],
        "fhir_resource_hash": "sha256:" + sha256_hex(canon(med_request)),
        "control": "ISMP-independent-double-check",
    }


def authorization_context(action, approver_id, approved_at_ms):
    return {
        "ep_version": "1.0",
        "context_type": "ep.signoff.v1",
        "action": action,
        "action_hash": "sha256:" + sha256_hex(canon(action)),
        "human_oversight": {"control_mode": "in_the_loop"},
        "approver": approver_id,
        "approved_at_ms": approved_at_ms,
    }


def issue_receipt(context, sk=clinician_sk):
    return {
        "payload": context,
        "sig": b64u(sk.sign(canon(context)).signature),
        "approver_pub": b64u(sk.verify_key.encode()),   # display only
        "receipt_id": "ep_" + sha256_hex(canon(context)),
    }


def verify_receipt(receipt, trusted_pub, action_being_executed):
    try:
        VerifyKey(b64u_dec(trusted_pub)).verify(canon(receipt["payload"]), b64u_dec(receipt["sig"]))
    except BadSignatureError:
        return (False, "signature invalid (forged or tampered)")
    p = receipt["payload"]
    if p["action"] != action_being_executed:
        return (False, "receipt is not for the action being executed")
    if p["action_hash"] != "sha256:" + sha256_hex(canon(action_being_executed)):
        return (False, "action hash mismatch")
    return (True, f"authorized by {p['approver']}")


def fhir_provenance(receipt):
    """Surface the EP receipt back into the chart as a FHIR Provenance resource so
    it is discoverable from the Epic record. PHI-free: targets the order, carries
    the receipt id/hash and the clinician, not patient data."""
    p = receipt["payload"]
    return {
        "resourceType": "Provenance",
        "target": [{"reference": f'{p["action"]["fhir_resource_type"]}/{p["action"]["fhir_resource_ref"]}'}],
        "recorded": "2026-06-25T00:00:00Z",
        "agent": [{
            "type": {"coding": [{"code": "author"}]},
            "who": {"identifier": {"system": "https://emiliaprotocol.ai/approver", "value": p["approver"]}},
        }],
        "signature": [{
            "type": [{"system": "urn:iso-astm:E1762-95:2013", "code": "1.2.840.10065.1.12.1.5"}],
            "when": "2026-06-25T00:00:00Z",
            "who": {"identifier": {"value": p["approver"]}},
            "data": b64u(canon(receipt)),          # the portable EP receipt, verifiable offline
            "_emilia_receipt_id": receipt["receipt_id"],
        }],
    }


if __name__ == "__main__":
    # An Epic FHIR MedicationRequest for a high-alert medication (PHI omitted here;
    # in production this is the real resource fetched from the Epic FHIR API).
    med_request = {
        "id": "MR-44192",
        "resourceType": "MedicationRequest",
        "status": "active",
        "medication_code": "rxnorm:1819",        # buprenorphine (high-alert class)
        "dose": {"value": 8, "unit": "mg"},
        "intent": "order",
    }

    action = fhir_action(med_request)
    ctx = authorization_context(action, "epic:clinician:jchen-pharmd", 1_750_000_000_000)
    receipt = issue_receipt(ctx)

    print("receipt_id:", receipt["receipt_id"])
    print("verify     ->", verify_receipt(receipt, APPROVER_PUB, action))

    prov = fhir_provenance(receipt)
    print("\nFHIR Provenance written back to the chart:")
    print("  target   :", prov["target"][0]["reference"])
    print("  agent    :", prov["agent"][0]["who"]["identifier"]["value"])
    print("  receipt  :", prov["signature"][0]["_emilia_receipt_id"])

    print("\n--- what the binding catches ---")
    # Tamper: the dose is changed after the clinician signed.
    tampered = fhir_action({**med_request, "dose": {"value": 24, "unit": "mg"}})
    print("dose tampered     ->", verify_receipt(receipt, APPROVER_PUB, tampered))

    # Forgery: an impostor signs with their own key, checked against the pinned key.
    mallory = SigningKey.generate()
    forged = issue_receipt(ctx, sk=mallory)
    print("forged signature  ->", verify_receipt(forged, APPROVER_PUB, action))

    print("\nPHI-free: the receipt carries refs + hashes (resource lives in Epic), never patient data.")
