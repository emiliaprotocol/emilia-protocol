# SPDX-License-Identifier: Apache-2.0
# Python conformance runner: emits [{id, valid}] per vector. argv[1] = vectors path.
# Polymorphic: receipt (document) | signoff | quorum.
import sys, json, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "packages", "python-verify"))
from emilia_verify import (verify_receipt, verify_webauthn_signoff, verify_quorum,
                            verify_revocation, verify_time_attestation)
vectors = json.load(open(sys.argv[1]))["vectors"]
def run(v):
    if "document" in v: return verify_receipt(v["document"], v["public_key"]).valid
    if "signoff" in v: return verify_webauthn_signoff(v["signoff"], v["approver_public_key"], {"rpId": v.get("rp_id")})["valid"]
    if "quorum" in v: return verify_quorum(v["quorum"], {"rpId": "emiliaprotocol.ai"})["valid"]
    if "revocation" in v: return verify_revocation(v["target"], v["revocation"], {"revokerKeys": v.get("revoker_keys"), "maxAgeSeconds": v.get("max_age_seconds"), "now": v.get("now")})["valid"]
    if "time_attestation" in v: return verify_time_attestation(v["time_attestation"], {"tsaKeys": v.get("tsa_keys"), "expectedHash": v.get("expected_hash"), "notBefore": v.get("not_before"), "notAfter": v.get("not_after")})["valid"]
    return False
print(json.dumps([{"id": v["id"], "valid": run(v)} for v in vectors]))
