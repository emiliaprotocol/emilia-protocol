<!-- SPDX-License-Identifier: Apache-2.0 -->
# CCS 1.1.20 L1 receipt to AEB composition v1

This runner consumes the exact upstream L1 reference receipt shipped by
`ccs-verifier==1.1.20` as `machine-policy-decision` evidence. It pins the
annotated tag object, target commit, both PyPI artifact hashes, and exact
upstream vector bytes. The tag is annotated but not GPG-signed, so the byte
pins do not claim cryptographic publisher authentication. The runner verifies
the Ed25519
signature, relying-party issuer pin, audience, expiry, rule version, action,
and tool. AEB then joins the signed full `args_digest` to the exact action
independently constructed by the executor and derives its CAID.

Run the pinned checks:

```bash
npm run conformance:composition:ccs-l1-aeb
```

The eight cases cover the exact source and artifact pins, valid receipt, signature
tampering, untrusted signing key, expiry, exact-action mapping, action
substitution, and unavailable status.

The 1.1.20 source distribution ships a reference vector whose package and rule
versions both identify 1.1.20. See the
[release audit](../../../interop/ccs-aeb/CCS-1.1.20-L1-AUDIT.md) for the exact
source lock and verification boundary. The 1.1.19 audit and its fixtures remain
checked in as historical evidence of the corrected stale-vector issue.

## Scope

CCS remains the owner of its native verification and rule semantics. This
profile consumes a CCS `allow` only as machine-policy evidence. It does not
turn that result into human authorization, provider admission, or effect
proof. The public reference key is test material, not a production trust
anchor. Running this kit reproduces the EMILIA reference adapter; it is not an
independent implementation, deployment result, certification, IETF adoption,
or endorsement.
