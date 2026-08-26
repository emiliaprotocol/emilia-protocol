<!-- SPDX-License-Identifier: Apache-2.0 -->
# CCS 1.1.19 L1 receipt to AEB composition v1

This runner consumes an explicitly labeled EMILIA-derived L1 receipt generated
from the exact tagged `ccs-verifier==1.1.19` source lock and public reference
seed as `machine-policy-decision` evidence. It pins the upstream tag object and
commit, both PyPI artifact hashes, the exact stale 1.1.14 vector shipped in the
1.1.19 source distribution, and the separately generated 1.1.19 fixture. It
then verifies the Ed25519
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

The 1.1.19 source distribution still bundles a stale 1.1.14 reference vector.
This profile preserves and hash-checks those bytes without relabeling them. See the
[release audit](../../../interop/ccs-aeb/CCS-1.1.19-L1-AUDIT.md) for the exact
boundary and deterministic EMILIA-derived-vector method.

## Scope

CCS remains the owner of its native verification and rule semantics. This
profile consumes a CCS `allow` only as machine-policy evidence. It does not
turn that result into human authorization, provider admission, or effect
proof. The public reference key is test material, not a production trust
anchor. Running this kit reproduces the EMILIA reference adapter; it is not an
independent implementation, deployment result, certification, IETF adoption,
or endorsement.
