<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-EXTERNAL-VERIFICATION-STATEMENT-v1

`EP-EXTERNAL-VERIFICATION-STATEMENT-v1` is the small artifact a non-EMILIA
verifier signs after it checks EP evidence. It is the adoption rail for the
structural gap called out in the capability map: an outside party needs a
portable way to say, in its own name, exactly what it verified.

The statement is implemented in
[`packages/gate/reports/external-verification.js`](../packages/gate/reports/external-verification.js).

## What It Says

A statement records:

- the external verifier identity and pinned Ed25519 key;
- the subject checked, such as an evidence-log head, admissibility result,
  receipt, or conformance run;
- the procedure performed, such as `EP-GATE-REPERFORMANCE-v1`;
- stable input digests, issuer-key counts, profile hashes, and other scoped
  inputs the verifier consumed;
- the verifier's result and named checks;
- the limitations and non-claims.

The signature covers every field above, excluding only the signature envelope.
`statement_without_signature` is the statement JSON object with the **entire
top-level `signature` member removed** (not merely `signature_b64u` or
`statement_digest`). The signed bytes are the domain-separation label, whose
final byte is a single NUL (`0x00`, one byte, not the two characters backslash
and zero), byte-concatenated with the RFC 8785 (JCS) canonicalization of that
object:

```text
"EP-EXTERNAL-VERIFICATION-STATEMENT-v1" || 0x00 || JCS(statement_without_signature)
```

The resulting `statement_digest` is:

```text
"sha256:" || hex(SHA-256(signed_bytes))
```

An independent signer MUST reproduce these exact bytes; the normative reference
is `externalVerificationDigest` / `signingBytes` in
`packages/gate/reports/external-verification.js`, and
`examples/external-verification/sign-statement.mjs` signs correctly by
construction. A digest that diverges here is refused before the signature is
checked, so a signer that gets these bytes wrong will not verify even with a
valid key.

**Golden test vector.** Reproduce the digest construction in isolation, in any
language, before integrating: `examples/external-verification/digest-test-vector.json`
carries a fixed example statement and its `expected_statement_digest`
(`sha256:d771c82a...`). If your independent signer does not reproduce that value
for that input, your construction diverges from this section and your statements
will not verify regardless of your verifier logic. This is the most common
integration wall.

**Line endings (a separate, silent trap).** `suite_digest` is SHA-256 over the
**raw bytes** of each conformance vector file, so a checkout that rewrites line
endings (Windows Git with the default `core.autocrlf=true`) changes the digest
without changing the vectors. The repository ships a `.gitattributes` pinning
`conformance/vectors/**` to verbatim LF; an implementer cloning independently
must keep those files LF (`core.autocrlf=false`) or reproduce the digests over
the canonicalized JSON value rather than the raw bytes.

## Acceptance

Verification is fail-closed:

- unsupported version: refused;
- missing or malformed signature: refused;
- digest mismatch after canonical recomputation: refused;
- valid signature from an unpinned verifier key: refused;
- invalid signature under the pinned verifier key: refused;
- a pin that matches the key but omits or contradicts the statement's
  `verifier.id`: refused (a pin vouches for an identity, not just a key);
- an envelope `key_id` that differs from the value derived from the carried
  public key: refused (the envelope is outside the signed bytes, so the
  verifier recomputes `key_id` and never trusts the carried one).

A relying party accepts the statement only by pinning the external verifier key
out of band, and every pin entry must name the `verifier_id` it vouches for.
The statement's carried key is evidence to check against that pin, not a trust
root by itself. Note that `checks.signature` is evaluated only after the key is
pinned; a pinning refusal reports `signature: false` in the sense of "not
established," not "cryptographically invalid" (the `reason` field
disambiguates).

## Non-Claims

The statement deliberately does not authorize the action. It does not certify
business correctness, legal compliance, human understanding, or wisdom. It says
only: this external verifier, under this pinned key, signed this exact procedure,
inputs, result, and limitations.

It also carries no freshness or scope guarantees: there is no expiry, nothing
binds a statement to a particular consumer, a valid statement is replayable
verbatim, and `generated_at` is asserted by the signer, not verified. A relying
party that needs freshness must ask the verifier for a new statement over a new
subject digest. The default `limitations` array states this in-band.

That narrowness is the point. An auditor, standards reviewer, COSA implementer,
or design partner can now issue a durable artifact saying what they checked
without becoming an EP authority or trusting an EMILIA-operated service.

## Reference API

```js
import {
  signExternalVerificationStatement,
  verifyExternalVerificationStatement,
} from '@emilia-protocol/gate/reports/external-verification';

const statement = signExternalVerificationStatement({
  verifier: { id: 'ext:auditor:alpha', name: 'Alpha External Verification' },
  subject: { kind: 'gate_evidence_log', evidence_head: 'sha256:...' },
  procedure: { id: 'ep-gate-reperformance', version: 'EP-GATE-REPERFORMANCE-v1' },
  inputs: { entries_digest: 'sha256:...', admissibility_profile_hash: 'sha256:...' },
  result: { status: 'verified', checks: [{ id: 'chain_reperformed', ok: true }] },
}, verifierPrivateKey);

const result = verifyExternalVerificationStatement(statement, {
  pinnedVerifierKeys: [{ verifier_id: 'ext:auditor:alpha', public_key: '<base64url SPKI>' }],
});
```

The focused conformance tests are in
[`packages/gate/reports/external-verification.test.js`](../packages/gate/reports/external-verification.test.js).

## Turnkey Harness

A step-by-step harness for issuing this statement over a conformance run,
from a fresh clone with only Node installed, lives in
[`examples/external-verification/`](../examples/external-verification/). It
keeps the two possible procedures honestly distinct: signing over YOUR OWN
verifier's results against the public vectors
(`EP-CONFORMANCE-RUN-OWN-IMPLEMENTATION-v1`, the meaningful one) versus
re-executing this repository's own reference runner on your machine
(`EP-CONFORMANCE-RUN-REFERENCE-RUNNER-v1`, a consistency check that is never
an independent implementation, and whose statement says so in its
limitations).
