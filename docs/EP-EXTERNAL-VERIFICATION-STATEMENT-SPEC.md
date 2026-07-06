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
The signed bytes are:

```text
"EP-EXTERNAL-VERIFICATION-STATEMENT-v1\0" || JCS(statement_without_signature)
```

The resulting `statement_digest` is:

```text
"sha256:" || hex(SHA-256(signed_bytes))
```

## Acceptance

Verification is fail-closed:

- unsupported version: refused;
- missing or malformed signature: refused;
- digest mismatch after canonical recomputation: refused;
- valid signature from an unpinned verifier key: refused;
- invalid signature under the pinned verifier key: refused.

A relying party accepts the statement only by pinning the external verifier key
out of band. The statement's carried key is evidence to check against that pin,
not a trust root by itself.

## Non-Claims

The statement deliberately does not authorize the action. It does not certify
business correctness, legal compliance, human understanding, or wisdom. It says
only: this external verifier, under this pinned key, signed this exact procedure,
inputs, result, and limitations.

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
