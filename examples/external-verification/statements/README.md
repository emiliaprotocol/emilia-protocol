<!-- SPDX-License-Identifier: Apache-2.0 -->
# External verification statements on record

Signed `EP-EXTERNAL-VERIFICATION-STATEMENT-v1` statements issued by parties other
than the maintainer, published here as received. Each is accepted only by pinning
the issuer's `verifier_id` together with its `public.key`. Anyone can re-check a
statement:

```zsh
node examples/external-verification/verify-statement.mjs \
  examples/external-verification/statements/<dir>/statement.json \
  --pin examples/external-verification/statements/<dir>/public.key \
  --verifier-id <the verifier id>
```

A statement's acceptance proves the signature is genuine and the run is bound to
the stated commit. It does not by itself establish that the signer's verifier is
independent of this repository's code; read the `inputs.implementation` field for
what actually produced the per-vector results.

## Statements

### COSA / J Diesel NY — 2026-07-06

- Directory: [`cosa/`](cosa/)
- Verifier: `ext:verifier:cosa` (COSA, J Diesel NY), key_id
  `ep:external-verifier-key:sha256:d20b9e48115ee89a`
- Procedure: `ep-conformance-own-implementation` (MODE A)
- Result: `verified`, all 16 suites, 158 of 158 vectors pass, zero divergences,
  bound to commit `4c15586`.
- Verified against the pinned key with `verify-statement.mjs`: accepted.

**What this is, stated precisely.** This is the first external verification
statement EP has on record: a party other than the maintainer ran the full public
vector set and signed the result under its own key. It is external reproduction of
the vector pass, which is a real and useful data point.

**What this is not.** The statement's own `inputs.implementation` field reads
`COSA Node (Python/emilia-verify)`, so this run used the `emilia-verify` package
from this project, not a separate verifier. It therefore does not establish an
INDEPENDENT implementation agreeing on the vectors. A COSA-authored clean-room
verifier that does not wrap ours would be a further such data point. The
independence milestone itself has now arrived by another route: an externally
authored from-spec Rust verifier whose `implementation` names a verifier that does
not depend on this repository's code, agreeing on all 162 published vectors, is
recorded in the Rust cleanroom entry below.

### Rust cleanroom verifier / J Diesel NY — 2026-07-07 (the independence milestone)

- Directory: [`rust-cleanroom/`](rust-cleanroom/)
- Verifier: `ext:verifier:emilia-cleanroom-rust` (J Diesel NY), key_id
  `ep:external-verifier-key:sha256:87c8c5029475f53a`
- Procedure: `ep-conformance-own-implementation`
- Result: `verified`, all 16 suites, 162 of 162 vectors pass, zero divergences,
  including `same_party_evidence_presented_as_independent` correctly rejected.
- Implementation: `emilia-rust-verifier 0.1.0 (cleanroom, Rust)` — a from-scratch
  Rust verifier whose source is public at
  [`jdieselny/ecr-wg/rust/ep-cleanroom-verifier`](https://github.com/jdieselny/ecr-wg/tree/main/rust/ep-cleanroom-verifier),
  built on `ed25519-dalek`/`p256`/`rsa`/`sha2` with its own RFC 8785 JCS and
  RFC 3161 DER/CMS handling. It does not wrap or import any package from this
  repository.

**Verified by the maintainer, each step re-run here.** The signature is accepted
under the pinned key with `verify-statement.mjs`; all 16 `suite_digests` match
this repository's published vector bytes exactly (the statement's `commit` field
lags one commit; the digests are what bind, and they bind to the 162-vector set);
and the maintainer cloned the public source, built it with a local Rust
toolchain, and re-ran all 16 suites: 162/162 with zero divergences, measured
independently of the numbers in the statement.

The same immutable external source tree has since been rebuilt by the current
evaluator and passes the expanded 163-vector bundle. That newer result is an
evaluator-generated CI artifact, not a rewrite of this signed 162-vector
statement. The stronger differential-hostility campaign is not green: it finds
one accepted duplicate-root JSON member, two raw-parser crashes, and twelve
malformed canonicalization inputs that panic the runner. The pinned public
implementation therefore remains external interoperability evidence, not
strict-clean-room accepted evidence. A newer third-party-attested GUV'NOR run is
pending its corrected signed manifest and public source commit; it will be
recorded separately rather than retroactively changing this statement.

**What remains attestation.** That the implementation was written only from the
Internet-Drafts and the vector schemas, without reading this repository's
verifier code, is the implementer's stated construction process. Publishing the
source makes that claim auditable by anyone; no output can prove it. Stated
precisely: one implementation set from this repository (JavaScript, Python, Go,
one team) and one externally authored from-spec Rust implementation agree on all
163 current vectors; the original signed statement remains bound to its
162-vector input set.
