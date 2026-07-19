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
- Historical signed result: `verified`, all 16 suites, 158 of 158 vectors pass,
  zero divergences, bound to commit `4c15586` and that input set.
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
external-implementation milestone has now arrived by another route: a Rust
verifier authored outside this project is rebuilt from pinned public source and
passes the current evaluator's conformance and hostility campaigns. Its strict
construction-independence status remains separately and explicitly unresolved.

### Rust verifier / J Diesel NY — 2026-07-07 (external implementation milestone)

- Directory: [`rust-cleanroom/`](rust-cleanroom/)
- Verifier: `ext:verifier:emilia-cleanroom-rust` (J Diesel NY), key_id
  `ep:external-verifier-key:sha256:87c8c5029475f53a`
- Procedure: `ep-conformance-own-implementation`
- Historical signed result: `verified`, all 16 suites, 162 of 162 vectors pass,
  zero divergences, including `same_party_evidence_presented_as_independent`
  correctly rejected; this remains bound to the statement's 162-vector input set.
- Implementation: `emilia-rust-verifier 0.1.0 (cleanroom, Rust)` — described by
  its author as a from-scratch Rust verifier, with source public at
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
evaluator at a later pinned public commit and passes the expanded 163-vector
bundle. That newer result is an evaluator-generated CI artifact, not a rewrite
of this signed 162-vector statement. The later commit also passes the pinned
differential-hostility campaign: 353 structured attacks and 6 raw-parser
refusals with zero divergences. It remains external interoperability and
hostility evidence, not strict clean-room acceptance, until a separate attestor
signs a current-schema manifest under an independently pinned key. The
implementer-signed record of the full current vector set now exists separately:
see the 2026-07-13 statement below, which does not retroactively change this
one.

**What remains attestation.** That the implementation was written only from the
Internet-Drafts and the vector schemas, without reading this repository's
verifier code, is the implementer's stated construction process. Publishing the
source makes that claim auditable by anyone; no output can prove it.

### Rust verifier / J Diesel NY — 2026-07-13 (historical pinned-input statement)

- File: [`rust-cleanroom/statement-2026-07-13.json`](rust-cleanroom/statement-2026-07-13.json),
  published as received.
- Verifier: `ext:verifier:emilia-cleanroom-rust` (J Diesel NY), same key_id
  `ep:external-verifier-key:sha256:87c8c5029475f53a` as the 2026-07-07 statement.
- Signed result for this historical input: `verified`, all 17 suites, 193 of 193 vectors, bound to this
  repository's commit `a904480` by per-suite `suite_digests`.

**Verified by the maintainer 2026-07-13, each step re-run here.** The statement
is accepted under the stored pin with `verify-statement.mjs` (`verified: true`,
`accepted: true`); all 17 `suite_digests` match this repository's vector bytes
at `a904480` exactly; and, separately from the statement, the maintainer rebuilt
the public source at its pinned commit `f4c10aa` with a local toolchain and
re-ran all 17 suites (193/193, zero divergences) plus the differential-hostility
campaign (353 structured cases and 6 raw-parser refusals, zero divergences).

**Scope, unchanged.** The statement is signed by the implementing organization,
not by a separate attestor, so it does not change the strict clean-room
acceptance status above. The statement does not name the implementation source
commit; the maintainer's rebuild pins that independently. The statement's own
limitations field notes that per-vector results are produced by the named
implementation and compared by its harness against each vector's `expect.valid`;
the maintainer's independent re-run closes that distance for the same source
tree. Construction independence remains the implementer's attestation, auditable
in the public source. Stated precisely: one implementation set from this
repository (JavaScript, Python, Go, one team) and one externally authored
from-spec Rust implementation agree on the 193-vector historical input set; the original
signed statement remains bound to its 162-vector input set, and this one is
bound to the 193-vector set at `a904480`.
