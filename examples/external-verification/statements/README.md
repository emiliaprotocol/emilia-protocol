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
INDEPENDENT implementation agreeing on the vectors. The independent clean-room
reimplementation (COSA's own verifier, not wrapping ours) remains the
independent-implementation data point, and it is still underway. When a statement
arrives whose `implementation` names a verifier that does not depend on this
repository's code, that one is the independence milestone, and it will be recorded
here as such.
