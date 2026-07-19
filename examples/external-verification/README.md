<!-- SPDX-License-Identifier: Apache-2.0 -->
# Issue your first EP-EXTERNAL-VERIFICATION-STATEMENT-v1

This directory is a turnkey harness for an implementer who built their OWN
verifier for EP formats (for example a clean-room reimplementation like COSA)
and wants to publish a signed, portable record of exactly what they checked.
You need a fresh clone of this repository and Node.js 18 or newer. Nothing
else: no npm install, no account, no server, no EMILIA-operated service.

The statement format is specified in
[`docs/EP-EXTERNAL-VERIFICATION-STATEMENT-SPEC.md`](../../docs/EP-EXTERNAL-VERIFICATION-STATEMENT-SPEC.md).
The statement is signed with YOUR key, in YOUR name. Nobody grades it, and
issuing one implies no endorsement in either direction.

## The two procedures, and why they are labeled differently

- **MODE A (default, the one that matters):** you run YOUR OWN verifier over
  the public conformance vectors and this harness signs over your results.
  Procedure: `EP-CONFORMANCE-RUN-OWN-IMPLEMENTATION-v2`.
- **MODE B (`--run-reference`):** the harness re-executes this repository's
  own reference runner on your machine and signs over its outcome. That only
  shows the repository's own verifiers behave the same on your machine. It is
  NOT an independent implementation, the statement says so explicitly, and it
  never substitutes for MODE A.

## Step 1: clone and enter the repository

```zsh
git clone https://github.com/emiliaprotocol/emilia-protocol
cd emilia-protocol
```

Every command below is run from the repository root.

## Step 2: mint your verifier keypair

```zsh
node examples/external-verification/generate-key.mjs
```

This writes two files into `examples/external-verification/out/`:

- `private-key.pem`: your Ed25519 signing key. **It never leaves `out/`.
  Never commit it, never mail it, never paste it anywhere.** The `out/`
  directory is gitignored so `git add` cannot pick it up.
- `public.key`: the public half in the exact format a relying party pins
  (SPKI, base64url). This one you share.

The script refuses to overwrite an existing key; pass `--force` only if you
really mean to destroy the old one.

## Step 3: run YOUR verifier over the vectors

Pick the suites you implemented from `conformance/vectors/`. Suite files are
the `*.v1.json` files that contain a top-level `vectors` array (the directory
also holds generator scripts and a few non-suite JSON files; the harness
refuses anything that is not a real suite, so a wrong pick fails loudly, not
silently). Implementing `receipts.v1.json` alone is already a meaningful
result. For each suite, run your own verifier over every vector and write the
outcome to a results file.

**Results-file contract:** a JSON array with exactly one entry per vector in
the suite. For ordinary validity suites, use the same `valid` contract as
[`conformance/plugfest-pack/`](../../conformance/plugfest-pack/README.md):

```json
[
  { "id": "accept_minimal", "valid": true },
  { "id": "reject_tampered_payload", "valid": false }
]
```

`id` is the vector's `id` from the suite file and `valid` is what YOUR
verifier concluded. Name each file `<suite-file-name>.results.json`, so for
the suite `receipts.v1.json` the file is `receipts.v1.json.results.json`.

Typed suites must preserve their published result type instead of collapsing it
to a boolean:

```json
[
  { "id": "eq_pass", "outcome": "in_bounds" },
  { "id": "graph_predicates_in_bounds_admissible", "verdict": "admissible" }
]
```

- `expect.outcome` requires an `outcome` result.
- `expect.verdict` requires a `verdict` result.
- `expect.accepted` requires an `accepted` boolean result and, when the vector
  carries `expect.reason`, the exact `reason` string.
- `expect.valid` requires a `valid` boolean result.

Each row must contain only `id` and its one matching result field; an
`accepted` row also carries `reason` when the vector requires it. The harness
refuses normalized booleans for typed vectors, preserving the exact result in
the signed `results_digest`. Outcome Binding uses `outcome` and `verdict`;
Authority Introduction's serialized join suite uses `accepted` plus exact
refusal reasons.

Outcome Binding's filing packet contains two suites that must be run together:
`outcome-binding.v1.json` covers semantic predicate and evidence-graph replay,
while `outcome-binding.exec.v1.json` carries a real signed Trust Receipt, real
v2 log proof, and real executor attestations. Both require typed results;
testing only one suite does not clear that draft's independent-verification
gate.

For example, if your verifier binary is called `cosa-verify` and prints that
JSON array (replace with your real command):

```zsh
mkdir -p examples/external-verification/out/results
cosa-verify conformance/vectors/receipts.v1.json > examples/external-verification/out/results/receipts.v1.json.results.json
cosa-verify conformance/vectors/signoffs.v1.json > examples/external-verification/out/results/signoffs.v1.json.results.json
```

## Step 4: sign the statement

Fill in your own identity and implementation name:

```zsh
node examples/external-verification/sign-statement.mjs --results examples/external-verification/out/results --verifier-id ext:verifier:cosa --verifier-name "COSA" --org "Your organization" --implementation "cosa-verify 0.1.0 (clean-room, Rust)"
```

The harness derives each suite name from its results file's name (that is why
the `<suite-file-name>.results.json` naming in Step 3 matters), loads that
suite from `conformance/vectors/`, compares each reported value and type
against the vector's published expectation, and writes the signed statement to
`examples/external-verification/out/statement.json`, printing its
`statement_digest`.

Two honest outcomes are possible and both sign:

- `result.status: verified` means every suite matched fully.
- `result.status: divergent` means at least one vector differed. That is a
  valid finding, arguably the most useful one this exercise can produce, and
  the per-suite checks record exactly which suites diverged (`passed/total`).

Structural problems never sign. The harness refuses, with a distinct reason,
on an unknown suite name, a missing vector id, a duplicate id, an extra id, or
a malformed file.

## Step 5: check it verifies before you send it

```zsh
node examples/external-verification/verify-statement.mjs examples/external-verification/out/statement.json --pin examples/external-verification/out/public.key --verifier-id ext:verifier:cosa
```

The `--verifier-id` must be the same id you signed with: a relying party pins
your key together with your identity, never the key alone. Exit code 0 and
`ACCEPTED` means a relying party who pins your `public.key` under that id
will accept the signature. Acceptance is about the signature, not the run:
always read `result.status` too.

### Building your own signer? Two walls to clear first

Real implementers hit these two before anything else, so clear them in isolation:

1. **Digest construction.** Check your `statement_digest` code against
   [`digest-test-vector.json`](digest-test-vector.json) — a fixed statement and
   its expected digest. If you do not reproduce `sha256:d771c82a...`, your signed
   bytes are wrong (usual causes: signing over the whole statement including the
   `signature` block, or writing the domain separator as two characters instead
   of a single `0x00` NUL byte). `verify-statement.mjs` prints this diagnostic on
   a `statement_digest_mismatch`.
2. **Line endings — fixed in procedure v2.** `suite_digest` is now SHA-256 over
   the JCS-canonical value of each vector file, so it is invariant to line endings:
   a Windows CRLF checkout no longer changes it, and you reproduce it with the same
   JCS you already use for receipts. (Procedure v1 hashed raw bytes and did have
   this trap, which cost a real implementer several rounds; the repo `.gitattributes`
   still pins the vectors to LF as defense in depth.)

## MODE B: re-running the repository's own reference runner

If you have not built your own verifier yet, you can still sign a much weaker
statement over a re-execution of the repository's own cross-language runner
(requires Python 3 and Go in addition to Node, and takes a few minutes):

```zsh
node examples/external-verification/sign-statement.mjs --run-reference --verifier-id ext:verifier:yourname --verifier-name "Your name"
```

This is a DIFFERENT procedure (`EP-CONFORMANCE-RUN-REFERENCE-RUNNER-v2`) and
the statement carries a limitation saying it re-executed the repository's own
reference runner and is not an independent implementation. Do not present a
MODE B statement as an interop result.

## What the statement does NOT claim

Directly from the spec: the statement does not authorize any action, does not
certify business correctness, legal compliance, human understanding, or
wisdom, and is not an endorsement by or of anyone. It says only that this
verifier, under this key, ran this exact procedure over these exact inputs
and got this result, with these limitations. MODE A additionally records that
the per-vector results came from your own verifier and are self-reported; the
harness only compared them to the published typed expectations.

## Self-test

The harness tests itself end to end in a temp directory (no key material
touches the repository tree):

```zsh
node examples/external-verification/self-test.mjs
```

## Send it back

Reply with two files: `statement.json` and `public.key` (never
`private-key.pem`). Statements are welcome as a GitHub issue or pull request
adding a row to the matrix in
[`conformance/plugfest-pack/README.md`](../../conformance/plugfest-pack/README.md),
or directly to team@emiliaprotocol.ai.
