<!-- SPDX-License-Identifier: Apache-2.0 -->

# EMILIA conformance surfaces

This directory contains several evidence surfaces with different scopes. Their
counts and claims must remain separate.

## Current claim ledger

| Surface | Pinned scope | Current result | Honest boundary |
| --- | --- | --- | --- |
| Same-team cross-language corpus | [`conformance-manifest.json`](conformance-manifest.json) | **21 suites / 332 vectors** agree across JavaScript, Python, and Go | Three ports maintained in one repository by one team; a consistency check, not three independent implementations |
| External Rust baseline | [`external/rust-cleanroom-jdieselny.v1.json`](external/rust-cleanroom-jdieselny.v1.json) | **16 suites / 164 vectors**, plus **359 hostility cases** (353 structured and 6 raw-parser cases) | Externally authored and time-pinned; construction evidence is not yet an independently attested strict clean-room acceptance |
| Referee / AEB-1 | A separate `AEB-1-REFEREE-MANIFEST-v1` described in [`docs/REFEREE.md`](../docs/REFEREE.md) | 13-case offline runner self-test | Not included in either corpus count; not production mediation, certification, deployment evidence, or authorization |

Do not add the Rust baseline, Referee adapters, AEB-1 cases, invariants, formal
states, fuzz cases, or ordinary unit tests to the 21-suite/332-vector total.
Each has its own manifest and claim boundary.

## Same-team JavaScript / Python / Go corpus

[`suites.mjs`](suites.mjs) is the live suite catalog. The checked-in
[`conformance-manifest.json`](conformance-manifest.json) pins every suite,
execution companion, runner, source tree, normalized result, and total.

The 21 suites cover receipts, signoffs, four-outcome resolution, quorum,
revocation, semantic and real-crypto outcome binding, Authority Document/Proof
joins, time attestations, Trust Receipt profiles, provenance, evidence records,
canonicalization, parser boundaries, AEC role acceptance, currency,
initiator attestations, consumption proofs, witnesses, and RFC 3161 timestamp
proofs.

Run all three same-team ports over the same vectors:

```sh
npm run conformance
```

Verify that the checked-in manifest still matches the catalog, vector bytes,
runners, source trees, and normalized outputs:

```sh
npm run conformance:manifest:check
```

A green run establishes agreement with the expected results for this current
corpus. It does not establish independent implementation, production
deployment, complete mediation, or fitness for a particular relying party.

## External Rust evidence

The external Rust verifier is not a fourth row in the current same-team
manifest. Its evidence is independently scoped by
[`external/rust-cleanroom-jdieselny.v1.json`](external/rust-cleanroom-jdieselny.v1.json),
which pins:

- the public source repository, commit, and tree;
- the Rust toolchain and locked build;
- the frozen 16-suite/164-vector bundle and result manifest; and
- the evaluator commit, corpus digest, workflow evidence, and 359-case hostility
  boundary.

The newer suites in the 21-suite live corpus are not attributed to Rust. The
external result is interoperability evidence over its time-pinned input set,
not a claim that Rust passed all 332 current vectors. Its implementation-signed
construction statement predates the pinned hardening commit, so
`strict_clean_room_acceptance` remains false until a qualifying independent
attestation is pinned and verified.

See [`clean-room/README.md`](clean-room/README.md) for the external intake and
runner protocol and
[`clean-room/EXTERNAL-CHALLENGE.md`](clean-room/EXTERNAL-CHALLENGE.md) for the
hostility boundary.

## Referee / AEB-1 manifests stay separate

[EMILIA Referee](../docs/REFEREE.md) is an offline AEB-1 self-test harness. It
runs one locally selected runner by absolute path and fixed arguments, verifies
the runner executable's SHA-256, exchanges one strict JSON request/result, and
emits a non-authorizing `SELF_TEST` report. Runner reports keep native
`VERIFIED`, RP `ACCEPTED`, CAID/action `MATCH`, and AEC `SATISFIED` separate.
Referee records and compares those claims; it does not perform native
verification, relying-party acceptance, mapping, or AEC composition itself.

Each AEB-1 self-test uses a separate `AEB-1-REFEREE-MANIFEST-v1` containing its
closed cases, expected results, schemas, limits, and deterministic-run policy;
the report separately records the command, executable digest, and result
digests. Referee manifests are not members of
[`conformance-manifest.json`](conformance-manifest.json) and MUST NOT increase
its 21 suites, 332 vectors, or three same-team implementation count. This also
prevents a protocol adapter from inflating the external Rust baseline.

The public consequence-boundary profile and pack are:

- [`AEB-1 Consequence Admission Conformance`](../docs/conformance/AEB-1-CONSEQUENCE-ADMISSION.md)
- [`aeb-1/`](aeb-1/)
- [`referee/schemas/`](referee/schemas/)

The public AEB-1 consequence-admission pack and the separate Referee
external-manifest self-test live under [`aeb-1/`](aeb-1/) and
[`referee/`](referee/), respectively. Neither enters the 21-suite manifest.

A passing Referee report means only that the pinned local runner matched the 13
checked-in cases under the manifest's exact limits and deterministic reruns. It
is not certification, authorization, production mediation, or proof that a
deployment completely controls every consequential action. The launcher is
no-shell and bounded, but it is not a network, syscall, filesystem, or
descendant-process sandbox. Do not expose its caller-selected executable
interface as a hosted arbitrary-code endpoint.

## Runner contract for another language

For the current cross-language corpus, a runner receives one absolute vector
file path and writes only one JSON array to stdout:

```text
runner [fixed arguments...] /absolute/path/to/vectors.json
```

```json
[
  { "id": "accept_valid", "valid": true },
  { "id": "reject_tampered", "valid": false }
]
```

The exact result shape is suite-specific. A runner must return every expected
vector ID exactly once, add no IDs, emit strict JSON without diagnostic text,
and exit nonzero on internal failure. The harness checks the complete typed
result for suites that require more than one primary verdict.

Adding a runner to the same repository does not make it independent. External
implementations should use the source-free intake in [`clean-room/`](clean-room/)
and publish their provenance and construction claims separately.

## Adding or changing a live suite

1. Add or update the language-agnostic vector file under [`vectors/`](vectors/).
2. Add it to [`suites.mjs`](suites.mjs), including an execution companion when
   public vectors intentionally omit proof material.
3. Implement the complete result contract in JavaScript, Python, and Go.
4. Run `npm run conformance`.
5. Regenerate the manifest with `npm run conformance:manifest`.
6. Run `npm run conformance:manifest:check`, `npm run check:conformance-docs`,
   and `npm run check:public-conformance-claims`.

Do not hand-edit counts. The live catalog and generated manifest are the
authoritative current sources.

## Other conformance surfaces

- [`INVARIANTS.md`](INVARIANTS.md) covers safety-invariant replay across
  JavaScript, Python, and Go. Invariant counts are not receipt-vector counts.
- [`operator2/`](operator2/) exercises a live two-operator federation path. Both
  operators are EMILIA-run, so it is not an independent-operator claim. See
  [`docs/conformance/FEDERATION-PROOF.md`](../docs/conformance/FEDERATION-PROOF.md).
- `fixtures.json`, `conformance.test.js`, and `verify_hashes.py` cover the older
  trust-scoring compatibility surface. They are not part of the current
  21-suite manifest unless named by [`suites.mjs`](suites.mjs).

## License

Apache-2.0, the same as EMILIA Protocol.
