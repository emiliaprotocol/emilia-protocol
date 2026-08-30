# EMILIA × CCS composition example

This directory contains an **interoperability example contributed by the EMILIA
project** (Iman Schrock). It shows how a CCS v1.4
conformance receipt is consumed as **pre-admission machine-policy evidence** by
an AEB-style gate, then bound to one executor-owned action and one relying-party
admission domain.

## Provenance

The two JSON files here are byte-identical copies from the EMILIA standalone
composition harness, commit
[`995d803`](https://github.com/emiliaprotocol/emilia-protocol/commit/995d80367f99601bb16509c6c89a5f9e72c74885),
directory `conformance/composition/ccs-v14-aeb-github-v0.1/`:

| file | sha256 | role |
|---|---|---|
| `vectors.reference.json` | `3f61bc9eb2ce3d2d1e6a771aa94d2be1cfb964eac93babe3c5334f883ab72cd7` | The proposed examples fixture: the pinned CCS ALLOW receipt, the exact GitHub `issue-update` action, its CAID, relying party, and provider |
| `upstream-01-allow.receipt.json` | `889855dc9fcebdb642bd7e0f369651015781b4c004227aef510feb1fb7cb4361` | The upstream CCS v1.4 conformance `01-allow` receipt this composition pins |

The harness itself (`run.standalone.mjs`, Node >= 20.19, Node built-ins only)
lives in the EMILIA repository at the commit above. It is not vendored here;
fetch it from the pinned commit to reproduce the eight composition cases.

## What the fixture demonstrates

The runner exercises eight deterministic cases:

1. the pinned public vector verifies (valid Ed25519 over the JCS signing input);
2. the valid composition — CCS ALLOW plus a separate EMILIA authority decision —
   enters the counting provider exactly once;
3. receipt tampering is refused;
4. the wrong relying party is refused;
5. a stale status is refused;
6. action substitution (issue 538 → 539) is refused;
7. a CCS ALLOW with no EMILIA authority is refused (zero provider entries);
8. a lost provider response returns `INDETERMINATE` and blocks blind retry.

## Boundaries (authoritative)

- **The GitHub-shaped receipt in `emilia_github_fixture` is an EMILIA-authored
  compatible fixture, not a Correctover certification or a Correctover-issued
  upstream vector.** It is source-compatible with the CCS v1.4 receipt shape.
- A CCS ALLOW receipt is **machine-policy evidence only**. It is not execution
  authority and does not by itself prove what the provider ultimately executed.
  Provider entry additionally requires a current AEB evaluation for the exact
  action and a separate relying-party authorization decision.
- Both receipts use the **public deterministic conformance key**
  (fingerprint `26a02d86f5d0a10f`). It is test material, not a production trust
  root, and MUST NOT be trusted or reused outside conformance fixtures.
- The provider in the harness is a counting test stub; no live GitHub issue or
  external account is changed.

## Independent verification

The upstream receipt is a 30-field CCS L1 receipt signed with Ed25519 over the
JCS (JSON Canonicalization Scheme) canonicalization of the 29 unsigned fields (1221-byte signing
input). Any standard-library + Ed25519 + JCS verifier can validate it without
importing CCS code. The Correctover check used here is a **standalone
package-independent** checker that operates **without importing the CCS
verifier package**. The standalone package-independent conformance checker
([`checkers/independent_checker.py`](https://github.com/DSHCorrectover/ccs-conformance-vectors/blob/a3503b2bc48922f92a28c372003885a0831da02b/checkers/independent_checker.py),
MIT license; Python standard library plus `cryptography` and `jcs` only, and
it operates **without importing the CCS verifier package**) lives
in the pinned CCS bundle repository at bundle commit [`a3503b2`](https://github.com/DSHCorrectover/ccs-conformance-vectors/commit/a3503b2bc48922f92a28c372003885a0831da02b),
not in this repository. It independently verifies the pinned bundle.
