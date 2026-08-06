<!-- SPDX-License-Identifier: Apache-2.0 -->
# CAID → AEC → AEB → Capsule composition vector

This directory is the executable first profile promised in the CAID/AEC/AEB
and Agent Action Capsule composition discussion. It upgrades the earlier
WHO→WHAT digest seam into one attempt-scoped result with seven independent
axes:

`native_results[] / action_linkage / principal_linkage / evidence_satisfaction / decision / admission / outcome`

Run it with:

```bash
node examples/composition/caid-aec-aeb-capsule-v1/run.mjs
```

Regenerate the frozen candidate bytes with:

```bash
node examples/composition/caid-aec-aeb-capsule-v1/run.mjs --emit
(cd examples/composition/caid-aec-aeb-capsule-v1 && shasum -a 256 -c CHECKSUMS.sha256)
```

## What executes

- CAID is recomputed with the repository's `payment.release.1` definition.
- AEC runs the real `verifyAuthorizationChain()` implementation with a
  relying-party-pinned human-plus-machine-policy requirement.
- AEB runs the governed `evaluateAebConsequenceCase()` kernel.
- Capsule statements are deterministic COSE_Sign1 objects. The independent
  EMILIA candidate verifier checks the public `-00` Class-1 invariants used by
  these fixtures and returns structured findings.
- Class 2 remains `NOT_EVALUATED` because the producer's private constraint
  manifest and bound private evidence are intentionally absent.

## Eight attempts

1. Exact action, satisfied evidence, one consumed invocation, observed result.
2. Different-action splice, refused before admission.
3. Cryptographically valid but stale evidence, AEC unsatisfied.
4. Second attempt after consumption, refused as already consumed.
5. Timeout before dispatch, no invocation and outcome `NONE`.
6. Timeout after dispatch, authority consumed and outcome `INDETERMINATE`.
7. Capsule runtime claim contradicted by an independent observer, preserved as
   `DIVERGENT` rather than overwritten.
8. Unknown required binding, returned as a structured refusal rather than a
   pass, thrown exception, or crash.

## Files

- `manifest.json` pins every draft revision, source parent, and implementation
  file digest.
- `bundle.json` is the frozen input and expected-result bundle.
- `report.emilia-js.json` is EMILIA's reproducible run report.
- `external-report.template.json` is the exact slot for a second independent
  Capsule/Composition implementation report.
- `CHECKSUMS.sha256` freezes the generated handoff bytes.

## Claim boundary

This is a candidate, same-team composition vector. It proves that the EMILIA
implementation produces the frozen results and that the bounded Capsule
Class-1 checks execute independently of AEC/AEB. It is not general Capsule
conformance and not independent interoperability. The candidate freezes only
after a second implementation reproduces the exact bundle and returns the
completed external report.
