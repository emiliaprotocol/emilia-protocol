<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-ASSURANCE-PACKAGE-v1

**The reliance assurance layer. Not "can this action rely?" but "what does an
independent re-performance find in this supplied decision set under the expected
rule and trust roots?"**

The reliance kernel decides one action. The assurance package is what an audit
firm, a regulator, or an insurer takes to independently re-perform a supplied
set of automated decisions. It supplies a machine-verifiable evidence substrate
for independent re-performance. It does not prove that the set is the complete
production population unless coverage is anchored separately.

## Two halves

**`buildAssurancePackage(decisions, { profile, organization, now })`** — the
organization bundles its automated reliance decisions and the evidence each relied
on into ONE portable, content-addressed package: for each decision the action,
receipt, quorum, authority proof, revocation state, and consumption evidence, plus
the pinned `EP-RELIANCE-PROFILE-v1`, its `profile_hash`, the control catalog, and
the denial/exception history the runtime recorded. The package carries the verdict
the runtime CLAIMED (`stated_verdict`) so drift is checkable later. A
`package_digest` content-addresses everything except the timestamp.

**`reperformAssurancePackage(pkg, { approverKeys, logPublicKey,
expectedPackageDigest, expectedProfileHash, ... })`** — the
assurer RE-PERFORMS every reliance verdict offline from that evidence, under the
presented profile and its OWN out-of-band keys. It recomputes both the package
digest and the profile hash, recomputes each verdict with the reliance kernel,
compares to the stated verdict (drift), maps each to a control objective, and
emits an `EP-ASSURANCE-REPERFORMANCE-v1` workpaper. An assurer supplies
`expectedPackageDigest` and `expectedProfileHash` from an independent source when
it needs to establish that the presented package and rule are the ones it meant
to test. Without an out-of-band profile pin, re-performance tests the rule in the
package but does not establish that the organization authorized that rule. A
second assurer with the same package, pins, and keys reproduces the
`reperformance_digest` byte for byte.

## Drift is the material finding

The point of independent re-performance is to catch a runtime that claimed it
could rely on evidence that does not support reliance:

- `stated_verdict = rely` but recomputed `do_not_rely_*` →
  `drift_severity: relied_on_inadmissible_evidence`. The organization acted on
  evidence that fails the presented rule. This is a material exception for the
  assurer to investigate; the package alone does not prove the action occurred.
- `stated_verdict` a refusal that recomputes differently →
  `refused_admissible_or_reclassified`.

## Control objective mapping

Every reliance verdict maps to a control objective (`RELIANCE_CONTROL_CATALOG`,
`RC-1`…`RC-6`). A recomputed `rely` means the presented evidence satisfied the
presented profile. A recomputed `do_not_rely_*` identifies the control objective
that caused the offline refusal. Neither result alone proves how the live runtime
behaved.

| Control | Objective |
|---|---|
| RC-1 | Only a human with valid scoped authority for THIS exact action may authorize it |
| RC-2 | Authorization uses a device-bound named-human ceremony (Class-A or quorum) |
| RC-3 | The action conforms to a pinned, accepted policy |
| RC-4 | Authorization is consumed exactly once (no replay) |
| RC-5 | Reliance is evaluated against fresh revocation state |
| RC-6 | Evidence is signed by a trusted issuer and evaluated under a pinned rule |

## It supports; it never concludes

Like `reperform.js`, this is **support for an audit re-performance procedure**. The
`conclusion` fields (`supportable`, `opinion`, `signed_off_by`) are ALWAYS null and
`renderAssuranceWorkpaper` refuses to print a filled conclusion. The honesty block
states what re-performance does NOT establish: completeness of the decision
population, runtime freshness at the moment of decision, key custody or identity
proofing, and the business wisdom of any authorized action. **The auditor
concludes; the tool only recomputes.**

## PCAOB AS 1105 alignment

Audit evidence must be sufficient and appropriate; reliability turns on source,
controls, directness, and whether electronic information was modified. The package
gives an assurer content-addressed package bytes, explicit evidence inputs, a
reproducible presented rule, and direct re-performance of the verdict. An
out-of-band package/profile pin makes later mutation detectable. Immutability,
population completeness, source authenticity, and live operating effectiveness
require their own evidence and procedures.

## `ep-assure` CLI

```
node packages/gate/ep-assure.mjs <input.json> [--json] [--strict]
```

`input.json` carries a `package` (or raw `decisions` + `profile`) plus
auditor-pinned `keys`. It may also carry `expected_package_digest` and
`expected_profile_hash`, obtained out of band. It prints the workpaper (or the
full document with `--json`) and always exits non-zero when internal package or
profile integrity fails, or when either supplied out-of-band pin does not match.
For an intact package it also exits non-zero when it finds a
decision that relied on inadmissible evidence (`--strict`: on any drift), so it
drops into an audit or CI pipeline.

## Conformance

`tests/assurance-package.test.ts`: bundling, the drift catch (a runtime claiming
`rely` over an over-ceiling authorization is caught), deterministic
re-performance, null-conclusion enforcement, and full verdict→control coverage.
`examples/reliance/synthetic-continuous-assurance.mjs` runs an unaffiliated,
fully synthetic end-to-end story over a month of prior-auth decisions. No audit
firm participation, endorsement, audit opinion, or operating-effectiveness
conclusion is claimed.
