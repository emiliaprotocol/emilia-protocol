<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-ASSURANCE-PACKAGE-v1

**The reliance assurance layer. Not "can this action rely?" but "can an independent assurer reproduce, test, and attest that an organization's automated actions were governed by admissible evidence under its own pinned rule?"**

The reliance kernel decides one action. The assurance package is what an audit
firm, a regulator, or an insurer takes to independently re-perform a whole
population of automated decisions. It is EY-shaped: the missing machine-verifiable
evidence substrate under "transferable confidence."

## Two halves

**`buildAssurancePackage(decisions, { profile, organization, now })`** — the
organization bundles its automated reliance decisions and the evidence each relied
on into ONE portable, content-addressed package: for each decision the action,
receipt, quorum, authority proof, revocation state, and consumption evidence, plus
the pinned `EP-RELIANCE-PROFILE-v1`, its `profile_hash`, the control catalog, and
the denial/exception history the runtime recorded. The package carries the verdict
the runtime CLAIMED (`stated_verdict`) so drift is checkable later. A
`package_digest` content-addresses everything except the timestamp.

**`reperformAssurancePackage(pkg, { approverKeys, logPublicKey, ... })`** — the
assurer RE-PERFORMS every reliance verdict offline from that evidence, under the
package's pinned profile and its OWN out-of-band keys, **trusting nothing the
package asserts**. It recomputes each verdict with the reliance kernel, compares
to the stated verdict (drift), maps each to a control objective, and emits an
`EP-ASSURANCE-REPERFORMANCE-v1` workpaper. A second assurer with the same package
and keys reproduces the `reperformance_digest` byte for byte.

## Drift is the material finding

The point of independent re-performance is to catch a runtime that claimed it
could rely on evidence that does not support reliance:

- `stated_verdict = rely` but recomputed `do_not_rely_*` →
  `drift_severity: relied_on_inadmissible_evidence`. The organization acted on
  evidence that fails its own rule. This is the finding an auditor exists to make.
- `stated_verdict` a refusal that recomputes differently →
  `refused_admissible_or_reclassified`.

## Control objective mapping

Every reliance verdict maps to a control objective (`RELIANCE_CONTROL_CATALOG`,
`RC-1`…`RC-6`). A `rely` shows the control passing; every `do_not_rely_*` shows
the control OPERATING (it refused a non-admissible action). **Denials are the
control working**, mirroring the auditor-workpaper's refusal treatment.

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
gives an assurer a cryptographic source, an immutable content-addressed decision
trail, a reproducible pinned rule, and direct re-performance of the verdict.

## `ep-assure` CLI

```
node packages/gate/ep-assure.mjs <input.json> [--json] [--strict]
```

`input.json` carries a `package` (or raw `decisions` + `profile`) plus
auditor-pinned `keys`. It prints the workpaper (or the full document with
`--json`) and exits non-zero when it finds a decision that relied on inadmissible
evidence (`--strict`: on any drift), so it drops into an audit or CI pipeline.

## Conformance

`tests/assurance-package.test.ts`: bundling, the drift catch (a runtime claiming
`rely` over an over-ceiling authorization is caught), deterministic
re-performance, null-conclusion enforcement, and full verdict→control coverage.
`examples/reliance/ey-continuous-assurance.mjs` runs the end-to-end story over a
synthetic month of prior-auth decisions.
