<!-- SPDX-License-Identifier: Apache-2.0 -->

# ORIGIN-LABELS-v1 conformance pack

This directory is the stable entry point for the `EP-ORIGIN-LABELS-v1`
origin-label vocabulary: a closed label set with explicit taint-preserving
propagation rules and a hostile label-laundering vector set. It is the
conformance bar for information-flow evidence at the admission boundary.

- Vectors: [`vectors.json`](vectors.json)
- Implementation: [`packages/gate/src/field-origin-evidence.ts`](../../packages/gate/src/field-origin-evidence.ts)
  (`evaluateOriginLabelAssertions`, `originLabelTrustFloor`)
- Tests: [`packages/gate/field-origin-evidence.test.ts`](../../packages/gate/field-origin-evidence.test.ts)
  (vector-driven; every case in `vectors.json` is executed)

Run the vector suite through the gate test file:

```sh
cd packages/gate
npx tsx --test field-origin-evidence.test.ts
```

## The closed vocabulary

Six labels. An assertion using any other label is refused
`unknown_origin_label:<path>`.

| Label | Definition |
| --- | --- |
| `user-stated` | The exact value was entered or spoken for this action by the accountable human principal, over a channel the producer attributes to that principal. |
| `operator-config` | The exact value was read from configuration pinned by the operating organization before this action was proposed, not from any per-action input. |
| `counterparty-document` | The exact value was taken from a document or message authored by an identified external counterparty to this transaction, such as an invoice or contract. |
| `retrieved-untrusted` | The exact value was obtained from content the producer retrieved from a source it neither controls nor treats as an identified counterparty, such as a web page, search result, inbound message body, or output of an uncontrolled tool. |
| `model-generated` | The exact value was produced by model inference from the model parameters alone; a value produced from any per-action source material is derived, not model-generated. |
| `derived` | The exact value was computed, summarized, extracted, reformatted, or otherwise produced from one or more source values, and the assertion carries `derived_from` naming the base label class of every contributing source. |

Trust order, most trusted first (used for policy floors and derivation
floors; `derived` has no rank of its own):

`operator-config` > `user-stated` > `counterparty-document` >
`model-generated` > `retrieved-untrusted`

## Propagation rule (taint-preserving)

- `derived` MUST carry `derived_from` listing the base label class of every
  contributing source. Missing or empty: refused
  `derivation_unspecified:<path>`. A `derived_from` entry outside the five
  base classes (including a nested `derived`): refused
  `derivation_source_invalid:<path>`.
- The effective trust floor of a derived value is the LEAST-trusted label in
  its derivation set. Summarization, reformatting, extraction, or any other
  transform NEVER upgrades a label.
- The same path asserted twice with conflicting content is refused
  `origin_conflict:<path>`; an exact duplicate is refused
  `duplicate_origin_assertion:<path>`.
- The same exact value bytes (equal `value_digest`) asserted under labels
  with different effective floors is refused `value_origin_conflict:<path>`,
  naming the upgraded path.
- A policy rule whose path has no assertion is refused
  `origin_unasserted:<path>`; a floor below the rule's `minimum_label` is
  refused `origin_trust_floor_violation:<path>`.
- Fail-closed means a structured refusal with a named reason.
  `evaluateOriginLabelAssertions` never throws on hostile input, and
  INDETERMINATE never admits.

## Enforced versus stated residual

Enforced by the vectors in this pack:

- (a) a summary of retrieved-untrusted content re-asserted as `derived`
  without `derived_from`: `derivation_unspecified:<path>`;
- (b) a derivation-set laundering attempt whose pipeline also re-asserts the
  source path under a conflicting label: `origin_conflict:<path>`;
- (c) a derived floor of `retrieved-untrusted` against a policy minimum of
  `operator-config`: `origin_trust_floor_violation:<path>`;
- (d, byte-identical form) a value copied byte-for-byte to a path with a
  more-trusted label, when the producer supplies value digests:
  `value_origin_conflict:<path>`;
- (e) benign controls: correct pipelines, including derivations at the exact
  policy boundary, admit.

Stated residuals, deliberately NOT claimed as covered:

- Renamed-value laundering. A value altered by even one byte (rephrased,
  reformatted, re-encoded) carries a different digest, so the vocabulary
  structurally cannot link it to its untrusted source. The
  `residual-renamed-value-laundering-not-detectable` vector admits and is
  kept in the suite so the boundary stays visible.
- Value-consistency checking only runs where the producer supplies
  `value_digest`; assertions with a null digest opt out of it.
- Distinct fields can legitimately hold byte-identical low-entropy values
  (for example a shared currency code) under different labels; with digests
  supplied, such a set is refused as a conflict. Producers avoid this by
  omitting digests on low-entropy fields or asserting the copy as `derived`.
- A consistent lie. Labels are CLAIMS by the asserting producer, verified
  as internally consistent and policy-satisfying at admission; the boundary
  does not and cannot verify the producer told the truth. That is the
  producer signature's accountability, not the label system's.

## Relationship to EP-FIELD-ORIGIN-v0.1

The shipped `EP-FIELD-ORIGIN-v0.1` artifact and verifier are unchanged.
Its origin classes map onto this vocabulary through the informative
`ORIGIN_LABELS_V01_PROFILE_MAP` (`operator_pinned` to `operator-config`,
`approver_supplied` to `user-stated`, `untrusted_bounded` to
`retrieved-untrusted`, `derived_via_versioned_transform` to `derived`;
v0.1 `unknown` never admits in either system). That map is informative
only and changes no v0.1 verification behavior.

A green run is self-attested conformance evidence. It is not independent
certification, a production-deployment claim, proof of asserted origin
truth, prompt-injection detection, or authorization for any action.
