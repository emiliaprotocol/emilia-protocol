<!-- SPDX-License-Identifier: Apache-2.0 -->

# AEB-05 candidate section: closed origin-label assertions

STATUS: candidate text, not filed. AEB-04 was published on 2026-08-16 and
already defines the generic field-origin assertion input. This file proposes
additional closed-vocabulary, trust-floor, and laundering semantics for a
possible `draft-schrock-action-evidence-boundary-05`. No -05 submission has
been made. A published individual Internet-Draft is not an RFC, working-group
adoption, IETF consensus, or IETF endorsement; this file is not even that yet.

Working implementation and vectors backing every normative statement below:

- `packages/gate/src/field-origin-evidence.ts` (`EP-ORIGIN-LABELS-v1`
  vocabulary, `evaluateOriginLabelAssertions`, `originLabelTrustFloor`)
- `conformance/origin-labels/vectors.json` (hostile label-laundering vector
  set, benign controls, and the stated-residual case)

---

## Proposed section: Closed Origin-Label Assertions

### X.1. The input, not a format

A field-origin assertion set is an optional native artifact that a
producer on the proposal path presents to the effect boundary. It claims,
for each material field of the observed action, where the exact value came
from. Consistent with Section 1.1, AEB does not define a new
execution-evidence format here, and this section does not add one: any
assertion format is admissible whose native verifier establishes the
following closed contract for the integrity-protected payload:

- a per-path origin label drawn from one relying-party-pinned closed label
  vocabulary, identified by an explicit vocabulary version;
- for every label that designates a computed, summarized, extracted, or
  reformatted value, the set of source label classes it was produced from
  (its derivation sources); and
- a producer signature over the complete assertion set, verified under
  relying-party-selected trust inputs, binding the assertions to the exact
  observed action.

The vocabulary, the producer trust anchors, and the per-path minimum
labels are relying-party pins in the sense of Section 4. A label,
vocabulary identifier, or minimum carried only in presenter-controlled
data MUST NOT become its own trust anchor.

### X.2. Closed vocabulary requirement

The pinned vocabulary MUST be a closed set. An assertion using a label
outside the pinned set MUST be refused with a path-precise reason, not
mapped to a nearest neighbor and not ignored. A conforming vocabulary
MUST distinguish at least: values stated by the accountable human
principal; values from operator-pinned configuration; values from an
identified counterparty document; values retrieved from uncontrolled
sources; values produced by model inference alone; and derived values.

`EP-ORIGIN-LABELS-v1` (`user-stated`, `operator-config`,
`counterparty-document`, `retrieved-untrusted`, `model-generated`,
`derived`, with the trust order `operator-config` > `user-stated` >
`counterparty-document` > `model-generated` > `retrieved-untrusted`) is
one such vocabulary. It is cited here informatively, not required.

### X.3. Taint-preserving trust floor

The boundary MUST evaluate each assertion to an effective trust floor
under the pinned vocabulary's trust order:

- a non-derived label is its own floor;
- a derived value's floor is the LEAST-trusted label in its derivation
  set; and
- no transform upgrades a label: summarization, reformatting, extraction,
  or model processing of retrieved-untrusted material yields a value whose
  floor remains retrieved-untrusted.

A derived assertion that omits its derivation sources MUST be refused; an
absent derivation set is INDETERMINATE, and INDETERMINATE never admits.
The relying party pins a minimum label per material path; an effective
floor below the pinned minimum MUST be refused with a path-precise
reason before invocation.

### X.4. Internal-consistency checks

Before policy evaluation, the boundary MUST refuse an assertion set that
is internally inconsistent: the same path asserted under conflicting
labels, or, where the format carries per-value digests, the same exact
value bytes asserted under labels with different effective floors. These
checks catch a producer pipeline that launders a label while its own
earlier assertions contradict the laundered claim.

### X.5. Claim boundary and stated residuals

Origin labels are claims by the asserting producer. The effect boundary
verifies that the claims are internally consistent and satisfy the pinned
policy at admission; it does not and cannot verify that the producer told
the truth. That accountability belongs to the producer signature over the
assertion set, not to the label system. In particular:

- a producer that lies consistently, asserting a trusted label for a value
  it retrieved and never contradicting itself, is not detectable at this
  boundary;
- renamed-value laundering is not detectable: a value altered by even one
  byte carries a different digest, so digest-equality checks cannot link
  it to its untrusted source; and
- field-origin assertions are not prompt-injection detection, source
  truth, authorization, or effect truth, and satisfying this input alone
  MUST NOT cause SATISFIED, AUTHORIZED, reservation, or invocation.

A deployment claiming this input MUST state which of these residuals
apply unmitigated. Claiming coverage of renamed-value laundering is a
false claim under this section.

### X.6. EP-FIELD-ORIGIN-v0.1 as an informative profile

`EP-FIELD-ORIGIN-v0.1` (the signed per-field provenance artifact
implemented in `packages/gate/src/field-origin-evidence.ts`) is one
implementation profile of this input, cited informatively. Its origin
classes map onto `EP-ORIGIN-LABELS-v1` as `operator_pinned` to
`operator-config`, `approver_supplied` to `user-stated`,
`untrusted_bounded` to `retrieved-untrusted`, and
`derived_via_versioned_transform` to `derived`; its `unknown` class never
admits in either system. The profile additionally binds each assertion to
the exact action digest, pins per-field snapshot freshness, and pins
versioned transforms. Nothing in AEB requires that profile: a deployment
satisfies this section with any format meeting the closed contract in
X.1, exactly as other native inputs satisfy their slots under their own
specifications.

---

## Honest boundaries of this candidate text

- This file is candidate prose only. AEB-04 is public; this narrower extension
  is not part of it. No -05 revision exists on the Datatracker, and no filing
  decision is made here.
- The implementation evidence is same-team reference code and vectors in
  this repository, not an independent implementation or reproduction.
- The laundering vector set demonstrates refusal of the enumerated
  detectable shapes and admission of benign controls. It does not
  demonstrate detection of consistent producer lies or renamed-value
  laundering; those are stated residuals by design.
