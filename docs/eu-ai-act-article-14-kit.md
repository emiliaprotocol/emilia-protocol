# EU AI Act Article 14 Human-Oversight Engineering Kit

> **Not legal advice and not a compliance determination.** This kit helps an
> engineering team make one human-oversight control observable and
> independently testable. Whether the complete oversight design is appropriate
> and proportionate is a separate legal, operational, and risk judgment.

## The narrow problem

An Article 14 program may need to show that a natural person could understand,
monitor, disregard, override, reverse, intervene, or stop a high-risk system.
EMILIA does not provide all of those capabilities. It provides one enforceable
slice:

> For a configured consequential action, require authorization evidence from an
> enrolled person before execution, bind that evidence to the exact action, and
> retain a record an independent party can verify.

That slice is relevant to Article 14 human oversight and Article 12 logging. It
does not replace safe-state design, training, staffing, user interfaces,
automation-bias controls, documentation, or conformity assessment.

## What to define before integration

| Question | Required deployment answer |
|---|---|
| What consequence is gated? | A named action type and the material fields that distinguish one action from another |
| Who may authorize it? | A current approver roster with role and scope, bound to pinned keys |
| What assurance is required? | Software signature, Class-A WebAuthn user verification, or M-of-N distinct-human quorum |
| What policy was evaluated? | A versioned policy document and its pinned digest |
| How fresh must evidence be? | Issuance/expiry window plus current revocation or status inputs where required |
| What happens when state is unavailable? | Refuse; never fall back to the evidence that happened to be available |
| What is retained? | Receipt, refusal, execution record, log head, trust inputs, and the reporting-period export |
| What remains outside the claim? | Identity proofing, comprehension, competence, legality, safety, and system-level compliance |

## A four-week implementation

### Week 1 - Inventory and bind

1. List consequential actions.
2. Define the material fields for each action.
3. Define the human authority and separation-of-duties rule.
4. Version and hash the policy.
5. Decide what a safe refusal looks like.

### Week 2 - Observe and test

Run the Gate in observation mode. Compare proposed receipt requirements and
refusal reasons with the approved risk control. Observation produces evidence
about the proposed policy; it does not enforce it.

Required test cases:

- missing receipt;
- unpinned approver key;
- initiator self-approval;
- action substitution;
- valid signature under the wrong policy;
- stale or revoked authority;
- replay and concurrent presentation;
- unavailable consumption storage;
- execution fields that differ from the authorized fields.

### Week 3 - Enforce

Enable receipt requirements for the approved action classes. For higher-risk
actions, require Class-A WebAuthn user verification or a distinct-human quorum.
Use the durable ownership-fenced consumption store. Once an external effect is
attempted, an unknown result burns or freezes the approval; it must never
silently reopen for retry.

### Week 4 - Export and re-perform

Export:

- Trust Receipts and verification material;
- the tamper-evident Gate evidence log;
- the action-risk manifest and policy digests;
- the approver roster snapshot and revocation/status inputs;
- `EP-GATE-ART14-PACK-v1` for the reporting period;
- test output for the negative cases above.

Give the export to a party that did not operate the system and ask them to
re-run the verifier. The verifier should reach the same cryptographic result
without the issuing service.

## Re-perform the core checks

Node:

```sh
npx @emilia-protocol/verify receipt.json
```

Library verification of a full Trust Receipt:

```js
import { verifyTrustReceipt } from '@emilia-protocol/verify';

const report = verifyTrustReceipt(receipt, {
  approverKeys,
  logPublicKey,
  strict: true,
  rpId: 'approvals.example.eu',
  expectedPolicyHash: 'sha256:...',
});

if (!report.valid) throw new Error(report.errors.join('; '));
```

Python and Go ports are available for cross-language consistency. They are
same-team ports, not three independent implementations.

## Evidence properties and limits

| Evidence property | What can be established | What cannot be inferred |
|---|---|---|
| Exact-action binding | The signed Action Object matches the receipt digest | The action was wise, lawful, or safe |
| Pinned approver key | The signature verifies under the key the relying party pinned for that approver | The enrolment process correctly proved legal identity |
| Class-A WebAuthn | RP ID, challenge, signature, user presence, and user verification check | What the person perceived or understood |
| Quorum | Threshold, distinct signers/keys, ordering where declared, and initiator exclusion | Organizational independence beyond the pinned roster |
| One-time consumption | A shared atomic store accepted one presentation and refused later/concurrent use | Exactly-once physical effect outside the executor boundary |
| Evidence-log chain | Alteration or removal within the retained chain is detectable | Completeness of actions never routed through the Gate |
| Period report | Deterministic summary of the supplied verified log entries | Article 14 compliance or certification |

## Current legal timeline

The Commission's current implementation page states that rules for Annex III
high-risk systems apply from **2 December 2027**, while product-integrated
high-risk systems apply from **2 August 2028**. Transparency rules apply from
August 2026. See:
<https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai>.

## Related public artifacts

- Mechanism-neutral checklist: `docs/ART14-EVIDENCE-CHECKLIST.md`
- Evidence-capability crosswalk: `docs/compliance/EU-AI-ACT-MAPPING.md`
- Gate report: `packages/gate/reports/art14.js`
- Trust Receipt verifier: `packages/verify/index.js`
- One-time store: `packages/gate/store.js`
- Execution binding: `packages/gate/execution-binding.js`
- Human-control crosswalk: `docs/compliance/HUMAN_CONTROL_CROSSWALK.md`

The protocol texts are active individual IETF Internet-Drafts, not adopted IETF
standards or endorsements.
