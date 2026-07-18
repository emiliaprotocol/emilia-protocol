# Action Escrow product brief

## Product promise

**Both sides sign. The system obeys.**

**Your e-sign provider proves the document was signed. EMILIA makes the system
obey it.**

Action Escrow is a contractor-milestone reference experience. It joins one
final agreement, structured material terms, separate party decisions, milestone
evidence, and an external custodian's state before allowing one exact release.

It is an enforcement demonstration, not a claim that EMILIA holds money,
adjudicates workmanship, or makes a contract legally enforceable.

## Audience and scenario

- Homeowner: Maya Chen, fictional.
- Contractor: Oak & Line Builders LLC, fictional.
- Project: Lakeview kitchen renovation, fictional.
- Milestone: cabinet installation and countertop template.
- Exact release: USD 18,400.00 to the contractor's bound custodian destination.
- Retainage after release: USD 4,600.00.
- Custody: customer-selected external custodian model, simulated locally.

The experience is written for both parties, with a contractor-oriented primary
view. Each party can download the same portable evidence-package manifest and
the exact final PDF it references.

## Five separate public claims

The release-clearance UI must always show five visibly separate rows:

1. **Final document + material-term mapping verified.** The shipped
   `EP-DOCUMENT-ACTION-BINDING-v1` verifier authenticates the issuer-signed join
   among the final PDF digest, typed material terms, exact release template, and
   required party roster.
2. **Final document execution verified.** The configured e-sign adapter
   authoritatively refetches the provider record, exact final PDF bytes, and
   participant-set and version-event snapshots twice. This proves the provider
   reported the document executed; it authorizes no release.
3. **Both parties accepted the final agreement.** Separate pinned signatures
   bind the homeowner and contractor to the same final PDF bytes and current
   document-action binding; acceptance still authorizes no payment.
4. **Homeowner and contractor approved the exact release action.** Separate
   Ed25519-signed `EP-RESOLUTION-v1` artifacts bind each party to the same
   document-action binding, action digest, completion-evidence digest, amount,
   destination, and amendment version.
5. **External custodian reports funding and release state.** The demo
   uses the shipped external-custodian adapter contract with signed,
   deterministic local reports. The provider and any license reference are
   simulated and make no licensing assertion.

No row may substitute for another. A signed document is not a payment
authorization. The demo proves this boundary by presenting a valid document
acceptance as a release approval and showing the Action Escrow kernel refusal
`resolution_profile_invalid`.

## Shipped implementation path

The reference scenario imports and exercises:

- `packages/verify/document-action-binding.js`
  - `signDocumentActionBinding`
  - `verifyDocumentActionBinding`
- `packages/gate/action-escrow.js`
  - `createActionEscrowKernel`
- `packages/gate/action-escrow-verifiers.js`
  - `computeActionEscrowAgreementDigest`
  - `createActionEscrowDocumentBindingVerifier`
- `packages/gate/action-escrow-custodian.js`
  - `createActionEscrowCustodianBridge`
  - `createActionEscrowCustodianStatementVerifier`
- `packages/gate/action-escrow-state.js`
  - `signActionEscrowStateStatement`
  - `createActionEscrowStatePackageVerifier`
- `packages/gate/action-escrow-evidence.js`
  - `buildActionEscrowEvidencePackage`
  - `verifyActionEscrowEvidencePackage`
- `lib/integrations/action-escrow/acrobat-sign.js`
  - deterministic authenticated-refetch simulation
- `lib/integrations/action-escrow/licensed-custodian.js`
  - deterministic external-custodian simulation

There is no parallel receipt or Gate implementation in the example.

## Reference flow

1. Generate the final PDF and fetch those exact bytes through the simulated
   e-sign adapter.
2. Issue and verify the DAB over the PDF, typed terms, release template, pinned
   Action Escrow profile, custodian transaction, and party roster.
3. Record homeowner and contractor agreement acceptances. These make the
   agreement effective but authorize no payment.
4. Request funding and verify a signed external-custodian funding statement.
5. Verify the contractor's signed completion-evidence manifest. This proves
   artifact integrity and submitter control only.
6. Evaluate signed homeowner outcomes: approve, decline, reject, or amend.
7. Record separate homeowner and contractor approvals for the exact release.
8. Reserve and invoke the external custodian once through the shipped custodian
   bridge.
9. Authoritatively reconcile and verify the bridge's signed release-state
   observation.
10. Refuse replay from durable `released` state before another provider call.
11. Sign the exact durable state and build the portable evidence package.
12. Re-perform every package trust boundary with relying-party-pinned keys.

Every successful state compare-and-swap also appends the exact revision to the
Postgres history table atomically. Lost acknowledgements can make a caller
uncertain, but cannot leave the current state without its durable revision
record. Normal reads verify the complete contiguous journal and refuse if its
tail does not match the current state byte-for-byte.

## Outcome semantics

| Outcome | Meaning | Original release |
| --- | --- | --- |
| Approve | Accept this exact action | Eligible only with the contractor's matching approval |
| Decline | Do not release now | Closed |
| Reject | Do not accept this evidence/action | Closed |
| Amend | Propose replacement terms and a new version | Closed until a new DAB and fresh mutual acceptance |

Every outcome is signed. Only `approved` can satisfy the Action Escrow release
approval check.

## Refusal bench

The public demo mutates exactly eight facts and must show all eight refusals:

| Mutation | Shipped refusal |
| --- | --- |
| Final PDF byte | `document_digest_mismatch` |
| Structured material term | `binding_digest_mismatch` |
| Destination/payee | `action_digest_mismatch` |
| Amount | `action_digest_mismatch` |
| Signer seat | `resolution_verification_refused` |
| Milestone evidence | `milestone_evidence_invalid` |
| Amendment version | `action_digest_mismatch` |
| Replay | `release_already_applied` |

The custodian adapter's release method must be called exactly once.

Cancellation and amendment are deliberately blocked as soon as a funding
request enters the custodian boundary. A missing local funding statement cannot
prove that an external transfer did not arrive. The kernel therefore refuses
both until a separately authenticated no-funds result or completed custodian
unwind/refund/rebind action is implemented.
`completed` means administrative archival only; it requires an authenticated
state command and makes no workmanship, acceptance, or waiver claim.

## Portable evidence

The JSON download is the output of
`buildActionEscrowEvidencePackage`, not a demo-specific wrapper. It includes:

- the DAB;
- final PDF digest, byte length, media type, and file name;
- the provider-neutral document-execution claim;
- distinct homeowner and contractor agreement acceptances that carry no
  release authority;
- both exact release approvals;
- signed funding and release statements;
- milestone evidence;
- release reservation, provider request, and execution record;
- the exact durable state snapshot and operator-signed state statement;
- verification-profile reference;
- package digest and explicit limitations.

The PDF bytes are intentionally not embedded. The final PDF is downloaded
beside the JSON and joined by its exact byte digest. Package verification
requires relying-party-owned trust roots and re-runs each component verifier;
the package digest alone does not make an invalid component trustworthy.

## Provider claims

The hero remains provider-neutral. Adobe Acrobat Sign may appear only lower in
the experience as a clearly labeled simulated adapter. The demo has no Adobe
partnership, endorsement, credential, or live API call.

The custodian is likewise a simulated model. Copy must not imply that the named
fictional provider is licensed, solvent, connected, or fit for a real
transaction.

## Non-claims

Action Escrow does not establish:

- contract enforceability, comprehension, voluntariness, or legal compliance;
- signer identity beyond control of pinned demo keys;
- workmanship, physical completion, or truth of submitted evidence;
- custodian licensing, solvency, or non-bypassability;
- that EMILIA holds, transmits, settles, or controls money.

The reference proves cryptographic and state-machine behavior inside the
demonstrated release boundary only.
