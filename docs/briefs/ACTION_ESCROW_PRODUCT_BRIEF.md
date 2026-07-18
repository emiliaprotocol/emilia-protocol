# Action Escrow product brief

## Product promise

**Both sides sign. The system obeys.**

**Your e-sign provider proves the document was signed. EMILIA makes the system
obey it.**

Action Escrow is a contractor-milestone reference experience. It joins one
project-system change-order snapshot, one final agreement, structured material
terms, separate party decisions, milestone evidence, and an external
custodian's state before allowing one exact release.

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

## Six separate public claims

The release-clearance UI must always show six visibly separate rows:

1. **Project change-order source verified.** The read-only project-system
   adapter authenticates to the provider, refetches the complete structured
   change order and line-item set twice, and refuses an incomplete or changing
   view. The source record establishes neither acceptance nor release
   authority.
2. **Final document + material-term mapping verified.** The shipped
   `EP-DOCUMENT-ACTION-BINDING-v1` verifier authenticates the issuer-signed join
   among the final PDF digest, typed material terms, exact release template, and
   required party roster. The exact release template includes the project
   snapshot digest.
3. **Final document execution verified.** The configured e-sign adapter
   authoritatively refetches the provider record, exact final PDF bytes, and
   participant-set and version-event snapshots twice. This proves the provider
   reported the document executed; it authorizes no release.
4. **Both parties accepted the final agreement.** Separate pinned signatures
   bind the homeowner and contractor to the same final PDF bytes and current
   document-action binding; acceptance still authorizes no payment.
5. **Homeowner and contractor approved the exact release action.** Separate
   P-256 WebAuthn-shaped `EP-RESOLUTION-v1` artifacts bind each party to the same
   document-action binding, action digest, completion-evidence digest, amount,
   destination, and amendment version.
6. **External custodian reports funding and release state.** The demo
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
- `lib/integrations/action-escrow/procore-change-order.js`
  - read-only complete-view and stable-snapshot enforcement
- `lib/integrations/action-escrow/licensed-custodian.js`
  - deterministic external-custodian simulation

There is no parallel receipt or Gate implementation in the example.

## Reference flow

1. Refetch one complete, stable project change-order snapshot through the
   read-only simulated Procore adapter.
2. Generate the final PDF and fetch those exact bytes through the simulated
   e-sign adapter.
3. Issue and verify the DAB over the PDF, typed terms, project snapshot digest,
   release template, pinned Action Escrow profile, custodian transaction, and
   party roster.
4. Record homeowner and contractor agreement acceptances. These make the
   agreement effective but authorize no payment.
5. Request funding and verify a signed external-custodian funding statement.
6. Verify the contractor's signed completion-evidence manifest. This proves
   artifact integrity and submitter control only.
7. Evaluate signed homeowner outcomes: approve, decline, reject, or amend.
8. Record separate homeowner and contractor approvals for the exact release.
9. Reserve and invoke the external custodian once through the shipped custodian
   bridge.
10. Authoritatively reconcile and verify the bridge's signed release-state
   observation.
11. Refuse replay from durable `released` state before another provider call.
12. Sign the exact durable state and build the portable evidence package.
13. Re-perform every package trust boundary with relying-party-pinned keys.

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

The public demo mutates exactly nine facts and must show all nine refusals:

| Mutation | Shipped refusal |
| --- | --- |
| Final PDF byte | `document_digest_mismatch` |
| Structured material term | `binding_digest_mismatch` |
| Destination/payee | `action_digest_mismatch` |
| Amount | `action_digest_mismatch` |
| Signer seat | `resolution_verification_refused` |
| Milestone evidence | `milestone_evidence_invalid` |
| Amendment version | `action_digest_mismatch` |
| Project source snapshot | `action_digest_mismatch` |
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
`assembleActionEscrowEvidencePackage`, not a demo-specific wrapper. It includes:

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

The PDF bytes and project source record are intentionally not embedded. They
are downloaded beside the JSON. The PDF is joined by its exact byte digest, and
the DAB's exact action template binds the project-record snapshot digest.
Package verification requires relying-party-owned trust roots and re-runs each
component verifier; the package digest alone does not make an invalid component
trustworthy.

## Provider claims

The hero remains provider-neutral. Procore and Adobe Acrobat Sign may appear
only lower in the experience as clearly labeled simulated adapters. The demo
has no provider partnership, endorsement, credential, or live API call.

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
