# AE-CHALLENGE Transport-Neutral Evidence Negotiation

Runnable interop demo for one claim: AE-CHALLENGE is transport-neutral
evidence negotiation. OAuth transaction authorization can be one admissible
presentation profile, and the same negotiation model can also consume
independently verifiable evidence obtained outside OAuth. In one line: OAuth
and others, not others instead of OAuth.

```bash
node examples/ae-transport-neutral-v1/demo.mjs
node --test examples/ae-transport-neutral-v1/demo.test.mjs
```

No dependencies beyond Node and this repository.

## The thesis, concretely

A single relying party refuses one exact consequential action (a USD 2,500.00
payment initiation) with one `AE-CHALLENGE-v1` object carried in an RFC 9457
Problem Details response. The challenge names the missing evidence
requirement, the action digest the server computed, the audience, and the
presentation methods the relying party consumes. Then the SAME challenge
shape is satisfied through two independent evidence forms, evaluated by the
SAME relying-party evaluator:

1. **OAuth path.** A transaction-bound access token whose RFC 9396
   `authorization_details` describe the exact action, paired with the
   protected resource's transaction challenge, in the shape defined by
   `draft-rosomakho-oauth-txn-challenge-00`. Native verification is the
   repository's existing adapter
   (`packages/verify/src/aeb-oauth-transaction-challenge-adapter.ts`): JWT
   signatures against pinned keys, transaction binding, audience, lifetimes,
   and a relying-party-pinned `authorization_details` verifier.
2. **Non-OAuth path.** A human-key-signed EP authorization receipt (Ed25519,
   issued by `packages/issue`, verified by `packages/verify`) bound to the
   same action object. No authorization server participates in this leg. It
   is a portable, offline-verifiable signature by an enrolled human approver
   key over the exact action content.

For each path the evaluator, in order: rederives the action digest and CAID
from the action it is about to execute (a presented digest is never
trusted), verifies the evidence under that form's own native rules, confirms
the evidence denotes the same action by recomputing the CAID from the signed
content, checks the audience binding, and then uses a downstream AEB/Gate
store to admit at most one provider entry under the local authority state.
That admission step is composition outside AE-CHALLENGE. The three outcomes stay
distinct: ADMIT, REFUSE, and INDETERMINATE are never collapsed into one
"verified" flag.

## What each case proves

| Case | Outcome | What it proves |
| --- | --- | --- |
| `admit-oauth-evidence-for-action-a` | ADMIT | OAuth transaction authorization satisfies the challenge. OAuth is a first-class evidence form, not a competitor. |
| `admit-human-receipt-for-action-a` | ADMIT | The same evaluator admits human-key evidence with no authorization server in the loop. The negotiation layer is transport-neutral. |
| `refuse-oauth-token-for-different-action` | REFUSE | A token issued for action B cannot execute action A. The granted `authorization_details` recompute to a different CAID than the action about to run. |
| `refuse-receipt-replay-after-consume` | REFUSE | Downstream admission state blocks reuse after commit. Replaying the receipt against a fresh challenge hits the consumed reservation. |
| `refuse-evidence-for-wrong-audience` | REFUSE | An access token whose audience names another relying party fails native verification. |
| `refuse-challenge-bound-to-other-audience` | REFUSE | The challenge is bound to its expected presenter; otherwise-valid evidence cannot rescue a challenge minted for a different presenter. |
| `refuse-oauth-when-policy-requires-human-key` | REFUSE | The load-bearing case. The relying party's policy admits only human-key evidence, so a perfectly valid AS-issued token is refused before it is parsed. The relying party, not the authorization server, decides which evidence forms count. |
| `indeterminate-when-effect-response-lost` | INDETERMINATE | The effect ran but its response was lost. The evaluator reports the truth (unknown) and holds the reservation instead of releasing the authority. |
| `indeterminate-blind-retry-not-reexecuted` | INDETERMINATE | A blind retry with the same evidence does not re-execute the effect. The unresolved reservation forces reconciliation; the effect count stays at one. |

## Relationship to draft-rosomakho-oauth-txn-challenge

This demo composes with the OAuth transaction challenge draft; it does not
replace it. The OAuth leg is consumed in the shape that draft defines: the
protected resource's challenge JWT plus the AS-issued transaction-bound
access token, verified as a pair. AE-CHALLENGE sits at a different layer. It
is the relying party's machine-readable statement of what evidence is
missing and which forms it will accept, and one of those forms can be the
output of the OAuth transaction challenge flow. Where the deployment's
native protocol already requires OAuth transaction authorization, that
requirement stands, and the AE challenge identifier and nonce remain
separate from the OAuth `txn`. The routing guard in
`lib/negotiate/evidence-challenge.ts`
(`selectAuthorizationChallengeMechanism`) makes substitution explicitly
unavailable.

The routing rule is intentionally asymmetric:

- If native OAuth transaction authorization is the only missing requirement,
  the protected resource uses the OAuth transaction challenge without an AE
  challenge.
- If native OAuth authorization is required and independent evidence is also
  missing, OAuth remains primary. An explicit composition profile may add a
  separate AE challenge, with separate identifiers and replay state.
- If no native OAuth grant is required, an application may use AE-CHALLENGE
  to negotiate whichever independently verifiable evidence forms its local
  policy accepts.

For graph and loop orchestrators, control-flow continuity never implies
authority continuity. Each receiving executor rederives the concrete action
after task decomposition or rewriting and applies its own routing rule. A
prior token, receipt, or challenge may be input evidence, but it does not
authorize a materially changed graph node. A blind retry after an unknown
provider outcome goes to reconciliation rather than back through admission.

## What is real and what is simulated

Real repository code, reused rather than reimplemented:

- AE-CHALLENGE minting and the RFC 9457 carrier:
  `lib/negotiate/evidence-challenge.js` (`createEvidenceChallenge`,
  `createEvidenceChallengeProblem`, `parseEvidenceChallengeProblem`).
- Server-side action digest: `artifactDigest` from
  `lib/evidence/evidence-graph.js`.
- CAID computation: `computeCaid` from `caid/impl/js/caid.mjs`
  (jcs-sha256).
- OAuth transaction-challenge native verification:
  `createOAuthTransactionChallengeAebAdapter` from `packages/verify`.
- Receipt issuance and verification: `issueTrustReceipt` from
  `packages/issue`, `verifyTrustReceipt` from `packages/verify`.
- One-time consumption state machine: `InMemoryAebConsumptionStore` from
  `packages/verify` (the durable Postgres equivalents live in
  `@emilia-protocol/gate`).

Simulated stand-ins, and what that limits:

- **There is no live authorization server.** The protected-resource
  challenge JWT and the AS-issued access token are minted locally with
  throwaway ES256 keys, constructed to the exact claim shape the draft
  defines so the real adapter verifies them. The demo therefore proves the
  relying-party verification and negotiation behavior, not interoperability
  with any deployed AS product.
- **The human approver is a locally generated Ed25519 key pair**, enrolled
  in a relying-party-pinned key directory for the run. No real approval
  ceremony or hardware key is involved.
- **The consumption store is in-memory.** It demonstrates the reserve,
  consume, and held-reservation semantics; a production deployment needs
  the durable, fenced stores.
- **The effect is a local function.** "Response lost" is a thrown error,
  standing in for a network partition after dispatch.

This is a demonstration harness. It verifies protocol behavior under
hostile inputs; it is not evidence about any production deployment, and no
claim of interoperability with external OAuth implementations is made.

## Scope notes

- The evaluator here is a profile-specific consumer of two presentation
  methods. It is intentionally not `evaluatePresentation` from
  `lib/negotiate/evidence-challenge.ts`, which pins the `ep-aec-v1` evidence
  chain profile; the challenge object's `present_as` field exists precisely
  so a relying party can advertise the closed set of methods its own
  consumer implements.
- Receipt verification establishes authenticity. Admission is the
  evaluator's separate decision (action match, audience, consumption), which
  is why `verifyTrustReceipt`'s own report labels its scope
  `AUTHENTICITY IS NOT ADMISSION OR REPLAY PREVENTION`.
