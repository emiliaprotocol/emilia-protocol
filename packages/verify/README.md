# @emilia-protocol/verify

**Zero-dependency offline verification for EP trust receipts.**

Verify Ed25519-signed trust receipts, Merkle anchor proofs, and commitment proofs using only Node.js built-in `crypto`. No EP infrastructure required. No API key. No account. Just math.

This is the core primitive that makes EP a **protocol**, not an API.

## Install

```bash
npm install @emilia-protocol/verify
```

## Quick Start

```js
import { verifyReceipt } from '@emilia-protocol/verify';

// Load a receipt document (EP-RECEIPT-v1 format)
const receipt = JSON.parse(fs.readFileSync('receipt.json', 'utf8'));

// Get the signer's public key (from /.well-known/ep-keys.json)
const publicKey = 'MFYwEAYHKoZIzj0CAQYFK4EEAA...'; // base64url SPKI DER

const result = verifyReceipt(receipt, publicKey);
console.log(result);
// { valid: true, checks: { version: true, signature: true, anchor: null } }
```

## In the browser, edge, or Deno

The default entry uses Node's `crypto`. For any runtime with the W3C Web Crypto
API — every modern browser, Deno, Cloudflare Workers, Vercel Edge — import the
`/web` build instead. Same inputs, same `{ valid, checks }` output (proven
byte-for-byte in `web.test.js`); the functions are `async` because Web Crypto is.

```js
import { verifyReceipt, verifyWebAuthnSignoff } from '@emilia-protocol/verify/web';

const r = await verifyReceipt(receipt, publicKey);          // Ed25519
const s = await verifyWebAuthnSignoff(signoff, approverKey, // ECDSA P-256
  { rpId: 'emiliaprotocol.ai' });
```

This is what powers [emiliaprotocol.ai/verify](https://www.emiliaprotocol.ai/verify):
a relying party verifies a receipt entirely in their own tab — nothing uploaded,
no server trusted. Receipts use Ed25519; Class-A device signoffs use ECDSA P-256
over a WebAuthn assertion (the `/web` build converts the DER signature to the raw
form Web Crypto expects). Call `isSupported()` to feature-detect.

## API

### Gate Qualification v2

`@emilia-protocol/verify/gate-qualification` verifies a closed, signed
qualification graph offline and returns `QUALIFIED`, `NOT_QUALIFIED`, or
`INDETERMINATE`. The caller supplies the trusted keys, trusted time, expected
candidate, assignment, policy, protected-request and current-status bindings;
the evidence graph cannot select its own trust policy.

```js
import {
  evaluateQualification,
} from '@emilia-protocol/verify/gate-qualification';

const decision = evaluateQualification(bundle, relyingPartyContext);
```

`@emilia-protocol/verify/gate-qualification-promptfoo` converts a complete,
immutably pinned Promptfoo v3 result into `EVALUATION_ONLY` evidence. It does
not emit a Qualification Statement and never authorizes provider entry.

```js
import {
  adaptPromptfooQualificationArtifact,
} from '@emilia-protocol/verify/gate-qualification-promptfoo';
```

Both modules are also re-exported from the package root. A `QUALIFIED` result
is non-authorizing: it does not grant permission, reserve resources, consume
authority, invoke a provider, or establish legality or business suitability.

### AEB evidence boundary — `@emilia-protocol/verify/aeb-adapter-contract`

The AEB kernel verifies native evidence under relying-party-pinned adapters,
maps every accepted leg through a pinned CAID profile, composes the legs through
`EP-AEC-v1`, enforces distinct-human quorum and no-self-approval, and reserves
the authorization before execution.

Use `createAebNativeVerificationAttestationAdapter()` when a native protocol
verifier runs at a workload gateway. Its signed attestation binds the native
artifact digest, protocol, audience, subject, evidence role, mapper, resolver,
CAID, and normalized-action digest. Presenter-selected roots, mappers, profiles,
and unsigned gateway headers are not trusted.

`InMemoryAebConsumptionStore` is test-only. Fleet execution uses
`authorizeAebExecutionDurable()` and `reconcileAebExecutionDurable()` with the
durable, ownership-fenced store contract implemented by
`@emilia-protocol/gate`.

`@emilia-protocol/verify/aeb-acceptance-profile` publishes the relying party's
content-addressed foreign-proof allowlist, exact AEB configuration,
requirement, registry, action type, and required evidence roles. The same
profile has fixed `monitor` and `enforce` semantics: monitor can report that
pre-consumption checks pass but cannot authorize or reserve evidence; enforce
requires an execution-time verification bound to the exact evaluation record,
local authorization, and atomic one-time consumption. An atomic replay
conflict can be decided only in enforce mode.

`@emilia-protocol/verify/aeb-execution-conditions` evaluates an opaque,
human-approved predicate-set commitment at the execution boundary. The exact
action, approval evidence, basis, presentation, resolver profile, source trust,
freshness, and enforcement strength are relying-party pinned. `observed` and
`leased` resolutions can satisfy the conditions axis but cannot claim
prevention; only `compare-and-set` and `provider-enforced` resolutions carrying
enforcement evidence can do so. `ADMIT` is scoped to execution conditions and
does not establish authorization or physical truth. When supplied to
`authorizeAebExecution` or `authorizeAebExecutionDurable`, only a valid `ADMIT`
result can reach the one-time reservation; predicate failure refuses, and
uncertainty routes to reconciliation required before authority is reserved.

Four revision-pinned foreign-proof adapters are available:

- `aeb-oasnt-adapter` verifies the OASNT-01 compact authorization token against
  an enrolled hardware-attested P-256 key and recomputes its action, display,
  and protected-request commitments. OASNT's native CAID namespace remains
  distinct from the EMILIA CAID projection.
- `aeb-aps-adapter` verifies the APS-03 signed ActionIntent and PolicyDecision
  chain, preserves the complete `aps-action-ref-v2` material, recomputes the
  decision reference, and delegates authority-chain semantics to a separately
  pinned pure verifier.
- `aeb-mcgraw-delegation-adapter` verifies deterministic COSE_Sign1 Budget
  proof claims for the exact protected HTTP request. ML-DSA-65 verification and
  delegation-chain semantics are supplied by separately pinned pure backends,
  so the package retains its zero-runtime-dependency boundary.
- `aeb-oauth-transaction-challenge-adapter` requires both the protected
  resource's signed challenge and the authorization server's access token,
  verifies their transaction and actor linkage, and delegates RAR narrowing to
  a separately pinned pure verifier. A challenge or pending transaction ID is
  never treated as approval, and the adapter does not infer a human approver.

All four outputs remain evidence, not final authority. AEB composes the roles;
the customer-owned local Gate decides whether the exact action may execute.

`@emilia-protocol/verify/aeb-native-adapters` supplies concrete AgentROA and
ORPRG adapters. Both use relying-party-pinned roots, profiles, status, and
expected actions. ORPRG uses non-mutating native inspection: it verifies the
permit and exposes its native replay unit, while the Gate atomically fences
that replay unit before any effect. Inspection is never reported as a final
native `ALLOW`.

`@emilia-protocol/verify/authorization-server-confirmation` verifies a closed
EdDSA Authorization Server grant under relying-party-pinned issuer, key,
audience, Resource Server key and freshness limits, while preserving signed
policy, directory-snapshot, exact-action and human-evidence commitments. It
emits the separate
`authorization-server-confirmation` role. An AEB `evidence-binding` term then
requires its signed human-evidence digest and human subject to match a
separately verified `human-authorization` leg. A valid AS signature is evidence
only: it never emits `SATISFIED` or `AUTHORIZED`, and an agent-orchestrator
signature cannot substitute for the AS. The signed grant distinguishes token
issuance time from the time the AS observed its directory snapshot, and the
relying party pins the maximum acceptable snapshot age. This prevents a fresh
token from laundering stale directory state into a claim of current standing;
it does not prove HR-system freshness or instantaneous employment status.

`@emilia-protocol/verify/authorization-bundle` verifies the closed
`EP-AUTHORIZATION-BUNDLE-v1` pre-execution human-evidence object. The relying
party supplies the exact action, audience, native OAuth/RAR binding,
policy-selected approver set, accepted key classes, current policy result, and
any required status or presentation verifiers. The result is exactly
`SATISFIED`, `REFUSE`, or `INDETERMINATE`; even `SATISFIED` explicitly sets
`authorization_decision: false`. A separate compare-and-set helper binds one
bundle digest to one native grant, but the caller must perform that transition
atomically in its own durable authoritative store. The package includes 21
same-repository hostile cases; they are not an external interoperability claim.

`@emilia-protocol/verify/policy-decision-evidence` is the distribution bridge
for existing local policy engines. It projects an exact OPA boolean or Cerbos
effect into a short-lived Ed25519 statement, verifies it under a
relying-party-pinned bridge key, pins the accepted engine and policy digest,
and maps the signed action through CAID. Its evidence role is normally
`machine-policy-decision`. A machine `ALLOW` satisfies only that role; it is
not human intent, authorization, admission, complete-mediation proof, or an
effect receipt. Consequential requirements should compose it with a separate
`human-authorization` leg:

```js
requirements: {
  'human-plus-local-policy': {
    '@version': 'AEB-REQUIREMENT-v1',
    all_of: ['human-authorization', 'machine-policy-decision'],
    terms: [{ type: 'one-time-consumption' }],
  },
}
```

The bridge signs what the integration observed; it does not make OPA or Cerbos
independent witnesses. Keep the bridge key behind the credential-owning
enforcement point and use Gate's durable consumption path for execution.

`@emilia-protocol/verify/aeb-psea-adapter` adds an optional, revision-pinned
adapter for `draft-yossif-psea-02`. It verifies strict ES256 compact JWS/EAT
proofs against enrolled P-256 keys; rejects unknown headers and claims; binds
issuer, audience, operation, tier, nonce, UV, UEID, lifetime, attestation
appraisal, and the JCS action hash; and projects the exact action into CAID.
`verifyAndCommitPseaProof()` atomically advances the native counter and consumes
the `jti` through a caller-supplied durable store before Gate admission. The
adapter does not mint PSEA proofs, identify a named human beyond pinned
enrollment, establish WYSIWYS, or replace AEC/Gate authorization and outcome
reconciliation. The hostile fixture set is
`conformance/vectors/psea-aeb.v1.json`; it is an EMILIA adapter suite, not an
independent PSEA interoperability claim.

`@emilia-protocol/verify/fido-ap2-bridge` verifies a relying-party-pinned
WebAuthn ES256/P-256 human-authorization ceremony over one closed, immediate
AP2 v0.2 `CheckoutMandate`/`PaymentMandate` projection. The signed context
commits to exact canonical SD-JWT token strings, both disclosure-resolved
verified payloads, the checkout-hash algorithm derived from the exact issuer
token, the merchant checkout JWT,
native-verification attestation, readable disclosure, CAID, normalized action,
tenant, relying party, audience, operation, frozen provider request,
provider/account, approver, nonce, and deadline. Native AP2 verification stays
a separate authoritative attestation leg: it must verify the merchant checkout
JWS, current checkout state, hash/transaction linkage, disclosed claims, and
credential scope. The bridge does not reinterpret those credentials or turn a
valid WebAuthn assertion into local authorization.

The pinned immediate-payment subset follows AP2 v0.2 literally: an immediate
payment omits `execution_date`, and optional merchant, instrument, PISP, and
risk members are accepted only with their schema-defined types. `null` does
not stand in for an omitted AP2 optional member. Bridge and AEB instants are
limited to millisecond precision so JavaScript comparison never truncates a
future not-before value into the present.

The closed WebAuthn profile accepts only an enrolled ES256/P-256 key, a 37-byte
extension-free assertion with UP and UV, approved origin/RP bindings, and
relying-party-pinned backup policy. The default
`above-enrollment-and-one-time` policy also requires a counter above
enrollment; Gate compares and advances the durable RP/credential head
atomically with admission. The explicit `not-relied-upon` policy supports
authenticators such as synced platform passkeys whose counters remain zero;
under that policy the counter supplies no clone-detection claim and Gate does
not create a monotonic-counter resource. Exact ceremony binding, replay
resources, and one-time provider admission remain required under both modes.
Legacy, open, recurring, unknown, stale, or materially lossy AP2 semantics fail
closed. One-time execution custody remains the Gate Qualification v2
AdmissionStore boundary. A verified assertion proves the signed ceremony
occurred; it does not prove legal consent, human comprehension, current
authorization, admission, or replay prevention.

`createFidoAp2NativeSourceBinding()` domain-separates commitments to the exact
byte sequences and strict payload digests accepted by the native verifier.
Those commitments prevent a splice only when the caller supplies the exact
tokens and disclosure-resolved payloads accepted by its authoritative native
AP2 verifier and independently reprojects them before reliance. The
corresponding Gate 0.22.2 bridge performs that reprojection at admission; this
pure helper alone is not admission or native AP2 verification.

### A2A receipt binding — `@emilia-protocol/verify/a2a-receipt-binding`

`createA2AReceiptPresentation()` carries an EMILIA receipt on A2A v1.0's
official namespaced `Message.extensions` / `Message.metadata` extension point.
The closed profile binds the complete base receipt, exact semantic action,
pre-task initiating Message, server-issued Task and context, proof-retry
Message, selected Agent Card, and target interface. It also emits the
`EP-RECEIPT-EXTENSIONS-v1` companion index required by Receipts-10.

The Task ID cannot be present in the initiating Message because A2A assigns it
at the server. The bridge therefore preserves both phases instead of
retroactively treating the first attempt as authorized: the original Message
is committed by digest, then the signed companion binds that request and the
receipt to the returned Task/context and the exact retry Message.

`verifyA2AReceiptPresentation()` requires a relying-party-pinned Ed25519 binder,
the exact Task snapshot obtained by the caller over authenticated A2A transport,
the exact initiating Message, Agent Card and interface pins, current time,
extension negotiation, locally expected
action/CAID, and a caller-supplied receipt verifier that returns the digest and
CAID it actually verified. It rejects task, context, message, target, action,
receipt, metadata, protocol-version, and validity-window substitution. A valid
result is correlation evidence only: A2A server authentication, receipt
verification, local authorization, one-time consumption, execution, and
outcome proof remain separate decisions. Raw unsigned A2A objects never become
authority.

### Agent Edge Continuity — `@emilia-protocol/verify/agent-edge-continuity`

`EP-AGENT-EDGE-CONTINUITY-v1` carries one material action across user,
harness, model, MCP tool, A2A handoff, and effect boundaries without turning
provenance into authority. Every envelope binds the relying party, pinned
configuration, initiator, executor, CAID, normalized action, proposal, and
operation.

Verification is offline and relying-party controlled. Signer pins constrain
each key by status, validity, source, and edge; topology pins constrain roots,
transitions, execution edges, path depth, lifetime, and age.

The single-process `authorizeAgentContinuityExecution()` is for reference
tests. Fleet execution uses `authorizeAgentContinuityExecutionDurable()`,
which atomically fences AEB native replay identities plus every continuity ID
and handoff nonce. Historical AEB verification, a post-effect envelope before
reservation, or an insecure store cannot authorize execution.

The outcome edge is evidence only. Proposal-to-Effect custody keeps an
`INDETERMINATE` action locked and requires authenticated reconciliation.

### Signed current status — `@emilia-protocol/verify/status`

`EP-STATUS-v1` verifies fresh current/revoked state under a separately pinned
`EP-REVOKER-AUTHORITY-v1` certificate. Sequence and predecessor-digest binding
reject rollback or resurrection, terminal revocation cannot be undone, and an
unavailable or stale status authority produces `indeterminate`, never a
fabricated `revoked: false`.

### `verifyReceipt(doc, publicKeyBase64url)`

Verify an EP-RECEIPT-v1 document. Performs three independent checks:

1. **Version** — Document format is EP-RECEIPT-v1
2. **Signature** — Ed25519 signature over canonical payload
3. **Anchor** (if present) — Merkle proof reconstructs claimed root

Returns `{ valid, checks, error? }`.

### `verifyMerkleAnchor(leafHash, proof, expectedRoot)`

Verify a Merkle inclusion proof. The root can be independently checked on Base L2 via [Basescan](https://basescan.org).

Returns `boolean`.

### `verifyCommitmentProof(proof, publicKeyBase64url)`

Verify an EP-PROOF-v1 commitment proof. Checks expiry and signature.

Returns `{ valid, claim, error? }`.

### `verifyReceiptBundle(bundle, publicKeyBase64url)`

Verify all receipts in an EP-BUNDLE-v1 document.

Returns `{ valid, total, verified, failed }`.

### `verifyWebAuthnSignoff(signoff, approverPublicKeySpkiB64u, { rpId? })`

Verify a Class-A (device-bound key) signoff fully offline: the WebAuthn
challenge equals SHA-256(JCS(context)) for the exact signed context, the
authenticator asserted user presence + verification, and the ECDSA P-256
signature verifies against the enrolled approver key.

Returns `{ valid, checks, error? }`.

### `verifyResolutionReceipt(receipt, opts)` - `@emilia-protocol/verify/resolution`

Verify an additive `EP-RESOLUTION-v1` record for a briefing-and-binding
envelope. The signed context preserves `approved`, `declined`, `amended`, and
`rejected` as distinct outcomes and binds the source envelope digest, exact
action digest, principal, initiator, nonce, and validity window.

The relying party supplies the exact `bindingMoment`, `expectedActionHash`,
role-scoped `principalKeys`, `rpId`, and an exact `allowedOrigins` list. Before
an authentic approval returns `authorizes_action: true`, it must additionally
supply `expectedSelectedOption`, `expectedNonce`, `expectedInitiator`, and an
in-window `evaluationTime`. Callers gating execution test `authorizes_action`,
not merely `valid`; authentic negative outcomes are evidence and never authority.

Returns `{ valid, authorizes_action, outcome, requires_successor, checks, reason? }`.

### `verifyTrustReceipt(receipt, { approverKeys, logPublicKey, now })`

> **Authenticity is not admission or replay prevention.** This pure offline
> verifier never authorizes an effect and never atomically consumes a receipt.
> Every result carries `decision_scope.authenticity_only: true`,
> `admission_authorized: false`, and an explicit replay/revocation status.
> Consequential execution must use the credential-owning Gate /
> `makeReceiptGate()` with one shared atomic consumption store.

The full offline verification algorithm from the Internet-Draft
(draft-schrock-ep-authorization-receipts, Section 6.3) over a Section 6.2
Trust Receipt — all six steps, no network:

1. Recompute the action hash from the canonical Action Object
2. Recompute each context hash; confirm it commits to the action hash, the policy hash, and a distinct approver
3. Verify each signoff signature (Class-A WebAuthn or Class-B Ed25519) against the pinned approver key, checking the key's validity window and refusing any key directory entry carrying `compromised_at`
4. Separation of duties — initiator in no approver slot, approvers pairwise distinct, approval count ≥ `required_approvals`
5. Merkle inclusion of the receipt leaf against the checkpoint root, and the
   checkpoint signature against the trusted log key. The signature is Ed25519
   over the raw 32-byte SHA-256 digest of the UTF-8 JCS serialization of the
   checkpoint after removing `log_signature` (exact current-profile object:
   `{log_key_id, root_hash, tree_size}`). It is not a signature over the JSON
   text or an encoded digest string.
6. `signed_at` / `committed_at` within `[issued_at, expires_at]`

Returns `{ valid, checks, errors, attestation, strict, decision_scope }` and
fails closed on missing cryptographic input. `valid: true` means the supplied
artifact passed the requested authenticity checks; it does **not** mean the
action is currently authorized or unused.

`verifyTrustReceipt` authenticates each presented Authorization Context, but it
does not evaluate the companion EP-QUORUM set-level policy. Its always-present
`decision_scope.quorum_ordering` reports whether a `prev_context_hash` was
present and names `verifyQuorum` as the required verifier. A green base receipt
result MUST NOT be described as proof of threshold, roster order, or ordered
chain linkage unless `verifyQuorum` also accepts the exact members and pinned
policy.

`valid_from` / `valid_to` express ordinary issuance and rotation windows.
`compromised_at` is different: its presence is a terminal relying-party directory
fact, so a stolen key cannot evade it by signing a backdated `issued_at`. When a
relying party supplies its own RFC 3339 `now`, the verifier also refuses an
`issued_at`, `signed_at`, or `consumption.committed_at` after that verifier
decision time. Omitting `now` preserves
offline historical verification; trusted timestamp evidence is still required
when a deployment needs to prove when a receipt was actually created.
`evaluateReliance` treats its `input.now` as the authoritative decision clock
and forwards that exact instant into receipt verification; callers do not need,
and cannot use, a separate `opts.now` to weaken the temporal check.

For a current reliance decision, set `verificationMode: 'current'` and pass the
relying party's trusted `now`. Current mode requires every signing key to remain
current at that decision time, so a presenter cannot evade an expired
`valid_to` by backdating the receipt. If an operator narrows `valid_to` into the
past, also pass the previous directory as `previousApproverKeys`: the
transition fails closed unless the new entry carries `compromised_at` (or the
relying party records the explicit
`allowRetroactiveExpiryWithoutCompromise: true` exception).

```js
const result = verifyTrustReceipt(receipt, {
  approverKeys: currentDirectory,
  previousApproverKeys: priorDirectory,
  logPublicKey,
  verificationMode: 'current',
  now: relyingPartyClock,
  revocationStatements,
  revokerKeys,
});
```

When `revocationStatements` is absent, `decision_scope.revocation_status` is
`unknown`, never “not revoked.” An authentic exact-target revocation refuses;
a malformed exact-target statement is `indeterminate` and also refuses.

Current-mode financial actions at or above USD 100,000 require a pinned RFC
3161 `timestampProof`. The built-in trigger recognizes payment, transfer, wire,
disbursement, purchase, refund, and financial action types. Other deployments
can require the same control explicitly with `requireTimestampProof: true`.

Class-A WebAuthn verification surfaces `sign_count`, backup eligibility, backup
state, and a counter status under `webauthn_signoffs`. Pass the previously
stored counter in `webauthnSignCounts[keyId]`. The default `observe` policy
reports a non-advancing counter; `webauthnCounterPolicy: 'enforce'` refuses it.
A zero counter remains `unsupported`, because authenticators are permitted not
to implement signature counters. A non-advancing nonzero counter is a signal
of possible cloning, malfunction, or reordered assertions—not proof by itself.

#### Strict verifier mode — *requires 1.5.0*

For deployment gates and hostile-environment verification, opt into strict mode:

```js
const r = verifyTrustReceipt(receipt, {
  approverKeys,
  logPublicKey,
  strict: true,
  rpId: 'www.emiliaprotocol.ai',
  expectedPolicyHash: 'sha256:...',
});
```

Strict mode preserves the frozen Section 6.3 `checks` object, then adds
`r.strict` as a second gate. When `strict: true`, `valid` requires both the base
checks and:

- `pinned_keys` — every signer and the log are locally pinned.
- `rp_id` — Class-A WebAuthn `rpIdHash` matches the caller-pinned RP ID.
- `user_presence` / `user_verification` — Class-A signoffs asserted UP + UV.
- `key_windows` — every approver key has parseable `valid_from` / `valid_to` and was valid at `issued_at`.
- `policy_hash` — every context matches `expectedPolicyHash`.
- `no_unsigned` — critical action, context, signoff, consumption, and log proof fields are present.

Without `strict: true`, `strict` is `{ enabled: false, valid: true, checks: {}, errors: [] }`, so existing verification and conformance semantics are unchanged.

### `verifyOutcomeBinding(receipt, attestation, opts)` — experimental

Verify an executor-signed `EP-OUTCOME-ATTESTATION-v1` against the exact Trust
Receipt, signed predicted effects, action hash, receipt bytes, and consumption
nonce it names:

```js
import {
  buildOutcomeAttestation,
  trustReceiptDigest,
  verifyOutcomeBinding,
} from '@emilia-protocol/verify';

const attestation = buildOutcomeAttestation({
  receipt_id: receipt.receipt_id,
  receipt_digest: trustReceiptDigest(receipt),
  action_hash: receipt.action_hash,
  consumption_nonce: receipt.consumption.nonce,
  execution_id: 'exec_123',
  executor_id: 'ep:executor:payments',
  executed_at: new Date().toISOString(),
  observed_effects,
  signer: executorSigner,
});

const result = verifyOutcomeBinding(receipt, attestation, {
  receiptOptions: { approverKeys, logPublicKey },
  executorKeys: {
    'ep:executor:payments': { public_key: executorPublicKey },
  },
  policyPredictedEffects: optionalAdditionalConstraints,
});
```

The executor signs observations, never the human-approved prediction. Signed
predictions come only from the fully verified receipt; relying-party policy may
add constraints but cannot replace or loosen them. If the policy field is
supplied but is not an array, verification refuses instead of treating it as
absent. `result.outcome_binding`
preserves `in_bounds`, `divergent`, and `incomparable` as distinct results, and
`valid` is true only for a fully bound, verified, in-bounds result.
`result.result_digest` commits to the exact receipt, attestation, signed
predictions, supplied policy predictions, checks, reasons, and typed outcome;
two different signed inputs do not share a digest merely because they reach the
same reduced verdict.

### `verifyOutcomeObservationSet(predictions, observations, opts)` — experimental

Reconcile executor, system-of-record, and independent-observer claims without
letting the presenter select the trust policy. Each `sourceKeys` pin carries the
canonical Ed25519 public key, role, source class, `control_domain_id`, status,
validity interval, and optional compromise time. `sourceRequirements` can
require a distinct-source quorum by canonical key and declared control domain;
`observationWindows` binds the accepted interval and maximum attestation delay.

```js
const result = verifyOutcomeObservationSet(predictions, observations, {
  sourceKeys,
  sourceRequirements: [{
    role: 'independent_observer',
    source_class: 'revenue_meter',
    min_distinct_sources: 2,
    distinct_by: ['key', 'control_domain'],
  }],
  observationWindows: [{
    role: 'independent_observer',
    source_class: 'revenue_meter',
    relation: 'exact',
    not_before,
    not_after,
    max_attestation_delay_ms: 30_000,
  }],
  now,
  expectedReceiptId,
  expectedReceiptDigest,
  expectedActionHash,
  expectedActionCaid,
  expectedConsumptionNonce,
  expectedOperationId,
});
```

The same canonical key cannot fill executor and independent-observer roles,
even under alternate text encodings. Different keys in one declared control
domain also do not establish independence. A declared control domain is a
relying-party input, not proof of organizational separation or physical truth.
Missing, non-current, non-distinct, stale, or window-mismatched evidence returns
`lifecycle_state: 'indeterminate'`; it never authorizes blind replay.

#### Advisory: the PIP-007 initiator escalation attestation — *requires 1.4.0*

When the contexts carry a [PIP-007](https://github.com/emiliaprotocol/emilia-protocol/blob/main/PIPs/PIP-007-initiator-attestation.md) `initiator_attestation`, the result includes an **advisory** report:

```js
const r = verifyTrustReceipt(receipt, { approverKeys, logPublicKey });
r.attestation; // { present, consistent, issues: [] }
```

- `present` — a context carries an attestation.
- `consistent` — it is present in **every** context with an **identical** canonical form (the cross-context identity rule the protocol flags to catch a divide-and-misinform orchestrator showing different approvers different reasons).
- `issues` — any PIP-007 §1 malformations: unknown members, a `statement` over 280 characters, `escalation_trigger` of `policy_rule` without a `policy_basis`, or a bad enum value.

The advisory **never affects `valid` or any member of `checks`** — by design (PIP-007 §2): a receipt carrying a malformed attestation still verifies cryptographically, exactly as it does on a verifier that predates this PIP. The attestation is **a claim by the initiator** — identified but never trusted — so a policy engine MUST NOT use it to relax any check or raise any trust score.

#### Transparency, revocation, time, and consumption checks

The optional evidence checks extend `verifyTrustReceipt` in the same shape as
`priorCheckpoint`: each runs only when its evidence or requirement is supplied,
adds one member to `checks`, folds into `valid` by conjunction, and fails closed
with a distinct reason. The always-present `decision_scope` is intentionally
outside the cryptographic checks: it prevents callers from mistaking offline
authenticity for current admission or atomic replay protection.

```js
const r = verifyTrustReceipt(receipt, {
  approverKeys, logPublicKey,

  // 1. Witness quorum (EP-WITNESS-v1): k distinct pinned witnesses cosigned the head.
  witnessQuorum: { cosignatures, pinnedWitnessKeys, k: 2 },

  // 2. Trusted-time proof (RFC 3161): a pinned TSA timestamped a digest you choose.
  timestampProof: { token, expectedDigest, pinnedTsaKeys },

  // 3. Currency (EP-CURRENCY-v1): passes ONLY on a proven-fresh signed head.
  currency: { now, maxStalenessSeconds, freshHead, freshHeadRequired },

  // 4. Consumption proof (EP-SMT-CONSUME-v1): a nonce went absent -> present once.
  consumptionProof: bundle,

  // 5. Initiator-software attestation (EP-INITIATOR-ATTESTATION-v1).
  requireInitiatorAttestation: true,

  // 6. Current exact-target revocation statements from pinned revokers.
  revocationStatements,
  revokerKeys,
});
// checks.witness_quorum / .timestamp_proof / .currency / .consumption /
// .initiator_attestation / .revocation are added only when active, and the full
// module result is surfaced under the matching top-level member.
```

Honesty boundaries (also stated in each module):

- **Witness quorum** proves `k` trusted witnesses saw **one** head (the local, single-view half of equivocation detection). It does **not** prove no different head was shown elsewhere; that cross-view gossip is the deployment's responsibility.
- **Timestamp proof** proves a TSA asserted the digest existed at `gen_time` (the bytes predate `gen_time`). It is authentic-as-of-token only and says nothing about current TSA-certificate validity or revocation, and it does not prove the action was correct or authorized.
- **Currency** is a separate axis from offline authenticity. `checks.currency` passes **only** on status `fresh`; both `stale` and the honest offline default **`unknown`** fail the opted-in gate, because offline verification can **never** establish currency. Read `result.currency.currency_at_T` to tell `unknown` (offline only) apart from `stale`.
- **Consumption proof** proves the tree-shaped consumption facts only. Checkpoint **signatures** and currency of the later head are the caller's responsibility.
- **Initiator attestation** says **which** software asked; it does **not** prove the software behaved (the labels are self-asserted, and the digest is authentic-as-supplied, not proof of correct execution).
- **Revocation statements** prove only what the presented, pinned statements
  establish. Absence from a supplied list is not proof of current
  non-revocation; without a current authenticated status source the result
  remains `unknown`.

Both the witness and consumption profiles now ship a verifier **and** a reference emitter, so the emit/verify loop is closed at reference level. A third party can PRODUCE these artifacts, not only check them:

- **Witness (EP-WITNESS-v1).** The reference witness emitter is the cosigner service in [`witness/`](../../witness) (`witness/server.mjs`). It imports the signing digest and domain tag from this package (`witness.js`), so a cosignature it emits is byte-identical to what `verifyWitnessCosignature()` / `requireWitnessQuorum()` check.
- **Consumption (EP-SMT-CONSUME-v1).** The reference issuer-side emitter is `ReferenceConsumptionTree` in `consumption-proof.js`, exported as `@emilia-protocol/verify/consumption-proof.js`. It maintains the sparse consumption tree and emits the non-inclusion / inclusion sub-proofs in the exact wire format `verifyConsumptionProof()` accepts, so anyone can reproduce a full bundle.

Reference emitters pin the wire format; they are not production infrastructure. A production issuer maintains its own sparse consumption ledger (not the in-memory reference tree), and the security of the witness leg comes from RUNNING several independent witnesses under separate operators and comparing their views. That ecosystem step is deployment, not reference code.

All five of these profiles (**EP-WITNESS-v1**, **EP-CURRENCY-v1**, **EP-SMT-CONSUME-v1**, **EP-INITIATOR-ATTESTATION-v1**, and **timestamp proof (RFC 3161)**) are now ported to Python (`packages/python-verify`) and Go (`packages/go-verify`) and run cross-language in `conformance/run.mjs` over shared vector suites (`currency.v1.json`, `initiator-attestation.v1.json`, `consumption-proof.v1.json`, `witness.v1.json`, `timestamp-proof.v1.json`), where the JavaScript, Python, and Go verifiers must agree. The RFC 3161 timestamp-proof ports keep the package's dependency posture: the JS minimal DER/CMS reader was hand-ported to **pure Python** (with `cryptography` used only for the RSA/ECDSA signature verify, so no new dependency) and to **pure-stdlib Go**, and all three lanes agree over real `openssl`-minted TimeStampTokens, including the exact per-vector refusal path. As always, this is one team's three-language ports (a consistency check), not clean-room independent implementations.

### Federation (PIP-006) — *requires 1.3.0*

Cross-operator verification: accept a receipt issued by a different EP
operator using only its published discovery surfaces.

```js
import { verifyFederatedReceipt, verifyFederatedReceiptOffline } from '@emilia-protocol/verify';

// Online: resolves the issuer's keys from a caller-pinned discovery URL and
// checks its revocation surface. Treat receipt.signature.key_discovery as a
// hint, not a trust root.
const verdict = await verifyFederatedReceipt(receipt, {
  keyDiscoveryUrl: 'https://op-a.example/.well-known/ep-keys.json',
  expectedSigner: 'ep:operator:op-a',
  networkBoundary: {
    resolveAddresses: resolveEveryAddress,
    fetchPinned: fetchWithoutReresolving,
  },
  statusVerifier: verifyPinnedCurrentStatus,
});
// { accepted, verified, revoked, signer, keyMatched: 'current'|'historical', checks }

// If the live revocation surface is unavailable, a valid signature remains
// verified:true but accepted is false until status can be confirmed.

// Air-gapped: supply the issuer's ep-keys.json + revocation set yourself.
const offline = verifyFederatedReceiptOffline(receipt, discoveryDoc, { revokedReceiptIds });
```

The network boundary must reject the whole DNS answer set unless every address
is public, connect directly to one approved address without re-resolving, retain
hostname TLS/SNI validation, report the connected address, and refuse
redirects. A plain injected `fetch` is deliberately insufficient against DNS
rebinding.

`resolveOperatorKeys(discoveryDoc, signerId)` is also exported (current keys
first, then `historical_keys` whose signed `issued_at` is no later than a valid
`retired_at`). See
`docs/FEDERATION-REGISTRY.md` for the operator discovery convention.

## Design Principles

- **Zero dependencies** — Only `node:crypto`. No supply chain risk.
- **Offline-first** — Core verification makes no network calls. The optional
  federation online path requires an explicit resolver plus pinned transport;
  no EP-operated server is required.
- **Deterministic** — Canonical JSON serialization for reproducible signatures.
- **Auditable** — A few small files, ~1,000 lines total. Read the entire thing in an hour.

## How It Works

```
Receipt Document (EP-RECEIPT-v1)
├── payload (canonical JSON)
├── signature
│   ├── algorithm: "Ed25519"
│   ├── signer: "ep_entity_..."
│   └── value: base64url signature
└── anchor (optional)
    ├── leaf_hash: SHA-256 of receipt
    ├── merkle_proof: [{hash, position}, ...]
    ├── merkle_root: root hash
    └── chain: "base-sepolia"

Verification:
1. Canonicalize payload → sorted-key JSON
2. Verify Ed25519(canonical_payload, signature, public_key)
3. If anchor: reconstruct Merkle root from proof, compare
```

## Getting Public Keys

Signer public keys are discoverable at `/.well-known/ep-keys.json` on any EP operator:

```bash
curl https://ep.example.com/.well-known/ep-keys.json
```

## Reliance gap reports (acceptance preflight)

`reliance-gap.js` wraps the reliance kernel (`reliance.js`) into a diagnostic:
given a de-identified action packet and a relying party's pinned
EP-RELIANCE-PROFILE-v1, it emits one deterministic EP-RELIANCE-GAP-REPORT-v1
with the kernel verdict passed through verbatim, a missing-evidence list
(each entry: requirement, why it matters, how to close it), the JCS+sha256
action digest, the pinned profile digest, a plain-language control mapping
(authority, identity, freshness, revocation, consumption, signoff, audit
trail), a closed limitations list, and the exact command that reproduces the
report offline.

```js
import { buildRelianceGapReport } from '@emilia-protocol/verify/reliance-gap';

const report = buildRelianceGapReport(
  { action, evidence, context },       // the packet
  profile,                             // the relying party's pinned rule
  { now: '2026-07-08T15:00:00Z' },     // evaluation time (never the wall clock)
);
```

The packet's `evidence` is an array of artifacts, either `{ type, artifact }`
envelopes or bare artifacts detected by shape (`receipt`, `quorum`,
`authority_proof`, `revocation_state`, `consumption`). Artifact types with no
registered verifier are recorded as `unverifiable_present` and never count
toward satisfaction. The packet's `context` carries the relying party's
verification material: `approver_keys`, `log_public_key`, `rp_id`,
`revoker_keys`. The `profile` argument accepts a bare profile or a signed
EP-RELIANCE-PROFILE-REGISTRY-v1 entry (unwrapped; the entry's `profile_id` is
reported).

Determinism contract: no wall-clock reads (evaluation time comes only from
`opts.now` or `packet.evaluated_at`; absent both, the builder refuses with a
reason), keys sorted, arrays stable, so the same inputs reproduce the same
bytes. `buildMultiPartyRelianceGapReport` evaluates the SAME packet against
several profiles and emits one combined EP-RELIANCE-GAP-MULTI-v1 report.

From the CLI:

```bash
npx @emilia-protocol/verify reliance-gap packet.json --profile profile.json
npx @emilia-protocol/verify reliance-gap packet.json --profiles ./profiles \
  --now 2026-07-08T15:00:00Z --out report.json
```

Exit codes: 0 = `rely` (all rely in `--profiles` mode), 2 = any
`do_not_rely_*`, 1 = operational error. Fully offline; no network access.
A worked five-relying-party example lives in `examples/reliance-gap/` at the
repository root. A single gap report is the per-action preflight;
EP-ASSURANCE-PACKAGE-v1 (`packages/gate/reports/assurance-package.js`)
bundles a population of such reliance decisions so an independent assurer can
re-perform every verdict offline.

## License

Apache-2.0
