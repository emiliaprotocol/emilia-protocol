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

`@emilia-protocol/verify/aeb-native-adapters` supplies concrete AgentROA and
ORPRG adapters. Both use relying-party-pinned roots, profiles, status, and
expected actions. ORPRG uses non-mutating native inspection: it verifies the
permit and exposes its native replay unit, while the Gate atomically fences
that replay unit before any effect. Inspection is never reported as a final
native `ALLOW`.

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

### `verifyTrustReceipt(receipt, { approverKeys, logPublicKey })` — *requires 1.3.0*

The full offline verification algorithm from the Internet-Draft
(draft-schrock-ep-authorization-receipts, Section 6.3) over a Section 6.2
Trust Receipt — all six steps, no network:

1. Recompute the action hash from the canonical Action Object
2. Recompute each context hash; confirm it commits to the action hash, the policy hash, and a distinct approver
3. Verify each signoff signature (Class-A WebAuthn or Class-B Ed25519) against the pinned approver key, checking the key's validity window
4. Separation of duties — initiator in no approver slot, approvers pairwise distinct, approval count ≥ `required_approvals`
5. Merkle inclusion of the receipt leaf against the checkpoint root, and the checkpoint signature against the trusted log key
6. `signed_at` / `committed_at` within `[issued_at, expires_at]`

Returns `{ valid, checks, errors, attestation, strict }` and fails closed on any missing input.

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

#### Opt-in transparency and currency knobs (requires 3.5.0)

Five **additive, opt-in** checks extend `verifyTrustReceipt` in the same shape as `priorCheckpoint`: each runs **only** when you pass its option, adds **one** member to `checks` when active, folds into `valid` by conjunction, and **fails closed** with a distinct reason. Pass none of them and the result is byte-for-byte what a pre-3.5.0 verifier returns (the frozen seven `checks` members, no extra top-level members).

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
});
// checks.witness_quorum / .timestamp_proof / .currency / .consumption /
// .initiator_attestation are added only for the options you passed, and the
// full module result is surfaced under the matching top-level member.
```

Honesty boundaries (also stated in each module):

- **Witness quorum** proves `k` trusted witnesses saw **one** head (the local, single-view half of equivocation detection). It does **not** prove no different head was shown elsewhere; that cross-view gossip is the deployment's responsibility.
- **Timestamp proof** proves a TSA asserted the digest existed at `gen_time` (the bytes predate `gen_time`). It is authentic-as-of-token only and says nothing about current TSA-certificate validity or revocation, and it does not prove the action was correct or authorized.
- **Currency** is a separate axis from offline authenticity. `checks.currency` passes **only** on status `fresh`; both `stale` and the honest offline default **`unknown`** fail the opted-in gate, because offline verification can **never** establish currency. Read `result.currency.currency_at_T` to tell `unknown` (offline only) apart from `stale`.
- **Consumption proof** proves the tree-shaped consumption facts only. Checkpoint **signatures** and currency of the later head are the caller's responsibility.
- **Initiator attestation** says **which** software asked; it does **not** prove the software behaved (the labels are self-asserted, and the digest is authentic-as-supplied, not proof of correct execution).

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
