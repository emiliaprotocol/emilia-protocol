# @emilia-protocol/gate — EMILIA Gate

**The Consequence Firewall.** Deny-by-default enforcement for consequential machine actions.

> If an agent cannot produce a valid receipt, it cannot change money, code, permissions, data,
> infrastructure, energy, or physical state.

A guarded action runs **only** if it arrives with a receipt that is **valid** (Ed25519 over
canonical JSON, signed by a pinned issuer), **in-scope** (bound to the exact action), **sufficiently
assured** (meets the action's required tier), **fresh**, and **unused** (not a replay). Otherwise it
is refused with a machine-readable `Receipt-Required` challenge (HTTP 428). Every decision — allow or
deny — is appended to a tamper-evident evidence log.

This is **not** authentication ("who are you") or permissions ("are you allowed here"). It is a
**policy-enforcement point** that requires portable proof a named human authorized *this exact
action* before the world is mutated.

## Run it

```bash
node --test                       # Gate + red-team + EG-1 + MCP + adapter tests
node demo.mjs                     # end-to-end: passthrough -> 428 -> too-low -> drift -> allow -> replay -> tamper -> reliance packet
node eg1.mjs                      # EG-1 conformance: 8/8 -> "EG-1 Enforced"
node adapters/github-demo.mjs     # an agent tries to delete a prod repo (refused without a receipt)
node custody-demo.mjs             # rotate, revoke a compromised issuer key live, retention export
```

## Use it

```js
import { createTrustedActionFirewall } from '@emilia-protocol/gate';

const gate = createTrustedActionFirewall({
  trustedKeys: [ISSUER_PUBKEY_B64U], // pin the issuers you trust
  store: sharedConsumptionStore,      // durable + ownership-fenced + permanent
  maxAgeSec: 900,
});

// Facts from the system of record, not from attacker-controlled request input.
const observedAction = {
  action_type: 'payment.release',
  amount_usd: 40000,
  currency: 'USD',
  payment_instruction_id: 'pi_123',
  beneficiary_account_hash: 'sha256:...',
};

const out = await gate.run({
  selector: { protocol: 'mcp', tool: 'release_payment' },
  receipt,
  observedAction,
}, async () => {
  // Only reached after receipt verification, assurance enforcement, field
  // binding, and one-time reservation.
  return releasePayment(observedAction);
});

if (!out.ok) throw out.body; // 428 Receipt Required
console.log(out.packet.verdict); // "rely"
```

## Three-plane deployment

High-consequence infrastructure separates three jobs instead of asking one
vendor or appliance to prove its own work:

1. **Enforcement plane** — an executor-side Gate returns 428 and does not call
   the actuator until the pinned authorization profile is satisfied.
2. **Witness plane** — an independently pinned TAP, packet broker, or sensor
   signs privacy-minimized observations. Observation never establishes that an
   action was authorized, blocked, executed, or physically completed.
3. **Control plane** — a relying party pins the coverage inventory and
   settlement profile, joins signed evidence by exact action digest, reports
   `gated`, `witness_only`, `ungated`, `stale`, or `unknown`, and meters only
   protected actions.

```js
import { evaluateGateControlPlane } from '@emilia-protocol/gate/control-plane';

const report = await evaluateGateControlPlane({
  coverage: { deployments, probes, witnesses }, // presenter evidence only
  settlements: [{ bundle }],
}, {
  coverageInventory,       // relying-party pinned
  settlementProfile,       // relying-party pinned
  expectedProbeNonces,     // current RP challenges, keyed by surface
  attestationVerifiers,
  pinnedProbes,
  pinnedWitnesses,
  witnessSequenceStore,     // durable atomic stream checkpoint store
  verifyAuthorization,
  verifyExecution,
  verifyOutcome,
});
```

The reference demonstration is `node examples/gate-control-plane/demo.mjs`.
It shows a complete view becoming `witness_only` and settlement-ineligible when
the Gate is removed while the network witness remains healthy.
Witness-dependent production decisions fail closed unless `witnessSequenceStore`
is durable or the relying party supplies a previously accepted durable witness
result through the explicit trusted-acceptance option.

## Default action packs

`createTrustedActionFirewall()` ships with high-risk defaults. These are category-based, not just
amount-based:

- `payment.release` — money movement, `class_a`
- `payment.bank_details.change` — bank-detail / beneficiary change, `class_a`
- `deploy.production` — production deploy, `quorum`
- `permission.admin.change` — permission / admin change, `quorum`
- `data.export` — bulk sensitive-data export, `class_a`
- `record.delete` — destructive record deletion, `class_a`
- `regulated.decision.override` — regulated decision override, `quorum`

Each pack also defines `execution_binding.required_fields`. The executor must pass those observed
fields from the real system of record. If the signed claim and observed mutation differ, the gate
refuses with `execution_binding_failed` before consuming the receipt.

Execution-parameter binding is therefore a **Gate** guarantee that holds **only when you supply a
system-of-record `observedAction`**: it is the Gate — not receipt verification on its own — that
proves the executed parameters matched what was authorized. If a required field is declared but no
`observedAction` is provided, the check fails closed (`execution_binding_failed`), never silently
passes. A bare `@emilia-protocol/require-receipt` gate binds the action type/target only; reach for
this package when parameter drift (amount, beneficiary, commit, role, …) must be caught.

Prefer `gate.run(...)` for mutations: it reserves the receipt, runs the side effect, commits
one-time consumption after success, and emits the execution receipt + reliance packet. Once the
executor is invoked, a thrown error is an **indeterminate effect**, not proof that nothing happened:
the approval is burned (or its no-TTL reservation remains frozen if the store is unavailable) so a
blind retry cannot duplicate the side effect. Retryable integrations should make the downstream
operation idempotent under `receipt_id` and reconcile the result. Use lower-level `gate.check(...)`
only when your framework has to separate authorization from execution.

Use your own manifest when you need custom policy:

```js
import { createGate } from '@emilia-protocol/gate';

const gate = createGate({ manifest, trustedKeys: [ISSUER_PUBKEY_B64U], store: sharedConsumptionStore });
```

## Framework adapters

```js
// 1) Express / Connect route wrapper. The handler is the effect callback;
// Gate owns reservation, execution, consumption, and evidence as one lifecycle.
app.post('/payments', gate.route(
  async (req, res) => res.json(await releasePayment(req.paymentFromSystemOfRecord)),
  {
    selector: { protocol: 'http', method: 'POST', path: '/payments' },
    observedAction: (req) => req.paymentFromSystemOfRecord,
  },
));

// 2) Wrap any function
const release = gate.guard(reallyRelease, {
  selector: () => ({ tool: 'release_payment', protocol: 'mcp' }),
  receipt: (_amount, r) => r,
  observedAction: (amount) => ({
    action_type: 'payment.release',
    amount_usd: amount,
    currency: 'USD',
    payment_instruction_id: 'pi_123',
    beneficiary_account_hash: 'sha256:...',
  }),
});
```

`gate.middleware()` is intentionally deprecated and always refuses: middleware
cannot prove that code after `next()` executed, so consuming a one-time receipt
there would create an authorization-without-effect ambiguity. Use
`gate.route()`, `gate.guard()`, or `gate.run()` for mutations.

## MCP drop-in

Agents live at the MCP tool-call boundary. One wrapper turns a dangerous tool into a
receipt-required one:

```js
import { createTrustedActionFirewall } from '@emilia-protocol/gate';
import { gateMcpTool } from '@emilia-protocol/gate/mcp';

const gate = createTrustedActionFirewall({ trustedKeys: [ISSUER_PUBKEY_B64U], store: sharedConsumptionStore });

server.tool('release_payment', gateMcpTool(
  gate,
  { tool: 'release_payment', observedAction: (args) => paymentSystem.describe(args) },
  async (args) => paymentSystem.release(args),
));
// No valid receipt -> a structured MCP error ({ isError, _emilia.challenge }).
// On success -> the tool result with { _emilia: { execution, reliance } } attached.
```

## System-of-record adapters

Adoption happens where the mutation happens — *"install this before your agent can touch
production."* Each adapter guards the destructive operations of a real system so the mutation never
reaches it without a receipt bound to **this** resource (a receipt for resource A cannot authorize
mutating B). All share one fail-closed contract (`adapters/_kit.js`).

```js
import { createGate } from '@emilia-protocol/gate';
import { createGithubManifest, guardGithubMutation } from '@emilia-protocol/gate/adapters/github';

const gate = createGate({ manifest: createGithubManifest(), trustedKeys: [ISSUER_PUBKEY_B64U], store: sharedConsumptionStore });
await guardGithubMutation(gate, octokit, {
  op: 'repo.delete',                 // | 'permission.change' | 'branch_protection.remove'
  params: { owner: 'acme', repo: 'prod' },
  receipt,                           // throws EMILIA_RECEIPT_REQUIRED if absent/invalid/replayed/drifted
});
```

| Adapter | Import | Guarded ops (assurance) |
|---|---|---|
| **GitHub** | `@emilia-protocol/gate/adapters/github` | repo.delete `class_a`, permission.change `quorum`, branch_protection.remove `class_a` |
| **Stripe** | `@emilia-protocol/gate/adapters/stripe` | payout.create `class_a`, refund.create `class_a`, bank_account.change `quorum` |
| **Supabase / Postgres** | `@emilia-protocol/gate/adapters/supabase` | sql.destructive `class_a`, data.export `class_a`, rls.change `quorum` |
| **AWS (IAM + network)** | `@emilia-protocol/gate/adapters/aws` | iam.attach_policy `quorum`, iam.create_access_key `class_a`, iam.delete_user `class_a`, ec2.authorize_ingress `quorum` |

```js
import { createStripeManifest, guardStripeMutation } from '@emilia-protocol/gate/adapters/stripe';
const gate = createGate({ manifest: createStripeManifest(), trustedKeys: [ISSUER_PUBKEY_B64U], store: sharedConsumptionStore });
await guardStripeMutation(gate, stripe, { op: 'payout.create', params: { amount: 40000, currency: 'usd', destination: 'acct_x' }, receipt });
// Supabase: guardSupabaseMutation(gate, db, { op: 'sql.destructive', params: { sql }, receipt })  // binds the exact statement
// AWS:      guardAwsMutation(gate, client, { op: 'iam.attach_policy', params: { user, policy_arn }, receipt })
```

Clients are injected (the real `@octokit/rest`, `stripe`, a `pg`/Supabase client, or the AWS SDK), so
the adapters are testable without credentials. Adding an adapter is ~40 lines: a frozen action pack
(selectors + tiers + `execution_binding.required_fields`) and an op map (`selector`, `observed(params)`,
`perform(client, params)`) passed to `createAdapter()`.

## Earn EG-1

**EG-1 conformance** answers the only question that matters for adoption: *does your integration
actually enforce the gate, or are you just claiming it?* An integration earns **EG-1 Enforced** only
if it demonstrably passes all eight checks:

1. missing receipt → 428
2. software receipt on a Class-A action → refused
3. observed execution drift → refused
4. valid Class-A / quorum receipt → runs
5. same receipt replay → refused
6. tampered receipt → refused
7. execution proof binds to the authorization decision
8. reliance packet returns verdict `rely`

```js
import { createTrustedActionFirewall, createEg1Harness, gateConformance } from '@emilia-protocol/gate';

const harness = createEg1Harness();
const gate = createTrustedActionFirewall({
  trustedKeys: [harness.publicKey],
  approverKeys: harness.approverKeys,
  rpId: harness.rpId,
  allowedOrigins: harness.allowedOrigins,
  allowEphemeralStore: true, // conformance fixture only
});
const report = await gateConformance({ gate, harness });
// report.passed === true; report.badge === 'EG-1 Enforced'
```

For a custom integration (an HTTP service, another language), provide your own `invoke` to
`runEg1({ invoke, harness })` — it drives the same eight scenarios. `node eg1.mjs` self-certifies the
reference gate and exits non-zero on any failure, so it drops straight into CI. This turns an open PR
into a crisp claim: *"this PR makes `delete_row` earn EG-1."*

## What it adds over a bare verifier

`@emilia-protocol/require-receipt` already does manifest matching, offline verification, and the 428
challenge. The Gate composes that and adds the lifecycle controls a firewall needs:

- **Assurance tiers** — `software` < `class_a` (device signoff) < `quorum` (m-of-n). A `critical`
  action can demand `class_a` or `quorum`; a lower-assurance receipt is refused (`assurance_too_low`).
  In the lightweight EP-RECEIPT-v1 gate, the tier is an issuer-attested claim
  inside a receipt signed by a pinned issuer key. For independent verification
  of every embedded device/quorum signature, use the EP §6.2 trust-receipt
  verifier in `@emilia-protocol/verify`.
- **One-time consumption** — a receipt authorizes one action, once. Replays are refused
  (`replay_refused`). Gate construction requires a durable, ownership-fenced, permanent store.
  The process-local store is available only through explicit `allowEphemeralStore:true` for tests
  and reference demos.
- **Evidence log** — the local logger hash-chains decisions and detects alteration when given its
  complete process history. It is not a fleet ledger: a sink cannot prevent restart-from-genesis or
  cross-replica forks. Safety-critical deployments use `createAtomicEvidenceLog()` over a durable
  backend whose compare-and-append transaction advances one shared head across replicas.
- **Execution-field binding** — for high-risk packs, the signed claim must match the executor's
  observed mutation fields (`amount_usd`, `commit_sha`, `principal_id`, `record_id`, etc.). This
  closes "approved harmless X, executed dangerous Y."
- **Reliance packet** — `gate.reliancePacket()` turns the decision, execution receipt, field binding,
  and evidence head into the compact artifact an auditor, insurer, or investigator can review.
- **Independent coverage evidence** — deployment attestation plus a separately pinned active probe
  can establish a declared surface as `gated`; a passive network witness alone is always
  `witness_only`. Inventory completeness remains an explicit relying-party assumption.

## Formal-to-runtime bridge

Every Gate has an explicit runtime lifecycle monitor. It mirrors the load-bearing
state ordering behind the formal model: authorization must precede the effect,
consumption is one-way, and execution evidence follows the effect attempt. A
divergence emits a bounded `SPEC_DIVERGENCE` event and moves the Gate into
fail-closed safe mode. In safe mode, pass-through is disabled and a receipt must
earn at least Class-A assurance before execution.

```js
import { createRuntimeMonitor, createTrustedActionFirewall } from '@emilia-protocol/gate';

const monitor = createRuntimeMonitor({
  onDivergence: (event) => siem.append(event),
  authorizeRecovery: (request) => operatorApproval.verify(request),
});
const gate = createTrustedActionFirewall({ runtimeMonitor: monitor, /* ... */ });
```

Recovery is explicit and operator-authorized; it never re-authorizes a prior
receipt. The repository's `check:runtime-bridge` gate binds each monitor
theorem to an invariant declared in `formal/ep_handshake.cfg`, so a renamed or
removed formal source cannot silently leave the runtime map stale. This is a
machine-checked coverage binding, not a claim that TLA+ is automatically
compiled into JavaScript: the formal specifications remain the source of the
invariants and the monitor's transition table is covered by its own tests.

## Capability receipts

`capability-receipt.js` adds an issuer-signed capability envelope around an
ordinary EP receipt. The envelope binds a secret preimage, an integer budget,
currency, expiry, a signed delegation chain, and an optional `m-of-n` Shamir
threshold. The envelope's `consumed` field is only an issuance invariant; spend
state lives in an atomic capability store and is never trusted from the bearer
object.

```js
import {
  createMemoryCapabilityStore,
  executeWithCapability,
  mintCapabilityReceipt,
} from '@emilia-protocol/gate/capability-receipt';

const minted = mintCapabilityReceipt(baseReceipt, {
  issuerPrivateKey,
  budget: { amount: 1_000_000, currency: 'USD' },
  expiry: '2026-12-31T00:00:00.000Z',
  scope: {
    profile: CAPABILITY_SCOPE_PROFILE,
    operation_id_field: 'payment_instruction_id',
    action_digests: allowedPaymentActions.map(capabilityActionDigest),
  },
});
const store = createMemoryCapabilityStore(); // tests only; use Postgres in production
store.registerCapability(minted.capabilityReceipt);
await executeWithCapability({
  capabilityReceipt: minted.capabilityReceipt,
  secret: minted.secret,
  action: { amount: 10_000, currency: 'USD' },
  observedAction: actionFromTheSystemOfRecord,
  store,
  gate,
  trustedIssuerKeys: [capabilityIssuerPublicKey],
  operationId: 'provider-idempotency-key',
  executeAction: sendPayment,
});
```

The production adapter requires a transaction callback and locks the capability
state row before reserving budget. If the external effect throws, the reserved
amount is committed as indeterminate; it is never silently reopened. The
capability path is separate from ordinary receipt consumption: the capability
store owns replay and budget state for each explicitly supplied operation ID.
The verifier requires a pinned capability issuer key. Every operation must
match one exact signed action digest, and the caller's stable operation ID must
equal the signed scope's field in the executor-observed action. The same digest
is persisted with the reservation. The separate budget projection must match
the amount and currency in that verified action, and the effect callback
receives a clone of the verified action—not the projection. A new operation ID
therefore cannot relabel the same payment instruction after a timeout.

The built-in `urn:emilia:scope:action-digest-set-v1` profile is exact-byte
scope. `urn:emilia:scope:caid-set-v1` is also supported for interoperable
material-action scope, but only when the deployment supplies its pinned CAID
resolver as `capabilityCaidResolver`; a missing, unknown, or non-matching CAID
fails closed. CAID correlates content here—it does not replace issuer trust,
human authorization, holder proof, or durable budget state.

### Gate-integrated capability enforcement

For an action that must be both human-authorized and budget-limited, pass the
capability store when constructing the Gate and supply a capability to `run()`
or `guard()`:

```js
const gate = createTrustedActionFirewall({
  capabilityStore: postgresCapabilityStore,
  capabilityTrustedIssuerKeys: [capabilityIssuerPublicKey],
  capabilityCaidResolver: resolveWithPinnedCaidRegistry, // for caid-set scopes
  // ...the ordinary Gate trust and durable evidence configuration
});

const result = await gate.run({
  selector: { protocol: 'mcp', tool: 'release_payment' },
  observedAction: actionFromTheSystemOfRecord,
  capability: {
    capabilityReceipt,
    secret,
    action: { amount: 10_000, currency: 'USD' },
    operationId: 'provider-idempotency-key',
  },
}, (authorization, operation) => sendPayment(actionFromTheSystemOfRecord, {
  idempotencyKey: operation.providerIdempotencyKey,
  authorization,
}));
```

The Gate verifies the ordinary receipt first without consuming it, requires the
capability amount and currency to equal the observed action's `amount` or
`amount_usd` and `currency`, checks the signed exact-action scope, reserves the
budget and action digest before calling `sendPayment`, and passes the stable
operation ID to the provider adapter as its idempotency key. A replay,
out-of-scope action, operation relabel, overspend, missing registration, or
envelope mismatch never enters the effect. An exception after the effect begins
commits the amount as `indeterminate` and keeps the operation closed for
authenticated reconciliation. Capability issuer keys are pinned separately
from the ordinary receipt trust list.

Delegation is issuer-authorized and budget-backed: `delegateCapabilityReceipt`
atomically reserves and commits the child budget against the parent before the
child is registered. A failed child registration is reported for
reconciliation; it never creates spendable budget out of thin air. A holder
cannot edit `delegation_chain` or enlarge a child because the issuer signs the
entire envelope.

## Zero-knowledge range receipts

`zk-range-proof.js` provides `EP-ZK-RANGE-RECEIPT-v1`. It uses Bulletproofs over
Ristretto255 to prove a hidden integer `v` satisfies `0 <= v <= max` without
revealing `v` or its blinding factor. The second commitment proves the upper
bound relation `max - v` without relying on a mutable claim. The envelope
binds a public policy hash, predicate, base-receipt digest, issuer key, and
nonce. The ordinary EP receipt signature must still be verified separately.

The cryptographic engine is an explicit optional backend:
`@aptos-labs/confidential-asset-bindings@1.1.2`. It is not pulled into the
default Gate install because its WASM/mobile distribution is large. A
deployment enabling ZK receipts must pin, audit, and pass the backend's own
proof tests. This v1 is a genuine hidden-range proof; it is not a claim that
the repository automatically compiles all TLA+ invariants into R1CS.

## Action Escrow

Action Escrow is the Gate profile for a two-party agreement whose downstream
release must obey the exact final document. The customer application supplies
the signed agreement, material terms, party acceptances, funding evidence,
milestone evidence, and action-specific release approvals. Gate verifies and
binds those inputs, advances a signed lifecycle, and consumes the release once.
Each release approval is a standard `EP-RESOLUTION-v1` WebAuthn record over a
canonical binding moment. Gate independently pins the approval option,
initiator, per-party nonce, evaluation time, exact action digest, and the
document and milestone-evidence digests rendered to the approver.

The public modules are `action-escrow`, `action-escrow-state`,
`action-escrow-postgres`, `action-escrow-custodian`,
`action-escrow-package`, and `action-escrow-verifiers`. A licensed external
provider holds or moves funds; EMILIA does not take custody, inspect work,
adjudicate disputes, or make an agreement legally enforceable. An ambiguous
provider outcome enters reconciliation and is never retried as though nothing
happened.

Construction and contractor integrations use the explicit
`EP-ACTION-ESCROW-CONTRACTOR-TEMPLATE-v1` profile. Build its DAB verifier with
`createActionEscrowContractorDocumentBindingVerifier()` and its portable
six-row package with `assembleActionEscrowContractorEvidencePackage()`. The
package carries the exact project-system sidecar bytes beside the PDF and
re-performs both under relying-party-owned verifiers. A project record is
source evidence only: it cannot fill agreement-acceptance, release-approval,
or custodian-effect rows. The legacy template and package APIs refuse the
contractor profile instead of silently ignoring its project-source binding.
Unmarked project-bound artifacts from the unreleased `0.11.1` preview remain
verifiable only through the contractor package path, including its exact
sidecar and relying-party-owned project-source verifier.

## Production custody

The three things a serious buyer (CISO, auditor, insurer) asks after the demo:

**AEC execution custody.** `createAECExecutionGate()` requires a relying-party requirement,
executor-owned action, explicit human floor, and constructor-pinned custom verifier and key
registries. Transaction input may carry evidence, but never verifier code, trust keys, or human
acceptance profiles; attempts to do so are refused before verification. Production mode additionally refuses an expiring
consumption store or a process-local evidence logger. It consumes
`aec:action:<canonical-action-digest>` before the effect, passes the effect a frozen pre-await action
snapshot, and conservatively burns or freezes the action after an indeterminate result. Every
otherwise identical intended effect therefore needs a unique action-instance nonce inside the
signed action. Use `createAtomicEvidenceLog()` from `@emilia-protocol/gate/evidence`; its backend
must atomically compare and append against one durable shared head. The gate independently
recomputes every logger acknowledgment and requires its entry bytes to equal the requested
decision; the atomic logger also requires readback to equal the exact submitted sequence and
predecessor.

**Issuer key rotation + revocation.** A flat `trustedKeys` list can't revoke a leaked key
or rotate without downtime. A key registry can — a receipt is verified only against keys
valid (and not revoked) at its issuance time. Revocation is fail-closed and immediate.

```js
import { createGate, createKeyRegistry } from '@emilia-protocol/gate';

const registry = createKeyRegistry([
  { kid: 'issuer-1', key: KEY1 },
  { kid: 'issuer-2', key: KEY2, not_before: '2026-07-01T00:00:00Z' }, // rotation window
]);
const gate = createGate({ manifest, keyRegistry: registry, store: sharedConsumptionStore });
registry.revoke('issuer-1'); // compromised — refused immediately, live, no redeploy
```

**Fleet-safe replay defense.** The in-memory store is per-process. In production, back the
consumption store with a shared key-value store whose insert-if-absent, compare-and-set, and
conditional delete operations are atomic:

```js
import { createDurableConsumptionStore } from '@emilia-protocol/gate';
const store = createDurableConsumptionStore(redisBackend); // addIfAbsent + compareAndSet + deleteIfValue + has
const gate = createGate({ manifest, keyRegistry, store });
// A receipt consumed on one pod cannot be replayed on another.
```

Reservations carry an opaque owner token and have no TTL. Only that owner may commit or release;
an abandoned reservation requires reconciliation because automatically reopening it after a crash
could repeat an effect whose response was lost. A TTL may apply only to committed rows.
The Postgres adapter rejects malformed or regressing clocks before expiry-bearing state changes.
The model-based fault gate runs 5,000 generated schedules across crash, lag, rollback, failover,
duplicate delivery, and before/after-linearization response loss; see
`security/CONSUMPTION_FAULT_STATUS.md`.

**Evidence retention.** Classify the evidence log into hot/cold/expired with legal hold, and
export the auditor/SIEM manifest (tied to the evidence head). `EP_AUDIT_HOT_DAYS` /
`EP_AUDIT_COLD_DAYS` set the horizons.

```js
gate.retention({ hotDays: 365, coldDays: 2190, legalHold: ['<evidence-hash>'] });
gate.retentionExport();  // EP-GATE-RETENTION-EXPORT-v1 manifest
```

Issuer-side **KMS/HSM signing custody** (production mode refuses dev-local private keys) lives in
EP core (`lib/key-custody.js`, `assertProductionKeyCustody` / `createExternalCustodySigner`).

## Boundary

EMILIA Gate does not stop every bad actor. It makes **legitimate infrastructure refuse unreceipted
consequential actions by default**, so the parties with leverage (clouds, payment rails, regulators,
insurers) can *require* a receipt — and "no receipt" becomes like "no TLS cert" or "unsigned binary":
not always illegal, just untrusted. Necessary, not sufficient.

## Standards

The mechanism is specified in `draft-schrock-ep-enforcement-point` (the Receipt-Required rail) over
`draft-schrock-ep-authorization-receipts`. Earn the **RR-1** conformance level via
`receiptRequiredConformance()` in `@emilia-protocol/require-receipt`. Reference implementation;
experimental. Apache-2.0. Fails closed.
