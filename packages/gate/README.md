# @emilia-protocol/gate — EMILIA Gate

**The Trusted Action Firewall.** Deny-by-default enforcement for consequential machine actions.

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

const gate = createGate({ manifest, trustedKeys: [ISSUER_PUBKEY_B64U] });
```

## Framework adapters

```js
// 1) Express / Connect middleware
app.post(
  '/payments',
  gate.middleware({
    selector: { protocol: 'http', method: 'POST', path: '/payments' },
    observedAction: (req) => req.paymentFromSystemOfRecord,
  }),
  handler,
);

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

## MCP drop-in

Agents live at the MCP tool-call boundary. One wrapper turns a dangerous tool into a
receipt-required one:

```js
import { createTrustedActionFirewall } from '@emilia-protocol/gate';
import { gateMcpTool } from '@emilia-protocol/gate/mcp';

const gate = createTrustedActionFirewall({ trustedKeys: [ISSUER_PUBKEY_B64U] });

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

const gate = createGate({ manifest: createGithubManifest(), trustedKeys: [ISSUER_PUBKEY_B64U] });
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
const gate = createGate({ manifest: createStripeManifest(), trustedKeys: [ISSUER_PUBKEY_B64U] });
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
const gate = createTrustedActionFirewall({ trustedKeys: [harness.publicKey] });
const report = await gateConformance({ gate, harness });
// report.passed === true; report.badge === 'EG-1 Enforced'
```

For a custom integration (an HTTP service, another language), provide your own `invoke` to
`runEg1({ invoke, harness })` — it drives the same eight scenarios. `node eg1.mjs` self-certifies the
reference gate and exits non-zero on any failure, so it drops straight into CI. This turns an open PR
into a crisp claim: *"this PR makes `delete_row` earn EG-1."*

## What it adds over a bare verifier

`@emilia-protocol/require-receipt` already does manifest matching, offline verification, and the 428
challenge. The Gate composes that and adds the three things a firewall needs:

- **Assurance tiers** — `software` < `class_a` (device signoff) < `quorum` (m-of-n). A `critical`
  action can demand `class_a` or `quorum`; a lower-assurance receipt is refused (`assurance_too_low`).
  In the lightweight EP-RECEIPT-v1 gate, the tier is an issuer-attested claim
  inside a receipt signed by a pinned issuer key. For independent verification
  of every embedded device/quorum signature, use the EP §6.2 trust-receipt
  verifier in `@emilia-protocol/verify`.
- **One-time consumption** — a receipt authorizes one action, once. Replays are refused
  (`replay_refused`). Default store is in-memory; swap in Redis/DB for a fleet.
- **Evidence log** — the local logger hash-chains decisions and detects alteration when given its
  complete process history. It is not a fleet ledger: a sink cannot prevent restart-from-genesis or
  cross-replica forks. Safety-critical deployments use `createAtomicEvidenceLog()` over a durable
  backend whose compare-and-append transaction advances one shared head across replicas.
- **Execution-field binding** — for high-risk packs, the signed claim must match the executor's
  observed mutation fields (`amount_usd`, `commit_sha`, `principal_id`, `record_id`, etc.). This
  closes "approved harmless X, executed dangerous Y."
- **Reliance packet** — `gate.reliancePacket()` turns the decision, execution receipt, field binding,
  and evidence head into the compact artifact an auditor, insurer, or investigator can review.

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
const gate = createGate({ manifest, keyRegistry: registry });
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
