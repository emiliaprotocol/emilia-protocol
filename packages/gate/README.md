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

Prefer `gate.run(...)` for mutations: it reserves the receipt, runs the side effect, commits
one-time consumption only after success, releases the reservation if the action fails before
mutation, and emits the execution receipt + reliance packet. Use lower-level `gate.check(...)` only
when your framework has to separate authorization from execution.

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
production."* The GitHub adapter guards destructive Octokit calls so the mutation never reaches
GitHub without a receipt bound to **this** repo:

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
- **One-time consumption** — a receipt authorizes one action, once. Replays are refused
  (`replay_refused`). Default store is in-memory; swap in Redis/DB for a fleet.
- **Evidence log** — every decision is hash-chained (`evidence.verify()` detects any alteration).
  This is the compliance / insurance artifact.
- **Execution-field binding** — for high-risk packs, the signed claim must match the executor's
  observed mutation fields (`amount_usd`, `commit_sha`, `principal_id`, `record_id`, etc.). This
  closes "approved harmless X, executed dangerous Y."
- **Reliance packet** — `gate.reliancePacket()` turns the decision, execution receipt, field binding,
  and evidence head into the compact artifact an auditor, insurer, or investigator can review.

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
