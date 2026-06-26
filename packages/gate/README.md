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
node --test        # 10 tests
node demo.mjs       # end-to-end: passthrough -> 428 -> too-low -> allow -> replay -> tamper
```

## Use it

```js
import { createGate } from '@emilia-protocol/gate';

const gate = createGate({
  manifest,             // EP-ACTION-RISK-MANIFEST-v0.1: which actions are guarded + their tier
  trustedKeys: [ISSUER_PUBKEY_B64U],   // pin the issuers you trust
  maxAgeSec: 900,
});

// 1) Framework-agnostic check
const out = await gate.check({ selector: { protocol: 'mcp', tool: 'release_payment' }, receipt });
if (!out.allow) throw out.challenge;   // 428 Receipt-Required

// 2) Express / Connect middleware
app.post('/payments', gate.middleware({ action: 'payment.release' }), handler);

// 3) Wrap any function
const release = gate.guard(reallyRelease, { selector: () => ({ tool: 'release_payment', protocol: 'mcp' }), receipt: (args, r) => r });
```

## What it adds over a bare verifier

`@emilia-protocol/require-receipt` already does manifest matching, offline verification, and the 428
challenge. The Gate composes that and adds the three things a firewall needs:

- **Assurance tiers** — `software` < `class_a` (device signoff) < `quorum` (m-of-n). A `critical`
  action can demand `class_a` or `quorum`; a lower-assurance receipt is refused (`assurance_too_low`).
- **One-time consumption** — a receipt authorizes one action, once. Replays are refused
  (`replay_refused`). Default store is in-memory; swap in Redis/DB for a fleet.
- **Evidence log** — every decision is hash-chained (`evidence.verify()` detects any alteration).
  This is the compliance / insurance artifact.

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
