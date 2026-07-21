<!-- SPDX-License-Identifier: Apache-2.0 -->
# Receipt Required — Conformance & Badge

A "Receipt Required compliant" claim only means something if anyone can re-run
the check. This defines what the badge asserts and how to earn it. Don't trust
the badge — run the harness.

[![Receipt Required: RR-1](https://img.shields.io/badge/Receipt%20Required-RR--1-22c55e)](https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/RECEIPT-REQUIRED-CONFORMANCE.md)

## Level RR-1

A tool endpoint is **RR-1 conformant** for a receipt-required action when all of
the following hold (see [RECEIPT-REQUIRED.md](RECEIPT-REQUIRED.md) for the wire
details):

1. **manifest_valid** — the service publishes a valid `EP-ACTION-RISK-MANIFEST-v0.1`
   at `/.well-known/agent-actions.json` declaring the action.
2. **challenge_on_missing** — a call with no receipt returns a Receipt Required
   challenge (`428`, or legacy `402`) carrying the `required` action block.
3. **runs_on_valid** — a valid, action-bound `EP-RECEIPT-v1` lets the action run.
4. **replay_refused** — presenting the *same* receipt again is refused
   (one-time consumption).
5. **forged_refused** — a receipt with an altered signed field is refused.

## Level RR-2 (acquisition profile)

RR-2 is additive to RR-1. It requires a valid Action Control v0.2 manifest with
the acquisition extension, strict HTTP problem details, an exact out-of-band
authorization-endpoint pin, parameter/action-digest binding, durable
idempotency, separate approval and polling capabilities, Class-A/quorum
terminal evidence, and no receipt on non-approved states. Selector ambiguity,
cross-tenant lookup, endpoint substitution, changed-idempotency replay,
unsigned evidence, and CAID/action substitution must all refuse.

The repository does not ship an RR-2 badge merely because these source tests
pass. An RR-2 claim requires the black-box acquisition and gateway suites
against an exact deployed endpoint/runtime digest. Until then the profile is a
tested reference implementation, not deployment certification.

The repository's reference server currently exercises RR-2 only for the
server-controlled `payment.release` Class-A profile. This is not a universal
acquisition claim: unsupported Action Control entries omit the authorization
descriptor and remain RR-1 challenge/enforcement surfaces.

## Earn it — run the harness

The check is shipped in `@emilia-protocol/require-receipt` and is **not** a
self-assertion: it probes your real dispatcher.

```js
import { receiptRequiredConformance } from '@emilia-protocol/require-receipt';

const report = await receiptRequiredConformance({
  dispatch: yourGuardedCallTool,        // (name, args, receipt) -> { status, body }
  tool: 'release_payment',
  action: 'payment.release',
  issueReceipt: () => mintTestReceipt('payment.release'), // a receipt your server accepts
  manifest: yourActionRiskManifest,
});

console.log(report.level, report.passed, report.checks);
// RR-1 true { manifest_valid: true, challenge_on_missing: true,
//             runs_on_valid: true, replay_refused: true, forged_refused: true }
```

If `report.passed` is true you may display the badge. EMILIA's own example
servers are held to this in CI (`tests/receipt-required-conformance.test.ts`),
so the reference implementations can never silently fall out of conformance.

## Claim the badge

Add to your README once the harness passes:

```md
[![Receipt Required: RR-1](https://img.shields.io/badge/Receipt%20Required-RR--1-22c55e)](https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/RECEIPT-REQUIRED-CONFORMANCE.md)
```

The badge links here so anyone can read what it means and re-run the check. A
badge with no passing harness behind it is just a sticker — that's the opposite
of the point.
