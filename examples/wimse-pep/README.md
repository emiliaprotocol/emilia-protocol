# WIMSE PEP: a per-action human-authorization obligation

**One idea:** at a WIMSE Policy Enforcement Point, after the workload identity is
already authenticated by WIMSE, apply one extra obligation for the irreversible /
high-consequence subset of actions: verify an EMILIA authorization receipt bound
to the exact action. The receipt is a per-action human-authorization obligation
the PEP enforces on top of WIMSE workload identity and delegation.

This maps directly onto `draft-ietf-wimse-arch-08`:

- **Section 3.3 (PEP/PDP).** The PEP allows, blocks, or applies obligations on a
  request based on the already-authenticated context. `enforceHumanAuthorizationObligation`
  is one such obligation.
- **Section 3.4.11 (AI/ML intermediaries).** A delegated agent operates within a
  standing delegation. Delegation says the agent MAY act. This obligation says a
  named human authorized THIS specific consequential action, evaluated at the
  enforcement point. Delegation is necessary but not sufficient for the
  consequential subset; the receipt is the sufficiency proof.

## The whole obligation (~30 lines)

It calls EP's real offline verifier (`verifyEmiliaReceipt` from
`@emilia-protocol/require-receipt`) over a relative path, so it runs from a fresh
clone with only Node. It is fail-closed: `allow=true` only when the receipt
verifies against a **pinned** issuer key, binds the **exact** action, and is
inside its **validity window**. Every other outcome is `allow=false` with a
precise reason (`missing_receipt`, `wrong_issuer_key`, `action_mismatch`,
`expired`, `malformed_receipt`, ...).

```js
import { verifyEmiliaReceipt } from '../../packages/require-receipt/index.js';

export function enforceHumanAuthorizationObligation({ action, presentedReceipt, pinnedIssuerKeys, now = Date.now(), maxAgeSec = 900 }) {
  if (!action) return { allow: false, reason: 'no_action_specified' };
  if (!Array.isArray(pinnedIssuerKeys) || pinnedIssuerKeys.length === 0) return { allow: false, reason: 'no_pinned_issuer_keys' };
  if (!presentedReceipt) return { allow: false, reason: 'missing_receipt' };

  const v = verifyEmiliaReceipt(presentedReceipt, { trustedKeys: pinnedIssuerKeys, action, maxAgeSec });
  if (v.ok) return { allow: true, reason: 'authorized', receipt_id: v.receipt_id, subject: v.subject };

  const REASON = {
    malformed_receipt: 'malformed_receipt',
    payload_outside_ijson_profile: 'malformed_receipt',
    bad_signature_encoding: 'malformed_receipt',
    no_trusted_keys_configured: 'no_pinned_issuer_keys',
    untrusted_or_invalid_signature: 'wrong_issuer_key',
    receipt_expired: 'expired',
    action_mismatch: 'action_mismatch',
    outcome_not_accepted: 'outcome_not_accepted',
  };
  return { allow: false, reason: REASON[v.reason] || v.reason, detail: v.detail };
}
```

## Run it

```zsh
node examples/wimse-pep/demo.mjs
node examples/wimse-pep/self-test.mjs
```

`demo.mjs` mints demo receipts inline with the real EP signing/canonicalization
path (Ed25519 over JCS-canonical JSON) using a throwaway in-memory key, then
drives one already-authenticated WIMSE workload identity through four requests:

```
ALLOW  (a) valid workload identity WITH a valid human-authorization receipt
DENY   (b) same valid workload identity but NO receipt (delegation alone)
DENY   (c) receipt bound to a DIFFERENT action (action_mismatch)
DENY   (d1) receipt signed by an UNPINNED issuer key (wrong_issuer_key)
DENY   (d2) receipt from the pinned issuer but EXPIRED (expired)
```

`self-test.mjs` asserts those decisions (plus a tampered receipt and the
misconfiguration cases) and exits non-zero on any mismatch.

## What this is NOT

- **It does not replace WIMSE workload identity or delegation.** The workload
  identity (WIT/WIC) is assumed already authenticated by WIMSE upstream; this is
  one additional obligation the PEP applies, in the Section 3.3 sense. It is a
  composition, not a competing model.
- **The receipt does not authorize by itself.** EP proves a named human
  authorized the action and that the evidence is integrity-protected. That is
  necessary, not sufficient, for a safe execution. WIMSE still decides which
  workload acts under which principal's standing authority.
- **The receipt is authorization evidence, not a bearer capability.** It binds
  one exact action, so a leaked copy grants nothing beyond that single action it
  already names, and it carries no standing authority. Replaying that same action
  is refused once the Gate consumes the receipt. This example is the verification
  obligation only and does not itself consume, so pair it with
  `@emilia-protocol/gate` for one-time consumption, assurance tiers, and the
  evidence log. Note also that the receipt carries no holder or channel binding
  on its own; the Gate, or a WIMSE PoP binding, is what ties presentation to a
  specific caller.
- **This is minimal by design.** A production PEP would additionally bind
  execution parameters (amount, beneficiary) against the system of record and
  enforce an assurance tier. `@emilia-protocol/gate` does all of that; this file
  is the smallest honest slice that shows a WIMSE implementer the shape.

## Honesty note on the verifiers

The in-repo JS/Python/Go verifiers this example uses are **one repo's consistency
check**, not independent implementations of the spec. An independent COSA
reimplementation is underway; until it lands, treat cross-language agreement here
as a self-consistency property of this codebase.

Apache-2.0 · part of [EMILIA Protocol](https://www.emiliaprotocol.ai)
