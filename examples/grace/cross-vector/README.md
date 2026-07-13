<!-- SPDX-License-Identifier: Apache-2.0 -->
# Verifiable curtailment, the cross-vector: EP's WHO leg

Working material for the joint vector set proposed on the coalition thread
(2026-07-12): one action threaded through an AAC Class-1 capsule as WHAT and an
EP-RECEIPT as WHO, joined by a shared subject digest and `human_authorization_ref`;
positives accept on both sides, negatives reject at the right stage.

This directory is EP's half, committed so counterparties can bind to stable bytes.

## The committed sample

`ep-receipt.sample.json` carries a signed EP-RECEIPT-v1 for one curtailment-shaped
action (`grid.curtailment.shed`, 12 MW, a bounded window, the demand carried as an
opaque digest), plus the pinned verification keys and the policy. Verify it:

```bash
node examples/grace/cross-vector/verify-sample.mjs
```

Offline, no service, no account. It prints the two join fields and runs the two
EP-side negatives from the joint set:

- **subject digest** = the receipt's `action_hash` (SHA-256 over the RFC 8785
  canonical action). The capsule (WHAT) and any third attestor claim (the meter,
  per the composition-level ruling on the flagship thread) bind this same digest.
- **`human_authorization_ref`** = `{ receipt_id, action_hash }`.
- **wrong-action splice**: the 12 MW approval presented for a 45 MW shed refuses.
- **unsigned rely**: the reliance verdict flips from `rely` to
  `do_not_rely_unsigned` when the receipt is withheld.

`make-ep-who-sample.mjs` regenerates the sample under fresh keys; the committed
file is the stable one to bind against. `capsule_id` mismatch is a WHAT-side
negative and lives with the capsule's verifier, not here.

## Claim boundary

This is EP's leg only. The demand (CAN), execution and metered outcome (WHAT),
and the transparency record verify in their own trust boundaries under their own
verifiers; legs join by digest equality and never by one verifier ingesting
another's evidence. A passing WHO leg proves a named human's signature covered
this exact shed before it ran. It does not prove the demand was lawful, the shed
happened, the meter is honest, or that any relying party must accept the packet.
The full runnable composition (order, gate, shed, meter, settlement, adversarial
refusals) is one directory up: `python3 examples/grace/proof_of_curtailment.py`.
