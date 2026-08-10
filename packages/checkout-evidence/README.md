# Agentic checkout evidence (experimental)

`@emilia-protocol/checkout-evidence` builds one neutral, independently
replayable packet joining:

1. the complete structured checkout terms;
2. the structured summary presented for approval;
3. an authorization artifact bound to that presentation and action;
4. the exact action observed at the payment boundary; and
5. the one-time consumption record.

It also captures the four compact AP2 v0.2 artifacts used by AP2's own dispute
verification procedure. AP2 verification remains native: callers must supply an
AP2 verifier and its trust anchors. EMILIA does not reinterpret AP2 signatures,
selective disclosures, constraints, or receipts.

## Why this is a separate action profile

The existing CAID `payment.release.1` identifies release of a payment
instruction to settlement. It does not bind line items, quantities, tax,
shipping, recurrence, or the approval presentation. This package therefore
uses a local experimental `commerce.purchase.submit.1` definition whose
`checkout_digest` commits to the whole structured checkout. It is not added to
the public CAID registry until the field set survives integration review.

## Verdicts

- `VERIFIED`: packet integrity and every configured required native verifier
  succeeded.
- `INVALID`: content, action, presentation, effect, consumption, or required
  native verification conflicts.
- `INDETERMINATE`: required evidence or a verifier is unavailable, or the
  payment effect is unknown.

`INDETERMINATE` never authorizes a retry.

## Deliberate limits

This package does **not** claim that:

- the purchase was legally authorized under Regulation E, Regulation Z, state
  agency law, or a cardholder agreement;
- the packet satisfies Visa, Mastercard, a processor, or an issuer's current
  dispute rules;
- a merchant will win a chargeback;
- goods were delivered or were as described; or
- the packet is PCI storage. Raw PAN, CVV/CVC, and similar fields are refused.

The output is a source dossier. A later processor adapter may map accepted
facts into the processor's current reason-code-specific evidence fields, but it
must not relabel unsupported fields as network-approved evidence.

## Minimal use

```js
import {
  buildPurchaseAction,
  buildStructuredPresentation,
  createCheckoutEvidencePacket,
  verifyCheckoutEvidencePacket,
} from '@emilia-protocol/checkout-evidence';
import { captureAp2V02Evidence } from '@emilia-protocol/checkout-evidence/ap2';

const built = buildPurchaseAction({ checkoutTerms, paymentInstructionId });
const presentation = buildStructuredPresentation({
  checkoutTerms,
  action: built.action,
  actionCaid: built.action_caid,
});

const packet = createCheckoutEvidencePacket({
  createdAt,
  checkoutTerms,
  paymentInstructionId,
  presentation,
  authorization,
  execution,
  consumption,
  nativeEvidence: [captureAp2V02Evidence(ap2Artifacts)],
});

const result = await verifyCheckoutEvidencePacket(packet, {
  verifyAuthorization,
  verifyExecution,
  verifyConsumption,
  nativeVerifiers: { 'ap2-v0.2': verifyAp2 },
});
```

The package is private and experimental in v0. It is a falsifiable integration
surface, not a public card-network compatibility claim.
