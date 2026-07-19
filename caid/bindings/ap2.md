<!-- PRIVATE. PR-ready text only. NOT submitted anywhere. Gated on Iman's word. -->
# Binding: Google AP2 (Agent Payments Protocol)

Target: AP2, "an open protocol for the emerging Agent Economy"
(https://ap2-protocol.org/). Per the same page, Google announced the
protocol on 2025-09-16 and "has donated it to the FIDO Alliance for
standards development."

Terminology note (grounded): the task brief for this note referenced
"Intent Mandate" and "Cart Mandate". The spec published at
ap2-protocol.org as fetched on 2026-07-08 defines exactly two mandate
types, Checkout Mandate and Payment Mandate, and the glossary
(https://ap2-protocol.org/glossary/) defines neither an Intent Mandate
nor a Cart Mandate. This note therefore uses the current published
terms. The Checkout Mandate covers the cart role (the finalized
merchant-signed order contents) and the open-stage mandates cover the
intent role (pre-finalization constraints).

## 1. How AP2 binds approval to mandates (grounded summary)

Every claim below is anchored to fetched text.

- Two mandate types. "The Checkout Mandate is a Mandate used for
  authorizing the completion of a checkout"
  (https://ap2-protocol.org/ap2/checkout_mandate/). "The Payment
  Mandate is a Mandate used for authorizing the payment for a
  particular checkout" (https://ap2-protocol.org/ap2/payment_mandate/).

- Mandates are SD-JWT verifiable credentials. A Verifiable Digital
  Credential is "an Issuer-signed credential (i.e., a set of Claims)
  whose authenticity can be verified"
  (https://ap2-protocol.org/glossary/). The closed Checkout Mandate's
  `vct` field is the "Verifiable Credential Type claim as defined in
  SD-JWT" (https://ap2-protocol.org/ap2/checkout_mandate/), and "Each
  AP2 Mandate type identifies its schema using the `vct` claim" with
  versioned names such as `mandate.payment.1`
  (https://ap2-protocol.org/ap2/specification/).

- The cart contents live in a merchant-signed JWT. "The Merchant MUST
  provide a merchant-signed JWT containing the Checkout to the
  Shopping Agent" (https://ap2-protocol.org/ap2/specification/). The
  closed Checkout Mandate carries it as `checkout_jwt`, the
  "base64url-encoded serialized merchant-signed JWT of the Checkout
  payload" (https://ap2-protocol.org/ap2/checkout_mandate/).

- Approval binds to the cart by hash. "The closed Checkout Mandate is
  bound to this Checkout JWT using a cryptographic hash"; verification
  must "Verify that the hash of the Checkout JWT sent for approval
  matches the value included for the `checkout_hash` claim"
  (https://ap2-protocol.org/ap2/specification/). `checkout_hash` is
  the "base64url-encoded hash of the checkout_jwt field value,
  uniquely identifying this checkout"
  (https://ap2-protocol.org/ap2/checkout_mandate/).

- The Payment Mandate joins on the same hash. "The Payment Mandate is
  bound to a particular Checkout using the cryptographic hash of the
  Checkout JWT" (https://ap2-protocol.org/ap2/specification/); its
  `transaction_id` is the "base64url-encoded hash of the checkout_jwt
  field value, uniquely identifying the checkout"
  (https://ap2-protocol.org/ap2/payment_mandate/).

- User approval happens on a Trusted Surface: "A secure, non-agentic
  interface that renders Mandate Content to the User for authorization
  and consent" (https://ap2-protocol.org/glossary/). In human-present
  flows "the User directly signs closed Mandate Content"; in
  human-not-present flows "the User signs open Mandate Content. The
  Agent then signs closed Mandate Content on the user's behalf, and
  provides the entire Mandate chain to demonstrate the authorization"
  (https://ap2-protocol.org/ap2/agent_authorization/).

- Disputes are an explicit design goal. "A primary objective is to
  provide supporting evidence that helps payment networks establish
  accountability and liability principles", and "Transactions must be
  anchored to deterministic, non-repudiable proof of intent from all
  parties, such as the user-signed Checkout Mandate"
  (https://ap2-protocol.org/faq/).

Net: AP2's internal join key is `checkout_hash`, a hash over a signed
envelope (the merchant's Checkout JWT), not over typed canonical
content. Every artifact that wants to reference the transaction must
hold or hash that AP2-specific JWT.

## 2. Where a CAID goes

Define an action type for the finalized order, e.g. `order.place.1`
(registered, or local definitions in the same schema; presence based,
per DESIGN.md section 3):

- `merchant_id` (string): the merchant identity from the Checkout
  payload (the checkout_jwt "contains order details including merchant
  identity, line items with product IDs/titles, prices, currency",
  https://ap2-protocol.org/ap2/checkout_mandate/).
- `line_items` (array): product id, title, quantity, unit price as
  amount-string, per item.
- `total_amount` (amount-string): AP2's `payment_amount` carries
  "currency (ISO 4217) and amount in minor units"
  (https://ap2-protocol.org/ap2/payment_mandate/); the issuer maps
  minor units to a decimal string using the ISO 4217 exponent, stated
  in `digest_notes` (normalization is the issuer's job, DESIGN.md
  section 2).
- `currency` (enum, ISO 4217 alpha-3).
- `checkout_id` (string): the merchant's order identifier from the
  Checkout payload.

The issuing side (Shopping Agent or merchant surface) extracts these
fields from the Checkout payload it already has, computes
`caid:1:order.place.1:jcs-sha256:<digest>`, and carries the string
ALONGSIDE the mandate: as an additional claim next to `checkout_hash`
where AP2 schema rules permit extension claims, or, with zero spec
changes, in each party's own transaction records keyed to the mandate.
CAID does not replace `checkout_hash` and must not: `checkout_hash`
binds the exact signed envelope inside AP2's trust chain; the CAID
names the typed order content so artifacts OUTSIDE that chain (an
insurer's agent-liability object, a compliance audit record, an
EMILIA-style authorization receipt, a merchant ERP entry) can join on
the same identifier without holding or parsing the JWT. Incidental
harmony: AP2's `vct` values (`mandate.payment.1`,
https://ap2-protocol.org/ap2/specification/) already use the same
lowercase dotted versioned grammar as CAID action types.

## 3. What an AP2 adopter gains unilaterally

Dispute evidence keyed by a portable identifier. AP2's stated goal is
"supporting evidence that helps payment networks establish
accountability and liability principles"
(https://ap2-protocol.org/faq/), but its join key is the hash of an
AP2-specific JWT: a chargeback processor, insurer, or regulator that
is not an AP2 participant cannot recompute or interpret
`checkout_hash` without the JWT and AP2 tooling. A CAID on the same
transaction is recomputable by any party holding the plain action
object, in ~200 lines of any language, with no AP2 stack, no FIDO
membership, and no SD-JWT parsing. Second, material-fields validation:
`checkout_hash` binds whatever bytes the JWT contained; computing a
CAID under `order.place.1` fails closed unless the referenced content
actually names merchant, items, amount, and currency, which hardens
the adopter's own dispute file against the "digest over
{action:'wire'} binds nothing" failure (DESIGN.md, design goal 1).
This value exists with zero other adopters.

## 4. PR-ready pitch (NOT submitted; gated)

Proposal: carry an optional Canonical Action IDentifier (CAID)
alongside the Checkout Mandate. A CAID is a typed content digest
(caid:1:order.place.1:jcs-sha256:...) computed over the order's
material fields (merchant, line items, amount, currency) under RFC
8785 JCS + SHA-256. It carries no trust semantics: it is not
authorization, not identity, and it does not touch or replace
checkout_hash, which continues to bind the merchant-signed Checkout
JWT inside AP2's trust chain. What it adds is a join key that parties
outside that chain can use: insurers, auditors, and dispute processors
can reference the exact typed order content and recompute the digest
without holding the JWT or joining the AP2 network, and each artifact
still verifies in its own trust boundary. Cost of adoption is one
optional field and a ~200-line issuer; the type registry is CC0 and
private deployments can carry local type definitions in the same
format.

## Status

Grounded note only, all quotes fetched 2026-07-08 from
ap2-protocol.org. No PR, issue, or contact opened. Filing anything is
gated on Iman's word.
