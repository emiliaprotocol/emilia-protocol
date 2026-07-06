<!-- SPDX-License-Identifier: Apache-2.0 -->
# Multi-party authorization (the two-person rule) for AP2 mandates

*A proposed, additive extension — offered as a neutral, Apache-2.0 reference, not a product.*
*Draft for posting to the AP2 community (GitHub Discussions on google-agentic-commerce/AP2, and/or the FIDO Alliance agentic-payments work).*

## The gap

AP2 represents an agent purchase as three signed mandates — Intent, Cart, Payment —
each a **single** principal's authorization (the user signs intent/cart; the merchant
co-signs the cart). That is exactly right for consumer commerce.

It does not yet express the control that governs the *highest-value* transactions in
enterprise, treasury, and public-sector commerce: **more than one distinct, accountable
human must authorize before the action proceeds.** Examples an agentic future will hit
immediately:

- a corporate procurement agent committing a cart above a delegated threshold (two
  approvers, by policy);
- a treasury agent moving funds (dual control — the maker/checker rule);
- a government disbursement or release-authority agent (an ordered chain: program
  officer → authorizing official → inspector general).

Today an AP2 deployment can only model this out-of-band, in the merchant's or operator's
own system — which puts the multi-party control back inside the party whose conduct an
auditor would examine, and breaks the non-repudiation guarantee AP2 worked to establish.

## The proposal: a quorum profile, additive over mandates

Add an **optional multi-party profile** in which a mandate (typically the Cart Mandate)
is satisfied by a **quorum** of distinct human signatures over the *same* cart/action,
rather than one. Concretely:

- **N distinct signers**, each producing a standard AP2/WebAuthn user signature over the
  same cart hash (no new signature type, no new cryptography);
- a **fail-closed predicate** the verifier evaluates: all signatures valid · each bound
  to the same cart/action · signers pairwise **distinct** (separation of duties) · each
  an **admitted role** on the policy roster · **threshold met** (M-of-N) · optional
  **order** respected · all within a bounded **time window**;
- **degenerate case = today's AP2**: a quorum of one is the current single-signer mandate,
  so the extension is strictly additive and backward-compatible.

Because each member is just another verifiable signature over the existing cart, AP2's
non-repudiation and dispute-attribution properties extend naturally: the audit trail now
shows *which named humans* authorized, in what order, bound to the exact cart.

## Why this is offered, and by whom

This is the open multi-party authorization profile we maintain as **EP-QUORUM** in the
EMILIA Protocol:

- a posted IETF Internet-Draft, `draft-schrock-ep-quorum` (companion to
  `draft-schrock-ep-authorization-receipts`);
- a peer-citable preprint (Zenodo, CC-BY);
- **three cross-language reference verifiers** (JavaScript, Python, Go) that agree on the
  predicate, plus **nine adversarial conformance vectors** (under-threshold, duplicate
  human, out-of-order, action-mismatch, expired-window, bad-signature, wrong-role);
- all Apache-2.0.

We are not proposing AP2 adopt EMILIA. We are offering the predicate, the conformance
vectors, and the reference verifiers as raw material for an AP2/FIDO multi-party profile —
the same way the single-signer mandate already leans on WebAuthn/FIDO.

## What it does and does not provide (stated plainly)

A satisfied quorum proves N distinct enrolled humans each signed the exact cart, in order
where required, with their own device keys, and that no orchestrator forged any of them.
It does **not** defeat collusion among the required number of humans, one human controlling
multiple enrolled identities (an enrollment-layer concern), or coercion of a full quorum —
it makes those events *attributable*, not impossible. We would rather state that bound than
overclaim a control this consequential.

## The question for the working group

Is multi-party authorization in scope for AP2 / the FIDO agentic-payments work? If so, we
will contribute a profile draft + the conformance vectors and help align it with the
mandate model. If it belongs as a separate composable layer, that is fine too — the point
is that the highest-value agent commerce needs it, and the rigor already exists in the open.

---
*References (resolve by name): AP2 spec — ap2-protocol.org/specification ; AP2 repo —
google-agentic-commerce/AP2 ; EP-QUORUM I-D — datatracker.ietf.org/doc/draft-schrock-ep-quorum/ ;
EMILIA verifiers + vectors — github.com/emiliaprotocol/emilia-protocol (packages/verify,
conformance/vectors/quorum.v1.json). Contact: Iman Schrock · team@emiliaprotocol.ai*
