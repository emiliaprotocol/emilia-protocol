<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP profile as ATTP's human-intent evidence input (draft-sharif-attp)

**Status:** individual profile, offered as input to the Agent Trust Transport Protocol
(`draft-sharif-attp`, R. Sharif). ATTP scopes intent and consent out of its own document
and calls for them to be supplied by an additional mechanism. This profile shows how an EP
receipt is exactly that mechanism, taken as one input to an ATTP trust decision and joined
on the action ATTP already signs. EP does not touch ATTP's trust scoring, action limits,
or compliance gating.

**Anchor (against the current draft).** The Security Considerations state: a valid
signature "does not, by itself, establish that the action was authorised by a human, free
of coercion, or produced on an uncompromised host. Establishing intent or consent is out of
scope for this document and, where required, MUST be provided by an additional mechanism
(for example, a human-presence attestation bound to the action)." The abstract frames ATTP
as answering "should this agent be allowed to perform this action, at this magnitude,
against this counterparty, right now?" across five progressive trust levels (L0 to L4) with
action-limit tiers. This profile fills the additional-mechanism slot for the intent/consent
input to that decision.

**Grounded in running code.** Every EP claim below is the behavior of the filed drafts and
their reference verifiers (`packages/verify/`, JavaScript/Python/Go, public accept/refuse
vectors): `draft-schrock-ep-authorization-receipts`, `draft-schrock-ep-quorum`.

## The one input ATTP scopes out, supplied

| ATTP decision element | EP contribution | Honest scope |
|---|---|---|
| **intent / consent** (out of scope, "MUST be provided by an additional mechanism, e.g. a human-presence attestation bound to the action") | An EP receipt: proof that the human behind the agent authorized this exact action, offline-verifiable against a pinned key, bound to the action by a canonical digest. Precisely a human attestation bound to the action. | EP proves a named human approved this exact action. It does not score the agent, screen the counterparty, or judge magnitude; those stay ATTP's. |
| **action, at this magnitude** (L0 to L4 tiers) | The relying party requires an EP receipt only above the magnitude tier where human intent is demanded; routine low-tier actions clear on ATTP's own trust score. The receipt is the evidence for the tier that needs a human, and nothing changes below it. | EP is a per-action gate for the high-magnitude subset, not a tax on every call. |
| **freedom from coercion / uncompromised host** | Out of EP's scope too, and EP says so. A device-bound user-verification ceremony raises the bar; it does not prove coercion-freedom or host integrity. | Neither ATTP nor EP claims to solve coercion or host compromise; the profile does not paper over it. |
| **not identity** | EP is human authorization, not agent identity. It composes with ATTP's per-agent ECDSA P-256 identity, it does not duplicate it. | The two answer different questions; conflating them is the error both specs avoid. |

## The composition is the one ATTP already does

ATTP evaluates delegation chains as inputs to a trust decision and states it "can
interoperate with such receipts," naming `draft-nelson-agent-delegation-receipts`. The EP
receipt plugs in the same way and at the same seam: it is one more signed input to the
trust decision, joined on the same action ATTP signs. Where ATTP's policy requires human
intent for a high-magnitude action, the EP receipt is the evidence; where it does not,
nothing changes. DRP answers who delegated authority to the agent; EP answers whether a
named human approved this exact action; ATTP scores and gates. Three inputs, one decision,
joined on the action.

## What this profile deliberately leaves to ATTP

- Trust scoring (the five behavioural dimensions), action-limit tiers, compliance gating
  (sanctions, jurisdictional), kill switches, and anomaly detection. EP supplies one input
  to the decision; it never makes the decision.
- Agent identity (per-agent ECDSA P-256). EP composes with it, never asserts it.
- The transport bindings (MCPS and others). EP rides whichever transport ATTP carries.

## Offered as a drop-in evidence type

If useful, the EP receipt is a ready value for ATTP's additional-mechanism slot: filed
Internet-Drafts, three-language verifiers, and public accept/refuse vectors, including the
refuse case where a valid signature over the wrong action is presented and rejected. The
relying party pins the receipt bar for the tiers that demand it; ATTP keeps everything else.
