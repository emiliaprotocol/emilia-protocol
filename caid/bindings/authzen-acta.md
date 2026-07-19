# CAID binding note: OpenID AuthZEN and ACTA signed receipts

Status: PRIVATE, grounded draft. PR-ready text only. NOT submitted anywhere.
Submission of either pitch is gated on Iman's explicit go (DESIGN.md section 9).

Sources read in full on 2026-07-08 and refreshed on 2026-07-14:

- OpenID AuthZEN, "Authorization API 1.0", https://openid.net/specs/authorization-api-1_0.html
  (header: "Published: 11 January 2026 Status: Final").
- OpenID AuthZEN, "Access Request and Approval Profile - Draft 1",
  https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html
  (published 9 July 2026).
- draft-farley-acta-signed-receipts-02, "Signed Decision Receipts for
  Machine-to-Machine Access Control",
  https://www.ietf.org/archive/id/draft-farley-acta-signed-receipts-02.txt
  (Independent stream, Informational, 28 June 2026).

Every quoted string below is verbatim from the fetched source. Claims about
the documents are made only where anchored by a quote or a named field.

Scope statement (applies to everything below): CAID proves that artifacts
reference the same typed content. It does not prove the action was
authorized, executed, safe, or wise. It confers no trust, names no humans,
and replaces no verifier: every artifact that carries a CAID still verifies
inside its own trust boundary under its own spec. Composition joins on the
identifier; it never ingests another verifier's evidence into its own trust
boundary.

---

## Target 1: OpenID AuthZEN Authorization API and Approval Profile

### 1. Where the action lives

The unit of work is the access evaluation request. Section 6.1: "The Access
Evaluation request is an object consisting of four entities previously
defined in the Information Model", with `subject` and `resource` REQUIRED,
plus "action : REQUIRED. The action (or verb) of type Action" and
"context : OPTIONAL. The context (or environment) of type Context."

The action itself is a verb, not the full acted-upon content. Section 5.3:
"An Action is the type of access that the requester intends to perform"
and "Action is an object that contains a REQUIRED name key with a string
value, and an OPTIONAL properties key with an object value." The material
parameters ride in properties; Section 5.3.1: "Such attributes can include,
but are not limited to, parameters of the action that is being requested."
The target is separate; Section 5.2: "A Resource is the target of an access
request", with REQUIRED `type` and `id` and "properties : OPTIONAL. An
object which can be used to express additional attributes of a Resource."

So in AuthZEN the action-as-content is spread across four members
(action.name, action.properties, resource.type/id/properties, subject).
The base decision that comes back is a boolean; Section 5.5: "Decision is an
object that contains a REQUIRED decision key with a boolean value, and an
OPTIONAL context key with an object value."

The July 2026 Access Request and Approval Profile materially strengthens that
flow. It binds a denial, request, approval task, and later re-evaluation; it
also defines a JWS-signed `approval.state` option and an exact-match baseline
over Subject, Resource, Action, and authorization-relevant Context. The base
completion mode deliberately leaves the PDP authoritative. CAID therefore
does not fill a missing approval protocol. Its narrower role is to give those
AuthZEN objects a typed, cross-protocol material-action identifier and to
define when a separately verified native object may be projected to that
identifier under a relying-party-pinned mapping profile.

### 2. Where a CAID goes

Two existing extension points admit a CAID with zero normative change to the
Authorization API. Primary placement is the request `context` member, because a CAID
identifies the whole typed action (verb plus target plus material fields),
not an attribute of the resource alone, and Section 5.4 defines Context as
exactly the request-scoped bag: "Context is an object which can be used to
express attributes of the environment." Alternative placement is
`resource.properties` when a PDP policy needs to match on the identifier
directly (Section 5.2: properties "can be used to express additional
attributes of a Resource").

```json
{
  "subject":  {"type": "agent", "id": "agent-7"},
  "action":   {"name": "release_payment",
               "properties": {"amount": "1250.00", "currency": "EUR"}},
  "resource": {"type": "payment_instruction", "id": "pi_9912"},
  "context":  {"caid": "caid:1:payment.release.1:jcs-sha256:Ftw...9aA"}
}
```

The PEP computes the CAID over its own typed action object (the CAID
registry entry for the type states which fields are material) and places
the string in `context.caid`. The PDP can echo it in the decision response
`context`, which Section 5.5 defines as "An object which can convey
additional information that can be used by the PEP as part of the decision
enforcement process." Request log, decision log, and any downstream
artifact now carry one join key. The CAID adds no trust semantics to the
evaluation: the PDP still decides under its own policy, and nothing about
the identifier makes the decision more or less authorized. When the Access
Request and Approval Profile is used, the same member can remain within the
authorization-relevant Context set so denial binding, approval scope, and
re-evaluation all cover it. A deployment MUST NOT infer that an
`approval.state` and a CAID refer to equivalent native content merely because
both strings are present; native verification and a pinned mapping profile
remain separate prerequisites.

### 3. Unilateral gain

An adopting PEP gains before any second party exists:

- Material-fields validation on its own requests. computeCaid refuses
  (missing_material_field, mistyped_field, invalid_amount) when the action
  object omits or malforms a required field of the registered type, so
  under-specified evaluation requests are caught at the PEP before the PDP
  renders a decision over incomplete content.
- Content-bound decision logs. Every signed or tamper-evident decision record
  can carry an identifier that commits to the typed content decided on, so an
  auditor can verify the content commitment instead of relying on prose. CAID
  alone does not make an unsigned log trustworthy.
- Lower-cost interop later. A receipt, outcome attestation, or permit using
  the same suite and pinned type definition can join to the PDP decision by
  CAID equality. Different native representations require explicit pinned
  mapping profiles, and every artifact still verifies under its own spec.

### 4. PR-ready pitch (AuthZEN, non-normative interop example)

> Title: Non-normative example: correlating evaluation decisions with a
> canonical action identifier in request context
>
> AuthZEN deliberately keeps Context open ("an object which can be used to
> express attributes of the environment", Section 5.4), and the Access
> Request and Approval Profile defines an integrity-protected
> authorization-relevant Context set. This PR adds one
> non-normative example showing a PEP carrying a canonical action
> identifier (CAID), a typed content digest of the action being decided,
> in `context.caid`, and a PDP echoing it in the decision response
> `context` (Section 5.5). The identifier carries no trust semantics and
> changes no evaluation behavior; it gives deployments a stable join key
> between the PDP's decision and pre- or post-execution evidence about the
> same action produced by other systems. It does not replace the approval
> profile or alter PDP authority. No normative text changes.

---

## Target 2: ACTA signed receipts (draft-farley-acta-signed-receipts-02)

### 1. What its signed receipts attest

The abstract: "This document defines a portable, cryptographically signed
receipt format for recording machine-to-machine access control decisions."
The receipted unit is the decision event: the access decision receipt
(Section 3.1) carries "tool_name (REQUIRED): The name of the tool being
invoked" and "decision (REQUIRED): The policy evaluation result. One of:
'allow', 'deny', 'rate_limit'." Receipts deliberately exclude content;
Section 8.3: "Receipts are designed to capture decision metadata, NOT
request content."

The draft already has a correlation anchor, added in -02 (Appendix C:
"Added action_ref as an OPTIONAL common payload field"). Section 2.2
defines it: "action_ref (OPTIONAL): A cross-engine correlation anchor: the
SHA-256 hash of the canonical representation of the action being
evaluated", computed as "action_ref = SHA-256(canonicalize({ agentId,
actionType, scopeRequired, timestamp }))" "where canonicalize follows
RFC 8785 (JCS)".

Read precisely, action_ref identifies an evaluation event, not the
action-as-content: the digest input is fixed at four fields, includes a
timestamp, and includes the agent identity, while the material parameters
of the action (an amount, a beneficiary, a target record) are not in the
digest at all. Two receipts about the same action content evaluated at
different times, or attributed to different agent ids, carry different
action_refs; conversely action_ref equality says nothing about what the
action's parameters were.

### 2. Where a CAID goes

An OPTIONAL common payload field `caid` (Section 2.2 is the natural home,
exactly where -02 added action_ref) referencing the acted-upon action by
its typed content digest:

```json
{
  "type": "protectmcp:decision",
  "tool_name": "release_payment",
  "decision": "allow",
  "caid": "caid:1:payment.release.1:jcs-sha256:Ftw...9aA",
  "action_ref": "9c2f...44d1",
  "issued_at": "2026-07-08T10:11:12Z",
  "issuer_id": "sb:issuer:4Kpm7Q3wXx2b"
}
```

`caid` complements action_ref rather than replacing it: action_ref keeps
answering "same evaluation event across co-located engines", `caid`
answers "same typed action content across any artifact anywhere." The
machinery cost is near zero: ACTA already canonicalizes with JCS (the
abstract: "serialized using deterministic JSON canonicalization
[RFC8785]") and already hashes with SHA-256, which are exactly CAID's
jcs-sha256 suite. It also respects Section 8.3's minimal-disclosure rule:
a CAID is a digest, so the receipt still carries no request content, and
digest-typed material fields keep raw identifiers out of the underlying
action object too. The CAID confers no trust on the receipt; the receipt
still verifies solely under ACTA's own signature and verification rules
(Section 4), and CAID equality never imports another system's evidence
into the ACTA verifier's trust boundary.

### 3. Unilateral gain

An adopting ACTA issuer gains alone:

- Material-fields validation for what it receipts. The action_ref recipe
  digests whatever four values it is handed; nothing checks that the
  action's required parameters were present or well-typed. computeCaid
  refuses to emit an identifier for an under-specified action, so the
  issuer's own receipts can no longer silently reference a content-free
  action (the "digest over {action:'wire'} binds nothing" failure).
- Time-stable and agent-stable reference. Because the CAID digests the
  action-as-authorized-content and not the evaluation timestamp or agent
  id, pre-execution and post-execution receipts about the same content
  join by string equality even across retries and re-evaluations.
- Joins beyond the ACTA ecosystem. Permits, outcome attestations, and
  audit records issued by systems that will never implement action_ref's
  exact four-field recipe still join to ACTA receipts on the CAID.

### 4. PR-ready pitch (ACTA, draft author)

> Subject: -03 suggestion: OPTIONAL caid common payload field alongside
> action_ref
>
> action_ref in -02 cleanly identifies the evaluation event: SHA-256 over
> {agentId, actionType, scopeRequired, timestamp}. Because timestamp and
> agentId are inside the digest, it cannot identify the action's content
> across time, retries, or unrelated ecosystems, and the action's material
> parameters are outside the digest entirely. Suggest adding an OPTIONAL
> `caid` common payload field in Section 2.2: a canonical action
> identifier, a typed JCS/SHA-256 digest of the action object itself with
> per-type required material fields. Same RFC 8785 and SHA-256 machinery
> the draft already mandates, still zero request content in the receipt
> (Section 8.3 preserved), no trust semantics added. action_ref keeps
> answering "same evaluation"; caid adds "same action content" for joins
> with artifacts outside the ACTA ecosystem.

---

## Fetch record

The source fetches succeeded on the dates above; no DRAFT-BLOCKED condition.
Quotes were verified against the raw source texts (curl of the I-D .txt and
the AuthZEN HTML), not against a summarizer's paraphrase. One
transliteration note: the ACTA abstract contains a Unicode em-dash in the
source; quotes here were chosen to avoid reproducing it, keeping this file
ASCII-clean per DESIGN.md style rules.
