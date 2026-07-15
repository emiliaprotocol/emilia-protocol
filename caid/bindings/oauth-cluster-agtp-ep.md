# Binding note: OAuth vendor cluster, AGTP composition, and EP

Status: PRIVATE. PR-ready and email-ready text only. NOTHING in this file
has been submitted, mailed, posted, or opened as a PR or issue. Every send
is gated on Iman's explicit go (DESIGN.md section 9). The EP pitch is gated
twice: the emilia-protocol repo is public, so merging it would be the first
public reference to CAID.

What CAID is not (applies to every pitch below, verbatim spirit of
DESIGN.md section 5): CAID proves that artifacts reference the same typed
content. It does not prove the action was authorized, executed, safe, or
wise. It confers no trust, names no humans, and replaces no verifier: every
artifact that carries a CAID still verifies inside its own trust boundary
under its own spec.

Grounding: every target below carries at least one quoted anchor. IETF
quotes were obtained 2026-07-08 by fetch-and-extract of the plain-text
drafts at www.ietf.org/archive/id (extraction instructed to quote
verbatim). EP material was read directly from the emilia-protocol repo in
this session (file:line cited). Claims not traceable to a quote or a read
file are not made.

---

## 1. draft-liu-ai-agent-authorization-integration-00 (evidence records)

Source: https://www.ietf.org/archive/id/draft-liu-ai-agent-authorization-integration-00.txt
Liu, Zhu, Xue (Alibaba); Krishnan (Cisco); Parecki (Okta).

Where the action evidence lives. The draft "combines cross-domain
identity, policy-based authorization, user consent evidence, and multi-hop
delegation into a cohesive framework" (abstract). Its consent-evidence
object is the evidence record: "The signed record of the user's
confirmation action during authorization, including what was displayed to
the user, how the user confirmed, a cryptographic signature from the AS,
and the audit_trail sub-object for semantic traceability." The audit_trail
sub-object correlates by opaque URN UUIDs (members "evidence_ref" and
"proposal_ref"), and permitted operations are expressed as an
authorization_details entry of type rego_policy: "The Rego policy defining
what operations the agent is permitted to perform." The confirmed action is
therefore named only indirectly: minted UUIDs plus policy text, no
content-derived identifier of the action object itself.

Where a CAID goes. One member of the evidence record (inside audit_trail
or as its sibling): the CAID of the action object the user confirmed,
computed by the AS at confirmation time. Downstream artifacts about the
same action (permit, receipt, outcome record, log line) carry the same
string.

Unilateral gain. UUIDs correlate only inside the namespace that minted
them; a CAID is recomputable by anyone holding the action object, so
evidence records join with artifacts issued by systems that never saw the
AS's UUIDs. The selfish hardening is local: material-field validation
refuses to issue confirmation evidence over an action object that omits
the amount or beneficiary, closing the "digest over {action:'wire'} binds
nothing" failure inside their own artifact.

Pitch (email-ready, to the draft authors):

    Your evidence record signs what was displayed and how the user
    confirmed, and audit_trail correlates by minted URN UUIDs. Consider
    one more member: a canonical action identifier (CAID), a typed digest
    of the confirmed action object, caid:1:<action_type>:jcs-sha256:<digest>.
    UUIDs correlate only where the minting namespace is shared; a CAID is
    recomputed by anyone holding the action object, so evidence records
    join with permits, receipts, and logs from systems that never saw your
    UUIDs. It carries no trust semantics; the record verifies as before.

---

## 2. draft-jiang-oauth-intent-admission-00 (intent admission assertions)

Source: https://www.ietf.org/archive/id/draft-jiang-oauth-intent-admission-00.txt
Jiang, Li, Song, Liu (Huawei).

Where the action lives. The Intent Admission Assertion "is a JWT [RFC7519]
protected as a JWS", and "The admission decision is a single Rich
Authorization Requests [RFC9396] authorization detail object with 'type'
set to 'intent_admission'." The admitted intent sits outside the assertion
and is bound by digest: "intent_ref (REQUIRED): A binding to the admitted
intent (Section 3.4): a JSON object with members 'hash_alg', 'digest'
(base64url), and 'canonicalization'." Canonicalization is already CAID's:
"If the admitted intent is a JSON object, the digest input MUST be the
JSON Canonicalization Scheme [RFC8785] representation of that object, and
'canonicalization' MUST be 'jcs'." So when hash_alg is SHA-256, the
intent_ref digest is byte-identical to the CAID digest over the same
object. This is the closest existing artifact to CAID on the wire; what it
lacks is a type discipline: nothing states which fields of the digested
intent were material.

Where a CAID goes. The admitted intent object becomes a CAID action object
(versioned action_type inside the digested bytes, material fields per a
registered or local type definition). The IAA then carries the full caid
string beside intent_ref (or as a new intent_ref member); the digest bytes
they already compute do not change.

Unilateral gain. Today an admission over an under-specified blob and one
over a fully specified action are indistinguishable in binding strength.
Material-field validation lets the admitting party refuse under-specified
intents before signing, and the typed identifier makes the IAA joinable by
any other artifact about the same action, at zero new cryptography since
the JCS pipeline already exists.

Pitch (email-ready, to the draft authors):

    intent_ref already binds the IAA to a JCS digest of the admitted
    intent, which is byte-identical to a CAID computation when hash_alg is
    SHA-256. What the digest lacks is a type: nothing states which fields
    of the intent were material, so admission over an under-specified
    object binds as strongly on paper as admission over a complete one.
    CAID adds the missing half with zero new crypto: a versioned
    action_type inside the digested bytes plus a registry entry listing
    REQUIRED material fields (amounts as strings). Admission semantics
    stay entirely yours.

---

## 3. draft-chen-oauth-agent-authz-use-cases-01 (use-case gaps)

Source: https://www.ietf.org/archive/id/draft-chen-oauth-agent-authz-use-cases-01.txt
M. Chen, J. Chen (China Mobile); Yao (CNNIC); Jiang, Liu (Huawei).

Where the gap lives. The draft "categorizes them into distinct scenarios,
details their specific authorization requirements, and performs a
comprehensive gap analysis against the existing OAuth 2.0 framework
[RFC6749] and its common extensions" (abstract), across nine use cases
(Personal Digital Assistant through Automated Security Incident Response).
Two stated requirements are exactly the join-key problem. Correlation:
"Auditable Context: The entire process must be tied to a single, auditable
claim_id that is securely passed along the chain" and "Standard audit
context identifier passed across all agent hops for compliance logging."
Emergent actions: "The exact permissions required may not be known at the
start of a task but emerge as the agent plans and executes its steps" with
"Intent-to-Permission Translation: The system must translate the
high-level intent ("plan a picnic") into a series of specific,
just-in-time permission requests."

Where a CAID goes. Into the gap analysis as a candidate mechanism class:
content-derived action identifiers beside issued correlation IDs. Each
just-in-time permission request names its concrete action by CAID; the
emergent steps of one task correlate because every hop recomputes the same
string from the action object, with no pre-issued identifier to thread
through the chain.

Unilateral gain. An issued claim_id requires every hop to trust one issuer
and forward the value intact; a content-derived identifier requires
neither, so the audit-context requirement is satisfiable even across hops
that drop or rewrite metadata. Because CAID carries no authorization
semantics, citing it does not favor any of the competing OAuth mechanisms
the analysis compares.

Pitch (email-ready, to the draft authors):

    The gap analysis requires "a single, auditable claim_id that is
    securely passed along the chain". An issued identifier assumes every
    hop shares an issuer and forwards the value intact; a content-derived
    identifier assumes neither. CAID names each concrete action by a typed
    JCS/SHA-256 digest of the action object, so every hop recomputes the
    same string independently and correlation survives hops that drop
    metadata. Worth listing content-derived action identifiers beside
    issued claim_ids; CAID is neutral among the mechanisms you compare.

---

## 4. draft-hood-agtp-composition-01 (external-IdP credential slot)

Source: https://www.ietf.org/archive/id/draft-hood-agtp-composition-01.txt
C. Hood (Nomotic, Inc.). Title: "AGTP Composition Profiles: Agent Group
Messaging Protocols, External Identity Providers, and HTTP Gateways".

Where the credential slot lives. AGTP composes with "external identity
providers (OAuth, OIDC, enterprise IdPs)" (abstract). The credential is
deliberately opaque to the transport: "AGTP servers process the
Authorization request header per HTTP semantics ([RFC9110]). The header
value is opaque to AGTP itself; the configured validator interprets it"
(section 9.3). Its role: "External IdP credentials answer 'on whose behalf
is the agent acting.'" (section 9.1). And the audit boundary: "AGTP MUST
NOT stamp the raw Authorization header value or the raw token onto the
Attribution-Record" (section 9.4). Net effect: the attribution record can
say which agent and on whose behalf, but has no sanctioned way to say
WHICH action the carried credential authorized.

Where a CAID goes. Two spots, both preserving the opacity rule: (a) a
member of the Attribution-Record carrying the CAID of the action the
credential authorized. CAID is safe where raw tokens are forbidden because
it is not a capability: possession proves nothing and it is public by
construction. (b) Inside whatever external-IdP credential is carried,
which AGTP continues to treat as opaque. The two layers then join on the
identifier while each verifies in its own trust boundary.

Unilateral gain. AGTP-side audit gains a join from transport attribution
to authorization evidence without AGTP ever interpreting, validating, or
ingesting the credential, and without weakening section 9.4. Note for us:
this pitch is deliberately CAID-only. Per emilia-protocol
examples/ep-over-agtp/demo.mjs (header comment), agtp-composition-01's
published external-IdP sources are OAuth/OIDC/SPIFFE and the draft does
not name EP; ep-receipt-v1 in that slot is EMILIA's proposed realization,
not something the draft adopted. Keep the two proposals separate.

Pitch (email-ready, to C. Hood):

    Section 9.4's rule against stamping raw credentials onto the
    Attribution-Record is right, and it leaves the record unable to say
    which action the credential authorized. A canonical action identifier
    (CAID) fills that slot without bending the rule: a typed JCS/SHA-256
    digest of the action object, public by construction, possession proves
    nothing. The gateway stamps the CAID; the external-IdP credential
    references the same CAID internally; an auditor joins transport
    attribution to authorization evidence while AGTP never interprets the
    credential.

---

## 5. EMILIA Protocol (EP receipt payload)

Source (read this session):
/Users/imanschrock/Documents/GitHub.nosync/emilia-protocol/examples/ep-over-agtp/demo.mjs
/Users/imanschrock/Documents/GitHub.nosync/emilia-protocol/standards/README.md

Where the action lives. The demo builds the action object at demo.mjs:44-50
with action_type already present: action_type 'payment.release', amount_usd
40000 (JSON number), currency 'USD', payment_instruction_id 'pi_42',
beneficiary_account_hash 'sha256:7c9e...beef' (placeholder). The receipt
payload embeds it as the claim (demo.mjs:57, claim: { ...action, outcome:
'allow_with_signoff' }) and the join is raw JCS byte-equality: "The join:
the action the executor is about to run must equal the authorized claim."
(demo.mjs:90, enforced at :92). EP already implements RFC 8785 JCS
(demo.mjs:26-31), and the composition layer already joins on an action
digest: EP-AEC verifies that "for ONE action, heterogeneous receipts
(delegation, policy-permit, human authorization) all bind the same
canonical action digest" (standards/README.md, EP-AEC section).

Where a CAID goes. The existing action objects already carry action_type
and the material fields; they need only (a) the versioned type name
(payment.release -> payment.release.1) and (b) material-field validation
per the type definition to be CAID-conformant. Against the
payment.release.1 entry in DESIGN.md section 3 that concretely means: the
amount becomes an amount-string ("40000", never the JSON number 40000),
the beneficiary digest becomes a real sha256:<lowercase hex> value (the
demo's ellipsized placeholder would be refused as mistyped_field), and
field names align to the registry entry or EP registers a local definition
with its current names in the same schema (local definitions are
first-class, DESIGN.md section 3). The receipt payload then carries the
caid string beside the claim, and the AEC / evidence-graph join key
becomes the CAID.

Unilateral gain. EP's own join upgrades from private JCS byte-equality to
a typed identifier that non-EP artifacts (IAAs, AGTP attribution records,
liu evidence records) can carry, so EP receipts become joinable by parties
that never run EP code. Locally, material-field validation catches an
under-specified claim before the approver signs it, which is the same
selfish hardening we pitch to everyone else, applied to ourselves first.

Pitch (PR-ready, for the emilia-protocol repo; merging is gated because
the repo is public and this would be CAID's first public reference):

    examples/ep-over-agtp/demo.mjs already builds the action object with
    action_type and the material fields, and joins on JCS byte-equality of
    the claim. Two mechanical changes make it CAID-conformant: version the
    type name (payment.release -> payment.release.1) and pass
    material-field validation, which per the payment.release.1 registry
    entry moves the amount to an amount-string ("40000", not the JSON
    number 40000) and requires a real lowercase-hex beneficiary digest.
    The join then compares CAID strings, and every EP artifact names its
    action with an identifier non-EP systems can carry too.

---

## Fetch status

All four IETF fetches succeeded 2026-07-08; both EP repo files read this
session. No target is DRAFT-BLOCKED.
