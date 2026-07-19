<!-- PRIVATE. Grounded binding note. PR-ready text, NOT submitted. Gated on Iman's go per DESIGN.md section 9. -->
# CAID binding note: WIMSE architecture and OAuth Actor Receipts

Status: grounded draft, not submitted anywhere. Sources fetched 2026-07-08:
- draft-ietf-wimse-arch-08 (Workload Identity in a Multi System Environment
  (WIMSE) Architecture, 2026-07-06)
- draft-ietf-wimse-s2s-protocol-07 (WIMSE Workload-to-Workload
  Authentication; the WG has since split this document, cited here for the
  WIT/WPT mechanics it defines)
- draft-mcguinness-oauth-actor-receipts-00

Scope statement (applies to everything below): CAID proves that artifacts
reference the same typed content. It does not prove the action was
authorized, executed, safe, or wise. It confers no trust, names no humans,
and replaces no verifier. Every artifact below still verifies inside its own
trust boundary under its own spec.

---

## Target 1: WIMSE (draft-ietf-wimse-arch)

### 1.1 Grounded summary

WIMSE defines identity for software, not people: "A workload is an
independently addressable and executable software entity" (arch-08,
section 2). The credential is the WIT: "The Workload Identity Token (WIT)
is a JWS [RFC7515] signed JWT [RFC7519] that represents the identity of a
workload" (s2s-07, section 3.1), proven per request by the WPT: "An
additional JWT, the Workload Proof Token (WPT), is signed by the private
key corresponding to the public key in the WIT" (s2s-07, section 3.2).

Information about the human or transaction rides alongside as context, not
as the workload's identity: "it is common for a workload to require
information about a user or other entity that originated the request"
(arch-08, section 3.4.6), and "This context is propagated and possibly
augmented from workload to workload using tokens" (arch-08, section 3.4.6).
The WPT can pin that context cryptographically: "tth: Hash of the Txn-Token
[I-D.ietf-oauth-transaction-tokens], if present in the request, which might
convey end-user identity and/or authorization context of the request"
(s2s-07, section 3.2). Delegation and agents are in scope: "Workloads may
need to impersonate or act on behalf of another principal in the system"
(arch-08, section 3.4.7); "When invoking downstream workloads, the agent
SHOULD propagate the upstream security context, unless it has been
explicitly authorized to translate or reduce its scope" (arch-08, section
3.4.11). Audit is mandatory: "Each authenticated request MUST leave a
verifiable and inspectable trace regardless of authentication and
authorization decision" (arch-08, section 3.4.5).

Note on grounding: arch-08 contains no explicit sentence stating that
workload identity is distinct from personal identity. The separation is
structural (users appear only as context data, section 3.4.6), so this note
claims the structural separation and nothing stronger.

### 1.2 Where a CAID goes

In the propagated security context. The context that moves "from workload
to workload using tokens" today carries information about the originating
user and prior processing; nothing in it canonically names the pending
action. A `caid` member in the transaction/security context (for example a
claim in the Txn-Token that the WPT already hashes via `tth`) names the
pending action as a typed, canonicalized object with required material
fields. The effect: the workload proof chain (WIT + WPT + tth) and every
other artifact about the same action (permit, receipt, outcome attestation,
audit record) join on one identifier. Each hop's mandatory audit trace
(section 3.4.5) records the same caid, so traces across workloads are
provably about the same typed content without any workload trusting
another's evidence.

### 1.3 Unilateral gain (why adopt with zero other adopters)

A deployment that puts a CAID in its context gets material-field validation
on its own artifact: a digest over `{"action":"wire"}` binds nothing, and
the type registry's REQUIRED fields refuse it at issuance. The agent case
is the sharpest: an agent that must "propagate the upstream security
context" can only be audited against what that context names. A caid makes
"the action the context authorized" a recomputable digest instead of prose.
No new trust semantics, no new verifier, one string in a token the WPT
already hashes.

### 1.4 PR-ready pitch (WIMSE)

The architecture already propagates security context between workloads and
already lets the WPT pin a transaction token by hash (tth). What no layer
defines is what "the transaction" canonically is: today it is whatever
free-form structure each deployment puts in the context, so two artifacts
about the same action cannot be joined mechanically. CAID is a typed action
object, a canonicalization and digest suite (JCS + SHA-256), and a compact
identifier string. Putting a caid in the propagated context means the
workload proof, the per-hop audit traces section 3.4.5 requires, and any
external evidence about the action all reference the same recomputable
digest. It carries no trust semantics: it is not authorization, identity,
or proof, and every verifier stays in its own trust boundary. Adoption cost
is one field in the context and a lookup table; the validation of required
material fields pays for itself even in a single-vendor deployment.

---

## Target 2: OAuth Actor Receipts (draft-mcguinness-oauth-actor-receipts)

### 2.1 Grounded summary

The draft "defines OAuth Actor Receipts, an optional companion provenance
profile for delegated OAuth tokens that conform to the OAuth Actor Profile
for Delegation" (abstract). Each hop gets its own signed record: "An actor
receipt records one actor hop. The issuer that adds a new outermost actor
hop signs a receipt describing that hop" (section 5). Receipts are
hash-chained: "prh MUST be the base64url encoding without padding of the
hash of the ASCII octets of the complete compact serialization of the next
older receipt in the chain, computed using the algorithm identified by
prh_alg (defaulting to SHA-256)" (section 7.2.3), and immutable once
chained: systems "MUST preserve each compact JWT string byte-for-byte; any
modification...invalidates prh for any receipt that references it"
(section 7.3).

The receipt claims are identity- and time-shaped: required iss, sub, act,
iat, exp, jti; optional sub_iss, sub_profile, cnf, prh, prh_alg, origin_jti
(section 7.2). origin_jti binds a receipt to a token instance, not to
action content: when it matches "the value binds receipt[0] to the current
outer-token instance" (section 7.2.5). The draft states its own limits:
"Receipts do not prove that the current outer token's audience, scope,
expiration, or other authorization details were in force when older
receipts were created" (section 13.4), and non-goals include "defining
transparency logs, non-repudiation systems, or public audit infrastructure"
(section 4).

### 2.2 Where a CAID goes

One optional claim, `caid`, inside each receipt's claim set. The chain
today answers who delegated to whom, hop by hop, with independent
signatures. No claim in the receipt names what action the delegation was
for: origin_jti points at a token instance, and the enumerated claims carry
no action content. A caid in each receipt names the typed action the
delegation concerns. Because receipts are preserved byte-for-byte and
hash-chained through prh, a caid inside a chained receipt is tamper-evident
for free under the draft's existing rules. Every hop carrying the same caid
makes the whole delegation chain joinable to the action's other evidence
(the permit that authorized it, the attestation of its outcome, the audit
record of its execution) issued under other specs, each verified in its own
boundary.

### 2.3 Unilateral gain (why adopt with zero other adopters)

The receipt issuer's own artifact gets harder. A receipt that references
the action only through an outer token's jti proves provenance of a token,
not provenance of a decision about content. With a caid, the issuer commits
each hop to a canonicalized action object whose required material fields
were validated at issuance (an amount, a beneficiary digest, an instruction
id, per the type registry). An auditor replaying the chain can recompute
the digest offline. This does not close the section 13.4 gap (a caid says
nothing about which authorization details were in force), and it should not
claim to; it adds a content anchor the chain currently lacks, at the cost
of one optional claim.

### 2.4 PR-ready pitch (actor receipts)

The receipt chain is a clean answer to who acted at each hop: independent
signatures, prh hash-chaining, byte-for-byte preservation. What the claims
do not carry is the action itself; origin_jti binds to a token instance,
and iss/sub/act describe parties. CAID supplies the missing reference: a
typed action object, JCS + SHA-256 canonicalization, and a compact
identifier (caid:1:type:suite:digest). One optional claim per receipt, and
each hop is bound to canonical action content that rides the chain's
existing tamper-evidence. The delegation chain then joins, by identifier
equality alone, to permits, outcome attestations, and audit records about
the same action issued under other specs. CAID adds no trust semantics and
does not touch the outer token's trust model or the section 13.4 caveats;
receipts verify exactly as they do now. Issuers gain required-field
validation of the action object on day one, with or without any other
adopter.

---

## Verification trail (this session)

- arch-08 quotes: fetched from ietf.org archive txt, sections 2, 3.4.5,
  3.4.6, 3.4.7, 3.4.11.
- s2s-07 quotes: fetched from ietf.org archive txt, sections 3.1, 3.2.
  Datatracker notes the document was replaced by four split documents;
  WIT/WPT mechanics cited from the -07 text actually read.
- actor-receipts-00 quotes: fetched from ietf.org archive txt, abstract,
  sections 4, 5, 7.2, 7.2.3, 7.2.5, 7.3, 13.4.
- No claim above about either target extends past the quoted text. The
  "explicitly not personal identity" framing sometimes used for WIMSE was
  NOT found verbatim in arch-08 and is deliberately not asserted here.
