# IANA media type registrations — EMILIA Protocol

Completed registration templates per RFC 6838, Section 5.6, prepared for the
**provisional standard media type** path (the vehicle for names whose defining
specification is still in development). See `README.md` in this directory for
submission channels, order of operations, and the status tracker.

**Consistency rule applied throughout:** every string below is taken verbatim
from a draft's own text. Nothing here invents a name a draft does not carry.
The backing documents are **active INDIVIDUAL Internet-Drafts, not
IETF-adopted or endorsed**; a permanent standards-tree registration needs
approval the drafts do not yet have, which is exactly why these are prepared
as provisional registrations.

---

## 1. application/authorization-evidence-challenge+json

**Status: READY-ON-POST.** The string is fixed by draft text:
`draft-schrock-authorization-evidence-challenge-00`, Section 2, specifies that
a challenge is "returned (in the HTTP binding) with status 428 and media type
application/authorization-evidence-challenge+json". Section 5 (IANA
Considerations) of the -00 states "A future revision will register the media
type" — so the -01 must carry this registration text before the permanent
registration can complete; a **provisional** registration can be requested as
soon as the -00 is live on the datatracker.

**Deployment honesty note:** the reference enforcement point returns the
challenge object today labeled `application/json` (Express `res.json()`); this
registration names the dedicated type the draft declares, it does not describe
what is currently on the wire.

### Registration template (RFC 6838 §5.6)

**Type name:** application

**Subtype name:** authorization-evidence-challenge+json

**Required parameters:** N/A

**Optional parameters:** N/A (none defined; the `@version` member inside the
document, value `AE-CHALLENGE-v1`, gates interpretation)

**Encoding considerations:** binary. The content is JSON [RFC8259] encoded in
UTF-8.

**Security considerations:** See Section 4 of
draft-schrock-authorization-evidence-challenge-00. A challenge authorizes
nothing by itself: a forged challenge cannot make an action admissible, and a
fully satisfied challenge yields a verdict under the relying party's policy,
never a promise of execution. Challenges are single-use (nonce) and expiring,
which bounds replay and hoarding; the relying party retains challenge state
and MAY bound it by the expiry window. Verification of evidence presented in
answer to a challenge proves signature, binding, and log integrity — never the
business correctness of the underlying action. Deployments that store,
forward, or answer challenges outside the issuing context take on the risks
Section 4 of the draft describes.

**Interoperability considerations:** Uses the `+json` structured syntax suffix
[RFC6839]; processors that treat the content as generic JSON can parse it but
lose the challenge semantics (single-use nonce, expiry, action digest
binding). Consumers encountering an unrecognized `@version` value should treat
the document as unprocessable rather than guessing.

**Published specification:** draft-schrock-authorization-evidence-challenge-00,
"An Authorization Evidence Challenge for High-Risk Agent Actions", Section 2
(an active individual Internet-Draft, not IETF-adopted or endorsed; intended
status Informational).

**Applications that use this media type:** Relying-party enforcement points
that refuse a high-consequence machine-initiated action with HTTP 428 and a
machine-readable statement of the evidence required; agents that parse the
challenge to obtain and present that evidence. Reference implementation:
`packages/gate` and `packages/require-receipt` in the EMILIA Protocol
repository (JavaScript, Python, and Go verifiers live in one repository — a
consistency check, not independent implementations; an externally authored
from-spec Rust implementation, source public, separately agrees on all 162
published vectors).

**Fragment identifier considerations:** As specified for `+json` in RFC 6839,
Section 3.1. No type-specific fragment identifier syntax is defined.

**Additional information:**

- Deprecated alias names for this type: none
- Magic number(s): none
- File extension(s): none expected; the object is a transient HTTP response
  body, not a stored file
- Macintosh file type code(s): none

**Person & email address to contact for further information:** Iman Schrock,
team@emiliaprotocol.ai

**Intended usage:** COMMON

**Restrictions on usage:** none

**Author:** Iman Schrock, EMILIA Protocol, Inc.

**Change controller:** IETF (on permanent standards-tree registration; the
draft author until then)

**Provisional registration? (standards tree only):** Yes

---

## 2. application/ep-receipt+json

**Status: PROPOSED, requires draft text in next rev.** The string is
draft-specified — `draft-schrock-ep-authorization-receipts-05`, Section 12
(IANA Considerations): "A future version may register the
application/ep-receipt+json media type" — but "may register" is not a
registration request. Do **not** file this until a -06 (or later) commits to
the registration in its IANA Considerations. The template below is prepared so
that revision can carry it verbatim.

### Registration template (RFC 6838 §5.6)

**Type name:** application

**Subtype name:** ep-receipt+json

**Required parameters:** N/A

**Optional parameters:** N/A (none defined; the document's own version member,
profile `EP-RECEIPT-v1`, gates interpretation)

**Encoding considerations:** binary. The content is JSON [RFC8259] encoded in
UTF-8. Signatures are computed over a canonical form (JCS-style
canonicalization of an I-JSON value subset) as specified by the defining
draft, so byte-exact transport of the canonical payload matters to verifiers.

**Security considerations:** See Section 11 of
draft-schrock-ep-authorization-receipts-05. A receipt is offline-verifiable
authorization evidence: Ed25519 signatures over canonical JSON, bound to a
specific action, with one-time consumption against replay. Verification
proves signature, binding, and (where a log is used) log-inclusion integrity —
never the business correctness of the authorized action, and offline
verification does not by itself prove non-revocation or log honesty (the draft
states this as a MUST NOT overclaim). Possession of a receipt is evidence,
not permission: the enforcement point, not the document, is the control.

**Interoperability considerations:** Uses the `+json` structured syntax suffix
[RFC6839]. Processors that treat the content as generic JSON lose the
verification semantics; verifiers must apply the canonicalization profile of
the defining draft before checking signatures, since divergent
canonicalization produces divergent verdicts on identical documents.

**Published specification:** draft-schrock-ep-authorization-receipts
(revision carrying the registration text; -05 is the current revision:
"Authorization Receipts for High-Risk Agent Actions" — an active individual
Internet-Draft, not IETF-adopted or endorsed; intended status Informational).

**Applications that use this media type:** Enforcement points that require an
authorization receipt before executing a high-consequence agent action;
agents presenting receipts; auditors verifying them offline. Reference
implementation: the EMILIA Protocol repository (JavaScript, Python, and Go
verifiers in one repository — a consistency check, not independent
implementations; an independent clean-room reimplementation (COSA) is
underway).

**Fragment identifier considerations:** As specified for `+json` in RFC 6839,
Section 3.1. No type-specific fragment identifier syntax is defined.

**Additional information:**

- Deprecated alias names for this type: none
- Magic number(s): none
- File extension(s): none registered; deployments that store receipts at rest
  commonly use `.json`
- Macintosh file type code(s): none

**Person & email address to contact for further information:** Iman Schrock,
team@emiliaprotocol.ai

**Intended usage:** COMMON

**Restrictions on usage:** none

**Author:** Iman Schrock, EMILIA Protocol, Inc.

**Change controller:** IETF (on permanent standards-tree registration; the
draft author until then)

**Provisional registration? (standards tree only):** Yes

---

## Named in draft text but NOT prepared here

These strings appear in posted or batch drafts only tentatively. No template
is prepared, so nothing can be filed that a draft does not back.

| String | Where it appears | Why not prepared |
|---|---|---|
| `application/ep-aec+json` | draft-schrock-ep-authorization-evidence-chain-01, Section 10: "may request a media type (e.g. \"application/ep-aec+json\")" | Illustrative ("e.g."), not specified. Also an acronym-collision risk: the challenge draft's object is `AE-CHALLENGE-v1` while this draft's "AEC" is the evidence *chain*. The chain draft should pick and fix the string in a future revision first. |
| `application/ep-eye-advisory+json` | posted/draft-schrock-emilia-eye-00, IANA Considerations: "may register" (together with a SET event-type URI) | Tentative ("may"); the eye draft is outside the current registration batch. Revisit if/when a revision commits to it. |
