# IANA media type registrations — EMILIA Protocol

Registration templates per RFC 6838, Section 5.6. The AE Challenge media type
now follows the Independent Stream publication path for a permanent
standards-tree registration; the current receipts draft carries its own
standards-tree registration request. See `README.md` in this directory for
submission channels, order of operations, and the status tracker.

**Consistency rule applied throughout:** every string below is taken verbatim
from a draft's own text. Nothing here invents a name a draft does not carry.
The backing documents are **individual Internet-Drafts, not IETF-adopted or
endorsed**. A permanent standards-tree registration needs approval the drafts
do not yet have.

---

## 1. application/authorization-evidence-challenge+json

**Status: DIRECT REQUEST CLOSED / ISE SUBMISSION STAGED.** IANA
closed ticket #1456851 on 2026-08-07 without a merits decision because the
document had not reached a publication-stage review. IANA advised that an
Independent Stream document can be processed when it reaches IETF conflict
review. The type is not registered. Revision -02 was published on 2026-08-07
with the full permanent standards-tree template and Independent Stream
metadata; the checklist-complete ISE submission is staged in Gmail and unsent.
The string remains fixed by draft text:
`draft-schrock-ae-challenge-02`, Section 2, specifies that
a challenge is "returned (in the HTTP binding) with status 428 and media type
application/authorization-evidence-challenge+json". Section 5 (IANA
Considerations) requests permanent standards-tree registration.

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

**Encoding considerations:** binary. The content is one UTF-8 JSON text
consisting of a single JSON object [RFC8259]. It is not a JSON text sequence
and does not use record-separator framing. Binary is selected because JSON
representations may contain lines longer than 998 octets.

**Security considerations:** See Section 4 of
draft-schrock-ae-challenge-02. A challenge authorizes
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

**Published specification:** draft-schrock-ae-challenge-02,
"An Authorization Evidence Challenge for High-Risk Agent Actions", Section 2
(published 2026-08-07; intended status Informational; not IETF-adopted or
endorsed).

**Applications that use this media type:** Relying-party enforcement points
that refuse a high-consequence machine-initiated action with HTTP 428 and a
machine-readable statement of the evidence required; agents that parse the
challenge to obtain and present that evidence. Reference implementation:
`packages/gate` and `packages/require-receipt` in the EMILIA Protocol
repository (JavaScript, Python, and Go verifiers live in one repository — a
consistency check, not independent implementations; a separately authored Rust
verifier rebuilt from pinned public source passes the pinned 16-suite/164-vector clean-room bundle plus
359 hostile cases, while strict independently attested construction acceptance
remains zero).

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

**Change controller:** IETF

**Provisional registration? (standards tree only):** No

---

## 2. application/ep-authorization-receipt+json

**Status: CARRIED BY CURRENT DRAFT.** The active
`draft-schrock-ep-authorization-receipts-10`, Section 13, requests this media
type and carries the complete registration template. Process the registration
with the Standards Track document. The older proposed name
`application/ep-receipt+json` is not the name selected by -10 and must not be
filed as an alias.

### Registration template (RFC 6838 §5.6)

**Type name:** application

**Subtype name:** ep-authorization-receipt+json

**Required parameters:** none

**Optional parameters:** none

**Encoding considerations:** binary; the representation is a JSON object
encoded as UTF-8 according to RFC 8259.

**Security considerations:** See the Security Considerations section of
draft-schrock-ep-authorization-receipts-10. Receipt verification requires
independently selected log, approver, directory, and policy trust inputs. A
valid receipt is evidence, not current authorization, proof of execution, or
proof of human comprehension. Implementations must also apply the draft's
duplicate-member, Unicode-scalar, depth, and number restrictions.

**Interoperability considerations:** The
`EP-AUTHORIZATION-RECEIPT-v1` format profile and its offline verification
algorithm are defined by the draft. The shorter identifier `EP-RECEIPT-v1`
names a different generic envelope and is not an alias.

**Published specification:** draft-schrock-ep-authorization-receipts-10,
"Authorization Receipts for High-Risk Agent Actions" (an active individual
Internet-Draft, not IETF-adopted or endorsed; intended status Standards Track).

**Applications that use this media type:** Agent-action authorization systems,
verifying executors, audit systems, and evidence exchange services.

**Fragment identifier considerations:** none

**Additional information:**

- Magic number(s): none
- File extension(s): none
- Macintosh file type code(s): none

**Person & email address to contact for further information:** Iman Schrock,
team@emiliaprotocol.ai

**Intended usage:** COMMON

**Restrictions on usage:** none

**Author:** Iman Schrock

**Change controller:** IETF

**Provisional registration? (standards tree only):** No

---

## Named in draft text but NOT prepared here

These strings appear in posted or batch drafts only tentatively. No template
is prepared, so nothing can be filed that a draft does not back.

| String | Where it appears | Why not prepared |
|---|---|---|
| `application/ep-aec+json` | draft-schrock-ep-authorization-evidence-chain-01, Section 10: "may request a media type (e.g. \"application/ep-aec+json\")" | Illustrative ("e.g."), not specified. Also an acronym-collision risk: the challenge draft's object is `AE-CHALLENGE-v1` while this draft's "AEC" is the evidence *chain*. The chain draft should pick and fix the string in a future revision first. |
| `application/ep-eye-advisory+json` | posted/draft-schrock-emilia-eye-00, IANA Considerations: "may register" (together with a SET event-type URI) | Tentative ("may"); the eye draft is outside the current registration batch. Revisit if/when a revision commits to it. |
