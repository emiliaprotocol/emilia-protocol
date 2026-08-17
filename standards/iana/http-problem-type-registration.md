# Authorization Evidence Required HTTP Problem Type

Backing specification: `draft-schrock-ae-challenge-07`, Sections 3 and 6.
The draft is an individual Internet-Draft and is not IETF-adopted or endorsed.

Registration policy: Specification Required under RFC 9457 Section 4.2 and
RFC 8126 Section 4.6. This allocation does not require IETF Review or Standards
Action.

**Type URI:**
`https://iana.org/assignments/http-problem-types#ae-required`

**Title:** Authorization Evidence Required

**Recommended HTTP status code:** 403

**Reference:** `draft-schrock-ae-challenge-07`

The problem indicates that an origin server refused an action because required
authorization evidence is missing, stale, or unverifiable. The
`evidence_challenge` extension carries the transport-neutral challenge. The
problem response and its challenge authorize nothing and provide no promise of
later execution.
