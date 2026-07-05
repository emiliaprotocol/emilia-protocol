# IANA HTTP Field Name registrations — EMILIA Protocol

Registration templates for the "Hypertext Transfer Protocol (HTTP) Field Name
Registry" (RFC 9110, Sections 16.3.1 and 18.4; registry:
<https://www.iana.org/assignments/http-fields>). See `README.md` in this
directory for submission channels and the status tracker.

**Both entries here are PROPOSED, requires draft text in next rev.** No
posted or batch draft carries a normative HTTP field *definition* or a
registration request. The field names below appear in
`draft-schrock-agent-action-manifest-00` — Section 5 (on refusal the service
SHOULD return 428 [RFC6585] "with the declared challenge header, and the
caller presents its receipt in the declared proof header") and the worked
example's control object (`"challenge_header": "Receipt-Required"`,
`"proof_header": "X-EMILIA-Receipt"`) — and are deployed in the reference
implementation (`packages/require-receipt/index.js`:
`RECEIPT_REQUIRED_HEADER = 'Receipt-Required'`,
`RECEIPT_PROOF_HEADER = 'X-EMILIA-Receipt'`; consumed in `packages/gate`).
That names the strings; it does not define the fields. A next revision must
add a field-definition section (syntax, semantics, and whether the values are
RFC 8941/RFC 9651 Structured Fields) plus an IANA Considerations request
before either entry is filed. Prepared as **provisional** registrations,
which is the registry's lane for fields whose specification is in progress.

**Consistency rule applied:** these are the deployed, draft-named strings. Do
not invent replacement names here — if the next revision introduces a cleaner
successor field (see the RFC 6648 note under entry 2), that is the draft's
decision to make, and this file gets updated to match the draft, not the
other way around.

---

## 1. Receipt-Required

Response field accompanying an HTTP 428 (Precondition Required, RFC 6585)
refusal of a receipt-gated action; carries compact challenge parameters
telling the caller what evidence to bring.

### Registration template (RFC 9110 §16.3.1)

**Field name:** Receipt-Required

**Status:** provisional

**Specification document(s):**
draft-schrock-agent-action-manifest-00, Section 5 (names the field via the
control object's `challenge_header` member) — an active individual
Internet-Draft, not IETF-adopted or endorsed. A normative field definition is
required in a future revision before permanent registration.

**Comments:**
Response field only. The deployed serialization
(`packages/require-receipt/index.js`, `receiptRequiredHeader()`) is a
comma-separated list of `key="quoted-value"` parameters (e.g. `action`,
`quorum`, `max_age`), which is close to — but not declared as — an RFC 8941 /
RFC 9651 Structured Fields Dictionary. The defining revision should state
explicitly whether the field is a Structured Fields Dictionary and, if so,
adopt that serialization exactly. The full machine-readable challenge rides
in the 428 response body (see the authorization-evidence-challenge draft);
this field is the compact summary. Before filing, check the registry for any
existing "Receipt-Required" entry [verify against the live registry at
submission time].

**Author/Change controller:** Iman Schrock, EMILIA Protocol, Inc.
(team@emiliaprotocol.ai); IETF on any later permanent registration.

---

## 2. X-EMILIA-Receipt

Request field carrying the caller's authorization receipt: the Base64
encoding of the UTF-8 `EP-RECEIPT-v1` JSON document, presented to satisfy a
receipt-gated action.

### Registration template (RFC 9110 §16.3.1)

**Field name:** X-EMILIA-Receipt

**Status:** provisional

**Specification document(s):**
draft-schrock-agent-action-manifest-00, Section 5 (names the field via the
control object's `proof_header` member); receipt profile per
draft-schrock-ep-authorization-receipts. Both are active individual
Internet-Drafts, not IETF-adopted or endorsed. A normative field definition
is required in a future revision before permanent registration.

**Comments:**
Request field only. The deployed value
(`packages/gate/index.js` middleware) is a single Base64 token that decodes
to the UTF-8 JSON receipt — note this is plain Base64 content, **not** an
RFC 8941 Byte Sequence (no colon delimiters) in the deployed form; the
defining revision should decide between keeping the raw-Base64 form and
adopting the Structured Fields Byte Sequence.

RFC 6648 deprecates the "X-" prefix for new field names, so a *permanent*
registration under this name is disfavored. The honest path: (a) register
the deployed name provisionally, because it is what is on the wire and in
posted draft text; (b) let the next draft revision decide whether to define
an unprefixed successor field, keeping X-EMILIA-Receipt as a documented
deployed alias. This file deliberately does not invent the successor name.

**Author/Change controller:** Iman Schrock, EMILIA Protocol, Inc.
(team@emiliaprotocol.ai); IETF on any later permanent registration.

---

## Registry-fit notes (both entries)

- RFC 9110's registry columns are: Field Name; Status (permanent /
  provisional / obsoleted / deprecated); Reference; Comments (optional).
  The templates above map onto those columns; the prose "Specification
  document(s)" becomes the Reference column.
- Provisional entries exist precisely so in-progress specifications can hold
  a name without claiming more than they have — which matches where these
  drafts stand.
