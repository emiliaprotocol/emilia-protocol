# RECEIPTS-13 CANDIDATE, NOT FILED

Candidate Security Considerations text for a possible future
`draft-schrock-ep-authorization-receipts-13`. Revision -12 was published on
2026-08-16 and does not contain this post-quantum material. This working text
has not been submitted to the IETF, and nothing here is a working-group
document, IETF consensus, or IETF endorsement. Check the live Datatracker
revision again before numbering any submission.

Intended placement: a new subsection of Section 13 (Security
Considerations), following the existing operator-compromise and
presentation-attack subsections, plus one sentence of Related Work already
present at -11 (the RFC 4998 paragraph) that this text extends.

Implementation evidence backing every claim below:
`packages/verify/src/pq-signature-agility.ts` (EP-SIG-AGILITY-v1),
`packages/verify/src/pq-hybrid.ts` (EP-HYBRID-v1),
`packages/verify/src/evidence-record.ts` (EP-EVIDENCE-REATTESTATION-v1),
`conformance/pq-agility/vectors.json` (deterministic Ed25519 + ML-DSA-65
vectors over the same canonical receipt bytes).

---

## 13.X. Signature Algorithm Horizon and Agility

### 13.X.1. The verification horizon

A receipt in this profile is not a session artifact; it is testimony. The
parties who rely on it -- auditors, courts, insurers, and records officers --
read it on the schedule of disputes and statutes of limitations, not on the
schedule of protocol deployments. Government retention schedules commonly
require 10 to 25 or more years. A receipt signed under Ed25519 [RFC8032]
today must therefore still be trustworthy testimony a decade or more from
now, over a horizon in which the aging of any single signature algorithm,
including the possible arrival of a cryptanalytically relevant quantum
computer, is a planning assumption rather than a hypothetical.

Two properties, together, are how evidence outlives algorithms:

1. Algorithm agility: the signature algorithm is an explicit, verified
   field of the receipt, drawn from a closed registry, so the same receipt
   content can be signed under a current algorithm without changing what is
   signed.
2. Re-attestation: evidence signed under an aging algorithm is periodically
   re-committed under a current one, in the renewal style of RFC 4998,
   BEFORE the aging algorithm is broken. The companion evidence-record
   document defines that mechanism; this section defines the agility that
   makes it possible.

### 13.X.2. Algorithm agility (normative sketch)

The signed bytes remain exactly the canonical form of the receipt payload
(Section 4); agility changes which algorithm signs those bytes, never the
bytes themselves.

* The `signature.algorithm` field is drawn from a closed registry. This
  profile registers two values: `Ed25519` [RFC8032] and `ML-DSA-65`
  (FIPS 204, module-lattice-based digital signatures).
* A verifier MUST refuse a receipt whose declared algorithm is outside the
  registry, with a distinct reason (`unknown_algorithm`). An unknown
  algorithm is INDETERMINATE, and an INDETERMINATE result never authorizes:
  it MUST NOT be treated as verified, and MUST NOT fall through to any
  default algorithm.
* A verifier MUST check that the pinned verification key belongs to the
  declared algorithm before verifying, and refuse on mismatch. Verifying
  bytes under a key of a different type than the signature declares is an
  algorithm-confusion defect, not a compatibility feature.
* Malformed signature or key material MUST refuse with a distinct reason;
  it MUST NOT throw, and MUST NOT be reported with the same reason as a
  well-formed signature that fails cryptographic verification.

### 13.X.3. Hybrid presentation

An issuer MAY present signatures under more than one registered algorithm
over the same canonical bytes. Two verification policies are defined:

* `hybrid_all`: the receipt verifies only if every algorithm the relying
  party requires is present and every presented signature verifies. The
  required set is relying-party configuration and MUST NOT default to
  whatever set was presented, or stripping a leg would silently narrow the
  requirement.
* `per_algorithm`: each algorithm's verdict is reported separately and the
  composite verdict is withheld. Per-algorithm VERIFIED results MUST NOT be
  collapsed into a single verdict by the verifier; composition is the
  relying party's policy decision.

A plain multi-signature presentation does not by itself prevent signature
stripping, because the individual signatures do not commit to the set of
algorithms presented. Where stripping resistance is required, the envelope
form in which every signature covers a domain-separated input committing to
the full algorithm set (the EP-HYBRID-v1 construction) SHOULD be used; its
anti-stripping property is that removing an algorithm from the set changes
what every remaining signature covers.

### 13.X.4. Honest boundary

Algorithm agility protects receipts signed from now on. It does not
retroactively protect a receipt that was already issued under a single
algorithm: if that algorithm is later broken, a new signature made after
the break proves nothing about the past, because a forger could mint the
same. The only defense for already-issued receipts is re-attestation under
a still-strong algorithm performed BEFORE the old algorithm breaks (see the
evidence-record re-attestation mechanism). Deployments SHOULD therefore
treat algorithm agility and scheduled re-attestation as one control, not
two options.

The reference implementation's ML-DSA-65 backend is a pure-JavaScript
FIPS 204 implementation that is not an independently audited or
FIPS-validated module. Support for the `ML-DSA-65` registry value is a
format and verification-behavior claim, not a certification claim.

---

## FILING GATE (not I-D body text)

This is a pre-filing checklist item, NOT prose for the Internet-Draft.

NIST posted a July 2026 planning note for pending FIPS 204 errata. Before
filing this car:

* Pin and review the exact FIPS 204 publication plus errata snapshot in force
  at filing time (record the publication date and errata revision).
* Re-verify the ctx-string statement and every parameter-set claim in this
  document (ML-DSA-65 signature length 3309 bytes, public key 1952 bytes,
  secret key 4032 bytes) against that pinned snapshot, since an errata could
  restate or correct any of them.
* Do not file until the pinned snapshot and this document agree.
