# STAGED, NOT FILED

Staged section text for a future `draft-schrock-ep-evidence-record-02`.
This is working text only: it has not been submitted to the IETF, and
nothing here is a working-group document, IETF consensus, or IETF
endorsement. The published revision is -01; check the live Datatracker
revision before numbering any submission.

Intended placement: a new section following Section 5 (Crypto-agility) of
-01, which already states that each renewal MAY use a different signature
algorithm "including post-quantum signatures once profiled". This section
is that profile. Per the portfolio consolidation record, crypto agility and
re-anchoring belong to this document (the retired standalone
draft-schrock-ep-pqc-00 was folded into it).

Implementation evidence backing every claim below:
`packages/verify/src/evidence-record.ts` (EP-EVIDENCE-REATTESTATION-v1:
`createReattestation`, `verifyReattestationChain`),
`packages/verify/src/pq-signature-agility.ts` (the EP-SIG-AGILITY-v1
algorithm registry it verifies under), and
`packages/verify/evidence-record-reattestation.test.ts` (valid, broken,
out-of-order, unpinned-key, and unknown-algorithm chains).

---

## N. Signature Re-Attestation (EP-EVIDENCE-REATTESTATION-v1)

### N.1. Purpose

The renewal chain of Section 3 preserves WHEN-evidence across hash aging:
each archive timestamp re-anchors the previous one under a fresh hash. This
section defines the parallel mechanism for SIGNATURE aging: evidence signed
under an aging signature algorithm (for example Ed25519 [RFC8032]) is
periodically re-committed under a current one (for example ML-DSA-65,
FIPS 204), so that the evidence's integrity claim never rests solely on an
algorithm that has since weakened.

Authorization evidence has a decades-long verification horizon: disputes,
statutes of limitations, and 10-25+ year government retention schedules all
outlast any single algorithm's expected lifetime. A receipt that must be
trustworthy testimony in 2035 cannot assume that the algorithm that signed
it in 2026 is still unbroken then. Re-attestation is how the evidence
migrates forward.

### N.2. Relation to RFC 4998

The Evidence Record Syntax [RFC4998] preserves signed data across algorithm
aging by chained ArchiveTimeStamps: each renewal covers the prior
attestation under a fresh algorithm, made while the prior algorithm is
still secure. The mechanism in this section is a profile-level analogue of
that renewal discipline, expressed over EP's canonical JSON artifacts and
the EP signature-algorithm registry. It is NOT an implementation of ERS:
it does not produce or consume RFC 4998 ASN.1 structures, does not
implement the ERS reduction of hash trees, and interoperates with ERS only
in the sense of applying the same published renewal principle.

### N.3. Structure

A re-attestation chain is an ordered array of entries:

    {
      "@version": "EP-EVIDENCE-REATTESTATION-v1",
      "prior_record_digest": "<digest_alg>:<hex>",
      "digest_alg": "sha256" | "sha384" | "sha512",
      "reattested_at": "<RFC 3339 instant>",
      "new_signature": { "alg": "<registry value>", "key_id": "<pinned id>", "sig": "<base64url>" }
    }

* Entry 0's `prior_record_digest` is the digest of the protected record
  bytes the relying party holds.
* Entry i (i > 0) digests the canonical bytes of the FULL entry i-1,
  including its signature. Because entry i-1 committed to its own
  predecessor the same way, each re-anchor commits transitively to the
  complete prior chain and to the original record bytes.
* `new_signature.alg` is drawn from the closed EP signature-algorithm
  registry (Ed25519, ML-DSA-65); `new_signature.sig` covers the canonical
  bytes of the entry's own fields (version, digest algorithm, prior digest,
  time), recomputed by the verifier, never taken from the presenter.
* `reattested_at` values MUST strictly increase along the chain.

### N.4. Verification

A verifier walks the chain newest-to-oldest and, for every link, reports
the signature algorithm used, whether the digest linkage holds, and whether
the signature verifies under the key pinned for that link's `key_id`.
Verification is fail-closed throughout: a malformed entry, an unsupported
digest algorithm, an unpinned key identifier, an algorithm outside the
registry, or a failed signature is a refusal that names the link index and
the reason. An unknown algorithm never verifies; an INDETERMINATE link
never authorizes reliance on the chain.

The chain is valid only if every link holds and the times strictly
increase. A valid chain establishes that the current, still-strong
signature commits to the exact prior evidence bytes, so the evidence's
integrity no longer depends on the oldest algorithm alone.

### N.5. The before-the-break boundary

Re-attestation preserves INTEGRITY continuity across algorithm
transitions. It cannot resurrect a signature that was already forgeable
when it was re-attested: if the old algorithm was broken before the
re-anchor, the re-anchor faithfully preserves a claim that was already
untrustworthy, and no later chain repairs that. The re-anchor MUST happen
BEFORE the old algorithm breaks. The chain records this discipline -- each
link's time is signed -- but it cannot prove the discipline was timely
relative to cryptanalytic history; that judgment belongs to the relying
party and to the operational renewal policy (the same boundary Section 8
of -01 states for the timestamp renewal chain, and the same boundary
RFC 4998 itself carries).

Two further boundaries, stated plainly:

* A valid re-attestation chain does not prove the protected artifact was
  correct or authorized; it preserves the bytes' integrity lineage, nothing
  more.
* The strength of a re-anchor is the strength of its key custody: a
  re-attestation key that is not independently protected adds a signature,
  not assurance. Deployments SHOULD pin re-attestation keys per key_id and
  SHOULD anchor re-attestation events to witnessed heads, for the reasons
  Section 6.4 of -01 gives for renewal anchoring generally.
