# Selective Disclosure of Authorization Receipts (staged section for presentation-binding -01)

STATUS: STAGED, NOT FILED. This is working text intended for the
`draft-schrock-ep-presentation-binding-01` revision. It has not been
submitted to Datatracker, and nothing here is an IETF document, adopted or
otherwise. Wording, section numbering, and normative keywords are draft-ready
but remain subject to the -01 assembly pass.

Reference implementation: `packages/verify/src/receipt-selective-disclosure.ts`
(Apache-2.0), conformance vectors in `conformance/selective-disclosure/`.

## Terminology note

Presentation-binding -00 uses "presentation" for what a signing surface
displayed to the human approver (the presentation attack: a surface that
shows one thing and commits another). This section introduces a second,
distinct act that also deserves the word: a holder later PRESENTS a receipt
to an auditor, insurer, or regulator. To keep the two apart, this section
uses DISCLOSURE PRESENTATION for the holder-to-relying-party act and leaves
"presentation attack" with its -00 meaning. The two compose: -00 narrows
what the approver was shown; this section narrows what the relying party
gets to read.

## 1. Problem

An authorization receipt is evidence, and evidence travels. The party a
receipt must convince (an auditor sampling controls, an insurer pricing a
book, a regulator examining one action) is rarely the party the receipt's
business content belongs to. Today the holder's choice is binary: hand over
the whole receipt, including beneficiary names, amounts, memos, and
counterparty identifiers that the relying purpose does not need, or hand
over nothing and ask to be trusted. Both answers are wrong, and the second
one is the exact failure this protocol family exists to remove.

What the relying party actually needs to verify is narrow: that an
authorized approval bound THIS exact action (the CAID), that the issuer
signature is intact over the exact signed bytes, and that the evidence
grade of the approval is visible. Everything else is disclosure policy.

## 2. What this is, exactly

A profile of standard salted-digest selective disclosure, applied to an
already-signed artifact. The pattern is the one SD-JWT
[I-D.ietf-oauth-selective-disclosure-jwt] standardized for JWTs: the signed
body carries digests of disclosable fields; the holder releases, per
audience, the openings it chooses; the verifier recomputes digests against
the signed body. This section claims exactly that and nothing more. It is
not a new cryptographic scheme, it introduces no new signature algorithm,
and it does not claim the unlinkability that pairing-based schemes such as
BBS [I-D.irtf-cfrg-bbs-signatures] provide. Where those properties are
needed, use those schemes; where a salted-digest profile over an existing
Ed25519 receipt is enough, this is that profile, offline-checkable with the
same zero-dependency verifier as the rest of the receipt family.

## 3. Construction

### 3.1 Disclosure-ready issuance

At issuance preparation, BEFORE signing, each designated-disclosable field
value in the receipt payload is replaced by a commitment slot:

    ep-sd-commit:sha256:<hex>

where the digest is SHA-256 over the canonical bytes (RFC 8785 JCS, EP
strict profile) of:

    { "domain": "EP-SD-COMMIT-v1", "path": <field path>,
      "salt": <base64url, >= 128 bits>, "value": <original value> }

The signed payload additionally carries a `disclosure` block naming the
committed paths:

    "disclosure": { "@version": "EP-SD-v1", "alg": "sha256",
                    "paths": [ <sorted field paths> ] }

The issuer signs the resulting payload as an ordinary EP-RECEIPT-v1 payload
(Ed25519 over the canonical bytes) and delivers the openings
({path, salt, value} per designated field) to the holder OUTSIDE the signed
body. Salts MUST be fresh, per-field, and at least 128 bits; salt reuse
across fields MUST be refused at preparation and again at verification.
Committing the field path inside the digest is what makes an opening
unusable at any other field.

### 3.2 The issuance constraint, stated rather than papered over

An EP-RECEIPT-v1 signature covers the full canonical payload bytes, and
Ed25519 verification requires every signed byte. A receipt whose business
fields were signed in PLAINTEXT therefore cannot have those fields hidden
later while the signature still verifies. There is no construction that
avoids this without changing the signature scheme, and this profile does
not pretend to have found one. Selective disclosure REQUIRES
disclosure-ready issuance. Already-issued plaintext receipts remain fully
verifiable and fully presentable, but only in full; a verifier under this
profile refuses them with `missing_disclosure_block`. This is the same
constraint SD-JWT carries (the issuer must embed disclosure digests in the
signed JWT), inherited for the same reason.

### 3.3 The non-redactable closed set

The following payload paths can never be designated disclosable, nor can
any path above or below them. The set is closed and enforced twice: at
issuance preparation and, independently, against the SIGNED disclosure
block at verification, so a misissued or forged designation is refused by
the verifier regardless of what the issuer did.

    caid                        action.caid
    action.action_type          action_digest
    canonical_action_digest     evidence_grade
    verification_status         signoffs
    required_approvals          disclosure

Rationale: a disclosure presentation is only evidence because it still
means "THIS exact action, approved with THIS evidence". Redacting the CAID
or the evidence-grade fields would collapse it into "something was approved
somehow", which is laundered authority in a new costume, and the verifier
MUST refuse it (`non_redactable_path:<path>`).

### 3.4 Disclosure presentation and audience binding

A disclosure presentation carries the signed receipt byte-for-byte
unchanged, the chosen subset of openings, and a binding:

    { "@version": "EP-SD-PRESENTATION-v1",
      "receipt": <signed disclosure-ready receipt>,
      "disclosed": [ { "path", "salt", "value" } ... ],
      "binding": { "audience", "nonce", "created_at" },
      "holder_proof": { "public_key", "signature" } (OPTIONAL) }

No signature is ever re-created; every presentation reuses the one issuer
signature. The binding names the relying party (`audience`) and echoes a
verifier-chosen fresh `nonce`. A verifier MUST refuse a presentation bound
to a different audience or nonce (`binding_audience_mismatch`,
`binding_nonce_mismatch`); this prevents a verifier from accepting a
presentation that was produced for someone else. Where possession matters,
the relying party pins a holder key and requires `holder_proof`, an Ed25519
signature over the binding digest (SHA-256 over the canonical bytes of the
domain-separated structure binding receipt digest, disclosed-set digest,
audience, nonce, and created_at). Verified-versus-accepted applies to the
holder proof exactly as -00 applies it to the display attestation: a
verifying holder proof under an unpinned key is VERIFIED, not ACCEPTED.

### 3.5 Verification

A verifier with the presentation, the pinned issuer key, and no network
access:

1. verifies the issuer signature over the receipt exactly as any
   EP-RECEIPT-v1 verifier does (all signed bytes are present, because
   undisclosed fields are commitments, not gaps);
2. checks the signed `disclosure` block against the non-redactable closed
   set, and that the plaintext CAID is present and well-formed;
3. checks commitment accounting: every declared path holds a well-formed
   slot, and no commitment-marker string appears at an undeclared path
   (`undeclared_commitment:<path>`);
4. recomputes each disclosed opening's commitment and compares it to the
   signed slot (`digest_mismatch:<path>` on failure, including any
   cross-field swap), refusing absent or short salts
   (`missing_salt:<path>`, `salt_too_short:<path>`) and salt reuse
   (`salt_reuse`);
5. checks the audience/nonce binding and, where pinned, the holder proof;
6. applies relying-party policy: any required field that is neither
   plaintext nor opened refuses with
   `undisclosed_required_field:<path>`.

Every failure is a structured refusal with a named reason. Hostile input
MUST produce a refusal, never a crash; refusal is the safe outcome, exactly
as -00 requires of the renderer.

## 4. Residual risk, stated

This profile hides field VALUES. It deliberately does not hide, and
implementers MUST NOT claim it hides:

- STRUCTURE. The verifier learns which fields exist, which were designated
  disclosable, and which were withheld: the signed `disclosure.paths` list
  is visible by design. A relying party can price what it was not shown.
- LINKABILITY. Two disclosure presentations of the same receipt share the
  same issuer signature bytes and the same commitment digests and are
  trivially linkable to each other. Unlinkable presentation is BBS
  territory, out of scope here.
- EQUALITY UNDER SALT REUSE. Salts exist because a digest over a
  low-entropy value (a currency code, a boolean, a small amount) is an
  oracle: without a salt, the verifier confirms guesses by recomputation.
  Per-field fresh salts are therefore mandatory and their absence is
  refused by construction, but a careless issuer that reuses salts ACROSS
  receipts recreates the oracle across those receipts, and no verifier can
  detect that from one presentation.
- POSSESSION. Audience/nonce binding without a pinned holder key stops a
  verifier from accepting someone else's presentation; it does not prove
  who holds the receipt. Pin a holder key where that matters.

The presentation attack of -00 is also unchanged by this section: selective
disclosure governs what a RELYING PARTY reads, not what the APPROVER saw.
A receipt whose approval was laundered through a dishonest surface stays
laundered no matter how it is disclosed; the deterministic renderer and
display attestation remain the -00 answer to that, and the two mechanisms
compose without touching each other's bytes.

## 5. Relation to prior art

SD-JWT [I-D.ietf-oauth-selective-disclosure-jwt] (OAuth WG) defines
salted-digest selective disclosure for JWTs, including the issuance-time
digest embedding and key-binding JWT this profile mirrors for a non-JWT,
JCS-canonical Ed25519 receipt. BBS signatures
[I-D.irtf-cfrg-bbs-signatures] (CFRG) provide multi-message selective
disclosure with unlinkable proofs at the cost of pairing-based cryptography
and a different signature scheme; this profile trades those properties away
to keep the existing receipt algorithm suite and offline verifier. The
contribution of this section is the PROFILE: the commitment domain, the
path-bound commitment structure, the closed non-redactable set that keeps a
redacted receipt meaning "this exact action", the audience/nonce binding,
and the named-refusal verification algorithm, with conformance vectors.

## 6. For the -01 assembly pass

- Fold the terminology note into -00's Terminology section.
- Register `EP-SD-v1`, `EP-SD-PRESENTATION-v1`, `EP-SD-COMMIT-v1`, and
  `EP-SD-BINDING-v1` alongside the -00 wire tags when the IANA section
  materializes.
- The Implementation Status appendix gains the reference implementation and
  vectors named at the top of this file.
