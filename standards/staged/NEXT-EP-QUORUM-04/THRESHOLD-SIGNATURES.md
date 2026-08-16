# Staged car for ep-quorum -04: threshold signatures are not quorum approval

Status: STAGED, NOT FILED. Draft-ready Security Considerations text extending
section 10.8 of draft-schrock-ep-quorum-03. Rides only with a revision that
carries its own substance, per the substance rule. Grounded in a full read of
the posted -03 text on 2026-08-16.

## Why this paragraph exists now

Section 10.8 of -03 already refuses the conflation of human quorum with
threshold SECRET CUSTODY (m-of-n share reconstruction). The adjacent and now
practical proposal it does not yet answer is threshold SIGNING: FROST
(RFC 9591) makes m-of-n Schnorr co-signing that emits one aggregate signature
cheap and standardized, and "replace your multi-signature ceremony with one
threshold signature" is a foreseeable suggestion. Answering it in print before
it is proposed is the cheapest defense of the design choice EP-QUORUM already
made: separate, individually attributable, action-bound approver signatures.

## Proposed Security Considerations text (new subsection after 10.8)

### 10.9. Human quorum is not an aggregate threshold signature

Threshold signature schemes such as FROST (RFC 9591) allow m of n key-share
holders to jointly produce a single signature verifiable under one group
public key. Such an aggregate signature proves that a sufficient subset of
share holders participated in a signing protocol for the signed bytes. It
does not provide what EP-QUORUM's evidence model requires:

- Attribution. The aggregate signature does not identify WHICH m share
  holders participated. The quorum trail's per-approver requirements --
  distinct enrolled identity, role admission, order position, and timing for
  each named approver -- cannot be satisfied by a signature that names no
  individual. A dispute, revocation, or after-the-fact accountability
  question ("which accountable human said yes?") has no answer in the
  aggregate form.

- Ceremony binding. Participation in a signing protocol round is not the
  EP-QUORUM approval ceremony. Nothing in the aggregate proves that each
  participating share holder separately reviewed the exact action content,
  acted within an admitted role, or acted within the approval window.

- Failure semantics. An aggregate signature either verifies or does not. The
  quorum trail's incremental states (under_threshold, expired member
  approval, order violation) and their named refusals have no counterpart,
  so a relying party loses the ability to say WHY a quorum is not satisfied.

Implementations and public claims MUST NOT describe an aggregate threshold
signature, however produced, as EP-QUORUM approval. This is a statement
about evidence semantics, not about the cryptographic quality of threshold
schemes: for key protection of a SINGLE enrolled approver, a threshold
scheme protecting that one approver's key is compatible with this document,
because the resulting signature still attributes to that one named approver.

Accountable and traceable threshold signature schemes in the literature aim
to restore signer attribution to aggregate signatures. A future presentation
profile could evaluate whether such a scheme can carry per-approver,
action-bound ceremony evidence equivalent to separate signatures. Until a
scheme demonstrably does, the separate-signature design is retained
deliberately: for testimony, aggregation is a compression of exactly the
information the trail exists to preserve.

## Falsifier and review note

If a FROST-based approval proposal appears in the corpus, this text is the
prepared answer (frontier board item 7, falsifier calendar 2026-11-15). If an
accountable-threshold scheme with per-signer attribution and per-approver
ceremony binding is published and implemented, revisit the final paragraph
rather than hardening it.
