# EP Legal Framework

**Status:** v1 (Apr 2026).
**Disclaimer:** This document is authored by protocol maintainers, not by lawyers. It is a set of structural claims and recommendations for counsel — NOT legal advice. No operator should deploy Accountable Signoff into a high-stakes workflow without independent legal review of this framework in their jurisdiction. Where this document makes claims about legal effect, those claims are HYPOTHESES for counsel to validate, not warranties.

---

## 1. Why this document exists

Accountable Signoff is a novel primitive: it produces cryptographic evidence that a specific named human assumed ownership of a specific action at a specific time. Protocol-level novelty does not automatically map to legal-level recognizability. A cryptographically perfect signoff is worthless in a dispute if a court says "we can't use this as evidence."

Three questions need concrete answers per jurisdiction before EP-backed signoffs can be treated as authoritative:

1. **Evidentiary admissibility.** Under what conditions will a court treat an EP signoff attestation as admissible evidence of the signer's consent?
2. **Legal attribution.** Does "cryptographically attributed to a named human" equate to "legally attributable," and what defenses remain available (forgery claim, duress claim, lost-device claim)?
3. **Liability allocation.** When a cryptographically valid signoff turns out to be fraudulent (phished, coerced, or technically forged), who bears the loss — the operator, the signer, the relying party, or the counterparty?

EP gives each question a concrete technical substrate. None of that is worth anything unless the framework maps cleanly to the local legal regime.

---

## 2. Evidentiary model

The canonical claim EP asserts with a signoff attestation:

> At time T, authenticated identity I (bound to authority A under assurance level L) produced a signature S over the canonical hash H of a specific action context C, within challenge window W, from channel CH.

All eight elements — T, I, A, L, S, H, C, W, CH — are captured in the signoff attestation and in the hash-linked event log. All are cryptographically bound. All are reproducible from anchored state.

**What this likely supports (for counsel to verify):**

- **Authenticity**: the signature binds the attestation to the private key held by the authenticated identity. Under Federal Rule of Evidence 901 (US) / corresponding provisions elsewhere, this is a strong authentication basis IF the operator can establish that the private key was controlled by the named human at the time.
- **Integrity**: the hash chain and anchored Merkle root make log tampering detectable by any verifier. Integrity does not establish truth, but it establishes that the recorded evidence has not been altered post hoc.
- **Non-repudiation (weak form)**: the signer cannot plausibly deny having produced the signature without also claiming key compromise. Key compromise remains a valid defense; EP does not eliminate it, but it does produce a specific, investigable timeline for when compromise would have to have occurred.

**What this does NOT support:**

- **Proof of intent.** The signature proves the key produced it. It does not prove the named human understood what they were signing. Operators must maintain defensible interaction logs that the human *saw* the specific action context before signing. EP produces the technical substrate (`challenge_viewed` event, timing data); operator UX must produce the human-factors substrate (clear disclosure, no dark patterns).
- **Proof that the human was not coerced.** Cryptography is neutral on duress. Operators handling high-value authority (treasury, override, payment change) should implement additional out-of-band duress signaling.
- **Proof of capacity.** A signoff by a user who was cognitively impaired, not legally of age, or acting without authority the organization grants them is technically valid and legally questionable. This is an identity-layer problem, not a protocol-layer one.

---

## 3. Recommended operator posture

For each deployment, the operator SHOULD maintain:

1. **A written signoff policy** describing which roles may sign for which action classes, with explicit delegation rules. The written policy is the governance layer; EP enforces it mechanically. Without the written policy, the enforcement is legally unmoored.
2. **An identity enrollment record** for every human who holds signoff authority. This should include identity verification strength at enrollment, device or key provisioning attestation, and a signed acknowledgment by the user that they understand the authority conveyed. This record is the "the human controlled the key at the time" evidence.
3. **A UX attestation** that the signoff flow clearly disclosed the action being signed. Screenshots, UX test records, or a signed UX review by counsel. The goal is to preempt a later "I didn't know what I was signing" argument.
4. **An incident response playbook** for claims of key compromise or coerced signature. How fast is the key revoked? Who is notified? What is the standard of evidence for accepting such a claim? Silence here is a liability.
5. **A retention policy** for signoff events and attestations. Longer than dispute windows; shorter than indefinite (retention in perpetuity has its own privacy risks). A baseline of 7 years for financial contexts, adjusted per local retention law.

---

## 4. Jurisdictional notes (NOT a survey — flags for counsel)

### United States
- Federal Rules of Evidence 901, 902(13), 902(14) address authentication of electronic records. EP attestations plausibly qualify under 902(13)/(14) with a custodian certification; independent counsel review required.
- UETA and E-SIGN Act broadly recognize electronic signatures. Accountable Signoff is a stronger form, not a weaker one, so baseline recognition is plausible.
- State-level variation is material for notarization, medical, and public-benefit contexts. Government deployments must be verified per-state.

### European Union
- eIDAS 2 distinguishes simple, advanced (AES), and qualified (QES) electronic signatures. EP's current crypto substrate maps most naturally to AES; QES requires certified QSCD (qualified signature creation devices) which EP does not mandate. For a signoff to cross the QES threshold, the operator must integrate an eIDAS-certified QSCD into the signing step; this is compatible with EP but not automatic.
- **PSD2 Article 72 and 74** (see §5A.1) flip the burden-of-proof allocation for consumer payment transactions. This overrides §5 for any EU-facing payment deployment.
- GDPR retention and access rights apply to signoff attestations that contain personal data. Append-only logs require pseudonymization-at-ingest (see §6A) rather than mutation. Retention policy must defend against "delete my signoff events" requests through the pseudonymization pattern; operators who attempt to hold full personal data in the log will fail supervisory review.

### United Kingdom
- Electronic Communications Act 2000 and the UK GDPR analogue to the EU treatment. Post-Brexit divergence is small but counsel-specific.
- **PSRs 2017 Regulation 75** mirrors PSD2 Article 72 (see §5A.2); consumer burden cannot be shifted by contract.

### Singapore, Canada, Australia
- Each has an e-signature act with broad recognition. Accountable Signoff is a superset of typical e-signature evidence and should be recognized; no known reason to doubt.

### High-risk jurisdictions
- Jurisdictions with weak rule of law, aggressive data localization requirements, or state-level key escrow demands are not currently supported targets for signoff-backed workflows. Document the non-target list and revisit with counsel.

---

## 5. Liability allocation model (draft — B2B ONLY)

**Scope restriction: this allocation applies to business-to-business deployments only.** For consumer-facing deployments, see §5A.

A defensible default allocation, subject to contractual modification:

- **Operator**: liable for bugs in the protocol implementation, including failures of replay resistance, nonce generation, binding validation, or signature verification. Covered by warranty to integrators.
- **Integrator / relying party**: liable for deploying signoff on action classes that policy explicitly excludes, failing to enroll identities at appropriate assurance levels, or failing to maintain the written governance.
- **Signer**: in a B2B context, liable for actions signed unless they can establish key compromise with specific evidence (device lost on date X, forensic evidence of malware, etc.). The burden of proof on compromise is on the signer; the technical substrate to dispute is the event log + timing.
- **Counterparty / victim**: liable for zero in the normal case; their recourse is against the operator and integrator. This is the allocation the primary buyer is paying for.

This allocation is a proposal. It will be modified per deal. It should NOT be modified silently by one party.

### 5.1. Compromise-notification duty

A signer's "key compromise" defense is cognizable under this framework only if the compromise was reported:

- Within **24 hours of the signer's discovery** of the compromise, AND
- Within **30 days** of the attested compromise event, whichever is earlier,
- Via a documented channel (specified in the deployment contract) that is logged to the append-only audit log.

Late reporting does not categorically bar the defense — courts will assess facts — but it shifts the evidentiary weight against the signer. This mirrors the duty-to-report structure the card networks have used for decades and that financial counsel will recognize.

## 5A. Consumer and regulated-payment exceptions

The §5 allocation IS NOT legally enforceable in several jurisdictions for consumer-facing deployments or for payment transactions subject to regulated electronic-money regimes. Operators MUST carve these out explicitly.

### 5A.1. EU — PSD2 Articles 72 and 74

Under Directive (EU) 2015/2366 (PSD2), Article 72 places the burden of proof on the **payment service provider**, not the payer, for any disputed authenticated electronic payment. Article 74 limits payer liability to €50 for unauthorized transactions resulting from lost/stolen payment instruments, and to zero if the payer could not have been aware of the loss or if the operator failed to provide suitable means of notification. These are NON-DEROGABLE for consumer payment instruments.

A contractual clause attempting to shift the burden to a consumer is **void** under EU consumer protection doctrine and may trigger supervisory action from the relevant national competent authority (BaFin, AMF, De Nederlandsche Bank, etc.).

**Carve-out language** for any EU-facing deployment:

> For payment transactions subject to Directive (EU) 2015/2366 ("PSD2") or its successor, the burden-of-proof allocation in §5 is inapplicable. The operator bears the burden of proving authentication integrity per PSD2 Article 72. Payer liability is limited per PSD2 Article 74.

### 5A.2. UK — Payment Services Regulations 2017 (PSRs)

Regulation 75 of the PSRs 2017 mirrors PSD2. Post-Brexit divergence exists in detail, not structure. Carve-out language as above with PSRs citations.

### 5A.3. Germany — BGH case law on Anscheinsbeweis

The German Federal Court of Justice (BGH) has progressively tightened the evidentiary standard for online banking disputes over the past decade. A blanket "signer proves compromise" clause imposed on a consumer is likely unenforceable under §307 BGB as an unreasonable deviation from the statutory allocation. Operators deploying consumer-facing signoff in Germany MUST engage local counsel on a per-deployment basis; this framework does not attempt to predict the outcome.

### 5A.4. California and other US state-level variations

Several US states (notably California via amendments to UETA and analogous provisions in the CCPA/CPRA era) disfavor contractual shifting of authentication burden in consumer financial contexts. Deployments in regulated US financial verticals MUST incorporate state-specific review; the §5 default is a starting point for negotiation in B2B only.

### 5A.5. Consumer protection safe harbor

Operators who want to deploy consumer-facing signoff in any jurisdiction SHOULD default to the **inverse** of §5: operator bears the burden of proving authentication integrity; signer liability is capped per the local analog of PSD2 Article 74. This posture is more expensive for the operator and less finicky in every jurisdiction that matters.

---

## 6. Contract language skeleton

The following is illustrative, not complete. Use with counsel.

```
WHEREAS the Parties wish to allocate risk arising from cryptographically
authenticated action authorization via the EMILIA Protocol ("EP"), and
specifically from EP Accountable Signoff attestations ("Attestations"),

Section 1 (Authenticity). An Attestation is deemed authentic for purposes of
this Agreement if and only if:
  (a) it verifies under the operator's then-current authority set at the
      time of attestation, and
  (b) it is reproducible from the anchored Merkle root of the operator's
      event log, and
  (c) it includes a binding_hash matching the canonical binding envelope
      for the referenced action.

Section 2 (Non-Repudiation Defense). A Party against whom an Attestation is
asserted may rebut authenticity only by demonstrating, with specific and
contemporaneous evidence:
  (a) compromise of the authenticating key material prior to Attestation, or
  (b) duress or incapacity of the named human at the time of Attestation, or
  (c) a defect in the operator's implementation of EP sufficient to produce
      a false Attestation.

Section 3 (Liability Allocation). [Insert allocation per §5 above, modified
as negotiated.]

Section 4 (Retention). Each Party shall retain all Attestations, challenge
records, and anchored roots for at least [X] years from the date of
attestation, or for the statute of limitations applicable to the underlying
action, whichever is longer.
```

Again: this is a skeleton for counsel to refine. Do not paste this into a production contract.

---

## 6A. GDPR erasure and append-only logs

EP's hash-chained, anchored audit log is fundamentally incompatible with literal Article 17 erasure and Article 16 rectification: a chain cannot be edited without breaking integrity, and anchored Merkle roots cannot be rewritten at all. This is not a defect — integrity is the point — but it requires explicit design accommodation.

### 6A.1. The standard pattern: pseudonymization at ingest

EP deployments subject to GDPR MUST store personal identifiers (signer name, email, government ID numbers, device identifiers containing PII) in a **separate, mutable mapping table**, never directly in the append-only log or in the signed attestation material. The log entries reference the signer via:

```
signer_ref = HMAC-SHA256(deployment_salt, personal_identifier)
```

The `signer_ref` is a pseudonym — useless without the mapping. The mapping table is the GDPR-erasable artifact.

When an Article 17 erasure request is fulfilled:
- The mapping table entry for the requesting person is deleted.
- The `signer_ref` in the log becomes unlinkable. The log remains intact — integrity preserved, but the person is no longer identifiable.
- If the mapping was the only way to authenticate that signer in future workflows, the person is effectively de-enrolled from the system. Future Article 17 requests on the same pseudonym fail because there is nobody to link back.

This pattern satisfies Article 17 substantively (the person is no longer identifiable from system data) without requiring the log to be edited.

### 6A.2. Legitimate-interest balancing test

For the retention of pseudonymous log entries after erasure of the mapping, the lawful basis is legitimate interest under Article 6(1)(f). The balancing test must be documented in a DPIA-adjacent artifact; a template (for counsel to refine):

- **Purpose**: evidentiary integrity of high-stakes action authorization; dispute resolution; fraud investigation.
- **Necessity**: no less-intrusive alternative exists that preserves integrity.
- **Proportionality**: pseudonymization ensures that the log entry does not identify the person after erasure; integrity is preserved without ongoing identifiability.
- **Safeguards**: salt rotation policy, access controls on the mapping table, audit trail of mapping-table access, retention schedule for both tables.
- **Outcome**: legitimate interest prevails; retention is lawful on a pseudonymized basis.

The test must be reviewed periodically and per jurisdiction; the template is a starting point.

### 6A.3. Article 16 rectification

Rectification requests on fact errors (e.g., "this log entry says I signed, but I didn't") are addressed via the signed attestation material itself, not by editing the log. A rectification adds a new signed record declaring the disputed attestation invalid; the original remains in the chain as historical evidence, and the new record is the operative statement going forward. Courts and regulators are more comfortable with this "append correction" pattern than with editing integrity-critical logs.

## 7. Known hard problems

- **Cross-jurisdictional signoff.** A signer in Country A attesting to an action that executes in Country B raises conflicts of law. Default heuristic: the action's jurisdiction governs; the signer's jurisdiction governs the signer's capacity and consent. Counsel must confirm.
- **Consumer vs. B2B.** Consumer signoffs for financial actions may trigger consumer protection regimes (CFPA, PSD2 SCA, etc.) that EP does not automatically satisfy. B2B is the conservative first target.
- **Regulated industries.** Healthcare (HIPAA), financial (GLBA, SOX), and government (FedRAMP, FISMA) impose additional documentation and assurance requirements that EP supports but does not automatically provide. Every regulated deployment needs a compliance mapping.
- **Dispute discovery.** In litigation, an opposing party may demand disclosure of event logs, authority key material provenance, and identity enrollment records. The operator must be able to produce these, and the signer must be prepared for them to be produced. Document the discovery posture before signing.

---

## 8. Next steps for maintainers

1. **Engage outside counsel** (US federal + state; EU; UK; at minimum the initial pilot jurisdiction) to review this framework and issue opinions on the §2 evidentiary claims.
2. **Obtain a written FRE 902(13)/(14) custodian certification template** that operators can adapt for their log export procedures.
3. **Produce a one-pager** summarizing the operator-side written-policy requirements for integrators to adopt. Part of the standard deployment kit.
4. **Establish a precedent library** — as real signoffs are tested in real disputes (hopefully rare), document outcomes for future reference.
