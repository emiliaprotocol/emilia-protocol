# AI Trust Desk — Master Services Agreement (DRAFT TEMPLATE)

> ⚠️ **This is a starting template, not legal advice.** It was drafted to save
> your attorney time, not replace them. Have a qualified lawyer review and
> adapt it before sending it to any customer. Fields in `[BRACKETS]` need your
> input. Liability, indemnity, and limitation clauses especially must be
> reviewed for your jurisdiction and risk tolerance.

---

**MASTER SERVICES AGREEMENT**

This Master Services Agreement ("Agreement") is entered into as of the date of
acceptance (the "Effective Date") by and between **[LEGAL ENTITY NAME]**, a
[Delaware C-Corporation / LLC] ("Provider," "we," "us"), and the customer
identified at checkout or on the order form ("Customer," "you").

By submitting an intake form or completing payment for an AI Trust Desk
engagement, Customer agrees to this Agreement.

### 1. Services
1.1 **Description.** Provider operates "AI Trust Desk," a service that (a) ingests
a security/compliance questionnaire and intake information supplied by Customer,
(b) drafts responses and AI-specific policy documents using a combination of
Provider's versioned policy templates and automated (LLM-assisted) drafting,
each answer bound to a cited source, (c) publishes a hosted "trust page" with
cryptographically signed, timestamped claims that Customer's prospective buyers
can independently verify, and (d) provides the tier-specific deliverables
described at the point of sale (the "Services").

1.2 **Human review.** Responses the automated pipeline flags as requiring human
judgment are reviewed by a Provider reviewer before publication. Provider does
not represent that every response is individually human-authored; Provider
represents that every published response is bound to a cited source and that
flagged responses receive human review.

1.3 **Tiers & turnaround.** Deliverables, price, and target turnaround for each
tier (Emergency Review, Full Completion, AI Trust Packet, Retainer) are as
stated at the point of sale. Turnaround targets are good-faith estimates, not
guarantees, and exclude time awaiting Customer information.

### 2. Customer responsibilities
2.1 **Accuracy of inputs.** Customer is solely responsible for the accuracy,
completeness, and lawfulness of all information it provides about its product,
security posture, data practices, subprocessors, certifications, and
operations. Provider's analysis and drafting rely on Customer's representations
and Provider does not independently audit or verify the truth of Customer's
underlying claims.

2.2 **Authority.** Customer represents it has authority to share the information
it submits and that doing so does not violate any third-party obligation.

2.3 **No certification claims.** Customer will not, and will not direct Provider
to, state on a trust page any certification (e.g., SOC 2, ISO 27001, FedRAMP,
HITRUST, PCI-DSS) that Customer does not actually hold.

### 3. Allocation of responsibility
3.1 **Provider is responsible for** the correctness of its analysis and policy
drafting given Customer's inputs, the operation and availability of the trust-
page platform, and the integrity of the cryptographic signing and verification.

3.2 **Customer is responsible for** the truth of the underlying facts about its
product and business that the Services describe. A trust page reflects
Customer's representations; it is not Provider's audit, certification, or
attestation of Customer's security.

### 4. Fees & payment
4.1 Fees are due in advance via the payment method presented at checkout
(processed by Stripe). One-time engagements are billed once; Retainer
engagements bill monthly with a [3]-month minimum term.
4.2 Fees are non-refundable except as required by law or as expressly stated.
4.3 Customer is responsible for applicable taxes.

### 5. Confidentiality
5.1 Each party will protect the other's Confidential Information with at least
reasonable care and use it only to perform or receive the Services.
5.2 Provider treats Customer's questionnaire content, intake information, and
non-public security details as Customer Confidential Information.
5.3 An NDA is available on request and, if executed, supplements this Section.

### 6. Data handling, retention & deletion
6.1 **Processing.** Provider processes Customer data to deliver the Services.
Provider's sub-processors are listed at
https://www.emiliaprotocol.ai/legal/sub-processors and include, for AI Trust
Desk, LLM providers (Anthropic, OpenAI) used on zero-retention API tiers and
not for model training, an email provider (Resend), hosting (Vercel),
database (Supabase), and payment processing (Stripe).
6.2 **AI processing.** Customer questionnaire text and product description are
transmitted to LLM providers at inference time to draft responses. Provider
configures these on zero-retention tiers and does not permit use of Customer
data for provider model training.
6.3 **Retention.** Published trust pages and their artifacts are retained for the
engagement term plus [12] months unless Customer requests earlier deletion.
6.4 **Deletion.** Customer may request deletion of its data at any time by
emailing [PRIVACY EMAIL]; Provider will delete within [30] days, excluding
backups that age out on Provider's ordinary cycle and records Provider must
retain by law.

### 7. Intellectual property
7.1 **Provider IP.** Provider retains all rights in the AI Trust Desk platform,
its policy templates, software, and methods. The underlying EMILIA Protocol is
Apache-2.0 licensed; this Agreement does not alter that license.
7.2 **Customer deliverables.** Upon full payment, Customer receives a
non-exclusive, perpetual license to use the completed questionnaire responses
and policy documents Provider delivers for Customer's own compliance and sales
purposes.
7.3 **Customer data.** Customer retains all rights in the information it submits.

### 8. Warranties & disclaimers
8.1 Provider warrants it will perform the Services in a professional and
workmanlike manner.
8.2 **EXCEPT AS EXPRESSLY STATED, THE SERVICES ARE PROVIDED "AS IS." PROVIDER
DISCLAIMS ALL OTHER WARRANTIES, EXPRESS OR IMPLIED, INCLUDING MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. PROVIDER DOES NOT
WARRANT THAT A TRUST PAGE WILL CAUSE ANY BUYER TO APPROVE, ACCEPT, OR CLOSE ANY
TRANSACTION.**

### 9. Limitation of liability
9.1 **NEITHER PARTY IS LIABLE FOR INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL,
OR PUNITIVE DAMAGES, OR LOST PROFITS OR REVENUE.**
9.2 **PROVIDER'S TOTAL AGGREGATE LIABILITY UNDER THIS AGREEMENT WILL NOT EXCEED
THE FEES CUSTOMER PAID TO PROVIDER IN THE [12] MONTHS PRECEDING THE CLAIM.**
9.3 These limits do not apply to a party's breach of confidentiality, Customer's
payment obligations, or a party's indemnification obligations [— confirm carve-
outs with counsel].

### 10. Indemnification
10.1 **Customer** will indemnify Provider against third-party claims arising from
(a) the inaccuracy of Customer's representations about its product or security,
or (b) Customer's unlawful or unauthorized submission of data.
10.2 **Provider** will indemnify Customer against third-party claims that the
AI Trust Desk platform infringes a U.S. intellectual-property right.

### 11. Term & termination
11.1 This Agreement applies to each engagement. Retainer engagements continue
month-to-month after the minimum term until cancelled with [30] days' notice.
11.2 Either party may terminate for the other's uncured material breach after
[15] days' written notice.
11.3 Sections 3, 5, 6, 7, 8, 9, 10, and 12 survive termination.

### 12. General
12.1 **Governing law:** [STATE], USA, excluding conflict-of-laws rules.
12.2 **Disputes:** [courts of [COUNTY, STATE] / binding arbitration via [AAA/JAMS]].
12.3 **Entire agreement:** this Agreement, plus the order/checkout terms and any
executed NDA, is the entire agreement and supersedes prior discussions.
12.4 **Assignment:** neither party may assign without consent, except to a
successor in a merger or sale of substantially all assets.
12.5 **Notices:** to Provider at [LEGAL EMAIL]; to Customer at the email on file.

---

**Provider:** [LEGAL ENTITY NAME] — [SIGNATORY NAME, TITLE]
**Customer:** acceptance via intake submission / checkout, or signature below.

---

## Pre-send checklist for the founder
- [ ] Fill every `[BRACKET]` (entity name, state, emails, retention windows, term)
- [ ] Lawyer review of Sections 8–10 (warranty / liability / indemnity)
- [ ] Confirm the liability cap is acceptable for a $24,500 engagement
- [ ] Decide: click-accept at checkout vs. countersigned PDF (click-accept is fine for self-serve; bigger deals may want a signature)
- [ ] Make sure `/legal/sub-processors`, `/legal/privacy`, `/legal/terms` are consistent with this MSA
- [ ] Confirm zero-retention claims with your actual Anthropic/OpenAI tier settings before stating them
