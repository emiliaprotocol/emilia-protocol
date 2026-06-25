Re: Pre-rulemaking comment — Automated Decision-Making Technology Act (SB 26-189)

Submitted by: Iman Schrock, EMILIA Protocol (team@emiliaprotocol.ai) — an open-source (Apache-2.0) standard for verifiable human authorization of consequential automated actions.

Thank you for the opportunity to comment. We offer one focused, vendor-neutral recommendation aimed at making the Act's accountability and human-oversight provisions provable rather than merely asserted.

The problem the rules can solve. When an automated system participates in a consequential decision, the central question an auditor, a consumer, or this Office will ask is: was a human actually responsible for this specific decision, and can that be shown after the fact? Today the answer usually lives in a deployer's own logs — records the deployer can edit and that no outside party can independently verify. "A human reviewed this" is, in practice, an unfalsifiable claim. As decisions are made at machine speed and volume, self-attested logs are a weak foundation for accountability.

Recommendation. Where the rules address documentation of human review or oversight, a consumer's right to human review or to appeal, or the records a deployer must retain, we encourage the Office to recognize — and to permit deployers to satisfy those obligations with — independently verifiable authorization records: a record that

- is bound to the specific decision (so it cannot be reused for a different one),
- is attributable to a named, accountable human reviewer or approver,
- is tamper-evident, and
- can be verified by a third party without trusting the deployer's own systems.

This is technology- and vendor-neutral: it specifies properties, not a product, and can be met with standard, royalty-free cryptography (digital signatures over a canonical record of the decision). Recognizing such records would let deployers demonstrate compliance with confidence, give consumers a meaningful basis for appeal, and give this Office an artifact it can actually audit — rather than a log it must take on faith.

Offer. We maintain an open, royalty-free specification and a working, offline verifier for exactly this kind of human-authorization record, published as IETF Internet-Drafts. We would be glad to provide technical input, a worked example, or testimony to the rulemaking at no cost. We have no product to sell the State; our interest is simply that the accountability the Act envisions be verifiable in practice.

Respectfully submitted,
Iman Schrock
EMILIA Protocol · team@emiliaprotocol.ai · github.com/emiliaprotocol
