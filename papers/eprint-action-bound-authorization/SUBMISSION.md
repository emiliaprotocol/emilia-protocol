# ePrint submission metadata

Status: not submitted.

## Title

Offline Evidence, Online Admission: Action-Bound Human Authorization Under a Signature-Soliciting Adversary

## Author

Iman Schrock, EMILIA Protocol, Inc.

## Suggested category

Cryptographic protocols

## Keywords

Action binding, authorization evidence, digital signatures, replay prevention, symbolic analysis, Tamarin, AI agents

## Submission abstract

An agent can hold a valid session and broad delegated authority while still needing a human decision for one consequential action discovered during execution. A signed approval artifact can provide portable evidence that an uncompromised approver key signed a canonical commitment to the exact action. It cannot, by itself, provide global one-time admission. We formalize this separation under an adversary that controls the network and approval orchestrator and may solicit honest signatures over arbitrary actions. Under standard signature, hash, and canonical-encoding assumptions, offline verification gives action agreement. We then show that a static artifact presented to two isolated, correct verifiers can be accepted once by each, so replay prevention requires a shared atomic consumption domain, equivalent coordination, or a uniquely addressed admission domain. Two Tamarin models verify action binding and injective acceptance within one consumption domain, while finding the expected counterexamples when consumption is omitted or split across domains. The result is a narrow placement rule: signatures make authorization evidence portable; state at the execution boundary makes admission one-time.

## Editor-facing scope check

- Self-contained construction and adversary model
- One central positive result and one central negative result
- Computational proof sketch for cross-action non-transferability
- Machine-checked symbolic models with retained negative controls
- Explicit assumptions and exclusions
- No dependence on the EMILIA product or Internet-Drafts for the argument
