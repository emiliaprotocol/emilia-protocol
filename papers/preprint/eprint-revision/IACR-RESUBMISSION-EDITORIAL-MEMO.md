# IACR ePrint resubmission editorial memo

Date: 30 August 2026

## Scope of the comparison

The comparison used the five newest ePrint reports by archive sequence when the
review began. Their histories each show archive approval on 30 August 2026.
That approval is an ePrint screening decision, not peer review.

1. [2026/1833, *On the Fault Injection Security of White-box Ciphers*](https://eprint.iacr.org/2026/1833.pdf)
2. [2026/1832, *Universally Composable Hybrid PAKE Secure Against Harvest-Now-Decrypt-Later Attacks*](https://eprint.iacr.org/2026/1832.pdf)
3. [2026/1831, *Silent-Share*](https://eprint.iacr.org/2026/1831.pdf)
4. [2026/1830, *The Extended Wedge Attack*](https://eprint.iacr.org/2026/1830.pdf)
5. [2026/1829, *Decomposed LWE is Equivalent to Succinct LWE*](https://eprint.iacr.org/2026/1829.pdf)

All five PDFs were read end to end. Report 1832 is the direct cryptographic-
protocol comparator. Reports 1831, 1833, 1830, and 1829 were used for model,
novelty, attack, and proof presentation respectively.

## Editorial pattern that cleared the archive screen

The five reports differ technically, but their readable core follows the same
sequence:

1. State one concrete problem before introducing a name for the solution.
2. Make the adversary and winning event explicit.
3. Give a complete construction or protocol in one place.
4. Present a dependency ladder from definitions to lemmas to the main theorem.
5. Separate computational assumptions from state, implementation, or timing
   assumptions.
6. Explain novelty by comparison to the closest result, not by adjectives.
7. Put full reductions, algorithms, or executable evidence in the report.
8. State negative results and limitations next to the claims they qualify.

## How v5 applies that pattern

- The title now says the exact scope: per-issuance authorization
  non-amplification under chosen-context signature collection.
- The abstract begins with the minimal failure: one genuine approval can reach
  two provider entries without a signature forgery.
- The introduction states one research question and includes a result map that
  assigns each claim to its load-bearing assumption.
- The paper defines a stateful authorization-admission syntax, EUF-CMA,
  collision resistance, the typed encoding, key-purpose separation, the oracle
  experiment, and its exact win conditions.
- Validated caller input, issuance storage, and the unique `Issued` witness are
  now joined at the issue boundary. The real-resource predicate catches both
  mutated input and byte-identical duplicate issuance.
- The exact action and evidence map are carried through
  `ValidatedEntryInput`, independently checked by mediation, and preserved in
  the entry event.
- Independently generated enrollment keys now have an explicit
  `KeyCollision` bad event rather than a silently conditioned setup.
- Successful consumption must atomically emit one exact `Consumed` event; a
  returned token without the trace event is charged as a registry failure.
- The main result is split honestly. The exact-witness theorem is the
  cryptographic reduction; the one-entry result follows from the explicit
  linear state resources; a corollary composes the two.
- A worked no-forgery replay attack and a closest-work table make the novelty
  relational and falsifiable.
- Detailed Tamarin counts were moved to an appendix. The main text uses the
  models only as bounded case studies, not as a proof of the computational
  theorem or a database implementation.

## Submission claim

The bounded contribution is an exact cross-role correspondence from issued,
multi-signer authorization evidence to a provider-entry event under adaptive
chosen-context collection, with cryptographic authenticity separated from
stateful single-use enforcement.

The paper does not claim that signatures create one-time state, that the idea
of replay prevention is new, that one issuance exhausts semantically equivalent
authority, or that provider entry proves a physical effect.
