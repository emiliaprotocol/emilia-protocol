# Citation and Claim-Annotation Packet

Status: public pre-submission working material. Do not represent it as a
submitted or peer-reviewed artifact until the cited revision and evidence hashes are frozen.

## Annotation vocabulary

Every technical sentence in the paper and its public derivatives carries one
of these evidence classes in the claim-to-evidence ledger:

- `FORMAL-TLC-BOUNDED`: TLC explored the complete finite state space named by
  the checked-in configuration. This is not an unbounded proof.
- `FORMAL-ALLOY-BOUNDED`: Alloy found no counterexample within the exact scope
  named by the checked-in command. This is not an unbounded proof.
- `FORMAL-TAMARIN-SYMBOLIC`: Tamarin verified the named lemma in the stated
  symbolic model and threat assumptions.
- `EXECUTABLE-CROSS-LANGUAGE`: the same deterministic vector was executed by
  the TypeScript, Python, and Go ports. This is conformance testing, not a
  refinement proof or an independent implementation claim.
- `IMPLEMENTED-REFERENCE`: the behavior exists in the reference code and its
  exact tests pass; no deployment or independent-operation claim follows.
- `STAGED-EXPERIMENTAL`: an artifact exists as public experimental source but is
  not deployed, independently audited, submitted, or externally reviewed.
- `EXTERNAL-DEPENDENCY`: the property depends on a relying-party pin, platform
  verifier, witness, provider, hardware root, or other party outside EMILIA.
- `VISION`: architecture or research direction with no present-tense product or
  security claim.

`VERIFIED` never appears without the method, scope, model, result artifact, and
assumptions. `PROVEN` is reserved for an actual proof of the precise statement.

## Citeable statements

### Current formal-method spine

> EMILIA is a capability-based authorization-receipt system for consequential
> machine actions. Its reference repository continuously checks complementary
> lifecycle, relational, and symbolic security models with TLC, Alloy, and
> Tamarin, and executes shared conformance vectors across TypeScript, Python,
> and Go. The model checks are explicitly bounded where applicable, the
> symbolic results state their threat assumptions, and cross-language
> conformance is not presented as a refinement proof.

Freeze the exact obligation, assertion, lemma, vector, and implementation
counts from the submission commit; do not copy counts from a deck or chat.

### Conservation of Authority

> Conservation of Authority is the non-amplification property of an accepted
> delegation: along every valid root-to-leaf path, action scope, amount ceiling,
> expiry, and remaining delegation depth are monotonically non-increasing.
> Across parallel children, aggregate budget conservation additionally requires
> an authoritative allocation proof and atomic reservation accounting.

This is not the scalar equation `authority_in = authority_out`. Authority is a
product order over heterogeneous constraints, and sibling allocations require
an independent aggregate bound. The repository's finite models can provide
bounded counterexample search. Calling this an unbounded machine-checked
theorem requires an inductive TLAPS, Lean, Coq, or Isabelle proof over arbitrary
valid chains and fan-out.

### Platform attestation as an AEC leg

> An `ep-platform-attestation` AEC component lets a relying party require that a
> signed EAT/JWT bind the same action and nonce to an accepted measured build,
> under relying-party-pinned external-Verifier result-signing keys, EAT profile,
> reference measurements, and freshness policy.

The claim is intentionally about appraisal of one signed token under explicit
pins. It does not establish silicon provenance, supply-chain integrity,
physical execution, absence of compromise, or generic conformance of every EAT
or platform-attestation format.

### Receipt Program

> The Receipt Program composes an already configured Gate, CAID resolution,
> bounded-capability reservation, provider execution, terminal evidence, and a
> signed certificate. Its formal model checks the abstract transition
> invariants; its executable tests cover the concrete cryptographic, storage,
> timeout, projection, and evidence-link boundaries that the abstract model
> intentionally omits.

Do not call the certificate a zero-knowledge proof, consensus result, provider
attestation, or independent proof of physical outcome.

## Primary references

- Leslie Lamport, *TLA+* and the TLC model checker:
  https://lamport.org/tla/tools.html
- Daniel Jackson, “Alloy: A Lightweight Object Modelling Notation,” ACM TOSEM
  11(2), 2002: https://people.csail.mit.edu/dnj/publications/alloy-journal.pdf
- Simon Meier, Benedikt Schmidt, Cas Cremers, and David Basin, “The TAMARIN
  Prover for the Symbolic Analysis of Security Protocols,” CAV 2013:
  https://beschmi.net/cav13.pdf
- RFC 8785, JSON Canonicalization Scheme:
  https://www.rfc-editor.org/info/rfc8785/
- RFC 9334, Remote ATtestation procedureS Architecture:
  https://www.rfc-editor.org/info/rfc9334/
- RFC 9711, Entity Attestation Token:
  https://www.rfc-editor.org/info/rfc9711/
- RFC 9782, Entity Attestation Token Media Types:
  https://www.rfc-editor.org/info/rfc9782/

## Venue facts

The official ETAPS 2027 call lists the TACAS paper deadline as **October 15,
2026 AoE** and mandatory TACAS artifact submission as **October 29, 2026 AoE**:
https://www.etaps.org/2027/cfp/

The paper should be pitched as an applied formal-methods system and artifact,
not as a new cryptographic primitive, processor architecture, or proof system.

## Language excluded from outbound material

Do not use “Trust Singularity Machine,” “physics,” “structurally impossible,”
“first,” “proves everything,” “no more ransomware,” “correct by construction,”
“the proof is the program,” fixed ZK proof-size/latency numbers, or assertions
that every computation is human-authorized. Those phrases collapse external
trust assumptions and unbuilt layers into claims the evidence cannot support.
