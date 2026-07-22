# TACAS 2027 Claim-to-Evidence Ledger

Status: public pre-submission working source; not a peer-reviewed security claim or artifact release.

## Citation-ready sentence

> EMILIA Protocol is a capability-based authorization-receipt system for consequential machine actions with CI-gated TLA+, Alloy, and Tamarin models of selected core invariants: 57 TLC obligations in the post-integration corpus (a 40-obligation handshake/capability baseline plus 14 Receipt Program invariants and three temporal properties); 32 bounded Alloy assertions; and 22 Tamarin lemmas, of which 19 verify and three deliberately falsified comparison lemmas expose missing consumption or registry-view pinning. Its shared conformance suite contains 329 vectors exercised by three same-team TypeScript/Node, Python, and Go reference ports. The repository also contains opt-in Ed25519 plus ML-DSA-65 and Bulletproofs prototypes outside the default receipt path, optional Merkle anchoring, and witness-cosigning code for which independent operators remain pending.

This is the longest defensible one-sentence version at the pinned revision. A paper abstract should normally use the first two clauses and move optional cryptographic and witness mechanisms to a scoped implementation section.

## Annotation vocabulary

Use these labels consistently in the manuscript, figures, and artifact:

- **SPECIFIED:** written as a property but not yet run.
- **BOUNDED-CHECKED:** TLC or Alloy completed with no counterexample under the stated finite configuration or scope.
- **SYMBOLICALLY VERIFIED:** Tamarin verified the named lemma under its Dolev-Yao theory and model assumptions.
- **FALSIFIED AS DESIGNED:** a deliberately weaker comparison lemma produced the expected counterexample.
- **EXECUTABLE EVIDENCE:** tests or conformance vectors passed; this is not a formal proof.
- **OPERATIONAL ASSUMPTION:** trust-anchor administration, clocks, deployment, hardware, or external services are relied on but not proven by the protocol model.
- **NOT MODELED:** no formal model currently covers the claim.

These annotations become citeworthy when each one is attached to an immutable source revision, exact file and property name, tool version, raw result, and artifact hash. A later DOI can identify the released bundle; it must not be minted or published before the submission artifact is approved.

## Claim table

| ID | Defensible claim at snapshot | Status and scope | Repository evidence |
|---|---|---|---|
| C1 | The public TLC corpus checks separate handshake, capability, Receipt Program, Trust Program, lifecycle-remedy, and Authority Program models. | BOUNDED-CHECKED only for each named configuration. Freeze and regenerate the aggregate obligation count from the submission commit; do not infer that every named property is an invariant. | `formal/*.cfg`; `formal/*.tla`; `formal/results/`; `formal/PROOF_STATUS.md`; `.github/workflows/tlc.yml` |
| C2 | The handshake model completed the recorded one-handshake exploration with 413,137 generated and 45,342 distinct states and no error. | BOUNDED-CHECKED only for the named constants and event bound. The two-handshake exploration was not exhaustively completed. | `formal/PROOF_STATUS.md`; `formal/ep_handshake.tla`; `formal/ep_handshake.cfg` |
| C3 | Alloy checks 32 assertions across four bounded relational models. | BOUNDED-CHECKED under each model's finite scope and facts. Signature verification is abstracted in relevant models. | `formal/ep_relations.als`; `formal/ep_federation.als`; `formal/ep_quorum.als`; `formal/ep_delegation.als`; `formal/AlloyCheck.java`; `formal/PROOF_STATUS.md`; `.github/workflows/alloy.yml` |
| C4 | The Tamarin corpus contains 22 lemmas: 19 verified and three deliberately falsified comparison lemmas. | SYMBOLICALLY VERIFIED or FALSIFIED AS DESIGNED under the model's Dolev-Yao theory. This is not computational cryptographic proof. | `formal/tamarin/ep_receipt_core.spthy`; `formal/tamarin/ep_quorum_core.spthy`; `formal/tamarin/ep_reliance_composed.spthy`; `formal/tamarin/README.md`; `formal/PROOF_STATUS.md`; `.github/workflows/tamarin.yml` |
| C5 | One-time consumption is load-bearing for injective acceptance/execution in the modeled symbolic protocols. | The core no-consumption comparison and the composed no-consumption comparison are deliberately falsified; the corresponding consumption-bearing lemmas verify. State this as a modeled necessity result, not universal impossibility of replay. | `unchecked_acceptance_is_injective`; `injective_acceptance_with_consumption`; `unchecked_composition_is_injective`; `injective_execution_with_consumption` in the Tamarin sources and recorded results |
| C6 | Exact registry-view pinning is load-bearing in the composed symbolic model. | FALSIFIED AS DESIGNED: omitting the exact current view admits the stale-view trace; the strict-view lemma verifies. | `strict_registry_view_is_exact`; `unchecked_registry_view_is_current` in `formal/tamarin/ep_reliance_composed.spthy` and `formal/tamarin/results/ep_reliance_composed.summary.txt` |
| C7 | The conformance corpus records 21 suites, 329 vectors, and three reference ports. | EXECUTABLE EVIDENCE. `relationship` is explicitly `same_team_ports`. The TypeScript source executes as a Node/JavaScript runtime beside Python and Go. | `lib/proof-stats.json`; `conformance/conformance-manifest.json`; `conformance/run.mts`; `.github/workflows/ci.yml` |
| C8 | CI runs the three language ports against shared vectors and separately gates TLC, Alloy, and Tamarin. | EXECUTABLE/OPERATIONAL evidence at the pinned revision. CI is not a refinement proof and does not prove the hosted runner or release pipeline trustworthy. | `.github/workflows/ci.yml`; `.github/workflows/tlc.yml`; `.github/workflows/alloy.yml`; `.github/workflows/tamarin.yml` |
| C9 | A strict clean-room independent implementation has not yet been accepted. | Negative scope fact. The recorded Rust candidate has `strictCleanRoomAcceptance: false`; do not market same-team ports as independent. | `lib/proof-stats.json`; `conformance/clean-room/conformance-manifest.v1.json`; `conformance/external/` |
| C10 | Delegated capability authority is modeled as monotonically non-increasing. | BOUNDED-CHECKED in TLA+ and Alloy under stated bounds; executable enforcement remains separate. | `DelegationAuthorityNonIncreasing` in `formal/ep_capability.tla`; `AuthorityNonIncreasing` in `formal/ep_delegation.als`; `packages/gate/src/capability-receipt.ts` |
| C11 | `EP-AUTHORITY-PROGRAM-v1` is a pure verifier over a relying-party-pinned signed recursive series/parallel program and immutable signed stage receipts. | PUBLIC EXPERIMENTAL EXECUTABLE EVIDENCE. It rejects arbitrary DAG vocabulary, requires a relying-party root CAID/action binding decision, verifies exact predecessor receipt digests, joins separately verified AEC/AOM results, requires capability narrowing and authoritative parallel allocation, and always returns `freshness_proven: false`, `revocation_checked: false`, and `execution_proven: false`. It is not deployed, independently reviewed, or an adopted standard. | `packages/verify/src/authority-program.ts`; `packages/verify/authority-program.test.ts`; `docs/architecture/AUTHORITY-PROGRAM.md`; `conformance/vectors/authority-program.v1.json` |
| C12 | Conservation of Authority can be stated for the authority-program fold: validity implies every stage's capability is narrowed and every parallel allocation is authoritative. | BOUNDED-CHECKED in the representative four-stage nested series/parallel TLC configuration. Callback correctness remains a relying-party assumption; the model does not inspect native capability arithmetic. | `formal/ep_authority_program.tla` invariant `ConservationOfAuthority`; `formal/ep_authority_program.cfg`; `packages/verify/src/authority-program.ts` |
| C13 | Authority-program verification proves neither freshness, current non-revocation, nor material execution. | BOUNDED-CHECKED execution exclusion plus executable result contract. `executionProven` remains false in every modeled state; the verifier also reports `freshness_proven: false` and `revocation_checked: false` in every outcome. | `NoExecutionProof` in `formal/ep_authority_program.tla`; closed result fields in `packages/verify/src/authority-program.ts` and its test |
| C14 | The receipt-program kernel has executable CAID, capability, terminal-outcome, and evidence checks, and its bounded lifecycle model contributes 14 invariants plus three temporal properties. | EXECUTABLE EVIDENCE plus BOUNDED-CHECKED lifecycle abstraction. The model does not prove TypeScript, database linearizability, cryptography, provider truth, wall-clock deadlines, settlement, or arbitrary concurrency. Python and Go receipt-program ports are explicitly absent. | claim `receipt-program-is-caid-bound-budgeted-and-terminal` in `security/claims.v1.json`; `packages/gate/src/receipt-program.ts`; `packages/gate/receipt-program.test.ts`; `formal/ep_receipt_program.tla`; `formal/ep_receipt_program.cfg` |
| C15 | The repository has an opt-in Ed25519 plus ML-DSA-65 prototype. | EXECUTABLE prototype only. It is not wired into default `EP-RECEIPT-v1`, deployed Gate receipts, or FIPS validation. | `packages/verify/src/pq-hybrid.ts`; `packages/verify/pq-hybrid.test.ts`; `docs/RECEIPT-CLAIMS.md` |
| C16 | The repository has an optional Bulletproofs range-receipt envelope. | EXECUTABLE optional backend/prototype; not invented cryptography and not evidence that every deployment uses zero knowledge. | `packages/gate/src/zk-range-proof.ts`; its tests and exported declarations |
| C17 | Receipt formats support optional Merkle inclusion anchoring. | EXECUTABLE/specification evidence. A Merkle anchor proves inclusion relative to the selected root; it does not prove statement truth or independent operation. | `docs/trust-receipt-spec.md`; receipt verifier and conformance vectors; `docs/RECEIPT-CLAIMS.md` |
| C18 | The repository has a witness-cosigning design and reference implementation. | EXECUTABLE reference evidence only. Independent operators and a deployed multi-operator witness network remain pending. | `packages/verify/src/witness.ts`; `packages/verify/witness.test.ts`; witness server/emitter sources; `docs/RECEIPT-CLAIMS.md` |
| C19 | An `ep-platform-attestation` AEC component consumes a closed EAT/JWT appraisal result only under relying-party-pinned verifier key, profile, audience, nonce, action digest, accepted build measurement, clock, and age limit. | IMPLEMENTED-REFERENCE plus EXTERNAL-DEPENDENCY. The verifier refuses presenter keys and component-verifier replacement and returns `hardware_verified: false`. It does not appraise raw TPM/TEE evidence or prove hardware genuineness. No Python, Go, deployed hardware, or independent operator is claimed. | `packages/verify/src/platform-attestation.ts`; `packages/verify/platform-attestation.test.ts`; `conformance/vectors/platform-attestation.v1.json`; `docs/PLATFORM-ATTESTATION-AEC.md`; claim `platform-attestation-result-is-rp-pinned-and-action-bound` in `security/claims.v1.json` |

## Reproducible count derivation

The paper must regenerate, not manually transcribe, these totals:

```text
TLC baseline obligations = 26 ep_handshake invariants
                         + 10 ep_capability invariants
                         +  4 ep_capability temporal properties
                         = 40

Receipt Program addition = 14 invariants
                         +  3 temporal properties
                         = 17

Selected TLC paper corpus = 40 + 17 + 12 = 69 obligations

Alloy assertions = 15 relations
                 +  7 federation
                 +  6 quorum
                 +  4 delegation
                 = 32

Tamarin lemmas = 5 receipt-core
                + 5 quorum-core
                + 12 composed-reliance
                = 22 total = 19 verified + 3 deliberately falsified
```

`lib/proof-stats.json` is a generated summary and may intentionally expose narrower method-specific fields. The paper must not treat a single aggregate object as the complete corpus count without reconciling it against every checked configuration and Tamarin source in the frozen submission revision.

### Receipt Program integration freeze

The public Receipt Program model must be content-bound again at the final submission freeze:

- `formal/ep_receipt_program.tla` SHA-256: `3fe3b4b4219540b9e11f0fc0f7d723076a32cfc47b60fc0f19184d9cafffd393`
- `formal/ep_receipt_program.cfg` SHA-256: `b08be183d459990a8deda29b7cb20fcbb14db32293906481a733aed254f3c18c`
- TLC 2.19 result: no error; 1,729 states generated, 780 distinct states, depth 10.
- Configuration count: 14 invariants and three temporal properties.

The complete run is recorded in
`formal/results/ep-receipt-program.tlc.summary.txt`. Before paper submission,
replace the candidate hash with the merged artifact-freeze commit and rerun TLC
from that exact clean revision.

## Threats to validity

### Internal validity

- The models and implementations are maintained by the same organization; shared misunderstandings can survive all three ports.
- Conformance vectors can encode the same specification mistake as the implementations.
- Generated statistics can lag model files. Every submission build must fail on count drift.
- The authority-program model abstracts callback correctness to booleans; it proves the fold rejects failed root binding, narrowing, or allocation assertions, not that a callback's native verifier is correct.

### Construct validity

- “Authorization,” “identity,” “execution,” and “truth” are distinct. A valid receipt does not establish natural-person identity, legal authority, comprehension, physical outcome, or current revocation unless the selected profile supplies those inputs.
- “No replay” is scoped to a conforming shared atomic consumption domain, not every independent executor worldwide.
- Merkle inclusion, witness signatures, and platform attestation establish different facts and must not be collapsed into one trust score.

### External validity

- TLC and Alloy results are bounded; larger concurrency or topology may expose behavior outside checked scopes.
- Tamarin is symbolic and omits computational probabilities, implementation parsing, wall clocks, full WebAuthn internals, and several operational trust systems.
- There is no accepted independent clean-room port at the pinned revision.
- There is no deployed independent witness fleet, hardware-attestation evaluation, or production settlement evaluation supporting the paper's core claims.

### Conclusion validity

- “No counterexample within the model” is not “secure in all deployments.”
- Cross-language agreement is not a proof that the specification is correct.
- A deliberately falsified weaker lemma establishes a counterexample to that weaker model; it does not by itself prove the restored mechanism is sufficient outside the stronger modeled assumptions.

## Do-not-claim list

- Do not claim EP is the first authorization-receipt, staged-approval, or distributed-trust system.
- Do not use 40 as the selected paper-corpus TLC total. The exact formulation is a 40-obligation baseline plus 17 bounded Receipt Program obligations plus 12 bounded Authority Program obligations, for 69 total; do not call all 69 invariants.
- Do not claim all 22 Tamarin lemmas verify; 19 verify and three are deliberately falsified comparison lemmas.
- Do not claim independence for the three same-team reference ports.
- Do not claim a formal refinement proof from TLA+/Alloy/Tamarin to TypeScript, Python, or Go.
- Do not claim global replay impossibility, universal atomicity, or execution truth.
- Do not claim the bounded Receipt Program model proves implementation correctness, provider truth, settlement, or arbitrary concurrency.
- Do not claim the authority-program verifier proves freshness, non-revocation, or execution; its result explicitly says each is unproven or unchecked.
- Do not claim DTC settlement is production infrastructure. The public Base profile is experimental source until independently audited and deployed.
- Do not claim new cryptography, post-quantum security, FIPS validation, or a production zero-knowledge deployment.
- Do not claim an independent witness network, independent hardware attestation, or independently reproduced settlement.
- Do not claim standards adoption merely because private or submitted Internet-Draft sources exist.
- Do not use “physics,” “structurally impossible,” “no more ransomware,” “unhackable,” or category-wide impossibility language.

## Evidence-freeze checklist

- Record `git rev-parse HEAD` and require a clean worktree.
- Hash every model, config, runner, raw result, vector manifest, and paper table input.
- Pin TLC, Alloy, Tamarin, Maude, Java, Node, Python, and Go versions.
- Re-run all models and vectors from a clean container or VM.
- Generate the count table mechanically and diff it against the manuscript.
- Preserve raw positive and negative outputs, including falsified traces.
- Have one person who did not implement the relevant verifier execute the artifact instructions.
- Create public `CITATION.cff`, archival DOI, and Software Heritage/Zenodo links only after explicit publication approval.
