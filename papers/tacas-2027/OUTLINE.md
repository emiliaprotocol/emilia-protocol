# TACAS 2027 Paper Outline

Status: public pre-submission working source; not submitted or peer reviewed.

## Venue and deadline contract

Target category: TACAS 2027 case-study paper, maximum 18 pages excluding the bibliography.

- Paper submission: Thursday, October 15, 2026, Anywhere on Earth (AoE).
- TACAS mandatory artifact submission: Thursday, October 29, 2026, AoE, for regular tool and tool-demonstration papers.
- Important category boundary: the official ETAPS call makes artifact evaluation voluntary, after acceptance, for research and case-study papers. This outline nevertheless treats October 29 as the internal artifact-grade reproducibility freeze. If the paper is reclassified as a regular tool paper, October 29 becomes the actual mandatory artifact deadline.
- Official source: <https://etaps.org/2027/cfp/>.

## Working title

**Mechanically Checked Authorization Receipts: A Tri-Method Case Study Across Three Language Ports**

The title deliberately claims a case study and mechanically checked properties. It does not claim a new model-checking algorithm, a refinement proof, independent implementations, universal security, or new cryptography.

## One-sentence thesis

A consequential-action authorization protocol can keep its specification, selected safety claims, negative counterexamples, and three same-team language ports from silently drifting by binding complementary formal models and shared conformance vectors into continuous integration.

## Draft abstract

Authorization receipts bind a consequential machine action to evidence of approval, policy, and one-time consumption. Their security depends not only on cryptography but on lifecycle, delegation, quorum, registry, replay, and consequence-boundary invariants that cross specification and implementation boundaries. This paper presents an industrial case study of EMILIA Protocol's verification methodology. The selected TLA+/TLC corpus checks 69 obligations: a 40-obligation handshake/capability baseline, 14 invariants and three temporal properties for the bounded Receipt Program lifecycle, and 11 invariants plus one liveness property for a bounded Authority Program fold. Alloy checks 32 bounded relational assertions over receipt, federation, quorum, and delegation structures; and Tamarin analyzes 22 symbolic-protocol lemmas, with 19 verified and three deliberately falsified comparison lemmas that expose replay or stale-registry behavior when load-bearing restrictions are removed. The repository then exercises shared conformance vectors through TypeScript/Node, Python, and Go reference ports in CI. We report what each method establishes, where their assumptions do not compose, and how negative results changed the modeled protocol. The study does not claim a refinement proof, independent implementations, computational cryptographic proofs, global replay prevention, or that a model proves a deployed settlement system. It contributes a reproducible claim-to-evidence discipline for authorization protocols whose failures can trigger monetary, infrastructure, or other irreversible effects.

## Contributions

1. **Tri-method specification by semantic fit.** TLA+ covers lifecycle and bounded capability state; Alloy covers bounded relational, delegation, federation, and quorum structure; Tamarin covers an unbounded symbolic attacker over selected receipt, quorum, registry, consumption, and execution bindings.
2. **Negative results as design evidence.** Three deliberately unsafe Tamarin comparison lemmas are falsified. They demonstrate same-receipt replay without consumption and stale-registry acceptance without exact registry-view pinning. These are necessity demonstrations, not failed headline guarantees.
3. **Specification-to-port drift control.** Shared conformance vectors are run through TypeScript/Node, Python, and Go ports. They are same-team ports and provide consistency evidence, not independent interoperability evidence or a refinement proof.
4. **A claim-to-evidence publication method.** Every numerical and security claim is assigned a status, model boundary, source path, tool version, immutable revision, and reproducibility command. Unsupported category claims are excluded before submission.
5. **Authority composition.** A bounded TLA+ model mirrors the pure `EP-AUTHORITY-PROGRAM-v1` series/parallel verification fold and states Conservation of Authority: a valid program result requires stage-scoped capability narrowing and authoritative parallel allocation. It explicitly preserves `execution_proven = false`. The model is public, bounded, same-team evidence and is not an independent proof of execution.

## 18-page structure

Page budgets exclude bibliography and should be treated as ceilings.

1. **Introduction and failure model — 1.5 pages**
   - Consequential machine actions and why receipt verification is a state/composition problem, not only a signature check.
   - Research questions: which properties belong in which formalism; how model and implementation drift is detected; what negative models reveal.
   - Contributions and exact non-claims.

2. **Protocol and trust boundaries — 2.0 pages**
   - Action digest, approval context, quorum, consumption, relying-party pins, CAID, capability attenuation, and execution boundary.
   - Verified versus accepted; issuer claim versus relying-party trust.
   - One figure: authorization/evidence/consequence boundary, with trust roots and online state called out.

3. **Methodology and evidence discipline — 1.5 pages**
   - Why TLA+, Alloy, and Tamarin are complementary rather than redundant.
   - Status vocabulary: specified, checked within bounds, symbolically verified, deliberately falsified, executable-only, and out of scope.
   - Immutable evidence snapshot, generated statistics, CI workflows, and claim ledger.

4. **TLA+ lifecycle and capability models — 2.5 pages**
   - `ep_handshake.tla`: 26 invariants under one-handshake bounded exploration.
   - `ep_capability.tla`: ten invariants and four temporal properties under finite budgets, operations, capabilities, delegation depth, and ticks.
   - `ep_receipt_program.tla`: 14 invariants and three temporal properties for two attempts contending over one stable operation identifier. This is a bounded control-flow abstraction, not proof of TypeScript, database linearizability, provider truth, or settlement.
   - Counterexamples found while authoring and fixes made.
   - State-explosion limit: the two-handshake search was not exhaustively completed.

5. **Alloy relational models — 2.0 pages**
   - 32 assertions across `ep_relations.als`, `ep_federation.als`, `ep_quorum.als`, and `ep_delegation.als`.
   - SAT scope and abstracted signature assumptions.
   - Why bounded relational checks do not establish unbounded protocol security.

6. **Tamarin symbolic analysis and negative results — 2.5 pages**
   - Core receipt, quorum, and composed reliance models.
   - 22 total lemmas: 19 verified, three deliberately falsified comparison lemmas.
   - Replay without consumption and stale registry view without exact pinning.
   - Dolev-Yao and symbolic-encoding assumptions; WebAuthn, directory, wall clock, and computational security exclusions.

7. **Cross-language conformance and CI coupling — 2.0 pages**
   - 21 suites, 329 vectors, three same-team reference ports.
   - CI jobs that execute models and cross-language vectors.
   - A worked drift example must be reconstructed from git history before submission; do not invent one from memory.
   - Explain why agreement is consistency evidence, not independent implementation evidence or formal refinement.

8. **Evaluation and reproducibility — 1.5 pages**
   - Re-run matrix, toolchain pins, expected outputs, runtime, and artifact layout.
   - Include machine-readable raw results, not only prose summaries.
   - Artifact smoke test from a clean environment and one evaluator not involved in implementation before submission.

9. **Threats to validity — 1.0 page**
   - Model bounds and abstraction gaps.
   - Same-team implementation bias.
   - CI and generated-statistics drift.
   - No deployed independent witness network or production settlement evaluation.
   - Trust Program, lifecycle-remedy, and DTC settlement models are outside the paper's selected 69-obligation corpus even when separately CI-gated.

10. **Related work and conclusion — 1.5 pages**
    - Authorization receipts, WebAuthn, in-toto layouts, SCITT, RATS/EAT, capability systems, TLA+/Alloy/Tamarin industrial case studies.
    - Position the contribution as a verification methodology and evidence discipline, not invention of staged authorization or cryptographic primitives.

Total: 18 pages.

## Required figures and tables

- Figure 1: trust-boundary diagram from action proposal through signoff, consumption, consequence, and evidence.
- Figure 2: claim-to-method map showing that TLA+, Alloy, Tamarin, executable vectors, and operational controls cover different surfaces.
- Figure 3: CI evidence spine from model source and vectors to three language-port outcomes and generated evidence bundle.
- Table 1: exact obligations, bounds, tool versions, and results.
- Table 2: deliberate counterexamples and the mechanism restored by each negative result.
- Table 3: claim-to-evidence ledger distilled from `CLAIM-EVIDENCE.md`.

## Threat-to-validity language for direct reuse

> TLC exhaustively explores only the finite configurations named in the configuration files; Alloy assertions hold only within their stated SAT scopes. Tamarin provides unbounded symbolic reasoning for the modeled message theory, not computational proofs of Ed25519, WebAuthn, SHA-256, JCS, or implementation code. The three language implementations are maintained by the same team and their agreement on shared vectors is consistency evidence, not independent interoperability evidence and not a refinement proof from any formal model. CI demonstrates repeatable checks at the pinned revision; it does not establish deployment correctness, correct trust-anchor administration, wall-clock truth, natural-person identity, global replay prevention across independent stores, or physical execution. The bounded Receipt Program and Authority Program models establish selected lifecycle and composition properties within their stated abstractions; they do not prove TypeScript, database linearizability, provider truth, settlement, or arbitrary concurrency. The DTC Base profile is public experimental source with explicit audit and deployment blockers, not production infrastructure.

## Artifact plan

The submission artifact should be frozen from a clean public revision and contain:

- exact TLA+, CFG, Alloy, Tamarin, runner, and result files;
- an immutable manifest with SHA-256 hashes and tool/container versions;
- one command per model and one aggregate command;
- the 328-vector conformance manifest and all three port runners;
- raw outputs plus a script that regenerates every table number;
- `CLAIM-EVIDENCE.md`, a minimal `README`, license, data-availability statement, and `CITATION.cff`;
- a clean-machine smoke test and expected resource envelope.

For citeability after publication approval, archive the exact artifact revision in a DOI-bearing repository such as Zenodo and link that DOI to the paper. Before approval, keep the DOI upload, public repository release, and citation metadata private.

## Schedule back from the deadline

- **July 21–August 2:** freeze invariant wording, verify all counts, reconstruct one real drift incident from git history, and peer-review the authority-program model.
- **August 3–16:** draft protocol, methodology, TLA+, and Alloy sections; produce Figures 1–2.
- **August 17–30:** draft Tamarin, negative-results, and conformance sections; produce Figure 3 and Tables 1–2.
- **August 31–September 13:** run the artifact from a clean environment; resolve claim/evidence drift; obtain an external artifact dry run if possible.
- **September 14–27:** full paper integration, related work, threats to validity, and anonymous-submission audit.
- **September 28–October 7:** hostile technical review and reproducibility rerun from the frozen candidate.
- **October 8–14:** final formatting, bibliography, data-availability statement, and submission checks.
- **October 15:** paper submission by AoE.
- **October 16–28:** artifact-only fixes against the frozen paper claims; no claim expansion.
- **October 29:** internal artifact-grade freeze, and mandatory submission if the paper is categorized as a tool/tool-demonstration paper.

## Submission gates

- Every number regenerates from a checked-in source or script.
- Every formal claim names its bounds or symbolic assumptions in the same paragraph.
- No `first`, `impossible`, `physics`, `independent implementation`, `production proven`, or standards-adoption language.
- The anonymous manuscript contains no identifying repository URL or self-identifying implementation-status prose if submitted as a regular research paper. Confirm the category-specific double-blind rule immediately before submission.
- No unsubmitted paper, DOI deposit, or external submission is represented as complete without its explicit publication gate.
