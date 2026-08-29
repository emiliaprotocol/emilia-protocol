# IEEE CSF 2027 submission plan

## Recommendation

Target the **fall submission cycle** for the 40th IEEE Computer Security Foundations Symposium. The verified deadline is **15 October 2026, Anywhere on Earth**. Keep the winter cycle, **28 January 2027, Anywhere on Earth**, as the fallback if the fall version cannot meet the proof, anonymity, and presentation bar.

The official call is [CSF 2027 Call for Papers](https://csf2027.ieee-security.org/cfp.html). Recheck that page immediately before registration and submission in case the organizers publish clarifications.

This plan has not been submitted or registered with CSF.

## Why CSF is the right peer-reviewed target

The manuscript now asks a foundations question: what cryptographic property connects authentic approval artifacts to the number of provider entries they may authorize? It defines ANA, separates it from EUF-CMA and injective agreement, and gives a game-based compiler theorem with explicit state assumptions. That fits CSF's scope in foundational security, attack models, authorization and trust, formal methods, and applied cryptography more directly than a product or governance venue would.

The paper should be sold on that result. EMILIA is relevant as the source of the problem and artifacts, but it is not the contribution reviewers are being asked to accept.

## Verified venue requirements

- Main submission limit: **12 pages**, excluding acknowledgments, bibliography, and appendices.
- Format: the current IEEE two-column conference style required by the call.
- Review model: **double blind**.
- Author names, affiliations, acknowledgments, and identifying repository references must be removed or neutralized in the review version.
- The call includes an author review obligation. At least one senior author must agree to the reserve-reviewer policy unless an exemption in the call applies.
- Follow the call's AI-generated-content disclosure rule. Use an exact, factual disclosure for any content that falls within it. Ordinary editing or grammar assistance should not be inflated into a research contribution, but the final wording must follow the policy in force at submission time.

The present 15-page single-column preprint is not the CSF submission format. Converting it to two columns is a new editorial and typesetting pass, not a template switch followed by upload.

## Review-version positioning

### One-sentence claim

Authorization non-amplification is the missing trace property that prevents a collector from turning genuine, adaptively harvested signatures into more provider entries than the issuer created.

### Cryptology contribution

The work changes the counted event. EUF-CMA counts valid signatures on previously unsigned messages. ANA counts consequential entries attributed to issued authorization instances. The paper proves that message unforgeability and peer-run injectivity do not imply that entry bound, then gives a compiler from standard primitives plus exact consume state and complete mediation.

### Results reviewers should be able to locate quickly

1. The finite chosen-context ANA experiment and exact witness definition.
2. The separation propositions, especially why signer-to-collector injective agreement does not imply an executor-entry bound.
3. The compiler theorem and its sum over the full enrolled-key universe.
4. The deployment corollary that exposes registry and mediation failures instead of hiding them inside a cryptographic advantage.
5. The symbolic positive results and deliberate countermodels, presented as case studies rather than as the computational proof.

### Claims to avoid

- Do not call ANA a new primitive or a replacement for signatures.
- Do not claim the theorem proves database durability, complete mediation in deployed code, human identity, display fidelity, or exactly-once physical effects.
- Do not describe sequential approvers as one ceremony or claim that they were mutually aware.
- Do not turn an EMILIA implementation result into evidence for the general compiler unless the refinement argument is included.
- Do not imply that ePrint posting is peer review.

## Required manuscript work

### 1. Build the anonymous IEEE version

- Create a separate CSF source tree; do not mutate the archival preprint into two incompatible roles.
- Use the IEEE template specified by the call.
- Remove the author block, affiliation, ORCID, email, PDF author metadata, acknowledgments, and other direct identifiers.
- Refer to public artifacts in the neutral form permitted by the CSF anonymity rules. Because an earlier version is public, check the call and any FAQ for the exact self-citation and public-preprint treatment before submission. Do not guess.
- Remove product and standards language that is not needed for a theorem, model, or reproducibility statement.

### 2. Fit the main argument within 12 pages

Keep in the main body:

- the motivating attack in concrete form;
- syntax and adversary model;
- the ANA experiment and definition;
- the separations;
- the construction;
- the full compiler theorem, reduction structure, and real-resource corollary;
- the most informative symbolic results; and
- the closest related work.

Move to appendices only when the main paper remains independently checkable:

- routine encoding details;
- expanded symbolic traces and per-model result logs;
- secondary deployment discussion;
- full artifact instructions; and
- longer proofs whose statement and essential reduction remain in the main body.

Do not solve the page limit by shrinking type, hiding assumptions, or replacing proof steps with citations to the preprint.

### 3. Strengthen the proof presentation

- Put the event relation and winning condition in one compact figure or experiment box.
- State the ideal-resource interface before the theorem and identify exactly where each resource property is used.
- In the reduction, make the treatment of reveal queries and the fixed-key embedding explicit enough that a reviewer can audit it without reconstructing the game.
- Explain why the multi-user sum ranges over all `N` enrolled keys and why that fixes the post-selection problem in the earlier formulation.
- Keep the collision argument separate from the signature-forgery argument.
- Label the implementation corollary as a conditional refinement result, not an unconditional security theorem.

### 4. Make novelty easy to evaluate

The related-work section should compare properties, not application names. A compact comparison table can use these columns:

| Notion | Counted endpoint | Stateful consume required | What it does not establish |
| --- | --- | --- | --- |
| EUF-CMA | New valid signed message | No | Number of actions unlocked by a valid signature |
| Injective agreement | Matching protocol runs | Not necessarily | Downstream executor-entry cardinality |
| Transaction authorization | Signed transaction semantics | Scheme-dependent | One issued instance cannot unlock two provider entries |
| ANA | Provider entry mapped to an issued authorization instance | Yes | Human identity, display fidelity, or exactly-once physical effect |

Every row needs a precise citation or a statement that it is the paper's own characterization.

The review version must also name the nearest structural and terminological predecessors in the main body: anonymous counting tokens for per-client issuance limits, Bellare–Neven multisignatures for one common message under several certified keys, object-capability “No Authority Amplification,” source-authority non-amplification for agent memory, and CapLease for semantic reissuance across fresh identifiers. The paper's claim is the chosen-context issuance-to-provider-entry experiment and compiler, not ownership of the phrase “non-amplification” or the general idea of single use.

## Artifact plan

Prepare an anonymous artifact bundle with:

- the four Tamarin theories cited in the manuscript;
- pinned tool versions and runnable scripts;
- proof-status outputs and hashes;
- the deliberately weakened variants; and
- a short map from each paper claim to the file and lemma that supports it.

Run the bundle from a clean environment before submission. A green local run is not enough if the archive omits dependencies or paths.

## Submission sequence

1. Freeze the ePrint v4 theorem and artifact state.
2. Complete an independent proof audit and resolve every material finding.
3. Build the anonymous IEEE source as a separate artifact.
4. Run a cold read focused on whether the definition, separation, and theorem are understandable without EMILIA context.
5. Run the anonymous artifact bundle from a clean environment.
6. Check the latest CSF call and FAQ for template, preprint, anonymity, AI disclosure, conflict, and reviewer-obligation details.
7. Register the paper and authors by any registration deadline stated in the submission system.
8. Upload the final review PDF and supplement, then reopen the uploaded files and verify them.
9. Save the submission identifier and confirmation before reporting the paper as submitted.

## Go or no-go gates for the fall cycle

Submit in the fall cycle only if all of these are true:

- [ ] The compiler theorem survives independent technical review.
- [ ] The review PDF is within the 12-page main-body limit in the required IEEE format.
- [ ] The paper is double-blind under the current CSF rules, including treatment of the public preprint and artifacts.
- [ ] The novelty comparison is explicit and correctly cited.
- [ ] The Tamarin results reproduce from the anonymous artifact bundle.
- [ ] The title, abstract, introduction, theorem, conclusion, and submission form state the same bounded claim.
- [ ] The applicable AI-content disclosure has been completed accurately.
- [ ] The author review obligation is assigned.

If any proof or anonymity gate remains open by the fall deadline, use the winter cycle. A later clean submission is better than a rushed version whose theorem or identity handling gives reviewers an easy reason to stop.
