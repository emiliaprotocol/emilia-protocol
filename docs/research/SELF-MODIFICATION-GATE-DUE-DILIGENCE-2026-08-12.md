# Self-Modification Gate: hostile due diligence

Date: 2026-08-12
Decision: **build the experimental composition now; do not publish a new protocol or claim a validated market.**

## What survives

Self-improving systems make authorization continuity more important because an agent's code, prompts, weights, tools, memory policy, and evaluators can change. Identity, attestation, provenance, and evaluation remain useful descriptions of the candidate and runtime. They do not by themselves answer whether this exact candidate may be promoted to this target under this finite authority.

The strongest defensible EMILIA shape is therefore:

1. derive an exact action identifier over the base artifact, candidate artifact, change, evaluator profile, target, and policy;
2. verify separately signed human/root authority, allocation, exact-change, fitness, status, and canary evidence;
3. keep proposer, evaluator, and executor roles distinct;
4. forbid a candidate from modifying the evaluator, admission policy, trust roots, or consequence boundary in the same action;
5. reserve finite promotion authority before provider entry;
6. admit one provider attempt for that exact action inside one durable authority domain; and
7. record `INDETERMINATE` and refuse blind retry when the provider outcome is unknown.

This is a profile and product integration over existing CAID, Autonomy Control Plane, Trust Program, BCR, and Gate code. It is not a new evidence format.

## Corrections to the initial thesis

### DGM is not already reserve-execute-commit

The [Darwin Gödel Machine paper](https://arxiv.org/abs/2505.22954) and its [reference repository](https://github.com/jennyzzt/dgm) evaluate generated descendants in a sandbox and retain traceable lineage. In the reference outer loop, compiled descendants that retain code-edit ability can enter the archive; benchmark scores influence later evolutionary selection. Archive inclusion is not an executor admission decision and is not live deployment. DGM independently establishes the need for controlled candidate generation and evaluation, but it does not implement EMILIA's authority lifecycle.

### Attestation does not expire as a category

A fresh attestation can remeasure a changed workload. Artifact signatures and provenance can bind an exact candidate. The gap is not that these mechanisms become useless. The gap is that measurement, provenance, and identity are evidence inputs rather than authority to promote or deploy.

### The field already knows generic gating

The [Self-Improvements in Modern Agentic Systems survey](https://arxiv.org/abs/2607.13104) already calls for versioning, rollback, fixed budgets, governed critics, permission systems, verifier-gated changes, and audited safety boundaries. [AlphaEvolve](https://deepmind.google/blog/alphaevolve-a-gemini-powered-coding-agent-for-designing-advanced-algorithms/) and [OpenEvolve](https://github.com/algorithmicsuperintelligence/openevolve) pair evolutionary search with automated evaluators. The whitespace is not "put a gate around self-improvement."

### Evaluator evolution must be explicit, not frozen forever

The [Red Queen Gödel Machine](https://arxiv.org/abs/2606.26294) allows evaluator changes at controlled epoch boundaries. EMILIA should not claim an evaluator can never change. A candidate promotion binds the exact evaluator epoch and content digest used for its decision. An evaluator update is a separate meta-action, and results from an old epoch cannot silently satisfy the new policy.

### One BCR is not two independent meters

BCR's runtime budget is one amount and one unit. It can count promotion occurrences or meter cost, but it cannot independently conserve both without a second capability or composite allocation. The existing Autonomy Control Plane compiler statically checks calls and cents; production enforcement of both dimensions still needs distinct conserved runtime state.

## Competitive boundary

This is not greenfield.

- The [Microsoft Agent Governance Toolkit](https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/) provides runtime interception, policy engines, sandboxes, progressive delivery, and reinforcement-learning governance. EMILIA cannot lead with generic runtime policy or "govern self-improving agents."
- [Kubernetes Agent Sandbox](https://kubernetes.io/blog/2026/03/20/running-agents-on-kubernetes-with-agent-sandbox/) provides isolation and lifecycle support for agent-generated code. Isolation is complementary evidence, not the authorization boundary.
- [in-toto](https://in-toto.io/docs/getting-started/) binds authorized supply-chain actors, commands, materials, and products in signed layouts and link metadata. It is a close precedent for exact artifact and step provenance.
- [Sigstore policy-controller](https://docs.sigstore.dev/policy-controller/overview/) admits container images using signatures and attestations and resolves tags to immutable digests. It already covers a substantial part of exact-candidate deployment admission for Kubernetes.

EMILIA's remaining differentiated seam is narrower: a portable authority lifecycle that joins exact candidate and evaluator evidence to finite mandate state, consumes admission at the effect boundary, fences retries across wrapper-distinct requests in one shared durable domain, and preserves an authenticated unknown-outcome state. That distinction is technically meaningful, but commercial willingness to pay is unverified.

## Decision and gates

### GO now

- Ship the worked self-modification composition and hostile cases.
- Present it as an experimental Gate profile, not a new company thesis.
- Use promotion of code, prompts, weights, tools, or memory policy as the action class.
- Keep evaluator updates and control-plane updates as separately authorized meta-actions.

### NO-GO now

- No new IETF draft.
- No "first," "only," "strongest argument ever," or greenfield claim.
- No claim that DGM, AlphaEvolve, or OpenEvolve adopted this lifecycle.
- No claim that self-improving-agent teams have no governance instruments.
- No revenue, adoption, compliance, or liability claim.

### Evidence required before commercialization

1. one external self-improvement framework maps a real candidate and evaluator result into the profile;
2. its author or operator independently runs the hostile cases;
3. a production-shaped durable store test proves concurrent promotion fencing and reconciliation;
4. one operator confirms that existing provenance plus deployment policy does not solve its authority-consumption or unknown-outcome problem; and
5. one bounded pilot protects an actual promotion path.

Until those gates pass, the accurate market statement is: **EMILIA Gate can require exact-candidate authority, pinned evaluator evidence, and finite promotion admission before a self-modified agent reaches a covered live target, while preserving uncertainty after a lost acknowledgement.**
