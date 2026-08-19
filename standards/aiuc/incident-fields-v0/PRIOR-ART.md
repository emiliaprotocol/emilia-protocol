# Prior art and contribution boundary

This note records what the cited primary papers actually cover and what this
proposal adds. It avoids a first-to-invent claim.

## Hao-Hsuan Chen, arXiv:2605.25632

Chen's May 2026 paper, *Insuring Every Action: An Authority Frontier Framework
for Runtime Actuarial Control of Autonomous AI Agents*, makes the individual
side-effect-bearing action the empirical and pricing unit. Section 3 defines an
Actuarial Action Interface as a deterministic contract machine: the model
proposes; the interface parses and canonicalizes the action, quotes reserve,
binds budget, executes or downgrades, and records the event. Section 3.1 maps
each admissible action into exactly one of seven classes: `read_only`,
`additive_write`, `modify_write`, `destructive`, `monetary_low`,
`monetary_high`, and `external_commit`.

The paper also matters for evidence design. Its quote-bind-commit protocol
binds the canonical action, state, contract and policy versions into a
capability token. Section 3.8 separates an operational trace from an immutable
audit stream and pricing telemetry; the audit stream carries action hashes,
authority class, safe default, decision, token hash, executor result, and state
diff. Chen explicitly limits the work to actions passing through that interface
and excludes credential compromise, executor compromise, hidden side channels,
and full data-exfiltration security.

Contribution boundary: Chen's "authority classes" classify side-effect type
for a runtime actuarial contract. They do not serve as a retrospective incident
code for whether a documented mandate was standing, action-specific, denied,
revoked, exceeded, affirmatively absent, or unknowable at the time of an observed action. This
proposal therefore reuses Chen's seven labels only as the separate
`action_class` axis. It adds `authorization.status`, a per-field evidence grade,
and rules for public incident coding. It does not claim the per-action unit,
the seven action classes, quote-bind-commit, or audit-stream design as new.

Primary source:

- Hao-Hsuan Chen, [arXiv:2605.25632](https://arxiv.org/abs/2605.25632),
  especially Sections 3.1, 3.2, 3.8, 6, and 7;
  [DOI](https://doi.org/10.48550/arXiv.2605.25632).

## Kevin Wei and Lennart Heim

Wei and Heim's *Designing Incident Reporting Systems for Harms from
General-Purpose AI* defines incident-reporting systems as processes for
collecting information about safety- and rights-related events caused by
general-purpose AI. Their effects-based working definition includes both harm
events and near misses. Their institutional framework has seven dimensions:
policy goal; actors submitting and receiving reports; incident type; level of
risk materialization; enforcement; reporter anonymity; and post-reporting
actions.

Two design conclusions directly constrain this proposal. First, the authors
say information sharing benefits from standardization and interoperability,
while warning that duplicated reporting requirements create fragmentation and
burden. That supports a small, portable field group rather than a new reporting
system. Second, they state that their scope is institutional design and excludes
operational-level details such as documentation. The action-level field and
evidence-grade mechanics here are an implementation-level complement, not a
replacement for their framework.

This proposal does not choose the reporting institution, policy goal,
mandatory threshold, anonymity regime, disclosure rule, or post-reporting
action. Those remain system-design decisions under Wei and Heim's framework.
It also does not assume that a field useful for safety learning is sufficient
for accountability.

Primary sources:

- Kevin Wei and Lennart Heim,
  [full arXiv version 2511.05914](https://arxiv.org/abs/2511.05914), especially
  Sections 2 through 5 and the executive summary.
- Kevin Wei and Lennart Heim,
  [AAAI-26 paper](https://ojs.aaai.org/index.php/AAAI/article/view/41139),
  DOI [10.1609/aaai.v40i44.41139](https://doi.org/10.1609/aaai.v40i44.41139).

## Net contribution

The narrow addition is a join between two existing concerns:

1. Chen supplies an action-level side-effect classification and demonstrates
   why action, decision, and outcome records should remain distinct.
2. Wei and Heim supply the institutional reporting frame and the need for
   interoperable information without duplicative reporting burden.
3. This draft supplies a retrospective authorization-status axis, attaches an
   explicit evidence grade to each coding, and provides a minimal interchange
   object that an existing incident system may adopt without changing its
   reporting institution or requiring an EMILIA implementation.
