<!-- SPDX-License-Identifier: Apache-2.0 -->
# Candidate execution-time evidence carrier

This note proposes a small contract for carrying an execution-time evidence
requirement through a delegation chain. It is format neutral. It does not say
that the current Asor, HAMR, AgentEnvelope, OAuth, or WIMSE drafts already
define this contract.

A carrier using this contract would mark `required_evidence` as critical. Each
designation would name:

- a stable requirement ID and evidence profile;
- the required role and principal kind;
- the minimum number of qualifying principals;
- distinct-principal and self-approval rules; and
- the exact-action profile used to bind the evidence.

The carrier would also bind the concrete action, target, and acting-for
principal. A child could preserve or tighten a parent's requirement. It could
not remove it, lower the minimum, weaken an exclusion, change the evidence
role, change the acting-for principal, or substitute a different action or
target. A verifier that does not understand a required profile would refuse
the chain.

Evidence evaluation and action admission remain separate. Verification can be
side-effect free. The AEB handoff below is one composition, not a dependency in
either direction. A local AEB gate then reserves the operation and native
replay units in one linearizable admission domain. Refusal before provider
entry releases any temporary reservation and does not consume a new reliance
unit. Once admitted, provider entry is at most once in that domain. An unknown
post-dispatch outcome remains `INDETERMINATE`; the caller reconciles the
original operation instead of retrying it blindly.

An extensible delegation format could register these semantics as a critical
profile. A closed vocabulary needs a new revision or registered extension. In
particular, a private `required_evidence` floor cannot be inserted into the
`-00` revision of HAMR because that revision requires an unknown floor axis to
fail.

This is an EMILIA candidate for technical discussion. It is not evidence of
working-group adoption, author endorsement, freedom to operate, independent
implementation, or production deployment.
