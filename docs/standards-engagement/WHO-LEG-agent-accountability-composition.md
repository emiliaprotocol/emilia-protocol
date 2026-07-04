# WHO leg — contribution text for draft-mih-sato-agent-accountability-composition-00

Status: ready-to-paste contribution (Iman Schrock, WHO leg owner per the
2026-07-03 author split). Written in the composition draft's register:
requirements a format maps itself against, NOT slots any format is assigned
to; neutral among candidate formats; limits stated as plainly as the value.
Adapt headings/numbering to the skeleton when it lands.

---

## The WHO question

WHO — which named, accountable human (or quorum of distinct humans)
authorized this exact action? This is distinct from which agent acted
(identity), which workload carried the call (workload identity), and what
the agent was in general permitted to do (CAN). WHO is the question a
counterparty, auditor, or regulator asks when the action is consequential
enough that "a policy allowed it" is not an answer: a person, nameable
afterward, took responsibility for this specific act before it happened.

## Requirements a WHO record maps itself against

A record format claiming to answer WHO should be able to state, for each of
the following, whether it satisfies the requirement unconditionally, under
stated assumptions, or not at all. Partial mappings are expected and useful;
the point of the mapping is to make the conditions legible, not to rank
formats.

W1. Named accountable principal. The record identifies a human principal
    accountable for the authorization — not solely a device key, wallet
    key, or operator/vendor key. How the human-to-key binding was
    established (and its strength) is stated, not implied.

W2. Exact-action binding. The record binds the authorization to the exact
    observed action by the composition's shared action digest, such that the
    same record cannot satisfy WHO for a different action — and digest
    equality itself neither authorizes the action nor proves completeness.
    A record that binds a scope, a session, or a class of actions answers a
    different (still useful) question and says so.

W3. Temporal semantics. The record states whether authorization preceded
    execution. Pre-execution authorization and post-hoc ratification are
    both legitimate records; conflating them is not.

W4. Independent verifiability. A party that trusts neither the agent nor
    the operator can verify the record — signature, principal binding, and
    action binding — from the record plus published key material, without a
    callback to the operator on the critical path.

W5. Reuse semantics. The record states whether it authorizes one execution
    or many. Where one-time use is claimed, the enforcement locus (which is
    typically enforcement-point state, not a property verifiable from the
    record alone) is stated honestly.

W6. Quorum. Where more than one human must authorize (the two-person rule
    common to exactly the action classes that motivate this work), the
    record makes the DISTINCTNESS of the humans verifiable — M-of-N
    distinct accountable principals, not M signatures that may share a
    key or a person — and states whether ordering is significant.

W7. Verification versus acceptance. The format distinguishes what a
    verifier can establish from the record and public keys alone
    (signature and bindings hold) from what requires an out-of-band trust
    decision (this issuer's records are relied on here). A record from an
    unpinned issuer verifying correctly is not the same thing as a record a
    relying party should accept; formats that keep these separate compose
    more safely than formats that collapse them.

## Where WHO meets delegation and consent (open question)

A human authorizing THIS action and a human having delegated authority
under which an agent acts are different claims with different failure
modes; a composition must not let one masquerade as the other. Whether the
WHO leg's action binding should also be expressible in terms of the grant
(not only the runtime event) is co-owned with the CAN leg and deliberately
open in -00.

## Limits, stated plainly

A WHO record attests that an identified human authorized a described
action at a stated time. It does not attest that the human understood the
consequences, that the action was wise or compliant, or that the record's
issuer is honest — the last is a trust decision the relying party makes
out-of-band (W7). Revocation and freshness of WHO records follow the
composition's general treatment; a WHO record's validity window and any
revocation mechanism are stated by the format, and staleness is judged by
the relying party, fail-safe.

## Candidate formats

Formats map themselves against W1–W7; absence from the mapping implies
nothing about a format. (Per the composition's ground rules, no format is
mapped without its author in the room.) EP's authorization receipt and
quorum profiles (draft-schrock-ep-authorization-receipts,
draft-schrock-ep-quorum) will contribute a self-mapping as one candidate;
delegation-receipt and intent-token lineages are explicitly invited to map
the WHO-adjacent claims they carry, including where they answer a
different question than W1 (e.g., key-bound rather than named-principal
authorization).
