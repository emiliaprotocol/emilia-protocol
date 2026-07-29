<!-- SPDX-License-Identifier: CC0-1.0 -->
# Candidate PEDIGREE to AEB composition profile

Status: public candidate mapping, pending review by the PEDIGREE source author.
It is not an IETF consensus result, a normative update to PEDIGREE, or a claim
that PEDIGREE has adopted EMILIA.

Source owner and credit: **Karthik Rampalli**, author of
[`draft-rampalli-pedigree-00`](https://datatracker.ietf.org/doc/draft-rampalli-pedigree/).
Candidate mapping and executable vectors: EMILIA Protocol contributors.

## Boundary

PEDIGREE owns its native identity and delegation semantics. A PEDIGREE verifier
decides whether the SIT, parent chain, monotonic scope attenuation, mandate
narrowing, operator ceiling, lifetime, and revocation state satisfy PEDIGREE.
An AEB implementation MUST NOT reinterpret that native result.

The [Action Evidence Boundary -02](https://datatracker.ietf.org/doc/draft-schrock-action-evidence-boundary/)
answers a separate relying-party question: did the independently verified
evidence fill the evidence role that this effect owner required for this exact
material action? The candidate composition is therefore:

```text
PEDIGREE native verifier
  -> VERIFIED | NOT_VERIFIED | INDETERMINATE
  -> relying-party-pinned action mapping
  -> EQUIVALENT_UNDER_PROFILE | NOT_EQUIVALENT | INDETERMINATE
  -> AEC role: delegated_agent_authority
  -> SATISFIED | UNSATISFIED | INDETERMINATE
  -> separate local authorization decision at the effect owner
```

`VERIFIED`, action equivalence, evidence satisfaction, and authorization are
different propositions. A verified PEDIGREE does not by itself authorize an
effect. It can fill only the `delegated_agent_authority` role named by the
relying party, and only when the exact-action mapping and current-status checks
also succeed.

This candidate does not claim that a CAID digest is byte-identical to a
PEDIGREE B9 `subject_digest`. That proposition requires the source author's
confirmation of the exact canonical input bytes, not merely the shared use of
SHA-256 and RFC 8785.

## Exact-action mapping

PEDIGREE -00 carries a mandate and operator ceiling, not a CAID field. This
candidate therefore does not manufacture a CAID from token metadata. The
relying party constructs the material action it is about to execute and uses a
pinned mapping profile to evaluate both the PEDIGREE mandate and operator
ceiling against that action. The resulting evaluation record binds:

- the exact PEDIGREE artifact digest and source revision;
- the native verifier identifier and configuration digest;
- the exact material-action CAID and action digest;
- the mapping-profile identifier and digest;
- the mandate and ceiling decisions; and
- the freshness/revocation evidence used.

If the source action is broader than the observed action, material fields are
missing, the mandate language cannot be evaluated deterministically, current
status is unavailable, or source semantics would be lost, the mapping returns
`INDETERMINATE`. It never guesses equivalence.

PEDIGREE owns the native result when revocation status is unavailable. This
candidate does not change PEDIGREE's deployment-profile behavior. It only
preserves `INDETERMINATE` if that is the native result supplied to AEB.

## Completion blocks are post-effect evidence

PEDIGREE Section 8 defines a completion block as an executing-agent-signed,
post-effect artifact that binds an outcome to the delegation chain. It can fill
a `post_effect_outcome_evidence` role after invocation. It MUST NOT fill a
pre-action human-authorization, delegated-authority, or local-authorization
role. A valid completion-block signature does not reverse time or supply
authority that was required before execution.

## Executable cases

[`pedigree-aeb-composition.v1.json`](../../conformance/vectors/pedigree-aeb-composition.v1.json)
contains one positive case and five hostile cases:

1. a current, strictly verified chain whose mandate and ceiling permit the
   exact observed action;
2. a parent-swap failure that remains native `NOT_VERIFIED`;
3. a CAID mismatch that blocks even when the native mandate permits;
4. a native mandate denial that blocks even when the CAID matches;
5. a revoked ancestor that remains native `NOT_VERIFIED`; and
6. a completion block presented in the pre-action phase.

The CAID and mandate cases are deliberately independent. Either failure alone
is sufficient to refuse evidence-role satisfaction; no evaluation order can
turn one leg's success into the other leg's success.

The repository test checks the ownership boundary and every expected state.
These are synthetic composition vectors, not a PEDIGREE implementation or an
independent interoperability result. The candidate becomes author-reviewed
only after the source author confirms this exact revision.
