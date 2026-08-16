<!-- SPDX-License-Identifier: Apache-2.0 -->
# NOA policy-replay evaluator companion, first cut

Status: source-pinned discussion artifact for review by the NOA authors. It is
not an Internet-Draft, a NOA specification, an interoperability claim, or an
independent implementation result.

This first cut implements the companion boundary reserved by Section 11 of
`draft-noa-scitt-ai-agent-receipt-01`. It defines one evaluator contract,
`ep-admissibility-noa-replay/0.1`, and an executable corpus in both directions:

1. policy plus recorded inputs produce the exact four-member
   `governance.compliance` commitment carried by `noa.receipt/0.1`; and
2. a verifier given that commitment, the pinned evaluator profile, the policy,
   and the recorded inputs re-derives `MATCH`, `MISMATCH`, or `UNRESOLVED`.

The receipt format is untouched. This profile adds no member, changes no member,
and defines no new `noa.*` identifier. In particular, the evaluator profile is
relying-party-pinned out of band. Putting it inside `governance.compliance`
would violate the frozen closed receipt object and is an executed negative test.

## Evaluator contract

The relying party pins the exact string:

```text
ep-admissibility-noa-replay/0.1
```

That profile pins all of the following:

- policy grammar: the closed `EP-ADMISSIBILITY-POLICY-v1` object below;
- input grammar: the closed `NOA-POLICY-REPLAY-INPUT-v0.1` object below;
- operators: component-type `AND`, `OR`, and parentheses, plus freshness,
  revocation, exact-action agreement, and explicit negative evidence;
- evaluation order: malformed or unverifiable material, contradictory action or
  refusal evidence, live requirement satisfaction, stale or revoked evidence,
  then missing evidence;
- output mapping: `admissible` maps to `ALLOW`; every other completed classified
  policy result maps to `DENY`; and
- canonicalization: RFC 8785-compatible canonical JSON over the closed safe-
  integer I-JSON subset, followed by SHA-256 with lowercase hexadecimal.

`UNRESOLVED` is not a policy verdict. It means the verifier could not perform the
pinned replay because required material or the selected evaluator profile was
absent or unevaluable. It never maps to `ALLOW` or `DENY` and never authorizes an
action.

### Policy document

The policy is a closed object with exactly these members:

```json
{
  "@version": "EP-ADMISSIBILITY-POLICY-v1",
  "policy_id": "rp:money-movement:v1",
  "reliance_purpose": "money_movement",
  "requirement": "authorization_receipt AND policy_permit",
  "freshness_sec": {
    "authorization_receipt": 900,
    "policy_permit": 300
  },
  "revocation_required": [
    "authorization_receipt",
    "policy_permit"
  ],
  "require_action_agreement": true
}
```

The boolean grammar is:

```text
expression := term *("OR" term)
term       := atom *("AND" atom)
atom       := component-type | "(" expression ")"
```

A component type uses only ASCII letters, digits, and underscore. Unknown
members, malformed expressions, duplicate revocation entries, non-safe numeric
values, and non-NFC strings are unevaluable under this profile.

### Recorded-input document

The input is a closed object containing the explicit evaluation time, one exact
action digest, and one or more already-classified component facts. Every
component carries exactly `type`, `verified`, `action_digest`, `issued_at`,
`outcome`, and `revoked`. `outcome` is one of `allow`, `deny`, `denied`,
`refused`, or null. Timestamps are RFC 3339 with no leap-second spelling.
When the policy applies a freshness bound to a component type, that component
must carry `issued_at`; a missing timestamp or one later than `as_of` is
unevaluable rather than silently fresh.

`verified` is an input fact, not a trust shortcut. The relying party must obtain
it from the component's native verifier under its own pinned trust. This
companion does not authenticate the receipt carrier, prove the recorded inputs
are true or complete, prove the policy was in force, or prove the policy was
adequate.

## Commitments

After validating the closed documents, the producer computes:

```text
policyHash  = "sha256:" || lowercase-hex(SHA-256(JCS(policy-document)))
inputsHash  = "sha256:" || lowercase-hex(SHA-256(JCS(recorded-input-document)))
readSetHash = "sha256:" || lowercase-hex(SHA-256(JCS(sorted-read-set)))
```

The read set always contains:

```text
bundle.components[].outcome
bundle.components[].type
bundle.components[].verified
```

It additionally contains the action-digest paths when action agreement is
required, the evaluation time and issuance path when freshness is configured,
and the revocation path when revocation is required. The exact positive vector
pins the eight-path form and its digest.

The fourth commitment member is `verdict`, exactly `ALLOW` or `DENY`. A
verdictless commitment cannot establish that replay reproduced the recorded
decision under this profile.

## Verification order

1. Authenticate and structurally verify the `noa.receipt/0.1` carrier under the
   base receipt profile. This kit assumes that prerequisite has succeeded.
2. Load the evaluator profile selected by the relying party. Never read it from
   the receipt or the presenter.
3. Require the exact policy and recorded-input documents. Missing material is
   `UNRESOLVED`.
4. Validate both closed grammars and their canonical JSON domain. Unevaluable
   material is `UNRESOLVED`.
5. Recompute and compare `policyHash`, `readSetHash`, then `inputsHash` in that
   order. Any difference is `MISMATCH`, and evaluation does not run.
6. Evaluate the pinned policy over the recorded inputs and map the classified
   result to `ALLOW` or `DENY`.
7. Compare the derived verdict with the receipt commitment. Equality is
   `MATCH`; inequality is `MISMATCH`.

The order is observable and vectored. It prevents an uncommitted or substituted
policy from being run merely because the caller supplied it.

## Run it

```bash
npm run conformance:composition:noa-policy-replay
```

The corpus covers construction and verification, positive ALLOW and DENY,
policy substitution, input substitution, read-set substitution, verdict
substitution, missing material, an unknown evaluator, an extra receipt member,
malformed boolean grammar, an invalid outcome spelling, and an impossible date.

The exact NOA -01 archive bytes, the two posted companion drafts, the NOA
repository revision, the EMILIA evaluator base revision, and every local
load-bearing file are pinned in [`source-lock.json`](./source-lock.json).

## Evidence boundary

A passing run is EMILIA reproducing its own first-cut profile. It is not an
independent implementation, NOA compatibility, IETF adoption, or endorsement by
Tora Toraman or any other NOA author. The purpose of this artifact is to give the
authors exact text and executable cases to attack before deciding whether a NOA
companion document should exist.
