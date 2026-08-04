# Agent Operation Authorization: Policy-Resolution Binding Review Vector

This runnable review vector targets one narrow interoperability question in
[`draft-liu-agent-operation-authorization-02`](https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/):
does an Agent Operation Authorization Token identify immutable policy content,
or only a policy locator whose meaning can change after confirmation?

The draft places `agent_operation_authorization.policy_id` in the signed token.
It separately describes the proposal as a Rego policy and says the
Authorization Server presents the rendered operation to the user. The current
text does not state that `policy_id` is immutable, versioned, or bound to the
approved policy bytes.

## Reproduced ambiguity

The vector keeps all of these values unchanged:

- the signed JWT bytes and valid Authorization Server signature;
- `policy_id = "opa-policy-789"`;
- the confirmation record saying `Permit purchases up to USD 50.00`; and
- the operation presented to the Resource Server.

Only the policy registry changes. At confirmation, the identifier resolves to
a Rego rule capped at USD 50. At execution, the same identifier resolves to a
rule capped at USD 5,000. A USD 500 operation is then allowed by the resolved
policy even though the token remains byte-for-byte unchanged.

That does **not** establish that the draft is vulnerable or that any deployed
implementation uses mutable aliases. It establishes a portability gap: from
the token alone, an independent verifier cannot distinguish an immutable
deployment from a changed-semantics deployment. The honest portable verdict is
`INDETERMINATE`.

## Candidate repair

The comparison profile binds a digest of the complete policy-resolution tuple:

- policy media type;
- language version;
- evaluation entrypoint;
- input-schema digest; and
- exact policy source bytes.

Before evaluating the policy, the Resource Server recomputes that digest from
the resolved policy and refuses `policy_digest_mismatch`. A specification could
instead define `policy_id` as an immutable content address; the required
property is the same.

## Run

```bash
node examples/agent-operation-authorization/policy-binding.mjs
```

The source vector is
[`policy-alias-substitution.v1.json`](./policy-alias-substitution.v1.json).

This is an implementation review artifact, not an EMILIA extension claim. It
exists so the draft authors can confirm whether the current text already
intends immutable policy resolution, reject the model, or adopt a testable
binding rule.
