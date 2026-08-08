# Policy Engine Evidence Bridge

## Decision

EMILIA does not replace Open Policy Agent, Cerbos, Cedar, or another local
policy engine. Those systems decide whether an input satisfies a machine
policy. EMILIA adds the part they do not provide by themselves: portable,
exact-action evidence that can be composed with independent human authority
and consumed once by a credential-owning Gate.

The bridge is available from:

```text
@emilia-protocol/verify/policy-decision-evidence
```

## Security boundary

The bridge emits one evidence role: `machine-policy-decision`.

An OPA `true` or Cerbos `EFFECT_ALLOW` means only that the pinned local bridge
reported an allow result under the pinned policy digest for the signed exact
action. It does not establish:

- human intent or authorization;
- policy correctness or legal sufficiency;
- complete mediation or the absence of bypass routes;
- independent observation by OPA or Cerbos;
- one-time consumption; or
- provider entry or real-world effect.

Those properties remain separate. A consequential relying party should require
at least:

```text
human-authorization AND machine-policy-decision
```

Gate then makes its own local authorization decision and atomically consumes
the admission before the credential-owning adapter can invoke the provider.

## OPA integration

Evaluate the action with the locally pinned OPA bundle. Pass the exact boolean
result and the exact action object to `projectOpaPolicyDecision()`. The function
maps only `true` to `ALLOW` and only `false` to `DENY`; every other result is
`INDETERMINATE`.

```js
const claims = projectOpaPolicyDecision({
  issuer: 'https://policy-bridge.example',
  subject: 'workload:agent-17',
  audience: 'https://gate.example/admit',
  issued_at: now,
  expires_at: now + 120,
  decision_id: opaDecisionId,
  policy_id: 'opa:payments/allow',
  policy_digest: pinnedBundleDigest,
  action,
  native_decision_ref: `opa:decision:${opaDecisionId}`,
  result: opaResult,
});
const artifact = signPolicyDecisionEvidence(claims, bridgeSigner);
```

## Cerbos integration

Pass the exact CheckResources effect for the protected action to
`projectCerbosPolicyDecision()`. Only `EFFECT_ALLOW` and `EFFECT_DENY` receive
definite meanings; unknown values are `INDETERMINATE`.

```js
const claims = projectCerbosPolicyDecision({
  issuer: 'https://policy-bridge.example',
  subject: 'workload:agent-17',
  audience: 'https://gate.example/admit',
  issued_at: now,
  expires_at: now + 120,
  decision_id: requestId,
  policy_id: 'cerbos:resource-policy:payments',
  policy_digest: pinnedPolicyDigest,
  action,
  native_decision_ref: `cerbos:request:${requestId}#release`,
  effect,
});
const artifact = signPolicyDecisionEvidence(claims, bridgeSigner);
```

## Deployment requirements

1. Pin the bridge issuer, Ed25519 public key, audience, engines, policy digests,
   exact action type, freshness window, and evidence role in the relying party.
2. Keep the signing key and provider credential behind the enforcing boundary.
3. Sign only after the local engine evaluates the same frozen action that Gate
   will admit.
4. Refuse malformed, stale, unpinned, denied, or indeterminate results.
5. Require independent human authorization when human intent is part of the
   relying party's rule.
6. Use a durable Gate store for replay fencing and one-time consumption.

## Why this is the product shape

Local policy evaluation is mature and widely available. Reimplementing it
would add another configuration language and another enforcement proxy without
creating a defensible trust boundary. The bridge lets existing engines become
distribution for EMILIA while preserving their native ownership and keeping
the four decisions separate:

```text
native VERIFIED -> relying party ACCEPTED -> requirement SATISFIED -> Gate AUTHORIZED
```

No earlier decision implies a later one.
