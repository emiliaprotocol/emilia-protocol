# ACTA + EMILIA: machine decision and human authorization

This runnable example composes two different claims about one consequential
action:

| Component | Claim | Trust anchor |
|---|---|---|
| ACTA `protectmcp:decision` | A machine policy engine returned `allow` | ACTA issuer key pinned for the `acta-decision` role |
| EMILIA `EP-RECEIPT-v1` | A named human completed a fresh Class-A ceremony for the exact action | Approver directory, WebAuthn RP/origin, policy hash, and EP log key pinned by the relying party |

The executor requires both through `EP-AEC-v1` and then uses EMILIA's stateful
AEC execution gate to reserve the action before the effect. The same action
cannot execute twice through the same consumption domain.

```bash
node examples/acta-ep-join/demo.mjs
```

The positive path executes once. The same run also refuses:

- action substitution after either artifact was signed;
- an ACTA issuer key that is not pinned for the ACTA role;
- an ACTA machine receipt relabeled as human authorization;
- an expired human ceremony;
- substitution of a different, independently valid EP receipt;
- an ACTA envelope carrying its own verification key; and
- replay of the already executed action.

## Three bindings, three meanings

1. **`action_ref`** follows `draft-farley-acta-signed-receipts-02`: SHA-256
   over the JCS form of `{agentId, actionType, scopeRequired, timestamp}`. It
   correlates one policy-evaluation event.
2. **`caid`** identifies the material payment content under a pinned
   `payment.release.1` mapping profile. It does not authorize the payment.
3. **`ep_action_digest` plus `human_authorization_ref`** are signed ACTA
   extension members used by this example. They bind the machine decision to
   the same full EP action and to the exact EP receipt that the decision cites.

The ACTA signature and EP receipt are still verified separately under separate,
role-scoped keys. One artifact cannot fill the other artifact's requirement.

## Scope and non-claims

This is a non-normative interoperability profile against
`draft-farley-acta-signed-receipts-02`, not a complete ACTA implementation. It
supports ACTA's mandatory Ed25519 path only. It intentionally does not implement
ACTA's other receipt types, ES256 extension, commitment mode, selective
disclosure, Sigil, or identity manifest.

The demo opts into a process-local consumption store so it runs with no setup.
That store is not safe across replicas or restarts. Production execution through
the same gate requires EMILIA's capability-marked durable store and strict
shared evidence log; execution refuses without them unless the explicit demo
opt-in is present.

Neither receipt proves that the action was wise, lawful, or successfully
executed. The composed result proves only that the pinned machine-policy and
named-human evidence requirements were both satisfied for the same action at
the executor-controlled boundary.
