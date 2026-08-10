# Durable challenge store v2 migration

`EP-DURABLE-CHALLENGE-STORE-v2` removes the correlation-only `challenge_id`
from the replay key. Within one issuer-scoped store, the security key is now
the challenge nonce and uses the `ae-challenge:v2:` namespace.
Open and consumed record values likewise use `challenge-open:v2:` and
`challenge-consumed:v2:` markers; no v1 state marker is accepted as v2.

This is a fail-closed wire-state change. A v1 record is not accepted as a v2
record, and a v2 evaluator will refuse a still-open v1 challenge because it
cannot find the v2 registration.

Do not run v1 and v2 challenge issuers concurrently against one logical replay
domain. Use one of these deployment procedures:

1. Stop v1 challenge issuance, wait until every v1 challenge has expired and
   every in-flight v1 evaluation has completed, then deploy v2 issuance and
   evaluation together.
2. Perform a backend-specific atomic migration that derives the v2 nonce key
   from each authenticated v1 challenge record, refuses duplicate nonce keys,
   preserves open versus consumed state, and completes before any v2 issuer is
   enabled.

Do not copy only open records, drop consumed records early, or use a read-then-
write migration while issuers remain active. Any ambiguity or collision during
migration must leave v2 issuance disabled until an operator resolves it.

The package provides no generic migration because the minimal backend contract
does not expose record enumeration or a multi-key transaction. Deployments are
responsible for proving their backend-specific migration or using the drain
procedure above.
