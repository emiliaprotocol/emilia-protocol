# Durable challenge store v3 migration

`EP-DURABLE-CHALLENGE-STORE-v3` adds an explicitly configured stable
authenticated issuer identity to the nonce replay key. It uses the
`ae-challenge:v3:` namespace and `challenge-open:v3:` and
`challenge-consumed:v3:` value markers. Existing v2 keys are never interpreted
as v3 keys.

This is a fail-closed wire-state change. Do not repurpose the v2 namespace or
run v2 and v3 issuers concurrently in one logical replay domain.

Use one of these deployment procedures:

1. Stop v2 challenge issuance, wait until every v2 challenge has expired and
   every in-flight v2 evaluation has completed, then deploy v3 issuance and
   evaluation together.
2. Perform a backend-specific atomic migration that maps every authenticated
   issuer alias to one stable issuer identity, derives each v3 issuer-and-nonce
   key, rejects collisions, preserves open versus consumed state, and completes
   before any v3 issuer is enabled.

Do not copy only open records, drop consumed records early, or use a
read-then-write migration while issuers remain active. Any ambiguity, alias
conflict, or collision leaves v3 issuance disabled until an operator resolves
it.

The package provides no generic migration because the minimal backend contract
does not expose record enumeration or a multi-key transaction. A deployment
must prove its backend-specific migration or use the drain procedure above.
