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

## Authoritative owner record v2

The unpublished `EP-AE-CHALLENGE-OWNER-v1` prototype recomputed capacity
buckets from mutable call context. `EP-AE-CHALLENGE-OWNER-v2` instead stores an
`EP-AE-CHALLENGE-OWNER-RECORD-v2` record containing the issuance debit, pinned
bucket limits, and the authenticated presenter identity. Claim and finalization
lock the union of those stored buckets and any newly applicable buckets. They
never infer the issuance presenter from the challenge's audience string.

The v2 owner rejects v1 record JSON. Because v1 was never a published wire or
storage format, the supported upgrade is to stop issuance, drain every v1
challenge and reservation, remove the prototype owner records and counters
under an operator-reviewed transaction, then enable the v2 owner. A deployment
that has retained v1 records MUST NOT rewrite them in place without proving
that each original authenticated presenter and capacity bucket can be
reconstructed unambiguously.
