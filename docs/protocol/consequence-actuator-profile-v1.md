<!-- SPDX-License-Identifier: Apache-2.0 -->
# Consequence Actuator Profile v1

Status: public experimental implementation profile.

## Purpose and boundary

The consequence actuator is the final complete-mediation boundary between an
EMILIA Gate decision and a provider effect. Gate does not receive, store, or
forward the provider credential. A separately deployed actuator owns that
credential and accepts only a short-lived, signed, one-time execution envelope.

The envelope is not a new authorization artifact. `EP-RECEIPT-v1`, local Gate
policy, and any required AEB evaluation remain the authorization and evidence
inputs. The envelope carries the exact already-authorized execution binding
across the process boundary so a caller cannot replace the provider account,
target, operation, or action after Gate admission.

## Credential separation and flow

```text
receipt + evidence + observed action
                 |
                 v
        Gate authorizes exact action
                 |
                 v
 signed one-time execution envelope
       (no provider credential)
                 |
                 v
 actuator verifies immutable local pins
                 |
                 v
 atomic reserve ---- replay/race -> refuse
                 |
                 v
 provider callback uses actuator-held credential
                 |
          +------+------+
          |             |
      COMMITTED    INDETERMINATE
          |             |
          +------+------+
                 v
       permanent envelope consume
```

The provider callback captures the credential in actuator-local configuration
or a credential client. Its input is only the verified, deeply frozen envelope
payload. Provider credentials and caller-supplied credential fields are absent
from the TypeScript contract.

## Closed execution envelope

The wire object has exactly two members: `payload` and `signature`.

`payload` is
`EP-CONSEQUENCE-ACTUATOR-ENVELOPE-v1` and has the following closed field set:

- `issuer_id`
- `tenant_id`
- `attempt_id`
- `action_digest`
- `caid`
- `provider_account_id`
- `target_digest`
- `operation`
- `idempotency_key`
- `nonce`
- `issued_at`
- `expires_at`

`action_digest` identifies the exact canonical material action. `target_digest`
identifies the provider-side target independently of any display label.
`operation` selects the locally pinned provider operation, while
`idempotency_key` is the provider operation key and durable replay scope.
`nonce` is at least 128 bits of canonical base64url entropy.

The body is canonicalized under the Gate canonical JSON safety profile. The
Ed25519 signature covers:

```text
UTF8("EP-CONSEQUENCE-ACTUATOR-ENVELOPE-v1") || 0x00 ||
UTF8(canonical payload)
```

The signature object has exactly `algorithm`, `key_id`, and `value`.
`algorithm` is exactly `Ed25519`; `value` is a canonical unpadded base64url
64-byte signature. The envelope carries no public key. The actuator accepts
only its constructor-pinned key identifier and Ed25519 public key, so a
presenter cannot substitute its own trust root.

## Immutable actuator pins

Each actuator instance copies and freezes these local constructor pins:

- tenant and CAID;
- provider account, target digest, and operation;
- envelope issuer ID, key ID, and Ed25519 verification key fingerprint; and
- maximum envelope lifetime and clock skew.

The public pin view exposes only the public-key fingerprint, not mutable key
material. Attempt ID, action digest, and idempotency key are supplied from the
live Gate-to-actuator request and must equal the signed payload. All fixed and
live bindings are checked before replay storage or provider invocation.
Unknown fields, accessors, aliases, malformed canonical JSON, non-Ed25519
keys, bad signatures, future issuance, expiry, and overlong lifetimes fail
closed.

The default maximum lifetime is 60 seconds. Implementations may configure a
shorter limit and MUST NOT configure more than five minutes.

## One-time reserve and consume

The actuator store exposes only two mutations:

1. `reserve` atomically creates the `(tenant_id, nonce)` replay fence and the
   `(tenant_id, provider_account_id, operation, idempotency_key)` operation
   fence. A conflict refuses the invocation.
2. `consume` atomically moves the exact reserved binding from `RESERVED` to
   `CONSUMED` with outcome `COMMITTED` or `INDETERMINATE`.

There is no release operation. Once the provider callback is entered, an
exception or lost acknowledgement is `INDETERMINATE`, never evidence that the
effect did not occur. The envelope remains permanently unusable. If the
post-effect consume acknowledgement is lost, the caller receives
`store_consume_unconfirmed`; the implementation does not retry the provider
effect.

`MemoryConsequenceActuatorStore` is process-local and test-only. Its map
mutations occur synchronously before its async methods yield, giving one winner
under a same-process race, and it retains permanent replay and idempotency
fences. It is not a production durability claim.

`PostgresConsequenceActuatorStore` is the production consumer of the migration.
Its constructor requires a tenant pin, a dedicated executor principal name, and
a pool explicitly labeled with that same principal. Supabase API principals,
`service_role`, `postgres`, and the no-login group/owner roles are refused as
pool identities. PostgreSQL still independently checks `SESSION_USER` against
the tenant-principal map on every call.

The adapter emits only `SELECT` calls to `reserve_envelope` and
`consume_envelope`, binds every field positionally, and accepts exactly one row
whose `envelope_digest` equals the request. Zero rows is a replay or state
conflict. Null, missing, extra, or mismatched acknowledgements throw and are
therefore fail-closed at the actuator boundary. The adapter reports
`durable: true`, `atomic: true`, and `permanentConsumption: true`.

## PostgreSQL deployment contract

`20260725010000_consequence_actuator_store.sql` supplies the durable store
schema:

- `consequence_actuator_store_owner` is a `NOLOGIN NOBYPASSRLS` table and
  function owner;
- `consequence_actuator_executor` is a separate `NOLOGIN NOBYPASSRLS` group
  role for tenant-specific login principals;
- a private principal map binds `SESSION_USER` to the requested tenant;
- the envelope table has enabled and forced RLS plus an owner-only policy; and
- all table privileges are revoked from Supabase API roles, `service_role`,
  and the executor role.

Runtime code receives only `EXECUTE` on
`consequence_actuator_private.reserve_envelope` and
`consequence_actuator_private.consume_envelope`. Both functions are
`SECURITY DEFINER` with an empty `search_path`, are owned by the separate
no-login owner, and check tenant-principal membership. Runtime and Supabase
roles have no direct `SELECT`, `INSERT`, `UPDATE`, or `DELETE` authority over
the replay table.

Tenant principal rows are deployment-provisioned; the migration deliberately
does not expose a runtime principal-management RPC.
All text bindings have database byte-length checks (256 bytes for ordinary
identifiers, 512 for CAID, and 22–128 for the canonical base64url nonce), with
digest and nonce syntax checks repeated inside both runtime RPCs.

## Reference implementation

- `packages/gate/src/consequence-actuator.ts`
- `packages/gate/consequence-actuator.test.ts`
- `supabase/migrations/20260725010000_consequence_actuator_store.sql`
- `tests/consequence-actuator-migration-contract.test.ts`
