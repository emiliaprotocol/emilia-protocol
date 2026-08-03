# Agent Record creation capability

Agent Record creation has two independent server secrets:

- `EP_COMMIT_SIGNING_KEY` signs and verifies the public Agent Record projection.
- `EP_AGENT_RECORD_CREATION_CAPABILITY` authorizes the already-verified
  application path to invoke the irreversible database creator.

The creation capability must be independently generated in the exact form
`earc1_` followed by 64 lowercase hexadecimal characters. Do not derive it from
the Supabase service-role key or the signing key. Store it in the application
secret manager; never expose it to a browser or log it.

The database stores only its SHA-256 hash plus the configuring database session
role and timestamp. The non-superuser role that applies the migration receives
direct `EXECUTE` on one public configuration RPC. The migration removes its
temporary `SET` edges and drops the disposable role that created the permanent
owner, so the operator retains no `ADMIN`, `SET`, or `INHERIT` membership in
`agent_record_store_owner` and cannot execute the base creator. Using that same
hosted migration operator connection, configure or rotate the value with:

```sql
SELECT public.configure_agent_record_creation_capability(
  '<secret-manager value of EP_AGENT_RECORD_CREATION_CAPABILITY>'
);
```

The RPC returns only `true`; it never returns the secret or hash. `service_role`,
`anon`, and `authenticated` cannot execute it, read its forced-RLS table, or
execute `public.create_agent_record` directly. `service_role` can execute only
`public.create_agent_record_with_capability(...)`. PostgreSQL validates the
projection's closed shape but does not authenticate Ed25519; the application
must verify the freshly signed projection before calling the capability-gated
wrapper.

Production readiness is fail-closed. It is ready only when all of these hold:

1. `EP_AGENT_RECORD_CREATION_CAPABILITY` is present and matches the exact form.
2. Existing signing-key, durable-rate-limit, and database checks pass.
3. `public.check_agent_record_creation_capability(secret)` returns `true`.
4. The trial-binding, read, revoke, and capability-gated create RPCs have their
   expected ACLs.
5. `public.check_agent_record_storage_contract()` confirms the forced-RLS,
   private-table ACL, Arena source-reader policy, and immutable-trigger contract.

Missing, malformed, or database-mismatched capability configuration must keep
Agent Record creation unavailable with the generic `503 agent_record_unavailable`
surface. Readiness output must contain booleans only and never echo the secret.
