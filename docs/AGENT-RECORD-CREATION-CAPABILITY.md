# Agent Record creation capability

Agent Record creation has two independent server secrets:

- `EP_COMMIT_SIGNING_KEY` signs and verifies the public Agent Record projection.
- `EP_AGENT_RECORD_CREATION_CAPABILITY` authorizes the already-verified
  application path to invoke the irreversible database creator.

The creation capability must be independently generated in the exact form
`earc1_` followed by 64 lowercase hexadecimal characters. Do not derive it from
the Supabase service-role key or the signing key. Store it in the application
secret manager; never expose it to a browser or log it.

The database stores only its SHA-256 hash. A database operator configures the
same secret through a private-schema function while acting as
`agent_record_store_owner`:

```sql
BEGIN;
SET LOCAL ROLE agent_record_store_owner;
SELECT agent_record_private.configure_creation_capability(
  '<secret-manager value of EP_AGENT_RECORD_CREATION_CAPABILITY>'
);
COMMIT;
```

`service_role` cannot execute that configuration function, read its forced-RLS
table, or execute `public.create_agent_record` directly. It can execute only
`public.create_agent_record_with_capability(...)`. PostgreSQL validates the
projection's closed shape but does not authenticate Ed25519; the application
must verify the freshly signed projection before calling the capability-gated
wrapper.

Production readiness is fail-closed. It is ready only when all of these hold:

1. `EP_AGENT_RECORD_CREATION_CAPABILITY` is present and matches the exact form.
2. Existing signing-key, durable-rate-limit, and database checks pass.
3. `public.check_agent_record_creation_capability(secret)` returns `true`.
4. The read, revoke, and capability-gated create RPCs have their expected ACLs.

Missing, malformed, or database-mismatched capability configuration must keep
Agent Record creation unavailable with the generic `503 agent_record_unavailable`
surface. Readiness output must contain booleans only and never echo the secret.
