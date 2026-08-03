# Agent Record v1

Agent Record v1 is a minimal factual observation of one signed refusal in the
synthetic EMILIA Arena. It is not a score, rank, certification, marketplace
listing, identity, ownership, competence, or safety claim.

## Creation boundary

A record can be created only through `createAgentRecord()` while its Agent
Adoption session and sole Operating Bond are active. First, the service uses
the read-only `prepareAgentRecordRefusalSource()` path to open the encrypted
trial envelope, rebind the adoption ID, bond ID and digest, and Arena session,
and read and verify the immutable signed refusal without publishing a public
Arena share. Permit events have no signed refusal artifact and are rejected.

The service then signs the `EP-AGENT-RECORD-OBSERVATION-v1` projection before
any database mutation. The `create_agent_record_with_capability` wrapper first
authenticates the application-only creation capability. One base
`create_agent_record` database transaction then rechecks the active adoption
credential, latest bond, and immutable signed refusal source and inserts the
immutable Agent Record. A later failure or conflict leaves no partial record.
Unique constraints consume the opaque record ID, private source commitment,
source refusal digest, and SHA-256 owner-token hash. No caller chooses a vanity
identifier.

The creation request contains no timestamp fields. On an exact retry, the
service may compute and sign a candidate with fresh observation and retention
timestamps, but the transaction returns the original committed record,
projection, and timestamps without rewriting them. Exact means the same record
ID, owner credential, adoption and bond, and Arena refusal source. Reusing a
record ID with a different owner or source, or reusing an owner credential,
Arena source, or refusal digest for another record, fails as a conflict.

## Public projection

The outer `EP-AGENT-RECORD-OBSERVATION-v1` envelope contains only:

- opaque record ID;
- Operating Bond ID and digest;
- refusal-artifact profile and digest;
- action and refusal digests;
- refusal, observation, and retention instants;
- the explicit claim boundary; and
- an Ed25519 signature from the operator commit signing key, carrying its
  validated current key ID.

It contains no adoption or Arena session ID, owner token or hash, passkey or
credential ID, candidate URL, raw WebAuthn material, prompt, IP address, agent
label, raw action, or action parameters. Public verification resolves the
configured operator key by key ID. Artifact-supplied public keys are not part of
the schema and are rejected. Production creation fails closed when
`EP_COMMIT_SIGNING_KEY` is absent.

The private source commitment is a transaction and uniqueness binding. It is
not a field in the signed Agent Record envelope and is not returned by the
public Agent Record endpoint. The refusal-artifact digest is the only public
source binding; it is not a dereferenceable Arena URL.

`EP_AGENT_RECORD_SIGNING_KEY_ID` names the current Agent Record signing key.
When it is unset, the backward-compatible default is `ep-signing-key-1`. An ID
must match the closed ASCII shape `[A-Za-z0-9][A-Za-z0-9._:-]{0,63}`; the
reserved map-property names `constructor` and `prototype` are also forbidden.
The runtime and database reject any other shape.

## Operator signing-key rotation

Rotate the Agent Record signer in this order:

1. Derive key A's raw 32-byte Ed25519 public key and add its standard-base64
   value under key ID A in `EP_COMMIT_SIGNING_KEYS` while A is still current.
2. Deploy that retained-key map before changing the current signer.
3. Change `EP_COMMIT_SIGNING_KEY` to private seed B and
   `EP_AGENT_RECORD_SIGNING_KEY_ID` to a new key ID B in the same deployment.
   Never reuse A's ID for B's private key.
4. Verify both a newly signed B observation and an existing A observation.

Keep A's entry in `EP_COMMIT_SIGNING_KEYS` until every A-signed Agent Record is
past its public retention interval: at least 365 days after the last observation
signed by A, plus any deployment-clock allowance. Removing it earlier makes a
still-public record cryptographically unverifiable. The map holds public keys
only; never place an Ed25519 seed or other private key material in it.

## Owner credential and revocation

The browser generates one dedicated `ear1_` owner credential and stores it
before creation. The API never returns it and the database stores only its
SHA-256 hash. Possession proves control of this record credential only; it does
not prove identity or ownership of an agent, codebase, account, or key.

Revocation uses one database transaction to append an immutable terminal Agent
Record revocation. It does not rewrite or delete the Agent Record or its signed
public projection, and the consumed source cannot be republished into another
Agent Record. An exact revocation retry returns the original terminal result.
Exact public reads return the same not-found result for unknown, expired, and
revoked IDs.

## Retention boundary

Public availability is the half-open interval
`observed_at <= now < retention_expires_at`, where
`retention_expires_at = observed_at + 365 days` (exactly 31,536,000 seconds).
At the first instant equal to `retention_expires_at`, the record is no longer
public. Owner revocation ends public availability earlier.

The offline envelope verifier proves signature integrity and whether the signed
retention interval contains the supplied time. It deliberately returns
`status_checked: false`; it cannot determine whether the owner later revoked
the record. Only a current exact lookup through the operator service can return
`currently_public: true`, after the database has checked the append-only
revocation set. A cached envelope MUST NOT be treated as proof of current
publication status.

The minimal private binding, SHA-256 credential hash, and any revocation remain
as immutable replay tombstones so an expired or revoked source cannot be used
to mint a second record. They contain none of the forbidden raw/private fields
listed above.

The browser creates the opaque record identifier and 256-bit owner credential,
stores the pending pair before the network request, and submits both through the
authenticated creation route. A lost HTTP response can therefore be retried
without creating an ownerless public record or replacing the first committed
timestamps. A conflicting replay remains refused. The database stores only the
credential hash.

## Runtime readiness

Agent Record is an operated public observation service, not a locally
reproducible status verifier. In production, creation, exact public pages, the
public API, and owner revocation fail closed unless all of these dependencies are
ready:

- `EP_COMMIT_SIGNING_KEY` is a canonical base64-encoded 32-byte Ed25519 seed and
  `EP_AGENT_RECORD_SIGNING_KEY_ID` is valid;
- both `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN` configure the
  durable public rate limiter;
- `NEXT_PUBLIC_SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` configure the
  server-held database client;
- `EP_AGENT_RECORD_CREATION_CAPABILITY` has the exact `earc1_` plus 64
  lowercase-hex shape and matches the one-way capability configured in the
  private database store; and
- the service role can execute `check_agent_record_creation_capability`,
  `create_agent_record_with_capability`, `read_agent_adoption_session`,
  `read_agent_record_refusal_source`, `read_agent_record_public`, and
  `revoke_agent_record` with the deployed signatures.

The live authorization check confirms only whether the server-held creation
capability matches the private database configuration. The creation probe uses
that capability with null business inputs, which the base creator rejects in
its first validation block before any mutation. The dependency, read, and revoke
probes use valid-shaped but nonexistent, non-secret identifiers. Probe results are cached briefly;
no capability, key, token, URL, or database error detail is returned to a public
caller. An unavailable dependency produces one generic
`503 agent_record_unavailable` response, and `/adopt` keeps the synthetic
challenge and Operating Bond available while suppressing Agent Record creation.
Development and tests retain their documented ephemeral/in-memory behavior.

## Access model

`agent_record_private` is owned by a dedicated `NOLOGIN`, non-superuser,
non-`BYPASSRLS` role. Both tables use forced RLS. `anon`, `authenticated`, and
`service_role` have no direct table access. The public HTTP route performs an
exact opaque-ID lookup through the server-only
`read_agent_record_public(record_id)` RPC and then verifies the operator
signature before returning the envelope. `anon` and `authenticated` cannot
execute the RPC directly. There is no list, search, feed, sitemap, handle, or
enumeration function. Creation and owner revocation are separate
`service_role`-only `SECURITY DEFINER` RPCs. The service role cannot execute the
base creator directly: it must use `create_agent_record_with_capability`. The
matching capability is stored only as a private hash and can be checked through
a boolean-only server RPC; neither the capability table nor its configuration
function is granted to `service_role`. The database validates closed structure
and exact source bindings; it does not claim to verify Ed25519.
