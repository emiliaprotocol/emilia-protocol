# Agent Record v1

Agent Record v1 is a minimal factual observation of one signed refusal in the
synthetic EMILIA Arena. It is not a score, rank, certification, marketplace
listing, identity, ownership, competence, or safety claim.

## Creation boundary

A record can be created only through `createAgentRecord()` while its Agent
Adoption session and sole Operating Bond are active. The service delegates to
the existing `publishBoundAgentTrialRefusal()` bridge, which opens the encrypted
trial envelope, rebinds the adoption ID, bond ID and digest, and Arena session,
publishes the exact attempt, reloads the public Arena refusal, and verifies it.
Permit events have no signed refusal artifact and are rejected.

The database rechecks the active adoption credential and latest bond before its
atomic insert. Unique constraints consume the opaque record ID, Arena share,
source refusal digest, and SHA-256 owner-token hash. No caller chooses a vanity
identifier.

## Public projection

The outer `EP-AGENT-RECORD-OBSERVATION-v1` envelope contains only:

- opaque record ID;
- Operating Bond ID and digest;
- public Arena share ID and refusal-artifact digest;
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

Revocation appends one immutable terminal revocation. It does not update or
delete the source record and cannot republish it. Exact public reads return the
same not-found result for unknown, expired, and revoked IDs.

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
authenticated creation route. Creation is idempotent only for the exact same
identifier, owner credential, source, signed envelope, and timestamps. A lost
HTTP response can therefore be retried without creating an ownerless public
record; a conflicting replay remains refused. The database stores only the
credential hash.

## Access model

`agent_record_private` is owned by a dedicated `NOLOGIN`, non-superuser,
non-`BYPASSRLS` role. Both tables use forced RLS. `anon`, `authenticated`, and
`service_role` have no direct table access. The public HTTP route performs an
exact opaque-ID lookup through the server-only
`read_agent_record_public(record_id)` RPC and then verifies the operator
signature before returning the envelope. `anon` and `authenticated` cannot
execute the RPC directly. There is no list, search, feed, sitemap, handle, or
enumeration function. Creation and owner revocation are separate
`service_role`-only `SECURITY DEFINER` RPCs. The database validates closed
structure and exact source bindings; it does not claim to verify Ed25519.
