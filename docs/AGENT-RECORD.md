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
- an Ed25519 signature from the operator commit signing key.

It contains no adoption or Arena session ID, owner token or hash, passkey or
credential ID, candidate URL, raw WebAuthn material, prompt, IP address, agent
label, raw action, or action parameters. Public verification resolves the
configured operator key by key ID. Artifact-supplied public keys are not part of
the schema and are rejected. Production creation fails closed when
`EP_COMMIT_SIGNING_KEY` is absent.

## Owner credential and revocation

Creation returns one dedicated `ear1_` owner credential once. Only its SHA-256
hash is stored. Possession proves control of this record credential only; it
does not prove identity or ownership of an agent, codebase, account, or key.

Revocation appends one immutable terminal revocation. It does not update or
delete the source record and cannot republish it. Exact public reads return the
same not-found result for unknown, expired, and revoked IDs.

## Retention boundary

Public availability is the half-open interval
`observed_at <= now < retention_expires_at`, where
`retention_expires_at = observed_at + 365 days` (exactly 31,536,000 seconds).
At the first instant equal to `retention_expires_at`, the record is no longer
public. Owner revocation ends public availability earlier.

The minimal private binding, SHA-256 credential hash, and any revocation remain
as immutable replay tombstones so an expired or revoked source cannot be used
to mint a second record. They contain none of the forbidden raw/private fields
listed above.

## Access model

`agent_record_private` is owned by a dedicated `NOLOGIN`, non-superuser,
non-`BYPASSRLS` role. Both tables use forced RLS. `anon`, `authenticated`, and
`service_role` have no direct table access. The only public lookup is the
bounded `read_agent_record_public(record_id)` RPC; there is no list, search,
feed, sitemap, handle, or enumeration function. Creation and owner revocation
are separate `service_role`-only `SECURITY DEFINER` RPCs.
