# EP Security Review Checklist

This checklist is for verifying EP's security posture. Each item references the implementation file and expected behavior.

## Authorization Paths
- [ ] Every route with "operator-level" comment has a tested permission check (`app/api/audit/route.js`)
- [ ] `authenticateRequest()` validates API key against `api_keys` table (`lib/supabase.js`)
- [ ] Commit issuance checks `authorizeCommitIssuance()` before issuing (`lib/commit-auth.js`)
- [ ] Commit revocation/fulfillment checks `authorizeCommitAccess()` (`lib/commit-auth.js`)
- [ ] Dispute filing validates the filer is an affected party (`lib/canonical-writer.js`)
- [ ] Appeal filing validates the appealer is a dispute participant (`lib/canonical-writer.js`)

## Signing Model
- [ ] Ed25519 keypair derived from `EP_COMMIT_SIGNING_KEY` env var (`lib/commit.js`)
- [ ] Canonical payload is JSON-sorted before signing (`buildCanonicalPayload`)
- [ ] Signature covers all trust-relevant fields (commit_id, entity_id, decision, nonce, expires_at)
- [ ] Verification reconstructs canonical payload and verifies against stored public key
- [ ] Key discovery endpoint publishes current public keys (`/api/commit/keys`)
- [ ] `kid` field on commits identifies which key signed them

## Privacy Claims
- [ ] Commitment proofs exclude counterparty IDs and transaction amounts (`lib/zk-proofs.js`)
- [ ] HMAC commitment input is: receipt_id | entity_id | created_at only
- [ ] Proof response object contains only: claim, count, commitment_root, salt, anchor_block
- [ ] `reporter_ip` is hashed before storage (SHA-256, truncated)

## Abuse Controls
- [ ] Report abuse detection queries `trust_reports` table (not `disputes`)
- [ ] IP-based throttling uses hashed IPs
- [ ] Rate limiting per entity per report type per time window
- [ ] Dispute dampening reduces disputed receipt weight to 0.3x during review

## Audit Integrity
- [ ] Audit events are insert-only (no UPDATE/DELETE on audit_events)
- [ ] Every trust-changing write emits a durable event via `persistEvent()`
- [ ] Event types are semantically distinct (appeal filing ≠ dispute resolution)
- [ ] `eventLog` in-memory array is removed (no unbounded state)

## Appeal Path Correctness
- [ ] Only resolved disputes can be appealed (upheld/reversed/dismissed)
- [ ] Appeal resolution has its own event type (`dispute.appeal.resolved`)
- [ ] Appeal reversal recomputes trust profile
- [ ] Receipt graph_weight is correctly updated on appeal reversal

## Data Integrity
- [ ] Commit nonces are UNIQUE in DB + checked in memory
- [ ] Terminal commit states (fulfilled/revoked/expired) cannot transition
- [ ] Report types in API validation match DB CHECK constraint exactly
- [ ] OpenAPI schemas match runtime validation

## Enumeration Consistency
- [ ] Decision vocabulary: allow / review / deny (no 'block', no 'pass')
- [ ] Action types: install / connect / delegate / transact
- [ ] Report types: 5 canonical types matching DB constraint
- [ ] Dispute statuses match DB CHECK constraint

## Last Reviewed
- Date: 2026-03-19
- By: Automated security review
- Status: Initial checklist — items verified during Phase 1 audit remediation
