// SPDX-License-Identifier: Apache-2.0
//
// Executable schema-security contract for EP prod.
//
// This is the declarative source of truth for the SHAPE of the production
// database's security-critical objects. scripts/db-contract.mjs asserts each
// item against the live schema (via the gov_schema_contract_introspect RPC).
// The goal: prove a control EXISTS in prod, not that a migration was journaled.
//
// Many entries below encode real incidents as permanent regression tests:
//   - migration 113: api_keys/waitlist must not be anon-readable; sensitive
//     tables must not have anon/PUBLIC write policies.
//   - migration 112/111: key-mutating SECURITY DEFINER RPCs must not be
//     anon/authenticated/PUBLIC-executable.
//   - migration 098/114: columns/tables that drifted (journaled but absent).

export const contract = {
  // Tables that MUST exist. Missing => hard FAIL.
  requiredTables: [
    'api_keys', 'entities', 'receipts', 'score_history', 'needs', 'waitlist',
    'anchor_batches', 'merkle_batches', 'disputes', 'delegations', 'principals',
    'handshakes', 'handshake_bindings', 'handshake_consumptions', 'handshake_events',
    'handshake_parties', 'handshake_policies', 'handshake_presentations', 'handshake_results',
    'signoff_challenges', 'signoff_attestations', 'signoff_consumptions', 'signoff_events',
    'approver_credentials', 'protocol_events', 'security_events', 'tenants', 'tenant_members',
    'tenant_api_keys', 'tenant_environments', 'operator_applications', 'policy_rollouts',
    'investor_inquiries', 'partner_inquiries', 'fraud_flags', 'zk_proofs',
    'authorities', 'commits', 'revoked_commit_keys', 'consumed_gate_refs',
  ],

  // Tables that SHOULD exist but are KNOWN-MISSING and tracked for a staged
  // rollout. Reported loudly as KNOWN GAP (non-fatal) so they stay visible
  // without blocking CI — but if one ever appears, remove it from here.
  // (authorities reconciled 2026-06-29, mig 118/119 — now a requiredTable.)
  knownGapTables: [],

  // Columns that MUST exist on a table. Missing => hard FAIL.
  requiredColumns: {
    api_keys: ['key_hash', 'key_prefix', 'revoked_at', 'invalidated_at', 'entity_id', 'label'],
    entities: ['display_name', 'display_name_key', 'organization_id', 'status'],
    signoff_challenges: ['quorum_policy'],
    receipts: ['receipt_id'],
    authorities: ['key_id', 'public_key', 'role', 'status', 'valid_from', 'valid_to',
      'revoked_at', 'organization_id', 'subject_type', 'subject_ref', 'assurance_class'],
    // commits: verifyCommit resolves the verification key by `kid`, so a missing
    // kid column silently breaks issuance/verification (mig 132). Guard the
    // signature-verification dependency here so the drift check catches it.
    commits: ['commit_id', 'kid', 'signature', 'public_key', 'nonce',
      'entity_id', 'action_type', 'decision', 'expires_at', 'created_at'],
    revoked_commit_keys: ['kid', 'revoked_at', 'reason', 'revoked_by'],
    consumed_gate_refs: ['gate_ref', 'consumed_at', 'consumed_by_entity', 'consumed_for_action'],
  },

  // Tables that MUST have RLS enabled. RLS off => hard FAIL.
  rlsRequired: [
    'api_keys', 'entities', 'receipts', 'score_history', 'needs', 'waitlist',
    'anchor_batches', 'disputes', 'handshakes', 'signoff_challenges', 'signoff_attestations',
    'tenants', 'tenant_api_keys', 'operator_applications', 'policy_rollouts',
    'investor_inquiries', 'partner_inquiries', 'fraud_flags', 'authorities', 'commits',
    'revoked_commit_keys', 'consumed_gate_refs',
  ],

  // No anon/authenticated/PUBLIC may have a SELECT (or ALL) policy on these.
  // (mig 113: api_keys + waitlist were anon-readable.) authorities = permission root.
  noAnonRead: [
    'api_keys', 'waitlist', 'tenant_api_keys', 'authorities', 'commits',
    'revoked_commit_keys', 'consumed_gate_refs',
  ],

  // Column-level least-privilege on secret material. RLS gates ROWS; a column
  // GRANT is a SEPARATE gate. (2026-07 sweep: anon+authenticated held column
  // SELECT/INSERT/UPDATE on entities.private_key_encrypted — a Supabase bootstrap
  // default, NOT in any migration, so a migration scan can't see it.) These
  // (table, column) pairs MUST NOT be grantable by anon/authenticated; only
  // service_role/postgres. Revoked in migration 126; enforced statically against
  // the migration set by tests/schema-secret-grant-guard.test.js. LIVE
  // enforcement (catching a Supabase bootstrap re-grant after a project reset)
  // is a follow-up: extend gov_schema_contract_introspect() to surface anon/
  // authenticated column_grants, then assert them here like noAnonRead.
  // Full secret-bearing column set across ALL tables (live-swept 2026-07-02:
  // private_key|api_key_hash|secret|encrypted|seed|password|signing_key|key_hash).
  // Column SELECT/INSERT/UPDATE revoked from anon+authenticated in migration 127;
  // table-level write grants on the pure-infra tables revoked in migration 128.
  sensitiveColumnsNoPublicGrant: {
    entities: ['private_key_encrypted', 'api_key_hash'],
    api_keys: ['key_hash'],
    tenant_api_keys: ['key_hash'],
    sso_connections: ['oidc_client_secret'],
    webhook_endpoints: ['secret'],
  },

  // No anon/authenticated/PUBLIC may have a write policy (INSERT/UPDATE/DELETE/ALL)
  // on these. (mig 113: these were anon-writable via mis-scoped USING(true).)
  noAnonWrite: [
    'api_keys', 'entities', 'receipts', 'score_history', 'needs', 'anchor_batches',
    'signoff_challenges', 'signoff_attestations', 'handshakes', 'tenants', 'tenant_api_keys',
    'operator_applications', 'policy_rollouts', 'authorities',
    'revoked_commit_keys', 'consumed_gate_refs',
  ],

  // SECURITY DEFINER RPCs that MUST exist and MUST NOT be anon/authenticated/
  // PUBLIC-executable. (mig 111/112.) Overloads all checked.
  definerRpcsServiceRoleOnly: [
    'rotate_api_key_atomic', 'create_handshake_atomic', 'consume_handshake_atomic',
    'consume_signoff_atomic', 'approve_attestation_atomic', 'issue_challenge_atomic',
    'present_handshake_writes', 'verify_handshake_writes', 'resolve_authenticated_actor',
    'bulk_update_receipt_anchors', 'create_test_fixtures',
    'admin_begin_key_rotation', 'admin_complete_key_rotation',
    'consume_gate_ref_atomic', 'revoke_commit_key_atomic',
    'gov_schema_contract_introspect',
  ],

  // Functions that MUST exist (existence only). Includes the append-only
  // immutability triggers — their absence means tamper-evidence is unenforced.
  requiredRpcs: ['gov_schema_contract_introspect', 'load_verify_context',
    'prevent_protocol_event_mutation', 'prevent_handshake_event_mutation',
    'prevent_consumption_reversal'],
};
