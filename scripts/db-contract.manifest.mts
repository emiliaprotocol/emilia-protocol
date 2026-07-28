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

const RELEASE_LOCK_TABLES: string[] = [
  'release_locks',
  'release_lock_versions',
  'release_lock_draw_actions',
  'release_lock_round_acceptances',
  'release_lock_contact_bindings',
  'release_lock_invitations',
  'release_lock_sessions',
  'release_lock_pairings',
  'release_lock_registration_challenges',
  'release_lock_credentials',
  'release_lock_action_challenges',
  'release_lock_decisions',
  'release_lock_decision_invalidations',
  'release_lock_effects',
];

const RELEASE_LOCK_SERVICE_RPCS: string[] = [
  'release_lock_create_pending',
  'release_lock_activate_invitations',
  'release_lock_cancel_pending',
  'release_lock_exchange_invitation',
  'release_lock_create_pairing',
  'release_lock_exchange_pairing',
  'release_lock_resolve_session',
  'release_lock_begin_registration',
  'release_lock_load_registration',
  'release_lock_complete_registration',
  'release_lock_action_check_context',
  'release_lock_store_action_challenge',
  'release_lock_load_action_challenge',
  'release_lock_record_approval',
  'release_lock_draw_context',
  'release_lock_stage_draw',
  'release_lock_amendment_context',
  'release_lock_amend',
  'release_lock_claim_effect_binding',
  'release_lock_recover_effect',
  'release_lock_record_effect_outcome',
  'release_lock_evidence',
  'release_lock_participant_view',
  'release_lock_participant_evidence',
];

const CONSEQUENCE_ACTUATOR_RPC_ONLY_TABLES: string[] = [
  // The credential-owning actuator reaches this table only through
  // consequence_actuator_private SECURITY DEFINER RPCs under a dedicated
  // executor principal. Even service_role has no direct table grant.
  'consequence_actuator_envelopes',
];

const CONSEQUENCE_ACTUATOR_QUALIFIED_RPCS: string[] = [
  'consequence_actuator_private.reserve_envelope(text,text,text,text,text,text,text,text,text,timestamp with time zone,timestamp with time zone,text)',
  'consequence_actuator_private.consume_envelope(text,text,text,text,text,text,text,text,text,text,text)',
  'consequence_actuator_private.record_provider_attempt(jsonb,text)',
  'consequence_actuator_private.read_provider_attempt(text,text,text,text,text,text,text,text,text)',
  'consequence_actuator_private.record_provider_record(jsonb,text)',
  'consequence_actuator_private.read_provider_record(text,text,text,text,text,text,text,text,text)',
];

const ROLLOUT_ATTEMPT_QUALIFIED_TABLES: string[] = [
  'rollout_attempt_private.claims',
  'rollout_attempt_private.terminals',
];

const ROLLOUT_ATTEMPT_QUALIFIED_RPCS: string[] = [
  'rollout_attempt_private.apply_operation(text,text)',
];

const OPEN_EXPOSURE_QUALIFIED_TABLES: string[] = [
  'open_exposure_private.tenant_principals',
  'open_exposure_private.ceilings',
  'open_exposure_private.exposures',
  'open_exposure_private.history',
  'open_exposure_private.reconciliation_tokens',
];

const OPEN_EXPOSURE_QUALIFIED_RPCS: string[] = [
  'open_exposure_private.register_ceiling(jsonb)',
  'open_exposure_private.reserve(jsonb)',
  'open_exposure_private.begin_invocation(jsonb)',
  'open_exposure_private.mark_indeterminate(jsonb)',
  'open_exposure_private.reconcile(jsonb)',
  'open_exposure_private.read_exposure(jsonb)',
  'open_exposure_private.read_history(jsonb)',
  'open_exposure_private.sum_open(jsonb)',
  'open_exposure_private.list_aging(jsonb)',
  'open_exposure_private.list_deadlines(jsonb)',
];

const OPEN_EXPOSURE_SECURITY_ASSERTIONS: string[] = [
  'contract:table:open_exposure_private.tenant_principals:owner-force-rls-owner-only-acl',
  'contract:table:open_exposure_private.ceilings:owner-force-rls-owner-only-acl',
  'contract:table:open_exposure_private.exposures:owner-force-rls-owner-only-acl',
  'contract:table:open_exposure_private.history:owner-force-rls-owner-only-acl',
  'contract:table:open_exposure_private.reconciliation_tokens:owner-force-rls-owner-only-acl',
  'contract:function:open_exposure_private.register_ceiling(jsonb):owner-definer-empty-search-path-policy-admin-only',
  'contract:function:open_exposure_private.reserve(jsonb):owner-definer-empty-search-path-origin-only',
  'contract:function:open_exposure_private.begin_invocation(jsonb):owner-definer-empty-search-path-executor-only',
  'contract:function:open_exposure_private.mark_indeterminate(jsonb):owner-definer-empty-search-path-executor-only',
  'contract:function:open_exposure_private.reconcile(jsonb):owner-definer-empty-search-path-reconciler-only',
  'contract:function:open_exposure_private.read_exposure(jsonb):owner-definer-empty-search-path-reader-only',
  'contract:function:open_exposure_private.read_history(jsonb):owner-definer-empty-search-path-reader-only',
  'contract:function:open_exposure_private.sum_open(jsonb):owner-definer-empty-search-path-reader-only',
  'contract:function:open_exposure_private.list_aging(jsonb):owner-definer-empty-search-path-reader-only',
  'contract:function:open_exposure_private.list_deadlines(jsonb):owner-definer-empty-search-path-reader-only',
  'contract:trigger:open_exposure_private.tenant_principals.open_exposure_principal_separation_trigger:owner-before-insert-update-row-custody-disjoint',
  'contract:trigger:open_exposure_private.ceilings.open_exposure_ceilings_immutable_trigger:exact-before-update-delete-row-owner-only-immutable',
  'contract:trigger:open_exposure_private.exposures.open_exposure_record_guard_trigger:owner-before-update-delete-row-live-transition-guard',
  'contract:trigger:open_exposure_private.history.open_exposure_history_immutable_trigger:exact-before-update-delete-row-owner-only-immutable',
  'contract:trigger:open_exposure_private.reconciliation_tokens.open_exposure_reconciliation_tokens_immutable_trigger:exact-before-update-delete-row-owner-only-immutable',
  'contract:roles:open-exposure:least-privilege-membership-disjoint',
  'contract:index:open_exposure_private.open_exposure_ceiling_scope_idx:exact-unique-btree',
  'contract:index:open_exposure_private.open_exposure_open_aggregate_idx:exact-partial-btree-include',
  'contract:index:open_exposure_private.open_exposure_aging_idx:exact-partial-btree',
  'contract:index:open_exposure_private.open_exposure_deadline_idx:exact-partial-btree',
  'contract:index:open_exposure_private.open_exposure_history_read_idx:exact-btree',
];

const CONSEQUENCE_CONTROL_SECURITY_ASSERTIONS: string[] = [
  'contract:table:consequence_actuator_private.provider_attempts:owner-force-rls-owner-only-acl',
  'contract:table:consequence_actuator_private.provider_records:owner-force-rls-owner-only-acl',
  'contract:table:rollout_attempt_private.claims:owner-force-rls-owner-only-acl',
  'contract:table:rollout_attempt_private.terminals:owner-force-rls-owner-only-acl',
  'contract:function:consequence_actuator_private.reserve_envelope(text,text,text,text,text,text,text,text,text,timestamp with time zone,timestamp with time zone,text):owner-definer-empty-search-path-executor-only',
  'contract:function:consequence_actuator_private.consume_envelope(text,text,text,text,text,text,text,text,text,text,text):owner-definer-empty-search-path-executor-only',
  'contract:function:consequence_actuator_private.record_provider_attempt(jsonb,text):owner-definer-empty-search-path-executor-only',
  'contract:function:consequence_actuator_private.read_provider_attempt(text,text,text,text,text,text,text,text,text):owner-definer-empty-search-path-executor-only',
  'contract:function:consequence_actuator_private.record_provider_record(jsonb,text):owner-definer-empty-search-path-executor-only',
  'contract:function:consequence_actuator_private.read_provider_record(text,text,text,text,text,text,text,text,text):owner-definer-empty-search-path-executor-only',
  'contract:function:rollout_attempt_private.apply_operation(text,text):owner-definer-empty-search-path-executor-only',
  'contract:trigger:consequence_actuator_private.provider_attempts.consequence_actuator_provider_attempts_immutable:exact-before-update-delete-row-append-only',
  'contract:trigger:consequence_actuator_private.provider_attempts.consequence_actuator_provider_attempts_no_truncate:exact-before-truncate-statement-append-only',
  'contract:trigger:consequence_actuator_private.provider_records.consequence_actuator_provider_records_immutable:exact-before-update-delete-row-append-only',
  'contract:trigger:consequence_actuator_private.provider_records.consequence_actuator_provider_records_no_truncate:exact-before-truncate-statement-append-only',
  'contract:trigger:rollout_attempt_private.claims.rollout_attempt_claims_no_update_delete:exact-before-update-delete-row-append-only',
  'contract:trigger:rollout_attempt_private.claims.rollout_attempt_claims_no_truncate:exact-before-truncate-statement-append-only',
  'contract:trigger:rollout_attempt_private.terminals.rollout_attempt_terminals_no_update_delete:exact-before-update-delete-row-append-only',
  'contract:trigger:rollout_attempt_private.terminals.rollout_attempt_terminals_no_truncate:exact-before-truncate-statement-append-only',
  'contract:roles:consequence-actuator:least-privilege-membership-disjoint',
  'contract:roles:rollout-attempt:least-privilege-membership-disjoint',
  'contract:index:public.idx_security_events_single_child_per_parent:exact-unique-btree',
  'contract:index:public.idx_receipts_single_child_per_parent:exact-unique-btree',
];

// These tables are reached through server-side/service-role paths only. RLS is
// necessary but not sufficient: a table ACL is a separate Data API gate, so
// the live contract checks both controls.
const SERVICE_ONLY_TABLES: string[] = [
  // Append-only Trust Receipt/signoff/evidence ledger. Every application read
  // is tenant-projected by the server; client roles must never query or append
  // rows directly.
  'audit_events',
  'api_keys',
  'tenant_api_keys',
  'sso_connections',
  'webhook_endpoints',
  'scim_provisioning_tokens',
  'scim_users',
  'scim_groups',
  'saml_consumed_assertions',
  'revoked_commit_keys',
  'revoked_sessions',
  'session_cutoffs',
  'authority_registry_epoch',
  'fraud_flags',
  'partner_inquiries',
  'investor_inquiries',
  // Marvel durable capability store (packages/gate/capability-receipt.js):
  // spending/budget state reached only through the service-role durable store.
  'ep_capability_state',
  'ep_capability_operations',
  // Durable AEB operation and native-protocol replay fences. These are
  // authoritative execution-control state and therefore service-only.
  'ep_aeb_consumption_operations',
  'ep_aeb_consumption_replay_fences',
  'ep_remedy_case_sets',
  'ep_remedy_case_set_events',
  // Approval acquisition and evidence-readiness state are tenant-bound,
  // service-only control-plane records. Public roles must never query or
  // mutate them directly.
  'approval_acquisition_requests',
  'guard_receipt_streams',
  'guard_receipt_event_bindings',
  ...CONSEQUENCE_ACTUATOR_RPC_ONLY_TABLES,
];

interface DbContract {
  requiredTables: string[];
  requiredQualifiedTables: string[];
  requiredQualifiedRpcs: string[];
  requiredReconcileAssertions: string[];
  knownGapTables: string[];
  requiredColumns: Record<string, string[]>;
  requiredIndexes: Record<string, string[]>;
  rlsRequired: string[];
  noAnonRead: string[];
  tableGrantsNoPublic: string[];
  tableGrantsNoServiceRoleDirect: string[];
  tableWriteGrantsNoServiceRole: string[];
  sensitiveColumnsNoPublicGrant: Record<string, string[]>;
  noAnonWrite: string[];
  serviceRolePoliciesRequired: string[];
  definerRpcsServiceRoleOnly: string[];
  requiredDefinerRpcSignatures: string[];
  requiredRpcs: string[];
}

export const contract: DbContract = {
  // Tables that MUST exist. Missing => hard FAIL.
  requiredTables: [
    'entities', 'receipts', 'score_history', 'needs', 'waitlist',
    'anchor_batches', 'merkle_batches', 'disputes', 'delegations', 'principals',
    'handshakes', 'handshake_bindings', 'handshake_consumptions', 'handshake_events',
    'handshake_parties', 'handshake_policies', 'handshake_presentations', 'handshake_results',
    'signoff_challenges', 'signoff_attestations', 'signoff_consumptions', 'signoff_events',
    'approver_credentials', 'protocol_events', 'security_events', 'tenants', 'tenant_members',
    'tenant_environments', 'operator_applications', 'policy_rollouts',
    'zk_proofs',
    'authorities', 'commits', 'consumed_gate_refs',
    ...SERVICE_ONLY_TABLES,
    ...RELEASE_LOCK_TABLES,
  ],

  // Private-schema objects are qualified so the live reconciliation snapshot
  // cannot satisfy the contract with an unrelated public object. Exact RPC
  // signatures remain pinned here and are exercised by isolated PostgreSQL
  // application tests.
  requiredQualifiedTables: [
    'consequence_actuator_private.provider_attempts',
    'consequence_actuator_private.provider_records',
    ...ROLLOUT_ATTEMPT_QUALIFIED_TABLES,
    ...OPEN_EXPOSURE_QUALIFIED_TABLES,
  ],
  requiredQualifiedRpcs: [
    ...CONSEQUENCE_ACTUATOR_QUALIFIED_RPCS,
    ...ROLLOUT_ATTEMPT_QUALIFIED_RPCS,
    ...OPEN_EXPOSURE_QUALIFIED_RPCS,
  ],
  requiredReconcileAssertions: [
    ...CONSEQUENCE_CONTROL_SECURITY_ASSERTIONS,
    ...OPEN_EXPOSURE_SECURITY_ASSERTIONS,
  ],

  // Tables that SHOULD exist but are KNOWN-MISSING and tracked for a staged
  // rollout. Reported loudly as KNOWN GAP (non-fatal) so they stay visible
  // without blocking CI — but if one ever appears, remove it from here.
  // (authorities reconciled 2026-06-29, mig 118/119 — now a requiredTable.)
  knownGapTables: [],

  // Columns that MUST exist on a table. Missing => hard FAIL.
  requiredColumns: {
    api_keys: ['key_hash', 'key_prefix', 'revoked_at', 'invalidated_at', 'entity_id', 'label', 'auth_strength'],
    entities: ['display_name', 'display_name_key', 'organization_id', 'status', 'metadata'],
    signoff_challenges: ['quorum_policy'],
    receipts: ['receipt_id'],
    authorities: ['key_id', 'public_key', 'role', 'status', 'valid_from', 'valid_to',
      'revoked_at', 'organization_id', 'subject_type', 'subject_ref', 'assurance_class',
      'action_scopes', 'max_amount_usd', 'currency', 'delegation_parent', 'policy_hash'],
    authority_registry_epoch: ['organization_id', 'epoch', 'updated_at'],
    partner_inquiries: ['id', 'created_at', 'inquiry_type', 'name', 'email',
      'organization', 'title', 'website', 'message', 'metadata_json',
      'trust_surface', 'timeline'],
    investor_inquiries: ['id', 'created_at', 'inquiry_type', 'name', 'email',
      'organization', 'title', 'website', 'message', 'metadata_json',
      'why_emilia', 'help_offer'],
    // commits: verifyCommit resolves the verification key by `kid`, so a missing
    // kid column silently breaks issuance/verification (mig 132). Guard the
    // signature-verification dependency here so the drift check catches it.
    commits: ['commit_id', 'kid', 'signature', 'public_key', 'nonce',
      'entity_id', 'action_type', 'decision', 'expires_at', 'created_at'],
    revoked_commit_keys: ['kid', 'revoked_at', 'reason', 'revoked_by'],
    consumed_gate_refs: ['gate_ref', 'consumed_at', 'consumed_by_entity', 'consumed_for_action'],
    policy_rollouts: ['rollout_id', 'policy_id', 'version', 'environment', 'strategy',
      'status', 'initiated_by', 'tenant_id', 'authorization_receipt_id',
      'authorization_action_hash', 'authorization_execution_reference_id',
      'authorization_authority'],
    release_locks: ['lock_id', 'organization_id', 'contractor_entity_id',
      'current_version', 'status', 'max_expires_at'],
    release_lock_contact_bindings: ['contact_binding_id', 'lock_id', 'role',
      'identifier_digest', 'verification_proof_digest', 'authority_provider',
      'authority_key_id', 'authority_reference', 'authority_assertion',
      'authority_signature', 'authority_assertion_digest', 'authority_subject_digest',
      'authority_contact_binding_digest',
      'authority_expires_at'],
    release_lock_invitations: ['invitation_id', 'lock_id', 'role',
      'contact_binding_id', 'token_digest', 'activated_at', 'exchanged_at', 'revoked_at'],
    release_lock_sessions: ['session_id', 'lock_id', 'role', 'contact_binding_id',
      'token_digest', 'scope_version', 'scope_round', 'scope_action_hash',
      'expires_at', 'revoked_at'],
    release_lock_pairings: ['pairing_id', 'lock_id', 'version', 'role', 'round',
      'action_hash', 'token_digest', 'expires_at', 'exchanged_at', 'revoked_at'],
    release_lock_credentials: ['credential_id', 'lock_id', 'role',
      'contact_binding_id', 'public_key_spki', 'sign_count', 'revoked_at'],
    release_lock_action_challenges: ['challenge_id', 'lock_id', 'version', 'round',
      'role', 'action_hash', 'answer_digest', 'nonce', 'expires_at', 'consumed_at'],
    release_lock_decisions: ['decision_id', 'lock_id', 'version', 'round', 'role',
      'action_hash', 'resolution', 'resolution_digest'],
    release_lock_effects: ['effect_id', 'lock_id', 'version', 'effect_reference',
      'status', 'reservation_expires_at', 'reservation_attempts', 'claim_attempts',
      'effect_contract_digest', 'retryable', 'provider_result'],
    scim_provisioning_tokens: ['tenant_id', 'token_hash', 'token_prefix', 'revoked_at'],
    ep_capability_state: ['capability_id', 'capability_fingerprint', 'budget_amount',
      'currency', 'consumed_amount', 'reserved_amount', 'expires_at'],
    ep_capability_operations: ['operation_id', 'capability_id', 'action_digest', 'amount', 'currency',
      'status', 'reservation_token', 'outcome', 'reconciliation_outcome',
      'reconciliation_evidence_digest', 'reserved_at', 'committed_at', 'reconciled_at'],
    ep_aeb_consumption_operations: ['tenant_id', 'relying_party_id', 'operation_key',
      'state', 'owner_token', 'reserved_at', 'consumed_at'],
    ep_aeb_consumption_replay_fences: ['tenant_id', 'relying_party_id', 'replay_key',
      'operation_key', 'reserved_at'],
    ep_remedy_case_sets: ['tenant_id', 'case_set_id', 'revision', 'status',
      'owner_token_digest', 'manifest_json', 'manifest_digest', 'state_json',
      'state_digest', 'recorded_at'],
    ep_remedy_case_set_events: ['tenant_id', 'case_set_id', 'revision',
      'previous_revision', 'status', 'state_json', 'state_digest', 'recorded_at'],
    approval_acquisition_requests: ['request_id', 'tenant_id', 'environment',
      'requester_key_id', 'producer_key_id', 'idempotency_digest', 'request_digest', 'challenge_hash',
      'action_hash', 'action_caid', 'action', 'approver_id', 'poll_token_hash',
      'poll_token_key_id', 'poll_token_ciphertext', 'poll_token_iv',
      'poll_token_tag', 'status', 'reconciliation_state', 'receipt_id',
      'signoff_id', 'receipt_action_hash', 'refusal_code', 'indeterminate_at',
      'reconciled_at', 'refused_at', 'expires_at', 'created_at', 'updated_at'],
    guard_receipt_streams: ['receipt_id', 'tenant_id', 'environment',
      'created_event_id', 'created_at'],
    guard_receipt_event_bindings: ['event_id', 'receipt_id', 'tenant_id',
      'environment', 'event_type', 'event_created_at', 'bound_at'],
    consequence_actuator_envelopes: ['tenant_id', 'attempt_id', 'action_digest',
      'caid', 'provider_account_id', 'target_digest', 'operation',
      'idempotency_key', 'nonce', 'issued_at', 'expires_at', 'envelope_digest',
      'state', 'reserved_at', 'consumed_at', 'outcome'],
    // enrollment_basis records whether an approver credential was bound against
    // the org's provisioned directory or operator-attested; directory_user_id
    // pins the exact scim_users row that authorized a directory-basis enrollment.
    // The enrollment gate writes both and Class-A provenance depends on them
    // (mig 20260718180000).
    approver_credentials: ['approver_id', 'organization_id', 'attested_by', 'enrollment_basis', 'directory_user_id'],
  },

  // Indexes that carry a safety property rather than merely query
  // acceleration. Missing one re-opens a replay/fork or custody-resolution
  // failure and therefore violates the live contract.
  requiredIndexes: {
    security_events: ['idx_security_events_single_child_per_parent'],
    receipts: ['idx_receipts_single_child_per_parent'],
    authorities: ['idx_authorities_delegation_parent'],
    commits: ['idx_commits_kid'],
    partner_inquiries: ['idx_partner_inquiries_email'],
    investor_inquiries: ['idx_investor_inquiries_email'],
  },

  // Tables that MUST have RLS enabled. RLS off => hard FAIL.
  rlsRequired: [
    'entities', 'receipts', 'score_history', 'needs', 'waitlist',
    'anchor_batches', 'disputes', 'handshakes', 'signoff_challenges', 'signoff_attestations',
    'tenants', 'operator_applications', 'policy_rollouts',
    'authorities', 'commits',
    'consumed_gate_refs',
    ...SERVICE_ONLY_TABLES,
    ...RELEASE_LOCK_TABLES,
  ],

  // No anon/authenticated/PUBLIC may have a SELECT (or ALL) policy on these.
  // (mig 113: api_keys + waitlist were anon-readable.) authorities = permission root.
  noAnonRead: [
    'waitlist', 'authorities', 'commits', 'consumed_gate_refs',
    ...SERVICE_ONLY_TABLES,
    ...RELEASE_LOCK_TABLES,
  ],

  // Table ACLs are checked independently of RLS policies. These tables are
  // server-only, so anon/authenticated/PUBLIC must have no direct read/write
  // privilege even if a bootstrap or restore recreates a permissive grant.
  tableGrantsNoPublic: [
    'authorities',
    'commits',
    'consumed_gate_refs',
    ...SERVICE_ONLY_TABLES,
    ...RELEASE_LOCK_TABLES,
  ],

  // Release Lock is deliberately RPC-only; service_role may execute the
  // narrowly-granted SECURITY DEFINER functions but must not query the tables.
  tableGrantsNoServiceRoleDirect: [
    'consumed_gate_refs',
    ...RELEASE_LOCK_TABLES,
    ...CONSEQUENCE_ACTUATOR_RPC_ONLY_TABLES,
  ],

  // Policy rollouts remain service-readable for control-plane status, but
  // activation is RPC-only after the contract migration.
  tableWriteGrantsNoServiceRole: ['policy_rollouts', 'authorities'],

  // Column-level least-privilege on secret material. RLS gates ROWS; a column
  // GRANT is a SEPARATE gate. (2026-07 sweep: anon+authenticated held column
  // SELECT/INSERT/UPDATE on entities.private_key_encrypted — a Supabase bootstrap
  // default, NOT in any migration, so a migration scan can't see it.) These
  // (table, column) pairs MUST NOT be grantable by anon/authenticated; only
  // service_role/postgres. Revoked in migrations 126/127/129 and enforced
  // statically by tests/schema-secret-grant-guard.test.js. Live enforcement
  // catches a Supabase/bootstrap re-grant after a project reset through the
  // normalized column_grants field added by the Fortress introspection migration.
  // Full secret-bearing column set across ALL tables (live-swept 2026-07-02:
  // private_key|api_key_hash|secret|encrypted|seed|password|signing_key|key_hash).
  // Column SELECT/INSERT/UPDATE revoked from anon+authenticated in migrations
  // 127/129;
  // table-level write grants on the pure-infra tables revoked in migration 128.
  sensitiveColumnsNoPublicGrant: {
    entities: ['private_key_encrypted', 'api_key_hash'],
    api_keys: ['key_hash'],
    tenant_api_keys: ['key_hash'],
    sso_connections: ['oidc_client_secret'],
    webhook_endpoints: ['secret'],
    scim_provisioning_tokens: ['token_hash'],
  },

  // No anon/authenticated/PUBLIC may have a write policy (INSERT/UPDATE/DELETE/ALL)
  // on these. (mig 113: these were anon-writable via mis-scoped USING(true).)
  noAnonWrite: [
    'entities', 'receipts', 'score_history', 'needs', 'anchor_batches',
    'signoff_challenges', 'signoff_attestations', 'handshakes', 'tenants',
    'operator_applications', 'policy_rollouts', 'authorities',
    'consumed_gate_refs',
    ...SERVICE_ONLY_TABLES,
    ...RELEASE_LOCK_TABLES,
  ],

  // These four replay/revocation tables intentionally expose a service_role
  // policy for the existing guarded-client paths. The other service-only
  // tables either rely on service_role's bypass or are RPC-only.
  serviceRolePoliciesRequired: [
    'audit_events', 'saml_consumed_assertions', 'revoked_commit_keys', 'revoked_sessions',
    'session_cutoffs', 'authority_registry_epoch', 'fraud_flags',
    'partner_inquiries', 'investor_inquiries',
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
    'bump_authority_registry_epoch',
    'activate_policy_rollout_authorized',
    'issue_tenant_api_key_audited',
    'consume_trust_receipt_authorized',
    'reserve_approval_acquisition_request',
    'enter_approval_acquisition_boundary',
    'complete_approval_acquisition_request',
    'reconcile_approval_acquisition_request',
    'refuse_approval_acquisition_request',
    'recover_approval_acquisition_poll_token',
    'bind_guard_receipt_event_scope',
    'reject_guard_receipt_binding_mutation',
    'gov_schema_contract_introspect',
    'gov_schema_reconcile_introspect',
    'complete_webauthn_registration_atomic',
    'consume_trust_desk_bootstrap_atomic',
    ...RELEASE_LOCK_SERVICE_RPCS,
  ],

  // These public mutation roots are pinned by identity arguments as well as by
  // name. Each exact overload must be SECURITY DEFINER, closed to public API
  // roles, and executable by service_role.
  requiredDefinerRpcSignatures: [
    'public.bump_authority_registry_epoch()',
    'public.consume_gate_ref_atomic(text,text,text,text,text)',
    'public.revoke_commit_key_atomic(text,text,text)',
  ],

  // Functions that MUST exist (existence only). Includes the append-only
  // immutability triggers — their absence means tamper-evidence is unenforced.
  requiredRpcs: ['gov_schema_contract_introspect', 'gov_schema_reconcile_introspect', 'load_verify_context',
    'prevent_protocol_event_mutation', 'prevent_handshake_event_mutation',
    'prevent_consumption_reversal'],
};
