/**
 * EMILIA Protocol — Postgres Integration Tests
 *
 * Tests DB-level invariants that application code depends on:
 *   1. Receipts are append-only (trigger blocks UPDATE and DELETE)
 *   2. Handshake consumption is irreversible (trigger blocks clearing consumed_at)
 *   3. Signoff consume-once (UNIQUE constraint on signoff_consumptions.signoff_id)
 *   4. Signoff status transitions are forward-only (trigger rejects backward moves)
 *
 * Requires a running Postgres instance. Configure via environment:
 *   PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE
 * Defaults: localhost:5433, user=ep_test, password=ep_test, database=ep_test
 *
 * Local setup: `docker compose -f docker-compose.test.yml up -d`
 * CI: GitHub Actions postgres service (see .github/workflows/ci.yml integration job)
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import pg from 'pg';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'node:crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const SCHEMA_FILE = path.join(__dirname, 'fixtures/integration-schema.sql');
const ORG_QUORUM_MIGRATION_FILE = path.join(
  __dirname,
  '../supabase/migrations/20260702062015_org_quorum_policies.sql',
);
const POLICY_ROLLOUT_MIGRATION_FILE = path.join(
  __dirname,
  '../supabase/migrations/20260719123000_policy_rollout_accountable_signoff.sql',
);
const POLICY_ROLLOUT_AUTHORITY_MIGRATION_FILE = path.join(
  __dirname,
  '../supabase/migrations/20260719123500_policy_rollout_authority_admin.sql',
);
const TENANT_API_KEY_ISSUE_MIGRATION_FILE = path.join(
  __dirname,
  '../supabase/migrations/20260719123600_tenant_api_key_audited_issue.sql',
);
const RECEIPT_API_KEY_PERMISSIONS_MIGRATION_FILE = path.join(
  __dirname,
  '../supabase/migrations/20260825130000_receipt_api_key_permissions.sql',
);
const HANDSHAKE_CONSUME_MIGRATION_FILE = path.join(
  __dirname,
  '../supabase/migrations/085_consume_atomic_mark_binding.sql',
);
const SIGNOFF_LIFECYCLE_MIGRATION_FILE = path.join(
  __dirname,
  '../supabase/migrations/20260826120000_signoff_atomic_state_locks.sql',
);
const SIGNOFF_REQUEST_UNIQUENESS_MIGRATION_FILE = path.join(
  __dirname,
  '../supabase/migrations/20260719124500_signoff_request_uniqueness.sql',
);
const AUDIT_EVENTS_APPEND_ONLY_MIGRATION_FILE = path.join(
  __dirname,
  '../supabase/migrations/20260719125000_audit_events_append_only.sql',
);
const TRUST_RECEIPT_CONSUME_MIGRATION_FILE = path.join(
  __dirname,
  '../supabase/migrations/20260719125500_trust_receipt_atomic_consume.sql',
);
const MOBILE_PRODUCTION_MIGRATION_FILE = path.join(
  __dirname,
  '../supabase/migrations/20260717072053_mobile_production_platform.sql',
);
const MOBILE_PGCRYPTO_SCHEMA_PIN_MIGRATION_FILE = path.join(
  __dirname,
  '../supabase/migrations/20260720182147_mobile_pgcrypto_schema_pin.sql',
);
const STRIX_TRANSACTIONAL_CLOSURE_MIGRATION_FILE = path.join(
  __dirname,
  '../supabase/migrations/20260826140000_strix_rls_and_lifecycle_fortress_db_security_invariants.sql',
);
const IDENTITY_PROOF_MOBILE_PAIRING_MIGRATION_FILE = path.join(
  __dirname,
  '../supabase/migrations/20260826150000_identity_proof_and_mobile_pairing_closure.sql',
);
const IDENTITY_RUNTIME_RESIDUAL_MIGRATION_FILE = path.join(
  __dirname,
  '../supabase/migrations/20260826170000_identity_runtime_residual_closure.sql',
);
const SKIP = !process.env.INTEGRATION_POSTGRES;

const SIGNOFF_POLICY_ID = '77777777-7777-4777-8777-777777777777';
const SIGNOFF_AUTHORITY_ID = '88888888-8888-4888-8888-888888888888';
const SIGNOFF_ORGANIZATION_ID = 'org-signoff';
const SIGNOFF_AUTHORITY_CLASS = 'treasury_officer';
const SIGNOFF_ACTION_TYPE = 'wire_transfer';
const SIGNOFF_POLICY_RULES = {
  accountable_signoff: {
    accountable_role: 'responder',
    action_types: [SIGNOFF_ACTION_TYPE],
    allowed_methods: ['passkey'],
    authority_class: SIGNOFF_AUTHORITY_CLASS,
    max_ttl_seconds: 300,
    organization_id: SIGNOFF_ORGANIZATION_ID,
    required: true,
    required_assurance: 'substantial',
  },
};

function canonicalPolicy(value) {
  if (Array.isArray(value)) return value.map(canonicalPolicy);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [
      key,
      canonicalPolicy(value[key]),
    ]));
  }
  return value;
}

const SIGNOFF_POLICY_HASH = crypto.createHash('sha256')
  .update(JSON.stringify(canonicalPolicy(SIGNOFF_POLICY_RULES)), 'utf8')
  .digest('hex');

// ---------------------------------------------------------------------------
// Connection helpers
// ---------------------------------------------------------------------------

let pool;

function getPool() {
  if (pool) return pool;
  pool = new pg.Pool({
    host:     process.env.PGHOST     ?? 'localhost',
    port:     parseInt(process.env.PGPORT ?? '5433', 10),
    user:     process.env.PGUSER     ?? 'ep_test',
    password: process.env.PGPASSWORD ?? 'ep_test',
    database: process.env.PGDATABASE ?? 'ep_test',
  });
  return pool;
}

async function query(sql, params) {
  return getPool().query(sql, params);
}

async function waitForBlockedQuery(fragment, timeoutMs = 3_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const { rows } = await query(
      `SELECT COALESCE(bool_or(wait_event_type = 'Lock'), false) AS blocked
       FROM pg_stat_activity
       WHERE datname = current_database()
         AND pid <> pg_backend_pid()
         AND query LIKE '%' || $1 || '%'`,
      [fragment],
    );
    if (rows[0].blocked) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`query did not reach a lock wait: ${fragment}`);
}

function migrationSection(sql, beginMarker, endMarker) {
  const start = sql.indexOf(beginMarker);
  const end = sql.indexOf(endMarker, start + beginMarker.length);
  if (start < 0 || end < 0) {
    throw new Error(`migration section missing: ${beginMarker} ... ${endMarker}`);
  }
  return sql.slice(start + beginMarker.length, end);
}

// ---------------------------------------------------------------------------
// Test lifecycle
// ---------------------------------------------------------------------------

beforeAll(async () => {
  if (SKIP) return;
  const schema = fs.readFileSync(SCHEMA_FILE, 'utf8');
  await query(schema);
  const quorumMigration = fs.readFileSync(ORG_QUORUM_MIGRATION_FILE, 'utf8');
  await query(quorumMigration);
  const rolloutMigration = fs.readFileSync(POLICY_ROLLOUT_MIGRATION_FILE, 'utf8');
  await query(rolloutMigration);
  const authorityMigration = fs.readFileSync(POLICY_ROLLOUT_AUTHORITY_MIGRATION_FILE, 'utf8');
  await query(authorityMigration);
  const tenantKeyMigration = fs.readFileSync(TENANT_API_KEY_ISSUE_MIGRATION_FILE, 'utf8');
  await query(tenantKeyMigration);
  const receiptKeyMigration = fs.readFileSync(
    RECEIPT_API_KEY_PERMISSIONS_MIGRATION_FILE,
    'utf8',
  );
  await query(receiptKeyMigration);
  const handshakeConsumeMigration = fs.readFileSync(
    HANDSHAKE_CONSUME_MIGRATION_FILE,
    'utf8',
  );
  await query(handshakeConsumeMigration);
  const signoffLifecycleMigration = fs.readFileSync(
    SIGNOFF_LIFECYCLE_MIGRATION_FILE,
    'utf8',
  );
  await query(signoffLifecycleMigration);
  await query(
    `INSERT INTO handshake_policies
       (policy_id, policy_key, version, mode, status, rules)
     VALUES ($1, 'accountable-signoff-test', 1, 'mutual', 'active', $2::jsonb)`,
    [SIGNOFF_POLICY_ID, JSON.stringify(SIGNOFF_POLICY_RULES)],
  );
  await query(
    `INSERT INTO authorities
       (authority_id, key_id, public_key, role, status, organization_id,
        subject_type, subject_ref, assurance_class, action_scopes, policy_hash)
     VALUES (
       $1, 'signoff-authority-key', 'test-public-key', $2, 'active', $3,
       'human_approver', 'entity-alice', 'A', ARRAY[$4]::text[], $5
     )`,
    [
      SIGNOFF_AUTHORITY_ID,
      SIGNOFF_AUTHORITY_CLASS,
      SIGNOFF_ORGANIZATION_ID,
      SIGNOFF_ACTION_TYPE,
      SIGNOFF_POLICY_HASH,
    ],
  );
  const signoffRequestMigration = fs.readFileSync(
    SIGNOFF_REQUEST_UNIQUENESS_MIGRATION_FILE,
    'utf8',
  );
  await query(signoffRequestMigration);
  const auditAppendOnlyMigration = fs.readFileSync(AUDIT_EVENTS_APPEND_ONLY_MIGRATION_FILE, 'utf8');
  await query(auditAppendOnlyMigration);
  const trustReceiptConsumeMigration = fs.readFileSync(
    TRUST_RECEIPT_CONSUME_MIGRATION_FILE,
    'utf8',
  );
  await query(trustReceiptConsumeMigration);
  const mobileProductionMigration = fs.readFileSync(
    MOBILE_PRODUCTION_MIGRATION_FILE,
    'utf8',
  );
  await query(mobileProductionMigration);
  const mobilePgcryptoSchemaPinMigration = fs.readFileSync(
    MOBILE_PGCRYPTO_SCHEMA_PIN_MIGRATION_FILE,
    'utf8',
  );
  await query(mobilePgcryptoSchemaPinMigration);
  const strixClosureMigration = fs.readFileSync(
    STRIX_TRANSACTIONAL_CLOSURE_MIGRATION_FILE,
    'utf8',
  );
  await query(migrationSection(
    strixClosureMigration,
    '-- BEGIN STRIX-TRANSACTIONAL-CLOSURE',
    '-- END STRIX-TRANSACTIONAL-CLOSURE',
  ));
  // The main fixture intentionally carries only the minimal tables needed by
  // the older invariant tests. Add the exact columns/tables consumed by the
  // identity migration so the real SQL function bodies compile and execute in
  // PostgreSQL rather than being tested as strings.
  await query(`
    ALTER TABLE public.entities ADD COLUMN organization_id text;
    ALTER TABLE public.handshakes
      DROP CONSTRAINT handshakes_status_check,
      ADD COLUMN metadata_json jsonb NOT NULL DEFAULT '{}'::jsonb,
      ADD CONSTRAINT handshakes_status_check CHECK (
        status IN ('initiated', 'presented', 'pending_verification', 'verified',
                   'rejected', 'consumed', 'revoked', 'expired')
      );
    ALTER TABLE public.approver_credentials
      ADD COLUMN public_key_cose text NOT NULL DEFAULT 'AQID',
      ADD COLUMN sign_count bigint NOT NULL DEFAULT 0,
      ADD COLUMN transports text[],
      ADD COLUMN enrollment_basis text,
      ADD COLUMN directory_user_id uuid,
      ADD COLUMN approver_name text,
      ADD COLUMN attestation_fmt text,
      ADD COLUMN attested_by text;
    CREATE TABLE public.scim_provisioning_tokens (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id text NOT NULL,
      organization_id text,
      token_hash text NOT NULL UNIQUE,
      token_prefix text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      last_used_at timestamptz,
      revoked_at timestamptz
    );
    CREATE TABLE public.scim_users (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id text NOT NULL,
      external_id text,
      user_name text NOT NULL,
      active boolean NOT NULL DEFAULT true,
      formatted_name text,
      given_name text,
      family_name text,
      display_name text,
      emails jsonb NOT NULL DEFAULT '[]'::jsonb,
      phone_numbers jsonb NOT NULL DEFAULT '[]'::jsonb,
      title text,
      raw jsonb NOT NULL DEFAULT '{}'::jsonb,
      version integer NOT NULL DEFAULT 1,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (tenant_id, user_name)
    );
    CREATE TABLE public.scim_groups (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id text NOT NULL,
      external_id text,
      display_name text NOT NULL,
      members jsonb NOT NULL DEFAULT '[]'::jsonb,
      version integer NOT NULL DEFAULT 1,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (tenant_id, display_name)
    );
    CREATE TABLE public.webauthn_challenges (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      kind text NOT NULL,
      organization_id text NOT NULL,
      approver_id text NOT NULL,
      challenge text NOT NULL,
      expires_at timestamptz NOT NULL,
      consumed_at timestamptz
    );
    ALTER TABLE public.handshake_events
      DROP CONSTRAINT handshake_events_event_type_check,
      ADD COLUMN event_payload jsonb NOT NULL DEFAULT '{}'::jsonb;
    CREATE TABLE public.handshake_presentations (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      handshake_id uuid NOT NULL REFERENCES public.handshakes(handshake_id),
      party_role text NOT NULL,
      presentation_type text NOT NULL,
      issuer_ref text,
      presentation_hash text NOT NULL,
      disclosure_mode text NOT NULL,
      raw_claims jsonb,
      normalized_claims jsonb,
      canonical_claims_hash text,
      actor_entity_ref text,
      authority_id text,
      issuer_status text,
      verified boolean NOT NULL DEFAULT false,
      verified_at timestamptz,
      revocation_checked boolean NOT NULL DEFAULT false,
      revocation_status text
    );
    CREATE TABLE public.handshake_results (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      handshake_id uuid NOT NULL UNIQUE REFERENCES public.handshakes(handshake_id),
      policy_version text NOT NULL,
      outcome text NOT NULL CHECK (outcome IN ('accepted', 'rejected', 'partial', 'expired')),
      reason_codes text[] DEFAULT '{}',
      assurance_achieved text,
      decision_ref text,
      evaluated_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE public.protocol_events (
      event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      aggregate_type text NOT NULL,
      aggregate_id text NOT NULL,
      command_type text NOT NULL,
      payload_json jsonb NOT NULL,
      payload_hash text NOT NULL,
      actor_authority_id text,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    INSERT INTO public.entities (entity_id, organization_id, status) VALUES
      ('scim-valid-tenant', '@org:scim-valid', 'active'),
      ('legacy-squatter', 'legacy-squatter', 'active'),
      ('victim-org', '@org:attacker', 'active');
    INSERT INTO public.scim_provisioning_tokens (
      tenant_id, organization_id, token_hash, token_prefix
    ) VALUES
      ('scim-valid-tenant', NULL, 'scim-valid-token-hash', 'scim_valid'),
      ('legacy-squatter', 'legacy-squatter', 'legacy-squatter-token-hash', 'scim_legacy'),
      ('victim-org', '@org:attacker', 'attacker-token-hash', 'scim_attack');
    INSERT INTO public.scim_users (tenant_id, user_name, active) VALUES
      ('scim-valid-tenant', 'valid@example.com', true),
      ('victim-org', 'cfo@victim.example', true);
  `);
  const identityProofMigration = fs.readFileSync(
    IDENTITY_PROOF_MOBILE_PAIRING_MIGRATION_FILE,
    'utf8',
  );
  await query(identityProofMigration);
  const identityRuntimeMigration = fs.readFileSync(
    IDENTITY_RUNTIME_RESIDUAL_MIGRATION_FILE,
    'utf8',
  );
  await query(identityRuntimeMigration);
});

afterAll(async () => {
  if (!pool) return;
  await pool.end();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function insertEntity(entityId) {
  const { rows } = await query(
    `INSERT INTO entities (entity_id) VALUES ($1) RETURNING id`,
    [entityId],
  );
  return rows[0].id;
}

async function insertReceipt(entityId, submittedBy = 'submitter-1', previousHash = null) {
  const receiptHash = `hash-${Math.random().toString(36).slice(2)}`;
  const { rows } = await query(
    `INSERT INTO receipts (entity_id, submitted_by, composite_score, receipt_hash, previous_hash)
     VALUES ($1, $2, $3, $4, $5) RETURNING id, receipt_hash`,
    [entityId, submittedBy, 88, receiptHash, previousHash],
  );
  return rows[0];
}

async function insertHandshake({
  policyId = SIGNOFF_POLICY_ID,
  policyHash = SIGNOFF_POLICY_HASH,
  policyVersion = 1,
  actionType = SIGNOFF_ACTION_TYPE,
} = {}) {
  const nonce = `nonce-${Math.random().toString(36).slice(2)}`;
  const { rows } = await query(
    `INSERT INTO handshakes
       (nonce, status, verified_at, policy_id, policy_hash,
        policy_version_number, action_type)
     VALUES ($1, 'verified', now(), $2, $3, $4, $5)
     RETURNING handshake_id`,
    [nonce, policyId, policyHash, policyVersion, actionType],
  );
  const handshakeId = rows[0].handshake_id;
  await query(
    `INSERT INTO handshake_parties
       (handshake_id, entity_ref, party_role, verified_status)
     VALUES
       ($1, 'entity-issuer', 'initiator', 'verified'),
       ($1, 'entity-alice', 'responder', 'verified'),
       ($1, 'entity-bob', 'verifier', 'verified')`,
    [handshakeId],
  );
  return handshakeId;
}

async function insertBinding(
  handshakeId,
  {
    consumed = false,
    verificationFinalized = false,
    policyHash = SIGNOFF_POLICY_HASH,
  } = {},
) {
  const finalized = consumed || verificationFinalized;
  const { rows } = await query(
    `INSERT INTO handshake_bindings
       (handshake_id, payload_hash, binding_hash, policy_hash, nonce, expires_at,
        consumed_at, consumed_by, consumed_for)
     VALUES ($1, $2, 'bhash-xyz', $3, $4, now() + interval '1 hour', $5, $6, $7)
     RETURNING id`,
    [handshakeId, 'phash-abc', policyHash,
     `bnonce-${Math.random().toString(36).slice(2)}`,
     finalized ? new Date() : null,
     finalized ? 'entity-verifier' : null,
     finalized ? `handshake_verified:${handshakeId}` : null],
  );
  return rows[0].id;
}

async function insertChallenge(
  bindingId,
  { expiresAt = new Date(Date.now() + 10 * 60 * 1000) } = {},
) {
  const { rows } = await query(
    `INSERT INTO signoff_challenges
       (handshake_id, binding_hash, accountable_actor_ref,
        signoff_policy_id, signoff_policy_hash, required_assurance,
        allowed_methods, required_authority_class, authority_organization_id,
        authority_id, status, expires_at)
     VALUES (
       $1, $2, 'entity-alice', $3, $4, 'substantial', ARRAY['passkey']::text[],
       $5, $6, $7, 'challenge_issued', $8
     )
     RETURNING challenge_id`,
    [
      bindingId,
      'bhash-xyz',
      SIGNOFF_POLICY_ID,
      SIGNOFF_POLICY_HASH,
      SIGNOFF_AUTHORITY_CLASS,
      SIGNOFF_ORGANIZATION_ID,
      SIGNOFF_AUTHORITY_ID,
      expiresAt,
    ],
  );
  return rows[0].challenge_id;
}

async function insertCeremonyEvidence(challengeId, {
  actor = 'entity-alice',
  authorityId = SIGNOFF_AUTHORITY_ID,
  authMethod = 'passkey',
  assuranceLevel = 'substantial',
  channel = 'web',
} = {}) {
  const { rows } = await query(
    `INSERT INTO signoff_ceremony_evidence
       (challenge_id, human_entity_ref, authority_id, auth_method,
        assurance_level, channel, evidence_hash, verified_at, expires_at)
     VALUES (
       $1, $2, $3, $4, $5, $6,
       'ceremony-hash-' || pg_catalog.gen_random_uuid()::text,
       now(), now() + interval '5 minutes'
     )
     RETURNING evidence_id`,
    [challengeId, actor, authorityId, authMethod, assuranceLevel, channel],
  );
  return rows[0].evidence_id;
}

async function insertAttestation(
  challengeId,
  bindingId,
  { expiresAt = new Date(Date.now() + 60 * 60 * 1000) } = {},
) {
  const { rows } = await query(
    `INSERT INTO signoff_attestations
       (challenge_id, handshake_id, binding_hash, auth_method, expires_at)
     VALUES ($1, $2, $3, 'passkey', $4) RETURNING signoff_id`,
    [challengeId, bindingId, 'bhash-xyz', expiresAt],
  );
  return rows[0].signoff_id;
}

const ROLLOUT_TENANT_ID = '33333333-3333-4333-8333-333333333333';
const ROLLOUT_POLICY_ID = '11111111-1111-4111-8111-111111111111';
const ROLLOUT_AUTHORITY_ID = '55555555-5555-4555-8555-555555555555';
const ROLLOUT_ACTION_HASH = 'a'.repeat(64);
const ROLLOUT_RULES = { deny: ['compromised'] };
const ROLLOUT_METADATA = { ticket: 'CAB-42' };

function rolloutAfterState(environment) {
  return {
    policy_id: ROLLOUT_POLICY_ID,
    policy_key: 'strict',
    policy_version: 2,
    policy_rules: ROLLOUT_RULES,
    policy_mode: 'mutual',
    policy_status: 'active',
    environment,
    strategy: 'immediate',
    canary_pct: null,
    metadata: ROLLOUT_METADATA,
  };
}

async function insertRolloutReceipt(receiptId, environment) {
  const beforeState = { active_rollouts: [] };
  const afterState = rolloutAfterState(environment);
  const canonicalAction = {
    organization_id: ROLLOUT_TENANT_ID,
    action_type: 'policy_rollout',
    target_resource_id: 'policy:strict',
    before_state_hash: 'before-hash',
    after_state_hash: 'after-hash',
    executing_key_id: 'key-abc123',
    rollout_policy_id: ROLLOUT_POLICY_ID,
    rollout_policy_key: 'strict',
    rollout_policy_version: 2,
    rollout_policy_rules: ROLLOUT_RULES,
    rollout_policy_mode: 'mutual',
    rollout_policy_status: 'active',
    rollout_environment: environment,
    rollout_strategy: 'immediate',
    rollout_canary_pct: null,
    rollout_metadata: ROLLOUT_METADATA,
    rollout_before_state: beforeState,
    rollout_after_state: afterState,
  };
  await query(
    `INSERT INTO audit_events
       (event_type, actor_id, actor_type, target_type, target_id, action, after_state)
     VALUES
       ('guard.trust_receipt.created', 'ep:cloud-key:key-abc123', 'principal', 'trust_receipt', $1, 'create', $2::jsonb),
       ('guard.signoff.requested', 'ep:cloud-key:key-abc123', 'principal', 'trust_receipt', $1, 'request_signoff', $3::jsonb),
       ('guard.signoff.approved', 'approver-1', 'principal', 'trust_receipt', $1, 'approved', $4::jsonb)`,
    [
      receiptId,
      JSON.stringify({
        organization_id: ROLLOUT_TENANT_ID,
        action_type: 'policy_rollout',
        target_resource_id: 'policy:strict',
        decision: 'allow_with_signoff',
        signoff_required: true,
        required_assurance: 'A',
        quorum_policy: null,
        action_hash: ROLLOUT_ACTION_HASH,
        before_state_hash: 'before-hash',
        after_state_hash: 'after-hash',
        expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
        canonical_action: canonicalAction,
      }),
      JSON.stringify({ signoff_id: `${receiptId}-signoff`, approver_id: 'approver-1' }),
      JSON.stringify({
        signoff_id: `${receiptId}-signoff`,
        approver_id: 'approver-1',
        approved_action_hash: ROLLOUT_ACTION_HASH,
        key_class: 'A',
        context: {
          action_hash: ROLLOUT_ACTION_HASH,
          issued_at: new Date().toISOString(),
        },
        webauthn: { credential_id: 'credential-1' },
      }),
    ],
  );
  return { beforeState, afterState };
}

async function activateRolloutAsServiceRole({
  receiptId,
  environment,
  beforeState,
  afterState,
  authorityId = ROLLOUT_AUTHORITY_ID,
  authorityIds = [authorityId],
  quorumPolicy = null,
}) {
  const client = await getPool().connect();
  try {
    await client.query('SET ROLE service_role');
    return await client.query(
      `SELECT * FROM public.activate_policy_rollout_authorized(
         $1::uuid, $2::uuid, $3::text, $4::integer, $5::text, $6::text,
         $7::smallint, $8::text, $9::jsonb, $10::text, $11::text,
         $12::jsonb, $13::jsonb, $14::uuid[], $15::jsonb
       )`,
      [
        ROLLOUT_TENANT_ID,
        ROLLOUT_POLICY_ID,
        'strict',
        2,
        environment,
        'immediate',
        null,
        'key:key-abc123',
        JSON.stringify(ROLLOUT_METADATA),
        receiptId,
        ROLLOUT_ACTION_HASH,
        JSON.stringify(beforeState),
        JSON.stringify(afterState),
        authorityIds,
        quorumPolicy ? JSON.stringify(quorumPolicy) : null,
      ],
    );
  } finally {
    await client.query('RESET ROLE').catch(() => {});
    client.release();
  }
}

async function consumeTrustReceiptAsServiceRole({
  receiptId,
  actionHash,
  organizationId,
  registryBindings,
}) {
  const client = await getPool().connect();
  try {
    await client.query('SET ROLE service_role');
    return await client.query(
      `SELECT public.consume_trust_receipt_authorized(
         $1::text, $2::text, $3::text, $4::text, $5::text, $6::text,
         $7::jsonb, $8::jsonb
       ) AS consumed`,
      [
        receiptId,
        actionHash,
        'ep:test:consumer',
        organizationId,
        'integration-test-executor',
        'provider-operation-1',
        JSON.stringify(registryBindings),
        JSON.stringify({ source: 'integration-test' }),
      ],
    );
  } finally {
    await client.query('RESET ROLE').catch(() => {});
    client.release();
  }
}

async function insertMobileIdentityRuntimeFixture(suffix) {
  const entityRef = `mobile-runtime-${suffix}`;
  const organizationId = `@org:${crypto.randomUUID()}`;
  const approverId = `mobile.runtime.${suffix}@example.com`;
  const identityCredentialId = `identity-credential-${suffix}`;
  const deviceKeyId = `ep:key:mobile-${crypto.randomBytes(20).toString('hex')}`;
  const tokenHash = crypto.randomBytes(32).toString('hex');
  const sessionId = crypto.randomUUID();
  const appId = 'ai.emiliaprotocol.approver';

  await query(
    `INSERT INTO public.entities (entity_id, organization_id, status)
     VALUES ($1, $2, 'active')`,
    [entityRef, organizationId],
  );
  const directoryUser = await query(
    `INSERT INTO public.scim_users (tenant_id, user_name, active)
     VALUES ($1, $2, true) RETURNING id, version`,
    [entityRef, approverId],
  );
  const token = await query(
    `INSERT INTO public.scim_provisioning_tokens (
       tenant_id, organization_id, token_hash, token_prefix
     ) VALUES ($1, $2, $3, 'mobile_runtime') RETURNING id`,
    [entityRef, organizationId, crypto.randomBytes(32).toString('hex')],
  );
  await query(
    `INSERT INTO public.approver_credentials (
       organization_id, approver_id, credential_id, public_key_spki,
       public_key_cose, key_class, sign_count, enrollment_basis,
       directory_user_id, valid_from
     ) VALUES ($1, $2, $3, 'runtime-identity-spki', 'AQID', 'A', 0,
       'directory', $4, clock_timestamp() - interval '1 minute')`,
    [organizationId, approverId, identityCredentialId, directoryUser.rows[0].id],
  );
  await query(
    `INSERT INTO public.mobile_enrollments (
       device_key_id, entity_ref, credential_id, public_key_spki, approver_id,
       platform, app_id, attestation_key_id, platform_public_key, status,
       valid_from, valid_to, sign_count, attestation_format
     ) VALUES (
       $1, $2, $3, $4, $5, 'android', $6, $7, $8, 'active',
       clock_timestamp() - interval '1 minute',
       clock_timestamp() + interval '1 day', 0, 'play-integrity-standard'
     )`,
    [
      deviceKeyId,
      entityRef,
      `device-credential-${suffix}`,
      'A'.repeat(96),
      approverId,
      appId,
      `android-keystore:sha256:${crypto.createHash('sha256').update(suffix).digest('base64url')}`,
      'C'.repeat(120),
    ],
  );
  await query(
    `INSERT INTO public.mobile_sessions (
       session_id, token_hash, entity_ref, organization_id, approver_id,
       directory_user_id, identity_credential_id, identity_proof_digest,
       identity_verified_at, profile_id, platform, app_id, device_key_id,
       expires_at
     ) VALUES (
       $1, $2, $3, $4, $5, $6, $7, $8, clock_timestamp(),
       'profile-runtime', 'android', $9, $10,
       clock_timestamp() + interval '1 day'
     )`,
    [
      sessionId,
      tokenHash,
      entityRef,
      organizationId,
      approverId,
      directoryUser.rows[0].id,
      identityCredentialId,
      `sha256:${crypto.randomBytes(32).toString('hex')}`,
      appId,
      deviceKeyId,
    ],
  );
  return {
    entityRef,
    organizationId,
    approverId,
    identityCredentialId,
    deviceKeyId,
    tokenHash,
    sessionId,
    appId,
    directoryUserId: directoryUser.rows[0].id,
    directoryUserVersion: directoryUser.rows[0].version,
    scimTokenId: token.rows[0].id,
  };
}

async function insertMobilePendingAction(fixture, suffix) {
  const actionReference = `action-${suffix}`;
  const challengeId = `challenge-${suffix}`;
  const actionHash = `sha256:${crypto.randomBytes(32).toString('hex')}`;
  await query(
    `INSERT INTO public.mobile_actions (
       action_reference, entity_ref, approver_id, initiator_id, action,
       presentation, policy, policy_id, expires_at
     ) VALUES ($1, $2, $3, 'integration-agent', $4::jsonb, $5::jsonb,
       '{}'::jsonb, 'policy-runtime', clock_timestamp() + interval '1 day')`,
    [
      actionReference,
      fixture.entityRef,
      fixture.approverId,
      JSON.stringify({ action_id: `runtime:${suffix}`, kind: 'release' }),
      JSON.stringify({
        '@version': 'EP-MOBILE-PRESENTATION-v1',
        title: 'Release protected action',
        summary: 'Release the pending protected action.',
        risk: 'high',
        consequence: 'The protected action will execute.',
        material_fields: { item: actionReference },
      }),
    ],
  );
  return { actionReference, challengeId, actionHash };
}

function buildMobileDecisionCommit(fixture, action, {
  previousHash = null,
  sequence = 0,
} = {}) {
  const issuedAt = new Date().toISOString();
  const profileHash = `sha256:${crypto.randomBytes(32).toString('hex')}`;
  const contextHash = `sha256:${crypto.randomBytes(32).toString('hex')}`;
  const decisionEvidence = {
    context: {
      action_hash: action.actionHash,
      decision: 'approved',
      approver: fixture.approverId,
      issued_at: issuedAt,
      mobile_binding: {
        profile_hash: profileHash,
        device_key_id: fixture.deviceKeyId,
      },
    },
    signoff: {
      key_class: 'A',
      approver_key_id: fixture.deviceKeyId,
      context_hash: contextHash,
      signed_at: issuedAt,
      webauthn: {
        authenticator_data: 'YQ',
        client_data_json: 'Yg',
        signature: 'Yw',
      },
    },
  };
  const body = {
    action_hash: action.actionHash,
    approver_id: fixture.approverId,
    challenge_id: action.challengeId,
    context_hash: contextHash,
    decision: 'approved',
    decision_evidence: decisionEvidence,
    device_key_id: fixture.deviceKeyId,
    event_type: 'mobile.ceremony.decision',
    prev_hash: previousHash ?? 'genesis',
    profile_hash: profileHash,
    record_id: `mar_${crypto.randomBytes(16).toString('hex')}`,
    seq: sequence,
    session_id: fixture.sessionId,
    verdict: 'verified',
  };
  const canonicalBody = JSON.stringify(body);
  const hash = crypto.createHash('sha256').update(canonicalBody, 'utf8').digest('hex');
  return {
    decisionEvidence,
    canonicalBody,
    record: { ...body, hash },
    hash,
  };
}

async function commitMobileDecisionAsServiceRole(fixture, action, commit) {
  const client = await getPool().connect();
  try {
    await client.query('SET ROLE service_role');
    return await client.query(
      `SELECT public.commit_mobile_action_decision(
         $1, $2::uuid, $3, $4, 'approved', 'verified', $5::jsonb,
         $6, $7::jsonb, $8
       ) AS result`,
      [
        fixture.entityRef,
        fixture.sessionId,
        action.challengeId,
        action.actionHash,
        JSON.stringify(commit.decisionEvidence),
        commit.record.prev_hash === 'genesis' ? null : commit.record.prev_hash,
        JSON.stringify(commit.record),
        commit.canonicalBody,
      ],
    );
  } finally {
    await client.query('RESET ROLE').catch(() => {});
    client.release();
  }
}

async function issueTenantApiKeyAsServiceRole(permission, suffix = 0) {
  const client = await getPool().connect();
  try {
    await client.query('SET ROLE service_role');
    return await client.query(
      `SELECT public.issue_tenant_api_key_audited(
         $1::uuid, 'production', $2::text, 'ept_live', $3::text,
         ARRAY[$4::text], now() + interval '30 days', $5::text
       ) AS api_key`,
      [
        ROLLOUT_TENANT_ID,
        suffix.toString(16).padStart(64, '0'),
        `${permission}-${suffix}`,
        permission,
        `entity:receipt-integration-${suffix}`,
      ],
    );
  } finally {
    await client.query('RESET ROLE').catch(() => {});
    client.release();
  }
}

// ---------------------------------------------------------------------------
// ── 0. Tenant API-key receipt capabilities are exactly mintable ─────────────
// ---------------------------------------------------------------------------

describe.skipIf(SKIP)('DB invariant: receipt API-key grants are exact', () => {
  it.each([
    ['receipt.read', 1],
    ['receipt.evidence', 2],
    ['receipt.consume', 3],
    ['receipt.execute', 4],
  ])('audits issuance of the %s capability', async (permission, suffix) => {
    const result = await issueTenantApiKeyAsServiceRole(permission, suffix);

    expect(result.rows[0].api_key.permissions).toEqual([permission]);
    const { rows } = await query(
      `SELECT actor_id, after_state -> 'permissions' AS permissions
       FROM audit_events
       WHERE event_type = 'cloud.tenant_api_key.issued'
         AND target_id = $1`,
      [result.rows[0].api_key.key_id],
    );
    expect(rows).toEqual([{
      actor_id: `entity:receipt-integration-${suffix}`,
      permissions: [permission],
    }]);
  });

  it('rejects a broader receipt-prefixed permission', async () => {
    await expect(issueTenantApiKeyAsServiceRole('receipt.admin', 5))
      .rejects.toThrow('invalid_tenant_api_key_issue');
  });
});

// ---------------------------------------------------------------------------
// ── 1. Receipts: append-only ─────────────────────────────────────────────────
// ---------------------------------------------------------------------------

describe.skipIf(SKIP)('DB invariant: receipts are append-only', () => {
  it('allows inserting a receipt', async () => {
    await insertEntity('ent-receipt-1');
    const row = await insertReceipt('ent-receipt-1');
    expect(row.id).toBeTruthy();
  });

  it('blocks UPDATE on a receipt', async () => {
    await insertEntity('ent-receipt-2');
    const { id } = await insertReceipt('ent-receipt-2');
    await expect(
      query(`UPDATE receipts SET composite_score = 99 WHERE id = $1`, [id]),
    ).rejects.toThrow('RECEIPT_IMMUTABLE');
  });

  it('blocks DELETE on a receipt', async () => {
    await insertEntity('ent-receipt-3');
    const { id } = await insertReceipt('ent-receipt-3');
    await expect(
      query(`DELETE FROM receipts WHERE id = $1`, [id]),
    ).rejects.toThrow('RECEIPT_IMMUTABLE');
  });

  it('allows multiple receipts for the same entity (ledger grows)', async () => {
    await insertEntity('ent-receipt-4');
    const first = await insertReceipt('ent-receipt-4', 'submitter-a');
    const second = await insertReceipt('ent-receipt-4', 'submitter-b', first.receipt_hash);
    await insertReceipt('ent-receipt-4', 'submitter-c', second.receipt_hash);
    const { rows } = await query(
      `SELECT count(*) FROM receipts WHERE entity_id = $1`, ['ent-receipt-4'],
    );
    expect(parseInt(rows[0].count, 10)).toBe(3);
  });

  it('refuses two children of the same receipt-chain predecessor', async () => {
    await insertEntity('ent-receipt-fork');
    const root = await insertReceipt('ent-receipt-fork', 'submitter-a');
    await insertReceipt('ent-receipt-fork', 'submitter-b', root.receipt_hash);
    await expect(
      insertReceipt('ent-receipt-fork', 'submitter-c', root.receipt_hash),
    ).rejects.toThrow(/idx_receipts_single_child_per_parent|duplicate key/i);
  });
});

// ---------------------------------------------------------------------------
// ── 2. Handshake bindings: consumption is irreversible ───────────────────────
// ---------------------------------------------------------------------------

describe.skipIf(SKIP)('DB invariant: handshake consumption is irreversible', () => {
  it('allows marking a binding as consumed', async () => {
    const hId = await insertHandshake();
    const bId = await insertBinding(hId);
    await query(
      `UPDATE handshake_bindings SET consumed_at = now() WHERE id = $1`, [bId],
    );
    const { rows } = await query(
      `SELECT consumed_at FROM handshake_bindings WHERE id = $1`, [bId],
    );
    expect(rows[0].consumed_at).toBeTruthy();
  });

  it('blocks clearing consumed_at once set', async () => {
    const hId = await insertHandshake();
    const bId = await insertBinding(hId, { consumed: true });
    await expect(
      query(`UPDATE handshake_bindings SET consumed_at = NULL WHERE id = $1`, [bId]),
    ).rejects.toThrow('CONSUMPTION_IRREVERSIBLE');
  });

  it('allows updating non-consumed fields on an unconsumed binding', async () => {
    const hId = await insertHandshake();
    const bId = await insertBinding(hId);
    await expect(
      query(
        `UPDATE handshake_bindings SET payload_hash = 'updated-hash' WHERE id = $1`,
        [bId],
      ),
    ).resolves.not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// ── 3. Signoff consumptions: insert-or-fail (consume-once) ───────────────────
// ---------------------------------------------------------------------------

describe.skipIf(SKIP)('DB invariant: signoff attestations are consumed at most once', () => {
  it('allows consuming an attestation', async () => {
    const hId = await insertHandshake();
    const bId = await insertBinding(hId);
    const cId = await insertChallenge(bId);
    const sId = await insertAttestation(cId, bId);

    const { rows } = await query(
      `INSERT INTO signoff_consumptions (signoff_id, binding_hash, execution_ref)
       VALUES ($1, $2, $3) RETURNING signoff_consumption_id`,
      [sId, 'bhash-xyz', 'exec-ref-1'],
    );
    expect(rows[0].signoff_consumption_id).toBeTruthy();
  });

  it('blocks a second consumption of the same attestation', async () => {
    const hId = await insertHandshake();
    const bId = await insertBinding(hId);
    const cId = await insertChallenge(bId);
    const sId = await insertAttestation(cId, bId);

    await query(
      `INSERT INTO signoff_consumptions (signoff_id, binding_hash, execution_ref)
       VALUES ($1, $2, $3)`,
      [sId, 'bhash-xyz', 'exec-ref-first'],
    );

    await expect(
      query(
        `INSERT INTO signoff_consumptions (signoff_id, binding_hash, execution_ref)
         VALUES ($1, $2, $3)`,
        [sId, 'bhash-xyz', 'exec-ref-replay'],
      ),
    ).rejects.toThrow(/unique|duplicate/i);
  });

  it('two different attestations can be consumed independently', async () => {
    const hId1 = await insertHandshake();
    const bId1 = await insertBinding(hId1);
    const cId1 = await insertChallenge(bId1);
    const sId1 = await insertAttestation(cId1, bId1);

    const hId2 = await insertHandshake();
    const bId2 = await insertBinding(hId2);
    const cId2 = await insertChallenge(bId2);
    const sId2 = await insertAttestation(cId2, bId2);

    await query(
      `INSERT INTO signoff_consumptions (signoff_id, binding_hash, execution_ref)
       VALUES ($1, $2, $3)`, [sId1, 'bhash-xyz', 'exec-1'],
    );
    await query(
      `INSERT INTO signoff_consumptions (signoff_id, binding_hash, execution_ref)
       VALUES ($1, $2, $3)`, [sId2, 'bhash-xyz', 'exec-2'],
    );

    const { rows } = await query(`SELECT count(*) FROM signoff_consumptions`);
    expect(parseInt(rows[0].count, 10)).toBeGreaterThanOrEqual(2);
  });
});

// ---------------------------------------------------------------------------
// ── 4. Signoff lifecycle state machines and immutable trust fields ──────────
// ---------------------------------------------------------------------------

describe.skipIf(SKIP)('DB invariant: signoff lifecycle permits only exact state edges', () => {
  it('allows forward transitions: issued → viewed → approved', async () => {
    const hId = await insertHandshake();
    const bId = await insertBinding(hId);
    const cId = await insertChallenge(bId);

    await query(
      `UPDATE signoff_challenges SET status = 'challenge_viewed' WHERE challenge_id = $1`,
      [cId],
    );
    await query(
      `UPDATE signoff_challenges
       SET status = 'approved',
           metadata = metadata || pg_catalog.jsonb_build_object(
             'approved_at', pg_catalog.transaction_timestamp()
           )
       WHERE challenge_id = $1`,
      [cId],
    );

    const { rows } = await query(
      `SELECT status FROM signoff_challenges WHERE challenge_id = $1`, [cId],
    );
    expect(rows[0].status).toBe('approved');
  });

  it('blocks backward transition: approved → challenge_issued', async () => {
    const hId = await insertHandshake();
    const bId = await insertBinding(hId);
    const cId = await insertChallenge(bId);

    await query(
      `UPDATE signoff_challenges
       SET status = 'approved',
           metadata = metadata || pg_catalog.jsonb_build_object(
             'approved_at', pg_catalog.transaction_timestamp()
           )
       WHERE challenge_id = $1`, [cId],
    );

    await expect(
      query(
        `UPDATE signoff_challenges SET status = 'challenge_issued' WHERE challenge_id = $1`,
        [cId],
      ),
    ).rejects.toThrow('SIGNOFF_CHALLENGE_TRANSITION_INVALID');
  });

  it('blocks backward transition: consumed → approved', async () => {
    const hId = await insertHandshake();
    const bId = await insertBinding(hId);
    const cId = await insertChallenge(bId);

    await query(
      `UPDATE signoff_challenges
       SET status = 'approved',
           metadata = metadata || pg_catalog.jsonb_build_object(
             'approved_at', pg_catalog.transaction_timestamp()
           )
       WHERE challenge_id = $1`, [cId],
    );
    await query(
      `UPDATE signoff_challenges
       SET status = 'consumed', consumed_at = pg_catalog.transaction_timestamp()
       WHERE challenge_id = $1`, [cId],
    );

    await expect(
      query(
        `UPDATE signoff_challenges SET status = 'approved' WHERE challenge_id = $1`,
        [cId],
      ),
    ).rejects.toThrow('SIGNOFF_CHALLENGE_TRANSITION_INVALID');
  });

  it('allows terminal denial: issued → denied', async () => {
    const hId = await insertHandshake();
    const bId = await insertBinding(hId);
    const cId = await insertChallenge(bId);

    await query(
      `UPDATE signoff_challenges
       SET status = 'denied',
           metadata = metadata || pg_catalog.jsonb_build_object(
             'denied_at', pg_catalog.transaction_timestamp(),
             'denial_reason', 'accountable actor refused'
           )
       WHERE challenge_id = $1`, [cId],
    );
    const { rows } = await query(
      `SELECT status FROM signoff_challenges WHERE challenge_id = $1`, [cId],
    );
    expect(rows[0].status).toBe('denied');
  });

  it('allows terminal revocation: issued → revoked', async () => {
    const hId = await insertHandshake();
    const bId = await insertBinding(hId);
    const cId = await insertChallenge(bId);

    await query(
      `UPDATE signoff_challenges
       SET status = 'revoked',
           revoked_at = pg_catalog.transaction_timestamp(),
           revocation_reason = 'authority withdrawn'
       WHERE challenge_id = $1`, [cId],
    );
    const { rows } = await query(
      `SELECT status FROM signoff_challenges WHERE challenge_id = $1`, [cId],
    );
    expect(rows[0].status).toBe('revoked');
  });

  it('allows expiry: issued → expired', async () => {
    const hId = await insertHandshake();
    const bId = await insertBinding(hId);
    const cId = await insertChallenge(bId);

    await query(
      `UPDATE signoff_challenges SET status = 'expired' WHERE challenge_id = $1`, [cId],
    );
    const { rows } = await query(
      `SELECT status FROM signoff_challenges WHERE challenge_id = $1`, [cId],
    );
    expect(rows[0].status).toBe('expired');
  });

  it('blocks backward transition: approved → challenge_viewed', async () => {
    const hId = await insertHandshake();
    const bId = await insertBinding(hId);
    const cId = await insertChallenge(bId);

    await query(
      `UPDATE signoff_challenges
       SET status = 'approved',
           metadata = metadata || pg_catalog.jsonb_build_object(
             'approved_at', pg_catalog.transaction_timestamp()
           )
       WHERE challenge_id = $1`, [cId],
    );
    await expect(
      query(
        `UPDATE signoff_challenges SET status = 'challenge_viewed' WHERE challenge_id = $1`,
        [cId],
      ),
    ).rejects.toThrow('SIGNOFF_CHALLENGE_TRANSITION_INVALID');
  });

  it('rejects pending-to-consumed and mutually exclusive terminal transitions', async () => {
    const issuedBinding = await insertBinding(await insertHandshake());
    const issuedChallenge = await insertChallenge(issuedBinding);
    await expect(query(
      `UPDATE signoff_challenges
       SET status = 'consumed', consumed_at = pg_catalog.transaction_timestamp()
       WHERE challenge_id = $1`,
      [issuedChallenge],
    )).rejects.toThrow('SIGNOFF_CHALLENGE_TRANSITION_INVALID');

    const deniedBinding = await insertBinding(await insertHandshake());
    const deniedChallenge = await insertChallenge(deniedBinding);
    await query(
      `UPDATE signoff_challenges
       SET status = 'denied',
           metadata = metadata || pg_catalog.jsonb_build_object(
             'denied_at', pg_catalog.transaction_timestamp(),
             'denial_reason', 'refused'
           )
       WHERE challenge_id = $1`,
      [deniedChallenge],
    );
    await expect(query(
      `UPDATE signoff_challenges
       SET status = 'approved',
           metadata = metadata || pg_catalog.jsonb_build_object(
             'approved_at', pg_catalog.transaction_timestamp()
           )
       WHERE challenge_id = $1`,
      [deniedChallenge],
    )).rejects.toThrow('SIGNOFF_CHALLENGE_TRANSITION_INVALID');

    const approvedBinding = await insertBinding(await insertHandshake());
    const approvedChallenge = await insertChallenge(approvedBinding);
    await query(
      `UPDATE signoff_challenges
       SET status = 'approved',
           metadata = metadata || pg_catalog.jsonb_build_object(
             'approved_at', pg_catalog.transaction_timestamp()
           )
       WHERE challenge_id = $1`,
      [approvedChallenge],
    );
    for (const terminal of ['denied', 'revoked']) {
      await expect(query(
        `UPDATE signoff_challenges SET status = $2 WHERE challenge_id = $1`,
        [approvedChallenge, terminal],
      )).rejects.toThrow('SIGNOFF_CHALLENGE_TRANSITION_INVALID');
    }
  });

  it('makes challenge and attestation authority facts immutable', async () => {
    const bindingId = await insertBinding(await insertHandshake());
    const challengeId = await insertChallenge(bindingId);
    await expect(query(
      `UPDATE signoff_challenges
       SET accountable_actor_ref = 'entity-attacker'
       WHERE challenge_id = $1`,
      [challengeId],
    )).rejects.toThrow('SIGNOFF_CHALLENGE_TRUST_FIELDS_IMMUTABLE');

    const signoffId = await insertAttestation(challengeId, bindingId);
    await expect(query(
      `UPDATE signoff_attestations
       SET auth_method = 'out_of_band'
       WHERE signoff_id = $1`,
      [signoffId],
    )).rejects.toThrow('SIGNOFF_ATTESTATION_TRUST_FIELDS_IMMUTABLE');

    await expect(query(
      `DELETE FROM signoff_attestations WHERE signoff_id = $1`,
      [signoffId],
    )).rejects.toThrow('SIGNOFF_ATTESTATION_DELETE_FORBIDDEN');
    await expect(query(
      `DELETE FROM signoff_challenges WHERE challenge_id = $1`,
      [challengeId],
    )).rejects.toThrow('SIGNOFF_CHALLENGE_DELETE_FORBIDDEN');
  });

  it('does not allow attestation terminal states to switch', async () => {
    const bindingId = await insertBinding(await insertHandshake());
    const challengeId = await insertChallenge(bindingId);
    const expiredSignoffId = await insertAttestation(challengeId, bindingId);
    await query(
      `UPDATE signoff_attestations SET status = 'expired' WHERE signoff_id = $1`,
      [expiredSignoffId],
    );
    await expect(query(
      `UPDATE signoff_attestations
       SET status = 'revoked', revoked_at = pg_catalog.transaction_timestamp(),
           revocation_reason = 'late revocation'
       WHERE signoff_id = $1`,
      [expiredSignoffId],
    )).rejects.toThrow('SIGNOFF_ATTESTATION_TRANSITION_INVALID');

    const revokedSignoffId = await insertAttestation(challengeId, bindingId);
    await query(
      `UPDATE signoff_attestations
       SET status = 'revoked', revoked_at = pg_catalog.transaction_timestamp(),
           revocation_reason = 'withdrawn'
       WHERE signoff_id = $1`,
      [revokedSignoffId],
    );
    await expect(query(
      `UPDATE signoff_attestations SET status = 'expired' WHERE signoff_id = $1`,
      [revokedSignoffId],
    )).rejects.toThrow('SIGNOFF_ATTESTATION_TRANSITION_INVALID');
  });

  it('removes direct service-role lifecycle writes while retaining reads and RPC execution', async () => {
    const { rows } = await query(
      `SELECT
         pg_catalog.has_table_privilege('service_role', 'public.signoff_challenges', 'SELECT') AS challenge_select,
         pg_catalog.has_table_privilege('service_role', 'public.signoff_challenges', 'INSERT') AS challenge_insert,
         pg_catalog.has_table_privilege('service_role', 'public.signoff_challenges', 'UPDATE') AS challenge_update,
         pg_catalog.has_table_privilege('service_role', 'public.signoff_attestations', 'INSERT') AS attestation_insert,
         pg_catalog.has_table_privilege('service_role', 'public.signoff_attestations', 'UPDATE') AS attestation_update,
         pg_catalog.has_table_privilege('service_role', 'public.signoff_consumptions', 'INSERT') AS consumption_insert,
         pg_catalog.has_function_privilege(
           'service_role',
           'public.issue_challenge_atomic(uuid,uuid,text,text,timestamptz,jsonb)',
           'EXECUTE'
         ) AS issue_execute`,
    );
    expect(rows[0]).toEqual({
      challenge_select: true,
      challenge_insert: false,
      challenge_update: false,
      attestation_insert: false,
      attestation_update: false,
      consumption_insert: false,
      issue_execute: true,
    });
  });
});

// ---------------------------------------------------------------------------
// ── 5. Signoff lifecycle transitions are serialized under row locks ────────
// ---------------------------------------------------------------------------

describe.skipIf(SKIP)('DB invariant: competing signoff transitions are atomic', () => {
  async function pendingChallenge({
    challengeExpiresAt = new Date(Date.now() + 10 * 60 * 1000),
  } = {}) {
    const handshakeId = await insertHandshake();
    const bindingId = await insertBinding(handshakeId, { verificationFinalized: true });
    const challengeId = await insertChallenge(bindingId, {
      expiresAt: challengeExpiresAt,
    });
    return { handshakeId, bindingId, challengeId };
  }

  async function approvedAttestation({
    expiresAt = new Date(Date.now() + 4 * 60 * 1000),
  } = {}) {
    const ids = await pendingChallenge({ challengeExpiresAt: expiresAt });
    const signoffId = crypto.randomUUID();
    const ceremonyEvidenceId = await insertCeremonyEvidence(ids.challengeId);
    const { rows } = await query(
      `SELECT public.approve_attestation_atomic(
         $1::uuid, $2::uuid, $3::uuid, 'bhash-xyz', 'entity-alice',
         'passkey', 'substantial', 'web', $5::timestamptz,
         'attestation-hash', pg_catalog.jsonb_build_object(
           'ceremony_evidence_id', $4::text
         )
       ) AS result`,
      [signoffId, ids.challengeId, ids.bindingId, ceremonyEvidenceId, expiresAt],
    );
    expect(rows[0].result.status).toBe('approved');
    return { ...ids, signoffId };
  }

  it('atomically expires a due challenge and records exactly one canonical event', async () => {
    const handshakeId = await insertHandshake();
    const bindingId = await insertBinding(handshakeId, { verificationFinalized: true });
    const challengeId = await insertChallenge(bindingId, {
      expiresAt: new Date(Date.now() - 1_000),
    });

    const { rows: expired } = await query(
      `SELECT public.expire_challenge_atomic($1::uuid, 'system') AS result`,
      [challengeId],
    );
    expect(expired[0].result.status).toBe('expired');

    const { rows } = await query(
      `SELECT
         (SELECT status FROM signoff_challenges WHERE challenge_id = $1) AS status,
         (SELECT count(*)::int FROM signoff_events
            WHERE challenge_id = $1 AND event_type = 'challenge_expired') AS events,
         (SELECT actor_entity_ref FROM signoff_events
            WHERE challenge_id = $1 AND event_type = 'challenge_expired') AS actor`,
      [challengeId],
    );
    expect(rows[0]).toEqual({ status: 'expired', events: 1, actor: 'system' });

    await expect(query(
      `SELECT public.expire_challenge_atomic($1::uuid, 'system')`,
      [challengeId],
    )).rejects.toThrow('SIGNOFF_CHALLENGE_NOT_EXPIRABLE');
    const { rows: replay } = await query(
      `SELECT count(*)::int AS count FROM signoff_events
       WHERE challenge_id = $1 AND event_type = 'challenge_expired'`,
      [challengeId],
    );
    expect(replay[0].count).toBe(1);
  });

  it('refuses premature challenge expiry without changing state or writing an event', async () => {
    const bindingId = await insertBinding(await insertHandshake(), {
      verificationFinalized: true,
    });
    const challengeId = await insertChallenge(bindingId);

    await expect(query(
      `SELECT public.expire_challenge_atomic($1::uuid, 'system')`,
      [challengeId],
    )).rejects.toThrow('SIGNOFF_CHALLENGE_NOT_EXPIRED');

    const { rows } = await query(
      `SELECT
         (SELECT status FROM signoff_challenges WHERE challenge_id = $1) AS status,
         (SELECT count(*)::int FROM signoff_events
            WHERE challenge_id = $1 AND event_type = 'challenge_expired') AS events`,
      [challengeId],
    );
    expect(rows[0]).toEqual({ status: 'challenge_issued', events: 0 });
  });

  it('atomically expires a due attestation while preserving the approved challenge history', async () => {
    const bindingId = await insertBinding(await insertHandshake(), {
      verificationFinalized: true,
    });
    const challengeId = await insertChallenge(bindingId);
    await query(
      `UPDATE signoff_challenges
       SET status = 'approved',
           metadata = metadata || pg_catalog.jsonb_build_object(
             'approved_at', pg_catalog.transaction_timestamp()
           )
       WHERE challenge_id = $1`,
      [challengeId],
    );
    const signoffId = await insertAttestation(challengeId, bindingId, {
      expiresAt: new Date(Date.now() - 1_000),
    });

    const { rows: expired } = await query(
      `SELECT public.expire_attestation_atomic($1::uuid, 'system') AS result`,
      [signoffId],
    );
    expect(expired[0].result.status).toBe('expired');

    const { rows } = await query(
      `SELECT
         (SELECT status FROM signoff_attestations WHERE signoff_id = $1) AS status,
         (SELECT status FROM signoff_challenges WHERE challenge_id = $2) AS challenge_status,
         (SELECT count(*)::int FROM signoff_events
            WHERE signoff_id = $1 AND event_type = 'signoff_expired') AS events,
         (SELECT actor_entity_ref FROM signoff_events
            WHERE signoff_id = $1 AND event_type = 'signoff_expired') AS actor`,
      [signoffId, challengeId],
    );
    expect(rows[0]).toEqual({
      status: 'expired',
      challenge_status: 'approved',
      events: 1,
      actor: 'system',
    });

    await expect(query(
      `SELECT public.expire_attestation_atomic($1::uuid, 'system')`,
      [signoffId],
    )).rejects.toThrow('SIGNOFF_ATTESTATION_NOT_EXPIRABLE');
  });

  it('refuses premature attestation expiry without changing state or writing an event', async () => {
    const bindingId = await insertBinding(await insertHandshake(), {
      verificationFinalized: true,
    });
    const challengeId = await insertChallenge(bindingId);
    await query(
      `UPDATE signoff_challenges
       SET status = 'approved',
           metadata = metadata || pg_catalog.jsonb_build_object(
             'approved_at', pg_catalog.transaction_timestamp()
           )
       WHERE challenge_id = $1`,
      [challengeId],
    );
    const signoffId = await insertAttestation(challengeId, bindingId);

    await expect(query(
      `SELECT public.expire_attestation_atomic($1::uuid, 'system')`,
      [signoffId],
    )).rejects.toThrow('SIGNOFF_ATTESTATION_NOT_EXPIRED');

    const { rows } = await query(
      `SELECT
         (SELECT status FROM signoff_attestations WHERE signoff_id = $1) AS status,
         (SELECT count(*)::int FROM signoff_events
            WHERE signoff_id = $1 AND event_type = 'signoff_expired') AS events`,
      [signoffId],
    );
    expect(rows[0]).toEqual({ status: 'approved', events: 0 });
  });

  it('rolls both expiry state transitions back when the canonical event cannot be written', async () => {
    const challengeBindingId = await insertBinding(await insertHandshake(), {
      verificationFinalized: true,
    });
    const challengeId = await insertChallenge(challengeBindingId, {
      expiresAt: new Date(Date.now() - 1_000),
    });

    const attestationBindingId = await insertBinding(await insertHandshake(), {
      verificationFinalized: true,
    });
    const attestationChallengeId = await insertChallenge(attestationBindingId);
    await query(
      `UPDATE signoff_challenges
       SET status = 'approved',
           metadata = metadata || pg_catalog.jsonb_build_object(
             'approved_at', pg_catalog.transaction_timestamp()
           )
       WHERE challenge_id = $1`,
      [attestationChallengeId],
    );
    const signoffId = await insertAttestation(
      attestationChallengeId,
      attestationBindingId,
      { expiresAt: new Date(Date.now() - 1_000) },
    );

    await query(`
      CREATE OR REPLACE FUNCTION reject_signoff_expiry_event_for_test()
      RETURNS trigger LANGUAGE plpgsql AS $test$
      BEGIN
        IF NEW.event_type IN ('challenge_expired', 'signoff_expired') THEN
          RAISE EXCEPTION 'TEST_EXPIRY_EVENT_REJECTED';
        END IF;
        RETURN NEW;
      END;
      $test$;
      CREATE TRIGGER reject_signoff_expiry_event_for_test
        BEFORE INSERT ON signoff_events
        FOR EACH ROW EXECUTE FUNCTION reject_signoff_expiry_event_for_test();
    `);
    try {
      await expect(query(
        `SELECT public.expire_challenge_atomic($1::uuid, 'system')`,
        [challengeId],
      )).rejects.toThrow('TEST_EXPIRY_EVENT_REJECTED');
      await expect(query(
        `SELECT public.expire_attestation_atomic($1::uuid, 'system')`,
        [signoffId],
      )).rejects.toThrow('TEST_EXPIRY_EVENT_REJECTED');

      const { rows } = await query(
        `SELECT
           (SELECT status FROM signoff_challenges WHERE challenge_id = $1) AS challenge_status,
           (SELECT status FROM signoff_attestations WHERE signoff_id = $2) AS attestation_status,
           (SELECT count(*)::int FROM signoff_events
              WHERE challenge_id = $1 AND event_type = 'challenge_expired') AS challenge_events,
           (SELECT count(*)::int FROM signoff_events
              WHERE signoff_id = $2 AND event_type = 'signoff_expired') AS attestation_events`,
        [challengeId, signoffId],
      );
      expect(rows[0]).toEqual({
        challenge_status: 'challenge_issued',
        attestation_status: 'approved',
        challenge_events: 0,
        attestation_events: 0,
      });
    } finally {
      await query(`DROP TRIGGER IF EXISTS reject_signoff_expiry_event_for_test ON signoff_events`);
      await query(`DROP FUNCTION IF EXISTS reject_signoff_expiry_event_for_test()`);
    }
  });

  it('matches the application policy hash and prevents in-place mutation of a pinned version', async () => {
    const { rows: hashed } = await query(
      `SELECT public.signoff_policy_rules_hash($1::jsonb) AS policy_hash`,
      [JSON.stringify(SIGNOFF_POLICY_RULES)],
    );
    expect(hashed[0].policy_hash).toBe(SIGNOFF_POLICY_HASH);

    await insertHandshake();
    await expect(query(
      `UPDATE handshake_policies
       SET rules = pg_catalog.jsonb_set(
         rules,
         '{accountable_signoff,required_assurance}',
         '"low"'::jsonb
       )
       WHERE policy_id = $1`,
      [SIGNOFF_POLICY_ID],
    )).rejects.toThrow('SIGNOFF_PINNED_POLICY_IMMUTABLE');

    const { rows } = await query(
      `SELECT rules FROM handshake_policies WHERE policy_id = $1`,
      [SIGNOFF_POLICY_ID],
    );
    expect(rows[0].rules).toEqual(SIGNOFF_POLICY_RULES);
  });

  it('derives actor, policy, assurance, methods, authority, and TTL from authoritative rows', async () => {
    const handshakeId = await insertHandshake();
    const bindingId = await insertBinding(handshakeId, { verificationFinalized: true });
    const challengeId = crypto.randomUUID();
    const { rows } = await query(
      `SELECT public.issue_challenge_atomic(
         $1::uuid, $2::uuid, 'bhash-xyz', 'entity-issuer',
         now() + interval '30 minutes',
         '{"accountableActorRef":"entity-attacker","requiredAssurance":"low","allowedMethods":["out_of_band"]}'::jsonb
       ) AS challenge`,
      [challengeId, handshakeId],
    );

    expect(rows[0].challenge).toMatchObject({
      challenge_id: challengeId,
      handshake_id: bindingId,
      binding_hash: 'bhash-xyz',
      accountable_actor_ref: 'entity-alice',
      signoff_policy_id: SIGNOFF_POLICY_ID,
      signoff_policy_hash: SIGNOFF_POLICY_HASH,
      required_assurance: 'substantial',
      allowed_methods: ['passkey'],
      required_authority_class: SIGNOFF_AUTHORITY_CLASS,
      authority_organization_id: SIGNOFF_ORGANIZATION_ID,
      authority_id: SIGNOFF_AUTHORITY_ID,
      status: 'challenge_issued',
    });
    expect(new Date(rows[0].challenge.expires_at).getTime())
      .toBeLessThanOrEqual(Date.now() + 301_000);

    const { rows: events } = await query(
      `SELECT detail FROM signoff_events
       WHERE challenge_id = $1 AND event_type = 'challenge_issued'`,
      [challengeId],
    );
    expect(events[0].detail).toMatchObject({
      accountable_actor_ref: 'entity-alice',
      signoff_policy_id: SIGNOFF_POLICY_ID,
      signoff_policy_hash: SIGNOFF_POLICY_HASH,
      required_assurance: 'substantial',
      allowed_methods: ['passkey'],
      required_authority_class: SIGNOFF_AUTHORITY_CLASS,
      authority_id: SIGNOFF_AUTHORITY_ID,
    });
  });

  it('refuses a legacy hash drift and a malformed authoritative signoff block', async () => {
    const driftedHash = 'f'.repeat(64);
    const driftedHandshakeId = await insertHandshake({ policyHash: driftedHash });
    await insertBinding(driftedHandshakeId, {
      verificationFinalized: true,
      policyHash: driftedHash,
    });

    await expect(query(
      `SELECT public.issue_challenge_atomic(
         $1::uuid, $2::uuid, 'bhash-xyz', 'entity-issuer',
         now() + interval '5 minutes', '{}'::jsonb
       )`,
      [crypto.randomUUID(), driftedHandshakeId],
    )).rejects.toThrow('SIGNOFF_POLICY_HASH_MISMATCH');

    const malformedPolicyId = crypto.randomUUID();
    const malformedRules = { accountable_signoff: { required: false } };
    const malformedHash = crypto.createHash('sha256')
      .update(JSON.stringify(canonicalPolicy(malformedRules)), 'utf8')
      .digest('hex');
    await query(
      `INSERT INTO handshake_policies
         (policy_id, policy_key, version, mode, status, rules)
       VALUES ($1, $2, 1, 'mutual', 'active', $3::jsonb)`,
      [malformedPolicyId, `malformed-${malformedPolicyId}`, JSON.stringify(malformedRules)],
    );
    const malformedHandshakeId = await insertHandshake({
      policyId: malformedPolicyId,
      policyHash: malformedHash,
    });
    await insertBinding(malformedHandshakeId, {
      verificationFinalized: true,
      policyHash: malformedHash,
    });

    await expect(query(
      `SELECT public.issue_challenge_atomic(
         $1::uuid, $2::uuid, 'bhash-xyz', 'entity-issuer',
         now() + interval '5 minutes', '{}'::jsonb
       )`,
      [crypto.randomUUID(), malformedHandshakeId],
    )).rejects.toThrow('SIGNOFF_POLICY_BLOCK_INVALID');
  });

  it('requires fresh one-time ceremony evidence and ignores forged method or assurance claims', async () => {
    const { bindingId, challengeId } = await pendingChallenge();
    const missingEvidenceSignoffId = crypto.randomUUID();
    await expect(query(
      `SELECT public.approve_attestation_atomic(
         $1::uuid, $2::uuid, $3::uuid, 'bhash-xyz', 'entity-alice',
         'passkey', 'high', 'web', now() + interval '4 minutes',
         'caller-claimed-passkey', '{}'::jsonb
       )`,
      [missingEvidenceSignoffId, challengeId, bindingId],
    )).rejects.toThrow('SIGNOFF_CEREMONY_EVIDENCE_REQUIRED');

    const ceremonyEvidenceId = await insertCeremonyEvidence(challengeId);
    await expect(query(
      `SELECT public.approve_attestation_atomic(
         $1::uuid, $2::uuid, $3::uuid, 'bhash-xyz', 'entity-alice',
         'out_of_band', 'low', 'web', now() + interval '4 minutes',
         'forged-weaker-claims', pg_catalog.jsonb_build_object(
           'ceremony_evidence_id', $4::text
         )
       )`,
      [crypto.randomUUID(), challengeId, bindingId, ceremonyEvidenceId],
    )).rejects.toThrow('SIGNOFF_CHALLENGE_METHOD_NOT_ALLOWED');

    await expect(query(
      `SELECT public.approve_attestation_atomic(
         $1::uuid, $2::uuid, $3::uuid, 'bhash-xyz', 'entity-alice',
         'passkey', 'low', 'web', now() + interval '4 minutes',
         'forged-assurance', pg_catalog.jsonb_build_object(
           'ceremony_evidence_id', $4::text
         )
       )`,
      [crypto.randomUUID(), challengeId, bindingId, ceremonyEvidenceId],
    )).rejects.toThrow('SIGNOFF_CHALLENGE_ASSURANCE_INSUFFICIENT');

    const validSignoffId = crypto.randomUUID();
    const { rows } = await query(
      `SELECT public.approve_attestation_atomic(
         $1::uuid, $2::uuid, $3::uuid, 'bhash-xyz', 'entity-alice',
         'passkey', 'substantial', 'web', now() + interval '4 minutes',
         'server-bound-attestation', pg_catalog.jsonb_build_object(
           'ceremony_evidence_id', $4::text
         )
       ) AS attestation`,
      [validSignoffId, challengeId, bindingId, ceremonyEvidenceId],
    );
    expect(rows[0].attestation).toMatchObject({
      signoff_id: validSignoffId,
      human_entity_ref: 'entity-alice',
      auth_method: 'passkey',
      assurance_level: 'substantial',
      ceremony_evidence_id: ceremonyEvidenceId,
      status: 'approved',
    });
  });

  it('rechecks the current authority-class grant before approval', async () => {
    const { bindingId, challengeId } = await pendingChallenge();
    const ceremonyEvidenceId = await insertCeremonyEvidence(challengeId);
    try {
      await query(
        `UPDATE authorities
         SET status = 'revoked', revoked_at = now()
         WHERE authority_id = $1`,
        [SIGNOFF_AUTHORITY_ID],
      );

      await expect(query(
        `SELECT public.approve_attestation_atomic(
           $1::uuid, $2::uuid, $3::uuid, 'bhash-xyz', 'entity-alice',
           'passkey', 'substantial', 'web', now() + interval '4 minutes',
           'stale-authority-attestation', pg_catalog.jsonb_build_object(
             'ceremony_evidence_id', $4::text
           )
         )`,
        [crypto.randomUUID(), challengeId, bindingId, ceremonyEvidenceId],
      )).rejects.toThrow('SIGNOFF_AUTHORITY_INVALID_OR_REVOKED');

      const { rows } = await query(
        `SELECT
           (SELECT count(*)::int FROM signoff_attestations WHERE challenge_id = $1) AS attestations,
           (SELECT consumed_at IS NULL FROM signoff_ceremony_evidence WHERE evidence_id = $2) AS evidence_unused`,
        [challengeId, ceremonyEvidenceId],
      );
      expect(rows[0]).toEqual({ attestations: 0, evidence_unused: true });
    } finally {
      await query(
        `UPDATE authorities
         SET status = 'active', revoked_at = NULL
         WHERE authority_id = $1`,
        [SIGNOFF_AUTHORITY_ID],
      );
    }
  });

  it('rejects expired authority and clamps challenge expiry to its binding window', async () => {
    const handshakeId = await insertHandshake();
    const bindingId = await insertBinding(handshakeId, { verificationFinalized: true });
    const expiredChallengeId = crypto.randomUUID();
    await query(
      `UPDATE handshake_bindings SET expires_at = now() - interval '1 second' WHERE id = $1`,
      [bindingId],
    );

    await expect(query(
      `SELECT public.issue_challenge_atomic(
         $1::uuid, $2::uuid, 'bhash-xyz', 'entity-issuer',
         now() + interval '5 minutes', '{}'::jsonb
       )`,
      [expiredChallengeId, handshakeId],
    )).rejects.toThrow('SIGNOFF_BINDING_EXPIRED');

    await query(
      `UPDATE handshake_bindings SET expires_at = now() + interval '1 minute' WHERE id = $1`,
      [bindingId],
    );
    const { rows: clamped } = await query(
      `SELECT public.issue_challenge_atomic(
         $1::uuid, $2::uuid, 'bhash-xyz', 'entity-issuer',
         now() + interval '5 minutes', '{}'::jsonb
       ) AS result`,
      [crypto.randomUUID(), handshakeId],
    );
    expect(new Date(clamped[0].result.expires_at).getTime())
      .toBeLessThanOrEqual(Date.now() + 61_000);

    const { rows } = await query(
      `SELECT count(*)::int AS count FROM signoff_challenges WHERE challenge_id = $1`,
      [expiredChallengeId],
    );
    expect(rows[0].count).toBe(0);
  });

  it('requires verification finalization and rejects already-consumed downstream authority', async () => {
    const unfinalizedHandshakeId = await insertHandshake();
    const unfinalizedBindingId = await insertBinding(unfinalizedHandshakeId);

    await expect(query(
      `SELECT public.issue_challenge_atomic(
         $1::uuid, $2::uuid, 'bhash-xyz', 'entity-issuer',
         now() + interval '5 minutes', '{}'::jsonb
       )`,
      [crypto.randomUUID(), unfinalizedHandshakeId],
    )).rejects.toThrow('SIGNOFF_BINDING_NOT_VERIFICATION_FINALIZED');

    await query(
      `UPDATE handshake_bindings
       SET consumed_at = now(), consumed_for = 'unrelated:marker'
       WHERE id = $1`,
      [unfinalizedBindingId],
    );
    await expect(query(
      `SELECT public.issue_challenge_atomic(
         $1::uuid, $2::uuid, 'bhash-xyz', 'entity-issuer',
         now() + interval '5 minutes', '{}'::jsonb
       )`,
      [crypto.randomUUID(), unfinalizedHandshakeId],
    )).rejects.toThrow('SIGNOFF_BINDING_NOT_VERIFICATION_FINALIZED');

    const handshakeId = await insertHandshake();
    const bindingId = await insertBinding(handshakeId, { verificationFinalized: true });
    await query(
      `INSERT INTO handshake_consumptions
         (handshake_id, binding_hash, consumed_by_type, consumed_by_id)
       VALUES ($1, 'bhash-xyz', 'external_execution', 'already-consumed')`,
      [handshakeId],
    );

    await expect(query(
      `SELECT public.issue_challenge_atomic(
         $1::uuid, $2::uuid, 'bhash-xyz', 'entity-issuer',
         now() + interval '5 minutes', '{}'::jsonb
       )`,
      [crypto.randomUUID(), handshakeId],
    )).rejects.toThrow('SIGNOFF_AUTHORITY_ALREADY_CONSUMED');

    const challengeId = await insertChallenge(bindingId);
    await expect(query(
      `SELECT public.approve_attestation_atomic(
         $1::uuid, $2::uuid, $3::uuid, 'bhash-xyz', 'entity-alice',
         'passkey', 'substantial', 'web', now() + interval '5 minutes',
         'attestation-hash', '{}'::jsonb
       )`,
      [crypto.randomUUID(), challengeId, bindingId],
    )).rejects.toThrow('SIGNOFF_AUTHORITY_ALREADY_CONSUMED');

    await query(
      `DELETE FROM handshake_consumptions WHERE handshake_id = $1`,
      [handshakeId],
    );
  });

  it('rejects approval of a pre-existing challenge after its binding expires', async () => {
    const { bindingId, challengeId } = await pendingChallenge();
    await query(
      `UPDATE handshake_bindings SET expires_at = now() - interval '1 second' WHERE id = $1`,
      [bindingId],
    );

    await expect(query(
      `SELECT public.approve_attestation_atomic(
         $1::uuid, $2::uuid, $3::uuid, 'bhash-xyz', 'entity-alice',
         'passkey', 'substantial', 'web', now() + interval '5 minutes',
         'attestation-hash', '{}'::jsonb
       )`,
      [crypto.randomUUID(), challengeId, bindingId],
    )).rejects.toThrow('SIGNOFF_BINDING_EXPIRED');

    const { rows } = await query(
      `SELECT count(*)::int AS count FROM signoff_attestations WHERE challenge_id = $1`,
      [challengeId],
    );
    expect(rows[0].count).toBe(0);
  });

  it('rejects consumption of a legacy overlong challenge after its binding expires', async () => {
    const { bindingId, challengeId, signoffId } = await approvedAttestation();
    await query(
      `UPDATE handshake_bindings SET expires_at = now() - interval '1 second' WHERE id = $1`,
      [bindingId],
    );

    await expect(query(
      `SELECT public.consume_signoff_atomic(
         $1::text, 'bhash-xyz', 'execution-expired-binding',
         $2::text, $3::text, 'entity-alice'
       )`,
      [signoffId, bindingId, challengeId],
    )).rejects.toThrow('SIGNOFF_BINDING_EXPIRED');

    const { rows } = await query(
      `SELECT count(*)::int AS count FROM signoff_consumptions WHERE signoff_id = $1`,
      [signoffId],
    );
    expect(rows[0].count).toBe(0);
  });

  it('allows a verification-finalized handshake to be revoked before downstream consumption', async () => {
    const { handshakeId, bindingId } = await pendingChallenge();

    const { rows: revoked } = await query(
      `SELECT public.revoke_handshake_atomic(
         $1::uuid, 'verified authority withdrawn', 'entity-alice'
       ) AS result`,
      [handshakeId],
    );
    expect(revoked[0].result.status).toBe('revoked');

    const { rows } = await query(
      `SELECT
         (SELECT consumed_for FROM handshake_bindings WHERE id = $1) AS consumed_for,
         (SELECT count(*)::int FROM handshake_consumptions WHERE handshake_id = $2) AS consumptions`,
      [bindingId, handshakeId],
    );
    expect(rows[0]).toEqual({
      consumed_for: `handshake_verified:${handshakeId}`,
      consumptions: 0,
    });
  });

  it('serializes approval behind handshake revocation and rejects stale authority', async () => {
    const { handshakeId, bindingId, challengeId } = await pendingChallenge();
    const revoker = await getPool().connect();
    const approver = await getPool().connect();
    try {
      await revoker.query('BEGIN');
      await revoker.query(
        `SELECT public.revoke_handshake_atomic($1::uuid, 'authority withdrawn', 'entity-alice')`,
        [handshakeId],
      );

      const approval = expect(approver.query(
        `SELECT public.approve_attestation_atomic(
           $1::uuid, $2::uuid, $3::uuid, 'bhash-xyz', 'entity-alice',
           'passkey', 'substantial', 'web', now() + interval '5 minutes',
           'attestation-hash', '{}'::jsonb
         )`,
        [crypto.randomUUID(), challengeId, bindingId],
      )).rejects.toThrow('SIGNOFF_HANDSHAKE_NOT_VERIFIED');
      await waitForBlockedQuery('approve_attestation_atomic');
      await revoker.query('COMMIT');
      await approval;

      const { rows } = await query(
        `SELECT
           (SELECT status FROM handshakes WHERE handshake_id = $1) AS handshake_status,
           (SELECT count(*)::int FROM signoff_attestations WHERE challenge_id = $2) AS attestations`,
        [handshakeId, challengeId],
      );
      expect(rows[0]).toEqual({ handshake_status: 'revoked', attestations: 0 });
    } finally {
      await revoker.query('ROLLBACK').catch(() => {});
      revoker.release();
      approver.release();
    }
  });

  it('serializes signoff consumption behind handshake revocation with no partial burn', async () => {
    const { handshakeId, bindingId, challengeId, signoffId } = await approvedAttestation();
    const revoker = await getPool().connect();
    const consumer = await getPool().connect();
    try {
      await revoker.query('BEGIN');
      await revoker.query(
        `SELECT public.revoke_handshake_atomic($1::uuid, 'authority withdrawn', 'entity-alice')`,
        [handshakeId],
      );

      const consumption = expect(consumer.query(
        `SELECT public.consume_signoff_atomic(
           $1::text, 'bhash-xyz', 'execution-revocation-race',
           $2::text, $3::text, 'entity-alice'
         )`,
        [signoffId, bindingId, challengeId],
      )).rejects.toThrow('SIGNOFF_HANDSHAKE_NOT_VERIFIED');
      await waitForBlockedQuery('consume_signoff_atomic');
      await revoker.query('COMMIT');
      await consumption;

      const { rows } = await query(
        `SELECT
           (SELECT count(*)::int FROM handshake_consumptions WHERE handshake_id = $1) AS handshake_consumptions,
           (SELECT count(*)::int FROM signoff_consumptions WHERE signoff_id = $2) AS signoff_consumptions,
           (SELECT consumed_at IS NOT NULL FROM handshake_bindings WHERE id = $3) AS binding_finalized,
           (SELECT consumed_for FROM handshake_bindings WHERE id = $3) AS binding_consumed_for`,
        [handshakeId, signoffId, bindingId],
      );
      expect(rows[0]).toEqual({
        handshake_consumptions: 0,
        signoff_consumptions: 0,
        binding_finalized: true,
        binding_consumed_for: `handshake_verified:${handshakeId}`,
      });
    } finally {
      await revoker.query('ROLLBACK').catch(() => {});
      revoker.release();
      consumer.release();
    }
  });

  it('serializes signoff consumption behind direct authority consumption', async () => {
    const { handshakeId, bindingId, challengeId, signoffId } = await approvedAttestation();
    const directConsumer = await getPool().connect();
    const signoffConsumer = await getPool().connect();
    try {
      await directConsumer.query('BEGIN');
      await directConsumer.query(
        `SELECT * FROM public.consume_handshake_atomic(
           $1::uuid, 'bhash-xyz', 'direct_execution', 'direct-1',
           'entity-alice', 'execution-direct-wins'
         )`,
        [handshakeId],
      );

      const signoffConsumption = expect(signoffConsumer.query(
        `SELECT public.consume_signoff_atomic(
           $1::text, 'bhash-xyz', 'execution-signoff-loses',
           $2::text, $3::text, 'entity-alice'
         )`,
        [signoffId, bindingId, challengeId],
      )).rejects.toThrow('SIGNOFF_AUTHORITY_ALREADY_CONSUMED');
      await waitForBlockedQuery('consume_signoff_atomic');
      await directConsumer.query('COMMIT');
      await signoffConsumption;

      const { rows } = await query(
        `SELECT
           (SELECT count(*)::int FROM handshake_consumptions WHERE handshake_id = $1) AS authority_consumptions,
           (SELECT count(*)::int FROM signoff_consumptions WHERE signoff_id = $2) AS signoff_consumptions,
           (SELECT consumed_for FROM handshake_bindings WHERE id = $3) AS binding_consumed_for`,
        [handshakeId, signoffId, bindingId],
      );
      expect(rows[0]).toEqual({
        authority_consumptions: 1,
        signoff_consumptions: 0,
        binding_consumed_for: `handshake_verified:${handshakeId}`,
      });
      await query(
        `DELETE FROM handshake_consumptions WHERE handshake_id = $1`,
        [handshakeId],
      );
    } finally {
      await directConsumer.query('ROLLBACK').catch(() => {});
      directConsumer.release();
      signoffConsumer.release();
    }
  });

  it('atomically burns authority, prevents replay, and defeats a losing revocation', async () => {
    const { handshakeId, bindingId, challengeId, signoffId } = await approvedAttestation();
    const consumer = await getPool().connect();
    const revoker = await getPool().connect();
    try {
      await consumer.query('BEGIN');
      await consumer.query(
        `SELECT public.consume_signoff_atomic(
           $1::text, 'bhash-xyz', 'execution-consume-wins',
           $2::text, $3::text, 'entity-alice'
         )`,
        [signoffId, bindingId, challengeId],
      );

      const revocation = expect(revoker.query(
        `SELECT public.revoke_handshake_atomic($1::uuid, 'too late', 'entity-alice')`,
        [handshakeId],
      )).rejects.toThrow('HANDSHAKE_ALREADY_CONSUMED');
      await waitForBlockedQuery('revoke_handshake_atomic');
      await consumer.query('COMMIT');
      await revocation;

      await expect(query(
        `SELECT public.consume_signoff_atomic(
           $1::text, 'bhash-xyz', 'execution-replay',
           $2::text, $3::text, 'entity-alice'
         )`,
        [signoffId, bindingId, challengeId],
      )).rejects.toThrow('SIGNOFF_AUTHORITY_ALREADY_CONSUMED');

      const { rows } = await query(
        `SELECT
           (SELECT count(*)::int FROM handshake_consumptions WHERE handshake_id = $1) AS handshake_consumptions,
           (SELECT count(*)::int FROM signoff_consumptions WHERE signoff_id = $2) AS signoff_consumptions,
           (SELECT consumed_at IS NOT NULL FROM handshake_bindings WHERE id = $3) AS binding_consumed,
           (SELECT consumed_for FROM handshake_bindings WHERE id = $3) AS binding_consumed_for,
           (SELECT status FROM handshakes WHERE handshake_id = $1) AS handshake_status`,
        [handshakeId, signoffId, bindingId],
      );
      expect(rows[0]).toEqual({
        handshake_consumptions: 1,
        signoff_consumptions: 1,
        binding_consumed: true,
        binding_consumed_for: `handshake_verified:${handshakeId}`,
        handshake_status: 'verified',
      });
      await query(
        `DELETE FROM handshake_consumptions WHERE handshake_id = $1`,
        [handshakeId],
      );
    } finally {
      await consumer.query('ROLLBACK').catch(() => {});
      consumer.release();
      revoker.release();
    }
  });

  it('rolls the authority burn back if a later signoff write fails', async () => {
    const { handshakeId, bindingId, challengeId, signoffId } = await approvedAttestation();
    await query(
      `INSERT INTO signoff_consumptions (signoff_id, binding_hash, execution_ref)
       VALUES ($1, 'bhash-xyz', 'legacy-divergent-row')`,
      [signoffId],
    );

    await expect(query(
      `SELECT public.consume_signoff_atomic(
         $1::text, 'bhash-xyz', 'execution-must-rollback',
         $2::text, $3::text, 'entity-alice'
       )`,
      [signoffId, bindingId, challengeId],
    )).rejects.toThrow(/duplicate|unique/i);

    const { rows } = await query(
      `SELECT
         (SELECT count(*)::int FROM handshake_consumptions WHERE handshake_id = $1) AS handshake_consumptions,
         (SELECT consumed_at IS NOT NULL FROM handshake_bindings WHERE id = $2) AS binding_finalized,
         (SELECT consumed_for FROM handshake_bindings WHERE id = $2) AS binding_consumed_for,
         (SELECT status FROM signoff_attestations WHERE signoff_id = $3) AS attestation_status,
         (SELECT count(*)::int FROM signoff_events
           WHERE signoff_id = $3 AND event_type = 'signoff_consumed') AS consumed_events`,
      [handshakeId, bindingId, signoffId],
    );
    expect(rows[0]).toEqual({
      handshake_consumptions: 0,
      binding_finalized: true,
      binding_consumed_for: `handshake_verified:${handshakeId}`,
      attestation_status: 'approved',
      consumed_events: 0,
    });
  });

  it('serializes approval against denial and permits exactly one terminal decision', async () => {
    const { bindingId, challengeId } = await pendingChallenge();
    const signoffId = crypto.randomUUID();
    const ceremonyEvidenceId = await insertCeremonyEvidence(challengeId);
    const approver = await getPool().connect();
    const denier = await getPool().connect();
    try {
      await approver.query('BEGIN');
      await approver.query(
        `SELECT public.approve_attestation_atomic(
           $1::uuid, $2::uuid, $3::uuid, 'bhash-xyz', 'entity-alice',
           'passkey', 'substantial', 'web', now() + interval '4 minutes',
           'attestation-hash', pg_catalog.jsonb_build_object(
             'ceremony_evidence_id', $4::text
           )
         )`,
        [signoffId, challengeId, bindingId, ceremonyEvidenceId],
      );

      const denial = expect(denier.query(
        `SELECT public.deny_challenge_atomic(
           $1::uuid, 'entity-alice', 'concurrent denial'
         )`,
        [challengeId],
      )).rejects.toThrow('SIGNOFF_CHALLENGE_NOT_DENIABLE');
      await waitForBlockedQuery('deny_challenge_atomic');
      await approver.query('COMMIT');
      await denial;

      const { rows } = await query(
        `SELECT
           (SELECT status FROM signoff_challenges WHERE challenge_id = $1) AS status,
           (SELECT count(*)::int FROM signoff_attestations WHERE challenge_id = $1) AS attestations,
           (SELECT array_agg(event_type ORDER BY created_at)
              FROM signoff_events WHERE challenge_id = $1) AS events`,
        [challengeId],
      );
      expect(rows[0]).toMatchObject({ status: 'approved', attestations: 1 });
      expect(rows[0].events).toEqual(['signoff_approved']);
    } finally {
      await approver.query('ROLLBACK').catch(() => {});
      approver.release();
      denier.release();
    }
  });

  it('serializes two concurrent attestations and commits exactly one approval', async () => {
    const { bindingId, challengeId } = await pendingChallenge();
    const ceremonyEvidenceId = await insertCeremonyEvidence(challengeId);
    const winningSignoffId = crypto.randomUUID();
    const losingSignoffId = crypto.randomUUID();
    const winner = await getPool().connect();
    const loser = await getPool().connect();
    try {
      await winner.query('BEGIN');
      await winner.query(
        `SELECT public.approve_attestation_atomic(
           $1::uuid, $2::uuid, $3::uuid, 'bhash-xyz', 'entity-alice',
           'passkey', 'substantial', 'web', now() + interval '4 minutes',
           'attestation-hash-winner', pg_catalog.jsonb_build_object(
             'ceremony_evidence_id', $4::text
           )
         )`,
        [winningSignoffId, challengeId, bindingId, ceremonyEvidenceId],
      );

      const losingApproval = expect(loser.query(
        `SELECT public.approve_attestation_atomic(
           $1::uuid, $2::uuid, $3::uuid, 'bhash-xyz', 'entity-alice',
           'passkey', 'substantial', 'web', now() + interval '4 minutes',
           'attestation-hash-loser', pg_catalog.jsonb_build_object(
             'ceremony_evidence_id', $4::text
           )
         )`,
        [losingSignoffId, challengeId, bindingId, ceremonyEvidenceId],
      )).rejects.toThrow('SIGNOFF_CHALLENGE_NOT_ATTESTABLE');
      await waitForBlockedQuery('approve_attestation_atomic');
      await winner.query('COMMIT');
      await losingApproval;

      const { rows } = await query(
        `SELECT
           (SELECT status FROM signoff_challenges WHERE challenge_id = $1) AS status,
           (SELECT count(*)::int FROM signoff_attestations WHERE challenge_id = $1) AS attestations,
           (SELECT count(*)::int FROM signoff_events
              WHERE challenge_id = $1 AND event_type = 'signoff_approved') AS approval_events,
           (SELECT consumed_at IS NOT NULL FROM signoff_ceremony_evidence
              WHERE evidence_id = $2) AS ceremony_consumed`,
        [challengeId, ceremonyEvidenceId],
      );
      expect(rows[0]).toEqual({
        status: 'approved',
        attestations: 1,
        approval_events: 1,
        ceremony_consumed: true,
      });
    } finally {
      await winner.query('ROLLBACK').catch(() => {});
      winner.release();
      loser.release();
    }
  });

  it('prevents approval after a concurrent challenge revocation commits', async () => {
    const { bindingId, challengeId } = await pendingChallenge();
    const revoker = await getPool().connect();
    const approver = await getPool().connect();
    try {
      await revoker.query('BEGIN');
      await revoker.query(
        `SELECT public.revoke_challenge_atomic(
           $1::uuid, 'entity-alice', 'authority withdrawn'
         )`,
        [challengeId],
      );

      const approval = expect(approver.query(
        `SELECT public.approve_attestation_atomic(
           $1::uuid, $2::uuid, $3::uuid, 'bhash-xyz', 'entity-alice',
           'passkey', 'substantial', 'web', now() + interval '5 minutes',
           'attestation-hash', '{}'::jsonb
         )`,
        [crypto.randomUUID(), challengeId, bindingId],
      )).rejects.toThrow('SIGNOFF_CHALLENGE_NOT_ATTESTABLE');
      await waitForBlockedQuery('approve_attestation_atomic');
      await revoker.query('COMMIT');
      await approval;

      const { rows } = await query(
        `SELECT
           (SELECT status FROM signoff_challenges WHERE challenge_id = $1) AS status,
           (SELECT count(*)::int FROM signoff_attestations WHERE challenge_id = $1) AS attestations,
           (SELECT array_agg(event_type ORDER BY created_at)
              FROM signoff_events WHERE challenge_id = $1) AS events`,
        [challengeId],
      );
      expect(rows[0]).toMatchObject({ status: 'revoked', attestations: 0 });
      expect(rows[0].events).toEqual(['challenge_revoked']);
    } finally {
      await revoker.query('ROLLBACK').catch(() => {});
      revoker.release();
      approver.release();
    }
  });

  it('prevents consumption after a concurrent attestation revocation commits', async () => {
    const { bindingId, challengeId, signoffId } = await approvedAttestation();
    const revoker = await getPool().connect();
    const consumer = await getPool().connect();
    try {
      await revoker.query('BEGIN');
      await revoker.query(
        `SELECT public.revoke_attestation_atomic(
           $1::uuid, $2::uuid, 'entity-alice', 'approval withdrawn'
         )`,
        [signoffId, challengeId],
      );

      const consumption = expect(consumer.query(
        `SELECT public.consume_signoff_atomic(
           $1::text, 'bhash-xyz', 'execution-1', $2::text, $3::text, 'entity-alice'
         )`,
        [signoffId, bindingId, challengeId],
      )).rejects.toThrow('SIGNOFF_ATTESTATION_NOT_CONSUMABLE');
      await waitForBlockedQuery('consume_signoff_atomic');
      await revoker.query('COMMIT');
      await consumption;

      const { rows } = await query(
        `SELECT
           (SELECT status FROM signoff_attestations WHERE signoff_id = $1) AS status,
           (SELECT count(*)::int FROM signoff_consumptions WHERE signoff_id = $1) AS consumptions,
           (SELECT array_agg(event_type ORDER BY created_at)
              FROM signoff_events WHERE challenge_id = $2) AS events`,
        [signoffId, challengeId],
      );
      expect(rows[0]).toMatchObject({ status: 'revoked', consumptions: 0 });
      expect(rows[0].events).toEqual(['signoff_approved', 'signoff_revoked']);
    } finally {
      await revoker.query('ROLLBACK').catch(() => {});
      revoker.release();
      consumer.release();
    }
  });

  it('rolls signoff consumption back when validity expires while lock acquisition waits', async () => {
    const expiresAt = new Date(Date.now() + 2_000);
    const {
      handshakeId,
      bindingId,
      challengeId,
      signoffId,
    } = await approvedAttestation({ expiresAt });
    const blocker = await getPool().connect();
    const consumer = await getPool().connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query(
        'SELECT handshake_id FROM handshakes WHERE handshake_id = $1 FOR UPDATE',
        [handshakeId],
      );

      const consumption = expect(consumer.query(
        `SELECT public.consume_signoff_atomic(
           $1::text, 'bhash-xyz', 'execution-expired-after-lock-wait',
           $2::text, $3::text, 'entity-alice'
         )`,
        [signoffId, bindingId, challengeId],
      )).rejects.toThrow('SIGNOFF_CHALLENGE_EXPIRED');
      await waitForBlockedQuery('consume_signoff_atomic');
      await new Promise((resolve) => setTimeout(
        resolve,
        Math.max(0, expiresAt.getTime() - Date.now() + 150),
      ));
      await blocker.query('COMMIT');
      await consumption;

      const { rows } = await query(
        `SELECT
           (SELECT count(*)::int FROM handshake_consumptions
              WHERE handshake_id = $1) AS handshake_consumptions,
           (SELECT count(*)::int FROM signoff_consumptions
              WHERE signoff_id = $2) AS signoff_consumptions,
           (SELECT status FROM signoff_challenges
              WHERE challenge_id = $3) AS challenge_status,
           (SELECT status FROM signoff_attestations
              WHERE signoff_id = $2) AS attestation_status,
           (SELECT count(*)::int FROM signoff_events
              WHERE signoff_id = $2 AND event_type = 'signoff_consumed') AS consumed_events`,
        [handshakeId, signoffId, challengeId],
      );
      expect(rows[0]).toEqual({
        handshake_consumptions: 0,
        signoff_consumptions: 0,
        challenge_status: 'approved',
        attestation_status: 'approved',
        consumed_events: 0,
      });
    } finally {
      await blocker.query('ROLLBACK').catch(() => {});
      blocker.release();
      consumer.release();
    }
  });

  it('consumption locks and requires the challenge to remain approved', async () => {
    const { bindingId, challengeId, signoffId } = await approvedAttestation();
    // Simulate an impossible legacy/corrupted row to prove the consume RPC's
    // locked state predicate remains independent of the new exact-edge trigger.
    await query(
      `ALTER TABLE signoff_challenges
       DISABLE TRIGGER enforce_signoff_challenge_exact_transitions`,
    );
    try {
      await query(
        `UPDATE signoff_challenges SET status = 'revoked' WHERE challenge_id = $1`,
        [challengeId],
      );
    } finally {
      await query(
        `ALTER TABLE signoff_challenges
         ENABLE TRIGGER enforce_signoff_challenge_exact_transitions`,
      );
    }

    await expect(query(
      `SELECT public.consume_signoff_atomic(
         $1::text, 'bhash-xyz', 'execution-2', $2::text, $3::text, 'entity-alice'
       )`,
      [signoffId, bindingId, challengeId],
    )).rejects.toThrow('SIGNOFF_CHALLENGE_NOT_CONSUMABLE');

    const { rows } = await query(
      `SELECT count(*)::int AS count
       FROM signoff_consumptions WHERE signoff_id = $1`,
      [signoffId],
    );
    expect(rows[0].count).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// ── 6. Handshake nonce uniqueness ───────────────────────────────────────────
// ---------------------------------------------------------------------------

describe.skipIf(SKIP)('DB invariant: handshake nonces are globally unique', () => {
  it('rejects a duplicate nonce', async () => {
    const nonce = `nonce-dup-${Math.random().toString(36).slice(2)}`;
    await query(`INSERT INTO handshakes (nonce, status) VALUES ($1, 'initiated')`, [nonce]);
    await expect(
      query(`INSERT INTO handshakes (nonce, status) VALUES ($1, 'initiated')`, [nonce]),
    ).rejects.toThrow(/unique|duplicate/i);
  });

  it('accepts two handshakes with different nonces', async () => {
    const n1 = `nonce-a-${Math.random().toString(36).slice(2)}`;
    const n2 = `nonce-b-${Math.random().toString(36).slice(2)}`;
    const { rows: r1 } = await query(
      `INSERT INTO handshakes (nonce, status) VALUES ($1, 'initiated') RETURNING handshake_id`, [n1],
    );
    const { rows: r2 } = await query(
      `INSERT INTO handshakes (nonce, status) VALUES ($1, 'initiated') RETURNING handshake_id`, [n2],
    );
    expect(r1[0].handshake_id).not.toBe(r2[0].handshake_id);
  });
});

// ---------------------------------------------------------------------------
// ── 6. Handshake status constraints ─────────────────────────────────────────
// ---------------------------------------------------------------------------

describe.skipIf(SKIP)('DB invariant: handshake status is constrained to valid values', () => {
  it('rejects an invalid handshake status', async () => {
    const nonce = `nonce-inv-${Math.random().toString(36).slice(2)}`;
    await expect(
      query(`INSERT INTO handshakes (nonce, status) VALUES ($1, 'hacked')`, [nonce]),
    ).rejects.toThrow(/check|constraint/i);
  });

  it('allows all valid handshake statuses', async () => {
    const statuses = ['initiated', 'presented', 'verified', 'consumed', 'revoked', 'expired'];
    for (const status of statuses) {
      const nonce = `nonce-${status}-${Math.random().toString(36).slice(2)}`;
      await expect(
        query(`INSERT INTO handshakes (nonce, status) VALUES ($1, $2)`, [nonce, status]),
      ).resolves.not.toThrow();
    }
  });
});

// ---------------------------------------------------------------------------
// ── 7. One binding per handshake ────────────────────────────────────────────
// ---------------------------------------------------------------------------

describe.skipIf(SKIP)('DB invariant: each handshake has at most one binding', () => {
  it('rejects a second binding for the same handshake', async () => {
    const hId = await insertHandshake();
    await insertBinding(hId);
    await expect(
      query(
        `INSERT INTO handshake_bindings (handshake_id, payload_hash, nonce, expires_at)
         VALUES ($1, $2, $3, now() + interval '1 hour')`,
        [hId, 'phash-second', `bnonce-${Math.random().toString(36).slice(2)}`],
      ),
    ).rejects.toThrow(/unique|duplicate/i);
  });

  it('allows one binding per handshake', async () => {
    const hId = await insertHandshake();
    const bId = await insertBinding(hId);
    expect(bId).toBeTruthy();
    const { rows } = await query(
      `SELECT count(*) FROM handshake_bindings WHERE handshake_id = $1`, [hId],
    );
    expect(parseInt(rows[0].count, 10)).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// ── 8. Entity uniqueness ────────────────────────────────────────────────────
// ---------------------------------------------------------------------------

describe.skipIf(SKIP)('DB invariant: entity_id is globally unique', () => {
  it('rejects a duplicate entity_id', async () => {
    const eid = `ent-dup-${Math.random().toString(36).slice(2)}`;
    await insertEntity(eid);
    await expect(insertEntity(eid)).rejects.toThrow(/unique|duplicate/i);
  });
});

// ---------------------------------------------------------------------------
// ── 9. Cross-handshake consumption isolation ────────────────────────────────
// ---------------------------------------------------------------------------

describe.skipIf(SKIP)('DB invariant: consumption does not bleed across handshakes', () => {
  it('two distinct handshakes can each be consumed independently', async () => {
    const hId1 = await insertHandshake();
    const bId1 = await insertBinding(hId1);
    const hId2 = await insertHandshake();
    const bId2 = await insertBinding(hId2);

    await query(
      `UPDATE handshake_bindings SET consumed_at = now() WHERE id = $1`, [bId1],
    );
    await query(
      `UPDATE handshake_bindings SET consumed_at = now() WHERE id = $1`, [bId2],
    );

    const { rows: r1 } = await query(
      `SELECT consumed_at FROM handshake_bindings WHERE id = $1`, [bId1],
    );
    const { rows: r2 } = await query(
      `SELECT consumed_at FROM handshake_bindings WHERE id = $1`, [bId2],
    );
    expect(r1[0].consumed_at).toBeTruthy();
    expect(r2[0].consumed_at).toBeTruthy();
  });

  it('consuming one binding does not affect the other handshake binding', async () => {
    const hId1 = await insertHandshake();
    const bId1 = await insertBinding(hId1);
    const hId2 = await insertHandshake();
    const bId2 = await insertBinding(hId2);

    await query(
      `UPDATE handshake_bindings SET consumed_at = now() WHERE id = $1`, [bId1],
    );

    const { rows } = await query(
      `SELECT consumed_at FROM handshake_bindings WHERE id = $1`, [bId2],
    );
    expect(rows[0].consumed_at).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// ── 10. Signoff FK integrity ─────────────────────────────────────────────────
// ---------------------------------------------------------------------------

describe.skipIf(SKIP)('DB invariant: signoff FK relationships are enforced', () => {
  it('rejects a challenge referencing a non-existent binding', async () => {
    const fakeBindingId = '00000000-0000-0000-0000-000000000000';
    await expect(
      query(
        `INSERT INTO signoff_challenges (handshake_id, binding_hash, status, expires_at)
         VALUES ($1, $2, 'challenge_issued', now() + interval '10 minutes')`,
        [fakeBindingId, 'bhash-fake'],
      ),
    ).rejects.toThrow(/foreign key|fk|violates/i);
  });

  it('rejects an attestation referencing a non-existent challenge', async () => {
    const hId = await insertHandshake();
    const bId = await insertBinding(hId);
    const fakeChallengeId = '00000000-0000-0000-0000-000000000001';
    await expect(
      query(
        `INSERT INTO signoff_attestations
           (challenge_id, handshake_id, binding_hash, auth_method)
         VALUES ($1, $2, $3, 'passkey')`,
        [fakeChallengeId, bId, 'bhash-xyz'],
      ),
    ).rejects.toThrow(/foreign key|fk|violates/i);
  });

  it('rejects a consumption referencing a non-existent attestation', async () => {
    const fakeSignoffId = '00000000-0000-0000-0000-000000000002';
    await expect(
      query(
        `INSERT INTO signoff_consumptions (signoff_id, binding_hash, execution_ref)
         VALUES ($1, $2, $3)`,
        [fakeSignoffId, 'bhash-fake', 'exec-fake'],
      ),
    ).rejects.toThrow(/foreign key|fk|violates/i);
  });
});

// ---------------------------------------------------------------------------
// ── 11. Generic receipt consume locks exact registry bindings ──────────────
// ---------------------------------------------------------------------------

describe.skipIf(SKIP)('DB invariant: generic Trust Receipt consume is atomic', () => {
  const organizationId = '88888888-8888-4888-8888-888888888888';
  const authorityId = '99999999-9999-4999-8999-999999999999';
  const approverId = 'generic-approver-1';
  const credentialId = 'generic-credential-1';
  const actionHash = 'e'.repeat(64);

  it('consumes once and rejects replay or changed authority facts', async () => {
    await query(
      `INSERT INTO approver_credentials
         (organization_id, approver_id, credential_id, public_key_spki,
          key_class, valid_from)
       VALUES ($1, $2, $3, 'generic-spki', 'A', now() - interval '1 day')
       ON CONFLICT (credential_id) DO NOTHING`,
      [organizationId, approverId, credentialId],
    );
    await query(
      `INSERT INTO authorities
         (authority_id, key_id, public_key, role, status, valid_from,
          organization_id, subject_type, subject_ref, assurance_class, action_scopes)
       VALUES
         ($1, 'generic-authority-key', 'generic-pk', 'controller', 'active',
          now() - interval '1 day', $2, 'human_approver', $3, 'A',
          ARRAY['deploy_production'])
       ON CONFLICT (authority_id) DO UPDATE SET
         status = 'active',
         revoked_at = NULL,
         subject_ref = EXCLUDED.subject_ref`,
      [authorityId, organizationId, approverId],
    );

    const receiptId = `tr_${'e'.repeat(32)}`;
    await query(
      `INSERT INTO audit_events
         (event_type, actor_id, actor_type, target_type, target_id, action, after_state)
       VALUES
         ('guard.trust_receipt.created', 'generic-initiator', 'principal',
          'trust_receipt', $1, 'create', $2::jsonb)`,
      [
        receiptId,
        JSON.stringify({
          organization_id: organizationId,
          action_type: 'deploy_production',
          action_hash: actionHash,
          signoff_required: true,
          required_assurance: 'A',
          quorum_policy: { required: 1 },
          expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
        }),
      ],
    );
    const registryBindings = [{
      authority_id: authorityId,
      approver_id: approverId,
      role: 'controller',
      credential_id: credentialId,
      required_assurance: 'A',
    }];

    const consumed = await consumeTrustReceiptAsServiceRole({
      receiptId,
      actionHash,
      organizationId,
      registryBindings,
    });
    expect(consumed.rows[0].consumed).toMatchObject({
      receipt_id: receiptId,
      consumed_by_system: 'integration-test-executor',
    });
    await expect(consumeTrustReceiptAsServiceRole({
      receiptId,
      actionHash,
      organizationId,
      registryBindings,
    })).rejects.toThrow('trust_receipt_already_consumed');

    const revokedReceiptId = `tr_${'f'.repeat(32)}`;
    await query(
      `INSERT INTO audit_events
         (event_type, actor_id, actor_type, target_type, target_id, action, after_state)
       VALUES
         ('guard.trust_receipt.created', 'generic-initiator', 'principal',
          'trust_receipt', $1, 'create', $2::jsonb)`,
      [
        revokedReceiptId,
        JSON.stringify({
          organization_id: organizationId,
          action_type: 'deploy_production',
          action_hash: actionHash,
          signoff_required: true,
          required_assurance: 'A',
          quorum_policy: null,
          expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
        }),
      ],
    );
    await query(
      `UPDATE authorities
       SET status = 'revoked', revoked_at = now()
       WHERE authority_id = $1`,
      [authorityId],
    );
    await expect(consumeTrustReceiptAsServiceRole({
      receiptId: revokedReceiptId,
      actionHash,
      organizationId,
      registryBindings,
    })).rejects.toThrow('trust_receipt_registry_facts_invalid');
  });

  it('uses post-lock wall clock when a bound Class-A credential expires while consume waits', async () => {
    const suffix = crypto.randomBytes(8).toString('hex');
    const expiringOrganizationId = `org-expiring-consume-${suffix}`;
    const expiringApproverId = `approver-expiring-${suffix}`;
    const expiringCredentialId = `credential-expiring-${suffix}`;
    const expiringAuthorityId = crypto.randomUUID();
    const expiringActionHash = crypto.randomBytes(32).toString('hex');
    const receiptId = `tr_${crypto.randomBytes(16).toString('hex')}`;

    await query(
      `INSERT INTO approver_credentials
         (organization_id, approver_id, credential_id, public_key_spki,
          key_class, valid_from)
       VALUES ($1, $2, $3, 'expiring-spki', 'A', clock_timestamp() - interval '1 day')`,
      [expiringOrganizationId, expiringApproverId, expiringCredentialId],
    );
    await query(
      `INSERT INTO authorities
         (authority_id, key_id, public_key, role, status, valid_from,
          organization_id, subject_type, subject_ref, assurance_class, action_scopes)
       VALUES
         ($1, $2, 'expiring-pk', 'controller', 'active',
          clock_timestamp() - interval '1 day', $3, 'human_approver', $4, 'A',
          ARRAY['deploy_production'])`,
      [
        expiringAuthorityId,
        `expiring-authority-key-${suffix}`,
        expiringOrganizationId,
        expiringApproverId,
      ],
    );
    await query(
      `INSERT INTO audit_events
         (event_type, actor_id, actor_type, target_type, target_id, action, after_state)
       VALUES
         ('guard.trust_receipt.created', 'expiry-race-creator', 'principal',
          'trust_receipt', $1, 'create', $2::jsonb)`,
      [
        receiptId,
        JSON.stringify({
          organization_id: expiringOrganizationId,
          action_type: 'deploy_production',
          action_hash: expiringActionHash,
          signoff_required: true,
          required_assurance: 'A',
          quorum_policy: null,
          expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
        }),
      ],
    );

    const registryBindings = [{
      authority_id: expiringAuthorityId,
      approver_id: expiringApproverId,
      role: 'controller',
      credential_id: expiringCredentialId,
      required_assurance: 'A',
    }];
    const blocker = await getPool().connect();
    try {
      await blocker.query('BEGIN');
      const { rows: validityRows } = await blocker.query(
        `UPDATE approver_credentials
            SET valid_to = clock_timestamp() + interval '650 milliseconds'
          WHERE credential_id = $1
          RETURNING valid_to > clock_timestamp() AS still_valid`,
        [expiringCredentialId],
      );
      expect(validityRows[0].still_valid).toBe(true);

      const consumption = expect(consumeTrustReceiptAsServiceRole({
        receiptId,
        actionHash: expiringActionHash,
        organizationId: expiringOrganizationId,
        registryBindings,
      })).rejects.toThrow('trust_receipt_registry_facts_invalid');
      await waitForBlockedQuery('consume_trust_receipt_authorized');
      await new Promise((resolve) => setTimeout(resolve, 900));
      const { rows: expiredRows } = await blocker.query(
        `SELECT valid_to <= clock_timestamp() AS expired
           FROM approver_credentials
          WHERE credential_id = $1`,
        [expiringCredentialId],
      );
      expect(expiredRows[0].expired).toBe(true);
      await blocker.query('COMMIT');
      await consumption;
    } finally {
      await blocker.query('ROLLBACK').catch(() => {});
      blocker.release();
    }

    const { rows } = await query(
      `SELECT
         count(*) FILTER (
           WHERE event_type = 'guard.trust_receipt.consumed'
         )::int AS consumptions,
         count(*) FILTER (
           WHERE event_type = 'guard.trust_receipt.consume_validity_checked'
         )::int AS validity_checks
       FROM audit_events
       WHERE target_type = 'trust_receipt' AND target_id = $1`,
      [receiptId],
    );
    expect(rows[0]).toEqual({ consumptions: 0, validity_checks: 0 });
  });

  it('serializes a bound rejection against consume and commits no consume event', async () => {
    const suffix = crypto.randomBytes(8).toString('hex');
    const raceOrganizationId = `org-rejection-race-${suffix}`;
    const raceApproverId = `approver-race-${suffix}`;
    const rejectingApproverId = `rejecter-race-${suffix}`;
    const raceCredentialId = `credential-race-${suffix}`;
    const raceAuthorityId = crypto.randomUUID();
    const raceActionHash = crypto.randomBytes(32).toString('hex');
    const receiptId = `tr_${crypto.randomBytes(16).toString('hex')}`;
    const approvedSignoffId = `sig-approved-${suffix}`;
    const rejectedSignoffId = `sig-rejected-${suffix}`;

    await query(
      `INSERT INTO approver_credentials
         (organization_id, approver_id, credential_id, public_key_spki,
          key_class, valid_from)
       VALUES ($1, $2, $3, 'race-spki', 'A', now() - interval '1 day')`,
      [raceOrganizationId, raceApproverId, raceCredentialId],
    );
    await query(
      `INSERT INTO authorities
         (authority_id, key_id, public_key, role, status, valid_from,
          organization_id, subject_type, subject_ref, assurance_class, action_scopes)
       VALUES
         ($1, $2, 'race-pk', 'controller', 'active', now() - interval '1 day',
          $3, 'human_approver', $4, 'A', ARRAY['deploy_production'])`,
      [raceAuthorityId, `race-authority-key-${suffix}`, raceOrganizationId, raceApproverId],
    );
    await query(
      `INSERT INTO audit_events
         (event_type, actor_id, actor_type, target_type, target_id, action, after_state)
       VALUES
         ('guard.trust_receipt.created', 'race-creator', 'principal',
          'trust_receipt', $1, 'create', $2::jsonb)`,
      [
        receiptId,
        JSON.stringify({
          organization_id: raceOrganizationId,
          action_type: 'deploy_production',
          action_hash: raceActionHash,
          signoff_required: true,
          required_assurance: 'A',
          quorum_policy: null,
          expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
        }),
      ],
    );
    await query(
      `INSERT INTO audit_events
         (event_type, actor_id, actor_type, target_type, target_id, action, after_state)
       VALUES
         ('guard.signoff.requested', 'race-creator', 'principal',
          'trust_receipt', $1, 'request_signoff', $2::jsonb),
         ('guard.signoff.requested', 'race-creator', 'principal',
          'trust_receipt', $1, 'request_signoff', $3::jsonb),
         ('guard.signoff.approved', $4, 'principal',
          'trust_receipt', $1, 'approved', $5::jsonb)`,
      [
        receiptId,
        JSON.stringify({
          signoff_id: approvedSignoffId,
          approver_id: raceApproverId,
          quorum: { approver_id: raceApproverId },
        }),
        JSON.stringify({
          signoff_id: rejectedSignoffId,
          approver_id: rejectingApproverId,
          quorum: { approver_id: rejectingApproverId },
        }),
        raceApproverId,
        JSON.stringify({
          signoff_id: approvedSignoffId,
          approver_id: raceApproverId,
          approved_action_hash: raceActionHash,
        }),
      ],
    );

    const registryBindings = [{
      authority_id: raceAuthorityId,
      approver_id: raceApproverId,
      role: 'controller',
      credential_id: raceCredentialId,
      required_assurance: 'A',
    }];
    const rejecter = await getPool().connect();
    try {
      await rejecter.query('BEGIN');
      await rejecter.query(
        `INSERT INTO audit_events
           (event_type, actor_id, actor_type, target_type, target_id, action, after_state)
         VALUES
           ('guard.signoff.rejected', $2, 'principal',
            'trust_receipt', $1, 'rejected', $3::jsonb)`,
        [
          receiptId,
          rejectingApproverId,
          JSON.stringify({
            signoff_id: rejectedSignoffId,
            approver_id: rejectingApproverId,
            approved_action_hash: raceActionHash,
          }),
        ],
      );

      const consumption = expect(consumeTrustReceiptAsServiceRole({
        receiptId,
        actionHash: raceActionHash,
        organizationId: raceOrganizationId,
        registryBindings,
      })).rejects.toThrow('trust_receipt_signoff_rejected');
      await waitForBlockedQuery('consume_trust_receipt_authorized');
      await rejecter.query('COMMIT');
      await consumption;

      const { rows } = await query(
        `SELECT
           count(*) FILTER (
             WHERE event_type = 'guard.signoff.rejected'
           )::int AS rejections,
           count(*) FILTER (
             WHERE event_type = 'guard.trust_receipt.consumed'
           )::int AS consumptions
         FROM audit_events
         WHERE target_type = 'trust_receipt' AND target_id = $1`,
        [receiptId],
      );
      expect(rows[0]).toEqual({ rejections: 1, consumptions: 0 });
    } finally {
      await rejecter.query('ROLLBACK').catch(() => {});
      rejecter.release();
    }
  });
});

// ---------------------------------------------------------------------------
// ── 12. Policy rollout receipt consume + activation is one transaction ─────
// ---------------------------------------------------------------------------

describe.skipIf(SKIP)('DB invariant: policy rollout Accountable Signoff is atomic', () => {
  it('serializes legacy writes during the expand window', async () => {
    await query(
      `INSERT INTO handshake_policies
         (policy_id, policy_key, version, mode, status, rules, tenant_id)
       VALUES ($1, 'strict', 2, 'mutual', 'active', $2::jsonb, $3)
       ON CONFLICT (policy_id) DO NOTHING`,
      [ROLLOUT_POLICY_ID, JSON.stringify(ROLLOUT_RULES), ROLLOUT_TENANT_ID],
    );

    const lockClient = await getPool().connect();
    const legacyClient = await getPool().connect();
    try {
      await lockClient.query('BEGIN');
      await lockClient.query(
        `SELECT pg_advisory_xact_lock(
           hashtextextended($1::text || ':strict:expand-lock-test', 0)
         )`,
        [ROLLOUT_TENANT_ID],
      );

      await legacyClient.query('BEGIN');
      await legacyClient.query('SET LOCAL ROLE service_role');
      const legacyWrite = legacyClient.query(
        `INSERT INTO policy_rollouts
           (policy_id, version, environment, strategy, status, initiated_by, tenant_id)
         VALUES ($1, 2, 'expand-lock-test', 'immediate', 'active', 'legacy', $2)`,
        [ROLLOUT_POLICY_ID, ROLLOUT_TENANT_ID],
      );
      const blocked = await Promise.race([
        legacyWrite.then(() => false),
        new Promise((resolve) => setTimeout(() => resolve(true), 75)),
      ]);
      expect(blocked).toBe(true);

      await lockClient.query('COMMIT');
      await legacyWrite;
      await legacyClient.query('ROLLBACK');
    } finally {
      await lockClient.query('ROLLBACK').catch(() => {});
      await legacyClient.query('ROLLBACK').catch(() => {});
      lockClient.release();
      legacyClient.release();
    }

    const { rows } = await query(
      `SELECT
         has_table_privilege('service_role', 'public.policy_rollouts', 'INSERT') AS service_insert,
         has_table_privilege('service_role', 'public.policy_rollouts', 'UPDATE') AS service_update`,
    );
    expect(rows[0]).toEqual({ service_insert: true, service_update: true });
  });

  it('activates once and classifies replay, stale state, and invalid authority', async () => {
    await query(
      `INSERT INTO handshake_policies
         (policy_id, policy_key, version, mode, status, rules, tenant_id)
       VALUES ($1, 'strict', 2, 'mutual', 'active', $2::jsonb, $3)
       ON CONFLICT (policy_id) DO NOTHING`,
      [ROLLOUT_POLICY_ID, JSON.stringify(ROLLOUT_RULES), ROLLOUT_TENANT_ID],
    );
    await query(
      `INSERT INTO authorities
         (authority_id, key_id, public_key, role, status, valid_from,
          organization_id, subject_type, subject_ref, assurance_class, action_scopes)
       VALUES
         ($1, 'authority-key', 'pk', 'policy_admin', 'active', now() - interval '1 day',
          $2, 'human_approver', 'approver-1', 'A', ARRAY['policy_rollout'])`,
      [ROLLOUT_AUTHORITY_ID, ROLLOUT_TENANT_ID],
    );
    await query(
      `INSERT INTO approver_credentials
         (organization_id, approver_id, credential_id, public_key_spki,
          key_class, valid_from)
       VALUES ($1, 'approver-1', 'credential-1', 'spki', 'A', now() - interval '1 day')`,
      [ROLLOUT_TENANT_ID],
    );

    const firstReceipt = `tr_${'a'.repeat(32)}`;
    const first = await insertRolloutReceipt(firstReceipt, 'production');
    const activated = await activateRolloutAsServiceRole({
      receiptId: firstReceipt,
      environment: 'production',
      ...first,
    });
    expect(activated.rows).toHaveLength(1);
    expect(activated.rows[0]).toMatchObject({
      authorization_receipt_id: firstReceipt,
      authorization_action_hash: ROLLOUT_ACTION_HASH,
      status: 'active',
    });
    expect(activated.rows[0].authorization_execution_reference_id)
      .toBe(`policy-rollout:${activated.rows[0].rollout_id}`);

    await expect(activateRolloutAsServiceRole({
      receiptId: firstReceipt,
      environment: 'production',
      ...first,
    })).rejects.toThrow('policy_rollout_receipt_unavailable');

    const staleReceipt = `tr_${'b'.repeat(32)}`;
    const stale = await insertRolloutReceipt(staleReceipt, 'production');
    await expect(activateRolloutAsServiceRole({
      receiptId: staleReceipt,
      environment: 'production',
      ...stale,
    })).rejects.toThrow('policy_rollout_signed_state_stale');

    const wrongAuthorityReceipt = `tr_${'c'.repeat(32)}`;
    const wrongAuthority = await insertRolloutReceipt(wrongAuthorityReceipt, 'qa');
    await expect(activateRolloutAsServiceRole({
      receiptId: wrongAuthorityReceipt,
      environment: 'qa',
      authorityId: '66666666-6666-4666-8666-666666666666',
      ...wrongAuthority,
    })).rejects.toThrow('policy_rollout_authority_invalid');

    const { rows: privilegeRows } = await query(
      `SELECT
         has_table_privilege('service_role', 'public.policy_rollouts', 'INSERT') AS service_insert,
         has_table_privilege('service_role', 'public.policy_rollouts', 'UPDATE') AS service_update,
         has_function_privilege(
           'anon',
           'public.activate_policy_rollout_authorized(uuid,uuid,text,integer,text,text,smallint,text,jsonb,text,text,jsonb,jsonb,uuid[],jsonb)',
           'EXECUTE'
         ) AS anon_execute`,
    );
    expect(privilegeRows[0]).toEqual({
      service_insert: true,
      service_update: true,
      anon_execute: false,
    });

    const { rows: consumeRows } = await query(
      `SELECT count(*)::integer AS count
       FROM audit_events
       WHERE target_type = 'trust_receipt'
         AND target_id = $1
         AND event_type = 'guard.trust_receipt.consumed'`,
      [firstReceipt],
    );
    expect(consumeRows[0].count).toBe(1);
  });

  it('uses post-lock wall clock when a relied-on Class-A credential expires during rollout activation', async () => {
    await query(
      `INSERT INTO handshake_policies
         (policy_id, policy_key, version, mode, status, rules, tenant_id)
       VALUES ($1, 'strict', 2, 'mutual', 'active', $2::jsonb, $3)
       ON CONFLICT (policy_id) DO UPDATE SET
         status = 'active', rules = EXCLUDED.rules, tenant_id = EXCLUDED.tenant_id`,
      [ROLLOUT_POLICY_ID, JSON.stringify(ROLLOUT_RULES), ROLLOUT_TENANT_ID],
    );
    await query(
      `INSERT INTO authorities
         (authority_id, key_id, public_key, role, status, valid_from,
          organization_id, subject_type, subject_ref, assurance_class, action_scopes)
       VALUES
         ($1, 'authority-key', 'pk', 'policy_admin', 'active',
          clock_timestamp() - interval '1 day', $2, 'human_approver',
          'approver-1', 'A', ARRAY['policy_rollout'])
       ON CONFLICT (authority_id) DO UPDATE SET
         status = 'active', revoked_at = NULL, valid_to = NULL,
         organization_id = EXCLUDED.organization_id,
         subject_ref = EXCLUDED.subject_ref,
         assurance_class = 'A', action_scopes = ARRAY['policy_rollout']`,
      [ROLLOUT_AUTHORITY_ID, ROLLOUT_TENANT_ID],
    );
    await query(
      `INSERT INTO approver_credentials
         (organization_id, approver_id, credential_id, public_key_spki,
          key_class, valid_from)
       VALUES ($1, 'approver-1', 'credential-1', 'spki', 'A',
               clock_timestamp() - interval '1 day')
       ON CONFLICT (credential_id) DO UPDATE SET
         organization_id = EXCLUDED.organization_id,
         approver_id = EXCLUDED.approver_id,
         key_class = 'A', revoked_at = NULL, valid_to = NULL`,
      [ROLLOUT_TENANT_ID],
    );

    const environment = `post-lock-expiry-${crypto.randomBytes(6).toString('hex')}`;
    const receiptId = `tr_${crypto.randomBytes(16).toString('hex')}`;
    const signedState = await insertRolloutReceipt(receiptId, environment);
    const blocker = await getPool().connect();
    try {
      await blocker.query('BEGIN');
      const { rows: validityRows } = await blocker.query(
        `UPDATE approver_credentials
            SET valid_to = clock_timestamp() + interval '650 milliseconds'
          WHERE credential_id = 'credential-1'
          RETURNING valid_to > clock_timestamp() AS still_valid`,
      );
      expect(validityRows[0].still_valid).toBe(true);

      const activation = expect(activateRolloutAsServiceRole({
        receiptId,
        environment,
        ...signedState,
      })).rejects.toThrow('policy_rollout_registry_validity_expired');
      await waitForBlockedQuery('activate_policy_rollout_authorized');
      await new Promise((resolve) => setTimeout(resolve, 900));
      const { rows: expiredRows } = await blocker.query(
        `SELECT valid_to <= clock_timestamp() AS expired
           FROM approver_credentials
          WHERE credential_id = 'credential-1'`,
      );
      expect(expiredRows[0].expired).toBe(true);
      await blocker.query('COMMIT');
      await activation;
    } finally {
      await blocker.query('ROLLBACK').catch(() => {});
      blocker.release();
    }

    const { rows } = await query(
      `SELECT
         (SELECT count(*)::int
            FROM policy_rollouts
           WHERE authorization_receipt_id = $1) AS rollouts,
         count(*) FILTER (
           WHERE event_type = 'guard.trust_receipt.consumed'
         )::int AS consumptions,
         count(*) FILTER (
           WHERE event_type = 'guard.policy_rollout.validity_checked'
         )::int AS validity_checks
       FROM audit_events
       WHERE target_type = 'trust_receipt' AND target_id = $1`,
      [receiptId],
    );
    expect(rows[0]).toEqual({ rollouts: 0, consumptions: 0, validity_checks: 0 });
  });

  it('atomically locks and rechecks every member of an org-pinned quorum', async () => {
    await query(
      `INSERT INTO handshake_policies
         (policy_id, policy_key, version, mode, status, rules, tenant_id)
       VALUES ($1, 'strict', 2, 'mutual', 'active', $2::jsonb, $3)
       ON CONFLICT (policy_id) DO NOTHING`,
      [ROLLOUT_POLICY_ID, JSON.stringify(ROLLOUT_RULES), ROLLOUT_TENANT_ID],
    );

    const quorumPolicy = {
      mode: 'threshold',
      required: 2,
      distinct_humans: true,
      window_sec: 600,
      approvers: [
        { role: 'change_control', approver: 'quorum-approver-1' },
        { role: 'security', approver: 'quorum-approver-2' },
      ],
    };
    await query(
      `INSERT INTO org_quorum_policies
         (organization_id, action_type, min_required, max_window_sec,
          require_distinct_humans, quorum_required, allowed_approvers, allowed_modes)
       VALUES ($1, 'policy_rollout', 2, 600, true, true, $2::jsonb, '["threshold"]'::jsonb)
       ON CONFLICT (organization_id, action_type)
       DO UPDATE SET
         min_required = EXCLUDED.min_required,
         max_window_sec = EXCLUDED.max_window_sec,
         require_distinct_humans = EXCLUDED.require_distinct_humans,
         quorum_required = EXCLUDED.quorum_required,
         allowed_approvers = EXCLUDED.allowed_approvers,
         allowed_modes = EXCLUDED.allowed_modes`,
      [ROLLOUT_TENANT_ID, JSON.stringify(quorumPolicy.approvers)],
    );

    const authorityIds = [
      '77777777-7777-4777-8777-777777777771',
      '77777777-7777-4777-8777-777777777772',
    ];
    for (let index = 0; index < 2; index += 1) {
      const approverId = `quorum-approver-${index + 1}`;
      const credentialId = `quorum-credential-${index + 1}`;
      await query(
        `INSERT INTO approver_credentials
           (organization_id, approver_id, credential_id, public_key_spki, key_class, valid_from)
         VALUES ($1, $2, $3, $4, 'A', now() - interval '1 day')
         ON CONFLICT (credential_id) DO NOTHING`,
        [ROLLOUT_TENANT_ID, approverId, credentialId, `spki-${index + 1}`],
      );
      await query(
        `INSERT INTO authorities
           (authority_id, key_id, public_key, role, status, valid_from,
            organization_id, subject_type, subject_ref, assurance_class, action_scopes)
         VALUES
           ($1, $2, $3, 'policy_admin', 'active', now() - interval '1 day',
            $4, 'human_approver', $5, 'A', ARRAY['policy_rollout'])
         ON CONFLICT (authority_id) DO NOTHING`,
        [
          authorityIds[index],
          `quorum-authority-key-${index + 1}`,
          `pk-${index + 1}`,
          ROLLOUT_TENANT_ID,
          approverId,
        ],
      );
    }

    const receiptId = `tr_${'d'.repeat(32)}`;
    const environment = 'quorum-test';
    const beforeState = { active_rollouts: [] };
    const afterState = rolloutAfterState(environment);
    const canonicalAction = {
      organization_id: ROLLOUT_TENANT_ID,
      action_type: 'policy_rollout',
      target_resource_id: 'policy:strict',
      before_state_hash: 'before-hash',
      after_state_hash: 'after-hash',
      executing_key_id: 'key-abc123',
      rollout_policy_id: ROLLOUT_POLICY_ID,
      rollout_policy_key: 'strict',
      rollout_policy_version: 2,
      rollout_policy_rules: ROLLOUT_RULES,
      rollout_policy_mode: 'mutual',
      rollout_policy_status: 'active',
      rollout_environment: environment,
      rollout_strategy: 'immediate',
      rollout_canary_pct: null,
      rollout_metadata: ROLLOUT_METADATA,
      rollout_before_state: beforeState,
      rollout_after_state: afterState,
    };
    const issuedAt = new Date().toISOString();
    await query(
      `INSERT INTO audit_events
         (event_type, actor_id, actor_type, target_type, target_id, action, after_state)
       VALUES
         ('guard.trust_receipt.created', 'ep:cloud-key:key-abc123', 'principal', 'trust_receipt', $1, 'create', $2::jsonb),
         ('guard.signoff.requested', 'ep:cloud-key:key-abc123', 'principal', 'trust_receipt', $1, 'request_signoff', $3::jsonb),
         ('guard.signoff.requested', 'ep:cloud-key:key-abc123', 'principal', 'trust_receipt', $1, 'request_signoff', $4::jsonb),
         ('guard.signoff.approved', 'quorum-approver-1', 'principal', 'trust_receipt', $1, 'approved', $5::jsonb),
         ('guard.signoff.approved', 'quorum-approver-2', 'principal', 'trust_receipt', $1, 'approved', $6::jsonb)`,
      [
        receiptId,
        JSON.stringify({
          organization_id: ROLLOUT_TENANT_ID,
          action_type: 'policy_rollout',
          target_resource_id: 'policy:strict',
          decision: 'allow_with_signoff',
          signoff_required: true,
          required_assurance: 'A',
          quorum_policy: quorumPolicy,
          action_hash: ROLLOUT_ACTION_HASH,
          before_state_hash: 'before-hash',
          after_state_hash: 'after-hash',
          expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
          canonical_action: canonicalAction,
        }),
        JSON.stringify({
          signoff_id: 'sig-quorum-1',
          quorum: { role: 'change_control', approver_id: 'quorum-approver-1', mode: 'threshold', required: 2 },
        }),
        JSON.stringify({
          signoff_id: 'sig-quorum-2',
          quorum: { role: 'security', approver_id: 'quorum-approver-2', mode: 'threshold', required: 2 },
        }),
        JSON.stringify({
          signoff_id: 'sig-quorum-1',
          approver_id: 'quorum-approver-1',
          approved_action_hash: ROLLOUT_ACTION_HASH,
          key_class: 'A',
          context: { action_hash: ROLLOUT_ACTION_HASH, issued_at: issuedAt },
          webauthn: { credential_id: 'quorum-credential-1' },
        }),
        JSON.stringify({
          signoff_id: 'sig-quorum-2',
          approver_id: 'quorum-approver-2',
          approved_action_hash: ROLLOUT_ACTION_HASH,
          key_class: 'A',
          context: { action_hash: ROLLOUT_ACTION_HASH, issued_at: new Date(Date.now() + 1000).toISOString() },
          webauthn: { credential_id: 'quorum-credential-2' },
        }),
      ],
    );

    const activated = await activateRolloutAsServiceRole({
      receiptId,
      environment,
      beforeState,
      afterState,
      authorityIds,
      quorumPolicy,
    });
    expect(activated.rows).toHaveLength(1);
    expect(activated.rows[0].authorization_authority).toMatchObject({
      quorum: true,
      policy: quorumPolicy,
    });
    expect(activated.rows[0].authorization_authority.members).toHaveLength(2);
  });
});

describe.skipIf(SKIP)('DB invariant: rollout authority administration is narrow and audited', () => {
  it('requires Class-A enrollment, grants once, and revokes in the same audit boundary', async () => {
    const approverId = 'approver-authority-admin-test';
    const credentialId = 'credential-authority-admin-test';
    await query(
      `INSERT INTO approver_credentials
         (organization_id, approver_id, credential_id, public_key_spki, key_class, valid_from)
       VALUES ($1, $2, $3, 'spki-admin-test', 'A', now() - interval '1 day')`,
      [ROLLOUT_TENANT_ID, approverId, credentialId],
    );

    const client = await getPool().connect();
    try {
      await client.query('SET ROLE service_role');
      const granted = await client.query(
        `SELECT public.grant_policy_rollout_authority(
           $1::uuid, $2, 'policy_admin', now() + interval '30 days',
           'key:key-admin-test', 'Integration test delegation'
         ) AS authority`,
        [ROLLOUT_TENANT_ID, approverId],
      );
      const authorityId = granted.rows[0].authority.authority_id;
      expect(granted.rows[0].authority).toMatchObject({
        approver_id: approverId,
        role: 'policy_admin',
        assurance_class: 'A',
        action_scopes: ['policy_rollout'],
        status: 'active',
      });

      await expect(client.query(
        `SELECT public.grant_policy_rollout_authority(
           $1::uuid, $2, 'policy_admin', now() + interval '30 days',
           'key:key-admin-test', 'Duplicate'
         )`,
        [ROLLOUT_TENANT_ID, approverId],
      )).rejects.toThrow('policy_rollout_authority_already_active');

      const revoked = await client.query(
        `SELECT public.revoke_policy_rollout_authority(
           $1::uuid, $2::uuid, 'key:key-admin-test', 'Approver changed role'
         ) AS authority`,
        [ROLLOUT_TENANT_ID, authorityId],
      );
      expect(revoked.rows[0].authority).toMatchObject({
        authority_id: authorityId,
        status: 'revoked',
      });

      const events = await client.query(
        `SELECT event_type, actor_id
         FROM audit_events
         WHERE target_type = 'authority' AND target_id = $1
         ORDER BY created_at`,
        [authorityId],
      );
      expect(events.rows).toEqual([
        { event_type: 'guard.authority.granted', actor_id: 'key:key-admin-test' },
        { event_type: 'guard.authority.revoked', actor_id: 'key:key-admin-test' },
      ]);

      const privileges = await client.query(
        `SELECT
           has_table_privilege('service_role', 'public.authorities', 'INSERT') AS service_insert,
           has_table_privilege('service_role', 'public.authorities', 'UPDATE') AS service_update,
           has_table_privilege('service_role', 'public.authorities', 'DELETE') AS service_delete`,
      );
      expect(privileges.rows[0]).toEqual({
        service_insert: false,
        service_update: false,
        service_delete: false,
      });
    } finally {
      await client.query('RESET ROLE').catch(() => {});
      client.release();
    }
  });
});

describe.skipIf(SKIP)('DB invariant: audit evidence is append-only', () => {
  it('rejects direct mutation of a recorded trust event', async () => {
    const targetId = `tr_${'e'.repeat(32)}`;
    const { rows } = await query(
      `INSERT INTO audit_events
         (event_type, actor_id, actor_type, target_type, target_id, action, after_state)
       VALUES ('guard.test.recorded', 'tester', 'system', 'trust_receipt', $1, 'record', '{}'::jsonb)
       RETURNING id`,
      [targetId],
    );
    await expect(query(
      `UPDATE audit_events SET action = 'tampered' WHERE id = $1`,
      [rows[0].id],
    )).rejects.toThrow('AUDIT_EVENT_IMMUTABILITY_VIOLATION');
    await expect(query(
      `DELETE FROM audit_events WHERE id = $1`,
      [rows[0].id],
    )).rejects.toThrow('AUDIT_EVENT_IMMUTABILITY_VIOLATION');
  });
});

describe.skipIf(SKIP)('DB invariant: SCIM tenant labels are never organization provenance', () => {
  it('backfills only a proved live binding and detaches the legacy self-org shape', async () => {
    const state = await query(
      `SELECT token_hash, organization_id, revoked_at IS NOT NULL AS revoked
         FROM public.scim_provisioning_tokens
        WHERE token_hash IN (
          'scim-valid-token-hash',
          'legacy-squatter-token-hash',
          'attacker-token-hash'
        )
        ORDER BY token_hash`,
    );
    expect(state.rows).toEqual([
      { token_hash: 'attacker-token-hash', organization_id: '@org:attacker', revoked: false },
      { token_hash: 'legacy-squatter-token-hash', organization_id: null, revoked: true },
      { token_hash: 'scim-valid-token-hash', organization_id: '@org:scim-valid', revoked: false },
    ]);
  });

  it('refuses active NULL, self-org, and live-binding-mismatched token provenance', async () => {
    const suffix = crypto.randomBytes(6).toString('hex');
    await expect(query(
      `INSERT INTO public.scim_provisioning_tokens
         (tenant_id, organization_id, token_hash, token_prefix)
       VALUES ('victim-org', NULL, $1, 'null_org')`,
      [`scim-null-${suffix}`],
    )).rejects.toThrow(/organization provenance|scim_tokens_live_org_provenance/);
    await expect(query(
      `INSERT INTO public.scim_provisioning_tokens
         (tenant_id, organization_id, token_hash, token_prefix)
       VALUES ('victim-org', 'victim-org', $1, 'self_org')`,
      [`scim-self-${suffix}`],
    )).rejects.toThrow(/organization provenance|scim_tokens_live_org_provenance/);
    await expect(query(
      `INSERT INTO public.scim_provisioning_tokens
         (tenant_id, organization_id, token_hash, token_prefix)
       VALUES ('victim-org', '@org:other', $1, 'wrong_org')`,
      [`scim-wrong-${suffix}`],
    )).rejects.toThrow(/organization provenance|live tenant/);
  });

  it('does not let a colliding tenant slug authorize directory enrollment into the victim org', async () => {
    const user = await query(
      `SELECT id FROM public.scim_users
        WHERE tenant_id = 'victim-org' AND user_name = 'cfo@victim.example'`,
    );
    const challenge = await query(
      `INSERT INTO public.webauthn_challenges
         (kind, organization_id, approver_id, challenge, expires_at)
       VALUES ('registration', 'victim-org', 'cfo@victim.example', 'squatter-challenge',
               clock_timestamp() + interval '5 minutes')
       RETURNING id`,
    );
    const completion = await query(
      `SELECT public.complete_webauthn_registration_atomic(
         $1, 'victim-org', 'cfo@victim.example', $2::jsonb
       ) AS result`,
      [challenge.rows[0].id, JSON.stringify({
        credential_id: `squatter-credential-${crypto.randomBytes(6).toString('hex')}`,
        public_key_cose: 'AQID',
        public_key_spki: 'BAUG',
        key_class: 'A',
        sign_count: 0,
        transports: ['internal'],
        enrollment_basis: 'directory',
        directory_user_id: user.rows[0].id,
      })],
    );
    expect(completion.rows[0].result).toEqual({ error: 'directory_user_inactive' });
    const durable = await query(
      `SELECT consumed_at IS NOT NULL AS consumed
         FROM public.webauthn_challenges WHERE id = $1`,
      [challenge.rows[0].id],
    );
    expect(durable.rows).toEqual([{ consumed: false }]);
  });

  it('rechecks the exact live tenant organization inside SCIM authority writes', async () => {
    const user = await query(
      `SELECT id, version FROM public.scim_users
        WHERE tenant_id = 'victim-org' AND user_name = 'cfo@victim.example'`,
    );
    const result = await query(
      `SELECT public.apply_scim_user_and_authority_atomic(
         'victim-org', 'victim-org', $1, $2, '{}'::jsonb, false, 'test'
       ) AS result`,
      [user.rows[0].id, user.rows[0].version],
    );
    expect(result.rows[0].result).toEqual({ error: 'tenant_binding_invalid' });
  });

  it('records one exact deprovision and revokes directory credentials on active rename', async () => {
    const suffix = crypto.randomBytes(8).toString('hex');
    const tenantId = `scim-lifecycle-${suffix}`;
    const organizationId = `@org:${crypto.randomUUID()}`;
    await query(
      `INSERT INTO public.entities (entity_id, organization_id, status)
       VALUES ($1, $2, 'active')`,
      [tenantId, organizationId],
    );
    const token = await query(
      `INSERT INTO public.scim_provisioning_tokens (
         tenant_id, organization_id, token_hash, token_prefix
       ) VALUES ($1, $2, $3, 'lifecycle') RETURNING id`,
      [tenantId, organizationId, crypto.randomBytes(32).toString('hex')],
    );
    const createDirectoryIdentity = async (approverId) => {
      const user = await query(
        `INSERT INTO public.scim_users (tenant_id, user_name, active)
         VALUES ($1, $2, true) RETURNING id, version`,
        [tenantId, approverId],
      );
      const credentialId = `credential-${crypto.randomBytes(8).toString('hex')}`;
      await query(
        `INSERT INTO public.approver_credentials (
           organization_id, approver_id, credential_id, public_key_spki,
           public_key_cose, key_class, sign_count, enrollment_basis,
           directory_user_id, valid_from
         ) VALUES ($1, $2, $3, 'lifecycle-spki', 'AQID', 'A', 0,
           'directory', $4, clock_timestamp() - interval '1 minute')`,
        [organizationId, approverId, credentialId, user.rows[0].id],
      );
      return { ...user.rows[0], approverId, credentialId };
    };
    const fields = (userName, active) => ({
      user_name: userName,
      external_id: '',
      active,
      formatted_name: '',
      given_name: '',
      family_name: '',
      display_name: '',
      title: '',
      emails: [],
      phone_numbers: [],
      raw: {},
    });

    const deactivated = await createDirectoryIdentity(`deactivate-${suffix}@example.com`);
    const deactivation = await query(
      `SELECT public.apply_scim_user_and_authority_atomic(
         $1::uuid, $2, $3, $4::uuid, $5, $6::jsonb, false, 'integration_deactivate'
       ) AS result`,
      [token.rows[0].id, tenantId, organizationId, deactivated.id,
        deactivated.version, JSON.stringify(fields(deactivated.approverId, false))],
    );
    expect(deactivation.rows[0].result).toMatchObject({
      status: 'updated',
      credentials_revoked: 1,
    });
    const deactivationState = await query(
      `SELECT
         (SELECT revoked_at IS NOT NULL FROM public.approver_credentials
           WHERE credential_id = $1) AS credential_revoked,
         count(*)::int AS events
       FROM public.audit_events
       WHERE event_type = 'scim.approver.deprovisioned'
         AND target_type = 'approver' AND target_id = $2`,
      [deactivated.credentialId, deactivated.approverId],
    );
    expect(deactivationState.rows[0]).toEqual({ credential_revoked: true, events: 1 });

    const renamed = await createDirectoryIdentity(`rename-${suffix}@example.com`);
    const replacement = `renamed-${suffix}@example.com`;
    const rename = await query(
      `SELECT public.apply_scim_user_and_authority_atomic(
         $1::uuid, $2, $3, $4::uuid, $5, $6::jsonb, false, 'integration_rename'
       ) AS result`,
      [token.rows[0].id, tenantId, organizationId, renamed.id,
        renamed.version, JSON.stringify(fields(replacement, true))],
    );
    expect(rename.rows[0].result).toMatchObject({ status: 'updated' });
    const renameState = await query(
      `SELECT
         (SELECT revoked_at IS NOT NULL FROM public.approver_credentials
           WHERE credential_id = $1) AS credential_revoked,
         count(*)::int AS events,
         max(after_state ->> 'reason') AS reason
       FROM public.audit_events
       WHERE event_type = 'scim.approver.deprovisioned'
         AND target_type = 'approver' AND target_id = $2`,
      [renamed.credentialId, renamed.approverId],
    );
    expect(renameState.rows[0]).toEqual({
      credential_revoked: true,
      events: 1,
      reason: 'scim_username_changed',
    });
  });
});

describe.skipIf(SKIP)('DB invariant: mobile pairing is bound to the named directory identity', () => {
  it('refuses wrong org, wrong approver, and counter replay while exact proof succeeds once', async () => {
    const suffix = crypto.randomBytes(8).toString('hex');
    const entityRef = `mobile-entity-${suffix}`;
    const organizationId = `@org:${crypto.randomUUID()}`;
    const approverId = `mobile.approver.${suffix}@example.com`;
    const credentialId = `credential-mobile-${suffix}`;
    const appId = 'ai.emiliaprotocol.approver';
    await query(
      `INSERT INTO public.entities (entity_id, organization_id, status)
       VALUES ($1, $2, 'active')`,
      [entityRef, organizationId],
    );
    const directoryUser = await query(
      `INSERT INTO public.scim_users (tenant_id, user_name, active)
       VALUES ($1, $2, true) RETURNING id`,
      [entityRef, approverId],
    );
    await query(
      `INSERT INTO public.scim_provisioning_tokens (
         tenant_id, organization_id, token_hash, token_prefix
       ) VALUES ($1, $2, $3, 'mobile_test')`,
      [entityRef, organizationId, crypto.randomBytes(32).toString('hex')],
    );
    await query(
      `INSERT INTO public.approver_credentials (
         organization_id, approver_id, credential_id, public_key_spki,
         public_key_cose, key_class, sign_count, enrollment_basis,
         directory_user_id, valid_from
       ) VALUES ($1, $2, $3, 'test-spki', 'AQID', 'A', 0, 'directory', $4, now() - interval '1 minute')`,
      [organizationId, approverId, credentialId, directoryUser.rows[0].id],
    );
    const codeHash = crypto.randomBytes(32).toString('hex');
    await query(
      `INSERT INTO public.mobile_pairings (
         code_hash, entity_ref, organization_id, approver_id, directory_user_id,
         profile_id, allowed_apps,
         expires_at, session_expires_at
       ) VALUES ($1, $2, $3, $4, $5, 'profile-1', $6::jsonb,
         now() + interval '5 minutes', now() + interval '1 day')`,
      [codeHash, entityRef, organizationId, approverId, directoryUser.rows[0].id,
        JSON.stringify({ ios: [appId], android: [] })],
    );
    const exchange = (tokenHash, expectedApprover, candidateCredential, counter) => query(
      `SELECT public.exchange_mobile_pairing_verified(
         $1, $2, 'ios', $3, $4, $5, $6, $7
       ) AS result`,
      [codeHash, tokenHash, appId, candidateCredential, expectedApprover, counter,
        `sha256:${'a'.repeat(64)}`],
    );

    const wrongApprover = await exchange(
      crypto.randomBytes(32).toString('hex'),
      'attacker@example.com',
      credentialId,
      5,
    );
    expect(wrongApprover.rows[0].result).toMatchObject({ ok: false, reason: 'approver_mismatch' });

    const wrongOrgCredential = `credential-wrong-org-${suffix}`;
    await query(
      `INSERT INTO public.approver_credentials (
         organization_id, approver_id, credential_id, public_key_spki,
         public_key_cose, key_class, sign_count, enrollment_basis,
         directory_user_id, valid_from
       ) VALUES ('@org:wrong', $1, $2, 'test-spki', 'AQID', 'A', 0,
         'directory', $3, now() - interval '1 minute')`,
      [approverId, wrongOrgCredential, crypto.randomUUID()],
    );
    const wrongOrg = await exchange(
      crypto.randomBytes(32).toString('hex'),
      approverId,
      wrongOrgCredential,
      5,
    );
    expect(wrongOrg.rows[0].result).toMatchObject({ ok: false, reason: 'identity_not_active' });

    const success = await exchange(
      crypto.randomBytes(32).toString('hex'),
      approverId,
      credentialId,
      5,
    );
    expect(success.rows[0].result).toMatchObject({ ok: true, approver_id: approverId });
    const codeReplay = await exchange(
      crypto.randomBytes(32).toString('hex'),
      approverId,
      credentialId,
      6,
    );
    expect(codeReplay.rows[0].result).toMatchObject({ ok: false, reason: 'invalid_or_consumed' });

    const secondCodeHash = crypto.randomBytes(32).toString('hex');
    await query(
      `INSERT INTO public.mobile_pairings (
         code_hash, entity_ref, organization_id, approver_id, directory_user_id,
         profile_id, allowed_apps,
         expires_at, session_expires_at
       ) VALUES ($1, $2, $3, $4, $5, 'profile-1', $6::jsonb,
         now() + interval '5 minutes', now() + interval '1 day')`,
      [secondCodeHash, entityRef, organizationId, approverId, directoryUser.rows[0].id,
        JSON.stringify({ ios: [appId], android: [] })],
    );
    const counterReplay = await query(
      `SELECT public.exchange_mobile_pairing_verified(
         $1, $2, 'ios', $3, $4, $5, 5, $6
       ) AS result`,
      [secondCodeHash, crypto.randomBytes(32).toString('hex'), appId, credentialId,
        approverId, `sha256:${'b'.repeat(64)}`],
    );
    expect(counterReplay.rows[0].result).toMatchObject({ ok: false, reason: 'credential_counter_replay' });
    const state = await query(
      `SELECT
         (SELECT count(*)::int FROM public.mobile_sessions WHERE entity_ref = $1) AS sessions,
         (SELECT consumed_at IS NULL FROM public.mobile_pairings WHERE code_hash = $2) AS replay_code_unconsumed,
         (SELECT sign_count::int FROM public.approver_credentials WHERE credential_id = $3) AS sign_count`,
      [entityRef, secondCodeHash, credentialId],
    );
    expect(state.rows[0]).toEqual({ sessions: 1, replay_code_unconsumed: true, sign_count: 5 });
  });

  it('rechecks deprovisioning after request-time touch inside the terminal action commit', async () => {
    const suffix = crypto.randomBytes(8).toString('hex');
    const fixture = await insertMobileIdentityRuntimeFixture(suffix);
    const touch = await query(
      `SELECT public.touch_mobile_session_verified($1::uuid, $2) AS active`,
      [fixture.sessionId, fixture.tokenHash],
    );
    expect(touch.rows[0].active).toBe(true);

    // Prove the wrapper admits the same fully-bound state machine while the
    // exact directory identity is active.
    const baseline = await insertMobilePendingAction(fixture, `${suffix}-baseline`);
    const baselineChallenge = await query(
      `SELECT public.register_mobile_action_challenge(
         $1, $2::uuid, $3, $4, $5, $6, 'approved',
         clock_timestamp() + interval '5 minutes'
       ) AS registered`,
      [fixture.entityRef, fixture.sessionId, baseline.actionReference,
        fixture.approverId, baseline.challengeId, baseline.actionHash],
    );
    expect(baselineChallenge.rows[0].registered).toBe(true);
    const baselineCommit = buildMobileDecisionCommit(fixture, baseline);
    const baselineResult = await commitMobileDecisionAsServiceRole(
      fixture,
      baseline,
      baselineCommit,
    );
    expect(baselineResult.rows[0].result).toEqual({ ok: true });

    const pending = await insertMobilePendingAction(fixture, `${suffix}-pending`);
    const requestTimeTouch = await query(
      `SELECT public.touch_mobile_session_verified($1::uuid, $2) AS active`,
      [fixture.sessionId, fixture.tokenHash],
    );
    expect(requestTimeTouch.rows[0].active).toBe(true);
    const pendingChallenge = await query(
      `SELECT public.register_mobile_action_challenge(
         $1, $2::uuid, $3, $4, $5, $6, 'approved',
         clock_timestamp() + interval '5 minutes'
       ) AS registered`,
      [fixture.entityRef, fixture.sessionId, pending.actionReference,
        fixture.approverId, pending.challengeId, pending.actionHash],
    );
    expect(pendingChallenge.rows[0].registered).toBe(true);

    const deprovisionFields = {
      user_name: fixture.approverId,
      external_id: '',
      active: false,
      formatted_name: '',
      given_name: '',
      family_name: '',
      display_name: '',
      title: '',
      emails: [],
      phone_numbers: [],
      raw: {},
    };
    const deprovisioned = await query(
      `SELECT public.apply_scim_user_and_authority_atomic(
         $1::uuid, $2, $3, $4::uuid, $5, $6::jsonb, false,
         'mobile_commit_deprovision'
       ) AS result`,
      [fixture.scimTokenId, fixture.entityRef, fixture.organizationId,
        fixture.directoryUserId, fixture.directoryUserVersion,
        JSON.stringify(deprovisionFields)],
    );
    expect(deprovisioned.rows[0].result).toMatchObject({
      status: 'updated',
      credentials_revoked: 1,
    });

    const refusedCommit = buildMobileDecisionCommit(fixture, pending, {
      previousHash: baselineCommit.hash,
      sequence: 1,
    });
    const refused = await commitMobileDecisionAsServiceRole(fixture, pending, refusedCommit);
    expect(refused.rows[0].result).toEqual({ ok: false, reason: 'session_inactive' });
    const state = await query(
      `SELECT
         (SELECT status FROM public.mobile_actions
           WHERE entity_ref = $1 AND action_reference = $2) AS action_status,
         (SELECT consumed_at IS NULL FROM public.mobile_action_challenges
           WHERE challenge_id = $3) AS challenge_unconsumed,
         (SELECT count(*)::int FROM public.mobile_evidence_records
           WHERE record_id = $4) AS refused_records,
         (SELECT revoked_at IS NOT NULL FROM public.mobile_sessions
           WHERE session_id = $5::uuid) AS session_revoked`,
      [fixture.entityRef, pending.actionReference, pending.challengeId,
        refusedCommit.record.record_id, fixture.sessionId],
    );
    expect(state.rows[0]).toEqual({
      action_status: 'pending',
      challenge_unconsumed: true,
      refused_records: 0,
      session_revoked: true,
    });
  });

  it('refuses terminal action commit after its exact Class-A credential expires', async () => {
    const suffix = crypto.randomBytes(8).toString('hex');
    const fixture = await insertMobileIdentityRuntimeFixture(suffix);
    const action = await insertMobilePendingAction(fixture, `${suffix}-expiry`);
    const requestTimeTouch = await query(
      `SELECT public.touch_mobile_session_verified($1::uuid, $2) AS active`,
      [fixture.sessionId, fixture.tokenHash],
    );
    expect(requestTimeTouch.rows[0].active).toBe(true);
    const challenge = await query(
      `SELECT public.register_mobile_action_challenge(
         $1, $2::uuid, $3, $4, $5, $6, 'approved',
         clock_timestamp() + interval '5 minutes'
       ) AS registered`,
      [fixture.entityRef, fixture.sessionId, action.actionReference,
        fixture.approverId, action.challengeId, action.actionHash],
    );
    expect(challenge.rows[0].registered).toBe(true);

    await query(
      `UPDATE public.approver_credentials
          SET valid_to = clock_timestamp() - interval '1 millisecond'
        WHERE credential_id = $1`,
      [fixture.identityCredentialId],
    );
    const decision = buildMobileDecisionCommit(fixture, action);
    const refused = await commitMobileDecisionAsServiceRole(fixture, action, decision);
    expect(refused.rows[0].result).toEqual({ ok: false, reason: 'session_inactive' });
    const state = await query(
      `SELECT
         (SELECT status FROM public.mobile_actions
           WHERE entity_ref = $1 AND action_reference = $2) AS action_status,
         (SELECT consumed_at IS NULL FROM public.mobile_action_challenges
           WHERE challenge_id = $3) AS challenge_unconsumed,
         (SELECT count(*)::int FROM public.mobile_evidence_records
           WHERE record_id = $4) AS refused_records,
         (SELECT revoked_at IS NOT NULL FROM public.mobile_sessions
           WHERE session_id = $5::uuid) AS session_revoked`,
      [fixture.entityRef, action.actionReference, action.challengeId,
        decision.record.record_id, fixture.sessionId],
    );
    expect(state.rows[0]).toEqual({
      action_status: 'pending',
      challenge_unconsumed: true,
      refused_records: 0,
      session_revoked: true,
    });
  });
});

describe.skipIf(SKIP)('DB invariant: issuer authority is rechecked under the presentation write', () => {
  it('admits an exact active authority and downgrades UUID/key mismatch and stale authority', async () => {
    const suffix = crypto.randomBytes(8).toString('hex');
    const authorityId = crypto.randomUUID();
    const keyId = `issuer-key-${suffix}`;
    await query(
      `INSERT INTO public.authorities (
         authority_id, key_id, public_key, algorithm, role, status, valid_from
       ) VALUES ($1, $2, 'issuer-public-key', 'Ed25519', 'issuer', 'active', now() - interval '1 minute')`,
      [authorityId, keyId],
    );
    const keyDigest = `sha256:${crypto.createHash('sha256').update('issuer-public-key').digest('hex')}`;
    const present = async (storedAuthorityId, hash) => {
      const { rows: handshakeRows } = await query(
        `INSERT INTO public.handshakes (nonce, status)
         VALUES ($1, 'initiated') RETURNING handshake_id`,
        [`issuer-proof-${suffix}-${crypto.randomBytes(4).toString('hex')}`],
      );
      const handshakeId = handshakeRows[0].handshake_id;
      await query(
        `INSERT INTO public.handshake_parties (handshake_id, entity_ref, party_role)
         VALUES ($1, 'entity-issuer', 'initiator')`,
        [handshakeId],
      );
      const result = await query(
        `SELECT public.present_handshake_writes(
         $1::uuid, 'initiator', 'verifiable_credential', $2, $3, 'full',
         '{"name":"Alice"}'::jsonb, '{"name":"Alice"}'::jsonb, $4,
         'entity-issuer', $5, $6, 'authority_signature_valid', true, true, 'good',
         'entity-issuer', true,
         $7::jsonb
         ) AS result`,
        [handshakeId, keyId, hash, crypto.randomBytes(32).toString('hex'),
          storedAuthorityId, keyDigest, JSON.stringify({
          issuer_proof_profile: 'EP-HANDSHAKE-ISSUER-PROOF-v1',
          issuer_proof_digest: `sha256:${'c'.repeat(64)}`,
          issuer_proof: { profile: 'EP-HANDSHAKE-ISSUER-PROOF-v1', signature: 'test' },
          issuer_proof_statement: { handshake_id: handshakeId, presentation_hash: hash },
          })],
      );
      return { handshakeId, result };
    };

    const exact = await present(authorityId, `presentation-exact-${suffix}`);
    expect(exact.result.rows[0].result).toMatchObject({
      verified: true,
      issuer_status: 'authority_signature_valid',
      revocation_status: 'good',
    });
    const mismatch = await present(crypto.randomUUID(), `presentation-mismatch-${suffix}`);
    expect(mismatch.result.rows[0].result).toMatchObject({
      verified: false,
      issuer_status: 'authority_identity_mismatch_at_write',
    });
    await query(
      `UPDATE public.authorities SET status = 'revoked', revoked_at = now()
       WHERE authority_id = $1`,
      [authorityId],
    );
    const stale = await present(authorityId, `presentation-stale-${suffix}`);
    expect(stale.result.rows[0].result).toMatchObject({
      verified: false,
      issuer_status: 'authority_not_active_at_write',
    });
    const stored = await query(
      `SELECT issuer_status, verified FROM public.handshake_presentations
       WHERE handshake_id = ANY($1::uuid[]) ORDER BY id`,
      [[exact.handshakeId, mismatch.handshakeId, stale.handshakeId]],
    );
    expect(stored.rows.filter((row) => row.verified)).toHaveLength(1);
  });
});
