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

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const SCHEMA_FILE = path.join(__dirname, 'fixtures/integration-schema.sql');
const ORG_QUORUM_MIGRATION_FILE = path.join(
  __dirname,
  '../supabase/migrations/124_org_quorum_policies.sql',
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
const SKIP = !process.env.INTEGRATION_POSTGRES;

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

async function insertHandshake() {
  const nonce = `nonce-${Math.random().toString(36).slice(2)}`;
  const { rows } = await query(
    `INSERT INTO handshakes (nonce, status) VALUES ($1, 'verified') RETURNING handshake_id`,
    [nonce],
  );
  return rows[0].handshake_id;
}

async function insertBinding(handshakeId, { consumed = false } = {}) {
  const { rows } = await query(
    `INSERT INTO handshake_bindings (handshake_id, payload_hash, nonce, expires_at, consumed_at)
     VALUES ($1, $2, $3, now() + interval '1 hour', $4) RETURNING id`,
    [handshakeId, 'phash-abc', `bnonce-${Math.random().toString(36).slice(2)}`,
     consumed ? new Date() : null],
  );
  return rows[0].id;
}

async function insertChallenge(bindingId) {
  const { rows } = await query(
    `INSERT INTO signoff_challenges (handshake_id, binding_hash, status, expires_at)
     VALUES ($1, $2, 'challenge_issued', now() + interval '10 minutes') RETURNING challenge_id`,
    [bindingId, 'bhash-xyz'],
  );
  return rows[0].challenge_id;
}

async function insertAttestation(challengeId, bindingId) {
  const { rows } = await query(
    `INSERT INTO signoff_attestations (challenge_id, handshake_id, binding_hash, auth_method)
     VALUES ($1, $2, $3, 'passkey') RETURNING signoff_id`,
    [challengeId, bindingId, 'bhash-xyz'],
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
// ── 4. Signoff challenge status: forward-only transitions ────────────────────
// ---------------------------------------------------------------------------

describe.skipIf(SKIP)('DB invariant: signoff challenge status is forward-only', () => {
  it('allows forward transitions: issued → viewed → approved', async () => {
    const hId = await insertHandshake();
    const bId = await insertBinding(hId);
    const cId = await insertChallenge(bId);

    await query(
      `UPDATE signoff_challenges SET status = 'challenge_viewed' WHERE challenge_id = $1`,
      [cId],
    );
    await query(
      `UPDATE signoff_challenges SET status = 'approved' WHERE challenge_id = $1`,
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
      `UPDATE signoff_challenges SET status = 'approved' WHERE challenge_id = $1`, [cId],
    );

    await expect(
      query(
        `UPDATE signoff_challenges SET status = 'challenge_issued' WHERE challenge_id = $1`,
        [cId],
      ),
    ).rejects.toThrow('SIGNOFF_BACKWARD_TRANSITION');
  });

  it('blocks backward transition: consumed → approved', async () => {
    const hId = await insertHandshake();
    const bId = await insertBinding(hId);
    const cId = await insertChallenge(bId);

    await query(
      `UPDATE signoff_challenges SET status = 'approved' WHERE challenge_id = $1`, [cId],
    );
    await query(
      `UPDATE signoff_challenges SET status = 'consumed' WHERE challenge_id = $1`, [cId],
    );

    await expect(
      query(
        `UPDATE signoff_challenges SET status = 'approved' WHERE challenge_id = $1`,
        [cId],
      ),
    ).rejects.toThrow('SIGNOFF_BACKWARD_TRANSITION');
  });

  it('allows terminal denial: issued → denied', async () => {
    const hId = await insertHandshake();
    const bId = await insertBinding(hId);
    const cId = await insertChallenge(bId);

    await query(
      `UPDATE signoff_challenges SET status = 'denied' WHERE challenge_id = $1`, [cId],
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
      `UPDATE signoff_challenges SET status = 'revoked' WHERE challenge_id = $1`, [cId],
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
      `UPDATE signoff_challenges SET status = 'approved' WHERE challenge_id = $1`, [cId],
    );
    await expect(
      query(
        `UPDATE signoff_challenges SET status = 'challenge_viewed' WHERE challenge_id = $1`,
        [cId],
      ),
    ).rejects.toThrow('SIGNOFF_BACKWARD_TRANSITION');
  });
});

// ---------------------------------------------------------------------------
// ── 5. Handshake nonce uniqueness ───────────────────────────────────────────
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
          quorum_policy: null,
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
