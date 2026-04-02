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

async function insertReceipt(entityId, submittedBy = 'submitter-1') {
  const { rows } = await query(
    `INSERT INTO receipts (entity_id, submitted_by, composite_score, receipt_hash)
     VALUES ($1, $2, $3, $4) RETURNING id`,
    [entityId, submittedBy, 88, `hash-${Math.random().toString(36).slice(2)}`],
  );
  return rows[0].id;
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

// ---------------------------------------------------------------------------
// ── 1. Receipts: append-only ─────────────────────────────────────────────────
// ---------------------------------------------------------------------------

describe.skipIf(SKIP)('DB invariant: receipts are append-only', () => {
  it('allows inserting a receipt', async () => {
    await insertEntity('ent-receipt-1');
    const id = await insertReceipt('ent-receipt-1');
    expect(id).toBeTruthy();
  });

  it('blocks UPDATE on a receipt', async () => {
    await insertEntity('ent-receipt-2');
    const id = await insertReceipt('ent-receipt-2');
    await expect(
      query(`UPDATE receipts SET composite_score = 99 WHERE id = $1`, [id]),
    ).rejects.toThrow('RECEIPT_IMMUTABLE');
  });

  it('blocks DELETE on a receipt', async () => {
    await insertEntity('ent-receipt-3');
    const id = await insertReceipt('ent-receipt-3');
    await expect(
      query(`DELETE FROM receipts WHERE id = $1`, [id]),
    ).rejects.toThrow('RECEIPT_IMMUTABLE');
  });

  it('allows multiple receipts for the same entity (ledger grows)', async () => {
    await insertEntity('ent-receipt-4');
    await insertReceipt('ent-receipt-4', 'submitter-a');
    await insertReceipt('ent-receipt-4', 'submitter-b');
    await insertReceipt('ent-receipt-4', 'submitter-c');
    const { rows } = await query(
      `SELECT count(*) FROM receipts WHERE entity_id = $1`, ['ent-receipt-4'],
    );
    expect(parseInt(rows[0].count, 10)).toBe(3);
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
});
