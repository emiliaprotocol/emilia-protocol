// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGate, createEg1Harness } from '../index.js';
import {
  createSupabaseManifest, guardSupabaseMutation, SUPABASE_OPS, isDestructiveSql, statementHash,
} from './supabase.js';

function fakeDb() {
  const calls = [];
  return {
    calls,
    query: async (sql) => { calls.push(['query', sql]); return { rowCount: 1 }; },
    export: async (table, recipient) => { calls.push(['export', table, recipient]); return { ok: true }; },
    alterPolicy: async (table, policy, def) => { calls.push(['rls', table, policy, def]); return { ok: true }; },
  };
}
function setup(action) {
  const harness = createEg1Harness({ action });
  return { harness, gate: createGate({ manifest: createSupabaseManifest(), trustedKeys: [harness.publicKey], approverKeys: harness.approverKeys }), db: fakeDb() };
}

const SQL = 'DELETE FROM payments WHERE id = 1';
const SQL_ACTION = { action_type: 'supabase.sql.destructive', statement_hash: statementHash(SQL) };

test('isDestructiveSql flags the dangerous shapes', () => {
  assert.equal(isDestructiveSql('DELETE FROM t WHERE id=1'), true);
  assert.equal(isDestructiveSql('drop table t'), true);
  assert.equal(isDestructiveSql('TRUNCATE t'), true);
  assert.equal(isDestructiveSql('UPDATE t SET x=1'), true); // no WHERE
  assert.equal(isDestructiveSql('SELECT * FROM t'), false);
  assert.equal(isDestructiveSql('UPDATE t SET x=1 WHERE id=2'), false);
});

test('exposes the destructive Supabase ops', () => {
  assert.deepEqual([...SUPABASE_OPS].sort(), ['data.export', 'rls.change', 'sql.destructive']);
});

test('destructive SQL WITHOUT a receipt never executes', async () => {
  const { gate, db } = setup(SQL_ACTION);
  await assert.rejects(
    () => guardSupabaseMutation(gate, db, { op: 'sql.destructive', params: { sql: SQL } }),
    (e) => e.code === 'EMILIA_RECEIPT_REQUIRED' && e.status === 428,
  );
  assert.equal(db.calls.length, 0);
});

test('destructive SQL WITH a valid Class-A receipt executes the exact statement', async () => {
  const { gate, harness, db } = setup(SQL_ACTION);
  const { result, reliance } = await guardSupabaseMutation(gate, db, {
    op: 'sql.destructive', params: { sql: SQL }, receipt: harness.mint({ outcome: 'allow_with_signoff' }),
  });
  assert.equal(result.rowCount, 1);
  assert.deepEqual(db.calls[0], ['query', SQL]);
  assert.equal(String(reliance.verdict).toLowerCase(), 'rely');
});

test('a receipt for one statement cannot authorize a different statement (drift)', async () => {
  const { gate, harness, db } = setup(SQL_ACTION); // authorizes the DELETE
  const receipt = harness.mint({ outcome: 'allow_with_signoff' });
  await assert.rejects(
    () => guardSupabaseMutation(gate, db, { op: 'sql.destructive', params: { sql: 'DROP TABLE payments' }, receipt }),
    (e) => /binding/.test(e.gate.reason),
  );
  assert.equal(db.calls.length, 0);
});

test('RLS policy change requires quorum', async () => {
  const action = { action_type: 'supabase.rls.change', table: 'payments', policy: 'allow_all' };
  const { gate, harness, db } = setup(action);
  const params = { table: 'payments', policy: 'allow_all', definition: 'USING (true)' };
  await assert.rejects(
    () => guardSupabaseMutation(gate, db, { op: 'rls.change', params, receipt: harness.mint({ outcome: 'allow_with_signoff' }) }),
    (e) => /assurance/.test(e.gate.reason),
  );
  const quorum = harness.mint({ outcome: 'allow_with_signoff', quorum: { signers: ['ep:a', 'ep:b'], threshold: 2 } });
  const { result } = await guardSupabaseMutation(gate, db, { op: 'rls.change', params, receipt: quorum });
  assert.equal(result.ok, true);
});
