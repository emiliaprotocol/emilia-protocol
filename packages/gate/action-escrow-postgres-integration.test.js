// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ACTION_ESCROW_PROFILE_VERSION,
  createActionEscrowKernel,
} from './action-escrow.js';
import {
  ACTION_ESCROW_STATE_SQL,
  createActionEscrowPostgresStore,
} from './action-escrow-postgres.js';

const digest = (character) => `sha256:${character.repeat(64)}`;
const parties = Object.freeze([
  Object.freeze({ party_id: 'ep:principal:client', role: 'client' }),
  Object.freeze({ party_id: 'ep:principal:contractor', role: 'contractor' }),
]);
const profile = Object.freeze({
  '@version': ACTION_ESCROW_PROFILE_VERSION,
  profile_id: 'postgres-integration',
  provider_id: 'licensed-custodian.test',
  required_acceptance_party_ids: parties.map(({ party_id }) => party_id),
  required_release_approver_party_ids: parties.map(({ party_id }) => party_id),
  prohibit_self_approval: false,
});

function fakePostgres() {
  const records = new Map();
  let available = true;
  let loseNextResponse = false;
  return {
    records,
    setAvailable(value) { available = value; },
    loseNextResponse() { loseNextResponse = true; },
    async query(text, params) {
      if (!available) throw new Error('database unavailable');
      let result;
      if (text === ACTION_ESCROW_STATE_SQL.read) {
        result = records.has(params[0])
          ? { rowCount: 1, rows: [{ ...records.get(params[0]) }] }
          : { rowCount: 0, rows: [] };
      } else if (text === ACTION_ESCROW_STATE_SQL.create) {
        if (records.has(params[0])) {
          result = { rowCount: 0, rows: [] };
        } else {
          records.set(params[0], { revision: 0, record_json: params[1] });
          result = { rowCount: 1, rows: [{ revision: 0 }] };
        }
      } else if (text === ACTION_ESCROW_STATE_SQL.compareAndSwap) {
        if (records.get(params[0])?.revision !== params[1]) {
          result = { rowCount: 0, rows: [] };
        } else {
          records.set(params[0], { revision: params[2], record_json: params[3] });
          result = { rowCount: 1, rows: [{ revision: params[2] }] };
        }
      } else if (text === ACTION_ESCROW_STATE_SQL.health) {
        result = { rowCount: 1, rows: [{ table_ready: true, can_use: true }] };
      } else {
        throw new Error('unexpected SQL');
      }
      if (loseNextResponse) {
        loseNextResponse = false;
        throw new Error('response lost after commit');
      }
      return result;
    },
  };
}

function input(idempotencyKey) {
  return {
    agreement_digest: digest('a'),
    document_action_binding_digest: digest('b'),
    milestone_id: 'milestone-01',
    release_action_digest: digest('c'),
    parties,
    profile,
    idempotency_key: idempotencyKey,
  };
}

function kernelWith(pg) {
  const store = createActionEscrowPostgresStore({
    query: pg.query.bind(pg),
    now: () => 1_768_521_600_000,
  });
  const neverCalled = async () => {
    throw new Error('unexpected verifier or provider call');
  };
  return createActionEscrowKernel({
    store,
    provider: { release: neverCalled, getRelease: neverCalled },
    profilesById: { [profile.profile_id]: profile },
    now: () => '2026-01-17T00:00:00.000Z',
    async verifyDocumentActionBinding(_artifact, expected) {
      return {
        valid: true,
        verification_digest: digest('d'),
        agreement_digest: expected.agreement_digest,
        document_action_binding_digest: expected.document_action_binding_digest,
        milestone_id: expected.milestone_id,
        release_action_digest: expected.release_action_digest,
        parties_digest: expected.parties_digest,
        profile_digest: expected.profile_digest,
      };
    },
    verifyAgreementAcceptance: neverCalled,
    verifyMilestoneEvidence: neverCalled,
    verifyResolutionReceipt: neverCalled,
    verifyProviderStatement: neverCalled,
  });
}

test('the production kernel persists and races transitions through the Postgres contract', async () => {
  const pg = fakePostgres();
  const kernel = kernelWith(pg);
  const created = await kernel.create({
    ...input('create'),
    document_action_binding: { artifact: 'test' },
  });
  assert.equal(created.ok, true);
  assert.equal(created.state, 'draft');
  assert.equal(created.revision, 0);

  const attempts = await Promise.all(
    Array.from(
      { length: 32 },
      (_, index) => kernel.beginAcceptance(input(`begin-${index}`)),
    ),
  );
  assert.equal(
    attempts.filter((result) => result.code === 'acceptance_requested').length,
    1,
  );
  const stored = [...pg.records.values()][0];
  assert.equal(stored.revision, 1);
  assert.equal(JSON.parse(stored.record_json).state, 'awaiting_acceptance');
});

test('a lost create acknowledgement is recovered idempotently from committed state', async () => {
  const pg = fakePostgres();
  const kernel = kernelWith(pg);
  pg.loseNextResponse();
  const first = await kernel.create({
    ...input('create-response-loss'),
    document_action_binding: { artifact: 'test' },
  });
  assert.equal(first.ok, false);
  assert.equal(first.code, 'store_unavailable');

  const recovered = await kernel.create({
    ...input('create-response-loss'),
    document_action_binding: { artifact: 'test' },
  });
  assert.equal(recovered.ok, true);
  assert.equal(recovered.code, 'escrow_created');
  assert.equal(recovered.state, 'draft');
  assert.equal(pg.records.size, 1);
});

test('database outage returns a closed verdict instead of creating an in-memory fallback', async () => {
  const pg = fakePostgres();
  const kernel = kernelWith(pg);
  pg.setAvailable(false);
  const refused = await kernel.create({
    ...input('create-outage'),
    document_action_binding: { artifact: 'test' },
  });
  assert.equal(refused.ok, false);
  assert.equal(refused.code, 'store_unavailable');
  assert.equal(pg.records.size, 0);
});
