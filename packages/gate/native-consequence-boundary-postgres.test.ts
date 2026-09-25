// SPDX-License-Identifier: Apache-2.0
// The shipped PostgreSQL consumption store backing the direct-native
// consequence boundary, driven through a deterministic fake of the store's
// exact SQL. Commit and release are fenced by owner tokens that live only in
// the store instance that reserved the row, so a "restart" here is a new store
// instance over the same fake database.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { digestAeb } from '@emilia-protocol/verify/aeb-adapter-contract';
import {
  AEB_NATIVE_AUTHORIZATION_GATEWAY_KEY_VERSION,
  AEB_NATIVE_AUTHORIZATION_PINS_VERSION,
  AEB_NATIVE_AUTHORIZATION_SOURCE_PIN_VERSION,
  AEB_NATIVE_AUTHORIZATION_STATUS_VERSION,
  issueAebNativeAuthorizationHandoff,
} from '@emilia-protocol/verify/aeb';
import {
  AEB_CONSUMPTION_DDL,
  AEB_CONSUMPTION_SQL,
  createPostgresAebDurableConsumptionStore,
  type AebRecoveryClaimAuthorization,
} from './aeb-consumption-store.js';
import {
  createNativeConsequenceBoundary,
  nativeConsequenceBoundaryActionFenceHolderKey,
  nativeConsequenceBoundaryReservationKey,
  type ConsequenceBoundaryAttemptBinding,
  type ConsequenceBoundaryAttemptReference,
  type ConsequenceBoundaryProviderEvidence,
} from './consequence-boundary.js';

const TENANT = 'tenant:acme';
const RELYING_PARTY = 'rp:payments';
const EXECUTOR = 'executor:gate-1';
const NOW = '2026-08-09T12:00:01.000Z';
const PROVIDER = Object.freeze({
  tenant_id: TENANT,
  provider_id: 'provider:bank',
  provider_account_id: 'account:one',
  environment: 'sandbox',
});
const ACTION = Object.freeze({
  action_type: 'payment.release.1',
  transfer_id: 'transfer-1',
  amount: '500.00',
  currency: 'USD',
});

type Row = { state: 'RESERVED' | 'CONSUMED' | 'RELEASED_NOT_ENTERED'; ownerToken: string | null };
type Db = { operations: Map<string, Row>; replays: Map<string, string> };

function scoped(tenantId: string, relyingPartyId: string, key: string) {
  return JSON.stringify([tenantId, relyingPartyId, key]);
}

function cloneDb(db: Db): Db {
  return {
    operations: new Map([...db.operations].map(([key, row]) => [key, { ...row }])),
    replays: new Map(db.replays),
  };
}

/** Deterministic, serializable fake of exactly the SQL the store issues. */
function fakePostgres() {
  let committed: Db = { operations: new Map(), replays: new Map() };
  let tail = Promise.resolve();
  const statements: string[] = [];
  let failOperationState = 0;

  async function lock(): Promise<() => void> {
    let release!: () => void;
    const turn = new Promise<void>((resolve) => { release = resolve; });
    const previous = tail;
    tail = previous.then(() => turn);
    await previous;
    return release;
  }

  const pool = {
    async connect() {
      let transaction: Db | null = null;
      let unlock: (() => void) | null = null;
      return {
        async query(text: string, params: any[] = []) {
          await Promise.resolve();
          statements.push(text);
          if (text === 'BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE') {
            unlock = await lock();
            transaction = cloneDb(committed);
            return { rowCount: 0, rows: [] };
          }
          if (text === 'COMMIT') {
            committed = transaction!;
            transaction = null;
            unlock?.();
            return { rowCount: 0, rows: [] };
          }
          if (text === 'ROLLBACK') {
            transaction = null;
            unlock?.();
            return { rowCount: 0, rows: [] };
          }
          const [tenantId, relyingPartyId, key, fourth] = params;
          if (text === AEB_CONSUMPTION_SQL.operationState) {
            if (failOperationState > 0) {
              failOperationState -= 1;
              throw new Error('pg_unavailable');
            }
            const row = (transaction ?? committed).operations.get(scoped(tenantId, relyingPartyId, key));
            return { rowCount: 1, rows: [{ state: row?.state ?? 'AVAILABLE' }] };
          }
          if (text === AEB_CONSUMPTION_SQL.hasReplayFence) {
            return {
              rowCount: 1,
              rows: [{ fenced: (transaction ?? committed).replays.has(scoped(tenantId, relyingPartyId, key)) }],
            };
          }
          assert.ok(transaction, `statement outside a transaction: ${text}`);
          const id = scoped(tenantId, relyingPartyId, key);
          const row = transaction.operations.get(id);
          if (text === AEB_CONSUMPTION_SQL.reserveOperation) {
            if (row) return { rowCount: 0, rows: [] };
            transaction.operations.set(id, { state: 'RESERVED', ownerToken: fourth });
            return { rowCount: 1, rows: [{ operation_key: key }] };
          }
          if (text === AEB_CONSUMPTION_SQL.reserveReplayKeys) {
            let inserted = 0;
            for (const replayKey of fourth as string[]) {
              const replayId = scoped(tenantId, relyingPartyId, replayKey);
              if (transaction.replays.has(replayId)) continue;
              transaction.replays.set(replayId, key);
              inserted += 1;
            }
            return { rowCount: inserted, rows: [] };
          }
          if (text === AEB_CONSUMPTION_SQL.commitOperation) {
            if (!row || row.state !== 'RESERVED' || row.ownerToken !== fourth) return { rowCount: 0, rows: [] };
            transaction.operations.set(id, { state: 'CONSUMED', ownerToken: null });
            return { rowCount: 1, rows: [{ operation_key: key }] };
          }
          if (text === AEB_CONSUMPTION_SQL.claimOperation) {
            if (!row || row.state !== 'RESERVED') return { rowCount: 0, rows: [] };
            transaction.operations.set(id, { ...row, ownerToken: fourth });
            return { rowCount: 1, rows: [{ operation_key: key }] };
          }
          if (text === AEB_CONSUMPTION_SQL.releaseOperation) {
            if (!row || row.state !== 'RESERVED' || row.ownerToken !== fourth) return { rowCount: 0, rows: [] };
            transaction.operations.delete(id);
            // ON DELETE CASCADE removes the fences this row holds.
            for (const [replayId, operationKey] of transaction.replays) {
              const [replayTenant, replayRp] = JSON.parse(replayId);
              if (replayTenant === tenantId && replayRp === relyingPartyId && operationKey === key) {
                transaction.replays.delete(replayId);
              }
            }
            return { rowCount: 1, rows: [{ operation_key: key }] };
          }
          if (text === AEB_CONSUMPTION_SQL.releaseTerminalOperation) {
            if (row?.state === 'RELEASED_NOT_ENTERED') return { rowCount: 1, rows: [{ operation_key: key }] };
            if (!row || row.state !== 'RESERVED' || row.ownerToken !== fourth) return { rowCount: 0, rows: [] };
            transaction.operations.set(id, { state: 'RELEASED_NOT_ENTERED', ownerToken: null });
            return { rowCount: 1, rows: [{ operation_key: key }] };
          }
          throw new Error(`fake pg received unknown SQL: ${text}`);
        },
        release() {
          assert.equal(transaction, null, 'client released with an open transaction');
        },
      };
    },
  };
  return {
    pool,
    statements,
    operation(key: string) {
      return committed.operations.get(scoped(TENANT, RELYING_PARTY, key));
    },
    fenceHolder(replayKey: string) {
      return committed.replays.get(scoped(TENANT, RELYING_PARTY, replayKey));
    },
    failNextOperationState(count = 1) {
      failOperationState += count;
    },
    restoreOperationState() {
      failOperationState = 0;
    },
  };
}

function pgStore(
  db: ReturnType<typeof fakePostgres>,
  authorize: (claim: AebRecoveryClaimAuthorization) => boolean = (claim) =>
    claim.authorization === 'recovery:approved',
  claims: AebRecoveryClaimAuthorization[] = [],
) {
  return createPostgresAebDurableConsumptionStore({
    pool: db.pool,
    recoveryPool: { connect: () => db.pool.connect() },
    tenantId: TENANT,
    relyingPartyId: RELYING_PARTY,
    authorizeRecoveryClaim: (claim) => {
      claims.push(claim);
      return authorize(claim);
    },
  });
}

function attemptStore() {
  const rows = new Map<string, {
    binding: ConsequenceBoundaryAttemptBinding;
    owner: string;
    state: 'RESERVED' | 'INVOKING' | 'INDETERMINATE' | 'COMMITTED' | 'RELEASED';
    evidence?: ConsequenceBoundaryProviderEvidence;
  }>();
  return {
    durable: true as const,
    ownershipFenced: true as const,
    compareAndSwap: true as const,
    atomicEvidenceBinding: true as const,
    rows,
    async reserve(binding: ConsequenceBoundaryAttemptBinding) {
      if (rows.has(binding.attempt_id)) return { reserved: false as const, reason: 'attempt_exists' };
      const owner = `owner:${crypto.randomBytes(24).toString('base64url')}`;
      rows.set(binding.attempt_id, { binding: structuredClone(binding), owner, state: 'RESERVED' });
      return { reserved: true as const, owner: owner as any };
    },
    async transition(input: any) {
      const row = rows.get(input.attempt_id);
      if (!row || row.owner !== input.owner || row.state !== input.expected_state) return false;
      row.state = input.next_state;
      return true;
    },
    async reconcile(input: any) {
      const row = rows.get(input.attempt_id);
      if (!row || row.owner !== input.owner || row.state !== input.expected_state) return false;
      row.state = input.next_state;
      row.evidence = structuredClone(input.evidence);
      return true;
    },
    async state(input: ConsequenceBoundaryAttemptReference) {
      const row = rows.get(input.attempt_id);
      if (!row || row.owner !== input.owner) throw new Error('attempt_not_owned');
      return { state: row.state, ...(row.evidence ? { evidence: structuredClone(row.evidence) } : {}) };
    },
  };
}

function nativeFixture() {
  const pair = crypto.generateKeyPairSync('ed25519');
  const gatewayId = 'gateway:authzen';
  const keyId = 'gateway-key:authzen:one';
  const source = {
    system: 'authzen' as const,
    profile: 'authzen:exact-action-result:1',
    issuer: 'https://authzen.example',
    authorization_id: 'native-authz:authzen:123',
  };
  const pins: any = {
    '@version': AEB_NATIVE_AUTHORIZATION_PINS_VERSION,
    relying_party_id: RELYING_PARTY,
    audience: 'https://gate.example/payments',
    executor_id: EXECUTOR,
    provider: PROVIDER,
    max_handoff_age_seconds: 120,
    max_status_age_seconds: 30,
    clock_skew_seconds: 2,
    gateway_keys: [{
      '@version': AEB_NATIVE_AUTHORIZATION_GATEWAY_KEY_VERSION,
      gateway_id: gatewayId,
      key_id: keyId,
      algorithm: 'Ed25519',
      public_key: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    }],
    accepted_sources: [{
      '@version': AEB_NATIVE_AUTHORIZATION_SOURCE_PIN_VERSION,
      gateway_id: gatewayId,
      system: source.system,
      profile: source.profile,
      issuer: source.issuer,
    }],
  };
  const handoffInput = {
    gateway_id: gatewayId,
    native_authorization: source,
    relying_party_id: RELYING_PARTY,
    audience: pins.audience,
    executor_id: EXECUTOR,
    provider: PROVIDER,
    action: ACTION,
    issued_at: '2026-08-09T12:00:00.000Z',
    not_before: '2026-08-09T12:00:00.000Z',
    expires_at: '2026-08-09T12:01:00.000Z',
    revocation_id: 'revocation:authzen:123',
  };
  const signer = { key_id: keyId, private_key: pair.privateKey };
  const issue = (authorizationId: string) => issueAebNativeAuthorizationHandoff({
    ...handoffInput,
    native_authorization: { ...source, authorization_id: authorizationId },
    revocation_id: `revocation:${authorizationId}`,
  }, signer);
  return { pins, handoff: issue(source.authorization_id), issue };
}

function statusFor(handoff: any) {
  return {
    '@version': AEB_NATIVE_AUTHORIZATION_STATUS_VERSION,
    gateway_id: handoff.gateway_id,
    native_authorization: handoff.native_authorization,
    revocation_id: handoff.revocation_id,
    checked_at: '2026-08-09T12:00:00.000Z',
    valid_until: '2026-08-09T12:00:30.000Z',
    revoked: false,
  };
}

function evidence(n: number) {
  return {
    evidence_id: `provider-evidence:${n}`,
    observed_at: '2026-08-09T12:00:02.000Z',
    evidence_digest: digestAeb({ provider: 'bank', n }),
  };
}

function boundary(
  f: ReturnType<typeof nativeFixture>,
  store: ReturnType<typeof pgStore>,
  attempts: ReturnType<typeof attemptStore>,
  invoke: () => Promise<any>,
) {
  let counter = 0;
  return createNativeConsequenceBoundary({
    executor_id: EXECUTOR,
    provider: PROVIDER,
    native_authorization: {
      pins: f.pins,
      trust_snapshot_id: 'native-trust-snapshot:pg:1',
      store,
      resolve_status: (handoff) => statusFor(handoff) as any,
      resolve_historical_pins: () => f.pins,
    },
    attempts: {
      store: attempts,
      create_id: () => `native-attempt:pg:${crypto.randomUUID()}:${++counter}`,
      recover: ({ attempt, recovery_authorization }) => {
        if (recovery_authorization !== 'recovery:approved') return null;
        const row = attempts.rows.get(attempt.attempt_id);
        return row ? { ...structuredClone(row.binding), owner: row.owner as any } : null;
      },
    },
    local_authorization_program_digest: digestAeb({ program: 'local:pg:1' }),
    local_authorize: () => true,
    invoke,
    provider_outcomes: {
      verification_program_digest: digestAeb({ program: 'outcome:pg:1' }),
      verify: () => true,
    },
    now: () => NOW,
  });
}

function keysFor(operationId: string, actionDigest: string) {
  const input = {
    relying_party_id: RELYING_PARTY,
    operation_id: operationId,
    action_digest: actionDigest as `sha256:${string}`,
  };
  return {
    operation: nativeConsequenceBoundaryReservationKey(input),
    holder: nativeConsequenceBoundaryActionFenceHolderKey(input),
  };
}

test('the PostgreSQL store declares the durable state read and its DDL grants it to the executor only', async () => {
  const db = fakePostgres();
  const store = pgStore(db);
  assert.equal(typeof store.state, 'function');
  assert.equal(await store.state('aeb-native-operation:missing'), 'AVAILABLE');
  assert.match(AEB_CONSUMPTION_DDL, /CREATE OR REPLACE FUNCTION ep_aeb_private\.operation_state\(/);
  assert.match(
    AEB_CONSUMPTION_DDL,
    /GRANT EXECUTE ON FUNCTION ep_aeb_private\.operation_state\(TEXT, TEXT, TEXT\)\n  TO ep_aeb_executor;/,
  );
  assert.ok(
    AEB_CONSUMPTION_DDL.indexOf('ALTER FUNCTION ep_aeb_private.operation_state')
      < AEB_CONSUMPTION_DDL.indexOf('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ep_aeb_private'),
  );
  db.failNextOperationState();
  await assert.rejects(store.state('aeb-native-operation:missing'), /pg_unavailable/);
});

test('a malformed operation-state answer throws instead of reporting a state', async () => {
  const store = createPostgresAebDurableConsumptionStore({
    pool: { connect: async () => ({ query: async () => ({ rowCount: 1, rows: [{ state: 'OPEN' }] }), release() {} }) },
    recoveryPool: { connect: async () => ({ query: async () => ({ rowCount: 0, rows: [] }), release() {} }) },
    tenantId: TENANT,
    relyingPartyId: RELYING_PARTY,
    authorizeRecoveryClaim: () => false,
  });
  await assert.rejects(store.state('aeb-native-operation:x'), /malformed PostgreSQL result/);
});

test('the shipped PostgreSQL store backs the native boundary and closes both reservations', async () => {
  const db = fakePostgres();
  const f = nativeFixture();
  let calls = 0;
  const h = boundary(f, pgStore(db), attemptStore(), async () => {
    calls += 1;
    return { state: 'EXECUTED', evidence: evidence(calls), result: { ok: true } };
  });
  const result = await h.run({ operation_id: 'operation:pg:1', handoff: f.handoff, action: ACTION });
  assert.equal(result.state, 'EXECUTED');
  assert.ok(result.state === 'EXECUTED');
  const keys = keysFor('operation:pg:1', result.attempt.action_digest as string);
  assert.equal(db.operation(keys.operation)?.state, 'CONSUMED');
  assert.equal(db.operation(keys.holder)?.state, 'CONSUMED');

  const again = await h.run({ operation_id: 'operation:pg:2', handoff: f.issue('native-authz:fresh:1'), action: ACTION });
  assert.equal(again.state, 'REFUSED');
  assert.equal(again.reason, 'native_action_already_executed');
  assert.equal(calls, 1);
});

test('after a restart, reconciliation claims both reservations through the authorized recovery path', async () => {
  const db = fakePostgres();
  const f = nativeFixture();
  const attempts = attemptStore();
  const before = boundary(f, pgStore(db), attempts, async () => { throw new Error('process lost the response'); });
  const uncertain = await before.run({ operation_id: 'operation:pg:restart', handoff: f.handoff, action: ACTION });
  assert.equal(uncertain.state, 'INDETERMINATE');
  assert.ok(uncertain.attempt);
  const keys = keysFor('operation:pg:restart', uncertain.attempt.action_digest as string);
  assert.equal(db.operation(keys.operation)?.state, 'RESERVED');
  assert.equal(db.operation(keys.holder)?.state, 'RESERVED');

  // A fresh authorization for the same action is fenced across the restart.
  const claims: AebRecoveryClaimAuthorization[] = [];
  let calls = 0;
  const after = boundary(f, pgStore(db, undefined, claims), attempts, async () => {
    calls += 1;
    return { state: 'EXECUTED', evidence: evidence(calls), result: {} };
  });
  const fenced = await after.run({
    operation_id: 'operation:pg:restart:retry',
    handoff: f.issue('native-authz:fresh:restart'),
    action: ACTION,
  });
  assert.equal(fenced.state, 'REFUSED');
  assert.equal(fenced.reason, 'native_action_in_flight');
  assert.equal(calls, 0);

  const reconciled = await after.reconcile({
    operation_id: 'operation:pg:restart',
    handoff: f.handoff,
    action: ACTION,
    attempt: uncertain.attempt,
    outcome: { state: 'EXECUTED', evidence: evidence(1), result: { recovered: true } },
    recovery_authorization: 'recovery:approved',
  });
  assert.equal(reconciled.state, 'EXECUTED');
  assert.deepEqual(claims.map((claim) => claim.operationKey), [keys.operation, keys.holder]);
  assert.ok(claims.every((claim) => claim.authorization === 'recovery:approved'
    && claim.requiredState === 'RESERVED'));
  assert.equal(db.operation(keys.operation)?.state, 'CONSUMED');
  assert.equal(db.operation(keys.holder)?.state, 'CONSUMED');
});

test('an unauthorized restart reconciliation leaves both reservations held', async () => {
  const db = fakePostgres();
  const f = nativeFixture();
  const attempts = attemptStore();
  const before = boundary(f, pgStore(db), attempts, async () => { throw new Error('lost'); });
  const uncertain = await before.run({ operation_id: 'operation:pg:unauthorized', handoff: f.handoff, action: ACTION });
  assert.equal(uncertain.state, 'INDETERMINATE');
  const keys = keysFor('operation:pg:unauthorized', uncertain.attempt!.action_digest as string);

  const denied = boundary(f, pgStore(db, () => false), attempts, async () => { throw new Error('no'); });
  const result = await denied.reconcile({
    operation_id: 'operation:pg:unauthorized',
    handoff: f.handoff,
    action: ACTION,
    attempt: uncertain.attempt,
    outcome: { state: 'EXECUTED', evidence: evidence(1), result: {} },
    recovery_authorization: 'recovery:approved',
  });
  assert.equal(result.state, 'INDETERMINATE');
  assert.equal(result.reason, 'authorization_consumption_unconfirmed');
  assert.equal(db.operation(keys.operation)?.state, 'RESERVED');
  assert.equal(db.operation(keys.holder)?.state, 'RESERVED');
  assert.equal([...attempts.rows.values()][0]?.state, 'INDETERMINATE');
});

test('after a restart, reconciliation to FAILED burns the authorization and releases the action fence', async () => {
  const db = fakePostgres();
  const f = nativeFixture();
  const attempts = attemptStore();
  const before = boundary(f, pgStore(db), attempts, async () => { throw new Error('lost'); });
  const uncertain = await before.run({ operation_id: 'operation:pg:failed', handoff: f.handoff, action: ACTION });
  assert.equal(uncertain.state, 'INDETERMINATE');
  const keys = keysFor('operation:pg:failed', uncertain.attempt!.action_digest as string);

  let calls = 0;
  const after = boundary(f, pgStore(db), attempts, async () => {
    calls += 1;
    return { state: 'EXECUTED', evidence: evidence(10 + calls), result: {} };
  });
  const failed = await after.reconcile({
    operation_id: 'operation:pg:failed',
    handoff: f.handoff,
    action: ACTION,
    attempt: uncertain.attempt,
    outcome: { state: 'FAILED', evidence: evidence(1), reason: 'provider_declined' },
    recovery_authorization: 'recovery:approved',
  });
  assert.equal(failed.state, 'FAILED');
  assert.equal(db.operation(keys.operation)?.state, 'CONSUMED');
  assert.equal(db.operation(keys.holder), undefined, 'fence holder released');

  const sameAuthority = await after.run({ operation_id: 'operation:pg:failed:2', handoff: f.handoff, action: ACTION });
  assert.equal(sameAuthority.state, 'REFUSED');
  assert.equal(sameAuthority.reason, 'native_replay_conflict');
  const fresh = await after.run({
    operation_id: 'operation:pg:failed:3',
    handoff: f.issue('native-authz:fresh:after-failed'),
    action: ACTION,
  });
  assert.equal(fresh.state, 'EXECUTED');
  assert.equal(calls, 1);
});

test('an unreadable operation state never becomes a provider entry', async () => {
  const db = fakePostgres();
  const f = nativeFixture();
  let calls = 0;
  const h = boundary(f, pgStore(db), attemptStore(), async () => {
    calls += 1;
    return { state: 'EXECUTED', evidence: evidence(calls), result: {} };
  });
  // Every durable state read fails: the boundary cannot confirm consumption,
  // reports INDETERMINATE after the one provider entry, and keeps the fences.
  db.failNextOperationState(50);
  const result = await h.run({ operation_id: 'operation:pg:state-down', handoff: f.handoff, action: ACTION });
  assert.equal(result.state, 'INDETERMINATE');
  assert.equal(result.reason, 'authorization_consumption_unconfirmed');
  assert.equal(calls, 1);
  db.restoreOperationState();
  const retry = await h.run({
    operation_id: 'operation:pg:state-down:retry',
    handoff: f.issue('native-authz:fresh:state-down'),
    action: ACTION,
  });
  assert.equal(retry.state, 'REFUSED');
  assert.equal(retry.reason, 'native_action_in_flight');
  assert.equal(calls, 1);
});
