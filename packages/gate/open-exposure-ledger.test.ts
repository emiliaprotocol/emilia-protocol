// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createMemoryOpenExposureLedger,
  type OpenExposureAuth,
  type OpenExposureCeilingInput,
  type OpenExposureReserveInput,
} from './open-exposure-ledger.js';

const DIGEST_A = `sha256:${'a'.repeat(64)}` as const;
const DIGEST_B = `sha256:${'b'.repeat(64)}` as const;
const DIGEST_C = `sha256:${'c'.repeat(64)}` as const;
const WINDOW_START = '2026-07-01T00:00:00.000Z';
const WINDOW_END = '2026-08-01T00:00:00.000Z';

function auth(
  tenantId: string,
  role: OpenExposureAuth['role'],
  authorityId: string,
): OpenExposureAuth {
  return {
    role,
    authorityId,
    credential: `${tenantId}:${role}:${authorityId}`,
  };
}

function authenticator(input: {
  tenantId: string;
  auth: OpenExposureAuth;
}): boolean {
  return input.auth.credential
    === `${input.tenantId}:${input.auth.role}:${input.auth.authorityId}`;
}

function ceiling(
  scope: OpenExposureCeilingInput['scope'],
  scopeValue: string,
  limitMinor: bigint,
  tenantId = 'tenant-a',
): OpenExposureCeilingInput {
  return {
    tenantId,
    ceilingId: `ceiling-${scope.toLowerCase()}-${scopeValue === '*' ? 'all' : scopeValue}`,
    scope,
    scopeValue,
    currency: 'USD',
    windowStart: WINDOW_START,
    windowEnd: WINDOW_END,
    limitMinor,
    policyDigest: DIGEST_A,
  };
}

const CEILINGS = [
  ceiling('TENANT', '*', 100n),
  ceiling('PROGRAM', 'program-a', 100n),
  ceiling('COUNTERPARTY', 'counterparty-a', 100n),
  ceiling('ACTION_CLASS', 'payment.release', 100n),
];

function reservation(
  exposureId: string,
  operationToken: string,
  amountMinor: bigint,
  tenantId = 'tenant-a',
): OpenExposureReserveInput {
  return {
    tenantId,
    exposureId,
    operationToken,
    programId: 'program-a',
    counterpartyId: 'counterparty-a',
    actionClass: 'payment.release',
    amountMinor,
    currency: 'USD',
    windowStart: WINDOW_START,
    windowEnd: WINDOW_END,
    reservedAt: '2026-07-28T12:00:00.000Z',
    invokeBy: '2026-07-28T12:05:00.000Z',
    reconcileBy: '2026-07-28T13:00:00.000Z',
    originAuthorityId: 'origin-a',
    executorAuthorityId: 'executor-a',
    reconciliationAuthorityId: 'reconciler-a',
    reservationEvidenceDigest: DIGEST_A,
  };
}

async function configuredLedger(extraCeilings: OpenExposureCeilingInput[] = []) {
  const ledger = createMemoryOpenExposureLedger({ authenticate: authenticator });
  for (const configured of [...CEILINGS, ...extraCeilings]) {
    const result = await ledger.registerCeiling(
      configured,
      auth(configured.tenantId, 'POLICY_ADMIN', 'policy-admin'),
    );
    assert.equal(result.ok, true);
  }
  return ledger;
}

test('atomic reservations admit one racing operation and refuse oversubscription', async () => {
  const ledger = await configuredLedger();
  const [first, second] = await Promise.all([
    ledger.reserve(
      reservation('exposure-1', `open-exposure-op:v1:${'1'.repeat(32)}`, 60n),
      auth('tenant-a', 'ORIGIN', 'origin-a'),
    ),
    ledger.reserve(
      reservation('exposure-2', `open-exposure-op:v1:${'2'.repeat(32)}`, 60n),
      auth('tenant-a', 'ORIGIN', 'origin-a'),
    ),
  ]);

  assert.equal([first, second].filter((result) => result.ok).length, 1);
  assert.deepEqual(
    [first, second].filter((result) => !result.ok).map((result) => result.reason),
    ['ceiling_exceeded'],
  );

  const sum = await ledger.sumOpen({
    tenantId: 'tenant-a',
    currency: 'USD',
    windowStart: WINDOW_START,
    windowEnd: WINDOW_END,
  }, auth('tenant-a', 'READER', 'risk-reader'));
  assert.equal(sum.ok, true);
  if (sum.ok) assert.equal(sum.totalMinor, 60n);
});

test('operation tokens are exact-replay idempotent and conflict on changed semantics', async () => {
  const ledger = await configuredLedger();
  const input = reservation(
    'exposure-replay',
    `open-exposure-op:v1:${'r'.repeat(32)}`,
    40n,
  );
  const caller = auth('tenant-a', 'ORIGIN', 'origin-a');

  const first = await ledger.reserve(input, caller);
  const replay = await ledger.reserve(structuredClone(input), caller);
  const conflict = await ledger.reserve({ ...input, amountMinor: 41n }, caller);

  assert.equal(first.ok, true);
  assert.equal(replay.ok, true);
  if (first.ok && replay.ok) {
    assert.equal(first.replayed, false);
    assert.equal(replay.replayed, true);
    assert.equal(replay.record.recordDigest, first.record.recordDigest);
    assert.equal(replay.record.revision, 0);
  }
  assert.deepEqual(conflict, { ok: false, reason: 'operation_token_conflict' });
});

test('tenant authentication prevents cross-tenant reads and token collisions remain tenant scoped', async () => {
  const tenantBCeilings = CEILINGS.map((entry) => ({
    ...entry,
    tenantId: 'tenant-b',
    ceilingId: `${entry.ceilingId}-tenant-b`,
  }));
  const ledger = await configuredLedger(tenantBCeilings);
  const token = `open-exposure-op:v1:${'t'.repeat(32)}`;

  const tenantA = await ledger.reserve(
    reservation('exposure-a', token, 25n),
    auth('tenant-a', 'ORIGIN', 'origin-a'),
  );
  const tenantB = await ledger.reserve(
    {
      ...reservation('exposure-b', token, 35n, 'tenant-b'),
      originAuthorityId: 'origin-b',
      executorAuthorityId: 'executor-b',
      reconciliationAuthorityId: 'reconciler-b',
    },
    auth('tenant-b', 'ORIGIN', 'origin-b'),
  );
  assert.equal(tenantA.ok, true);
  assert.equal(tenantB.ok, true);

  const crossed = await ledger.read(
    { tenantId: 'tenant-a', exposureId: 'exposure-a' },
    auth('tenant-b', 'READER', 'risk-reader'),
  );
  assert.deepEqual(crossed, { ok: false, reason: 'unauthenticated' });

  const sumB = await ledger.sumOpen({
    tenantId: 'tenant-b',
    currency: 'USD',
    windowStart: WINDOW_START,
    windowEnd: WINDOW_END,
  }, auth('tenant-b', 'READER', 'risk-reader'));
  assert.equal(sumB.ok, true);
  if (sumB.ok) assert.equal(sumB.totalMinor, 35n);
});

test('origin, executor, and reconciliation authorities are distinct and role-bound', async () => {
  const ledger = await configuredLedger();
  const token = `open-exposure-op:v1:${'a'.repeat(32)}`;
  const invalid = await ledger.reserve({
    ...reservation('exposure-invalid-authorities', token, 10n),
    reconciliationAuthorityId: 'executor-a',
  }, auth('tenant-a', 'ORIGIN', 'origin-a'));
  assert.deepEqual(invalid, { ok: false, reason: 'authority_separation_required' });

  const reserved = await ledger.reserve(
    reservation('exposure-authorities', token, 10n),
    auth('tenant-a', 'ORIGIN', 'origin-a'),
  );
  assert.equal(reserved.ok, true);

  const wrongBegin = await ledger.beginInvocation({
    tenantId: 'tenant-a',
    exposureId: 'exposure-authorities',
    operationToken: token,
    invokedAt: '2026-07-28T12:01:00.000Z',
  }, auth('tenant-a', 'ORIGIN', 'origin-a'));
  assert.deepEqual(wrongBegin, { ok: false, reason: 'wrong_authority' });

  const begun = await ledger.beginInvocation({
    tenantId: 'tenant-a',
    exposureId: 'exposure-authorities',
    operationToken: token,
    invokedAt: '2026-07-28T12:01:00.000Z',
  }, auth('tenant-a', 'EXECUTOR', 'executor-a'));
  assert.equal(begun.ok, true);

  const wrongClose = await ledger.reconcile({
    tenantId: 'tenant-a',
    exposureId: 'exposure-authorities',
    operationToken: token,
    reconciliationToken: `open-exposure-reconcile:v1:${'x'.repeat(32)}`,
    outcome: 'COMMITTED',
    evidenceDigest: DIGEST_B,
    observedAt: '2026-07-28T12:02:00.000Z',
  }, auth('tenant-a', 'EXECUTOR', 'executor-a'));
  assert.deepEqual(wrongClose, { ok: false, reason: 'wrong_authority' });
});

test('indeterminate custody stays open, blocks blind invocation retry, and closes only on authenticated evidence', async () => {
  const ledger = await configuredLedger();
  const token = `open-exposure-op:v1:${'i'.repeat(32)}`;
  const exposureId = 'exposure-indeterminate';
  assert.equal((await ledger.reserve(
    reservation(exposureId, token, 45n),
    auth('tenant-a', 'ORIGIN', 'origin-a'),
  )).ok, true);
  assert.equal((await ledger.beginInvocation({
    tenantId: 'tenant-a', exposureId, operationToken: token,
    invokedAt: '2026-07-28T12:01:00.000Z',
  }, auth('tenant-a', 'EXECUTOR', 'executor-a'))).ok, true);
  assert.equal((await ledger.markIndeterminate({
    tenantId: 'tenant-a', exposureId, operationToken: token,
    evidenceDigest: DIGEST_B,
    observedAt: '2026-07-28T12:02:00.000Z',
  }, auth('tenant-a', 'EXECUTOR', 'executor-a'))).ok, true);

  const blindRetry = await ledger.beginInvocation({
    tenantId: 'tenant-a', exposureId, operationToken: token,
    invokedAt: '2026-07-28T12:03:00.000Z',
  }, auth('tenant-a', 'EXECUTOR', 'executor-a'));
  assert.deepEqual(blindRetry, { ok: false, reason: 'reconciliation_required' });

  const stillUnknown = await ledger.reconcile({
    tenantId: 'tenant-a', exposureId, operationToken: token,
    reconciliationToken: `open-exposure-reconcile:v1:${'1'.repeat(32)}`,
    outcome: 'INDETERMINATE', evidenceDigest: DIGEST_C,
    observedAt: '2026-07-28T12:10:00.000Z',
  }, auth('tenant-a', 'RECONCILER', 'reconciler-a'));
  assert.equal(stillUnknown.ok, true);
  if (stillUnknown.ok) assert.equal(stillUnknown.record.status, 'INDETERMINATE');

  const sumWhileUnknown = await ledger.sumOpen({
    tenantId: 'tenant-a', currency: 'USD',
    windowStart: WINDOW_START, windowEnd: WINDOW_END,
  }, auth('tenant-a', 'READER', 'risk-reader'));
  assert.equal(sumWhileUnknown.ok, true);
  if (sumWhileUnknown.ok) assert.equal(sumWhileUnknown.totalMinor, 45n);

  const closed = await ledger.reconcile({
    tenantId: 'tenant-a', exposureId, operationToken: token,
    reconciliationToken: `open-exposure-reconcile:v1:${'2'.repeat(32)}`,
    outcome: 'COMMITTED', evidenceDigest: DIGEST_A,
    observedAt: '2026-07-28T12:20:00.000Z',
  }, auth('tenant-a', 'RECONCILER', 'reconciler-a'));
  assert.equal(closed.ok, true);
  if (closed.ok) assert.equal(closed.record.status, 'CLOSED_COMMITTED');
});

test('closeout replay cannot underflow deterministic open sums and history is immutable', async () => {
  const ledger = await configuredLedger();
  const token = `open-exposure-op:v1:${'u'.repeat(32)}`;
  const reconcileToken = `open-exposure-reconcile:v1:${'u'.repeat(32)}`;
  const exposureId = 'exposure-underflow';
  await ledger.reserve(
    reservation(exposureId, token, 30n),
    auth('tenant-a', 'ORIGIN', 'origin-a'),
  );

  const request = {
    tenantId: 'tenant-a', exposureId, operationToken: token,
    reconciliationToken: reconcileToken,
    outcome: 'PROVEN_NOT_COMMITTED' as const,
    evidenceDigest: DIGEST_B,
    observedAt: '2026-07-28T12:30:00.000Z',
  };
  const first = await ledger.reconcile(
    request,
    auth('tenant-a', 'RECONCILER', 'reconciler-a'),
  );
  const replay = await ledger.reconcile(
    structuredClone(request),
    auth('tenant-a', 'RECONCILER', 'reconciler-a'),
  );
  const conflict = await ledger.reconcile(
    { ...request, outcome: 'COMMITTED' },
    auth('tenant-a', 'RECONCILER', 'reconciler-a'),
  );
  assert.equal(first.ok, true);
  assert.equal(replay.ok, true);
  if (replay.ok) assert.equal(replay.replayed, true);
  assert.deepEqual(conflict, { ok: false, reason: 'reconciliation_token_conflict' });

  const sum = await ledger.sumOpen({
    tenantId: 'tenant-a', currency: 'USD',
    windowStart: WINDOW_START, windowEnd: WINDOW_END,
  }, auth('tenant-a', 'READER', 'risk-reader'));
  assert.equal(sum.ok, true);
  if (sum.ok) {
    assert.equal(sum.totalMinor, 0n);
    assert.deepEqual(sum.byProgram, []);
  }

  const history = await ledger.history(
    { tenantId: 'tenant-a', exposureId },
    auth('tenant-a', 'READER', 'risk-reader'),
  );
  assert.equal(history.ok, true);
  if (history.ok) {
    assert.deepEqual(history.entries.map((entry) => entry.event), [
      'RESERVED', 'CLOSED_PROVEN_NOT_COMMITTED',
    ]);
    assert.ok(history.entries.every(Object.isFrozen));
    assert.throws(() => {
      (history.entries as unknown as Array<unknown>).push({});
    }, TypeError);
  }
});

test('aging and deadline queries are tenant-scoped and deterministically ordered', async () => {
  const ledger = await configuredLedger();
  const older = reservation(
    'exposure-old', `open-exposure-op:v1:${'o'.repeat(32)}`, 10n,
  );
  const newer = reservation(
    'exposure-new', `open-exposure-op:v1:${'n'.repeat(32)}`, 15n,
  );
  await ledger.reserve({
    ...newer,
    reservedAt: '2026-07-28T12:02:00.000Z',
    invokeBy: '2026-07-28T12:04:00.000Z',
  }, auth('tenant-a', 'ORIGIN', 'origin-a'));
  await ledger.reserve({
    ...older,
    reservedAt: '2026-07-28T12:00:00.000Z',
    invokeBy: '2026-07-28T12:03:00.000Z',
  }, auth('tenant-a', 'ORIGIN', 'origin-a'));

  const aging = await ledger.listAging({
    tenantId: 'tenant-a',
    asOf: '2026-07-28T12:10:00.000Z',
    minimumAgeMs: 8 * 60_000,
    limit: 10,
  }, auth('tenant-a', 'RECONCILER', 'reconciler-a'));
  assert.equal(aging.ok, true);
  if (aging.ok) assert.deepEqual(
    aging.records.map((record) => record.exposureId),
    ['exposure-old', 'exposure-new'],
  );

  const due = await ledger.listDeadlines({
    tenantId: 'tenant-a',
    dueAtOrBefore: '2026-07-28T12:04:00.000Z',
    limit: 10,
  }, auth('tenant-a', 'RECONCILER', 'reconciler-a'));
  assert.equal(due.ok, true);
  if (due.ok) assert.deepEqual(
    due.records.map((record) => record.exposureId),
    ['exposure-old', 'exposure-new'],
  );
});
