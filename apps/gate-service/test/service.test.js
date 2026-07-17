// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DELETE_BODY,
  OBSERVED_ACTION,
  REPOSITORY,
  SECOND_API_TOKEN,
  TEST_GATE_ID,
  TEST_PRINCIPAL,
  TEST_TENANT_ID,
  createServiceFixture,
  receiptCarrier,
} from './helpers.js';

function evidencePath(path, actionId, extra = '') {
  const query = new URLSearchParams({
    tenant_id: TEST_TENANT_ID,
    gate_id: TEST_GATE_ID,
    action_id: actionId,
  });
  return `${path}?${query}${extra}`;
}

test('liveness is process-only while readiness is dependency-aware', async (t) => {
  const fixture = await createServiceFixture(t);
  const live = await fixture.request('/v1/live', { authenticated: false });
  const ready = await fixture.request('/v1/ready', { authenticated: false });
  assert.equal(live.status, 200);
  assert.deepEqual(live.body, {
    status: 'ok',
    service: 'emilia-gate-service',
  });
  assert.equal(ready.status, 200);
  assert.deepEqual(ready.body, {
    status: 'ready',
    service: 'emilia-gate-service',
    dependencies: 'ready',
  });
  assert.equal(fixture.getCalls.length, 0);
  assert.equal(fixture.deleteCalls.length, 0);
});

test('unready dependencies return 503 without exposing dependency details', async (t) => {
  const fixture = await createServiceFixture(t, { readiness: async () => ({ ok: false, secret: 'db-host' }) });
  const [live, ready] = await Promise.all([
    fixture.request('/v1/live', { authenticated: false }),
    fixture.request('/v1/ready', { authenticated: false }),
  ]);
  assert.equal(live.status, 200);
  assert.equal(ready.status, 503);
  assert.deepEqual(ready.body, {
    status: 'unavailable',
    service: 'emilia-gate-service',
    error: { code: 'dependency_not_ready' },
  });
  assert.equal(JSON.stringify(ready.body).includes('db-host'), false);
});

test('readiness checks are coalesced and bounded even when the dependency ignores cancellation', async (t) => {
  let calls = 0;
  let release;
  const blocked = new Promise((resolve) => { release = resolve; });
  const fixture = await createServiceFixture(t, {
    readiness: async () => {
      calls += 1;
      return blocked;
    },
  });

  const first = fixture.request('/v1/ready', { authenticated: false });
  const second = fixture.request('/v1/ready', { authenticated: false });
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(calls, 1);
  release({ ok: true });
  assert.deepEqual((await Promise.all([first, second])).map((response) => response.status), [200, 200]);

  let aborted = false;
  const hanging = await createServiceFixture(t, {
    readinessTimeoutMs: 100,
    readiness: async ({ signal }) => {
      signal.addEventListener('abort', () => { aborted = true; }, { once: true });
      return new Promise(() => {});
    },
  });
  const started = Date.now();
  const timedOut = await hanging.request('/v1/ready', { authenticated: false });
  assert.equal(timedOut.status, 503);
  assert.equal(aborted, true);
  assert.ok(Date.now() - started < 1000);
});

test('unauthenticated requests are refused before repository observation', async (t) => {
  const fixture = await createServiceFixture(t);
  const response = await fixture.request('/v1/actions', {
    method: 'POST',
    body: DELETE_BODY,
    authenticated: false,
  });
  assert.equal(response.status, 401);
  assert.equal(response.body.error.code, 'authentication_required');
  assert.match(response.headers.get('www-authenticate'), /^Bearer /);
  assert.equal(fixture.getCalls.length, 0);
  assert.equal(fixture.deleteCalls.length, 0);
  assert.equal(fixture.actionStore.records.size, 0);
});

test('target authorization runs before all action-store and connector access', async (t) => {
  const authorizeCalls = [];
  const fixture = await createServiceFixture(t, {
    authorizeAction: async (...args) => {
      authorizeCalls.push(args);
      return false;
    },
  });
  const baseline = Object.fromEntries(
    Object.entries(fixture.actionStore.calls).map(([name, calls]) => [name, calls.length]),
  );
  const response = await fixture.request('/v1/actions', { method: 'POST', body: DELETE_BODY });

  assert.equal(response.status, 403);
  assert.equal(response.body.error.code, 'action_not_authorized');
  assert.deepEqual(authorizeCalls, [[TEST_PRINCIPAL, 'github.repo.delete', 'acme', 'prod']]);
  assert.deepEqual(
    Object.fromEntries(Object.entries(fixture.actionStore.calls).map(([name, calls]) => [name, calls.length])),
    baseline,
  );
  assert.equal(fixture.getCalls.length, 0);
  assert.equal(fixture.deleteCalls.length, 0);
  assert.equal(JSON.stringify(response.body).includes('acme'), false);
});

test('no receipt returns a 428 exact-action challenge and makes zero DELETE calls', async (t) => {
  const fixture = await createServiceFixture(t);
  const response = await fixture.request('/v1/actions', { method: 'POST', body: DELETE_BODY });

  assert.equal(response.status, 428);
  assert.equal(response.body.status, 428);
  assert.equal(response.body.required.action, 'github.repo.delete');
  assert.deepEqual(response.body.required.observed_action, OBSERVED_ACTION);
  assert.deepEqual(response.body.resume, {
    method: 'POST',
    path: `/v1/actions/${response.body.action_id}/execute`,
    challenge_binding: response.body.resume.challenge_binding,
  });
  assert.match(response.body.resume.challenge_binding, /^[0-9a-f]{64}$/);
  assert.match(response.headers.get('receipt-required'), /github\.repo\.delete/);
  assert.equal(fixture.getCalls.length, 1, 'the service observes GitHub before issuing the exact challenge');
  assert.equal(fixture.deleteCalls.length, 0);
});

test('challenge resume reuses one row, re-observes, and refuses target substitution', async (t) => {
  const fixture = await createServiceFixture(t);
  const challenge = await fixture.request('/v1/actions', { method: 'POST', body: DELETE_BODY });
  const { action_id: actionId } = challenge.body;
  const binding = challenge.body.resume.challenge_binding;
  const baselineGets = fixture.getCalls.length;

  const substituted = await fixture.request(`/v1/actions/${actionId}/execute`, {
    method: 'POST',
    body: {
      action: 'github.repo.delete',
      challenge_binding: binding,
      owner: 'other',
    },
    carrier: receiptCarrier(fixture.harness.mint({ outcome: 'allow_with_signoff' })),
  });
  assert.equal(substituted.status, 400);

  const wrongBinding = await fixture.request(`/v1/actions/${actionId}/execute`, {
    method: 'POST',
    body: { action: 'github.repo.delete', challenge_binding: '0'.repeat(64) },
    carrier: receiptCarrier(fixture.harness.mint({ outcome: 'allow_with_signoff' })),
  });
  assert.equal(wrongBinding.status, 409);
  assert.equal(fixture.getCalls.length, baselineGets);

  const resumed = await fixture.request(`/v1/actions/${actionId}/execute`, {
    method: 'POST',
    body: { action: 'github.repo.delete', challenge_binding: binding },
    carrier: receiptCarrier(fixture.harness.mint({ outcome: 'allow_with_signoff' })),
  });
  assert.equal(resumed.status, 200);
  assert.equal(resumed.body.id, actionId);
  assert.equal(fixture.actionStore.records.size, 1);
  assert.equal(fixture.getCalls.length, baselineGets + 1, 'resume must re-observe GitHub');
  assert.equal(fixture.deleteCalls.length, 1);
});

test('resume re-observation challenges a stale receipt on the original row', async (t) => {
  const fixture = await createServiceFixture(t, {
    repository: (_args, call) => (call === 1 ? REPOSITORY : { ...REPOSITORY, default_branch: 'release' }),
  });
  const challenge = await fixture.request('/v1/actions', { method: 'POST', body: DELETE_BODY });
  const response = await fixture.request(`/v1/actions/${challenge.body.action_id}/execute`, {
    method: 'POST',
    body: {
      action: 'github.repo.delete',
      challenge_binding: challenge.body.resume.challenge_binding,
    },
    carrier: receiptCarrier(fixture.harness.mint({ outcome: 'allow_with_signoff' })),
  });

  assert.equal(response.status, 428);
  assert.equal(response.body.action_id, challenge.body.action_id);
  assert.equal(response.body.required.observed_action.default_branch, 'release');
  assert.notEqual(response.body.resume.challenge_binding, challenge.body.resume.challenge_binding);
  assert.equal(fixture.actionStore.records.size, 1);
  assert.equal(fixture.getCalls.length, 2);
  assert.equal(fixture.deleteCalls.length, 0);
});

test('concurrent challenge resumes atomically claim one execution', async (t) => {
  const fixture = await createServiceFixture(t);
  const challenge = await fixture.request('/v1/actions', { method: 'POST', body: DELETE_BODY });
  const receipt = receiptCarrier(fixture.harness.mint({ outcome: 'allow_with_signoff' }));
  const resume = () => fixture.request(`/v1/actions/${challenge.body.action_id}/execute`, {
    method: 'POST',
    body: {
      action: 'github.repo.delete',
      challenge_binding: challenge.body.resume.challenge_binding,
    },
    carrier: receipt,
  });

  const responses = await Promise.all([resume(), resume()]);
  assert.deepEqual(responses.map((response) => response.status).sort(), [200, 409]);
  assert.equal(fixture.actionStore.records.size, 1);
  assert.equal(fixture.getCalls.length, 2, 'only one resume may reach re-observation');
  assert.equal(fixture.deleteCalls.length, 1);
});

test('a receipt for the wrong action makes zero DELETE calls', async (t) => {
  const fixture = await createServiceFixture(t, {
    harnessAction: { ...OBSERVED_ACTION, action_type: 'github.issue.delete' },
  });
  const receipt = fixture.harness.mint({ outcome: 'allow_with_signoff' });
  const response = await fixture.request('/v1/actions', {
    method: 'POST',
    body: DELETE_BODY,
    carrier: receiptCarrier(receipt),
  });

  assert.equal(response.status, 428);
  assert.match(response.body.detail, /action|receipt/i);
  assert.equal(fixture.deleteCalls.length, 0);
});

test('an untrusted receipt cannot authorize itself with an inline issuer key', async (t) => {
  const fixture = await createServiceFixture(t);
  const foreign = await createServiceFixture(t);
  const receipt = foreign.harness.mint({ outcome: 'allow_with_signoff' });
  receipt.public_key = foreign.harness.publicKey;

  const response = await fixture.request('/v1/actions', {
    method: 'POST',
    body: DELETE_BODY,
    carrier: receiptCarrier(receipt),
  });

  assert.equal(response.status, 428);
  assert.match(response.body.detail, /untrusted|signature/i);
  assert.equal(fixture.deleteCalls.length, 0);
});

test('a valid exact receipt causes one canonical DELETE and exposes its action record', async (t) => {
  const fixture = await createServiceFixture(t);
  const receipt = fixture.harness.mint({ outcome: 'allow_with_signoff' });
  const response = await fixture.request('/v1/actions', {
    method: 'POST',
    body: DELETE_BODY,
    carrier: receiptCarrier(receipt),
  });

  assert.equal(response.status, 200);
  assert.equal(response.body.status, 'succeeded');
  assert.deepEqual(response.body.observed_action, OBSERVED_ACTION);
  assert.equal(fixture.deleteCalls.length, 1);
  assert.deepEqual(fixture.deleteCalls[0], {
    owner: 'Acme',
    repo: 'Prod',
    node_id: OBSERVED_ACTION.node_id,
    default_branch: 'main',
    visibility: 'private',
    idempotencyKey: fixture.deleteCalls[0].idempotencyKey,
    actionId: response.body.id,
  });
  assert.match(fixture.deleteCalls[0].idempotencyKey, /^emilia-[A-Za-z0-9_-]{43}$/);
  assert.notEqual(fixture.deleteCalls[0].idempotencyKey, receipt.payload.receipt_id);

  const stored = fixture.actionStore.records.get(response.body.id);
  stored.receipt = receipt;
  stored.connector_secret = 'must-not-leak';
  const lookup = await fixture.request(`/v1/actions/${response.body.id}`);
  assert.equal(lookup.status, 200);
  assert.equal(lookup.body.status, 'succeeded');
  assert.equal(lookup.body.outcome, 'deleted');
  assert.equal(JSON.stringify(lookup.body).includes(receipt.signature.value), false);
  assert.equal(JSON.stringify(lookup.body).includes('must-not-leak'), false);
});

test('action reads are caller-scoped and conceal records owned by another principal', async (t) => {
  const fixture = await createServiceFixture(t);
  const challenge = await fixture.request('/v1/actions', { method: 'POST', body: DELETE_BODY });

  const concealed = await fixture.request(`/v1/actions/${challenge.body.action_id}`, {
    token: SECOND_API_TOKEN,
  });
  assert.equal(concealed.status, 404);
  assert.equal(concealed.body.error.code, 'action_not_found');
  assert.equal(JSON.stringify(concealed.body).includes('acme'), false);

  const owned = await fixture.request(`/v1/actions/${challenge.body.action_id}`);
  assert.equal(owned.status, 200);
  assert.deepEqual(owned.body.target, { owner: 'acme', repo: 'prod' });
  assert.equal(Object.hasOwn(owned.body, 'principal_id'), false);
});

test('replaying the same receipt causes zero extra DELETE calls', async (t) => {
  const fixture = await createServiceFixture(t);
  const challenge = await fixture.request('/v1/actions', { method: 'POST', body: DELETE_BODY });
  const carrier = receiptCarrier(fixture.harness.mint({ outcome: 'allow_with_signoff' }));
  const resumeBody = {
    action: 'github.repo.delete',
    challenge_binding: challenge.body.resume.challenge_binding,
  };
  const path = `/v1/actions/${challenge.body.action_id}/execute`;
  const first = await fixture.request(path, { method: 'POST', body: resumeBody, carrier });
  const replay = await fixture.request(path, { method: 'POST', body: resumeBody, carrier });

  assert.equal(first.status, 200);
  assert.equal(replay.status, 409);
  assert.equal(fixture.deleteCalls.length, 1);
  assert.equal(fixture.actionStore.records.size, 1);
});

test('a timeout after DELETE burns the receipt and emits indeterminate evidence', async (t) => {
  const logEntries = [];
  const fixture = await createServiceFixture(t, {
    logger: { info: (entry) => logEntries.push(structuredClone(entry)) },
    deleteImpl: async () => {
      const error = new Error('connector secret response must never be logged');
      error.code = 'github_delete_outcome_unknown';
      error.timeout = true;
      error.ambiguous = true;
      throw error;
    },
  });
  const receipt = fixture.harness.mint({ outcome: 'allow_with_signoff' });
  const carrier = receiptCarrier(receipt);
  const challenge = await fixture.request('/v1/actions', { method: 'POST', body: DELETE_BODY });
  const resumeBody = {
    action: 'github.repo.delete',
    challenge_binding: challenge.body.resume.challenge_binding,
  };
  const path = `/v1/actions/${challenge.body.action_id}/execute`;

  const first = await fixture.request(path, { method: 'POST', body: resumeBody, carrier });
  assert.equal(first.status, 504);
  assert.equal(first.body.status, 'indeterminate');
  assert.equal(first.body.error.code, 'github_delete_timeout_outcome_unknown');
  assert.equal(fixture.deleteCalls.length, 1);
  assert.equal(await fixture.consumptionStore.has(receipt.payload.receipt_id), true);

  const action = await fixture.request(`/v1/actions/${first.body.id}`);
  assert.equal(action.status, 200);
  assert.equal(action.body.status, 'indeterminate');

  const records = await fixture.evidenceLog.all();
  assert.ok(records.some((record) => record.kind === 'execution' && record.outcome === 'indeterminate'));

  const replay = await fixture.request(path, { method: 'POST', body: resumeBody, carrier });
  assert.equal(replay.status, 409);
  assert.equal(fixture.deleteCalls.length, 1, 'the ambiguous first attempt must never be retried');

  const logged = JSON.stringify(logEntries);
  assert.equal(logged.includes(receipt.signature.value), false);
  assert.equal(logged.includes('connector secret response'), false);
});

test('startup reconciles interrupted destructive rows without touching GitHub', async (t) => {
  const statuses = ['observing', 'authorizing', 'executing'];
  const initialActions = statuses.map((status, index) => ({
    id: `interrupted-action-${String(index).padStart(16, '0')}`,
    action: 'github.repo.delete',
    status,
    principal_id: TEST_PRINCIPAL.id,
    tenant_id: TEST_TENANT_ID,
    gate_id: TEST_GATE_ID,
    target: { owner: 'secret-owner', repo: `secret-repo-${index}` },
    created_at: '2026-01-01T00:00:00.000Z',
    updated_at: '2026-01-01T00:00:00.000Z',
  }));
  const fixture = await createServiceFixture(t, { initialActions });

  for (const record of fixture.actionStore.records.values()) {
    assert.equal(record.status, 'indeterminate');
    assert.equal(record.error.code, 'service_restart_outcome_unknown');
  }
  assert.equal(fixture.actionStore.calls.reconcileInterrupted.length, 1);
  assert.equal(fixture.getCalls.length, 0);
  assert.equal(fixture.deleteCalls.length, 0);
});

test('evidence APIs are authenticated, caller-scoped, paginated, and redacted', async (t) => {
  const fixture = await createServiceFixture(t);
  const receipt = fixture.harness.mint({ outcome: 'allow_with_signoff' });
  const executed = await fixture.request('/v1/actions', {
    method: 'POST',
    body: DELETE_BODY,
    carrier: receiptCarrier(receipt),
  });
  const actionId = executed.body.id;

  const unauthorized = await fixture.request(evidencePath('/v1/evidence/history', actionId), {
    authenticated: false,
  });
  assert.equal(unauthorized.status, 401);

  const wrongScopeCalls = fixture.evidenceLog.calls.history.length;
  const wrongScope = await fixture.request(
    `/v1/evidence/history?tenant_id=other&gate_id=${encodeURIComponent(TEST_GATE_ID)}&action_id=${actionId}`,
  );
  assert.equal(wrongScope.status, 403);
  assert.equal(fixture.evidenceLog.calls.history.length, wrongScopeCalls);

  const first = await fixture.request(evidencePath('/v1/evidence/history', actionId, '&limit=1'));
  assert.equal(first.status, 200);
  assert.equal(first.body.records.length, 1);
  assert.equal(first.body.next_cursor, 1);
  const serialized = JSON.stringify(first.body);
  assert.equal(serialized.includes(receipt.payload.receipt_id), false);
  assert.equal(serialized.includes(receipt.payload.subject ?? 'never-present'), false);
  assert.equal(serialized.includes('Acme'), false);
  assert.equal(serialized.includes('Prod'), false);

  const second = await fixture.request(evidencePath(
    '/v1/evidence/history',
    actionId,
    `&limit=10&cursor=${first.body.next_cursor}`,
  ));
  assert.equal(second.status, 200);
  assert.ok(second.body.records.length >= 1);
  assert.equal(second.body.next_cursor, null);

  const recordId = first.body.records[0].record_id;
  const record = await fixture.request(evidencePath(`/v1/evidence/records/${recordId}`, actionId));
  assert.equal(record.status, 200);
  assert.equal(record.body.record.record_id, recordId);

  const head = await fixture.request(evidencePath('/v1/evidence/head', actionId));
  assert.equal(head.status, 200);
  assert.match(head.body.head.hash, /^[0-9a-f]{64}$/);

  const verification = await fixture.request(evidencePath('/v1/evidence/verify', actionId));
  assert.equal(verification.status, 200);
  assert.equal(verification.body.verification.ok, true);

  const exported = await fixture.request(evidencePath('/v1/evidence/export', actionId, '&limit=1'));
  assert.equal(exported.status, 200);
  assert.equal(exported.body.version, 'EP-GATE-EVIDENCE-EXPORT-v1');
  assert.equal(exported.body.records.length, 1);
  assert.equal(JSON.stringify(exported.body).includes(receipt.payload.receipt_id), false);
});

test('evidence verification reports tamper or fork without exposing history', async (t) => {
  const fixture = await createServiceFixture(t, {
    evidenceVerify: async () => ({
      ok: false,
      reason: 'fork_detected',
      at: 7,
      secret: 'database-row-payload',
    }),
  });
  const challenge = await fixture.request('/v1/actions', { method: 'POST', body: DELETE_BODY });
  const response = await fixture.request(evidencePath('/v1/evidence/verify', challenge.body.action_id));

  assert.equal(response.status, 409);
  assert.deepEqual(response.body.verification, { ok: false, reason: 'fork_detected', at: 7 });
  assert.equal(JSON.stringify(response.body).includes('database-row-payload'), false);
});

test('SIEM telemetry failure never changes enforcement and is visible in metrics', async (t) => {
  const fixture = await createServiceFixture(t, {
    siemForwarder: {
      async forward() { throw new Error('collector unavailable with secret endpoint'); },
    },
  });
  const response = await fixture.request('/v1/actions', {
    method: 'POST',
    body: DELETE_BODY,
    carrier: receiptCarrier(fixture.harness.mint({ outcome: 'allow_with_signoff' })),
  });
  assert.equal(response.status, 200);
  assert.equal(fixture.deleteCalls.length, 1);

  await new Promise((resolve) => setImmediate(resolve));
  const metrics = await fixture.request(
    `/v1/metrics?tenant_id=${encodeURIComponent(TEST_TENANT_ID)}`
      + `&gate_id=${encodeURIComponent(TEST_GATE_ID)}&action_id=github.repo.delete`,
  );
  assert.equal(metrics.status, 200);
  assert.ok(metrics.body.counters.telemetry_dropped_total >= 1);
  assert.equal(JSON.stringify(metrics.body).includes('collector unavailable'), false);
});

test('malformed input never escapes the HTTP boundary and caller-observed fields are refused', async (t) => {
  const fixture = await createServiceFixture(t);
  const malformed = await fixture.request('/v1/actions', {
    method: 'POST',
    rawBody: '{"action":',
  });
  assert.equal(malformed.status, 400);

  const duplicate = await fixture.request('/v1/actions', {
    method: 'POST',
    rawBody: '{"action":"github.repo.delete","action":"github.issue.delete","owner":"acme","repo":"prod"}',
  });
  assert.equal(duplicate.status, 400);

  const observedInjection = await fixture.request('/v1/actions', {
    method: 'POST',
    body: { ...DELETE_BODY, node_id: OBSERVED_ACTION.node_id },
  });
  assert.equal(observedInjection.status, 400);

  const bodyReceipt = await fixture.request('/v1/actions', {
    method: 'POST',
    body: { ...DELETE_BODY, receipt: {} },
  });
  assert.equal(bodyReceipt.status, 400);

  const dotSegment = await fixture.request('/v1/actions', {
    method: 'POST',
    body: { ...DELETE_BODY, owner: '..' },
  });
  assert.equal(dotSegment.status, 400);

  const wrongAction = await fixture.request('/v1/actions', {
    method: 'POST',
    body: { ...DELETE_BODY, action: 'github.repo.archive' },
  });
  assert.equal(wrongAction.status, 400);

  assert.equal(fixture.getCalls.length, 0);
  assert.equal(fixture.deleteCalls.length, 0);

  const invalidCarrier = await fixture.request('/v1/actions', {
    method: 'POST',
    body: DELETE_BODY,
    carrier: 'not*canonical-base64',
  });
  assert.equal(invalidCarrier.status, 428);
  assert.equal(invalidCarrier.body.detail, 'receipt_carrier_invalid');
  assert.equal(fixture.deleteCalls.length, 0);

  const duplicateReceiptJson = Buffer.from(
    '{"@version":"EP-RECEIPT-v1","payload":{},"payload":{"forged":true},"signature":{"value":"x"}}',
    'utf8',
  ).toString('base64');
  const duplicateCarrier = await fixture.request('/v1/actions', {
    method: 'POST',
    body: DELETE_BODY,
    carrier: duplicateReceiptJson,
  });
  assert.equal(duplicateCarrier.status, 428);
  assert.equal(duplicateCarrier.body.detail, 'receipt_carrier_invalid');
  assert.equal(fixture.deleteCalls.length, 0);
});
