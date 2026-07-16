// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DELETE_BODY,
  OBSERVED_ACTION,
  createServiceFixture,
  receiptCarrier,
} from './helpers.js';

test('GET /v1/health exposes a secret-free readiness response', async (t) => {
  const fixture = await createServiceFixture(t);
  const response = await fixture.request('/v1/health');
  assert.equal(response.status, 200);
  assert.deepEqual(response.body, {
    status: 'ok',
    service: 'emilia-gate-service',
    action: 'github.repo.delete',
  });
  assert.equal(fixture.getCalls.length, 0);
  assert.equal(fixture.deleteCalls.length, 0);
});

test('no receipt returns a 428 exact-action challenge and makes zero DELETE calls', async (t) => {
  const fixture = await createServiceFixture(t);
  const response = await fixture.request('/v1/actions', { method: 'POST', body: DELETE_BODY });

  assert.equal(response.status, 428);
  assert.equal(response.body.status, 428);
  assert.equal(response.body.required.action, 'github.repo.delete');
  assert.deepEqual(response.body.required.observed_action, OBSERVED_ACTION);
  assert.match(response.headers.get('receipt-required'), /github\.repo\.delete/);
  assert.equal(fixture.getCalls.length, 1, 'the service observes GitHub before issuing the exact challenge');
  assert.equal(fixture.deleteCalls.length, 0);
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

test('replaying the same receipt causes zero extra DELETE calls', async (t) => {
  const fixture = await createServiceFixture(t);
  const carrier = receiptCarrier(fixture.harness.mint({ outcome: 'allow_with_signoff' }));
  const first = await fixture.request('/v1/actions', { method: 'POST', body: DELETE_BODY, carrier });
  const replay = await fixture.request('/v1/actions', { method: 'POST', body: DELETE_BODY, carrier });

  assert.equal(first.status, 200);
  assert.equal(replay.status, 428);
  assert.match(replay.body.detail, /replay/i);
  assert.equal(fixture.deleteCalls.length, 1);
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

  const first = await fixture.request('/v1/actions', { method: 'POST', body: DELETE_BODY, carrier });
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

  const replay = await fixture.request('/v1/actions', { method: 'POST', body: DELETE_BODY, carrier });
  assert.equal(replay.status, 428);
  assert.equal(fixture.deleteCalls.length, 1, 'the ambiguous first attempt must never be retried');

  const logged = JSON.stringify(logEntries);
  assert.equal(logged.includes(receipt.signature.value), false);
  assert.equal(logged.includes('connector secret response'), false);
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
