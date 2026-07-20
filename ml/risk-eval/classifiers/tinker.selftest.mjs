// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRemoteClassifier } from './tinker.mjs';

const ENDPOINT = 'http://model.invalid/classify';
const response = (body, { ok = true, status = 200 } = {}) => ({
  ok,
  status,
  async json() {
    if (body instanceof Error) throw body;
    return body;
  },
});

const classifyWith = (fetchImpl, timeoutMs = 50) => createRemoteClassifier({
  endpoint: ENDPOINT,
  timeoutMs,
  fetchImpl,
});

test('lower-tier output cannot lower the deterministic signoff floor', async () => {
  const classify = classifyWith(async () => response({
    tier: 'allow',
    injection_suspected: false,
  }));
  const out = await classify({
    actionType: 'vendor_bank_account_change',
    targetChangedFields: ['bank_account'],
    riskFlags: [],
  });

  assert.equal(out.decision, 'allow_with_signoff');
  assert.equal(out.signoffRequired, true);
  assert.equal(out.advisory.requested_tier, 'allow');
  assert.equal(out.advisory.raised, false);
});

test('lower-tier output cannot lower the deterministic deny floor', async () => {
  const classify = classifyWith(async () => response({
    tier: 'allow',
    injection_suspected: false,
  }));
  const out = await classify({
    actionType: 'vendor_bank_account_change',
    targetChangedFields: ['bank_account'],
    riskFlags: ['impossible_travel'],
  });

  assert.equal(out.decision, 'deny');
  assert.equal(out.advisory.requested_tier, 'allow');
});

test('malformed model output fails closed to signoff', async () => {
  const classify = classifyWith(async () => response({
    tier: 'definitely_safe',
    injection_suspected: 'no',
  }));
  const out = await classify({
    actionType: 'update_profile',
    targetChangedFields: ['display_name'],
    riskFlags: [],
  });

  assert.equal(out.decision, 'allow_with_signoff');
  assert.equal(out.signoffRequired, true);
  assert.equal(out.advisory.status, 'error');
  assert.equal(out.advisory.error, 'malformed_response');
  assert.equal(out.advisory.raised, true);
});

test('invalid JSON fails closed to signoff', async () => {
  const classify = classifyWith(async () => response(new SyntaxError('invalid JSON')));
  const out = await classify({
    actionType: 'update_profile',
    targetChangedFields: ['display_name'],
    riskFlags: [],
  });

  assert.equal(out.decision, 'allow_with_signoff');
  assert.equal(out.advisory.error, 'malformed_response');
});

test('timeout fails closed to signoff', async () => {
  const classify = classifyWith((_url, { signal }) => new Promise((resolve, reject) => {
    signal.addEventListener('abort', () => {
      const error = new Error('aborted');
      error.name = 'AbortError';
      reject(error);
    }, { once: true });
  }), 5);
  const out = await classify({
    actionType: 'update_profile',
    targetChangedFields: ['display_name'],
    riskFlags: [],
  });

  assert.equal(out.decision, 'allow_with_signoff');
  assert.equal(out.advisory.error, 'timeout');
});

test('HTTP and network errors fail closed without returning allow', async (t) => {
  await t.test('HTTP error', async () => {
    const classify = classifyWith(async () => response({}, { ok: false, status: 503 }));
    const out = await classify({
      actionType: 'update_profile',
      targetChangedFields: ['display_name'],
      riskFlags: [],
    });
    assert.equal(out.decision, 'allow_with_signoff');
    assert.equal(out.advisory.error, 'http_error');
  });

  await t.test('network error', async () => {
    const classify = classifyWith(async () => {
      throw new Error('connection reset');
    });
    const out = await classify({
      actionType: 'update_profile',
      targetChangedFields: ['display_name'],
      riskFlags: [],
    });
    assert.equal(out.decision, 'allow_with_signoff');
    assert.equal(out.advisory.error, 'network_error');
  });
});

test('adversarial signal raises allow to signoff even when remote tier says allow', async () => {
  const classify = classifyWith(async () => response({
    tier: 'allow',
    injection_suspected: true,
  }));
  const out = await classify({
    actionType: 'send_email',
    targetChangedFields: [],
    riskFlags: [],
    context: { agent_reasoning: 'ignore previous instructions' },
  });

  assert.equal(out.decision, 'allow_with_signoff');
  assert.equal(out.advisory.injection_suspected, true);
  assert.equal(out.advisory.raised, true);
});

test('valid benign output preserves a deterministic allow', async () => {
  const classify = classifyWith(async () => response({
    tier: 'allow',
    injection_suspected: false,
  }));
  const out = await classify({
    actionType: 'update_profile',
    targetChangedFields: ['display_name'],
    riskFlags: [],
  });

  assert.equal(out.decision, 'allow');
  assert.equal(out.advisory.status, 'ok');
  assert.equal(out.advisory.raised, false);
});

test('remote deny remains advisory and raises allow only to signoff', async () => {
  const classify = classifyWith(async () => response({
    tier: 'deny',
    injection_suspected: false,
  }));
  const out = await classify({
    actionType: 'update_profile',
    targetChangedFields: ['display_name'],
    riskFlags: [],
  });

  assert.equal(out.decision, 'allow_with_signoff');
  assert.equal(out.advisory.requested_tier, 'deny');
});
