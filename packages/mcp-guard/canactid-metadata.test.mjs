// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  MCP_CANACTID_META_KEY,
  attachCanactidMetadata,
  withMcpReceiptGuard,
} from './dist/index.js';

const CURRENT = `canactid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`;
const LEGACY = `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`;

test('adds a server-computed canactid to MCP result metadata without mutation', () => {
  const result = Object.freeze({
    content: Object.freeze([{ type: 'text', text: 'released' }]),
    _meta: Object.freeze({ trace_id: 'trace-1' }),
  });
  const decorated = attachCanactidMetadata(result, CURRENT);
  assert.deepEqual(decorated, {
    content: [{ type: 'text', text: 'released' }],
    _meta: {
      trace_id: 'trace-1',
      [MCP_CANACTID_META_KEY]: CURRENT,
    },
  });
  assert.equal(result._meta[MCP_CANACTID_META_KEY], undefined);
});

test('refuses legacy caid and malformed MCP metadata instead of silently accepting either', () => {
  assert.throws(() => attachCanactidMetadata({ content: [] }, LEGACY), /current canactid/);
  assert.throws(() => attachCanactidMetadata({ content: [], _meta: [] }, CURRENT), /_meta/);
});

test('receipt guard publishes only a server-recomputed canactid on the MCP result', async () => {
  const guarded = withMcpReceiptGuard(async () => ({ content: [{ type: 'text', text: 'ok' }] }), {
    annotations: {
      wire: {
        irreversible: true,
        actionType: 'payment.release.1',
        targetResourceId: 'acct:A',
      },
    },
    resolveCanactid({ tool, args, action_type }) {
      assert.equal(tool, 'wire');
      assert.deepEqual(args, { amount: 50, destination: 'acct:A' });
      assert.equal(action_type, 'payment.release.1');
      return CURRENT;
    },
    client: {
      async requireReceipt(_params, mutate) {
        return { result: await mutate() };
      },
    },
  });

  const result = await guarded('wire', { amount: 50, destination: 'acct:A' });
  assert.equal(result._meta[MCP_CANACTID_META_KEY], CURRENT);
});

test('receipt guard refuses a legacy resolver result before the provider is entered', async () => {
  let providerCalls = 0;
  let receiptCalls = 0;
  const guarded = withMcpReceiptGuard(async () => {
    providerCalls += 1;
    return { content: [] };
  }, {
    annotations: {
      wire: {
        irreversible: true,
        actionType: 'payment.release.1',
        targetResourceId: 'acct:A',
      },
    },
    resolveCanactid: () => LEGACY,
    client: {
      async requireReceipt(_params, mutate) {
        receiptCalls += 1;
        return { result: await mutate() };
      },
    },
  });

  const result = await guarded('wire', { amount: 50, destination: 'acct:A' });
  assert.equal(result.ep_refused, true);
  assert.equal(result.stage, 'bind');
  assert.equal(result.rejected.reason, 'canactid_binding_invalid');
  assert.equal(receiptCalls, 0);
  assert.equal(providerCalls, 0);
});
