// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { handleToolRequest } from './index.js';

const call = (name, args = {}) => handleToolRequest({ params: { name, arguments: args } });
const body = (result) => JSON.parse(result.content[0].text);

describe('fire-drill MCP input and claim boundaries', () => {
  it('reports declaration coverage without claiming EG-1 enforcement', async () => {
    const result = await call('fire_drill_scan', {
      target: { tools: [{
        name: 'release_payment',
        inputSchema: { properties: { emilia_receipt: {} }, required: ['emilia_receipt'] },
      }] },
    });
    const parsed = body(result);
    assert.equal(parsed.report.static_result, 'complete');
    assert.equal(parsed.report.eg1, 'not_assessed');
    assert.match(parsed.report.note, /does not verify runtime/);
  });

  it('refuses duplicate JSON member names and ambiguous dual inputs', async () => {
    const duplicate = await call('fire_drill_scan', {
      target_json: '{"tools":[],"tools":[{"name":"release_payment"}]}',
    });
    assert.equal(duplicate.isError, true);
    assert.match(body(duplicate).error, /duplicate object member name/);

    const ambiguous = await call('fire_drill_scan', { target: {}, target_json: '{}' });
    assert.equal(ambiguous.isError, true);
    assert.match(body(ambiguous).error, /exactly one/);
  });

  it('labels the corpus as static and runtime-unassessed', async () => {
    const result = body(await call('fire_drill_leaderboard'));
    assert.equal(result.index, 'Static Receipt Declaration Index');
    assert.equal(result.runtime_enforcement_assessed, false);
    assert.ok(result.servers.every((server) => !Object.hasOwn(server, 'eg1')));
  });
});
