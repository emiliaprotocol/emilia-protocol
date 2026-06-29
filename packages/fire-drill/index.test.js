// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scan, classifyOperation, scanMcpManifest, scanOpenApi, badgeSvg, generatePullRequest, aggregate } from './index.js';
import { REPRESENTATIVE_CORPUS } from './corpus.js';

test('classifies the high-risk families', () => {
  assert.equal(classifyOperation({ name: 'release_payment' }).family, 'money_movement');
  assert.equal(classifyOperation({ name: 'delete_customer_data' }).family, 'data_destruction');
  assert.equal(classifyOperation({ name: 'deploy_production' }).family, 'production_deploy');
  assert.equal(classifyOperation({ name: 'change_permissions' }).family, 'permission_change');
  assert.equal(classifyOperation({ name: 'export_customers' }).family, 'data_export');
  assert.equal(classifyOperation({ name: 'get_status' }).dangerous, false);
  // HTTP DELETE is destructive regardless of name
  assert.equal(classifyOperation({ name: 'customers', method: 'DELETE', path: '/customers/{id}' }).family, 'data_destruction');
  // a read-only GET that merely mentions "deploy" is not a mutation
  assert.equal(classifyOperation({ name: 'list_deploys', method: 'GET' }).dangerous, false);
});

test('MCP manifest: an ungated dangerous tool FAILS', () => {
  const r = scanMcpManifest({
    tools: [
      { name: 'read_status', description: 'read only' },
      { name: 'delete_customer_data', description: 'hard delete a customer' },
    ],
  });
  assert.equal(r.eg1, 'fail');
  assert.equal(r.summary.dangerous, 1);
  assert.equal(r.summary.ungated, 1);
  assert.equal(r.score, 0);
  assert.match(r.findings[0].message, /delete_customer_data`? can execute without an accountable human receipt/);
  assert.ok(r.findings[0].fix.includes('@emilia-protocol/gate'));
});

test('MCP manifest: a dangerous tool with a receipt parameter PASSES', () => {
  const r = scanMcpManifest({
    tools: [{
      name: 'release_payment',
      description: 'move money',
      inputSchema: { type: 'object', properties: { amount: { type: 'number' }, emilia_receipt: { type: 'object' } } },
    }],
  });
  assert.equal(r.eg1, 'pass');
  assert.equal(r.summary.dangerous, 1);
  assert.equal(r.summary.gated, 1);
  assert.equal(r.score, 100);
});

test('a fully read-only manifest scores 100', () => {
  const r = scanMcpManifest({ tools: [{ name: 'list_items' }, { name: 'get_status' }] });
  assert.equal(r.score, 100);
  assert.equal(r.eg1, 'pass');
  assert.equal(r.summary.dangerous, 0);
});

test('OpenAPI: an ungated DELETE FAILS; a receipt header PASSES', () => {
  const fail = scanOpenApi({
    openapi: '3.0.0',
    paths: { '/customers/{id}': { delete: { operationId: 'deleteCustomer', summary: 'delete a customer' } } },
  });
  assert.equal(fail.eg1, 'fail');
  assert.equal(fail.findings[0].operation, 'deleteCustomer');

  const pass = scanOpenApi({
    openapi: '3.0.0',
    paths: {
      '/customers/{id}': {
        delete: {
          operationId: 'deleteCustomer',
          parameters: [{ name: 'X-Emilia-Receipt', in: 'header', required: true }],
        },
      },
    },
  });
  assert.equal(pass.eg1, 'pass');
});

test('partial coverage produces a fractional score', () => {
  const r = scanMcpManifest({
    tools: [
      { name: 'delete_record', description: 'delete' }, // ungated
      { name: 'release_payment', inputSchema: { properties: { emilia_receipt: {} } } }, // gated
    ],
  });
  assert.equal(r.summary.dangerous, 2);
  assert.equal(r.summary.gated, 1);
  assert.equal(r.score, 50);
  assert.equal(r.eg1, 'fail');
});

test('scan() auto-detects the input shape', () => {
  assert.equal(scan({ tools: [{ name: 'x' }] }).target_type, 'mcp');
  assert.equal(scan({ paths: {} }).target_type, 'openapi');
  assert.equal(scan([{ name: 'x' }]).target_type, 'tools');
  assert.throws(() => scan({ nonsense: true }));
});

test('badgeSvg renders green for pass, red for fail, score when given', () => {
  const pass = badgeSvg({ eg1: 'pass' });
  assert.ok(pass.startsWith('<svg') && pass.includes('EG-1 Enforced') && pass.includes('#16A34A'));
  const fail = badgeSvg({ eg1: 'fail' });
  assert.ok(fail.includes('not earned') && fail.includes('#DC2626'));
  const partial = badgeSvg({ score: 50 });
  assert.ok(partial.includes('50/100') && partial.includes('#D97706'));
  assert.ok(badgeSvg({ score: 100 }).includes('#16A34A'));
});

test('badgeSvg escapes quotes — no attribute breakout / event-handler injection', () => {
  const svg = badgeSvg({ eg1: 'pass', label: 'x" onload="alert(1)' });
  assert.ok(!svg.includes('" onload="alert'), 'must not contain a live broken-out attribute');
  assert.ok(svg.includes('&quot;'), 'the quote must be entity-escaped');
  // angle brackets are escaped, so no tag can form either
  const lt = String.fromCharCode(60); // '<'
  const svg2 = badgeSvg({ eg1: 'fail', label: `${lt}svg onload=1` });
  assert.ok(!svg2.includes(`${lt}svg onload`), 'raw angle bracket must not survive');
  assert.ok(svg2.includes('&lt;svg onload'), 'angle bracket must be entity-escaped');
});

test('generatePullRequest lists failing ops + the gate fix', () => {
  const r = scanMcpManifest({ tools: [{ name: 'delete_records' }, { name: 'release_payment' }] });
  const pr = generatePullRequest(r, { project: 'acme/mcp' });
  assert.match(pr.title, /Require an EMILIA receipt for 2 high-risk actions for acme\/mcp/);
  assert.ok(pr.body.includes('gateMcpTool') && pr.body.includes('delete_records') && pr.body.includes('release_payment'));
});

test('generatePullRequest confirms a clean pass', () => {
  const r = scanMcpManifest({ tools: [{ name: 'get_status' }] });
  const pr = generatePullRequest(r);
  assert.match(pr.title, /Confirm EG-1 Enforced/);
  assert.ok(pr.body.includes('EG-1 Enforced'));
});

test('aggregate summarizes a corpus honestly', () => {
  const reports = [
    scanMcpManifest({ tools: [{ name: 'delete_records' }] }),       // 1 ungated
    scanMcpManifest({ tools: [{ name: 'get_status' }] }),           // clean
    scanMcpManifest({ tools: [{ name: 'release_payment' }, { name: 'export_data' }] }), // 2 ungated
  ];
  const agg = aggregate(reports);
  assert.equal(agg.servers, 3);
  assert.equal(agg.servers_with_unguarded_action, 2);
  assert.equal(agg.pct_servers_with_unguarded_action, 67);
  assert.equal(agg.unguarded_operations, 3);
  assert.ok(agg.by_family.money_movement >= 1 && agg.by_family.data_destruction >= 1);
});

test('aggregate of an empty corpus is a clean 100', () => {
  const agg = aggregate([]);
  assert.equal(agg.servers, 0);
  assert.equal(agg.mean_score, 100);
  assert.equal(agg.pct_servers_with_unguarded_action, 0);
});

test('the representative corpus computes a real index (mostly unguarded)', () => {
  const agg = aggregate(REPRESENTATIVE_CORPUS.map((c) => scan(c.manifest)));
  assert.equal(agg.servers, REPRESENTATIVE_CORPUS.length);
  assert.ok(agg.pct_servers_with_unguarded_action >= 80); // the point of the Report
});
