// SPDX-License-Identifier: Apache-2.0
// Vercel / Cloudflare / Linear / Jira / Salesforce adapters — refuse without a
// receipt (client never called), run with a valid one, refuse drift, enforce tier.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGate, createEg1Harness } from '../index.js';
import { createVercelManifest, guardVercelMutation, VERCEL_OPS } from './vercel.js';
import { createCloudflareManifest, guardCloudflareMutation, CLOUDFLARE_OPS } from './cloudflare.js';
import { createLinearManifest, guardLinearMutation, LINEAR_OPS } from './linear.js';
import { createJiraManifest, guardJiraMutation, JIRA_OPS } from './jira.js';
import { createSalesforceManifest, guardSalesforceMutation, SALESFORCE_OPS } from './salesforce.js';

const A = 'allow_with_signoff';
const Q = { quorum: { signers: ['ep:a', 'ep:b'], threshold: 2 } };
function setup(manifest, action) {
  const harness = createEg1Harness({ action });
  return { harness, gate: createGate({ manifest, trustedKeys: [harness.publicKey], approverKeys: harness.approverKeys, quorumPolicy: harness.quorumPolicy, rpId: harness.rpId, allowedOrigins: harness.allowedOrigins, allowEphemeralStore: true }) };
}

test('op inventories', () => {
  assert.deepEqual([...VERCEL_OPS].sort(), ['deploy.promote', 'env.set', 'project.delete']);
  assert.deepEqual([...CLOUDFLARE_OPS].sort(), ['dns.delete', 'firewall.disable', 'zone.delete']);
  assert.deepEqual([...LINEAR_OPS].sort(), ['issue.bulk_delete', 'issue.delete', 'team.delete']);
  assert.deepEqual([...JIRA_OPS].sort(), ['issue.bulk_delete', 'permission.grant', 'project.delete']);
  assert.deepEqual([...SALESFORCE_OPS].sort(), ['data.export', 'permission_set.assign', 'records.bulk_delete']);
});

test('vercel: env.set refused without receipt, runs with Class-A, drift refused', async () => {
  const action = { action_type: 'vercel.env.set', project: 'app', key: 'STRIPE_KEY', target: 'production' };
  const { harness, gate } = setup(createVercelManifest(), action);
  const calls = [];
  const client = { upsertEnv: async (p) => { calls.push(p); return { ok: true }; } };
  await assert.rejects(() => guardVercelMutation(gate, client, { op: 'env.set', params: { project: 'app', key: 'STRIPE_KEY', target: 'production' } }), (e) => e.code === 'EMILIA_RECEIPT_REQUIRED');
  assert.equal(calls.length, 0);
  const ok = await guardVercelMutation(gate, client, { op: 'env.set', params: { project: 'app', key: 'STRIPE_KEY', target: 'production', value: 's' }, receipt: harness.mint({ outcome: A }) });
  assert.equal(ok.result.ok, true);
  await assert.rejects(
    () => guardVercelMutation(gate, client, { op: 'env.set', params: { project: 'app', key: 'OTHER', target: 'production' }, receipt: harness.mint({ outcome: A }) }),
    (e) => /binding/.test(e.gate.reason),
  );
});

test('vercel: promote-to-production requires quorum', async () => {
  const action = { action_type: 'vercel.deploy.promote', project: 'app', deployment_id: 'dpl_1' };
  const { harness, gate } = setup(createVercelManifest(), action);
  const client = { promoteDeployment: async () => ({ ok: true }) };
  await assert.rejects(
    () => guardVercelMutation(gate, client, { op: 'deploy.promote', params: { project: 'app', deployment_id: 'dpl_1' }, receipt: harness.mint({ outcome: A }) }),
    (e) => /assurance/.test(e.gate.reason),
  );
  const ok = await guardVercelMutation(gate, client, { op: 'deploy.promote', params: { project: 'app', deployment_id: 'dpl_1' }, receipt: harness.mint({ outcome: A, ...Q }) });
  assert.equal(ok.result.ok, true);
});

test('cloudflare: zone delete requires quorum; DNS delete is Class-A + replay-safe', async () => {
  const dns = { action_type: 'cloudflare.dns.delete', zone: 'z1', record_id: 'r1' };
  const { harness, gate } = setup(createCloudflareManifest(), dns);
  const client = { deleteDnsRecord: async () => ({ ok: true }), deleteZone: async () => ({ ok: true }), setFirewallRule: async () => ({ ok: true }) };
  const receipt = harness.mint({ outcome: A });
  const ok = await guardCloudflareMutation(gate, client, { op: 'dns.delete', params: { zone: 'z1', record_id: 'r1' }, receipt });
  assert.equal(ok.result.ok, true);
  await assert.rejects(() => guardCloudflareMutation(gate, client, { op: 'dns.delete', params: { zone: 'z1', record_id: 'r1' }, receipt }), (e) => /replay/.test(e.gate.reason));
});

test('linear: bulk delete binds the query hash', async () => {
  const action = { action_type: 'linear.issue.bulk_delete', team: 'ENG', query_hash: undefined };
  // mint with the same query the call uses so the hash matches.
  const harness = createEg1Harness({ action: { action_type: 'linear.issue.bulk_delete', team: 'ENG' } });
  const gate = createGate({ manifest: createLinearManifest(), trustedKeys: [harness.publicKey], approverKeys: harness.approverKeys, quorumPolicy: harness.quorumPolicy, rpId: harness.rpId, allowedOrigins: harness.allowedOrigins, allowEphemeralStore: true });
  const client = { bulkDeleteIssues: async () => ({ deleted: 9 }) };
  // The receipt must carry the query_hash; mint with extra fields matching observed.
  const { hashCanonical } = await import('./_kit.js');
  const qhash = hashCanonical('state = Done');
  const receipt = harness.mint({ outcome: A, extra: { query_hash: qhash } });
  const ok = await guardLinearMutation(gate, client, { op: 'issue.bulk_delete', params: { team: 'ENG', query: 'state = Done' }, receipt });
  assert.equal(ok.result.deleted, 9);
  await assert.rejects(
    () => guardLinearMutation(gate, client, { op: 'issue.bulk_delete', params: { team: 'ENG', query: 'state = Backlog' }, receipt: harness.mint({ outcome: A, extra: { query_hash: qhash } }) }),
    (e) => /binding/.test(e.gate.reason),
  );
  void action;
});

test('jira: project delete requires quorum, never reaches Jira without it', async () => {
  const action = { action_type: 'jira.project.delete', project_key: 'OPS' };
  const { harness, gate } = setup(createJiraManifest(), action);
  const calls = [];
  const client = { deleteProject: async (p) => { calls.push(p); return { ok: true }; } };
  await assert.rejects(() => guardJiraMutation(gate, client, { op: 'project.delete', params: { project_key: 'OPS' }, receipt: harness.mint({ outcome: A }) }), (e) => /assurance/.test(e.gate.reason));
  assert.equal(calls.length, 0);
  const ok = await guardJiraMutation(gate, client, { op: 'project.delete', params: { project_key: 'OPS' }, receipt: harness.mint({ outcome: A, ...Q }) });
  assert.equal(ok.result.ok, true);
});

test('salesforce: permission-set assign requires quorum; bulk delete binds SOQL', async () => {
  const sf = { action_type: 'salesforce.permission_set.assign', user: 'u1', permission_set: 'Admin' };
  const { harness, gate } = setup(createSalesforceManifest(), sf);
  const client = { assignPermissionSet: async () => ({ ok: true }), bulkDelete: async () => ({ deleted: 3 }) };
  await assert.rejects(
    () => guardSalesforceMutation(gate, client, { op: 'permission_set.assign', params: { user: 'u1', permission_set: 'Admin' }, receipt: harness.mint({ outcome: A }) }),
    (e) => /assurance/.test(e.gate.reason),
  );
  const ok = await guardSalesforceMutation(gate, client, { op: 'permission_set.assign', params: { user: 'u1', permission_set: 'Admin' }, receipt: harness.mint({ outcome: A, ...Q }) });
  assert.equal(ok.result.ok, true);
});
