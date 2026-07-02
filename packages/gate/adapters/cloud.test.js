// SPDX-License-Identifier: Apache-2.0
// K8s / Terraform / GCP adapters — refuse without a receipt (client never called),
// run with a valid receipt, refuse drift, enforce tier.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGate, createEg1Harness } from '../index.js';
import { createK8sManifest, guardK8sMutation, K8S_OPS } from './k8s.js';
import { createTerraformManifest, guardTerraformMutation, TERRAFORM_OPS } from './terraform.js';
import { createGcpManifest, guardGcpMutation, GCP_OPS } from './gcp.js';

function gateFor(manifest, action) {
  const harness = createEg1Harness({ action });
  return { harness, gate: createGate({ manifest, trustedKeys: [harness.publicKey], approverKeys: harness.approverKeys }) };
}
const A = 'allow_with_signoff';
const Q = { quorum: { signers: ['ep:a', 'ep:b'], threshold: 2 } };

test('op inventories', () => {
  assert.deepEqual([...K8S_OPS].sort(), ['namespace.delete', 'rbac.bind', 'secret.delete', 'workload.delete']);
  assert.deepEqual([...TERRAFORM_OPS].sort(), ['apply.destroy', 'state.rm', 'workspace.delete']);
  assert.deepEqual([...GCP_OPS].sort(), ['iam.set_policy', 'project.delete', 'sa_key.create', 'storage.bucket_delete']);
});

test('k8s: secret delete refused without receipt, runs with Class-A, drift refused', async () => {
  const action = { action_type: 'k8s.secret.delete', namespace: 'prod', name: 'db-creds' };
  const { harness, gate } = gateFor(createK8sManifest(), action);
  const calls = [];
  const client = { deleteSecret: async (p) => { calls.push(p); return { ok: true }; } };
  await assert.rejects(() => guardK8sMutation(gate, client, { op: 'secret.delete', params: { namespace: 'prod', name: 'db-creds' } }), (e) => e.code === 'EMILIA_RECEIPT_REQUIRED');
  assert.equal(calls.length, 0);
  const ok = await guardK8sMutation(gate, client, { op: 'secret.delete', params: { namespace: 'prod', name: 'db-creds' }, receipt: harness.mint({ outcome: A }) });
  assert.equal(ok.result.ok, true);
  await assert.rejects(
    () => guardK8sMutation(gate, client, { op: 'secret.delete', params: { namespace: 'prod', name: 'OTHER' }, receipt: harness.mint({ outcome: A }) }),
    (e) => /binding/.test(e.gate.reason),
  );
});

test('k8s: namespace delete requires quorum', async () => {
  const action = { action_type: 'k8s.namespace.delete', namespace: 'prod' };
  const { harness, gate } = gateFor(createK8sManifest(), action);
  const client = { deleteNamespace: async () => ({ ok: true }) };
  await assert.rejects(
    () => guardK8sMutation(gate, client, { op: 'namespace.delete', params: { namespace: 'prod' }, receipt: harness.mint({ outcome: A }) }),
    (e) => /assurance/.test(e.gate.reason),
  );
  const ok = await guardK8sMutation(gate, client, { op: 'namespace.delete', params: { namespace: 'prod' }, receipt: harness.mint({ outcome: A, ...Q }) });
  assert.equal(ok.result.ok, true);
});

test('terraform: destroy binds the plan hash and requires quorum', async () => {
  const action = { action_type: 'terraform.apply.destroy', workspace: 'prod', plan_hash: 'sha256:plan1' };
  const { harness, gate } = gateFor(createTerraformManifest(), action);
  const calls = [];
  const runner = { destroy: async (p) => { calls.push(p); return { destroyed: 3 }; } };
  // class_a insufficient
  await assert.rejects(
    () => guardTerraformMutation(gate, runner, { op: 'apply.destroy', params: { workspace: 'prod', plan_hash: 'sha256:plan1' }, receipt: harness.mint({ outcome: A }) }),
    (e) => /assurance/.test(e.gate.reason),
  );
  // quorum + correct plan runs
  const ok = await guardTerraformMutation(gate, runner, { op: 'apply.destroy', params: { workspace: 'prod', plan_hash: 'sha256:plan1' }, receipt: harness.mint({ outcome: A, ...Q }) });
  assert.equal(ok.result.destroyed, 3);
  // a different plan than approved is refused
  await assert.rejects(
    () => guardTerraformMutation(gate, runner, { op: 'apply.destroy', params: { workspace: 'prod', plan_hash: 'sha256:FULL_TEARDOWN' }, receipt: harness.mint({ outcome: A, ...Q }) }),
    (e) => /binding/.test(e.gate.reason),
  );
});

test('gcp: bucket delete (Class-A) runs; IAM set-policy requires quorum', async () => {
  const bAction = { action_type: 'gcp.storage.bucket_delete', bucket: 'prod-data' };
  const { harness, gate } = gateFor(createGcpManifest(), bAction);
  const client = { deleteBucket: async () => ({ ok: true }), setIamPolicy: async () => ({ ok: true }) };
  const ok = await guardGcpMutation(gate, client, { op: 'storage.bucket_delete', params: { bucket: 'prod-data' }, receipt: harness.mint({ outcome: A }) });
  assert.equal(ok.result.ok, true);

  const iamAction = { action_type: 'gcp.iam.set_policy', resource: 'proj/x', member: 'user:m@x', role: 'roles/owner' };
  const g2 = gateFor(createGcpManifest(), iamAction);
  await assert.rejects(
    () => guardGcpMutation(g2.gate, client, { op: 'iam.set_policy', params: { resource: 'proj/x', member: 'user:m@x', role: 'roles/owner' }, receipt: g2.harness.mint({ outcome: A }) }),
    (e) => /assurance/.test(e.gate.reason),
  );
  const okIam = await guardGcpMutation(g2.gate, client, { op: 'iam.set_policy', params: { resource: 'proj/x', member: 'user:m@x', role: 'roles/owner' }, receipt: g2.harness.mint({ outcome: A, ...Q }) });
  assert.equal(okIam.result.ok, true);
});
