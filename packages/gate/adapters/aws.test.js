// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGate, createEg1Harness } from '../index.js';
import { createAwsManifest, guardAwsMutation, AWS_OPS } from './aws.js';

function fakeAws() {
  const calls = [];
  return {
    calls,
    iam: {
      attachUserPolicy: async (p) => { calls.push(['attach', p]); return { ok: true }; },
      createAccessKey: async (p) => { calls.push(['key', p]); return { AccessKey: { AccessKeyId: 'AKIA1' } }; },
      deleteUser: async (p) => { calls.push(['del', p]); return { ok: true }; },
    },
    ec2: { authorizeSecurityGroupIngress: async (p) => { calls.push(['ingress', p]); return { Return: true }; } },
  };
}
function setup(action) {
  const harness = createEg1Harness({ action });
  return { harness, gate: createGate({ manifest: createAwsManifest(), trustedKeys: [harness.publicKey] }), aws: fakeAws() };
}

test('exposes the high-blast-radius AWS ops', () => {
  assert.deepEqual([...AWS_OPS].sort(), ['ec2.authorize_ingress', 'iam.attach_policy', 'iam.create_access_key', 'iam.delete_user']);
});

test('attach-policy requires quorum and never reaches AWS without it', async () => {
  const action = { action_type: 'aws.iam.attach_policy', user: 'svc-bot', policy_arn: 'arn:aws:iam::aws:policy/AdministratorAccess' };
  const { gate, harness, aws } = setup(action);
  const params = { user: 'svc-bot', policy_arn: 'arn:aws:iam::aws:policy/AdministratorAccess' };
  // no receipt
  await assert.rejects(() => guardAwsMutation(gate, aws, { op: 'iam.attach_policy', params }), (e) => e.code === 'EMILIA_RECEIPT_REQUIRED');
  // class_a is insufficient for a quorum action
  await assert.rejects(
    () => guardAwsMutation(gate, aws, { op: 'iam.attach_policy', params, receipt: harness.mint({ outcome: 'allow_with_signoff' }) }),
    (e) => /assurance/.test(e.gate.reason),
  );
  assert.equal(aws.calls.length, 0);
  // quorum executes
  const quorum = harness.mint({ outcome: 'allow_with_signoff', quorum: { signers: ['ep:a', 'ep:b'], threshold: 2 } });
  const { result, reliance } = await guardAwsMutation(gate, aws, { op: 'iam.attach_policy', params, receipt: quorum });
  assert.equal(result.ok, true);
  assert.equal(String(reliance.verdict).toLowerCase(), 'rely');
});

test('create-access-key (Class-A) runs with a valid signoff and refuses a different user (drift)', async () => {
  const action = { action_type: 'aws.iam.create_access_key', user: 'svc-bot' };
  const { gate, harness, aws } = setup(action);
  const ok = await guardAwsMutation(gate, aws, { op: 'iam.create_access_key', params: { user: 'svc-bot' }, receipt: harness.mint({ outcome: 'allow_with_signoff' }) });
  assert.equal(ok.result.AccessKey.AccessKeyId, 'AKIA1');
  // a receipt for svc-bot cannot mint a key for root
  await assert.rejects(
    () => guardAwsMutation(gate, aws, { op: 'iam.create_access_key', params: { user: 'root' }, receipt: harness.mint({ outcome: 'allow_with_signoff' }) }),
    (e) => /binding/.test(e.gate.reason),
  );
});

test('open-ingress requires quorum and binds group/cidr/port', async () => {
  const action = { action_type: 'aws.ec2.authorize_ingress', group_id: 'sg-1', cidr: '0.0.0.0/0', from_port: 22 };
  const { gate, harness, aws } = setup(action);
  const params = { group_id: 'sg-1', cidr: '0.0.0.0/0', from_port: 22 };
  const quorum = harness.mint({ outcome: 'allow_with_signoff', quorum: { signers: ['ep:a', 'ep:b'], threshold: 2 } });
  const { result } = await guardAwsMutation(gate, aws, { op: 'ec2.authorize_ingress', params, receipt: quorum });
  assert.equal(result.Return, true);
  assert.deepEqual(aws.calls[0][1], { GroupId: 'sg-1', CidrIp: '0.0.0.0/0', FromPort: 22, ToPort: 22, IpProtocol: 'tcp' });
});
