// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGate, createEg1Harness } from '../index.js';
import { createGithubManifest, guardGithubMutation, GITHUB_OPS } from './github.js';

function fakeOctokit() {
  const calls = [];
  return {
    calls,
    repos: {
      delete: async (p) => { calls.push(['delete', p]); return { status: 204 }; },
      addCollaborator: async (p) => { calls.push(['addCollaborator', p]); return { status: 201 }; },
      deleteBranchProtection: async (p) => { calls.push(['deleteBranchProtection', p]); return { status: 204 }; },
    },
  };
}

function setup(action) {
  const harness = createEg1Harness({ action });
  const gate = createGate({ manifest: createGithubManifest(), trustedKeys: [harness.publicKey], approverKeys: harness.approverKeys, quorumPolicy: harness.quorumPolicy, rpId: harness.rpId, allowedOrigins: harness.allowedOrigins });
  return { harness, gate, octokit: fakeOctokit() };
}

test('exposes the three destructive GitHub ops', () => {
  assert.deepEqual([...GITHUB_OPS].sort(), ['branch_protection.remove', 'permission.change', 'repo.delete']);
});

test('repo.delete WITHOUT a receipt never reaches GitHub', async () => {
  const { gate, octokit } = setup({ action_type: 'github.repo.delete', owner: 'acme', repo: 'prod' });
  await assert.rejects(
    () => guardGithubMutation(gate, octokit, { op: 'repo.delete', params: { owner: 'acme', repo: 'prod' } }),
    (e) => e.code === 'EMILIA_RECEIPT_REQUIRED' && e.status === 428,
  );
  assert.equal(octokit.calls.length, 0, 'the GitHub API must not be called on refusal');
});

test('repo.delete WITH a valid Class-A receipt executes and returns a reliance packet', async () => {
  const { gate, harness, octokit } = setup({ action_type: 'github.repo.delete', owner: 'acme', repo: 'prod' });
  const receipt = harness.mint({ outcome: 'allow_with_signoff' });
  const { result, reliance, execution } = await guardGithubMutation(gate, octokit, {
    op: 'repo.delete', params: { owner: 'acme', repo: 'prod' }, receipt,
  });
  assert.equal(result.status, 204);
  assert.deepEqual(octokit.calls[0], ['delete', { owner: 'acme', repo: 'prod' }]);
  assert.equal(String(reliance.verdict).toLowerCase(), 'rely');
  assert.ok(execution.authorizes_decision);
});

test('repo.delete refuses when the call targets a DIFFERENT repo than was authorized (drift)', async () => {
  const { gate, harness, octokit } = setup({ action_type: 'github.repo.delete', owner: 'acme', repo: 'prod' });
  const receipt = harness.mint({ outcome: 'allow_with_signoff' }); // authorizes acme/prod
  await assert.rejects(
    () => guardGithubMutation(gate, octokit, { op: 'repo.delete', params: { owner: 'acme', repo: 'staging' }, receipt }),
    (e) => e.code === 'EMILIA_RECEIPT_REQUIRED' && /binding/.test(e.gate.reason),
  );
  assert.equal(octokit.calls.length, 0);
});

test('repo.delete refuses a replayed receipt', async () => {
  const { gate, harness, octokit } = setup({ action_type: 'github.repo.delete', owner: 'acme', repo: 'prod' });
  const receipt = harness.mint({ outcome: 'allow_with_signoff' });
  await guardGithubMutation(gate, octokit, { op: 'repo.delete', params: { owner: 'acme', repo: 'prod' }, receipt });
  await assert.rejects(
    () => guardGithubMutation(gate, octokit, { op: 'repo.delete', params: { owner: 'acme', repo: 'prod' }, receipt }),
    (e) => /replay/.test(e.gate.reason),
  );
  assert.equal(octokit.calls.length, 1, 'the replay must not reach GitHub a second time');
});

test('permission.change requires quorum: a Class-A receipt is refused', async () => {
  const action = { action_type: 'github.permission.change', owner: 'acme', repo: 'prod', username: 'mallory', permission: 'admin' };
  const { gate, harness, octokit } = setup(action);
  const classA = harness.mint({ outcome: 'allow_with_signoff' });
  await assert.rejects(
    () => guardGithubMutation(gate, octokit, { op: 'permission.change', params: { owner: 'acme', repo: 'prod', username: 'mallory', permission: 'admin' }, receipt: classA }),
    (e) => /assurance/.test(e.gate.reason),
  );
  // With a quorum receipt it executes.
  const quorum = harness.mint({ outcome: 'allow_with_signoff', quorum: { signers: ['ep:a', 'ep:b'], threshold: 2 } });
  const { result } = await guardGithubMutation(gate, octokit, {
    op: 'permission.change', params: { owner: 'acme', repo: 'prod', username: 'mallory', permission: 'admin' }, receipt: quorum,
  });
  assert.equal(result.status, 201);
});
