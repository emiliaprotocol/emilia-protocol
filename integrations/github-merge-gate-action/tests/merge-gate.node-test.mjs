// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { canonicalize } from '../../../packages/verify/index.js';
import { evaluateMergeGate } from '../verify.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const actionRoot = path.resolve(here, '..');
const NOW = '2026-08-11T20:00:00.000Z';

function git(workspace, ...arguments_) {
  return execFileSync('git', arguments_, { cwd: workspace, encoding: 'utf8' }).trim();
}

function signReceipt(payload, privateKey) {
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: {
      algorithm: 'Ed25519',
      value: crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey).toString('base64url'),
    },
  };
}

async function fixture() {
  const workspace = await mkdtemp(path.join(tmpdir(), 'emilia-merge-gate-'));
  git(workspace, 'init', '-b', 'main');
  git(workspace, 'config', 'user.name', 'Merge Gate Test');
  git(workspace, 'config', 'user.email', 'merge-gate@example.test');
  await mkdir(path.join(workspace, '.emilia'), { recursive: true });
  await mkdir(path.join(workspace, 'src'), { recursive: true });
  const mandate = {
    '@version': 'EP-GITHUB-MERGE-MANDATE-v1',
    repository: 'acme/payments',
    allowed_base_refs: ['refs/heads/main'],
    allowed_path_prefixes: ['src/', 'docs/'],
    denied_path_prefixes: ['.github/', '.emilia/'],
    max_changed_files: 8,
    max_additions: 100,
    max_deletions: 100,
    max_changed_bytes: 1024,
    max_receipt_age_seconds: 900,
    issuer_id: 'customer:acme:security',
    issuer_key_id: 'key:merge-authority:1',
  };
  await writeFile(path.join(workspace, '.emilia', 'merge-mandate.json'), `${JSON.stringify(mandate, null, 2)}\n`);
  await writeFile(path.join(workspace, 'src', 'app.js'), 'export const value = 1;\n');
  git(workspace, 'add', '.');
  git(workspace, 'commit', '-m', 'base');
  const baseSha = git(workspace, 'rev-parse', 'HEAD');
  await writeFile(path.join(workspace, 'src', 'app.js'), 'export const value = 2;\n');
  git(workspace, 'add', '.');
  git(workspace, 'commit', '-m', 'candidate');
  const headSha = git(workspace, 'rev-parse', 'HEAD');
  const keys = crypto.generateKeyPairSync('ed25519');
  const issuerPublicKey = keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const mandateDigest = `sha256:${crypto.createHash('sha256').update(canonicalize(mandate)).digest('hex')}`;
  const action = {
    action_type: 'github.pull-request.merge.1',
    repository: 'acme/payments',
    base_ref: 'refs/heads/main',
    base_sha: baseSha,
    head_sha: headSha,
    mandate_digest: mandateDigest,
  };
  const caid = `caid:1:${action.action_type}:jcs-sha256:${crypto.createHash('sha256').update(canonicalize(action)).digest('base64url')}`;
  const payload = {
    receipt_id: 'receipt:merge:acme-payments:1',
    issuer: 'customer:acme:security',
    issuer_key_id: 'key:merge-authority:1',
    issued_at: '2026-08-11T19:55:00.000Z',
    expires_at: '2026-08-11T20:10:00.000Z',
    claim: {
      action_type: 'github.pull-request.merge.1',
      repository: 'acme/payments',
      base_ref: 'refs/heads/main',
      base_sha: baseSha,
      head_sha: headSha,
      mandate_digest: mandateDigest,
      caid,
      decision: 'AUTHORIZED',
    },
  };
  const receiptPath = path.join(await mkdtemp(path.join(tmpdir(), 'emilia-merge-receipt-')), 'receipt.json');
  await writeFile(receiptPath, `${JSON.stringify(signReceipt(payload, keys.privateKey), null, 2)}\n`);
  return { workspace, baseSha, headSha, mandate, mandateDigest, caid, keys, issuerPublicKey, payload, receiptPath };
}

async function rewriteReceipt(item, mutate) {
  const payload = structuredClone(item.payload);
  mutate(payload);
  await writeFile(item.receiptPath, `${JSON.stringify(signReceipt(payload, item.keys.privateKey), null, 2)}\n`);
}

async function evaluate(item, overrides = {}) {
  return evaluateMergeGate({
    workspace: item.workspace,
    baseSha: item.baseSha,
    headSha: item.headSha,
    repository: 'acme/payments',
    baseRef: 'refs/heads/main',
    mandatePath: '.emilia/merge-mandate.json',
    receiptPath: item.receiptPath,
    issuerPublicKey: item.issuerPublicKey,
    now: NOW,
    ...overrides,
  });
}

test('admits a signed exact-head merge inside the base-pinned mandate', async () => {
  const item = await fixture();
  const result = await evaluate(item);
  assert.equal(result.admitted, true, JSON.stringify(result));
  assert.equal(result.mandate_digest, item.mandateDigest);
  assert.equal(result.caid, item.caid);
  assert.equal(result.diff.changed_files, 1);
  assert.deepEqual(result.diff.paths, ['src/app.js']);
});

test('refuses head substitution and receipt tampering', async () => {
  const item = await fixture();
  await writeFile(path.join(item.workspace, 'src', 'app.js'), 'export const value = 3;\n');
  git(item.workspace, 'add', '.');
  git(item.workspace, 'commit', '-m', 'post-approval mutation');
  const newHead = git(item.workspace, 'rev-parse', 'HEAD');
  const substituted = await evaluate(item, { headSha: newHead });
  assert.equal(substituted.admitted, false);
  assert.equal(substituted.reason, 'receipt_head_sha_mismatch');

  const receipt = JSON.parse(await readFile(item.receiptPath, 'utf8'));
  receipt.payload.claim.repository = 'acme/other';
  await writeFile(item.receiptPath, JSON.stringify(receipt));
  const tampered = await evaluate(item);
  assert.equal(tampered.admitted, false);
  assert.equal(tampered.reason, 'receipt_signature_invalid');
});

test('candidate changes cannot widen the base-pinned mandate', async () => {
  const item = await fixture();
  const widened = { ...item.mandate, allowed_path_prefixes: [''] };
  await writeFile(path.join(item.workspace, '.emilia', 'merge-mandate.json'), JSON.stringify(widened));
  await mkdir(path.join(item.workspace, '.github', 'workflows'), { recursive: true });
  await writeFile(path.join(item.workspace, '.github', 'workflows', 'pwn.yml'), 'name: pwn\n');
  git(item.workspace, 'add', '.');
  git(item.workspace, 'commit', '-m', 'try to widen mandate');
  const result = await evaluate(item, { headSha: git(item.workspace, 'rev-parse', 'HEAD') });
  assert.equal(result.admitted, false);
  assert.equal(result.reason, 'path_denied');
  assert.equal(result.path, '.emilia/merge-mandate.json');
});

test('refuses expired receipts, non-ancestor bases, and unknown mandate fields', async () => {
  const expired = await fixture();
  const expiredResult = await evaluate(expired, { now: '2026-08-11T20:20:00.000Z' });
  assert.equal(expiredResult.admitted, false);
  assert.equal(expiredResult.reason, 'receipt_expired');

  const unrelated = await fixture();
  git(unrelated.workspace, 'checkout', '--orphan', 'unrelated');
  git(unrelated.workspace, 'rm', '-rf', '.');
  await mkdir(path.join(unrelated.workspace, 'src'), { recursive: true });
  await writeFile(path.join(unrelated.workspace, 'src', 'other.js'), 'export {};\n');
  git(unrelated.workspace, 'add', '.');
  git(unrelated.workspace, 'commit', '-m', 'unrelated');
  const unrelatedResult = await evaluate(unrelated, { headSha: git(unrelated.workspace, 'rev-parse', 'HEAD') });
  assert.equal(unrelatedResult.admitted, false);
  assert.equal(unrelatedResult.reason, 'base_not_ancestor_of_head');

  const unknown = await fixture();
  const badMandate = { ...unknown.mandate, magic_override: true };
  git(unknown.workspace, 'checkout', unknown.baseSha);
  await writeFile(path.join(unknown.workspace, '.emilia', 'merge-mandate.json'), JSON.stringify(badMandate));
  git(unknown.workspace, 'add', '.');
  git(unknown.workspace, 'commit', '-m', 'bad base mandate');
  const badBase = git(unknown.workspace, 'rev-parse', 'HEAD');
  await writeFile(path.join(unknown.workspace, 'src', 'app.js'), 'export const value = 4;\n');
  git(unknown.workspace, 'add', '.');
  git(unknown.workspace, 'commit', '-m', 'candidate');
  const bad = await evaluate(unknown, { baseSha: badBase, headSha: git(unknown.workspace, 'rev-parse', 'HEAD') });
  assert.equal(bad.admitted, false);
  assert.equal(bad.reason, 'mandate_unknown_field');
});

test('pins issuer identity, receipt lifetime, and a closed claim shape', async () => {
  const wrongIssuer = await fixture();
  await rewriteReceipt(wrongIssuer, (payload) => { payload.issuer = 'customer:mallory'; });
  assert.equal((await evaluate(wrongIssuer)).reason, 'receipt_issuer_mismatch');

  const wrongKey = await fixture();
  await rewriteReceipt(wrongKey, (payload) => { payload.issuer_key_id = 'key:other'; });
  assert.equal((await evaluate(wrongKey)).reason, 'receipt_issuer_key_id_mismatch');

  const longLived = await fixture();
  await rewriteReceipt(longLived, (payload) => { payload.expires_at = '2026-08-11T21:00:00.000Z'; });
  assert.equal((await evaluate(longLived)).reason, 'receipt_validity_window_too_long');

  const smuggled = await fixture();
  await rewriteReceipt(smuggled, (payload) => { payload.claim.override = true; });
  assert.equal((await evaluate(smuggled)).reason, 'receipt_claim_unknown_field');

  const wrongAlgorithm = await fixture();
  const wrongAlgorithmReceipt = JSON.parse(await readFile(wrongAlgorithm.receiptPath, 'utf8'));
  wrongAlgorithmReceipt.signature.algorithm = 'RSA';
  await writeFile(wrongAlgorithm.receiptPath, JSON.stringify(wrongAlgorithmReceipt));
  assert.equal((await evaluate(wrongAlgorithm)).reason, 'receipt_algorithm_unsupported');
});

test('refuses duplicate receipt members, binary changes, symlinks, and empty diffs', async () => {
  const duplicate = await fixture();
  const original = await readFile(duplicate.receiptPath, 'utf8');
  await writeFile(duplicate.receiptPath, original.replace('"issuer":', '"issuer":"customer:mallory","issuer":'));
  assert.equal((await evaluate(duplicate)).reason, 'receipt_invalid_json');

  const binary = await fixture();
  await writeFile(path.join(binary.workspace, 'src', 'image.bin'), Buffer.from([0, 1, 2, 3]));
  git(binary.workspace, 'add', '.');
  git(binary.workspace, 'commit', '-m', 'binary');
  assert.equal((await evaluate(binary, { headSha: git(binary.workspace, 'rev-parse', 'HEAD') })).reason, 'binary_diff_indeterminate');

  const symlink = await fixture();
  await writeFile(path.join(symlink.workspace, 'src', 'target.js'), 'export {};\n');
  execFileSync('ln', ['-s', 'target.js', path.join(symlink.workspace, 'src', 'alias.js')]);
  git(symlink.workspace, 'add', '.');
  git(symlink.workspace, 'commit', '-m', 'symlink');
  assert.equal((await evaluate(symlink, { headSha: git(symlink.workspace, 'rev-parse', 'HEAD') })).reason, 'git_object_mode_unsupported');

  const empty = await fixture();
  assert.equal((await evaluate(empty, { baseSha: empty.headSha })).reason, 'empty_diff');
});

test('refuses oversized one-line blobs that evade line-count limits', async () => {
  const item = await fixture();
  await writeFile(path.join(item.workspace, 'src', 'large.js'), `export const payload = '${'x'.repeat(2048)}';\n`);
  git(item.workspace, 'add', '.');
  git(item.workspace, 'commit', '-m', 'oversized one-line blob');
  const result = await evaluate(item, { headSha: git(item.workspace, 'rev-parse', 'HEAD') });
  assert.equal(result.admitted, false);
  assert.equal(result.reason, 'changed_bytes_limit_exceeded');
});

test('refuses control characters in changed paths before reporting them', async () => {
  const item = await fixture();
  await writeFile(path.join(item.workspace, 'src', 'hostile\nname.js'), 'export {};\n');
  git(item.workspace, 'add', '.');
  git(item.workspace, 'commit', '-m', 'hostile path');
  const result = await evaluate(item, { headSha: git(item.workspace, 'rev-parse', 'HEAD') });
  assert.equal(result.admitted, false);
  assert.equal(result.reason, 'git_diff_path_invalid');
});

test('action metadata makes branch protection and detached evidence boundaries explicit', async () => {
  const action = await readFile(path.join(actionRoot, 'action.yml'), 'utf8');
  const readme = await readFile(path.join(actionRoot, 'README.md'), 'utf8');
  assert.match(action, /^name: EMILIA Merge Gate$/m);
  assert.match(action, /^  using: node24$/m);
  assert.match(readme, /required status check/i);
  assert.match(readme, /does not merge/i);
  assert.match(readme, /detached/i);
  assert.match(readme, /full commit SHA/i);
  assert.doesNotMatch(readme, /exactly-once execution/i);
});
