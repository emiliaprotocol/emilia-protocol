// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const script = resolve(import.meta.dirname, 'crash-test.mjs');
let cwd;
let receiptPath;
let trustPath;

function run(args) {
  return spawnSync(process.execPath, [script, ...args], {
    cwd,
    encoding: 'utf8',
    timeout: 15_000,
  });
}

describe('crash-test relying-party trust boundary', () => {
  before(() => {
    cwd = mkdtempSync(resolve(tmpdir(), 'emilia-crash-test-'));
    const generated = run([]);
    assert.equal(generated.status, 0, generated.stderr || generated.stdout);
    receiptPath = resolve(cwd, 'emilia-workpaper/authorization-receipt.json');
    trustPath = resolve(cwd, 'emilia-workpaper/relying-party-trust-profile.json');
  });

  after(() => rmSync(cwd, { recursive: true, force: true }));

  it('accepts only when the relying party supplies the matching pinned profile', () => {
    assert.equal(run(['verify', receiptPath, '--trust', trustPath]).status, 0);
    assert.equal(run(['verify', receiptPath]).status, 2);
  });

  it('refuses a weaker presenter-selected quorum policy', () => {
    const profile = JSON.parse(readFileSync(trustPath, 'utf8'));
    profile.quorum_policy.required = 1;
    const path = resolve(cwd, 'weak-policy.json');
    writeFileSync(path, JSON.stringify(profile));
    assert.equal(run(['verify', receiptPath, '--trust', path]).status, 1);
  });

  it('refuses an unpinned approver key', () => {
    const profile = JSON.parse(readFileSync(trustPath, 'utf8'));
    const attacker = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    profile.approvers[0].public_key = attacker.publicKey
      .export({ type: 'spki', format: 'der' }).toString('base64url');
    const path = resolve(cwd, 'attacker-approver.json');
    writeFileSync(path, JSON.stringify(profile));
    assert.equal(run(['verify', receiptPath, '--trust', path]).status, 1);
  });

  it('refuses an operator key supplied by an attacker', () => {
    const profile = JSON.parse(readFileSync(trustPath, 'utf8'));
    const attacker = crypto.generateKeyPairSync('ed25519');
    profile.operator_public_key = attacker.publicKey
      .export({ type: 'spki', format: 'der' }).toString('base64url');
    const path = resolve(cwd, 'attacker-operator.json');
    writeFileSync(path, JSON.stringify(profile));
    assert.equal(run(['verify', receiptPath, '--trust', path]).status, 1);
  });

  it('refuses duplicate JSON member names before parsing', () => {
    const raw = readFileSync(trustPath, 'utf8').replace('{', '{"profile_id":"shadow",');
    const path = resolve(cwd, 'duplicate-profile.json');
    writeFileSync(path, raw);
    assert.equal(run(['verify', receiptPath, '--trust', path]).status, 2);
  });
});
