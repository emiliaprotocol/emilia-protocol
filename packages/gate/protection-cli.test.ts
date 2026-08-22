// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { activateProtectionPlan } from './bin/ep-protect.mjs';
import { createProtectionPlan } from './protection-plan.js';
import { verifyProtectionActivation } from './protection-activation.js';

test('customer plan is signed locally and verifies under the pinned owner key', () => {
  const directory = mkdtempSync(join(tmpdir(), 'emilia-protect-'));
  const planPath = join(directory, 'plan.json');
  const keyPath = join(directory, 'owner.pem');
  const outPath = join(directory, 'activation.json');
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const plan = createProtectionPlan({
    planId: 'personal-finance',
    ownerLabel: 'Owner',
    now: '2026-08-21T15:00:00.000Z',
    selections: [{ presetId: 'spend-money' }],
  });
  writeFileSync(planPath, `${JSON.stringify(plan, null, 2)}\n`);
  writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }));

  const result = activateProtectionPlan([
    'activate', planPath,
    '--private-key', keyPath,
    '--tenant', 'tenant-personal',
    '--gateway', 'gateway-mcp',
    '--authorizer', 'owner-local',
    '--key-id', 'owner-key-1',
    '--out', outPath,
  ], new Date('2026-08-21T15:05:00.000Z'));
  const activation = JSON.parse(readFileSync(outPath, 'utf8'));
  assert.equal(result.output, outPath);
  const verified = verifyProtectionActivation(activation, {
    trusted_keys: {
      'owner-key-1': {
        issuer_id: 'owner-local',
        public_key: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      },
    },
    expected: {
      activation_id: activation.activation_id,
      tenant_id: 'tenant-personal',
      gateway_id: 'gateway-mcp',
      authorizer_id: 'owner-local',
    },
    now: activation.valid_from,
  });
  assert.equal(verified.accepted, true, verified.reason);
});

test('activation refuses incomplete context, duplicate JSON members, and overwriting output', () => {
  assert.throws(() => activateProtectionPlan(['activate']), /Usage: ep-protect activate/);
  const directory = mkdtempSync(join(tmpdir(), 'emilia-protect-'));
  const planPath = join(directory, 'plan.json');
  const keyPath = join(directory, 'owner.pem');
  const outPath = join(directory, 'activation.json');
  const { privateKey } = generateKeyPairSync('ed25519');
  writeFileSync(planPath, '{"plan_id":"one","plan_id":"two"}\n');
  writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }));
  const args = ['activate', planPath, '--private-key', keyPath, '--tenant', 'tenant', '--gateway', 'gateway', '--authorizer', 'owner', '--key-id', 'key', '--out', outPath];
  assert.throws(() => activateProtectionPlan(args), /duplicate object member/);
  const validPlan = createProtectionPlan({
    planId: 'protected-delete',
    ownerLabel: 'Owner',
    now: '2026-08-21T15:00:00.000Z',
    selections: [{ presetId: 'delete-files' }],
  });
  writeFileSync(planPath, `${JSON.stringify(validPlan)}\n`);
  writeFileSync(outPath, 'existing');
  assert.throws(
    () => activateProtectionPlan(args, new Date('2026-08-21T15:05:00.000Z')),
    /EEXIST/,
  );
  assert.equal(readFileSync(outPath, 'utf8'), 'existing');
});

test('installed ep-protect bin executes through the npm-style symlink', () => {
  const directory = mkdtempSync(join(tmpdir(), 'emilia-protect-bin-'));
  const planPath = join(directory, 'plan.json');
  const keyPath = join(directory, 'owner.pem');
  const outPath = join(directory, 'activation.json');
  const binPath = join(directory, 'ep-protect');
  const { privateKey } = generateKeyPairSync('ed25519');
  const plan = createProtectionPlan({
    planId: 'installed-bin',
    ownerLabel: 'Owner',
    now: '2026-08-21T15:00:00.000Z',
    selections: [{ presetId: 'delete-files' }],
  });
  writeFileSync(planPath, `${JSON.stringify(plan)}\n`);
  writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }));
  symlinkSync(new URL('./bin/ep-protect.mjs', import.meta.url), binPath);

  const result = spawnSync(binPath, [
    'activate', planPath,
    '--private-key', keyPath,
    '--tenant', 'tenant-installed',
    '--gateway', 'gateway-installed',
    '--authorizer', 'owner-installed',
    '--key-id', 'owner-key-1',
    '--out', outPath,
  ], { encoding: 'utf8' });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /"status":"ACTIVATED"/);
  assert.equal(existsSync(outPath), true);
});
