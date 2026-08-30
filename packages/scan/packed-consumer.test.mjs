// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';

const MCP_GUARD_VERSION = '0.6.0';
const REQUIRE_RECEIPT_VERSION = '0.8.1';
const VERIFY_VERSION = '3.21.0';
const REGISTRY_CUTOFF = '2026-08-16T23:59:59.000Z';

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    ...options,
  });
  assert.equal(result.status, 0, `${command} ${args.join(' ')}\n${result.stdout}\n${result.stderr}`);
  return result.stdout;
}

test('packed scan refuses missing runtime, then uses the exact audited guard in a blank consumer', () => {
  const root = mkdtempSync(join(tmpdir(), 'emilia-scan-packed-'));
  const packs = join(root, 'packs');
  const consumer = join(root, 'consumer');
  mkdirSync(packs);
  mkdirSync(consumer);

  const packReport = JSON.parse(run('npm', [
    'pack',
    import.meta.dirname,
    '--json',
    '--pack-destination',
    packs,
  ]));
  const packEntries = Array.isArray(packReport) ? packReport : Object.values(packReport ?? {});
  assert.equal(packEntries.length, 1);
  assert.equal(typeof packEntries[0]?.filename, 'string');
  const scanTarball = join(packs, packEntries[0].filename);
  const guardPack = JSON.parse(run('npm', [
    'pack',
    join(import.meta.dirname, '..', 'mcp-guard'),
    '--json',
    '--pack-destination',
    packs,
  ]));
  const guardTarball = join(packs, guardPack[0].filename);
  const requireReceiptPack = JSON.parse(run('npm', [
    'pack',
    join(import.meta.dirname, '..', 'require-receipt'),
    '--json',
    '--pack-destination',
    packs,
  ]));
  const requireReceiptTarball = join(packs, requireReceiptPack[0].filename);
  const verifyPack = JSON.parse(run('npm', [
    'pack',
    join(import.meta.dirname, '..', 'verify'),
    '--json',
    '--pack-destination',
    packs,
  ]));
  const verifyTarball = join(packs, verifyPack[0].filename);

  writeFileSync(join(consumer, 'package.json'), JSON.stringify({ private: true, type: 'module' }));
  run('npm', [
    'install',
    '--ignore-scripts',
    '--no-audit',
    '--no-fund',
    scanTarball,
    verifyTarball,
  ], {
    cwd: consumer,
    env: { ...process.env, npm_config_before: REGISTRY_CUTOFF },
  });

  const installedRoot = realpathSync(join(consumer, 'node_modules'));
  const installedScan = realpathSync(join(installedRoot, '@emilia-protocol', 'scan'));
  assert.ok(installedScan.startsWith(`${installedRoot}${sep}`), installedScan);
  const scanBin = join(consumer, 'node_modules', '.bin', 'scan');
  const consumerEntries = readdirSync(consumer).sort();
  const missingEmit = spawnSync(scanBin, ['--sample', '--emit'], {
    cwd: consumer,
    encoding: 'utf8',
  });
  assert.equal(missingEmit.status, 2, `${missingEmit.stdout}\n${missingEmit.stderr}`);
  assert.equal(missingEmit.stdout, '');
  assert.match(missingEmit.stderr, /--emit requires a value/);
  assert.deepEqual(readdirSync(consumer).sort(), consumerEntries);

  const authorityHelp = run(scanBin, ['authority', '--help'], { cwd: consumer });
  assert.match(authorityHelp, /\n\s+64\s+usage, argument, or filesystem error/);

  const input = join(consumer, 'hostile-tools.json');
  writeFileSync(input, JSON.stringify([
    { name: 'rotateApiKey', description: 'Fetch the current API key and rotate it' },
    { name: 'archiveCustomer', description: 'List the customer and archive the record' },
  ]));
  const blankVerify = spawnSync(scanBin, [
    'protect',
    input,
    '--action',
    'rotateApiKey',
    '--apply',
    '--verify',
    '--out',
    'emilia',
  ], { cwd: consumer, encoding: 'utf8' });
  assert.equal(blankVerify.status, 1, `${blankVerify.stdout}\n${blankVerify.stderr}`);
  assert.match(
    `${blankVerify.stdout}${blankVerify.stderr}`,
    /npm install --save-exact @emilia-protocol\/mcp-guard@0\.6\.0/,
  );
  assert.equal(readdirSync(consumer).includes('emilia'), false,
    'missing runtime preflight must refuse before writing a starter');

  run('npm', [
    'install',
    '--ignore-scripts',
    '--no-audit',
    '--no-fund',
    guardTarball,
    requireReceiptTarball,
  ], {
    cwd: consumer,
    env: { ...process.env, npm_config_before: REGISTRY_CUTOFF },
  });
  const installedGuardPackage = JSON.parse(readFileSync(
    join(installedRoot, '@emilia-protocol', 'mcp-guard', 'package.json'),
    'utf8',
  ));
  assert.equal(installedGuardPackage.version, MCP_GUARD_VERSION);
  const installedRequireReceiptPackage = JSON.parse(readFileSync(
    join(installedRoot, '@emilia-protocol', 'require-receipt', 'package.json'),
    'utf8',
  ));
  assert.equal(installedRequireReceiptPackage.version, REQUIRE_RECEIPT_VERSION);
  const installedVerifyPackage = JSON.parse(readFileSync(
    join(installedRoot, '@emilia-protocol', 'verify', 'package.json'),
    'utf8',
  ));
  assert.equal(installedVerifyPackage.version, VERIFY_VERSION);

  const verifyOutput = run(scanBin, [
    'protect',
    input,
    '--action',
    'rotateApiKey',
    '--apply',
    '--verify',
    '--out',
    'emilia',
  ], { cwd: consumer });
  assert.match(verifyOutput, /EMILIA RR-1 CHECK: PASS — 4\/4 cases matched the protected-action contract/);
  assert.match(verifyOutput, /refused an exact synthetic receipt for an unscanned runtime tool/i);
  assert.equal(readdirSync(join(consumer, 'emilia')).includes('scan-adoption-handoff.json'), false,
    'first-stage verification must not emit a reviewed handoff');

  const integration = readFileSync(join(consumer, 'emilia', 'INTEGRATION.md'), 'utf8');
  assert.ok(
    integration.includes(`npm install --save-exact @emilia-protocol/mcp-guard@${MCP_GUARD_VERSION}`),
    'generated integration must pin the audited guard release exactly',
  );

  const manifestFile = join(consumer, 'emilia', 'action-control.manifest.json');
  const manifestBytes = readFileSync(manifestFile);
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const hostileManifestActions = manifest.actions.filter((action) => (
    action?.match?.protocol === 'mcp'
    && ['rotateApiKey', 'archiveCustomer'].includes(action.match.tool)
  ));
  assert.equal(hostileManifestActions.length, 2);
  assert.ok(hostileManifestActions.every((action) => action.receipt_required === true));

  const manifestDigest = `sha256:${createHash('sha256').update(manifestBytes).digest('hex')}`;
  const reviewedOutput = run(scanBin, [
    'protect',
    input,
    '--action',
    'rotateApiKey',
    '--reviewed',
    '--crossing-profile',
    'ccs-wang-draft08-v13',
    '--out',
    'emilia',
  ], { cwd: consumer });
  assert.match(reviewedOutput, /Reviewed handoff created without changing the Gate Starter/);

  const handoff = JSON.parse(readFileSync(join(consumer, 'emilia', 'scan-adoption-handoff.json'), 'utf8'));
  assert.equal(handoff['@version'], 'EP-SCAN-ADOPTION-HANDOFF-v3');
  assert.deepEqual(
    handoff.selected_actions.map((action) => action.selector.tool),
    ['rotateApiKey'],
  );
  assert.equal(handoff.local_refusal.handler_called, false);
  assert.equal(handoff.local_rr1.status, 'passed');
  assert.equal(handoff.local_rr1.profile, 'EP-RR-1-LOCAL-v1');
  assert.equal(handoff.local_rr1.manifest_sha256, manifestDigest);
  assert.deepEqual(
    handoff.local_rr1.tested_actions.map((action) => action.selector.tool),
    ['rotateApiKey'],
  );
  assert.deepEqual(
    handoff.local_rr1.cases.map(({ case_id, observed }) => ({ case_id, observed })),
    [
      { case_id: 'RR1-01-missing-receipt:rotateApiKey', observed: 'emilia_receipt_required' },
      { case_id: 'RR1-02-valid-receipt:rotateApiKey', observed: 'admitted' },
      { case_id: 'RR1-03-action-substitution:rotateApiKey', observed: 'action_mismatch' },
      { case_id: 'RR1-04-replay:rotateApiKey', observed: 'replay_refused' },
    ],
  );
  assert.match(handoff.local_rr1.results_digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(handoff.local_rr1.synthetic_handler_calls, 1);
});
