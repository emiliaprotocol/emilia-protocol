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
const REGISTRY_CUTOFF = '2026-08-16T23:59:59.000Z';

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    ...options,
  });
  assert.equal(result.status, 0, `${command} ${args.join(' ')}\n${result.stdout}\n${result.stderr}`);
  return result.stdout;
}

test('packed scan installs the audited guard and refuses hostile generated actions in a blank consumer', () => {
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

  writeFileSync(join(consumer, 'package.json'), JSON.stringify({ private: true, type: 'module' }));
  run('npm', [
    'install',
    '--ignore-scripts',
    '--no-audit',
    '--no-fund',
    scanTarball,
    guardTarball,
    requireReceiptTarball,
  ], {
    cwd: consumer,
    env: { ...process.env, npm_config_before: REGISTRY_CUTOFF },
  });

  const installedRoot = realpathSync(join(consumer, 'node_modules'));
  const installedScan = realpathSync(join(installedRoot, '@emilia-protocol', 'scan'));
  assert.ok(installedScan.startsWith(`${installedRoot}${sep}`), installedScan);
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
  run(scanBin, [
    'protect',
    input,
    '--apply',
    '--out',
    'emilia',
  ], { cwd: consumer });

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
  const verifyOutput = run(process.execPath, [
    join(consumer, 'emilia', 'verify-setup.mjs'),
    '--emit-handoff',
    '--reviewed-manifest-digest',
    manifestDigest,
    '--action',
    'rotateApiKey',
    '--action',
    'archiveCustomer',
  ], { cwd: consumer });
  assert.match(verifyOutput, /EMILIA RR-1 CHECK: PASS — 8\/8 cases matched the protected-action contract/);

  const handoff = JSON.parse(readFileSync(join(consumer, 'emilia', 'scan-adoption-handoff.json'), 'utf8'));
  assert.deepEqual(
    handoff.selected_actions.map((action) => action.selector.tool),
    ['rotateApiKey', 'archiveCustomer'],
  );
  assert.equal(handoff.local_refusal.handler_called, false);
  assert.equal(handoff.local_rr1.status, 'passed');
  assert.equal(handoff.local_rr1.profile, 'EP-RR-1-LOCAL-v1');
  assert.equal(handoff.local_rr1.manifest_sha256, manifestDigest);
  assert.deepEqual(
    handoff.local_rr1.tested_actions.map((action) => action.selector.tool),
    ['rotateApiKey', 'archiveCustomer'],
  );
  assert.deepEqual(
    handoff.local_rr1.cases.map(({ case_id, observed }) => ({ case_id, observed })),
    [
      { case_id: 'RR1-01-missing-receipt:rotateApiKey', observed: 'emilia_receipt_required' },
      { case_id: 'RR1-02-valid-receipt:rotateApiKey', observed: 'admitted' },
      { case_id: 'RR1-03-action-substitution:rotateApiKey', observed: 'action_mismatch' },
      { case_id: 'RR1-04-replay:rotateApiKey', observed: 'replay_refused' },
      { case_id: 'RR1-01-missing-receipt:archiveCustomer', observed: 'emilia_receipt_required' },
      { case_id: 'RR1-02-valid-receipt:archiveCustomer', observed: 'admitted' },
      { case_id: 'RR1-03-action-substitution:archiveCustomer', observed: 'action_mismatch' },
      { case_id: 'RR1-04-replay:archiveCustomer', observed: 'replay_refused' },
    ],
  );
  assert.match(handoff.local_rr1.results_digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(handoff.local_rr1.synthetic_handler_calls, 2);
});
