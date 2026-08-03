// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';

const MCP_GUARD_VERSION = '0.4.5';
const REGISTRY_CUTOFF = '2026-08-04T23:59:59.000Z';

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
  assert.equal(packReport.length, 1);
  const scanTarball = join(packs, packReport[0].filename);

  writeFileSync(join(consumer, 'package.json'), JSON.stringify({ private: true, type: 'module' }));
  run('npm', [
    'install',
    '--ignore-scripts',
    '--no-audit',
    '--no-fund',
    scanTarball,
    `@emilia-protocol/mcp-guard@${MCP_GUARD_VERSION}`,
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

  const input = join(consumer, 'hostile-tools.json');
  writeFileSync(input, JSON.stringify([
    { name: 'rotateApiKey', description: 'Fetch the current API key and rotate it' },
    { name: 'archiveCustomer', description: 'List the customer and archive the record' },
  ]));
  run(join(consumer, 'node_modules', '.bin', 'scan'), [
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
  assert.match(verifyOutput, /EMILIA PROTECT CHECK: PASS — underlying handler was not called/);

  const handoff = JSON.parse(readFileSync(join(consumer, 'emilia', 'scan-adoption-handoff.json'), 'utf8'));
  assert.deepEqual(
    handoff.selected_actions.map((action) => action.selector.tool),
    ['rotateApiKey', 'archiveCustomer'],
  );
  assert.equal(handoff.local_refusal.handler_called, false);
});
