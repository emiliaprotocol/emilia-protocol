// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  CROSSING_LAB_VERIFY_VERSION,
  crossingLabScanProfileContract,
  digestCrossingLab,
  initCrossingLab,
  sealCrossingLab,
} from './src/crossing-lab.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = resolve(HERE, 'cli.js');
const CROSSING_LAB_RUNTIME_SUPPORTED = process.allowedNodeEnvironmentFlags.has('--allow-net')
  && (process.allowedNodeEnvironmentFlags.has('--permission')
    || process.allowedNodeEnvironmentFlags.has('--experimental-permission'));
const runtimeTest = CROSSING_LAB_RUNTIME_SUPPORTED ? test : test.skip;

function freshWorkspace(): string {
  const parent = mkdtempSync(join(tmpdir(), 'emilia-crossing-lab-cli-'));
  const target = join(parent, 'workspace');
  initCrossingLab(target);
  return target;
}

function runCli(args: readonly string[]) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    maxBuffer: 4 * 1024 * 1024,
  });
}

function scanSeedFixture(): { seed: string; target: string } {
  const parent = mkdtempSync(join(tmpdir(), 'emilia-crossing-lab-cli-scan-'));
  const manifest = {
    actions: [{
      id: 'discovered.sendwire',
      action_type: 'payment.release.1',
      assurance_class: 'class_a',
      receipt_required: true,
      match: { protocol: 'mcp', tool: 'sendWire' },
      execution_binding: { required_fields: ['action_type', 'amount_usd'] },
    }],
  };
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(join(parent, 'action-control.manifest.json'), manifestBytes);
  const selectedAction = {
    id: 'discovered.sendwire',
    selector: { protocol: 'mcp', tool: 'sendWire' },
    action_type: 'payment.release.1',
    assurance_class: 'class_a',
    receipt_required: true,
    material_fields: ['action_type', 'amount_usd'],
  };
  const seedValue = {
    '@version': 'EP-SCAN-CROSSING-SEED-v1',
    verify_version: CROSSING_LAB_VERIFY_VERSION,
    profile_id: 'ccs-wang-draft08-v13',
    profile_contract: crossingLabScanProfileContract('ccs-wang-draft08-v13'),
    profile_compatibility: 'UNVERIFIED_OPERATOR_CONFIRMATION_REQUIRED',
    reviewed_manifest: {
      file: 'action-control.manifest.json',
      sha256: `sha256:${createHash('sha256').update(manifestBytes).digest('hex')}`,
    },
    generated_scaffold_sha256: `sha256:${'1'.repeat(64)}`,
    local_rr1_results_digest: `sha256:${'2'.repeat(64)}`,
    selected_action: selectedAction,
    selected_action_digest: digestCrossingLab(selectedAction),
    operator_confirmation: {
      status: 'required',
      workspace_state: 'unsealed',
      required_inputs: [
        'native_artifact',
        'adapter_bytes',
        'trust_roots',
        'status_source',
        'relying_party_id',
        'exact_material_fields',
        'profile_compatibility_confirmation',
      ],
    },
  };
  const seed = join(parent, 'scan-crossing-seed.json');
  writeFileSync(seed, `${JSON.stringify(seedValue, null, 2)}\n`);
  return { seed, target: join(parent, 'workspace') };
}

test('crossing-lab init-from-scan creates an unsealed workspace and rejects malformed operands', () => {
  const fixture = scanSeedFixture();
  const result = runCli(['crossing-lab', 'init-from-scan', fixture.seed, fixture.target]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /unsealed Crossing Lab workspace created/i);
  assert.equal(existsSync(join(fixture.target, 'workspace.json')), true);

  for (const args of [
    ['crossing-lab', 'init-from-scan'],
    ['crossing-lab', 'init-from-scan', fixture.seed],
    ['crossing-lab', 'init-from-scan', '--seed', fixture.target],
    ['crossing-lab', 'init-from-scan', fixture.seed, fixture.target, 'extra'],
  ]) {
    const invalid = runCli(args);
    assert.equal(invalid.status, 1);
    assert.match(invalid.stderr, /usage: verify crossing-lab init-from-scan/);
  }
});

function workspaceWithDifferentPinnedCaid(): { root: string; candidateCaid: string; pinnedCaid: string } {
  const root = freshWorkspace();
  const path = join(root, 'workspace.json');
  const workspace = JSON.parse(readFileSync(path, 'utf8'));
  const candidateCaid = workspace.evaluation.caid as string;
  const final = candidateCaid.at(-1);
  const pinnedCaid = `${candidateCaid.slice(0, -1)}${final === 'A' ? 'B' : 'A'}`;
  workspace.evaluation.caid = pinnedCaid;
  writeFileSync(path, `${JSON.stringify(workspace, null, 2)}\n`);
  sealCrossingLab(root);
  return { root, candidateCaid, pinnedCaid };
}

test('crossing-lab run strictly rejects malformed --out and extra operands', () => {
  const root = freshWorkspace();
  const invalidArguments = [
    [root, '--out'],
    [root, '--out', join(dirname(root), 'first.json'), '--out', join(dirname(root), 'second.json')],
    [root, '--out', '--dash-prefixed.json'],
    [root, 'extra-operand'],
  ];

  for (const args of invalidArguments) {
    const result = runCli(['crossing-lab', 'run', ...args]);
    assert.equal(result.status, 1, `args=${JSON.stringify(args)} stderr=${result.stderr}`);
    assert.match(result.stderr, /usage: verify crossing-lab run/);
    assert.equal(result.stdout, '');
  }
});

runtimeTest('failed run with --out preserves the report and prints bounded actionable diagnostics', () => {
  const { root, candidateCaid, pinnedCaid } = workspaceWithDifferentPinnedCaid();
  const reportPath = join(dirname(root), 'failed-report.json');
  const result = runCli(['crossing-lab', 'run', root, '--out', reportPath]);

  assert.equal(result.status, 2, result.stderr);
  assert.equal(existsSync(reportPath), true);
  const report = JSON.parse(readFileSync(reportPath, 'utf8'));
  assert.equal(report.lab_passed, false);
  assert.match(result.stdout, /Crossing Lab FAILED/);
  assert.match(result.stdout, /failed adapter row native-artifact-through:/);
  assert.match(result.stdout, /native=VERIFIED, acceptance=ACCEPTED, mapping=MATCH/);
  assert.match(result.stdout, /freshness=FRESH, satisfaction=UNSATISFIED, evaluation_valid=false/);
  assert.match(result.stdout, new RegExp(`candidate mapped CAID ${candidateCaid.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
  assert.match(result.stdout, new RegExp(`workspace evaluation CAID ${pinnedCaid.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
  assert.match(result.stdout, /Review it against the pinned mapping profile/);
  assert.match(result.stdout, /deliberately update workspace\.evaluation\.caid/);
  assert.match(result.stdout, /crossing-lab seal, then rerun crossing-lab run/);

  const rowLine = result.stdout.split('\n').find((line) => line.startsWith('failed adapter row native-artifact-through:'));
  assert.ok(rowLine);
  const reasons = rowLine.split('reasons=')[1]?.replace(/ \(\+\d+ more\)$/, '').split(', ') ?? [];
  assert.ok(reasons.length <= 3, rowLine);
});

runtimeTest('failed run without --out keeps stdout as parseable report JSON and diagnostics on stderr', () => {
  const { root, candidateCaid } = workspaceWithDifferentPinnedCaid();
  const result = runCli(['crossing-lab', 'run', root]);

  assert.equal(result.status, 2, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.lab_passed, false);
  assert.doesNotMatch(result.stdout, /failed adapter row/);
  assert.match(result.stderr, /failed adapter row native-artifact-through:/);
  assert.match(result.stderr, new RegExp(`candidate mapped CAID ${candidateCaid.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
});

test('a runtime without governed network denial fails operationally before adapter evaluation', {
  skip: CROSSING_LAB_RUNTIME_SUPPORTED,
}, () => {
  const root = freshWorkspace();
  const result = runCli(['crossing-lab', 'run', root]);
  assert.equal(result.status, 1, result.stderr);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /requires a Node permission runtime with --allow-net support/);
  assert.doesNotMatch(result.stderr, /Crossing Lab FAILED|failed adapter row/);
});
