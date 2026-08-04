#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
// `tsx` is loaded as an ESM import hook through the active Node executable.
// This works on the repository's Node 20 floor and avoids invoking the
// platform-specific node_modules/.bin/tsx wrapper directly.
const tsLoader = 'tsx';

const stages = [
  {
    label: 'Gate compiled-runtime freshness',
    command: process.execPath,
    displayCommand: 'node',
    args: ['scripts/check-gate-runtime-freshness.mjs'],
  },
  {
    label: 'standalone Node 20 runtime freshness',
    command: process.execPath,
    displayCommand: 'node',
    args: ['scripts/build-standalone-runtimes.mjs', '--check'],
  },
  {
    label: 'indeterminate-effect reconciliation demo',
    command: process.execPath,
    displayCommand: 'node',
    args: [
      '--import',
      tsLoader,
      'examples/indeterminate-effect-reconciliation/demo.mjs',
    ],
  },
  {
    label: 'indeterminate-effect reconciliation tests',
    command: process.execPath,
    displayCommand: 'node',
    args: [
      '--import',
      tsLoader,
      '--test',
      'examples/indeterminate-effect-reconciliation/scenario.test.mjs',
    ],
  },
  {
    label: 'Gate allowance demo',
    command: process.execPath,
    displayCommand: 'node',
    args: ['--import', tsLoader, 'examples/gate-allowance/demo.mjs'],
  },
  {
    label: 'Gate service focused tests',
    command: process.execPath,
    displayCommand: 'node',
    args: ['--import', tsLoader, '--test', 'apps/gate-service/test/service.test.js'],
  },
  {
    label: 'consequence-control actuator-client focused tests',
    command: process.execPath,
    displayCommand: 'node',
    args: [
      '--import',
      tsLoader,
      '--test',
      'apps/consequence-control-service/test/actuator-client.test.js',
    ],
  },
  {
    label: 'consequence-actuator split-boundary focused test',
    command: process.execPath,
    displayCommand: 'node',
    args: [
      '--import',
      tsLoader,
      '--test',
      'apps/consequence-actuator-service/test/split-integration.test.ts',
    ],
  },
];

function printScope(result) {
  console.log(`\nGate reference proof: ${result}`);
  console.log('Scope summary:');
  console.log('- Self-contained local examples exercise capability reconciliation and allowance enforcement with generated keys, in-memory state, and mock provider behavior.');
  console.log('- Focused repository tests exercise the Gate HTTP service, the consequence-control actuator client, and the authenticated split actuator boundary.');
  console.log('- These are separate local proof surfaces, not evidence of a real human, external bank, production deployment, or one end-to-end production integration.');
}

for (const [index, stage] of stages.entries()) {
  console.log(`\n[${index + 1}/${stages.length}] ${stage.label}`);
  console.log(`$ ${stage.displayCommand} ${stage.args.join(' ')}`);

  const result = spawnSync(stage.command, stage.args, {
    cwd: repositoryRoot,
    env: {
      ...process.env,
      FORCE_COLOR: '0',
      TZ: 'UTC',
    },
    stdio: 'inherit',
  });

  if (result.error) {
    console.error(`[FAIL] ${stage.label}: ${result.error.message}`);
    printScope(`FAILED at stage ${index + 1} of ${stages.length}`);
    process.exit(1);
  }

  if (result.status !== 0) {
    const termination = result.signal
      ? `signal ${result.signal}`
      : `exit status ${result.status}`;
    console.error(`[FAIL] ${stage.label}: ${termination}`);
    printScope(`FAILED at stage ${index + 1} of ${stages.length}`);
    process.exit(result.status ?? 1);
  }

  console.log(`[PASS] ${stage.label}`);
}

printScope(`PASSED all ${stages.length} stages`);
