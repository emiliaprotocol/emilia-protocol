// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const packageRoot = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(packageRoot, '../..');

function linkDeclaredDependencies(consumerRoot, packageJson) {
  for (const dependency of Object.keys(packageJson.dependencies ?? {})) {
    const segments = dependency.split('/');
    const source = path.join(repositoryRoot, 'node_modules', ...segments);
    const target = path.join(consumerRoot, 'node_modules', ...segments);
    assert.ok(fs.existsSync(source), `missing installed dependency ${dependency}`);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.symlinkSync(source, target, 'junction');
  }
}

test('a packed blank consumer resolves the bounded program runtime and AdmissionStore types', () => {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'emilia-gate-consumer-'));
  try {
    const packOutput = JSON.parse(execFileSync('npm', [
      'pack', '--ignore-scripts', '--json', '--pack-destination', temporaryRoot,
    ], { cwd: packageRoot, encoding: 'utf8' }));
    const tarball = path.join(temporaryRoot, packOutput[0].filename);
    const installedGate = path.join(
      temporaryRoot, 'consumer', 'node_modules', '@emilia-protocol', 'gate',
    );
    fs.mkdirSync(installedGate, { recursive: true });
    execFileSync('tar', ['-xzf', tarball, '--strip-components=1', '-C', installedGate]);

    const packedPackage = JSON.parse(fs.readFileSync(
      path.join(installedGate, 'package.json'), 'utf8',
    ));
    assert.deepEqual(packedPackage.exports['./bounded-execution-program'], {
      types: './dist/bounded-execution-program.d.ts',
      import: './bounded-execution-program.js',
    });
    assert.ok(packedPackage.files.includes('bounded-execution-program.js'));
    assert.deepEqual(packedPackage.exports['./bounded-execution-report'], {
      types: './dist/bounded-execution-report.d.ts',
      import: './bounded-execution-report.js',
    });
    assert.ok(packedPackage.files.includes('bounded-execution-report.js'));
    assert.ok(packedPackage.files.includes('sql/gate-qualification-v2.sql'));
    assert.ok(fs.existsSync(path.join(installedGate, 'sql', 'gate-qualification-v2.sql')));

    const consumerRoot = path.join(temporaryRoot, 'consumer');
    linkDeclaredDependencies(consumerRoot, packedPackage);
    fs.writeFileSync(path.join(consumerRoot, 'package.json'), JSON.stringify({ type: 'module' }));
    fs.writeFileSync(path.join(consumerRoot, 'consumer.mjs'), `
      import * as gate from '@emilia-protocol/gate';
      import * as program from '@emilia-protocol/gate/bounded-execution-program';
      import * as report from '@emilia-protocol/gate/bounded-execution-report';
      import * as admission from '@emilia-protocol/gate/admission-store';
      if (gate.signBoundedExecutionProgram !== program.signBoundedExecutionProgram) {
        throw new Error('root barrel does not export bounded execution programs');
      }
      if (typeof admission.createMemoryAdmissionStore !== 'function') {
        throw new Error('AdmissionStore subpath did not resolve');
      }
      if (gate.signBoundedExecutionReport !== report.signBoundedExecutionReport) {
        throw new Error('root barrel does not export bounded execution reports');
      }
    `);
    execFileSync(process.execPath, [path.join(consumerRoot, 'consumer.mjs')], {
      cwd: consumerRoot,
      stdio: 'pipe',
    });

    fs.writeFileSync(path.join(consumerRoot, 'consumer.ts'), `
      import {
        type BoundedExecutionProgramInput,
        signBoundedExecutionProgram,
      } from '@emilia-protocol/gate/bounded-execution-program';
      import {
        type BoundedExecutionReportInput,
        verifyBoundedExecutionReport,
      } from '@emilia-protocol/gate/bounded-execution-report';
      import {
        createMemoryAdmissionStore,
        type ExecutionProgramAdmissionStore,
        type ExecutionProgramOccurrence,
        type ExecutionProgramRuntimeState,
      } from '@emilia-protocol/gate';
      const store: ExecutionProgramAdmissionStore = createMemoryAdmissionStore();
      const state: ExecutionProgramRuntimeState | null = await store.readExecutionProgram({
        tenant_id: 'tenant:consumer',
        program_digest: 'sha256:' + '0'.repeat(64),
      });
      const occurrence: ExecutionProgramOccurrence | null = null;
      void (null as BoundedExecutionProgramInput | null);
      void signBoundedExecutionProgram;
      void (null as BoundedExecutionReportInput | null);
      void verifyBoundedExecutionReport;
      void state;
      void occurrence;
    `);
    fs.writeFileSync(path.join(consumerRoot, 'tsconfig.json'), JSON.stringify({
      compilerOptions: {
        target: 'ES2022',
        module: 'NodeNext',
        moduleResolution: 'NodeNext',
        strict: true,
        skipLibCheck: true,
        types: [],
        noEmit: true,
      },
      files: ['consumer.ts'],
    }));
    execFileSync(process.execPath, [
      path.join(repositoryRoot, 'node_modules', 'typescript', 'bin', 'tsc'),
      '-p', path.join(consumerRoot, 'tsconfig.json'),
    ], { cwd: consumerRoot, stdio: 'pipe' });
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
});
