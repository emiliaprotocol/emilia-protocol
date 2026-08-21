// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const gateRoot = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(gateRoot, '../..');
const verifyRoot = path.join(repositoryRoot, 'packages/verify');

function pack(packageRoot, destination) {
  const report = JSON.parse(execFileSync('npm', [
    'pack', '--ignore-scripts', '--json', '--pack-destination', destination,
  ], { cwd: packageRoot, encoding: 'utf8' }));
  const entries = Array.isArray(report) ? report : Object.values(report ?? {});
  assert.equal(entries.length, 1, 'npm pack must return exactly one package');
  assert.equal(typeof entries[0]?.filename, 'string', 'npm pack report must name the tarball');
  return path.join(destination, entries[0].filename);
}

function extract(tarball, target) {
  fs.mkdirSync(target, { recursive: true });
  execFileSync('tar', ['-xzf', tarball, '--strip-components=1', '-C', target]);
}

function linkExternalGateDependencies(consumerRoot, gatePackage) {
  for (const dependency of Object.keys(gatePackage.dependencies ?? {})) {
    if (dependency === '@emilia-protocol/verify') continue;
    const source = path.join(repositoryRoot, 'node_modules', ...dependency.split('/'));
    const target = path.join(consumerRoot, 'node_modules', ...dependency.split('/'));
    assert.ok(fs.existsSync(source), `missing installed dependency ${dependency}`);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.symlinkSync(source, target, 'junction');
  }
}

test('packed Gate and Verify expose the experimental A2A/AP2 integration to a blank consumer', () => {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'emilia-a2a-ap2-consumer-'));
  try {
    const gateTarball = pack(gateRoot, temporaryRoot);
    const verifyTarball = pack(verifyRoot, temporaryRoot);
    const consumerRoot = path.join(temporaryRoot, 'consumer');
    const installedGate = path.join(consumerRoot, 'node_modules', '@emilia-protocol', 'gate');
    const installedVerify = path.join(consumerRoot, 'node_modules', '@emilia-protocol', 'verify');
    extract(gateTarball, installedGate);
    extract(verifyTarball, installedVerify);

    const gatePackage = JSON.parse(fs.readFileSync(path.join(installedGate, 'package.json'), 'utf8'));
    const verifyPackage = JSON.parse(fs.readFileSync(path.join(installedVerify, 'package.json'), 'utf8'));
    assert.deepEqual(gatePackage.exports['./a2a-ap2-gate'], {
      types: './dist/a2a-ap2-gate.d.ts',
      import: './a2a-ap2-gate.js',
    });
    assert.ok(verifyPackage.exports['./ap2-native-adapter']);
    assert.ok(verifyPackage.exports['./a2a-evidence-challenge']);
    linkExternalGateDependencies(consumerRoot, gatePackage);
    fs.writeFileSync(path.join(consumerRoot, 'package.json'), JSON.stringify({ type: 'module' }));
    fs.writeFileSync(path.join(consumerRoot, 'consumer.mjs'), `
      import { A2AAp2Gate as RootGate } from '@emilia-protocol/gate';
      import {
        A2AAp2Gate,
        A2A_AP2_GATE_PROFILE_VERSION,
      } from '@emilia-protocol/gate/a2a-ap2-gate';
      import { AP2_NATIVE_AEB_ADAPTER_ID } from '@emilia-protocol/verify/ap2-native-adapter';
      import {
        A2A_AP2_NATIVE_PRESENTATION_METHOD,
      } from '@emilia-protocol/verify/a2a-evidence-challenge';
      if (RootGate !== A2AAp2Gate) throw new Error('Gate root export drift');
      if (A2A_AP2_GATE_PROFILE_VERSION !== 'EP-A2A-AP2-GATE-EXPERIMENTAL-v1') {
        throw new Error('Gate profile export drift');
      }
      if (AP2_NATIVE_AEB_ADAPTER_ID !== 'native:ap2-agent-authorization') {
        throw new Error('AP2 adapter export drift');
      }
      if (A2A_AP2_NATIVE_PRESENTATION_METHOD !== 'ap2-native') {
        throw new Error('A2A challenge export drift');
      }
    `);
    execFileSync(process.execPath, [path.join(consumerRoot, 'consumer.mjs')], {
      cwd: consumerRoot,
      stdio: 'pipe',
    });
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
});
