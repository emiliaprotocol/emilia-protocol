#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertPythonArtifactBytesMatch } from './python-artifact-integrity.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const argv = process.argv.slice(2);
const option = (name) => {
  const index = argv.indexOf(name);
  return index >= 0 ? argv[index + 1] : null;
};
const emitPath = option('--emit');
const outDir = option('--outdir');
const optionIndexes = new Set();
for (const name of ['--emit', '--outdir']) {
  const index = argv.indexOf(name);
  if (index >= 0) { optionIndexes.add(index); optionIndexes.add(index + 1); }
}
const packageArgs = argv.filter((_, index) => !optionIndexes.has(index));
if (packageArgs.length === 0) {
  console.error('usage: verify-reproducible-wheel [--emit FILE] [--outdir DIR] PACKAGE_DIR...');
  process.exit(2);
}

const python = process.env.PYTHON || 'python3';
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
let sourceDateEpoch = process.env.SOURCE_DATE_EPOCH;
if (!/^\d+$/.test(sourceDateEpoch || '')) {
  sourceDateEpoch = execFileSync('git', ['log', '-1', '--format=%ct'], { cwd: ROOT, encoding: 'utf8' }).trim();
}
if (!/^\d+$/.test(/** @type {string} */ (sourceDateEpoch))) throw new Error('SOURCE_DATE_EPOCH must be a non-negative integer');

function build(packageDir, destination) {
  execFileSync(python, [
    '-m', 'build', '--no-isolation', '--wheel', '--sdist', '--outdir', destination, packageDir,
  ], {
    cwd: ROOT,
    stdio: 'pipe',
    env: {
      ...process.env,
      SOURCE_DATE_EPOCH: sourceDateEpoch,
      PYTHONHASHSEED: '0',
      TZ: 'UTC',
      LC_ALL: 'C.UTF-8',
    },
  });
  return fs.readdirSync(destination)
    .filter((name) => name.endsWith('.whl') || name.endsWith('.tar.gz'))
    .sort();
}

const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-wheel-repro-'));
const packages = [];
try {
  for (let index = 0; index < packageArgs.length; index += 1) {
    const packageDir = path.resolve(ROOT, packageArgs[index]);
    const pyproject = path.join(packageDir, 'pyproject.toml');
    if (!fs.existsSync(pyproject)) throw new Error(`missing pyproject.toml: ${packageArgs[index]}`);
    const first = path.join(temp, `first-${index}`);
    const second = path.join(temp, `second-${index}`);
    fs.mkdirSync(first);
    fs.mkdirSync(second);
    const firstNames = build(packageDir, first);
    const secondNames = build(packageDir, second);
    if (firstNames.length !== 2 || JSON.stringify(firstNames) !== JSON.stringify(secondNames)) {
      throw new Error(`${packageArgs[index]} did not produce one identical wheel/sdist filename set`);
    }
    const artifacts = [];
    for (const name of firstNames) {
      const firstBytes = fs.readFileSync(path.join(first, name));
      const secondBytes = fs.readFileSync(path.join(second, name));
      let artifactHash;
      try { artifactHash = assertPythonArtifactBytesMatch(firstBytes, secondBytes); }
      catch { throw new Error(`${packageArgs[index]} is not reproducible: ${name} bytes differ`); }
      artifacts.push({ filename: name, sha256: artifactHash, bytes: firstBytes.length });
      if (outDir) {
        const destination = path.resolve(ROOT, outDir, path.basename(packageDir));
        fs.mkdirSync(destination, { recursive: true });
        fs.copyFileSync(path.join(first, name), path.join(destination, name));
      }
    }
    packages.push({ package: path.relative(ROOT, packageDir), artifacts });
  }
} catch (error) {
  if (/No module named build|No module named hatchling|Backend 'hatchling/.test(error.message || '')) {
    throw new Error(`${error.message}\nInstall pinned build tooling first: python -m pip install build==1.3.0 hatchling==1.31.0`);
  }
  throw error;
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}

const manifest = {
  '@version': 'EP-REPRODUCIBLE-PYTHON-ARTIFACTS-v1',
  source_date_epoch: Number(sourceDateEpoch),
  build: { command: 'python -m build --no-isolation --wheel --sdist', python_hash_seed: 0 },
  packages,
};
manifest.manifest_sha256 = sha256(Buffer.from(JSON.stringify(manifest), 'utf8'));
if (emitPath) {
  const target = path.resolve(ROOT, emitPath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, `${JSON.stringify(manifest, null, 2)}\n`);
}
console.log(`REPRODUCIBLE PYTHON: PASS (${packages.length} package(s), ${packages.reduce((sum, item) => sum + item.artifacts.length, 0)} artifacts; sha256:${manifest.manifest_sha256})`);
