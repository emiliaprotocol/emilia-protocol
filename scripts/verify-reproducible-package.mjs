#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';

export function assertArtifactBytesMatch(expected, observed) {
  const left = Buffer.isBuffer(expected) ? expected : Buffer.from(expected ?? []);
  const right = Buffer.isBuffer(observed) ? observed : Buffer.from(observed ?? []);
  if (!left.equals(right)) {
    const expectedHash = crypto.createHash('sha256').update(left).digest('hex');
    const observedHash = crypto.createHash('sha256').update(right).digest('hex');
    throw new Error(`published artifact bytes differ: ${expectedHash} != ${observedHash}`);
  }
  return crypto.createHash('sha256').update(left).digest('hex');
}

export function verifyReproduciblePackage(packagePath = 'packages/verify') {
  const packageDir = path.resolve(ROOT, packagePath);
  const packageJsonPath = path.join(packageDir, 'package.json');
  if (!fs.existsSync(packageJsonPath)) throw new Error(`package.json not found: ${packageJsonPath}`);
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-repro-pack-'));

  function pack(label) {
    const destination = path.join(scratch, label);
    fs.mkdirSync(destination);
    const run = spawnSync(npm, ['pack', packageDir, '--json', '--pack-destination', destination], {
      cwd: ROOT,
      encoding: 'utf8',
      env: { ...process.env, npm_config_ignore_scripts: 'true' },
    });
    if (run.status !== 0) {
      throw new Error(`npm pack ${label} failed:\n${run.stderr || run.stdout}`);
    }
    let report;
    try {
      report = JSON.parse(run.stdout);
    } catch {
      throw new Error(`npm pack ${label} did not return JSON: ${run.stdout}`);
    }
    if (!Array.isArray(report) || report.length !== 1 || typeof report[0].filename !== 'string') {
      throw new Error(`npm pack ${label} returned an unexpected report`);
    }
    const bytes = fs.readFileSync(path.join(destination, report[0].filename));
    return {
      bytes,
      filename: report[0].filename,
      files: (report[0].files || []).map((entry) => `${entry.path}:${entry.size}`).sort(),
      sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
    };
  }

  try {
    const first = pack('first');
    const second = pack('second');
    if (first.filename !== second.filename) throw new Error('pack filenames differ');
    if (JSON.stringify(first.files) !== JSON.stringify(second.files)) throw new Error('pack file manifests differ');
    if (!first.bytes.equals(second.bytes)) {
      throw new Error(`package bytes differ: ${first.sha256} != ${second.sha256}`);
    }
    const metadata = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    return { name: metadata.name, version: metadata.version, filename: first.filename, sha256: first.sha256, fileCount: first.files.length };
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = verifyReproduciblePackage(process.argv[2] || 'packages/verify');
    console.log(`reproducible package: ${result.name}@${result.version}`);
    console.log(`tarball: ${result.filename}`);
    console.log(`sha256: ${result.sha256}`);
    console.log(`files: ${result.fileCount}`);
  } catch (error) {
    console.error(`reproducibility check failed: ${error.message}`);
    process.exitCode = 1;
  }
}
