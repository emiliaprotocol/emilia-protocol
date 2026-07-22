#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { gzip, ungzip } from 'pako';

const ROOT: string = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const npm: string = process.platform === 'win32' ? 'npm.cmd' : 'npm';

export function assertArtifactBytesMatch(expected: Buffer | Uint8Array | undefined, observed: Buffer | Uint8Array | undefined): string {
  const left: Buffer = Buffer.isBuffer(expected) ? expected : Buffer.from(expected ?? []);
  const right: Buffer = Buffer.isBuffer(observed) ? observed : Buffer.from(observed ?? []);
  if (!left.equals(right)) {
    const expectedHash: string = crypto.createHash('sha256').update(left).digest('hex');
    const observedHash: string = crypto.createHash('sha256').update(right).digest('hex');
    throw new Error(`published artifact bytes differ: ${expectedHash} != ${observedHash}`);
  }
  return crypto.createHash('sha256').update(left).digest('hex');
}

/**
 * npm delegates gzip compression to the host Node/zlib toolchain. The tar
 * payload is stable, but npm 10/Node 20 and npm 11/Node 25 can emit different
 * DEFLATE streams for the same payload. Recompress with a pinned pure-JS
 * implementation so the bytes we attest and publish are toolchain-independent.
 *
 * @param {Buffer|Uint8Array} archive
 */
export function canonicalizeNpmTarball(archive: Buffer | Uint8Array): Buffer {
  const tarBytes: Uint8Array = ungzip(archive);
  const gzipBytes: Buffer = Buffer.from(gzip(tarBytes, {
    level: 9,
  }));
  // Pako 3 no longer exposes the v1 `header` option.  Normalize the two
  // gzip header fields that are allowed to vary by runtime: MTIME and OS.
  gzipBytes.writeUInt32LE(0, 4);
  gzipBytes[9] = 0xff;
  return gzipBytes;
}

/**
 * @param {string} [packagePath]
 * @param {{ outDir?: string | null }} [options]
 */
export function verifyReproduciblePackage(packagePath: string = 'packages/verify', { outDir = null }: { outDir?: string | null } = {}): any {
  const packageDir: string = path.resolve(ROOT, packagePath);
  const packageJsonPath: string = path.join(packageDir, 'package.json');
  if (!fs.existsSync(packageJsonPath)) throw new Error(`package.json not found: ${packageJsonPath}`);
  const metadata: any = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  const scratch: string = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-repro-pack-'));
  const packEnv: any = { ...process.env, npm_config_ignore_scripts: 'true' };

  function runPack(args: string[], label: string): any {
    const run = spawnSync(npm, ['pack', ...args, '--json'], {
      cwd: ROOT,
      encoding: 'utf8',
      env: packEnv,
    });
    if (run.status !== 0) {
      throw new Error(`npm pack ${label} failed:\n${run.stderr || run.stdout}`);
    }
    let report: any;
    try {
      report = JSON.parse(run.stdout as string);
    } catch {
      throw new Error(`npm pack ${label} did not return JSON: ${run.stdout}`);
    }
    if (!Array.isArray(report) || report.length !== 1 || typeof report[0].filename !== 'string') {
      throw new Error(`npm pack ${label} returned an unexpected report`);
    }
    return report[0];
  }

  function stageCanonicalPackage(): string {
    const inventory: any = runPack([packageDir, '--dry-run'], 'inventory');
    const stage: string = path.join(scratch, 'canonical-input');
    const binValues: any[] = typeof metadata.bin === 'string'
      ? [metadata.bin]
      : metadata.bin && typeof metadata.bin === 'object'
        ? Object.values(metadata.bin)
        : [];
    const executablePaths: Set<string> = new Set(binValues.map((value: any) => String(value).replace(/^\.\//, '')));
    fs.mkdirSync(stage, { recursive: true, mode: 0o755 });
    for (const entry of inventory.files || []) {
      if (!entry || typeof entry.path !== 'string' || path.isAbsolute(entry.path)) {
        throw new Error('npm pack inventory contains a malformed path');
      }
      const relative: string = entry.path.split('/').join(path.sep);
      const source: string = path.resolve(packageDir, relative);
      if (!source.startsWith(`${packageDir}${path.sep}`)) {
        throw new Error(`npm pack inventory escapes package root: ${entry.path}`);
      }
      const sourceStat = fs.lstatSync(source);
      if (!sourceStat.isFile()) {
        throw new Error(`npm pack inventory requires a regular file: ${entry.path}`);
      }
      const target: string = path.join(stage, relative);
      fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o755 });
      fs.copyFileSync(source, target);
      fs.chmodSync(target, executablePaths.has(entry.path) ? 0o755 : 0o644);
    }
    return stage;
  }

  function pack(packageInput: string, label: string): any {
    const destination: string = path.join(scratch, label);
    fs.mkdirSync(destination);
    const report: any = runPack([packageInput, '--pack-destination', destination], label);
    const bytes: Buffer = canonicalizeNpmTarball(
      fs.readFileSync(path.join(destination, report.filename)),
    );
    return {
      bytes,
      filename: report.filename,
      files: (report.files || []).map((entry: any) => `${entry.path}:${entry.size}:${entry.mode}`).sort(),
      sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
    };
  }

  try {
    const canonicalInput: string = stageCanonicalPackage();
    const first: any = pack(canonicalInput, 'first');
    const second: any = pack(canonicalInput, 'second');
    if (first.filename !== second.filename) throw new Error('pack filenames differ');
    if (JSON.stringify(first.files) !== JSON.stringify(second.files)) throw new Error('pack file manifests differ');
    if (!first.bytes.equals(second.bytes)) {
      throw new Error(`package bytes differ: ${first.sha256} != ${second.sha256}`);
    }
    let artifactPath: string | null = null;
    if (outDir) {
      const destination: string = path.resolve(ROOT, outDir);
      fs.mkdirSync(destination, { recursive: true });
      artifactPath = path.join(destination, first.filename);
      fs.writeFileSync(artifactPath, first.bytes);
    }
    return {
      name: metadata.name,
      version: metadata.version,
      packagePath: path.relative(ROOT, packageDir).split(path.sep).join('/'),
      filename: first.filename,
      sha256: first.sha256,
      bytes: first.bytes.length,
      fileCount: first.files.length,
      fileManifestSha256: crypto.createHash('sha256').update(JSON.stringify(first.files)).digest('hex'),
      ...(artifactPath ? { artifactPath } : {}),
    };
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const argv: string[] = process.argv.slice(2);
    let packagePath: string | null = null;
    let outDir: string | null = null;
    let emitPath: string | null = null;
    for (let index = 0; index < argv.length; index += 1) {
      const value: string = argv[index];
      if (value === '--outdir' || value === '--emit') {
        const next: string | undefined = argv[index + 1];
        if (!next) throw new Error(`${value} requires a path`);
        if (value === '--outdir') outDir = next;
        else emitPath = next;
        index += 1;
      } else if (value.startsWith('--')) {
        throw new Error(`unknown option: ${value}`);
      } else if (packagePath === null) {
        packagePath = value;
      } else {
        throw new Error(`unexpected argument: ${value}`);
      }
    }
    const result: any = verifyReproduciblePackage(packagePath || 'packages/verify', { outDir });
    const manifest: any = {
      '@version': 'EP-REPRODUCIBLE-NPM-ARTIFACT-v1',
      package_path: result.packagePath,
      package: result.name,
      version: result.version,
      artifact: {
        filename: result.filename,
        sha256: result.sha256,
        bytes: result.bytes,
        files: result.fileCount,
        file_manifest_sha256: result.fileManifestSha256,
      },
    };
    manifest.manifest_sha256 = crypto.createHash('sha256').update(JSON.stringify(manifest)).digest('hex');
    if (emitPath) {
      const target: string = path.resolve(ROOT, emitPath);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, `${JSON.stringify(manifest, null, 2)}\n`);
    }
    console.log(`reproducible package: ${result.name}@${result.version}`);
    console.log(`tarball: ${result.filename}`);
    console.log(`sha256: ${result.sha256}`);
    console.log(`files: ${result.fileCount}`);
  } catch (error) {
    console.error(`reproducibility check failed: ${(error as any).message}`);
    process.exitCode = 1;
  }
}
