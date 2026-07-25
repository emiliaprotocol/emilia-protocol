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
const git: string = process.platform === 'win32' ? 'git.exe' : 'git';

export function npmArtifactFilename(packageName: string, version: string): string {
  if (typeof packageName !== 'string'
    || typeof version !== 'string'
    || !/^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/u.test(packageName)
    || !/^[0-9A-Za-z][0-9A-Za-z.+-]*$/u.test(version)) {
    throw new Error('package identity is malformed');
  }
  return `${packageName.replace(/^@/u, '').replace(/\//gu, '-')}-${version}.tgz`;
}

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

function tarString(block: Buffer, offset: number, length: number): string {
  const field: Buffer = block.subarray(offset, offset + length);
  const terminator: number = field.indexOf(0);
  return field.subarray(0, terminator >= 0 ? terminator : field.length).toString('utf8');
}

function tarSize(block: Buffer): number {
  const value: string = tarString(block, 124, 12).trim();
  if (!/^[0-7]+$/u.test(value)) throw new Error('npm tarball contains an unsupported entry size');
  const size: number = Number.parseInt(value, 8);
  if (!Number.isSafeInteger(size) || size < 0) throw new Error('npm tarball contains an unsafe entry size');
  return size;
}

export function validatePackedPackageIdentity(
  archive: Buffer | Uint8Array,
  expectedName: string,
  expectedVersion: string,
): { name: string; version: string } {
  const tarBytes: Buffer = Buffer.from(ungzip(archive));
  const identities: any[] = [];
  for (let offset = 0; offset + 512 <= tarBytes.length;) {
    const header: Buffer = tarBytes.subarray(offset, offset + 512);
    if (header.every((value: number) => value === 0)) break;
    const name: string = tarString(header, 0, 100);
    const prefix: string = tarString(header, 345, 155);
    const entryPath: string = prefix ? `${prefix}/${name}` : name;
    const size: number = tarSize(header);
    const dataOffset: number = offset + 512;
    const nextOffset: number = dataOffset + Math.ceil(size / 512) * 512;
    if (nextOffset > tarBytes.length) throw new Error('npm tarball entry extends beyond the archive');
    if (entryPath === 'package/package.json') {
      const type: number = header[156];
      if (type !== 0 && type !== 0x30) {
        throw new Error('npm tarball package/package.json is not a regular file');
      }
      try {
        identities.push(JSON.parse(tarBytes.subarray(dataOffset, dataOffset + size).toString('utf8')));
      } catch {
        throw new Error('npm tarball package/package.json is not valid JSON');
      }
    }
    offset = nextOffset;
  }
  if (identities.length !== 1) {
    throw new Error(`npm tarball must contain exactly one package/package.json; found ${identities.length}`);
  }
  const [identity] = identities;
  if (identity?.name !== expectedName || identity?.version !== expectedVersion) {
    throw new Error(
      `npm tarball package identity differs from approved ${expectedName}@${expectedVersion}`,
    );
  }
  return { name: identity.name, version: identity.version };
}

/**
 * @param {string} [packagePath]
 * @param {{ outDir?: string | null, dependencyRoot?: string | null }} [options]
 */
export function verifyReproduciblePackage(
  packagePath: string = 'packages/verify',
  {
    outDir = null,
    dependencyRoot = null,
  }: { outDir?: string | null; dependencyRoot?: string | null } = {},
): any {
  const packageDir: string = path.resolve(ROOT, packagePath);
  const packageJsonPath: string = path.join(packageDir, 'package.json');
  if (!fs.existsSync(packageJsonPath)) throw new Error(`package.json not found: ${packageJsonPath}`);
  const packageJsonBytes: Buffer = fs.readFileSync(packageJsonPath);
  const metadata: any = JSON.parse(packageJsonBytes.toString('utf8'));
  const expectedFilename: string = npmArtifactFilename(metadata.name, metadata.version);
  const scratch: string = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-repro-pack-'));

  function isolatedEnv(label: string, ignoreScripts: boolean): NodeJS.ProcessEnv {
    const safeLabel: string = label.replace(/[^a-z0-9._-]+/giu, '-');
    const environmentRoot: string = path.join(scratch, `${safeLabel}-environment`);
    const home: string = path.join(environmentRoot, 'home');
    const cache: string = path.join(environmentRoot, 'npm-cache');
    const temporary: string = path.join(environmentRoot, 'tmp');
    for (const directory of [home, cache, temporary]) {
      fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    }
    return {
      ...process.env,
      HOME: home,
      USERPROFILE: home,
      XDG_CACHE_HOME: cache,
      npm_config_cache: cache,
      npm_config_ignore_scripts: ignoreScripts ? 'true' : 'false',
      TMPDIR: temporary,
      TMP: temporary,
      TEMP: temporary,
    };
  }

  function runPack(args: string[], label: string): any {
    const run = spawnSync(npm, ['pack', ...args, '--json'], {
      cwd: ROOT,
      encoding: 'utf8',
      env: isolatedEnv(`${label}-pack`, true),
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
    const [entry] = report;
    if (entry.name !== metadata.name
      || entry.version !== metadata.version
      || entry.filename !== expectedFilename) {
      throw new Error(
        `npm pack ${label} package identity differs from approved ${metadata.name}@${metadata.version} (${expectedFilename})`,
      );
    }
    return entry;
  }

  function copyEntry(source: string, target: string): void {
    const sourceStat: fs.Stats = fs.lstatSync(source);
    fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o755 });
    if (sourceStat.isSymbolicLink()) {
      fs.symlinkSync(fs.readlinkSync(source), target);
      return;
    }
    if (!sourceStat.isFile()) {
      throw new Error(`tracked package source is not a regular file: ${source}`);
    }
    fs.copyFileSync(source, target);
    fs.chmodSync(target, sourceStat.mode & 0o777);
  }

  function createSourceSnapshot(): { root: string; packageRelative: string } {
    const snapshotRoot: string = path.join(scratch, 'tracked-source');
    const packageRelative: string = path.relative(ROOT, packageDir);
    const packageIsInRepository: boolean = packageRelative === ''
      || (!path.isAbsolute(packageRelative)
        && packageRelative !== '..'
        && !packageRelative.startsWith(`..${path.sep}`));
    const packageJsonRelative: string = path.join(packageRelative, 'package.json');
    const trackedPackageJson = packageIsInRepository
      ? spawnSync(git, ['ls-files', '--error-unmatch', '--', packageJsonRelative], {
        cwd: ROOT,
        encoding: 'utf8',
      })
      : null;

    fs.mkdirSync(snapshotRoot, { recursive: true, mode: 0o755 });
    if (trackedPackageJson?.status === 0) {
      const listed = spawnSync(git, ['ls-files', '-z', '--cached'], {
        cwd: ROOT,
        encoding: 'utf8',
      });
      if (listed.status !== 0) {
        throw new Error(`git tracked-source inventory failed:\n${listed.stderr || listed.stdout}`);
      }
      for (const relative of listed.stdout.split('\0').filter(Boolean)) {
        const source: string = path.resolve(ROOT, relative);
        if (!source.startsWith(`${ROOT}${path.sep}`)) {
          throw new Error(`git tracked-source inventory escapes repository root: ${relative}`);
        }
        copyEntry(source, path.join(snapshotRoot, relative));
      }
      return { root: snapshotRoot, packageRelative };
    }

    fs.cpSync(packageDir, snapshotRoot, {
      recursive: true,
      filter: (source: string) => {
        const relative: string = path.relative(packageDir, source);
        if (!relative) return true;
        const first: string = relative.split(path.sep)[0];
        return first !== '.git' && first !== 'node_modules';
      },
    });
    return { root: snapshotRoot, packageRelative: '' };
  }

  function cloneDependencyTree(sourceRoot: string, targetRoot: string): void {
    const activeDirectories: Set<string> = new Set();
    const cloneEntry = (source: string, target: string): void => {
      const sourceLstat: fs.Stats = fs.lstatSync(source);
      const resolvedSource: string = sourceLstat.isSymbolicLink() ? fs.realpathSync(source) : source;
      if (sourceLstat.isSymbolicLink()) {
        const realSourceRoot: string = fs.realpathSync(sourceRoot);
        const isInternalLink: boolean = resolvedSource === realSourceRoot
          || resolvedSource.startsWith(`${realSourceRoot}${path.sep}`);
        if (isInternalLink) {
          const clonedTarget: string = path.join(
            targetRoot,
            path.relative(realSourceRoot, resolvedSource),
          );
          const relativeTarget: string = path.relative(path.dirname(target), clonedTarget) || '.';
          fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o755 });
          fs.symlinkSync(
            relativeTarget,
            target,
            fs.statSync(resolvedSource).isDirectory()
              ? (process.platform === 'win32' ? 'junction' : 'dir')
              : 'file',
          );
          return;
        }
      }
      const sourceStat: fs.Stats = sourceLstat.isSymbolicLink() ? fs.statSync(source) : sourceLstat;
      if (sourceStat.isDirectory()) {
        const realDirectory: string = fs.realpathSync(resolvedSource);
        if (activeDirectories.has(realDirectory)) {
          throw new Error(`dependency tree contains a symlink cycle: ${source}`);
        }
        activeDirectories.add(realDirectory);
        fs.mkdirSync(target, { recursive: true, mode: sourceStat.mode & 0o777 });
        for (const entry of fs.readdirSync(resolvedSource)) {
          cloneEntry(path.join(resolvedSource, entry), path.join(target, entry));
        }
        fs.chmodSync(target, sourceStat.mode & 0o777);
        activeDirectories.delete(realDirectory);
        return;
      }
      if (!sourceStat.isFile()) {
        throw new Error(`dependency tree entry is not a regular file or directory: ${source}`);
      }
      fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o755 });
      fs.copyFileSync(resolvedSource, target, fs.constants.COPYFILE_FICLONE);
      fs.chmodSync(target, sourceStat.mode & 0o777);
    };
    cloneEntry(sourceRoot, targetRoot);
  }

  function isolateBuildDependencies(buildRoot: string, buildPackageDir: string): void {
    const repositoryNodeModules: string = dependencyRoot
      ? path.resolve(dependencyRoot)
      : path.join(ROOT, 'node_modules');
    const packageNodeModules: string = path.join(packageDir, 'node_modules');
    if (fs.existsSync(repositoryNodeModules)) {
      cloneDependencyTree(
        repositoryNodeModules,
        path.join(buildRoot, 'node_modules'),
      );
    }
    if (buildPackageDir !== buildRoot && fs.existsSync(packageNodeModules)) {
      cloneDependencyTree(
        packageNodeModules,
        path.join(buildPackageDir, 'node_modules'),
      );
    }
  }

  function buildPackage(source: { root: string; packageRelative: string }, label: string): string {
    const buildRoot: string = path.join(scratch, `${label}-build`);
    fs.cpSync(source.root, buildRoot, { recursive: true });
    const buildPackageDir: string = path.join(buildRoot, source.packageRelative);
    if (typeof metadata.scripts?.build === 'string') {
      fs.rmSync(path.join(buildPackageDir, 'dist'), { recursive: true, force: true });
      isolateBuildDependencies(buildRoot, buildPackageDir);
      const run = spawnSync(npm, ['run', 'build'], {
        cwd: buildPackageDir,
        encoding: 'utf8',
        env: isolatedEnv(`${label}-build`, false),
      });
      if (run.status !== 0) {
        throw new Error(`package build ${label} failed:\n${run.stderr || run.stdout}`);
      }
      const builtPackageJson: Buffer = fs.readFileSync(path.join(buildPackageDir, 'package.json'));
      if (!builtPackageJson.equals(packageJsonBytes)) {
        throw new Error(`package build ${label} mutated package.json`);
      }
    }
    return buildPackageDir;
  }

  function stageCanonicalPackage(builtPackageDir: string, label: string): string {
    const inventory: any = runPack([builtPackageDir, '--dry-run'], `${label} inventory`);
    const stage: string = path.join(scratch, `${label}-canonical-input`);
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
      const source: string = path.resolve(builtPackageDir, relative);
      if (!source.startsWith(`${builtPackageDir}${path.sep}`)) {
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
    validatePackedPackageIdentity(bytes, metadata.name, metadata.version);
    return {
      bytes,
      filename: report.filename,
      files: (report.files || []).map((entry: any) => `${entry.path}:${entry.size}:${entry.mode}`).sort(),
      sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
    };
  }

  try {
    const source = createSourceSnapshot();
    const first: any = pack(stageCanonicalPackage(buildPackage(source, 'first'), 'first'), 'first');
    const second: any = pack(stageCanonicalPackage(buildPackage(source, 'second'), 'second'), 'second');
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
