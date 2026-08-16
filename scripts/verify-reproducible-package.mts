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

function tarMode(block: Buffer): number {
  const value: string = tarString(block, 100, 8).trim();
  if (!/^[0-7]+$/u.test(value)) throw new Error('npm tarball contains an unsupported entry mode');
  const mode: number = Number.parseInt(value, 8);
  if (!Number.isSafeInteger(mode) || mode < 0) throw new Error('npm tarball contains an unsafe entry mode');
  return mode & 0o777;
}

type PackedMember = {
  path: string;
  mode: number;
  bytes: number;
  sha256: string;
};

export function inspectPackedPackageMembers(archive: Buffer | Uint8Array): PackedMember[] {
  const tarBytes: Buffer = Buffer.from(ungzip(archive));
  const members: PackedMember[] = [];
  const seen: Set<string> = new Set();
  let offset: number = 0;
  let reachedEnd: boolean = false;
  while (offset + 512 <= tarBytes.length) {
    const header: Buffer = tarBytes.subarray(offset, offset + 512);
    if (header.every((value: number) => value === 0)) {
      reachedEnd = true;
      break;
    }
    const name: string = tarString(header, 0, 100);
    const prefix: string = tarString(header, 345, 155);
    const entryPath: string = prefix ? `${prefix}/${name}` : name;
    const segments: string[] = entryPath.split('/');
    const size: number = tarSize(header);
    const dataOffset: number = offset + 512;
    const nextOffset: number = dataOffset + Math.ceil(size / 512) * 512;
    if (!entryPath.startsWith('package/')
      || entryPath.startsWith('/')
      || entryPath.includes('\\')
      || segments.some((segment: string) => !segment || segment === '.' || segment === '..')
      || nextOffset > tarBytes.length) {
      throw new Error(`npm tarball contains an unsafe entry path: ${entryPath}`);
    }
    if (seen.has(entryPath)) throw new Error(`npm tarball contains a duplicate entry: ${entryPath}`);
    seen.add(entryPath);
    const type: number = header[156];
    if (type !== 0 && type !== 0x30) {
      throw new Error(`npm tarball links and non-regular entries are forbidden: ${entryPath}`);
    }
    const bytes: Buffer = tarBytes.subarray(dataOffset, dataOffset + size);
    members.push({
      path: entryPath.slice('package/'.length),
      mode: tarMode(header),
      bytes: size,
      sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
    });
    offset = nextOffset;
  }
  if (!reachedEnd || tarBytes.subarray(offset).some((value: number) => value !== 0)) {
    throw new Error('npm tarball has a missing or non-zero trailer');
  }
  return members.sort((left: PackedMember, right: PackedMember) => left.path.localeCompare(right.path));
}

export function validatePackedPackageIdentity(
  archive: Buffer | Uint8Array,
  expectedName: string,
  expectedVersion: string,
  expectedPackageJsonBytes: Buffer | Uint8Array,
): { name: string; version: string; packageJsonSha256: string } {
  const tarBytes: Buffer = Buffer.from(ungzip(archive));
  const identities: any[] = [];
  const packageJsonEntries: Buffer[] = [];
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
      const packageJsonBytes: Buffer = tarBytes.subarray(dataOffset, dataOffset + size);
      packageJsonEntries.push(packageJsonBytes);
      try {
        identities.push(JSON.parse(packageJsonBytes.toString('utf8')));
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
  const expectedBytes: Buffer = Buffer.from(expectedPackageJsonBytes);
  const [actualBytes] = packageJsonEntries;
  if (!actualBytes.equals(expectedBytes)) {
    const expectedSha256: string = crypto.createHash('sha256').update(expectedBytes).digest('hex');
    const actualSha256: string = crypto.createHash('sha256').update(actualBytes).digest('hex');
    throw new Error(
      `npm tarball package/package.json bytes differ from source package.json: `
      + `${actualSha256} != ${expectedSha256}`,
    );
  }
  return {
    name: identity.name,
    version: identity.version,
    packageJsonSha256: crypto.createHash('sha256').update(actualBytes).digest('hex'),
  };
}

/**
 * @param {string} [packagePath]
 * @param {{ outDir?: string | null, repositoryRoot?: string | null, reviewedCommit?: string | null }} [options]
 */
export function verifyReproduciblePackage(
  packagePath: string = 'packages/verify',
  {
    outDir = null,
    repositoryRoot = null,
    reviewedCommit = null,
  }: {
    outDir?: string | null;
    repositoryRoot?: string | null;
    reviewedCommit?: string | null;
  } = {},
): any {
  const root: string = path.resolve(repositoryRoot || ROOT);
  const packageDir: string = path.resolve(root, packagePath);
  const packageRelative: string = path.relative(root, packageDir).split(path.sep).join('/');
  if (path.isAbsolute(packageRelative)
    || packageRelative === '..'
    || packageRelative.startsWith('../')) {
    throw new Error('package path must be a repository-relative directory');
  }
  const scratch: string = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-repro-pack-'));

  function run(command: string, args: string[], label: string, options: any = {}): any {
    const result = spawnSync(command, args, {
      cwd: options.cwd || root,
      encoding: options.encoding ?? 'utf8',
      env: options.env,
      maxBuffer: 128 * 1024 * 1024,
    });
    if (result.status !== 0) {
      throw new Error(`${label} failed:\n${result.stderr || result.stdout}`);
    }
    return result;
  }

  const objectFormat: string = String(run(
    git,
    ['rev-parse', '--show-object-format'],
    'git object-format lookup',
  ).stdout).trim();
  const objectLength: number = objectFormat === 'sha1' ? 40 : objectFormat === 'sha256' ? 64 : 0;
  if (!objectLength) throw new Error(`unsupported git object format: ${objectFormat}`);
  if (reviewedCommit !== null
    && !new RegExp(`^[0-9a-f]{${objectLength}}$`, 'u').test(reviewedCommit)) {
    throw new Error('reviewed commit must be an exact full-length Git object id, not a ref');
  }
  const commit: string = String(run(
    git,
    ['rev-parse', '--verify', `${reviewedCommit || 'HEAD'}^{commit}`],
    'reviewed commit resolution',
  ).stdout).trim();
  if (!new RegExp(`^[0-9a-f]{${objectLength}}$`, 'u').test(commit)
    || (reviewedCommit !== null && commit !== reviewedCommit)) {
    throw new Error('reviewed commit did not resolve to the exact requested Git object');
  }
  for (const args of [
    ['diff', '--quiet', commit, '--'],
    ['diff', '--cached', '--quiet', commit, '--'],
  ]) {
    const comparison = spawnSync(git, args, { cwd: root, encoding: 'utf8' });
    if (comparison.status !== 0) {
      throw new Error('working checkout differs from the reviewed commit');
    }
  }
  const treeOid: string = String(run(
    git,
    ['rev-parse', '--verify', `${commit}^{tree}`],
    'reviewed tree resolution',
  ).stdout).trim();
  const packageTreeOid: string = packageRelative
    ? String(run(
      git,
      ['rev-parse', '--verify', `${commit}:${packageRelative}`],
      'reviewed package-tree resolution',
    ).stdout).trim()
    : treeOid;

  const sourceTree: Buffer = run(
    git,
    ['ls-tree', '-rz', '--full-tree', commit],
    'reviewed source-tree inventory',
    { encoding: 'buffer' },
  ).stdout as Buffer;
  const trackedPaths: Set<string> = new Set();
  for (const rawRecord of sourceTree.toString('utf8').split('\0').filter(Boolean)) {
    const match = rawRecord.match(/^(\d{6}) ([a-z]+) ([0-9a-f]+)\t(.+)$/u);
    if (!match) throw new Error(`malformed reviewed Git tree record: ${rawRecord}`);
    const [, mode, type, , relative] = match;
    const segments: string[] = relative.split('/');
    if (relative.startsWith('/')
      || relative.includes('\\')
      || segments.some((segment: string) => !segment || segment === '.' || segment === '..')) {
      throw new Error(`reviewed Git tree contains an unsafe path: ${relative}`);
    }
    if (type !== 'blob' || (mode !== '100644' && mode !== '100755')) {
      throw new Error(`reviewed Git tree contains a symlink, submodule, or unsupported mode: ${relative} (${mode} ${type})`);
    }
    trackedPaths.add(relative);
  }
  const packageJsonRelative: string = packageRelative ? `${packageRelative}/package.json` : 'package.json';
  if (!trackedPaths.has(packageJsonRelative)) {
    throw new Error(`reviewed package.json is not tracked at ${packageJsonRelative}`);
  }
  for (const relative of [...trackedPaths].filter((entry: string) => path.posix.basename(entry) === '.gitattributes')) {
    const attributes: Buffer = run(
      git,
      ['show', `${commit}:${relative}`],
      `reviewed attributes lookup for ${relative}`,
      { encoding: 'buffer' },
    ).stdout as Buffer;
    if (/\bexport-(?:ignore|subst)\b/u.test(attributes.toString('utf8'))) {
      throw new Error(`reviewed Git attributes may not transform or omit source archive bytes: ${relative}`);
    }
  }

  const snapshotRoot: string = path.join(scratch, 'reviewed-source');
  const sourceArchive: string = path.join(scratch, 'reviewed-source.tar');
  fs.mkdirSync(snapshotRoot, { recursive: true, mode: 0o700 });
  run(git, ['archive', '--format=tar', `--output=${sourceArchive}`, commit], 'reviewed source archive');
  const sourceArchiveBytes: Buffer = fs.readFileSync(sourceArchive);
  run('tar', ['-xf', sourceArchive, '-C', snapshotRoot], 'reviewed source extraction');
  const materializedPaths: Set<string> = new Set();
  const inspectMaterialized = (directory: string): void => {
    for (const name of fs.readdirSync(directory).sort()) {
      const absolute: string = path.join(directory, name);
      const relative: string = path.relative(snapshotRoot, absolute).split(path.sep).join('/');
      const stat: fs.Stats = fs.lstatSync(absolute);
      if (stat.isSymbolicLink()) throw new Error(`reviewed source extraction produced a symlink: ${relative}`);
      if (stat.isDirectory()) inspectMaterialized(absolute);
      else if (stat.isFile()) materializedPaths.add(relative);
      else throw new Error(`reviewed source extraction produced an unsupported entry: ${relative}`);
    }
  };
  inspectMaterialized(snapshotRoot);
  if (trackedPaths.size !== materializedPaths.size
    || [...trackedPaths].some((relative: string) => !materializedPaths.has(relative))) {
    throw new Error('reviewed source extraction does not exactly match the Git tree');
  }

  const packageJsonPath: string = path.join(snapshotRoot, packageJsonRelative);
  const packageJsonBytes: Buffer = fs.readFileSync(packageJsonPath);
  const metadata: any = JSON.parse(packageJsonBytes.toString('utf8'));
  const expectedFilename: string = npmArtifactFilename(metadata.name, metadata.version);
  const packageJsonBlobOid: string = String(run(
    git,
    ['rev-parse', '--verify', `${commit}:${packageJsonRelative}`],
    'reviewed package.json blob resolution',
  ).stdout).trim();

  const setTreeWritable = (directory: string, writable: boolean): void => {
    for (const name of fs.readdirSync(directory)) {
      const absolute: string = path.join(directory, name);
      const stat: fs.Stats = fs.lstatSync(absolute);
      if (stat.isSymbolicLink()) throw new Error(`isolated source contains a symlink: ${absolute}`);
      if (stat.isDirectory()) {
        if (writable) fs.chmodSync(absolute, 0o755);
        setTreeWritable(absolute, writable);
        if (!writable) fs.chmodSync(absolute, 0o555);
      } else if (stat.isFile()) {
        const executable: boolean = (stat.mode & 0o111) !== 0;
        fs.chmodSync(absolute, writable ? (executable ? 0o755 : 0o644) : (executable ? 0o555 : 0o444));
      } else {
        throw new Error(`isolated source contains an unsupported entry: ${absolute}`);
      }
    }
    fs.chmodSync(directory, writable ? 0o755 : 0o555);
  };

  function isolatedEnv(
    label: string,
    ignoreScripts: boolean,
    workingDirectory: string,
  ): NodeJS.ProcessEnv {
    const safeLabel: string = label.replace(/[^a-z0-9._-]+/giu, '-');
    const environmentRoot: string = path.join(scratch, `${safeLabel}-environment`);
    const home: string = path.join(environmentRoot, 'home');
    const cache: string = path.join(environmentRoot, 'npm-cache');
    const temporary: string = path.join(environmentRoot, 'tmp');
    const prefix: string = path.join(environmentRoot, 'npm-prefix');
    const userConfig: string = path.join(environmentRoot, 'npmrc');
    for (const directory of [home, cache, temporary, prefix]) {
      fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    }
    fs.writeFileSync(userConfig, '', { mode: 0o600 });
    const controlledPath: string = [
      path.dirname(process.execPath),
      ...(process.platform === 'win32'
        ? [
            path.join(process.env.SYSTEMROOT || 'C:\\Windows', 'System32'),
            process.env.SYSTEMROOT || 'C:\\Windows',
          ]
        : ['/usr/bin', '/bin']),
    ].join(path.delimiter);
    const environment: NodeJS.ProcessEnv = {
      HOME: home,
      USERPROFILE: home,
      XDG_CACHE_HOME: cache,
      PATH: controlledPath,
      PWD: workingDirectory,
      INIT_CWD: workingDirectory,
      RUNNER_TEMP: temporary,
      npm_config_cache: cache,
      npm_config_prefix: prefix,
      npm_config_userconfig: userConfig,
      npm_config_ignore_scripts: ignoreScripts ? 'true' : 'false',
      npm_config_audit: 'false',
      npm_config_fund: 'false',
      npm_config_update_notifier: 'false',
      TMPDIR: temporary,
      TMP: temporary,
      TEMP: temporary,
    };
    for (const key of ['CI', 'LANG', 'LC_ALL', 'SOURCE_DATE_EPOCH', 'TZ']) {
      if (process.env[key] !== undefined) environment[key] = process.env[key];
    }
    if (process.platform === 'win32') {
      for (const key of ['COMSPEC', 'PATHEXT', 'SYSTEMROOT', 'WINDIR']) {
        if (process.env[key] !== undefined) environment[key] = process.env[key];
      }
    }
    return environment;
  }

  function runPack(args: string[], label: string, workingDirectory: string): any {
    const run = spawnSync(npm, ['pack', ...args, '--json'], {
      cwd: workingDirectory,
      encoding: 'utf8',
      env: isolatedEnv(`${label}-pack`, true, workingDirectory),
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

  const dependencyTemplate: string = path.join(scratch, 'dependency-template');
  fs.cpSync(snapshotRoot, dependencyTemplate, { recursive: true });
  setTreeWritable(snapshotRoot, false);
  const templatePackageDir: string = path.join(dependencyTemplate, packageRelative);
  for (const installDirectory of [
    fs.existsSync(path.join(dependencyTemplate, 'package-lock.json')) ? dependencyTemplate : null,
    fs.existsSync(path.join(templatePackageDir, 'package-lock.json')) ? templatePackageDir : null,
  ].filter((value: string | null): value is string => value !== null)) {
    const install = spawnSync(npm, ['ci', '--ignore-scripts', '--min-release-age=0'], {
      cwd: installDirectory,
      encoding: 'utf8',
      env: isolatedEnv(`dependencies-${path.relative(dependencyTemplate, installDirectory) || 'root'}`, true, installDirectory),
    });
    if (install.status !== 0) {
      throw new Error(`locked dependency installation failed:\n${install.stderr || install.stdout}`);
    }
  }

  function isolateBuildDependencies(buildRoot: string, buildPackageDir: string): void {
    const repositoryNodeModules: string = path.join(dependencyTemplate, 'node_modules');
    const packageNodeModules: string = path.join(templatePackageDir, 'node_modules');
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

  function buildPackage(label: string): string {
    const buildRoot: string = path.join(scratch, `${label}-build`);
    fs.cpSync(snapshotRoot, buildRoot, { recursive: true });
    setTreeWritable(buildRoot, true);
    const buildPackageDir: string = path.join(buildRoot, packageRelative);
    if (typeof metadata.scripts?.build === 'string') {
      fs.rmSync(path.join(buildPackageDir, 'dist'), { recursive: true, force: true });
      isolateBuildDependencies(buildRoot, buildPackageDir);
      const run = spawnSync(npm, ['run', '--ignore-scripts', 'build'], {
        cwd: buildPackageDir,
        encoding: 'utf8',
        env: isolatedEnv(`${label}-build`, false, buildPackageDir),
      });
      if (run.status !== 0) {
        throw new Error(
          `package build ${label} failed:\nstdout:\n${run.stdout}\nstderr:\n${run.stderr}`,
        );
      }
      const builtPackageJson: Buffer = fs.readFileSync(path.join(buildPackageDir, 'package.json'));
      if (!builtPackageJson.equals(packageJsonBytes)) {
        throw new Error(`package build ${label} mutated package.json`);
      }
    }
    const rejectPackageSymlinks = (directory: string): void => {
      for (const name of fs.readdirSync(directory)) {
        if (name === 'node_modules') continue;
        const absolute: string = path.join(directory, name);
        const stat: fs.Stats = fs.lstatSync(absolute);
        if (stat.isSymbolicLink()) {
          throw new Error(`package build ${label} produced a forbidden symlink: ${path.relative(buildPackageDir, absolute)}`);
        }
        if (stat.isDirectory()) rejectPackageSymlinks(absolute);
        else if (!stat.isFile()) throw new Error(`package build ${label} produced an unsupported entry: ${absolute}`);
      }
    };
    rejectPackageSymlinks(buildPackageDir);
    for (const relative of trackedPaths) {
      if (packageRelative
        && relative !== packageRelative
        && !relative.startsWith(`${packageRelative}/`)) continue;
      const reviewedPath: string = path.join(snapshotRoot, relative);
      const builtPath: string = path.join(buildRoot, relative);
      const builtStat: fs.Stats = fs.lstatSync(builtPath);
      if (!builtStat.isFile() || builtStat.isSymbolicLink()
        || !fs.readFileSync(reviewedPath).equals(fs.readFileSync(builtPath))) {
        throw new Error(`package build ${label} mutated reviewed source bytes: ${relative}`);
      }
    }
    return buildPackageDir;
  }

  function stageCanonicalPackage(builtPackageDir: string, label: string): string {
    const inventory: any = runPack([builtPackageDir, '--dry-run'], `${label} inventory`, builtPackageDir);
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
    const report: any = runPack([packageInput, '--pack-destination', destination], label, packageInput);
    const bytes: Buffer = canonicalizeNpmTarball(
      fs.readFileSync(path.join(destination, report.filename)),
    );
    const identity = validatePackedPackageIdentity(
      bytes,
      metadata.name,
      metadata.version,
      packageJsonBytes,
    );
    const members: PackedMember[] = inspectPackedPackageMembers(bytes);
    return {
      bytes,
      filename: report.filename,
      members,
      sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
      packageJsonSha256: identity.packageJsonSha256,
    };
  }

  try {
    const first: any = pack(stageCanonicalPackage(buildPackage('first'), 'first'), 'first');
    const second: any = pack(stageCanonicalPackage(buildPackage('second'), 'second'), 'second');
    if (first.filename !== second.filename) throw new Error('pack filenames differ');
    if (JSON.stringify(first.members) !== JSON.stringify(second.members)) throw new Error('package member manifests differ');
    if (!first.bytes.equals(second.bytes)) {
      throw new Error(`package bytes differ: ${first.sha256} != ${second.sha256}`);
    }
    let artifactPath: string | null = null;
    if (outDir) {
      const destination: string = path.resolve(root, outDir);
      fs.mkdirSync(destination, { recursive: true });
      artifactPath = path.join(destination, first.filename);
      fs.writeFileSync(artifactPath, first.bytes);
    }
    const recipe: any = {
      '@version': 'EP-NPM-PACK-RECIPE-v2',
      source_materialization: 'git-object-exact-commit',
      dependency_install: 'npm-ci-lockfile-ignore-scripts',
      build_command: typeof metadata.scripts?.build === 'string' ? 'npm-run-build-ignore-lifecycle' : 'none',
      build_script: typeof metadata.scripts?.build === 'string' ? metadata.scripts.build : null,
      pack_command: 'npm-pack-ignore-scripts',
      canonical_gzip: 'pako-3-level-9-mtime-0-os-255',
      node: process.versions.node,
      npm: String(run(npm, ['--version'], 'npm version lookup').stdout).trim(),
    };
    const recipeSha256: string = crypto.createHash('sha256')
      .update(JSON.stringify(recipe))
      .digest('hex');
    const releaseRegistryPath: string = path.join(snapshotRoot, 'release/release-packages.v1.json');
    let dependencyEvidence: any = null;
    let releaseRegistrySha256: string | null = null;
    if (fs.existsSync(releaseRegistryPath)) {
      const registryBytes: Buffer = fs.readFileSync(releaseRegistryPath);
      const registry: any = JSON.parse(registryBytes.toString('utf8'));
      const entries: any[] = registry.packages?.filter(
        (entry: any) => entry?.ecosystem === 'npm' && entry.package === metadata.name,
      );
      if (registry['@version'] !== 'EP-RELEASE-PACKAGE-REGISTRY-v1'
        || entries?.length !== 1
        || entries[0].path !== packageRelative) {
        throw new Error('release registry does not bind the reviewed npm package');
      }
      const fields: string[] = ['dependencies', 'optionalDependencies', 'peerDependencies'];
      const internalDependencies: any[] = fields.flatMap((field: string) =>
        Object.entries(metadata[field] ?? {})
          .filter(([name]: [string, any]) => name.startsWith('@emilia-protocol/'))
          .map(([name, range]: [string, any]) => ({ field, name, range, spec: `${name}@${range}` })))
        .sort((left: any, right: any) => `${left.field}:${left.spec}`.localeCompare(`${right.field}:${right.spec}`));
      releaseRegistrySha256 = crypto.createHash('sha256').update(registryBytes).digest('hex');
      dependencyEvidence = {
        internal_dependencies: internalDependencies,
        pins: [...(entries[0].registry_dependency_tarballs ?? [])]
          .sort((left: any, right: any) => left.spec.localeCompare(right.spec)),
      };
    }
    return {
      name: metadata.name,
      version: metadata.version,
      packagePath: packageRelative,
      filename: first.filename,
      sha256: first.sha256,
      bytes: first.bytes.length,
      fileCount: first.members.length,
      members: first.members,
      fileManifestSha256: crypto.createHash('sha256').update(JSON.stringify(first.members)).digest('hex'),
      packageJsonSha256: first.packageJsonSha256,
      source: {
        object_format: objectFormat,
        commit_sha: commit,
        tree_oid: treeOid,
        package_tree_oid: packageTreeOid,
        package_json_blob_oid: packageJsonBlobOid,
        archive_sha256: crypto.createHash('sha256').update(sourceArchiveBytes).digest('hex'),
        release_registry_sha256: releaseRegistrySha256,
      },
      recipe,
      recipeSha256,
      dependencyEvidence,
      ...(artifactPath ? { artifactPath } : {}),
    };
  } finally {
    const makeRemovable = (entry: string): void => {
      const stat: fs.Stats = fs.lstatSync(entry);
      if (stat.isDirectory() && !stat.isSymbolicLink()) {
        fs.chmodSync(entry, 0o700);
        for (const name of fs.readdirSync(entry)) makeRemovable(path.join(entry, name));
      } else if (!stat.isSymbolicLink()) {
        fs.chmodSync(entry, 0o600);
      }
    };
    if (fs.existsSync(scratch)) makeRemovable(scratch);
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const argv: string[] = process.argv.slice(2);
    let packagePath: string | null = null;
    let outDir: string | null = null;
    let emitPath: string | null = null;
    let reviewedCommit: string | null = null;
    for (let index = 0; index < argv.length; index += 1) {
      const value: string = argv[index];
      if (value === '--outdir' || value === '--emit' || value === '--commit') {
        const next: string | undefined = argv[index + 1];
        if (!next) throw new Error(`${value} requires a path`);
        if (value === '--outdir') outDir = next;
        else if (value === '--emit') emitPath = next;
        else reviewedCommit = next;
        index += 1;
      } else if (value.startsWith('--')) {
        throw new Error(`unknown option: ${value}`);
      } else if (packagePath === null) {
        packagePath = value;
      } else {
        throw new Error(`unexpected argument: ${value}`);
      }
    }
    const result: any = verifyReproduciblePackage(packagePath || 'packages/verify', { outDir, reviewedCommit });
    const manifest: any = {
      '@version': 'EP-REPRODUCIBLE-NPM-ARTIFACT-v2',
      package_path: result.packagePath,
      package: result.name,
      version: result.version,
      source: result.source,
      recipe: result.recipe,
      recipe_sha256: result.recipeSha256,
      dependency_evidence: result.dependencyEvidence,
      artifact: {
        filename: result.filename,
        sha256: result.sha256,
        bytes: result.bytes,
        files: result.fileCount,
        file_manifest_sha256: result.fileManifestSha256,
        package_json_sha256: result.packageJsonSha256,
        members: result.members,
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
