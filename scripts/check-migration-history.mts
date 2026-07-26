#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

interface MigrationHistory {
  schema_version: string;
  as_of: string;
  remote_head: string;
  private_remote_versions: string[];
  retroactive_pending_versions: string[];
  forward_pending_versions: string[];
  deployment_sequence: string[];
  requires_include_all: boolean;
  remote_versions: string[];
  public_files: Record<string, string>;
}

const ROOT: string = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const HISTORY_PATH: string = 'supabase/migration-history.v1.json';
const MIGRATION_DIR: string = 'supabase/migrations';
const ARCHIVE_DIR: string = 'supabase/migration-archive/2026-07-25-history-reconciliation';
const SHA256: RegExp = /^[a-f0-9]{64}$/;
const VERSIONED_SQL: RegExp = /^((?:[0-9]{3}|[0-9]{14}))_.+\.sql$/;
const ROLE_PASSWORD: RegExp =
  /\b(?:create|alter)\s+(?:role|user)\b[\s\S]*?\bpassword\s+('(?:[^']|'')*'|[^\s;']+)/gi;
const WALK_SKIP: ReadonlySet<string> = new Set([
  '.git',
  '.next',
  'coverage',
  'dist',
  'node_modules',
]);

function invariant(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function readJson<T>(absolutePath: string): T {
  return JSON.parse(fs.readFileSync(absolutePath, 'utf8')) as T;
}

function sha256(absolutePath: string): string {
  return crypto.createHash('sha256').update(fs.readFileSync(absolutePath)).digest('hex');
}

function unique(values: string[], label: string): void {
  invariant(new Set(values).size === values.length, `${label} contains duplicate versions`);
}

function sorted(values: string[], label: string): void {
  invariant(
    values.join('\0') === [...values].sort().join('\0'),
    `${label} must be lexicographically sorted`,
  );
}

function migrationVersion(filename: string): string {
  const match: RegExpMatchArray | null = filename.match(VERSIONED_SQL);
  invariant(match, `${filename} is not a version-prefixed SQL migration`);
  return match[1];
}

function validateIsoDate(value: string, label: string): void {
  const match: RegExpMatchArray | null = value.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  invariant(match, `${label} is not an ISO date`);
  const date: Date = new Date(`${value}T00:00:00.000Z`);
  invariant(
    !Number.isNaN(date.valueOf()) && date.toISOString().slice(0, 10) === value,
    `${label} is not a real calendar date`,
  );
}

function validateVersion(version: string, label: string): void {
  invariant(/^(?:\d{3}|\d{14})$/.test(version), `${label} has a noncanonical version ${version}`);
  if (version.length !== 14) return;
  const date: string = `${version.slice(0, 4)}-${version.slice(4, 6)}-${version.slice(6, 8)}`;
  validateIsoDate(date, `${label} version ${version}`);
  const hour: number = Number(version.slice(8, 10));
  const minute: number = Number(version.slice(10, 12));
  const second: number = Number(version.slice(12, 14));
  invariant(
    hour <= 23 && minute <= 59 && second <= 59,
    `${label} version ${version} has an invalid time`,
  );
}

function stripSqlComments(sql: string): string {
  return sql
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/--[^\r\n]*/g, ' ');
}

function containsPlaintextRolePassword(sql: string): boolean {
  ROLE_PASSWORD.lastIndex = 0;
  for (const match of sql.matchAll(ROLE_PASSWORD)) {
    if (match[1].toLowerCase() !== 'null') return true;
  }
  return false;
}

function assertRegularFile(absolutePath: string, label: string): void {
  const stat: fs.Stats = fs.lstatSync(absolutePath);
  invariant(!stat.isSymbolicLink() && stat.isFile(), `${label} must be a regular file, not a symlink`);
}

function validatePrivateVersionNonExposure(
  root: string,
  privateRemote: Set<string>,
): void {
  const visit = (directory: string): void => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (!WALK_SKIP.has(entry.name)) visit(path.join(directory, entry.name));
        continue;
      }
      if (!entry.isFile() || !entry.name.endsWith('.sql')) continue;
      const match: RegExpMatchArray | null = entry.name.match(VERSIONED_SQL);
      if (!match || !privateRemote.has(match[1])) continue;
      const relative: string = path.relative(root, path.join(directory, entry.name));
      invariant(
        false,
        `private remote version ${match[1]} appears in public repository path ${relative}`,
      );
    }
  };
  visit(root);
}

function validateArchive(root: string, privateRemote: Set<string>): void {
  const archive: string = path.resolve(root, ARCHIVE_DIR);
  const checksumPath: string = path.join(archive, 'SHA256SUMS');
  invariant(fs.existsSync(checksumPath), `${ARCHIVE_DIR}/SHA256SUMS is missing`);
  assertRegularFile(checksumPath, `${ARCHIVE_DIR}/SHA256SUMS`);

  const entries: Map<string, string> = new Map();
  for (const line of fs.readFileSync(checksumPath, 'utf8').split(/\r?\n/)) {
    if (!line) continue;
    const match: RegExpMatchArray | null = line.match(/^([a-f0-9]{64}) {2}(.+)$/);
    invariant(match, `${ARCHIVE_DIR}/SHA256SUMS has a malformed entry`);
    invariant(!entries.has(match[2]), `${ARCHIVE_DIR}/SHA256SUMS repeats ${match[2]}`);
    entries.set(match[2], match[1]);
  }

  const archiveFiles: string[] = fs.readdirSync(archive).sort();
  for (const filename of archiveFiles) {
    invariant(
      filename === 'README.md' || filename === 'SHA256SUMS' || filename.endsWith('.sql'),
      `${ARCHIVE_DIR}/${filename} is not an allowed archive artifact`,
    );
    assertRegularFile(path.join(archive, filename), `${ARCHIVE_DIR}/${filename}`);
  }
  const archivedSql: string[] = archiveFiles.filter((filename: string) => filename.endsWith('.sql'));
  invariant(
    archivedSql.join('\0') === [...entries.keys()].sort().join('\0'),
    `${ARCHIVE_DIR}/SHA256SUMS must cover every archived SQL file exactly once`,
  );
  for (const filename of archivedSql) {
    const version: string = migrationVersion(filename);
    invariant(
      !privateRemote.has(version),
      `${ARCHIVE_DIR}/${filename} exposes private remote version ${version}`,
    );
    invariant(
      sha256(path.join(archive, filename)) === entries.get(filename),
      `${ARCHIVE_DIR}/${filename} does not match SHA256SUMS`,
    );
  }
}

export function validateMigrationHistory(root: string = ROOT): {
  publicFiles: number;
  remoteVersions: number;
  pendingVersions: number;
  privateRemoteVersions: number;
} {
  const historyPath: string = path.resolve(root, HISTORY_PATH);
  const migrationDir: string = path.resolve(root, MIGRATION_DIR);
  const history: MigrationHistory = readJson<MigrationHistory>(historyPath);

  invariant(history.schema_version === 'EP-MIGRATION-HISTORY-v1', 'migration history schema is not EP-MIGRATION-HISTORY-v1');
  validateIsoDate(history.as_of, 'migration history as_of');
  invariant(Array.isArray(history.remote_versions), 'remote_versions must be an array');
  invariant(Array.isArray(history.retroactive_pending_versions), 'retroactive_pending_versions must be an array');
  invariant(Array.isArray(history.forward_pending_versions), 'forward_pending_versions must be an array');
  invariant(Array.isArray(history.deployment_sequence), 'deployment_sequence must be an array');
  invariant(
    history.requires_include_all === (history.retroactive_pending_versions.length > 0),
    'requires_include_all must be true exactly while retroactive migrations are pending',
  );
  invariant(Array.isArray(history.private_remote_versions), 'private_remote_versions must be an array');
  invariant(history.public_files && typeof history.public_files === 'object', 'public_files must be an object');

  const pendingVersions: string[] = [
    ...history.retroactive_pending_versions,
    ...history.forward_pending_versions,
  ];
  unique(history.remote_versions, 'remote_versions');
  unique(history.retroactive_pending_versions, 'retroactive_pending_versions');
  unique(history.forward_pending_versions, 'forward_pending_versions');
  unique(pendingVersions, 'all pending versions');
  unique(history.deployment_sequence, 'deployment_sequence');
  unique(history.private_remote_versions, 'private_remote_versions');
  sorted(history.remote_versions, 'remote_versions');
  sorted(history.retroactive_pending_versions, 'retroactive_pending_versions');
  sorted(history.forward_pending_versions, 'forward_pending_versions');
  sorted(history.private_remote_versions, 'private_remote_versions');
  for (const version of [
    ...history.remote_versions,
    ...pendingVersions,
    ...history.deployment_sequence,
    ...history.private_remote_versions,
  ]) {
    validateVersion(version, 'migration history');
  }
  invariant(
    history.remote_head === history.remote_versions.at(-1),
    'remote_head must equal the last journaled remote version',
  );

  const remote: Set<string> = new Set(history.remote_versions);
  const pending: Set<string> = new Set(pendingVersions);
  const privateRemote: Set<string> = new Set(history.private_remote_versions);
  for (const version of privateRemote) {
    invariant(remote.has(version), `private remote version ${version} is not journaled remotely`);
  }
  for (const version of pending) {
    invariant(!remote.has(version), `pending version ${version} is already journaled remotely`);
  }
  for (const version of history.retroactive_pending_versions) {
    invariant(version < history.remote_head, `retroactive pending version ${version} must precede remote_head`);
  }
  for (const version of history.forward_pending_versions) {
    invariant(version > history.remote_head, `forward pending version ${version} must follow remote_head`);
  }
  invariant(
    history.deployment_sequence.join('\0') === [...pendingVersions].sort().join('\0'),
    'deployment_sequence must list every pending version exactly once in execution order',
  );

  const actualFiles: string[] = fs.readdirSync(migrationDir)
    .filter((filename: string) => filename.endsWith('.sql'))
    .sort();
  for (const filename of actualFiles) {
    assertRegularFile(path.join(migrationDir, filename), `${MIGRATION_DIR}/${filename}`);
  }
  const declaredFiles: string[] = Object.keys(history.public_files).sort();
  invariant(
    actualFiles.join('\0') === declaredFiles.join('\0'),
    'public_files must cover every executable SQL migration exactly once',
  );

  const publicVersions: string[] = actualFiles.map(migrationVersion);
  unique(publicVersions, 'executable migration versions');
  for (const version of privateRemote) {
    invariant(
      !actualFiles.some((filename: string) => migrationVersion(filename) === version),
      `private remote version ${version} must not exist in the public executable migration tree`,
    );
  }
  const expectedPublicVersions: string[] = [
    ...history.remote_versions.filter((version: string) => !privateRemote.has(version)),
    ...pendingVersions,
  ].sort();
  invariant(
    [...publicVersions].sort().join('\0') === expectedPublicVersions.join('\0'),
    'executable migration versions must equal public remote history plus declared pending versions',
  );

  for (const filename of actualFiles) {
    const expectedHash: string = history.public_files[filename];
    invariant(SHA256.test(expectedHash), `${filename} has a malformed SHA-256 pin`);
    const absolutePath: string = path.join(migrationDir, filename);
    invariant(sha256(absolutePath) === expectedHash, `${filename} does not match its SHA-256 pin`);
    const sql: string = stripSqlComments(fs.readFileSync(absolutePath, 'utf8'));
    invariant(
      !containsPlaintextRolePassword(sql),
      `${filename} contains a plaintext role password and belongs in private deployment history`,
    );
  }

  validateArchive(root, privateRemote);
  validatePrivateVersionNonExposure(root, privateRemote);
  return {
    publicFiles: actualFiles.length,
    remoteVersions: remote.size,
    pendingVersions: pending.size,
    privateRemoteVersions: privateRemote.size,
  };
}

function main(): void {
  const result = validateMigrationHistory();
  console.log(
    `Migration history: ${result.remoteVersions} remote, `
    + `${result.privateRemoteVersions} private, ${result.pendingVersions} pending, `
    + `${result.publicFiles} public SQL files; hashes and archive verified.`,
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main();
}
