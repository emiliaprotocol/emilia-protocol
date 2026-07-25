#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from check-migration-history.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const HISTORY_PATH = 'supabase/migration-history.v1.json';
const MIGRATION_DIR = 'supabase/migrations';
const ARCHIVE_DIR = 'supabase/migration-archive/2026-07-25-history-reconciliation';
const SHA256 = /^[a-f0-9]{64}$/;
const VERSIONED_SQL = /^((?:[0-9]{3}|[0-9]{14}))_.+\.sql$/;
const ROLE_PASSWORD = /\b(?:create|alter)\s+(?:role|user)\b[\s\S]{0,500}?\bpassword\s+('(?:[^']|'')*'|[^\s;']+)/gi;
function invariant(condition, message) {
    if (!condition)
        throw new Error(message);
}
function readJson(absolutePath) {
    return JSON.parse(fs.readFileSync(absolutePath, 'utf8'));
}
function sha256(absolutePath) {
    return crypto.createHash('sha256').update(fs.readFileSync(absolutePath)).digest('hex');
}
function unique(values, label) {
    invariant(new Set(values).size === values.length, `${label} contains duplicate versions`);
}
function sorted(values, label) {
    invariant(values.join('\0') === [...values].sort().join('\0'), `${label} must be lexicographically sorted`);
}
function migrationVersion(filename) {
    const match = filename.match(VERSIONED_SQL);
    invariant(match, `${filename} is not a version-prefixed SQL migration`);
    return match[1];
}
function validateIsoDate(value, label) {
    const match = value.match(/^(\d{4})-(\d{2})-(\d{2})$/);
    invariant(match, `${label} is not an ISO date`);
    const date = new Date(`${value}T00:00:00.000Z`);
    invariant(!Number.isNaN(date.valueOf()) && date.toISOString().slice(0, 10) === value, `${label} is not a real calendar date`);
}
function validateVersion(version, label) {
    invariant(/^(?:\d{3}|\d{14})$/.test(version), `${label} has a noncanonical version ${version}`);
    if (version.length !== 14)
        return;
    const date = `${version.slice(0, 4)}-${version.slice(4, 6)}-${version.slice(6, 8)}`;
    validateIsoDate(date, `${label} version ${version}`);
    const hour = Number(version.slice(8, 10));
    const minute = Number(version.slice(10, 12));
    const second = Number(version.slice(12, 14));
    invariant(hour <= 23 && minute <= 59 && second <= 59, `${label} version ${version} has an invalid time`);
}
function stripSqlComments(sql) {
    return sql
        .replace(/\/\*[\s\S]*?\*\//g, ' ')
        .replace(/--[^\r\n]*/g, ' ');
}
function containsPlaintextRolePassword(sql) {
    ROLE_PASSWORD.lastIndex = 0;
    for (const match of sql.matchAll(ROLE_PASSWORD)) {
        if (match[1].toLowerCase() !== 'null')
            return true;
    }
    return false;
}
function assertRegularFile(absolutePath, label) {
    const stat = fs.lstatSync(absolutePath);
    invariant(!stat.isSymbolicLink() && stat.isFile(), `${label} must be a regular file, not a symlink`);
}
function validateArchive(root, privateRemote) {
    const archive = path.resolve(root, ARCHIVE_DIR);
    const checksumPath = path.join(archive, 'SHA256SUMS');
    invariant(fs.existsSync(checksumPath), `${ARCHIVE_DIR}/SHA256SUMS is missing`);
    assertRegularFile(checksumPath, `${ARCHIVE_DIR}/SHA256SUMS`);
    const entries = new Map();
    for (const line of fs.readFileSync(checksumPath, 'utf8').split(/\r?\n/)) {
        if (!line)
            continue;
        const match = line.match(/^([a-f0-9]{64}) {2}(.+)$/);
        invariant(match, `${ARCHIVE_DIR}/SHA256SUMS has a malformed entry`);
        invariant(!entries.has(match[2]), `${ARCHIVE_DIR}/SHA256SUMS repeats ${match[2]}`);
        entries.set(match[2], match[1]);
    }
    const archiveFiles = fs.readdirSync(archive).sort();
    for (const filename of archiveFiles) {
        invariant(filename === 'README.md' || filename === 'SHA256SUMS' || filename.endsWith('.sql'), `${ARCHIVE_DIR}/${filename} is not an allowed archive artifact`);
        assertRegularFile(path.join(archive, filename), `${ARCHIVE_DIR}/${filename}`);
    }
    const archivedSql = archiveFiles.filter((filename) => filename.endsWith('.sql'));
    invariant(archivedSql.join('\0') === [...entries.keys()].sort().join('\0'), `${ARCHIVE_DIR}/SHA256SUMS must cover every archived SQL file exactly once`);
    for (const filename of archivedSql) {
        const version = migrationVersion(filename);
        invariant(!privateRemote.has(version), `${ARCHIVE_DIR}/${filename} exposes private remote version ${version}`);
        invariant(sha256(path.join(archive, filename)) === entries.get(filename), `${ARCHIVE_DIR}/${filename} does not match SHA256SUMS`);
    }
}
export function validateMigrationHistory(root = ROOT) {
    const historyPath = path.resolve(root, HISTORY_PATH);
    const migrationDir = path.resolve(root, MIGRATION_DIR);
    const history = readJson(historyPath);
    invariant(history.schema_version === 'EP-MIGRATION-HISTORY-v1', 'migration history schema is not EP-MIGRATION-HISTORY-v1');
    validateIsoDate(history.as_of, 'migration history as_of');
    invariant(Array.isArray(history.remote_versions), 'remote_versions must be an array');
    invariant(Array.isArray(history.retroactive_pending_versions), 'retroactive_pending_versions must be an array');
    invariant(Array.isArray(history.forward_pending_versions), 'forward_pending_versions must be an array');
    invariant(Array.isArray(history.deployment_sequence), 'deployment_sequence must be an array');
    invariant(history.requires_include_all === true, 'requires_include_all must be true while retroactive migrations are pending');
    invariant(Array.isArray(history.private_remote_versions), 'private_remote_versions must be an array');
    invariant(history.public_files && typeof history.public_files === 'object', 'public_files must be an object');
    const pendingVersions = [
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
    invariant(history.remote_head === history.remote_versions.at(-1), 'remote_head must equal the last journaled remote version');
    const remote = new Set(history.remote_versions);
    const pending = new Set(pendingVersions);
    const privateRemote = new Set(history.private_remote_versions);
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
    invariant(history.deployment_sequence.join('\0') === [...pendingVersions].sort().join('\0'), 'deployment_sequence must list every pending version exactly once in execution order');
    const actualFiles = fs.readdirSync(migrationDir)
        .filter((filename) => filename.endsWith('.sql'))
        .sort();
    for (const filename of actualFiles) {
        assertRegularFile(path.join(migrationDir, filename), `${MIGRATION_DIR}/${filename}`);
    }
    const declaredFiles = Object.keys(history.public_files).sort();
    invariant(actualFiles.join('\0') === declaredFiles.join('\0'), 'public_files must cover every executable SQL migration exactly once');
    const publicVersions = actualFiles.map(migrationVersion);
    unique(publicVersions, 'executable migration versions');
    for (const version of privateRemote) {
        invariant(!actualFiles.some((filename) => migrationVersion(filename) === version), `private remote version ${version} must not exist in the public executable migration tree`);
    }
    const expectedPublicVersions = [
        ...history.remote_versions.filter((version) => !privateRemote.has(version)),
        ...pendingVersions,
    ].sort();
    invariant([...publicVersions].sort().join('\0') === expectedPublicVersions.join('\0'), 'executable migration versions must equal public remote history plus declared pending versions');
    for (const filename of actualFiles) {
        const expectedHash = history.public_files[filename];
        invariant(SHA256.test(expectedHash), `${filename} has a malformed SHA-256 pin`);
        const absolutePath = path.join(migrationDir, filename);
        invariant(sha256(absolutePath) === expectedHash, `${filename} does not match its SHA-256 pin`);
        const sql = stripSqlComments(fs.readFileSync(absolutePath, 'utf8'));
        invariant(!containsPlaintextRolePassword(sql), `${filename} contains a plaintext role password and belongs in private deployment history`);
    }
    validateArchive(root, privateRemote);
    return {
        publicFiles: actualFiles.length,
        remoteVersions: remote.size,
        pendingVersions: pending.size,
        privateRemoteVersions: privateRemote.size,
    };
}
function main() {
    const result = validateMigrationHistory();
    console.log(`Migration history: ${result.remoteVersions} remote, `
        + `${result.privateRemoteVersions} private, ${result.pendingVersions} pending, `
        + `${result.publicFiles} public SQL files; hashes and archive verified.`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
    main();
}
