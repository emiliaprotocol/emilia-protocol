#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Trusted, secret-free reconciliation of a pull-request migration candidate.
// The live schema check deliberately executes only trusted base-branch code.
// This companion check treats the candidate checkout as data and proves that
// it preserves every base migration byte-for-byte while classifying every new
// migration in the governed migration-history ledger.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const VERSION_RE = /^(?:[0-9]{3}|[0-9]{14})$/;
const FILE_RE = /^(?:[0-9]{3}|[0-9]{14})_[a-z0-9][a-z0-9_]*\.sql$/;
const HASH_RE = /^[0-9a-f]{64}$/;

function fail(message) {
  console.error(`candidate reconciliation refused: ${message}`);
  process.exit(1);
}

function parseArguments() {
  const result = {};
  for (let position = 2; position < process.argv.length; position += 2) {
    const name = process.argv[position];
    const value = process.argv[position + 1];
    if (!['--base-root', '--candidate-root'].includes(name) || value === undefined) {
      fail('usage: --base-root PATH --candidate-root PATH');
    }
    result[name.slice(2)] = path.resolve(value);
  }
  if (!result['base-root'] || !result['candidate-root']) {
    fail('both --base-root and --candidate-root are required');
  }
  if (result['base-root'] === result['candidate-root']) {
    fail('base and candidate roots must be distinct checkouts');
  }
  return result;
}

function regularFiles(root) {
  const directory = path.join(root, 'supabase', 'migrations');
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail(`migration directory is unsafe: ${directory}`);
  const result = new Map();
  for (const name of fs.readdirSync(directory).sort()) {
    if (!name.endsWith('.sql')) continue;
    if (!FILE_RE.test(name)) fail(`noncanonical migration filename: ${name}`);
    const file = path.join(directory, name);
    const metadata = fs.lstatSync(file);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1) {
      fail(`migration must be one regular non-symlink file: ${name}`);
    }
    if (metadata.size > 16 * 1024 * 1024) fail(`migration is unexpectedly large: ${name}`);
    result.set(name, fs.readFileSync(file));
  }
  if (result.size === 0) fail(`no migrations found in ${root}`);
  return result;
}

function sha256(raw) {
  return crypto.createHash('sha256').update(raw).digest('hex');
}

function versionOf(filename) {
  const version = filename.slice(0, filename.indexOf('_'));
  if (!VERSION_RE.test(version)) fail(`invalid migration version: ${filename}`);
  return version;
}

function readLedger(root) {
  const file = path.join(root, 'supabase', 'migration-history.v1.json');
  const metadata = fs.lstatSync(file);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1) {
    fail('candidate migration ledger must be one regular non-symlink file');
  }
  let ledger;
  try {
    ledger = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    fail(`candidate migration ledger is invalid JSON: ${error.message}`);
  }
  if (ledger.schema_version !== 'EP-MIGRATION-HISTORY-v1') {
    fail('candidate migration ledger version is invalid');
  }
  const retroactive = ledger.retroactive_pending_versions;
  const forward = ledger.forward_pending_versions;
  const sequence = ledger.deployment_sequence;
  const publicFiles = ledger.public_files;
  if (![retroactive, forward, sequence].every(Array.isArray)
      || !publicFiles || typeof publicFiles !== 'object' || Array.isArray(publicFiles)) {
    fail('candidate migration ledger is missing pending classifications or public hashes');
  }
  const pending = [...retroactive, ...forward];
  if (pending.some((value) => typeof value !== 'string' || !VERSION_RE.test(value))
      || new Set(pending).size !== pending.length) {
    fail('candidate pending migration classification is invalid or duplicated');
  }
  if (sequence.length !== pending.length
      || sequence.some((value, index) => value !== pending[index])) {
    fail('candidate deployment sequence must equal retroactive then forward pending versions');
  }
  return { pending: new Set(pending), publicFiles };
}

const argumentsMap = parseArguments();
const baseFiles = regularFiles(argumentsMap['base-root']);
const candidateFiles = regularFiles(argumentsMap['candidate-root']);

for (const [name, bytes] of baseFiles) {
  const candidate = candidateFiles.get(name);
  if (candidate === undefined) fail(`candidate deletes base migration: ${name}`);
  if (sha256(bytes) !== sha256(candidate)) {
    fail(`candidate rewrites base migration: ${name}`);
  }
}

const added = [...candidateFiles.keys()].filter((name) => !baseFiles.has(name));
const ledger = readLedger(argumentsMap['candidate-root']);
for (const name of added) {
  const version = versionOf(name);
  if (!ledger.pending.has(version)) fail(`new migration is not classified as pending: ${name}`);
  const expectedHash = ledger.publicFiles[name];
  if (typeof expectedHash !== 'string' || !HASH_RE.test(expectedHash)) {
    fail(`new migration lacks a canonical ledger hash: ${name}`);
  }
  if (sha256(candidateFiles.get(name)) !== expectedHash) {
    fail(`new migration bytes do not match the candidate ledger: ${name}`);
  }
}

for (const name of candidateFiles.keys()) {
  const expectedHash = ledger.publicFiles[name];
  if (typeof expectedHash !== 'string' || !HASH_RE.test(expectedHash)) {
    fail(`candidate migration is absent from the public ledger: ${name}`);
  }
  if (sha256(candidateFiles.get(name)) !== expectedHash) {
    fail(`candidate migration bytes differ from the public ledger: ${name}`);
  }
}

console.log(`PR candidate reconciled: ${baseFiles.size} immutable base migrations, ${added.length} classified additions`);
