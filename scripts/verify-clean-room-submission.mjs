#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../packages/verify/index.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BUNDLE_PATH = path.join(ROOT, 'conformance/clean-room/bundle.v1.json');
const argv = process.argv.slice(2);

function option(name) {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : null;
}

const separator = argv.indexOf('--');
const manifestPath = option('--manifest');
const emitPath = option('--emit');
const trustedPath = option('--trusted-attestors');
const command = separator >= 0 ? argv[separator + 1] : null;
const commandArgs = separator >= 0 ? argv.slice(separator + 2) : [];
if (!manifestPath || !command) {
  console.error('usage: verify-clean-room-submission --manifest FILE [--trusted-attestors FILE] [--emit FILE] -- EXECUTABLE [ARGS...]');
  process.exit(2);
}

function readJson(file, label) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (error) { throw new Error(`${label} is not valid JSON: ${error.message}`); }
}

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function b64url(value) {
  return Buffer.from(value, 'base64url');
}

function validateManifest(manifest) {
  const problems = [];
  if (manifest?.['@version'] !== 'EP-CLEAN-ROOM-SUBMISSION-v1') problems.push('unexpected @version');
  const impl = manifest?.implementation;
  for (const field of ['implementation_id', 'organization', 'language', 'version', 'source_repository', 'source_commit', 'license_spdx']) {
    if (typeof impl?.[field] !== 'string' || impl[field].trim() === '') problems.push(`implementation.${field} is required`);
  }
  const independence = manifest?.independence;
  if (typeof independence?.claimed !== 'boolean') problems.push('independence.claimed must be boolean');
  if (!Array.isArray(independence?.authors) || independence.authors.length === 0) problems.push('independence.authors is required');
  if (!Array.isArray(independence?.specification_inputs) || independence.specification_inputs.length === 0) problems.push('independence.specification_inputs is required');
  if (!['none', 'reference_port'].includes(independence?.reference_source_access)) problems.push('independence.reference_source_access is invalid');
  if (independence?.claimed && independence.reference_source_access !== 'none') problems.push('a clean-room claim requires reference_source_access:none');
  if (independence?.claimed && (typeof independence.statement !== 'string' || independence.statement.length < 20)) problems.push('a clean-room claim requires a substantive statement');
  if (problems.length) throw new Error(`manifest refused: ${problems.join('; ')}`);
}

function verifyAttestation(manifest, trusted) {
  if (!manifest.attestation) return { status: manifest.independence.claimed ? 'self_attested_unverified' : 'not_claimed' };
  const pin = trusted?.keys?.find((key) => key.key_id === manifest.attestation.key_id);
  if (!pin) return { status: 'attestor_unpinned', key_id: manifest.attestation.key_id };
  if (manifest.attestation.algorithm !== 'Ed25519') return { status: 'invalid_attestation', reason: 'algorithm' };
  const unsigned = { ...manifest };
  delete unsigned.attestation;
  try {
    const key = crypto.createPublicKey({
      key: b64url(pin.public_key_spki_base64url),
      format: 'der',
      type: 'spki',
    });
    const valid = crypto.verify(null, Buffer.from(canonicalize(unsigned), 'utf8'), key, b64url(manifest.attestation.signature_base64url));
    return valid
      ? { status: 'third_party_attested', key_id: pin.key_id, organization: pin.organization }
      : { status: 'invalid_attestation', key_id: pin.key_id };
  } catch (error) {
    return { status: 'invalid_attestation', reason: error.message };
  }
}

const manifestAbsolute = path.resolve(manifestPath);
const manifest = readJson(manifestAbsolute, 'manifest');
validateManifest(manifest);
const bundle = readJson(BUNDLE_PATH, 'bundle');
if (bundle['@version'] !== 'EP-CLEAN-ROOM-VECTOR-BUNDLE-v1') throw new Error('unsupported vector bundle');
const trusted = trustedPath ? readJson(path.resolve(trustedPath), 'trusted attestors') : null;
const attestation = verifyAttestation(manifest, trusted);
if (manifest.independence.claimed && attestation.status === 'invalid_attestation') throw new Error('clean-room attestation signature is invalid');

const suiteResults = [];
let vectorCount = 0;
for (const suiteRef of bundle.suites) {
  const suitePath = path.resolve(ROOT, suiteRef.path);
  const suiteBytes = fs.readFileSync(suitePath);
  const actualHash = sha256(suiteBytes);
  if (actualHash !== suiteRef.sha256) throw new Error(`vector bundle drift: ${suiteRef.path}`);
  const suite = JSON.parse(suiteBytes);
  let output;
  try {
    output = execFileSync(command, [...commandArgs, suitePath], {
      cwd: ROOT,
      encoding: 'utf8',
      maxBuffer: 32 * 1024 * 1024,
      timeout: 120_000,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error) {
    throw new Error(`runner failed for ${suiteRef.path}: ${error.stderr || error.message}`);
  }
  let results;
  try { results = JSON.parse(output); } catch (error) { throw new Error(`runner emitted invalid JSON for ${suiteRef.path}: ${error.message}`); }
  if (!Array.isArray(results)) throw new Error(`runner output is not an array for ${suiteRef.path}`);
  const expected = new Map(suite.vectors.map((vector) => [vector.id, vector.expect.valid]));
  const seen = new Set();
  const failures = [];
  for (const result of results) {
    if (!result || typeof result.id !== 'string' || typeof result.valid !== 'boolean') throw new Error(`malformed runner result in ${suiteRef.path}`);
    if (seen.has(result.id)) throw new Error(`duplicate runner result ${result.id} in ${suiteRef.path}`);
    seen.add(result.id);
    if (!expected.has(result.id)) throw new Error(`runner added unknown vector ${result.id} in ${suiteRef.path}`);
    if (result.valid !== expected.get(result.id)) failures.push({ id: result.id, expected: expected.get(result.id), actual: result.valid });
  }
  for (const id of expected.keys()) if (!seen.has(id)) throw new Error(`runner omitted vector ${id} in ${suiteRef.path}`);
  if (failures.length) throw new Error(`conformance failures in ${suiteRef.path}: ${JSON.stringify(failures)}`);
  vectorCount += expected.size;
  suiteResults.push({ path: suiteRef.path, sha256: actualHash, vectors: expected.size, status: 'pass' });
}

const unsignedManifest = { ...manifest };
delete unsignedManifest.attestation;
const report = {
  '@version': 'EP-CLEAN-ROOM-EVALUATION-v1',
  implementation: manifest.implementation,
  conformance: { status: 'pass', bundle: bundle['@version'], suites: suiteResults.length, vectors: vectorCount },
  independence: {
    claimed: manifest.independence.claimed,
    status: manifest.independence.claimed ? attestation.status : 'not_claimed_reference_port',
    attestation,
  },
  manifest_sha256: sha256(Buffer.from(canonicalize(unsignedManifest), 'utf8')),
  suites: suiteResults,
};
report.result_sha256 = sha256(Buffer.from(canonicalize(report), 'utf8'));

if (emitPath) {
  const target = path.resolve(emitPath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, `${JSON.stringify(report, null, 2)}\n`);
}
console.log(`CLEAN-ROOM INTAKE: PASS (${suiteResults.length} suites, ${vectorCount} vectors; independence=${report.independence.status}; sha256:${report.result_sha256})`);
