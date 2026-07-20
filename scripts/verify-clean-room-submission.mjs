#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../packages/verify/index.js';
import { strictParseGate } from '../conformance/runners/strict-json.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BUNDLE_PATH = path.join(ROOT, 'conformance/clean-room/bundle.v1.json');
const SPECIFICATION_BUNDLE_PATH = path.join(ROOT, 'conformance/clean-room/specification-bundle.v1.json');
const FROZEN_ROOT = path.join(ROOT, 'conformance/clean-room/frozen-v1');
const argv = process.argv.slice(2);

function option(name) {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : null;
}

const separator = argv.indexOf('--');
const manifestPath = option('--manifest');
const emitPath = option('--emit');
const trustedPath = option('--trusted-attestors');
const requireExternal = argv.includes('--require-external');
const command = separator >= 0 ? argv[separator + 1] : null;
const commandArgs = separator >= 0 ? argv.slice(separator + 2) : [];
if (!manifestPath || !command) {
  console.error('usage: verify-clean-room-submission [--require-external] --manifest FILE [--trusted-attestors FILE] [--emit FILE] -- EXECUTABLE [ARGS...]');
  process.exit(2);
}

function readJson(file, label) {
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(fs.readFileSync(file));
    const value = JSON.parse(text);
    const gate = strictParseGate(text);
    if (!gate.ok) throw new Error(gate.reason);
    return value;
  }
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
  const exact = (value, allowed, label) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      problems.push(`${label} must be an object`);
      return;
    }
    for (const key of Object.keys(value)) if (!allowed.includes(key)) problems.push(`${label}.${key} is not allowed`);
  };
  exact(manifest, ['@version', 'implementation', 'runner', 'independence', 'attestation'], 'manifest');
  if (manifest?.['@version'] !== 'EP-CLEAN-ROOM-SUBMISSION-v1') problems.push('unexpected @version');
  const impl = manifest?.implementation;
  exact(impl, ['implementation_id', 'organization', 'language', 'version', 'source_repository', 'source_commit', 'license_spdx', 'build_instructions', 'dependencies'], 'implementation');
  for (const field of ['implementation_id', 'organization', 'language', 'version', 'source_repository', 'source_commit', 'license_spdx', 'build_instructions']) {
    if (typeof impl?.[field] !== 'string' || impl[field].trim() === '') problems.push(`implementation.${field} is required`);
  }
  if (!Array.isArray(impl?.dependencies) || impl.dependencies.some((value) => typeof value !== 'string' || value.trim() === '')) {
    problems.push('implementation.dependencies must be an array of non-empty strings');
  }
  const independence = manifest?.independence;
  exact(independence, ['claimed', 'authors', 'specification_inputs', 'specification_bundle_sha256', 'reference_source_access', 'emilia_affiliation', 'statement'], 'independence');
  if (typeof independence?.claimed !== 'boolean') problems.push('independence.claimed must be boolean');
  if (!Array.isArray(independence?.authors) || independence.authors.length === 0) problems.push('independence.authors is required');
  else if (independence.authors.some((value) => typeof value !== 'string' || value.trim() === '')) problems.push('independence.authors must contain non-empty strings');
  if (!Array.isArray(independence?.specification_inputs) || independence.specification_inputs.length === 0) problems.push('independence.specification_inputs is required');
  else if (independence.specification_inputs.some((value) => typeof value !== 'string' || value.trim() === '')) problems.push('independence.specification_inputs must contain non-empty strings');
  if (!/^[0-9a-f]{64}$/.test(independence?.specification_bundle_sha256 || '')) problems.push('independence.specification_bundle_sha256 is invalid');
  if (!['none', 'reference_port'].includes(independence?.reference_source_access)) problems.push('independence.reference_source_access is invalid');
  if (!['none', 'maintainer', 'contractor'].includes(independence?.emilia_affiliation)) problems.push('independence.emilia_affiliation is invalid');
  if (independence?.claimed && independence.reference_source_access !== 'none') problems.push('a clean-room claim requires reference_source_access:none');
  if (independence?.claimed && (typeof independence.statement !== 'string' || independence.statement.length < 20)) problems.push('a clean-room claim requires a substantive statement');
  const runner = manifest?.runner;
  exact(runner, ['protocol', 'artifact_argument_index', 'artifact_sha256', 'fixed_arguments'], 'runner');
  if (runner?.protocol !== 'EP-CONFORMANCE-FILE-RUNNER-v1') problems.push('runner.protocol is invalid');
  if (!Number.isInteger(runner?.artifact_argument_index) || runner.artifact_argument_index < -1) problems.push('runner.artifact_argument_index is invalid');
  if (!/^[0-9a-f]{64}$/.test(runner?.artifact_sha256 || '')) problems.push('runner.artifact_sha256 is invalid');
  if (!Array.isArray(runner?.fixed_arguments) || runner.fixed_arguments.some((value) => typeof value !== 'string')) problems.push('runner.fixed_arguments is invalid');
  if (manifest?.attestation && !['independent', 'implementation_organization', 'self'].includes(manifest.attestation.attestor_relationship)) {
    problems.push('attestation.attestor_relationship is invalid');
  }
  if (manifest?.attestation) exact(manifest.attestation, ['algorithm', 'key_id', 'attestor_relationship', 'signature_base64url'], 'attestation');
  if (problems.length) throw new Error(`manifest refused: ${problems.join('; ')}`);
}

function verifyRunnerBinding(manifest) {
  if (canonicalize(commandArgs) !== canonicalize(manifest.runner.fixed_arguments)) {
    throw new Error('runner binding refused: fixed arguments differ from the signed manifest');
  }
  const index = manifest.runner.artifact_argument_index;
  if (index >= commandArgs.length) throw new Error('runner binding refused: artifact_argument_index is out of range');
  // `command` is validated non-null at startup (line ~29: `if (!manifestPath || !command) { ...; process.exit(2); }`)
  // before this function is ever invoked (line ~164); the closure boundary just hides that from tsc.
  const executable = /** @type {string} */ (command);
  const candidate = index === -1 ? executable : commandArgs[index];
  const artifact = path.isAbsolute(candidate) ? candidate : path.resolve(ROOT, candidate);
  if (!fs.existsSync(artifact) || !fs.statSync(artifact).isFile()) {
    throw new Error('runner binding refused: signed runner artifact is not a file');
  }
  const actual = sha256(fs.readFileSync(artifact));
  if (actual !== manifest.runner.artifact_sha256) throw new Error('runner binding refused: executable artifact hash mismatch');
  return { path: artifact, sha256: actual };
}

function frozenMemberPath(memberPath, bundleLabel) {
  const resolved = path.resolve(FROZEN_ROOT, memberPath);
  if (!resolved.startsWith(`${FROZEN_ROOT}${path.sep}`)) {
    throw new Error(`${bundleLabel} member escapes frozen root`);
  }
  return resolved;
}

function verifyPinnedBundle(bundlePath, expectedVersion, memberField) {
  const bytes = fs.readFileSync(bundlePath);
  const bundle = readJson(bundlePath, expectedVersion);
  if (bundle['@version'] !== expectedVersion) throw new Error(`unsupported ${expectedVersion} bundle`);
  for (const member of bundle[memberField] || []) {
    if (typeof member?.path !== 'string' || !/^[0-9a-f]{64}$/.test(member.sha256 || '')) {
      throw new Error(`${expectedVersion} contains a malformed member`);
    }
    const memberPath = frozenMemberPath(member.path, expectedVersion);
    const memberBytes = fs.readFileSync(memberPath);
    if (sha256(memberBytes) !== member.sha256 || (member.bytes !== undefined && memberBytes.length !== member.bytes)) {
      throw new Error(`${expectedVersion} drift: ${member.path}`);
    }
  }
  return { bundle, sha256: sha256(bytes) };
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
    if (key.asymmetricKeyType !== 'ed25519') return { status: 'invalid_attestation', reason: 'key_type' };
    const valid = crypto.verify(null, Buffer.from(canonicalize(unsigned), 'utf8'), key, b64url(manifest.attestation.signature_base64url));
    return valid
      ? { status: 'third_party_attested', key_id: pin.key_id, organization: pin.organization, independent: pin.independent === true }
      : { status: 'invalid_attestation', key_id: pin.key_id };
  } catch (error) {
    return { status: 'invalid_attestation', reason: error.message };
  }
}

const manifestAbsolute = path.resolve(manifestPath);
const manifest = readJson(manifestAbsolute, 'manifest');
validateManifest(manifest);
const runnerBinding = verifyRunnerBinding(manifest);
const { bundle } = verifyPinnedBundle(BUNDLE_PATH, 'EP-CLEAN-ROOM-VECTOR-BUNDLE-v1', 'suites');
const specificationBundle = verifyPinnedBundle(
  SPECIFICATION_BUNDLE_PATH,
  'EP-CLEAN-ROOM-SPECIFICATION-BUNDLE-v1',
  'documents',
);
if (manifest.independence.specification_bundle_sha256 !== specificationBundle.sha256) {
  throw new Error('manifest refused: specification bundle hash does not match the evaluator input');
}
const trusted = trustedPath ? readJson(path.resolve(trustedPath), 'trusted attestors') : null;
const attestation = verifyAttestation(manifest, trusted);
if (manifest.independence.claimed && attestation.status === 'invalid_attestation') throw new Error('clean-room attestation signature is invalid');
if (requireExternal) {
  const problems = [];
  if (!manifest.independence.claimed) problems.push('independence must be claimed');
  if (manifest.independence.reference_source_access !== 'none') problems.push('reference source access must be none');
  if (manifest.independence.emilia_affiliation !== 'none') problems.push('EMILIA-affiliated implementations are not external');
  if (/emilia/i.test(manifest.implementation.organization)) problems.push('implementation organization is not external to EMILIA');
  if (!/^[0-9a-f]{40,64}$/.test(manifest.implementation.source_commit)) problems.push('source_commit must be an immutable 40-64 character hexadecimal commit');
  if (attestation.status !== 'third_party_attested' || attestation.independent !== true) problems.push('an independently pinned third-party attestation is required');
  if (manifest.attestation?.attestor_relationship !== 'independent') problems.push('attestor_relationship must be independent');
  if (String(attestation.organization || '').toLowerCase() === manifest.implementation.organization.toLowerCase()) {
    problems.push('attestor organization must differ from the implementation organization');
  }
  if (/emilia/i.test(String(attestation.organization || ''))) problems.push('EMILIA cannot attest external independence');
  const builtInRunnerHashes = [
    'conformance/runners/run-js.mjs',
    'conformance/runners/run_py.py',
    'packages/go-verify/cmd/conformance/main.go',
  ].map((file) => sha256(fs.readFileSync(path.join(ROOT, file))));
  if (builtInRunnerHashes.includes(runnerBinding.sha256)) problems.push('same-team reference runner cannot satisfy external acceptance');
  if (problems.length) throw new Error(`external clean-room acceptance refused: ${problems.join('; ')}`);
}

const suiteResults = [];
let vectorCount = 0;
for (const suiteRef of bundle.suites) {
  const suitePath = frozenMemberPath(suiteRef.path, 'vector bundle');
  const suiteBytes = fs.readFileSync(suitePath);
  const actualHash = sha256(suiteBytes);
  if (actualHash !== suiteRef.sha256) throw new Error(`vector bundle drift: ${suiteRef.path}`);
  const suiteText = new TextDecoder('utf-8', { fatal: true }).decode(suiteBytes);
  const suiteGate = strictParseGate(suiteText);
  if (!suiteGate.ok) throw new Error(`frozen vector JSON refused: ${suiteRef.path}: ${suiteGate.reason}`);
  const suite = JSON.parse(suiteText);
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
  try {
    const gate = strictParseGate(output);
    if (!gate.ok) throw new Error(gate.reason);
    results = JSON.parse(output);
  } catch (error) { throw new Error(`runner emitted invalid JSON for ${suiteRef.path}: ${error.message}`); }
  if (!Array.isArray(results)) throw new Error(`runner output is not an array for ${suiteRef.path}`);
  const expected = new Map(suite.vectors.map((vector) => [vector.id, vector.expect.valid]));
  const seen = new Set();
  const failures = [];
  for (const result of results) {
    if (!result || typeof result.id !== 'string' || typeof result.valid !== 'boolean'
      || Object.keys(result).some((key) => key !== 'id' && key !== 'valid')) {
      throw new Error(`malformed runner result in ${suiteRef.path}`);
    }
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
    status: requireExternal ? 'external_clean_room_attested'
      : (manifest.independence.claimed ? attestation.status : 'not_claimed_reference_port'),
    attestation,
  },
  specification_bundle: {
    version: specificationBundle.bundle['@version'],
    sha256: specificationBundle.sha256,
    documents: specificationBundle.bundle.documents.length,
  },
  runner: {
    protocol: manifest.runner.protocol,
    artifact_sha256: runnerBinding.sha256,
    fixed_arguments_sha256: sha256(Buffer.from(canonicalize(commandArgs), 'utf8')),
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
