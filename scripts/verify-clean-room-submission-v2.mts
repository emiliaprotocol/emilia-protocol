#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BUNDLE_RELATIVE_PATH = 'conformance/clean-room/v2/bundle.v2.json';
const EXPECTED_MANIFEST_SHA256 =
  '59ed3ea6f53365dd3616d2d37e3321d5a0e390461d284ab0858e67f781dd5b4e';
const EXPECTED_MANIFEST_CLAIM_SHA256 =
  'ce08fab44d17bd2f318eb4873665a1a5dce27fb20f0fa86e4a25d341f06b8e45';
const EXPECTED_AUTHORITY_COMPANION_SHA256 =
  '121a358459ffed223a41a79570cc5307693eaa89a59b3ad330710c5e2f286959';
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const GIT_OID_PATTERN = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;

type JsonObject = Record<string, any>;

export interface V2SuiteContract {
  path: string;
  sha256: string;
  vectors: number;
  executionPath: string;
  executionSha256: string;
  executionBytes: Buffer;
  expectations: Map<string, JsonObject>;
}

export interface PinnedKitV2 {
  root: string;
  bundle: JsonObject;
  bundleSha256: string;
  sourceManifestSha256: string;
  sourceManifestClaimSha256: string;
  authorityExecutionCompanionSha256: string;
  contracts: V2SuiteContract[];
}

function plainObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function exactKeys(
  value: unknown,
  allowed: readonly string[],
  required: readonly string[],
  label: string,
): asserts value is JsonObject {
  if (!plainObject(value)) throw new Error(`${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) throw new Error(`${label}.${key} is not allowed`);
  }
  for (const key of required) {
    if (!Object.hasOwn(value, key)) throw new Error(`${label}.${key} is required`);
  }
}

function nonEmptyString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

function sha256String(value: unknown, label: string): string {
  if (typeof value !== 'string' || !SHA256_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256`);
  }
  return value;
}

function immutableOid(value: unknown, label: string): string {
  if (typeof value !== 'string' || !GIT_OID_PATTERN.test(value)) {
    throw new Error(`${label} must be an immutable 40- or 64-character hexadecimal object ID`);
  }
  return value;
}

function safeRelativePath(value: unknown, label: string, allowDot = false): string {
  const candidate = nonEmptyString(value, label);
  if (candidate.includes('\\') || candidate.startsWith('/')) {
    throw new Error(`${label} is not a safe relative path`);
  }
  const normalized = path.posix.normalize(candidate);
  if (normalized !== candidate
    || (!allowDot && candidate === '.')
    || candidate === '..'
    || candidate.startsWith('../')) {
    throw new Error(`${label} is not a safe relative path`);
  }
  return candidate;
}

function resolveUnder(root: string, relativePath: string, label: string): string {
  const safe = safeRelativePath(relativePath, label);
  const target = path.resolve(root, safe);
  if (!target.startsWith(`${root}${path.sep}`)) throw new Error(`${label} escapes its root`);
  return target;
}

function readJson(target: string, label: string): { bytes: Buffer; value: any } {
  try {
    const bytes = fs.readFileSync(target);
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return { bytes, value: JSON.parse(text) };
  } catch (error) {
    throw new Error(`${label} is not valid UTF-8 JSON: ${errorMessage(error)}`);
  }
}

export function sha256V2(value: Buffer | Uint8Array | string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

export function canonicalizeV2(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('canonical JSON does not permit non-finite numbers');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalizeV2).join(',')}]`;
  if (!plainObject(value)) throw new Error('canonical JSON value contains an unsupported type');
  const fields = Object.keys(value).sort().map((key) => {
    if (value[key] === undefined) throw new Error(`canonical JSON does not permit undefined at ${key}`);
    return `${JSON.stringify(key)}:${canonicalizeV2(value[key])}`;
  });
  return `{${fields.join(',')}}`;
}

function canonicalDigest(value: unknown): string {
  return sha256V2(Buffer.from(canonicalizeV2(value), 'utf8'));
}

export function validateBundleDefinitionV2(bundle: any): void {
  exactKeys(
    bundle,
    ['@version', 'claim_scope', 'source_manifest', 'runner_protocol', 'suites', 'totals'],
    ['@version', 'claim_scope', 'source_manifest', 'runner_protocol', 'suites', 'totals'],
    'bundle',
  );
  if (bundle['@version'] !== 'EP-CLEAN-ROOM-VECTOR-BUNDLE-v2') {
    throw new Error('unsupported clean-room vector bundle');
  }
  nonEmptyString(bundle.claim_scope, 'bundle.claim_scope');

  exactKeys(
    bundle.source_manifest,
    ['path', 'sha256', 'manifest_sha256'],
    ['path', 'sha256', 'manifest_sha256'],
    'bundle.source_manifest',
  );
  if (bundle.source_manifest.path !== 'conformance/conformance-manifest.json') {
    throw new Error('bundle source manifest path is not the current conformance manifest');
  }
  if (sha256String(bundle.source_manifest.sha256, 'bundle.source_manifest.sha256')
      !== EXPECTED_MANIFEST_SHA256) {
    throw new Error('bundle source conformance manifest hash is not the pinned current manifest');
  }
  if (sha256String(
    bundle.source_manifest.manifest_sha256,
    'bundle.source_manifest.manifest_sha256',
  ) !== EXPECTED_MANIFEST_CLAIM_SHA256) {
    throw new Error('bundle source conformance manifest claim hash is not pinned');
  }

  exactKeys(
    bundle.runner_protocol,
    ['version', 'invocation', 'result_shape', 'result_comparison', 'complete_suite_required'],
    ['version', 'invocation', 'result_shape', 'result_comparison', 'complete_suite_required'],
    'bundle.runner_protocol',
  );
  if (bundle.runner_protocol.version !== 'EP-CONFORMANCE-FILE-RUNNER-v2'
      || bundle.runner_protocol.result_shape !== 'array<{id:string,result:object}>'
      || bundle.runner_protocol.complete_suite_required !== true) {
    throw new Error('bundle runner protocol is not the strict v2 typed-result protocol');
  }

  exactKeys(bundle.totals, ['suites', 'vectors'], ['suites', 'vectors'], 'bundle.totals');
  if (bundle.totals.suites !== 21 || bundle.totals.vectors !== 332) {
    throw new Error('bundle must pin exactly 21 suites and 332 vectors');
  }
  if (!Array.isArray(bundle.suites) || bundle.suites.length !== 21) {
    throw new Error('bundle must contain exactly 21 suites');
  }

  const paths = new Set<string>();
  let vectorCount = 0;
  let authorityCompanion: string | null = null;
  for (const [index, suite] of bundle.suites.entries()) {
    const label = `bundle.suites[${index}]`;
    exactKeys(
      suite,
      ['path', 'sha256', 'vectors', 'result_contract', 'execution_path', 'execution_sha256'],
      ['path', 'sha256', 'vectors', 'result_contract'],
      label,
    );
    const suitePath = safeRelativePath(suite.path, `${label}.path`);
    if (paths.has(suitePath)) throw new Error(`bundle contains duplicate suite path ${suitePath}`);
    paths.add(suitePath);
    sha256String(suite.sha256, `${label}.sha256`);
    if (!Number.isInteger(suite.vectors) || suite.vectors <= 0) {
      throw new Error(`${label}.vectors must be a positive integer`);
    }
    vectorCount += suite.vectors;
    if (suite.result_contract !== 'typed_object') {
      throw new Error(`${label}.result_contract must require a typed object`);
    }
    const hasExecutionPath = Object.hasOwn(suite, 'execution_path');
    const hasExecutionHash = Object.hasOwn(suite, 'execution_sha256');
    if (hasExecutionPath !== hasExecutionHash) {
      throw new Error(`${label} must pin both execution companion path and hash`);
    }
    if (hasExecutionPath) {
      const executionPath = safeRelativePath(suite.execution_path, `${label}.execution_path`);
      const executionHash = sha256String(suite.execution_sha256, `${label}.execution_sha256`);
      if (suitePath !== 'conformance/vectors/authority-document-proof-join.v1.json'
          || executionPath
            !== 'conformance/vectors/authority-document-proof-join.exec.v1.json') {
        throw new Error('only the Authority Document suite may name an execution companion');
      }
      authorityCompanion = executionHash;
    }
  }
  if (vectorCount !== 332 || vectorCount !== bundle.totals.vectors) {
    throw new Error('bundle suite total is not exactly 332 vectors');
  }
  if (authorityCompanion !== EXPECTED_AUTHORITY_COMPANION_SHA256) {
    throw new Error('bundle Authority Document execution companion hash is not pinned');
  }
}

function vectorExpectations(
  suitePath: string,
  suite: any,
): Map<string, JsonObject> {
  if (!plainObject(suite) || !Array.isArray(suite.vectors) || suite.vectors.length === 0) {
    throw new Error(`${suitePath}: suite must contain vectors`);
  }
  const expectations = new Map<string, JsonObject>();
  for (const vector of suite.vectors) {
    if (!plainObject(vector)
        || typeof vector.id !== 'string'
        || vector.id === ''
        || !plainObject(vector.expect)) {
      throw new Error(`${suitePath}: malformed vector or typed expectation`);
    }
    if (expectations.has(vector.id)) throw new Error(`${suitePath}: duplicate vector id ${vector.id}`);
    expectations.set(vector.id, vector.expect);
  }
  return expectations;
}

function validateSourceManifest(bundle: JsonObject, bytes: Buffer, manifest: any): void {
  if (sha256V2(bytes) !== bundle.source_manifest.sha256) {
    throw new Error('current conformance manifest hash mismatch');
  }
  if (!plainObject(manifest)
      || manifest['@version'] !== 'EP-CONFORMANCE-MANIFEST-v1'
      || manifest.manifest_sha256 !== bundle.source_manifest.manifest_sha256) {
    throw new Error('current conformance manifest claim hash mismatch');
  }
  const unsigned = { ...manifest };
  delete unsigned.manifest_sha256;
  if (canonicalDigest(unsigned) !== manifest.manifest_sha256) {
    throw new Error('current conformance manifest canonical claim hash is invalid');
  }
  if (manifest.totals?.suites !== 21 || manifest.totals?.vectors !== 332) {
    throw new Error('current conformance manifest is not the pinned 21-suite/332-vector set');
  }
  if (!Array.isArray(manifest.suites) || manifest.suites.length !== bundle.suites.length) {
    throw new Error('current conformance manifest suite list is incomplete');
  }
  for (let index = 0; index < bundle.suites.length; index += 1) {
    const declared = bundle.suites[index];
    const current = manifest.suites[index];
    for (const key of ['path', 'sha256', 'vectors', 'execution_path', 'execution_sha256']) {
      if (declared[key] !== current[key]) {
        throw new Error(`current conformance manifest differs at suite ${index}.${key}`);
      }
    }
  }
}

export function loadPinnedKitV2(
  { root = ROOT }: { root?: string } = {},
): PinnedKitV2 {
  const absoluteRoot = path.resolve(root);
  const bundlePath = resolveUnder(absoluteRoot, BUNDLE_RELATIVE_PATH, 'v2 bundle path');
  const { bytes: bundleBytes, value: bundle } = readJson(bundlePath, 'v2 vector bundle');
  validateBundleDefinitionV2(bundle);

  const manifestPath = resolveUnder(
    absoluteRoot,
    bundle.source_manifest.path,
    'source manifest path',
  );
  const { bytes: manifestBytes, value: manifest } = readJson(
    manifestPath,
    'current conformance manifest',
  );
  validateSourceManifest(bundle, manifestBytes, manifest);

  const contracts: V2SuiteContract[] = [];
  for (const suiteRef of bundle.suites) {
    const suitePath = resolveUnder(absoluteRoot, suiteRef.path, `suite ${suiteRef.path}`);
    const { bytes: suiteBytes, value: suite } = readJson(suitePath, `suite ${suiteRef.path}`);
    if (sha256V2(suiteBytes) !== suiteRef.sha256) {
      throw new Error(`pinned suite hash mismatch: ${suiteRef.path}`);
    }
    const official = vectorExpectations(suiteRef.path, suite);
    if (official.size !== suiteRef.vectors) {
      throw new Error(`pinned suite vector count mismatch: ${suiteRef.path}`);
    }

    const executionPath = suiteRef.execution_path ?? suiteRef.path;
    const executionSha256 = suiteRef.execution_sha256 ?? suiteRef.sha256;
    let executionBytes = suiteBytes;
    let executionSuite = suite;
    if (executionPath !== suiteRef.path) {
      const target = resolveUnder(
        absoluteRoot,
        executionPath,
        `execution companion ${executionPath}`,
      );
      const read = readJson(target, `execution companion ${executionPath}`);
      executionBytes = read.bytes;
      executionSuite = read.value;
      if (sha256V2(executionBytes) !== executionSha256) {
        throw new Error(`Authority Document execution companion hash mismatch`);
      }
    }
    const executable = vectorExpectations(executionPath, executionSuite);
    if (executable.size !== official.size) {
      throw new Error(`${suiteRef.path}: execution companion vector count mismatch`);
    }
    for (const [id, publicExpected] of official) {
      const richExpected = executable.get(id);
      if (!richExpected) {
        throw new Error(`${suiteRef.path}: execution companion omitted vector ${id}`);
      }
      if (executionPath !== suiteRef.path) {
        for (const [key, value] of Object.entries(publicExpected)) {
          if (!isDeepStrictEqual(richExpected[key], value)) {
            throw new Error(`${suiteRef.path}#${id}: execution companion expectation mismatch`);
          }
        }
      }
    }
    contracts.push({
      path: suiteRef.path,
      sha256: suiteRef.sha256,
      vectors: suiteRef.vectors,
      executionPath,
      executionSha256,
      executionBytes,
      expectations: executable,
    });
  }

  const authority = contracts.find((contract) =>
    contract.path === 'conformance/vectors/authority-document-proof-join.v1.json');
  if (!authority || authority.executionSha256 !== EXPECTED_AUTHORITY_COMPANION_SHA256) {
    throw new Error('Authority Document execution companion is missing or unpinned');
  }
  return {
    root: absoluteRoot,
    bundle,
    bundleSha256: sha256V2(bundleBytes),
    sourceManifestSha256: sha256V2(manifestBytes),
    sourceManifestClaimSha256: manifest.manifest_sha256,
    authorityExecutionCompanionSha256: authority.executionSha256,
    contracts,
  };
}

function compareTypedResult(expected: JsonObject, actual: JsonObject): string | null {
  if (typeof expected.reason_contains === 'string') {
    const expectedFields = { ...expected };
    const requiredReason = expectedFields.reason_contains;
    delete expectedFields.reason_contains;
    const actualFields = { ...actual };
    const reasons = actualFields.reasons;
    delete actualFields.reasons;
    if (!Array.isArray(reasons) || reasons.some((reason) => typeof reason !== 'string')) {
      return 'typed reasons array is required';
    }
    if (!isDeepStrictEqual(actualFields, expectedFields)) {
      return 'typed result fields differ';
    }
    return reasons.join(' ').includes(requiredReason)
      ? null
      : `typed reasons omit ${requiredReason}`;
  }
  return isDeepStrictEqual(actual, expected) ? null : 'exact typed result differs';
}

export function validateResultRowsV2(
  contract: V2SuiteContract,
  rows: unknown,
): Array<{ id: string; result: JsonObject }> {
  if (!Array.isArray(rows) || rows.length !== contract.expectations.size) {
    throw new Error(`${contract.path}: runner returned wrong result count`);
  }
  const seen = new Set<string>();
  const normalized: Array<{ id: string; result: JsonObject }> = [];
  for (const row of rows) {
    if (!plainObject(row)
        || Object.keys(row).length !== 2
        || !Object.hasOwn(row, 'id')
        || !Object.hasOwn(row, 'result')
        || typeof row.id !== 'string'
        || row.id === '') {
      throw new Error(`${contract.path}: malformed runner result row`);
    }
    if (seen.has(row.id)) throw new Error(`${contract.path}: duplicate vector id ${row.id}`);
    if (!contract.expectations.has(row.id)) {
      throw new Error(`${contract.path}: unknown vector id ${row.id}`);
    }
    if (!plainObject(row.result)) {
      throw new Error(`${contract.path}#${row.id}: result must be a typed result object`);
    }
    const difference = compareTypedResult(
      contract.expectations.get(row.id) as JsonObject,
      row.result,
    );
    if (difference) throw new Error(`${contract.path}#${row.id}: ${difference}`);
    seen.add(row.id);
    normalized.push({ id: row.id, result: row.result });
  }
  for (const id of contract.expectations.keys()) {
    if (!seen.has(id)) throw new Error(`${contract.path}: runner omitted vector id ${id}`);
  }
  return normalized;
}

function validateStringArray(value: unknown, label: string, allowEmpty = false): string[] {
  if (!Array.isArray(value)
      || (!allowEmpty && value.length === 0)
      || value.some((item) => typeof item !== 'string' || item.trim() === '')) {
    throw new Error(`${label} must be ${allowEmpty ? 'an' : 'a non-empty'} array of strings`);
  }
  return value;
}

export function verifySubmissionManifestV2(manifest: any, kit: PinnedKitV2): void {
  exactKeys(
    manifest,
    ['@version', 'implementation', 'runner', 'kit', 'construction'],
    ['@version', 'implementation', 'runner', 'kit', 'construction'],
    'submission',
  );
  if (manifest['@version'] !== 'EP-CLEAN-ROOM-SUBMISSION-v2') {
    throw new Error('unsupported clean-room submission version');
  }

  const implementationFields = [
    'implementation_id',
    'organization',
    'team_id',
    'language',
    'version',
    'source_repository',
    'source_commit',
    'source_tree_oid',
    'source_tree_path',
    'license_spdx',
    'build_instructions',
    'dependencies',
  ];
  exactKeys(
    manifest.implementation,
    implementationFields,
    implementationFields,
    'submission.implementation',
  );
  for (const key of [
    'implementation_id',
    'organization',
    'team_id',
    'language',
    'version',
    'source_repository',
    'license_spdx',
    'build_instructions',
  ]) {
    nonEmptyString(manifest.implementation[key], `submission.implementation.${key}`);
  }
  immutableOid(manifest.implementation.source_commit, 'submission.implementation.source_commit');
  immutableOid(manifest.implementation.source_tree_oid, 'submission.implementation.source_tree_oid');
  safeRelativePath(
    manifest.implementation.source_tree_path,
    'submission.implementation.source_tree_path',
    true,
  );
  validateStringArray(
    manifest.implementation.dependencies,
    'submission.implementation.dependencies',
    true,
  );

  exactKeys(
    manifest.runner,
    ['protocol', 'artifact_sha256', 'fixed_arguments'],
    ['protocol', 'artifact_sha256', 'fixed_arguments'],
    'submission.runner',
  );
  if (manifest.runner.protocol !== 'EP-CONFORMANCE-FILE-RUNNER-v2') {
    throw new Error('submission runner protocol is not v2');
  }
  sha256String(manifest.runner.artifact_sha256, 'submission.runner.artifact_sha256');
  validateStringArray(manifest.runner.fixed_arguments, 'submission.runner.fixed_arguments', true);

  exactKeys(
    manifest.kit,
    [
      'vector_bundle_sha256',
      'conformance_manifest_sha256',
      'conformance_manifest_claim_sha256',
      'authority_document_execution_companion_sha256',
    ],
    [
      'vector_bundle_sha256',
      'conformance_manifest_sha256',
      'conformance_manifest_claim_sha256',
      'authority_document_execution_companion_sha256',
    ],
    'submission.kit',
  );
  if (manifest.kit.vector_bundle_sha256 !== kit.bundleSha256) {
    throw new Error('submission vector bundle hash does not match the evaluator');
  }
  if (manifest.kit.conformance_manifest_sha256 !== kit.sourceManifestSha256) {
    throw new Error('submission conformance manifest hash does not match the evaluator');
  }
  if (manifest.kit.conformance_manifest_claim_sha256
      !== kit.sourceManifestClaimSha256) {
    throw new Error('submission conformance manifest claim hash does not match the evaluator');
  }
  if (manifest.kit.authority_document_execution_companion_sha256
      !== kit.authorityExecutionCompanionSha256) {
    throw new Error('submission Authority Document execution companion hash does not match the evaluator');
  }

  exactKeys(
    manifest.construction,
    [
      'reference_source_access',
      'emilia_affiliation',
      'specification_inputs',
      'statement',
    ],
    [
      'reference_source_access',
      'emilia_affiliation',
      'specification_inputs',
      'statement',
    ],
    'submission.construction',
  );
  if (manifest.construction.reference_source_access !== 'none') {
    throw new Error('construction claim refuses reference source access other than none');
  }
  if (manifest.construction.emilia_affiliation !== 'none') {
    throw new Error('construction claim refuses EMILIA affiliation');
  }
  validateStringArray(
    manifest.construction.specification_inputs,
    'submission.construction.specification_inputs',
  );
  if (nonEmptyString(
    manifest.construction.statement,
    'submission.construction.statement',
  ).length < 40) {
    throw new Error('submission construction statement is not substantive');
  }
}

export function verifyRunnerArtifactV2(
  runner: any,
  runnerPath: string,
): { path: string; sha256: string; mode: string } {
  const target = fs.realpathSync(path.resolve(runnerPath));
  const stat = fs.statSync(target);
  if (!stat.isFile()) throw new Error('runner artifact is not a file');
  if ((stat.mode & 0o111) === 0) throw new Error('runner artifact is not executable');
  if ((stat.mode & 0o222) !== 0) {
    throw new Error('runner artifact is mutable: write permission bits must be removed');
  }
  const actual = sha256V2(fs.readFileSync(target));
  if (actual !== runner.artifact_sha256) {
    throw new Error('runner artifact hash mismatch');
  }
  return {
    path: target,
    sha256: actual,
    mode: (stat.mode & 0o777).toString(8).padStart(3, '0'),
  };
}

function normalizedIdentity(value: unknown): string {
  return String(value ?? '').trim().toLowerCase();
}

function expectedAttestationClaim(manifest: any): JsonObject {
  return {
    submission_sha256: canonicalDigest(manifest),
    implementation_id: manifest.implementation.implementation_id,
    implementation_organization: manifest.implementation.organization,
    implementation_team_id: manifest.implementation.team_id,
    source_commit: manifest.implementation.source_commit,
    runner_artifact_sha256: manifest.runner.artifact_sha256,
    vector_bundle_sha256: manifest.kit.vector_bundle_sha256,
    conformance_manifest_sha256: manifest.kit.conformance_manifest_sha256,
    authority_document_execution_companion_sha256:
      manifest.kit.authority_document_execution_companion_sha256,
    reference_source_access: 'none',
    emilia_affiliation: 'none',
  };
}

export function verifyIndependentAttestationV2(
  manifest: any,
  attestation: any | null,
  trustedAttestors: any | null,
): JsonObject {
  if (attestation === null || attestation === undefined) {
    return {
      accepted: false,
      status: 'independent_attestation_missing',
    };
  }
  if (!trustedAttestors) {
    throw new Error('construction claim refused: no trusted-attestor input was supplied');
  }
  exactKeys(
    attestation,
    ['@version', 'claim', 'attestor', 'signature'],
    ['@version', 'claim', 'attestor'],
    'independent attestation',
  );
  if (attestation['@version'] !== 'EP-CLEAN-ROOM-INDEPENDENT-ATTESTATION-v2') {
    throw new Error('construction claim refused: unsupported attestation version');
  }
  if (!Object.hasOwn(attestation, 'signature')) {
    throw new Error('unsigned construction claim refused');
  }
  const claimFields = [
    'submission_sha256',
    'implementation_id',
    'implementation_organization',
    'implementation_team_id',
    'source_commit',
    'runner_artifact_sha256',
    'vector_bundle_sha256',
    'conformance_manifest_sha256',
    'authority_document_execution_companion_sha256',
    'reference_source_access',
    'emilia_affiliation',
    'reviewed_at',
    'statement',
  ];
  exactKeys(attestation.claim, claimFields, claimFields, 'independent attestation.claim');
  const expected = expectedAttestationClaim(manifest);
  for (const [key, value] of Object.entries(expected)) {
    if (attestation.claim[key] !== value) {
      throw new Error(`construction claim refused: signed ${key} does not match the submission`);
    }
  }
  if (nonEmptyString(
    attestation.claim.statement,
    'independent attestation.claim.statement',
  ).length < 40) {
    throw new Error('construction claim refused: attestor statement is not substantive');
  }
  const reviewedAt = nonEmptyString(
    attestation.claim.reviewed_at,
    'independent attestation.claim.reviewed_at',
  );
  if (!Number.isFinite(Date.parse(reviewedAt))) {
    throw new Error('construction claim refused: reviewed_at is not an ISO timestamp');
  }

  exactKeys(
    attestation.attestor,
    ['key_id', 'organization', 'team_id'],
    ['key_id', 'organization', 'team_id'],
    'independent attestation.attestor',
  );
  for (const key of ['key_id', 'organization', 'team_id']) {
    nonEmptyString(attestation.attestor[key], `independent attestation.attestor.${key}`);
  }
  if (normalizedIdentity(attestation.attestor.organization)
        === normalizedIdentity(manifest.implementation.organization)
      || normalizedIdentity(attestation.attestor.team_id)
        === normalizedIdentity(manifest.implementation.team_id)) {
    throw new Error('same-team construction claim refused');
  }
  if (/emilia/i.test(attestation.attestor.organization)
      || /emilia/i.test(attestation.attestor.team_id)) {
    throw new Error('EMILIA-affiliated construction attestor refused');
  }

  exactKeys(
    attestation.signature,
    ['algorithm', 'value_base64url'],
    ['algorithm', 'value_base64url'],
    'independent attestation.signature',
  );
  if (attestation.signature.algorithm !== 'Ed25519') {
    throw new Error('construction claim refused: signature algorithm must be Ed25519');
  }
  nonEmptyString(
    attestation.signature.value_base64url,
    'independent attestation.signature.value_base64url',
  );

  exactKeys(
    trustedAttestors,
    ['@version', 'keys'],
    ['@version', 'keys'],
    'trusted attestors',
  );
  if (trustedAttestors['@version'] !== 'EP-CLEAN-ROOM-TRUSTED-ATTESTORS-v2'
      || !Array.isArray(trustedAttestors.keys)) {
    throw new Error('construction claim refused: invalid trusted-attestor input');
  }
  const pin = trustedAttestors.keys.find((entry: any) =>
    entry?.key_id === attestation.attestor.key_id);
  if (!pin) throw new Error('construction claim refused: attestor key is not pinned');
  exactKeys(
    pin,
    ['key_id', 'organization', 'team_id', 'independent', 'public_key_spki_base64url'],
    ['key_id', 'organization', 'team_id', 'independent', 'public_key_spki_base64url'],
    'trusted attestor pin',
  );
  if (pin.independent !== true
      || normalizedIdentity(pin.organization)
        !== normalizedIdentity(attestation.attestor.organization)
      || normalizedIdentity(pin.team_id)
        !== normalizedIdentity(attestation.attestor.team_id)) {
    throw new Error('construction claim refused: attestor identity is not independently pinned');
  }

  let publicKey: crypto.KeyObject;
  let signature: Buffer;
  try {
    publicKey = crypto.createPublicKey({
      key: Buffer.from(pin.public_key_spki_base64url, 'base64url'),
      format: 'der',
      type: 'spki',
    });
    signature = Buffer.from(attestation.signature.value_base64url, 'base64url');
  } catch (error) {
    throw new Error(`construction claim refused: invalid key or signature encoding: ${errorMessage(error)}`);
  }
  if (publicKey.asymmetricKeyType !== 'ed25519') {
    throw new Error('construction claim refused: pinned key is not Ed25519');
  }
  const unsigned = { ...attestation };
  delete unsigned.signature;
  if (!crypto.verify(
    null,
    Buffer.from(canonicalizeV2(unsigned), 'utf8'),
    publicKey,
    signature,
  )) {
    throw new Error('construction claim refused: signature verification failed');
  }
  return {
    accepted: true,
    status: 'independent_attestation_verified',
    key_id: pin.key_id,
    organization: pin.organization,
    team_id: pin.team_id,
    claim_sha256: canonicalDigest(unsigned),
  };
}

function parseRunnerOutput(stdout: string, suitePath: string): any {
  try {
    return JSON.parse(stdout);
  } catch (error) {
    throw new Error(`${suitePath}: runner emitted invalid JSON: ${errorMessage(error)}`);
  }
}

export function verifyCleanRoomSubmissionV2({
  manifestPath,
  runnerPath,
  attestationPath,
  trustedAttestorsPath,
  emitPath,
  requireAcceptance = false,
  root = ROOT,
}: {
  manifestPath: string;
  runnerPath: string;
  attestationPath?: string | null;
  trustedAttestorsPath?: string | null;
  emitPath?: string | null;
  requireAcceptance?: boolean;
  root?: string;
}): JsonObject {
  const kit = loadPinnedKitV2({ root });
  const { value: manifest } = readJson(path.resolve(manifestPath), 'submission manifest');
  verifySubmissionManifestV2(manifest, kit);
  const runner = verifyRunnerArtifactV2(manifest.runner, runnerPath);
  const attestation = attestationPath
    ? readJson(path.resolve(attestationPath), 'independent attestation').value
    : null;
  const trusted = trustedAttestorsPath
    ? readJson(path.resolve(trustedAttestorsPath), 'trusted attestors').value
    : null;
  const acceptance = verifyIndependentAttestationV2(manifest, attestation, trusted);
  if (requireAcceptance && acceptance.accepted !== true) {
    throw new Error('external clean-room acceptance refused: independent attestation is required');
  }

  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-clean-room-v2-eval-'));
  const suites: JsonObject[] = [];
  let vectorCount = 0;
  try {
    for (const [index, contract] of kit.contracts.entries()) {
      verifyRunnerArtifactV2(manifest.runner, runner.path);
      const suiteTarget = path.join(
        temporary,
        `${String(index).padStart(2, '0')}-${path.basename(contract.executionPath)}`,
      );
      fs.writeFileSync(suiteTarget, contract.executionBytes, { mode: 0o444 });
      fs.chmodSync(suiteTarget, 0o444);
      let stdout: string;
      try {
        stdout = execFileSync(
          runner.path,
          [...manifest.runner.fixed_arguments, suiteTarget],
          {
            cwd: path.dirname(runner.path),
            encoding: 'utf8',
            timeout: 180_000,
            maxBuffer: 64 * 1024 * 1024,
            stdio: ['ignore', 'pipe', 'pipe'],
          },
        );
      } catch (error: any) {
        throw new Error(
          `${contract.path}: runner failed: ${String(error?.stderr || errorMessage(error)).trim()}`,
        );
      }
      if (sha256V2(fs.readFileSync(suiteTarget)) !== contract.executionSha256) {
        throw new Error(`${contract.path}: runner mutated the execution suite`);
      }
      verifyRunnerArtifactV2(manifest.runner, runner.path);
      const rows = validateResultRowsV2(
        contract,
        parseRunnerOutput(stdout, contract.path),
      );
      vectorCount += rows.length;
      suites.push({
        path: contract.path,
        sha256: contract.sha256,
        execution_path: contract.executionPath,
        execution_sha256: contract.executionSha256,
        vectors: rows.length,
        normalized_results_sha256: canonicalDigest(rows),
        status: 'pass',
      });
    }
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
  if (suites.length !== 21 || vectorCount !== 332) {
    throw new Error('external clean-room evaluation did not complete all 21 suites and 332 vectors');
  }

  const report: JsonObject = {
    '@version': 'EP-CLEAN-ROOM-EVALUATION-v2',
    conformance: {
      status: 'pass',
      bundle: kit.bundle['@version'],
      bundle_sha256: kit.bundleSha256,
      conformance_manifest_sha256: kit.sourceManifestSha256,
      conformance_manifest_claim_sha256: kit.sourceManifestClaimSha256,
      authority_document_execution_companion_sha256:
        kit.authorityExecutionCompanionSha256,
      suites: suites.length,
      vectors: vectorCount,
    },
    implementation: manifest.implementation,
    runner: {
      protocol: manifest.runner.protocol,
      artifact_sha256: runner.sha256,
      mode: runner.mode,
      fixed_arguments_sha256: canonicalDigest(manifest.runner.fixed_arguments),
    },
    construction: manifest.construction,
    acceptance,
    submission_sha256: canonicalDigest(manifest),
    suites,
  };
  report.report_sha256 = canonicalDigest(report);
  if (emitPath) {
    const target = path.resolve(emitPath);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, `${JSON.stringify(report, null, 2)}\n`);
  }
  return report;
}

function cliOptions(argv: string[]): {
  manifestPath: string;
  runnerPath: string;
  attestationPath?: string;
  trustedAttestorsPath?: string;
  emitPath?: string;
  requireAcceptance: boolean;
} {
  const values = new Map<string, string>();
  let requireAcceptance = false;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--require-acceptance') {
      requireAcceptance = true;
      continue;
    }
    if (![
      '--manifest',
      '--runner',
      '--attestation',
      '--trusted-attestors',
      '--emit',
    ].includes(argument)) {
      throw new Error(`unknown argument: ${argument}`);
    }
    const value = argv[++index];
    if (!value) throw new Error(`${argument} requires a value`);
    values.set(argument, value);
  }
  const manifestPath = values.get('--manifest');
  const runnerPath = values.get('--runner');
  if (!manifestPath || !runnerPath) {
    throw new Error(
      'usage: verify-clean-room-submission-v2 --manifest FILE --runner EXECUTABLE '
      + '[--attestation FILE --trusted-attestors FILE] [--require-acceptance] [--emit FILE]',
    );
  }
  return {
    manifestPath,
    runnerPath,
    attestationPath: values.get('--attestation'),
    trustedAttestorsPath: values.get('--trusted-attestors'),
    emitPath: values.get('--emit'),
    requireAcceptance,
  };
}

if (process.argv[1]
    && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const report = verifyCleanRoomSubmissionV2(cliOptions(process.argv.slice(2)));
    console.log(
      `CLEAN-ROOM V2: PASS (${report.conformance.suites} suites, `
      + `${report.conformance.vectors} vectors; acceptance=${report.acceptance.accepted}; `
      + `sha256:${report.report_sha256})`,
    );
  } catch (error) {
    console.error(`CLEAN-ROOM V2: FAIL: ${errorMessage(error)}`);
    process.exitCode = 1;
  }
}
