// SPDX-License-Identifier: Apache-2.0
/**
 * AEB Crossing Lab — an offline workbench over AEB-ADAPTER-v1.
 *
 * A local module implements the existing AebAdapter interface. The workbench
 * executes that adapter in a permission-bounded child process, then feeds the
 * exact native and mapping results into evaluateAebEvidence. It introduces no
 * new evidence envelope or authorization semantics.
 */
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, isAbsolute, join, parse, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  adapterPinDigest,
  digestAeb,
  evaluateAebEvidence,
  mappingProfileDigest,
  registryEntryDigest,
  unifiedRegistryDigest,
  type AebAdapter,
  type AebEvaluationRecord,
  type AebNativeResult,
  type AebPinnedAdapter,
  type AebPinnedConfig,
  type AebPinnedProfile,
  type AebRegistryEntry,
  type AebStatusInput,
  type AebUnifiedRegistry,
} from './aeb-adapter-contract.js';
import { canonicalizeStrictJson, strictJsonGate } from './strict-json.js';

// The governed CAID implementation is JavaScript and has no declaration file.
// @ts-expect-error -- the runtime result is checked before use.
import { computeCaid } from '../vendor/caid.mjs';

export const CROSSING_LAB_WORKSPACE_VERSION = 'EMILIA-CROSSING-LAB-LOCAL-WORKSPACE-v1' as const;
export const CROSSING_LAB_REPORT_VERSION = 'EMILIA-CROSSING-LAB-LOCAL-REPORT-v1' as const;
export const CROSSING_LAB_STATEMENT = 'SELF_ATTESTED_ADAPTER_COMPATIBILITY_TEST_NOT_CERTIFICATION' as const;
export const CROSSING_LAB_SCAN_SEED_VERSION = 'EP-SCAN-CROSSING-SEED-v1' as const;
export const CROSSING_LAB_DRAFT_WORKSPACE_VERSION = 'EP-AEB-CROSSING-LAB-DRAFT-v1' as const;
export const CROSSING_LAB_VERIFY_VERSION = '3.21.0' as const;

export const CROSSING_LAB_SCAN_PROFILES = Object.freeze([
  'ccs-wang-draft08-v13',
  'cedulon-aeb-crossing-v0.1',
  'pinto-cbap1-aeb-v0.1',
] as const);

export const CROSSING_LAB_SCAN_PROFILE_CONTRACTS = Object.freeze({
  'ccs-wang-draft08-v13': Object.freeze({
    action_type: 'agent.tool-invocation.1',
    material_fields: Object.freeze(['action_type', 'parameters']),
  }),
  'cedulon-aeb-crossing-v0.1': Object.freeze({
    action_type: 'cedulon.payment.attempt.1',
    material_fields: Object.freeze(['action_type', 'amount', 'currency', 'payee', 'tool', 'nonce', 'manifest_hash']),
  }),
  'pinto-cbap1-aeb-v0.1': Object.freeze({
    action_type: 'account.suspend.1',
    material_fields: Object.freeze(['account_ref', 'action_type', 'policy_event_ref']),
  }),
} as const);

export function crossingLabScanProfileContract(profileId: unknown): Obj {
  if (typeof profileId !== 'string' || !Object.hasOwn(CROSSING_LAB_SCAN_PROFILE_CONTRACTS, profileId)) {
    throw new TypeError('supported crossing profile required');
  }
  return structuredClone(
    CROSSING_LAB_SCAN_PROFILE_CONTRACTS[profileId as keyof typeof CROSSING_LAB_SCAN_PROFILE_CONTRACTS],
  );
}

export const CROSSING_LAB_LIMITS = Object.freeze({
  max_file_bytes: 1_048_576,
  max_adapter_bytes: 262_144,
  max_depth: 32,
  max_nodes: 65_536,
  required_file_count: 3,
  adapter_timeout_ms: 2_000,
  max_adapter_output_bytes: 262_144,
});

type Obj = Record<string, any>;
type Digest = `sha256:${string}`;

export type CrossingLabAxes = {
  native_verification: 'VERIFIED' | 'FAILED' | 'INDETERMINATE';
  acceptance: 'ACCEPTED' | 'REJECTED' | 'INDETERMINATE';
  mapping: 'MATCH' | 'MISMATCH' | 'INDETERMINATE';
  freshness: 'FRESH' | 'STALE' | 'UNAVAILABLE' | 'REVOKED' | 'CONSUMED' | 'INDETERMINATE';
  satisfaction: 'SATISFIED' | 'UNSATISFIED' | 'INDETERMINATE';
};

export type CrossingLabExpectationRule =
  | 'POSITIVE_SATISFIED'
  | 'ACTION_SUBSTITUTION_SAFE'
  | 'TRUST_SUBSTITUTION_SAFE'
  | 'STALE_STATUS_INDETERMINATE'
  | 'UNAVAILABLE_STATUS_INDETERMINATE'
  | 'REWRAPPED_REPLAY_IDENTITY_STABLE';

export interface CrossingLabExpectation {
  rule: CrossingLabExpectationRule;
  description: string;
}

export interface CrossingLabAdapterRow {
  id: string;
  category: 'positive' | 'hostile' | 'boundary';
  passed: boolean;
  expected: CrossingLabExpectation;
  actual: CrossingLabAxes & { evaluation_valid: boolean };
  reasons: string[];
  evaluation: AebEvaluationRecord;
}

export interface CrossingLabHarnessSelfTest {
  id: string;
  passed: boolean;
  observed: string;
}

export interface CrossingLabReport {
  '@version': typeof CROSSING_LAB_REPORT_VERSION;
  workspace_digest: Digest;
  adapter: { id: string; version: string; module_digest: Digest };
  evaluated_at: string;
  adapter_rows: CrossingLabAdapterRow[];
  harness_self_tests: CrossingLabHarnessSelfTest[];
  summary: { adapter_rows: number; passed: number; failed: number; harness_passed: number; harness_failed: number };
  lab_passed: boolean;
  assurance: {
    self_attested: true;
    certification: false;
    statement: typeof CROSSING_LAB_STATEMENT;
    evaluator_key_id: typeof LAB_EVALUATOR_KEY_ID;
    evaluator_key_purpose: 'PUBLIC_FIXED_SELF_TEST_KEY_NO_ATTRIBUTION';
  };
  non_claims: readonly string[];
  report_digest: Digest;
}

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const CAID_RE = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{0,255}$/;
const FILE_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const RFC3339_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const STATUS_REQUIRED_KEYS = ['checked_at', 'expires_at', 'revocation_checked', 'revoked', 'consumed'] as const;
const STATUS_ALLOWED_KEYS = new Set([...STATUS_REQUIRED_KEYS, 'unavailable']);
const LAB_EVALUATOR_KEY_ID = 'crossing-lab:self-test';
const LAB_EVALUATOR_PRIVATE_JWK = {
  crv: 'Ed25519',
  d: 'EBsZ3aVNd8cSzmZECgG0MMAPTreFIhgDFtTY9UTkQ_Y',
  x: 'c_kUSHs4ymdA65GF3OV8C3PDWhelodqfOvCmFe-6oUI',
  kty: 'OKP',
} as const;
const LAB_EVALUATOR_PUBLIC_JWK = {
  crv: 'Ed25519',
  x: LAB_EVALUATOR_PRIVATE_JWK.x,
  kty: 'OKP',
} as const;
// Published test material. It exists only to make local self-test records
// reproducible and provides no evaluator or operator attribution.
const SAMPLE_NATIVE_PRIVATE_JWK = {
  crv: 'Ed25519',
  d: 'rARIWOABK7u-SYCs2oDD5YhwuLyHJ_W0jUcv1bY-kqE',
  x: 'p_tE00vpoJ-uUuy93U7ezvHRjMxCJeogGEjmpHHOHko',
  kty: 'OKP',
} as const;
const SAMPLE_NATIVE_PUBLIC_JWK = {
  crv: 'Ed25519',
  x: SAMPLE_NATIVE_PRIVATE_JWK.x,
  kty: 'OKP',
} as const;
const LAB_EVALUATOR_PRIVATE = crypto.createPrivateKey({ key: LAB_EVALUATOR_PRIVATE_JWK, format: 'jwk' });
const LAB_EVALUATOR_PUBLIC_SPKI = crypto.createPublicKey({ key: LAB_EVALUATOR_PUBLIC_JWK, format: 'jwk' })
  .export({ type: 'spki', format: 'der' }).toString('base64url');
const SAMPLE_NATIVE_PRIVATE = crypto.createPrivateKey({ key: SAMPLE_NATIVE_PRIVATE_JWK, format: 'jwk' });
const SAMPLE_NATIVE_PUBLIC_SPKI = crypto.createPublicKey({ key: SAMPLE_NATIVE_PUBLIC_JWK, format: 'jwk' })
  .export({ type: 'spki', format: 'der' }).toString('base64url');

function isObject(value: unknown): value is Obj {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value: Obj, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return actual.length === sorted.length && actual.every((key, index) => key === sorted[index]);
}

function inspectJson(value: unknown, depth = 0, state = { nodes: 0 }): void {
  state.nodes += 1;
  if (state.nodes > CROSSING_LAB_LIMITS.max_nodes) throw new TypeError('JSON node limit exceeded');
  if (depth > CROSSING_LAB_LIMITS.max_depth) throw new TypeError('JSON depth limit exceeded');
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('non-finite JSON number');
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) inspectJson(item, depth + 1, state);
    return;
  }
  if (!isObject(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new TypeError('plain JSON object required');
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.getOwnPropertySymbols(value).length > 0) throw new TypeError('symbol JSON member refused');
  for (const descriptor of Object.values(descriptors)) {
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) throw new TypeError('canonical JSON properties required');
    inspectJson(descriptor.value, depth + 1, state);
  }
}

export function canonicalizeCrossingLab(value: unknown): string {
  inspectJson(value);
  return canonicalizeStrictJson(value);
}

export function digestCrossingLab(value: unknown): Digest {
  return `sha256:${crypto.createHash('sha256').update(canonicalizeCrossingLab(value), 'utf8').digest('hex')}`;
}

function sha256Bytes(value: Buffer | string): Digest {
  return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}

function parseStrictJson(raw: string, label: string): unknown {
  if (Buffer.byteLength(raw, 'utf8') > CROSSING_LAB_LIMITS.max_file_bytes) throw new TypeError(`${label} exceeds file-size limit`);
  const strict = strictJsonGate(raw);
  if (!strict.ok) throw new TypeError(`${label}: strict JSON required (${strict.reason})`);
  const value = JSON.parse(raw);
  inspectJson(value);
  return value;
}

function normalizeStatusInput(value: unknown): AebStatusInput & { unavailable: boolean } {
  if (!isObject(value)
      || Object.keys(value).some((key) => !STATUS_ALLOWED_KEYS.has(key))
      || !STATUS_REQUIRED_KEYS.every((key) => Object.hasOwn(value, key))
      || typeof value.checked_at !== 'string' || !RFC3339_RE.test(value.checked_at)
      || typeof value.expires_at !== 'string' || !RFC3339_RE.test(value.expires_at)
      || !Number.isFinite(Date.parse(value.checked_at)) || !Number.isFinite(Date.parse(value.expires_at))
      || typeof value.revocation_checked !== 'boolean'
      || typeof value.revoked !== 'boolean'
      || typeof value.consumed !== 'boolean'
      || (value.unavailable !== undefined && typeof value.unavailable !== 'boolean')) {
    throw new TypeError('invalid AEB status input');
  }
  return {
    checked_at: value.checked_at,
    expires_at: value.expires_at,
    revocation_checked: value.revocation_checked,
    revoked: value.revoked,
    consumed: value.consumed,
    unavailable: value.unavailable === true,
  };
}

function assertDirectFile(root: string, name: unknown, maxBytes: number): string {
  if (typeof name !== 'string' || !FILE_RE.test(name) || isAbsolute(name)) throw new TypeError('workspace file must be one relative filename');
  const candidate = resolve(root, name);
  const rel = relative(root, candidate);
  if (rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new TypeError('workspace path escapes root');
  const stat = lstatSync(candidate);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new TypeError(`${name} must be a regular non-symlink file`);
  if (stat.size > maxBytes) throw new TypeError(`${name} exceeds file-size limit`);
  const real = realpathSync(candidate);
  const realRel = relative(realpathSync(root), real);
  if (realRel === '..' || realRel.startsWith(`..${sep}`) || isAbsolute(realRel)) throw new TypeError('workspace file resolves outside root');
  return real;
}

function assertNoUserSymlinkComponents(absolutePath: string, label: string): void {
  const parsed = parse(absolutePath);
  const segments = absolutePath.slice(parsed.root.length).split(sep).filter(Boolean);
  let cursor = parsed.root;
  for (const segment of segments) {
    cursor = join(cursor, segment);
    const stat = lstatSync(cursor);
    if (stat.isSymbolicLink()) {
      const rootOwnedSystemAlias = dirname(cursor) === parsed.root && stat.uid === 0;
      if (!rootOwnedSystemAlias) throw new TypeError(`${label} must not traverse a symlink`);
    }
  }
}

const SCAN_REQUIRED_OPERATOR_INPUTS = Object.freeze([
  'native_artifact',
  'adapter_bytes',
  'trust_roots',
  'status_source',
  'relying_party_id',
  'exact_material_fields',
  'profile_compatibility_confirmation',
] as const);

function validateScanCrossingSeed(seed: unknown): asserts seed is Obj {
  if (!isObject(seed) || !exactKeys(seed, [
    '@version', 'verify_version', 'profile_id', 'profile_contract', 'profile_compatibility',
    'reviewed_manifest', 'generated_scaffold_sha256',
    'local_rr1_results_digest', 'selected_action', 'selected_action_digest',
    'operator_confirmation',
  ]) || seed['@version'] !== CROSSING_LAB_SCAN_SEED_VERSION) {
    throw new TypeError('invalid Scan crossing seed');
  }
  if (seed.verify_version !== CROSSING_LAB_VERIFY_VERSION) {
    throw new TypeError('Scan crossing seed Verify version mismatch');
  }
  const expectedProfileContract = crossingLabScanProfileContract(seed.profile_id);
  if (canonicalizeCrossingLab(seed.profile_contract) !== canonicalizeCrossingLab(expectedProfileContract)
      || seed.profile_compatibility !== 'UNVERIFIED_OPERATOR_CONFIRMATION_REQUIRED') {
    throw new TypeError('Scan crossing seed profile contract mismatch');
  }
  if (!DIGEST_RE.test(seed.generated_scaffold_sha256 ?? '')
      || !DIGEST_RE.test(seed.local_rr1_results_digest ?? '')
      || !DIGEST_RE.test(seed.selected_action_digest ?? '')) {
    throw new TypeError('invalid Scan crossing seed digest');
  }
  if (!isObject(seed.reviewed_manifest)
      || !exactKeys(seed.reviewed_manifest, ['file', 'sha256'])
      || !FILE_RE.test(seed.reviewed_manifest.file ?? '')
      || !DIGEST_RE.test(seed.reviewed_manifest.sha256 ?? '')) {
    throw new TypeError('invalid Scan crossing seed reviewed manifest');
  }
  const action = seed.selected_action;
  if (!isObject(action) || !exactKeys(action, [
    'id', 'selector', 'action_type', 'assurance_class', 'receipt_required', 'material_fields',
  ]) || !ID_RE.test(action.id ?? '') || !ID_RE.test(action.action_type ?? '')
      || !['class_a', 'quorum'].includes(action.assurance_class)
      || action.receipt_required !== true
      || !isObject(action.selector) || !exactKeys(action.selector, ['protocol', 'tool'])
      || action.selector.protocol !== 'mcp' || !ID_RE.test(action.selector.tool ?? '')
      || !Array.isArray(action.material_fields) || action.material_fields.length === 0
      || action.material_fields.length > 64
      || !action.material_fields.every((field: unknown) => typeof field === 'string' && ID_RE.test(field))
      || new Set(action.material_fields).size !== action.material_fields.length
      || !action.material_fields.includes('action_type')) {
    throw new TypeError('invalid Scan crossing seed selected action');
  }
  if (digestCrossingLab(action) !== seed.selected_action_digest) {
    throw new TypeError('selected action digest mismatch');
  }
  const confirmation = seed.operator_confirmation;
  if (!isObject(confirmation)
      || !exactKeys(confirmation, ['status', 'workspace_state', 'required_inputs'])
      || confirmation.status !== 'required' || confirmation.workspace_state !== 'unsealed'
      || canonicalizeCrossingLab(confirmation.required_inputs) !== canonicalizeCrossingLab(SCAN_REQUIRED_OPERATOR_INPUTS)) {
    throw new TypeError('invalid Scan crossing seed operator confirmation');
  }
  inspectJson(seed);
}

function verifySeedManifest(seedRoot: string, seed: Obj): void {
  const manifestPath = assertDirectFile(
    seedRoot,
    seed.reviewed_manifest.file,
    CROSSING_LAB_LIMITS.max_file_bytes,
  );
  const manifestStat = lstatSync(manifestPath);
  if (manifestStat.nlink !== 1) throw new TypeError('reviewed manifest must not be hard-linked');
  const manifestBytes = readFileSync(manifestPath);
  if (sha256Bytes(manifestBytes) !== seed.reviewed_manifest.sha256) {
    throw new TypeError('reviewed manifest digest mismatch');
  }
  const manifest = parseStrictJson(manifestBytes.toString('utf8'), seed.reviewed_manifest.file);
  if (!isObject(manifest) || !Array.isArray(manifest.actions)) {
    throw new TypeError('reviewed manifest has no action list');
  }
  if (!manifest.actions.every((candidate: unknown) => (
    isObject(candidate) && typeof candidate.id === 'string' && isObject(candidate.match)
  ))) {
    throw new TypeError('reviewed manifest contains an invalid action');
  }
  const seenIds = new Set<string>();
  const seenSelectors = new Set<string>();
  for (const candidate of manifest.actions as Obj[]) {
    const selector = canonicalizeCrossingLab(candidate.match);
    if (seenIds.has(candidate.id as string) || seenSelectors.has(selector)) {
      throw new TypeError('reviewed manifest contains a duplicate action id or selector');
    }
    seenIds.add(candidate.id as string);
    seenSelectors.add(selector);
  }
  const matches = (manifest.actions as Obj[]).filter((candidate) => (
    candidate.id === seed.selected_action.id
  ));
  if (matches.length !== 1) throw new TypeError('reviewed manifest selected action is not unique');
  const [selected] = matches;
  if (!isObject(selected)
      || selected.action_type !== seed.selected_action.action_type
      || selected.assurance_class !== seed.selected_action.assurance_class
      || selected.receipt_required !== true
      || canonicalizeCrossingLab(selected.match) !== canonicalizeCrossingLab(seed.selected_action.selector)
      || !isObject(selected.execution_binding)
      || canonicalizeCrossingLab(selected.execution_binding.required_fields)
        !== canonicalizeCrossingLab(seed.selected_action.material_fields)) {
    throw new TypeError('reviewed manifest selected action mismatch');
  }
}

function validateWorkspace(workspace: unknown): asserts workspace is Obj {
  if (!isObject(workspace) || !exactKeys(workspace, [
    '@version', 'adapter', 'artifact', 'artifact_digest', 'config', 'evaluated_at',
    'evaluation', 'expected_action', 'expected_action_digest',
    'hostile_expected_action', 'hostile_expected_action_digest',
  ]) || workspace['@version'] !== CROSSING_LAB_WORKSPACE_VERSION) throw new TypeError('invalid Crossing Lab workspace schema');
  if (!isObject(workspace.adapter) || !exactKeys(workspace.adapter, ['id', 'module', 'module_digest', 'version'])
      || !ID_RE.test(workspace.adapter.id ?? '') || !ID_RE.test(workspace.adapter.version ?? '')
      || !FILE_RE.test(workspace.adapter.module ?? '') || !DIGEST_RE.test(workspace.adapter.module_digest ?? '')) throw new TypeError('invalid adapter metadata');
  if (!FILE_RE.test(workspace.artifact ?? '') || !DIGEST_RE.test(workspace.artifact_digest ?? '')) throw new TypeError('invalid artifact pin');
  if (!DIGEST_RE.test(workspace.expected_action_digest ?? '')) throw new TypeError('invalid expected-action pin');
  if (!DIGEST_RE.test(workspace.hostile_expected_action_digest ?? '')) throw new TypeError('invalid hostile-action pin');
  if (!RFC3339_RE.test(workspace.evaluated_at ?? '') || !Number.isFinite(Date.parse(workspace.evaluated_at))) throw new TypeError('invalid evaluated_at');
  if (!isObject(workspace.config) || workspace.config['@version'] !== 'AEB-ADAPTER-v1') throw new TypeError('real AEB-ADAPTER-v1 config required');
  if (!isObject(workspace.evaluation) || !exactKeys(workspace.evaluation, [
    'artifact_ref', 'caid', 'consumption_nonce', 'executor_id', 'initiator_id',
    'operation_id', 'profile_id', 'requirement_ref', 'status', 'status_digest',
  ]) || !ID_RE.test(workspace.evaluation.artifact_ref ?? '') || !CAID_RE.test(workspace.evaluation.caid ?? '')
      || ![workspace.evaluation.operation_id, workspace.evaluation.consumption_nonce, workspace.evaluation.executor_id,
        workspace.evaluation.initiator_id, workspace.evaluation.profile_id, workspace.evaluation.requirement_ref].every((value) => typeof value === 'string' && ID_RE.test(value))
      || !isObject(workspace.evaluation.status) || !DIGEST_RE.test(workspace.evaluation.status_digest ?? '')) throw new TypeError('invalid AEB evaluation input');
  normalizeStatusInput(workspace.evaluation.status);
  const declared = new Set(['workspace.json', workspace.adapter.module, workspace.artifact]);
  if (declared.size !== CROSSING_LAB_LIMITS.required_file_count) throw new TypeError('workspace must declare exactly three distinct required files');
  inspectJson(workspace);
}

function workspacePinErrors(workspace: Obj, artifact: unknown, adapterBytes: Buffer): string[] {
  const reasons: string[] = [];
  if (sha256Bytes(adapterBytes) !== workspace.adapter.module_digest) reasons.push('adapter_module_pin_drift');
  if (digestAeb(artifact) !== workspace.artifact_digest) reasons.push('artifact_pin_drift');
  if (digestAeb(workspace.expected_action) !== workspace.expected_action_digest) reasons.push('expected_action_pin_drift');
  if (digestAeb(workspace.hostile_expected_action) !== workspace.hostile_expected_action_digest) reasons.push('hostile_action_pin_drift');
  if (workspace.hostile_expected_action_digest === workspace.expected_action_digest) reasons.push('hostile_action_not_distinct');
  if (digestAeb(normalizeStatusInput(workspace.evaluation.status)) !== workspace.evaluation.status_digest) reasons.push('status_pin_drift');
  const adapterPin = workspace.config?.adapters?.[workspace.adapter.id];
  if (!adapterPin || adapterPin.version !== workspace.adapter.version) reasons.push('adapter_identity_not_pinned');
  for (const [id, pin] of Object.entries(workspace.config?.adapters ?? {})) {
    try {
      if (!isObject(pin) || adapterPinDigest(id, pin as AebPinnedAdapter) !== pin.config_digest) reasons.push(`adapter_config_pin_drift:${id}`);
    } catch { reasons.push(`adapter_config_pin_drift:${id}`); }
  }
  for (const [id, profile] of Object.entries(workspace.config?.profiles ?? {})) {
    try {
      if (!isObject(profile) || mappingProfileDigest(id, profile as AebPinnedProfile) !== profile.profile_digest) reasons.push(`mapping_profile_pin_drift:${id}`);
    } catch { reasons.push(`mapping_profile_pin_drift:${id}`); }
  }
  const registry = workspace.config?.registry;
  try {
    if (!isObject(registry) || unifiedRegistryDigest(registry as AebUnifiedRegistry) !== registry.registry_digest) reasons.push('registry_pin_drift');
    else for (const [id, entry] of Object.entries(registry.entries ?? {})) {
      if (!isObject(entry) || registryEntryDigest(id, entry as AebRegistryEntry) !== entry.definition_digest) reasons.push(`registry_entry_pin_drift:${id}`);
    }
  } catch { reasons.push('registry_pin_drift'); }
  if (workspace.config?.evaluator_keys?.[LAB_EVALUATOR_KEY_ID]?.public_key !== LAB_EVALUATOR_PUBLIC_SPKI) {
    reasons.push('lab_evaluator_key_not_pinned');
  }
  return reasons.sort();
}

function permissionFlag(): string {
  // Older permission-model releases did not govern network access. Refuse
  // custom adapter execution unless the runtime recognizes --allow-net, then
  // intentionally omit that permission from the child.
  if (!process.allowedNodeEnvironmentFlags.has('--allow-net')) {
    throw new Error('Crossing Lab requires a Node permission runtime with --allow-net support');
  }
  if (process.allowedNodeEnvironmentFlags.has('--permission')) return '--permission';
  if (process.allowedNodeEnvironmentFlags.has('--experimental-permission')) return '--experimental-permission';
  throw new Error('Crossing Lab requires the Node permission model');
}

function invokeAdapter(
  adapterBytes: Buffer,
  adapterDigest: Digest,
  method: 'verifyNative' | 'mapAction',
  input: unknown,
): Obj {
  const workerPath = fileURLToPath(new URL('./crossing-lab-worker.js', import.meta.url));
  const child = spawnSync(process.execPath, [
    permissionFlag(),
    `--allow-fs-read=${workerPath}`,
    workerPath,
  ], {
    input: JSON.stringify({
      method,
      input,
      adapter_source_base64: adapterBytes.toString('base64'),
      adapter_digest: adapterDigest,
    }),
    encoding: 'utf8',
    timeout: CROSSING_LAB_LIMITS.adapter_timeout_ms,
    maxBuffer: CROSSING_LAB_LIMITS.max_adapter_output_bytes,
    env: {},
    cwd: dirname(workerPath),
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  if (child.error) throw new Error(`adapter worker failed: ${child.error.message}`);
  if (child.status !== 0) throw new Error(`adapter worker refused: ${(child.stderr || '').trim() || `exit ${child.status}`}`);
  const parsed = parseStrictJson(child.stdout, 'adapter output');
  if (!isObject(parsed) || !exactKeys(parsed, ['adapter_id', 'adapter_version', 'results'])
      || !Array.isArray(parsed.results) || parsed.results.length !== 2) {
    throw new TypeError('malformed adapter worker output');
  }
  if (canonicalizeCrossingLab(parsed.results[0]) !== canonicalizeCrossingLab(parsed.results[1])) {
    throw new TypeError(`${method} is not deterministic for identical pinned input`);
  }
  return {
    adapter_id: parsed.adapter_id,
    adapter_version: parsed.adapter_version,
    result: parsed.results[0],
  };
}

function closeAdapterResult(method: 'verifyNative' | 'mapAction', value: unknown): unknown {
  if (!isObject(value)) throw new TypeError(`${method} returned a non-object`);
  const allowed = method === 'verifyNative'
    ? new Set(['native_verification', 'acceptance', 'evidence_digest', 'status_digest', 'evidence_role', 'subject', 'replay_unit', 'evidence_bindings', 'reasons'])
    : new Set(['mapping', 'caid', 'action_digest', 'reasons']);
  const unknown = Object.keys(value).filter((key) => !allowed.has(key));
  if (unknown.length > 0) throw new TypeError(`${method} returned unknown members: ${unknown.sort().join(',')}`);
  return value;
}

function proxyAdapter(workspace: Obj, adapterBytes: Buffer, transform?: {
  native?: (value: unknown) => unknown;
  mapping?: (value: unknown) => unknown;
}): AebAdapter {
  const invoke = (method: 'verifyNative' | 'mapAction', input: unknown): unknown => {
    const envelope = invokeAdapter(adapterBytes, workspace.adapter.module_digest, method, input);
    if (envelope.adapter_id !== workspace.adapter.id || envelope.adapter_version !== workspace.adapter.version) {
      throw new TypeError('adapter identity/version differs from workspace pin');
    }
    const result = method === 'verifyNative'
      ? (transform?.native ? transform.native(envelope.result) : envelope.result)
      : (transform?.mapping ? transform.mapping(envelope.result) : envelope.result);
    return closeAdapterResult(method, result);
  };
  return {
    id: workspace.adapter.id,
    version: workspace.adapter.version,
    verifyNative(input) { return invoke('verifyNative', input) as AebNativeResult; },
    mapAction(input) { return invoke('mapAction', input) as ReturnType<AebAdapter['mapAction']>; },
  };
}

function configWithTrustRoots(config: AebPinnedConfig, adapterId: string, trustRoots: unknown[]): AebPinnedConfig {
  const clone = structuredClone(config);
  const current = clone.adapters[adapterId];
  const pin: AebPinnedAdapter = { ...current, trust_roots: trustRoots, config_digest: current.config_digest };
  pin.config_digest = adapterPinDigest(adapterId, pin);
  clone.adapters[adapterId] = pin;
  return clone;
}

function evaluate(
  workspace: Obj,
  artifact: unknown,
  adapter: AebAdapter,
  overrides: { config?: AebPinnedConfig; expectedAction?: unknown; status?: AebStatusInput; artifactRef?: string } = {},
): ReturnType<typeof evaluateAebEvidence> {
  return evaluateAebEvidence({
    config: overrides.config ?? workspace.config,
    adapters: { [workspace.adapter.id]: adapter },
    operation_id: workspace.evaluation.operation_id,
    consumption_nonce: workspace.evaluation.consumption_nonce,
    initiator_id: workspace.evaluation.initiator_id,
    executor_id: workspace.evaluation.executor_id,
    requirement_ref: workspace.evaluation.requirement_ref,
    caid: workspace.evaluation.caid,
    expected_action: overrides.expectedAction ?? workspace.expected_action,
    legs: [{
      adapter_id: workspace.adapter.id,
      profile_id: workspace.evaluation.profile_id,
      artifact_ref: overrides.artifactRef ?? workspace.evaluation.artifact_ref,
      artifact,
      status: overrides.status ?? workspace.evaluation.status,
    }],
    evaluated_at: workspace.evaluated_at,
    signer: { key_id: LAB_EVALUATOR_KEY_ID, private_key: LAB_EVALUATOR_PRIVATE },
  });
}

function axes(result: ReturnType<typeof evaluateAebEvidence>): CrossingLabAxes {
  const leg = result.record.legs[0];
  const freshness: CrossingLabAxes['freshness'] = !leg
    ? 'INDETERMINATE'
    : leg.freshness.unavailable
      ? 'UNAVAILABLE'
      : leg.freshness.revoked
        ? 'REVOKED'
        : leg.freshness.consumed
          ? 'CONSUMED'
          : leg.freshness.fresh
            ? 'FRESH'
            : leg.reasons.some((reason) => reason === 'status_stale' || reason === 'evidence_expired')
              ? 'STALE'
              : 'INDETERMINATE';
  return {
    native_verification: leg?.native_verification ?? 'INDETERMINATE',
    acceptance: leg?.acceptance ?? 'INDETERMINATE',
    mapping: leg?.mapping ?? 'INDETERMINATE',
    freshness,
    satisfaction: result.record.verdict,
  };
}

const EXPECTATIONS: Record<CrossingLabExpectationRule, CrossingLabExpectation> = {
  POSITIVE_SATISFIED: {
    rule: 'POSITIVE_SATISFIED',
    description: 'VERIFIED, ACCEPTED, MATCH, FRESH, SATISFIED, and a valid evaluation',
  },
  ACTION_SUBSTITUTION_SAFE: {
    rule: 'ACTION_SUBSTITUTION_SAFE',
    description: 'the changed material action is not MATCH, not SATISFIED, and not a valid positive evaluation',
  },
  TRUST_SUBSTITUTION_SAFE: {
    rule: 'TRUST_SUBSTITUTION_SAFE',
    description: 'substituted trust cannot remain VERIFIED, ACCEPTED, SATISFIED, or a valid positive evaluation',
  },
  STALE_STATUS_INDETERMINATE: {
    rule: 'STALE_STATUS_INDETERMINATE',
    description: 'stale status remains STALE and INDETERMINATE, regardless of where the native adapter detects it',
  },
  UNAVAILABLE_STATUS_INDETERMINATE: {
    rule: 'UNAVAILABLE_STATUS_INDETERMINATE',
    description: 'unavailable status remains UNAVAILABLE and INDETERMINATE, regardless of native decomposition',
  },
  REWRAPPED_REPLAY_IDENTITY_STABLE: {
    rule: 'REWRAPPED_REPLAY_IDENTITY_STABLE',
    description: 'a wrapper-only reference change preserves a valid positive evaluation and the native replay unit',
  },
};

function expectationPassed(
  rule: CrossingLabExpectationRule,
  actual: CrossingLabAdapterRow['actual'],
): boolean {
  switch (rule) {
    case 'POSITIVE_SATISFIED':
    case 'REWRAPPED_REPLAY_IDENTITY_STABLE':
      return actual.native_verification === 'VERIFIED'
        && actual.acceptance === 'ACCEPTED'
        && actual.mapping === 'MATCH'
        && actual.freshness === 'FRESH'
        && actual.satisfaction === 'SATISFIED'
        && actual.evaluation_valid;
    case 'ACTION_SUBSTITUTION_SAFE':
      return actual.mapping !== 'MATCH'
        && actual.satisfaction !== 'SATISFIED'
        && !actual.evaluation_valid;
    case 'TRUST_SUBSTITUTION_SAFE':
      return actual.native_verification !== 'VERIFIED'
        && actual.acceptance !== 'ACCEPTED'
        && actual.satisfaction !== 'SATISFIED'
        && !actual.evaluation_valid;
    case 'STALE_STATUS_INDETERMINATE':
      return actual.freshness === 'STALE'
        && actual.satisfaction === 'INDETERMINATE'
        && !actual.evaluation_valid;
    case 'UNAVAILABLE_STATUS_INDETERMINATE':
      return actual.freshness === 'UNAVAILABLE'
        && actual.satisfaction === 'INDETERMINATE'
        && !actual.evaluation_valid;
  }
}

function adapterRow(
  id: string,
  category: CrossingLabAdapterRow['category'],
  rule: CrossingLabExpectationRule,
  result: ReturnType<typeof evaluateAebEvidence>,
): CrossingLabAdapterRow {
  const actual = { ...axes(result), evaluation_valid: result.valid };
  return {
    id,
    category,
    passed: expectationPassed(rule, actual),
    expected: EXPECTATIONS[rule],
    actual,
    reasons: result.record.reasons,
    evaluation: result.record,
  };
}

function harnessSelfTests(
  workspace: Obj,
  artifact: unknown,
  adapterBytes: Buffer,
): CrossingLabHarnessSelfTest[] {
  const malformedNative = evaluate(workspace, artifact, proxyAdapter(workspace, adapterBytes, {
    native: (value) => isObject(value) ? { ...value, unknown_member: true } : value,
  }));
  const malformedMapping = evaluate(workspace, artifact, proxyAdapter(workspace, adapterBytes, {
    mapping: (value) => isObject(value) ? { ...value, unknown_member: true } : value,
  }));
  const duplicate = strictJsonGate('{"a":1,"a":2}');
  const drift = workspacePinErrors({ ...workspace, artifact_digest: `sha256:${'0'.repeat(64)}` }, artifact, adapterBytes);
  return [
    {
      id: 'harness-refuses-unknown-native-output',
      passed: malformedNative.record.legs[0]?.reasons.includes('adapter_evaluation_error') === true && malformedNative.valid === false,
      observed: malformedNative.record.legs[0]?.reasons.join(',') ?? 'missing_leg',
    },
    {
      id: 'harness-refuses-unknown-mapping-output',
      passed: malformedMapping.record.legs[0]?.reasons.includes('adapter_evaluation_error') === true && malformedMapping.valid === false,
      observed: malformedMapping.record.legs[0]?.reasons.join(',') ?? 'missing_leg',
    },
    {
      id: 'strict-json-refuses-duplicate-members',
      passed: duplicate.ok === false,
      observed: duplicate.ok ? 'unexpectedly_accepted' : duplicate.reason,
    },
    {
      id: 'workspace-pin-drift-refused-before-adapter',
      passed: drift.includes('artifact_pin_drift'),
      observed: drift.join(','),
    },
  ];
}

export function runCrossingLab(workspaceDirectory: string): CrossingLabReport {
  // Fail as an operational runtime error before constructing any adapter row.
  // Node permission releases without --allow-net do not govern network access,
  // so treating their failure as adapter evidence would blame valid adapters.
  permissionFlag();
  const rootStat = lstatSync(workspaceDirectory);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw new TypeError('workspace must be a non-symlink directory');
  const root = realpathSync(workspaceDirectory);
  const workspacePath = assertDirectFile(root, 'workspace.json', CROSSING_LAB_LIMITS.max_file_bytes);
  const workspace = parseStrictJson(readFileSync(workspacePath, 'utf8'), 'workspace.json');
  validateWorkspace(workspace);
  const artifactPath = assertDirectFile(root, workspace.artifact, CROSSING_LAB_LIMITS.max_file_bytes);
  const adapterPath = assertDirectFile(root, workspace.adapter.module, CROSSING_LAB_LIMITS.max_adapter_bytes);
  const artifact = parseStrictJson(readFileSync(artifactPath, 'utf8'), workspace.artifact);
  const adapterBytes = readFileSync(adapterPath);
  const pinErrors = workspacePinErrors(workspace, artifact, adapterBytes);
  if (pinErrors.length > 0) throw new TypeError(`workspace pin verification failed: ${pinErrors.join(',')}`);

  // Every adapter invocation receives this one verified byte sequence. The
  // mutable workspace path is never imported after its digest is checked.
  const adapter = proxyAdapter(workspace, adapterBytes);
  const positive = evaluate(workspace, artifact, adapter);
  const substituted = evaluate(workspace, artifact, adapter, { expectedAction: workspace.hostile_expected_action });
  const untrustedConfig = configWithTrustRoots(workspace.config, workspace.adapter.id, [{ key_id: 'untrusted:root' }]);
  const trustSubstitution = evaluate(workspace, artifact, adapter, { config: untrustedConfig });
  const evaluatedMs = Date.parse(workspace.evaluated_at);
  const configuredMaxAge = workspace.config.adapters[workspace.adapter.id]?.max_status_age_sec;
  const staleAgeSeconds = Number.isInteger(configuredMaxAge) && configuredMaxAge >= 0 ? configuredMaxAge + 60 : 60;
  const stale = evaluate(workspace, artifact, adapter, {
    status: {
      ...workspace.evaluation.status,
      checked_at: new Date(evaluatedMs - staleAgeSeconds * 1_000).toISOString(),
      expires_at: new Date(evaluatedMs + 60_000).toISOString(),
    },
  });
  const unavailable = evaluate(workspace, artifact, adapter, {
    status: { ...workspace.evaluation.status, unavailable: true },
  });
  const rewrapped = evaluate(workspace, artifact, adapter, {
    artifactRef: `${workspace.evaluation.artifact_ref}:rewrapped`,
  });

  const adapterRows: CrossingLabAdapterRow[] = [
    adapterRow('native-artifact-through', 'positive', 'POSITIVE_SATISFIED', positive),
    adapterRow('exact-action-substitution-refused', 'hostile', 'ACTION_SUBSTITUTION_SAFE', substituted),
    adapterRow('trust-root-substitution-refused', 'hostile', 'TRUST_SUBSTITUTION_SAFE', trustSubstitution),
    adapterRow('stale-status-is-indeterminate', 'boundary', 'STALE_STATUS_INDETERMINATE', stale),
    adapterRow('unavailable-status-is-indeterminate', 'boundary', 'UNAVAILABLE_STATUS_INDETERMINATE', unavailable),
  ];
  const replayRow = adapterRow(
    'replay-identity-is-wrapper-independent',
    'hostile',
    'REWRAPPED_REPLAY_IDENTITY_STABLE',
    rewrapped,
  );
  const positiveReplayUnit = positive.record.legs[0]?.replay_unit;
  const rewrappedReplayUnit = rewrapped.record.legs[0]?.replay_unit;
  if (!positiveReplayUnit || positiveReplayUnit !== rewrappedReplayUnit) {
    replayRow.passed = false;
    replayRow.reasons = [...new Set([...replayRow.reasons, 'replay_unit_changed_across_wrapper'])].sort();
  }
  adapterRows.push(replayRow);
  const selfTests = harnessSelfTests(workspace, artifact, adapterBytes);
  const body = {
    '@version': CROSSING_LAB_REPORT_VERSION,
    workspace_digest: digestCrossingLab(workspace),
    adapter: { id: workspace.adapter.id, version: workspace.adapter.version, module_digest: workspace.adapter.module_digest },
    evaluated_at: workspace.evaluated_at,
    adapter_rows: adapterRows,
    harness_self_tests: selfTests,
    summary: {
      adapter_rows: adapterRows.length,
      passed: adapterRows.filter((entry) => entry.passed).length,
      failed: adapterRows.filter((entry) => !entry.passed).length,
      harness_passed: selfTests.filter((entry) => entry.passed).length,
      harness_failed: selfTests.filter((entry) => !entry.passed).length,
    },
    lab_passed: positive.valid && adapterRows.every((entry) => entry.passed) && selfTests.every((entry) => entry.passed),
    assurance: {
      self_attested: true as const,
      certification: false as const,
      statement: CROSSING_LAB_STATEMENT,
      evaluator_key_id: LAB_EVALUATOR_KEY_ID as typeof LAB_EVALUATOR_KEY_ID,
      evaluator_key_purpose: 'PUBLIC_FIXED_SELF_TEST_KEY_NO_ATTRIBUTION' as const,
    },
    non_claims: [
      'authorization', 'certification', 'deployment_evidence', 'execution_evidence',
      'independent_attestation', 'native_specification_correctness', 'native_protocol_equivalence',
    ] as const,
  };
  return { ...body, report_digest: digestCrossingLab(body) };
}

const SAMPLE_MAPPING_DEFINITION = Object.freeze({
  '@version': 'EXAMPLE-PAYMENT-RELEASE-CAID-MAPPING-v1',
  native_protocol: 'EXAMPLE-NATIVE-APPROVAL-v1',
  projection: 'native-action-v1',
  action_type: 'payment.release.1',
  suite: 'jcs-sha256',
  definitions: [{
    action_type: 'payment.release.1',
    required_fields: [
      { name: 'action_type', type: 'string' },
      { name: 'amount', type: 'amount-string' },
      { name: 'currency', type: 'string' },
      { name: 'payee_ref', type: 'string' },
    ],
    optional_fields: [],
  }],
});

// Generate a genuine one-file adapter bundle by embedding the exact governed
// CAID runtime shipped in this package. External authors can replace this file
// with their own bundle; the Lab pins and executes only its exact bytes.
const SAMPLE_CAID_REFERENCE_SOURCE = readFileSync(
  fileURLToPath(new URL('../vendor/caid.mjs', import.meta.url)),
  'utf8',
);
const SAMPLE_ADAPTER = `// SPDX-License-Identifier: Apache-2.0
${SAMPLE_CAID_REFERENCE_SOURCE}

import crypto from 'node:crypto';

const EXPECTED_DEFINITION = Object.freeze(${JSON.stringify(SAMPLE_MAPPING_DEFINITION)});
function jcs(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('non-finite native JSON number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return '[' + value.map(jcs).join(',') + ']';
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + jcs(value[key])).join(',') + '}';
  }
  throw new TypeError('native value is not JSON');
}
function digest(value) {
  return 'sha256:' + crypto.createHash('sha256').update(jcs(value), 'utf8').digest('hex');
}
function normalizedStatus(status) {
  return {
    checked_at: status.checked_at,
    expires_at: status.expires_at,
    revocation_checked: status.revocation_checked,
    revoked: status.revoked,
    consumed: status.consumed,
    unavailable: status.unavailable === true,
  };
}
function nativeBody(artifact) {
  const { signature, ...body } = artifact;
  return body;
}

export default Object.freeze({
  id: 'example:native-approval',
  version: '1.0.0',
  verifyNative(input) {
    const root = input.trust_roots.find((candidate) => candidate
      && candidate.key_id === input.artifact.issuer_key_id
      && candidate.algorithm === 'Ed25519'
      && typeof candidate.public_key === 'string');
    let signatureVerified = false;
    try {
      const publicKey = crypto.createPublicKey({
        key: Buffer.from(root.public_key, 'base64url'), format: 'der', type: 'spki',
      });
      signatureVerified = publicKey.asymmetricKeyType === 'ed25519'
        && typeof input.artifact.signature === 'string'
        && crypto.verify(
          null,
          Buffer.from(jcs(nativeBody(input.artifact)), 'utf8'),
          publicKey,
          Buffer.from(input.artifact.signature, 'base64url'),
        );
    } catch {}
    const trusted = signatureVerified;
    const unavailable = input.status.unavailable === true;
    return {
      native_verification: trusted ? 'VERIFIED' : 'FAILED',
      acceptance: trusted ? (unavailable ? 'INDETERMINATE' : 'ACCEPTED') : 'REJECTED',
      evidence_digest: digest(input.artifact),
      status_digest: digest(normalizedStatus(input.status)),
      evidence_role: 'human-authorization',
      subject: { id: input.artifact.subject_id, kind: 'human' },
      replay_unit: digest({ protocol: 'example-native', native_id: input.artifact.native_id }),
      reasons: trusted
        ? (unavailable ? ['status_unavailable'] : [])
        : ['native_signature_invalid'],
    };
  },
  mapAction(input) {
    if (input.native.native_verification !== 'VERIFIED') {
      return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['native_verification_required'] };
    }
    const expectedResolverDigest = digest({ implementation: 'example:payment-release-resolver', version: '1.0.0' });
    const profileValid = input.profile
      && input.profile.version === '1.0.0'
      && input.profile.mapper_id === 'example:payment-release-mapper'
      && input.profile.resolver.id === 'example:payment-release-resolver'
      && input.profile.resolver.version === '1.0.0'
      && input.profile.resolver.implementation_digest === expectedResolverDigest
      && jcs(input.profile.definition) === jcs(EXPECTED_DEFINITION)
      && input.profile.semantic_equivalence.assertion === 'EQUIVALENT_UNDER_PROFILE'
      && input.profile.semantic_equivalence.loss_policy === 'NO_MATERIAL_FIELD_LOSS'
      && input.profile.semantic_equivalence.omitted_material_fields.length === 0
      && input.profile.semantic_equivalence.omitted_nonmaterial_fields.length === 0;
    if (!profileValid || input.artifact.action.action_type !== EXPECTED_DEFINITION.action_type) {
      return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_profile_not_supported'] };
    }
    const computed = computeCaid(input.artifact.action, {
      suite: EXPECTED_DEFINITION.suite,
      definitions: EXPECTED_DEFINITION.definitions,
    });
    if (!computed || typeof computed.caid !== 'string' || typeof computed.digest !== 'string') {
      return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['caid_mapping_failed'] };
    }
    return { mapping: 'MATCH', caid: computed.caid, action_digest: computed.digest, reasons: [] };
  },
});
`;

function registryEntry(id: string, kind: AebRegistryEntry['kind'], definition: unknown): AebRegistryEntry {
  const entry: AebRegistryEntry = { kind, version: '1', status: 'active', definition, definition_digest: digestAeb(null) };
  entry.definition_digest = registryEntryDigest(id, entry);
  return entry;
}

function sampleAebConfig(): AebPinnedConfig {
  const profileId = 'example:payment-release';
  const profile: AebPinnedProfile = {
    version: '1.0.0',
    definition: structuredClone(SAMPLE_MAPPING_DEFINITION),
    registry_entry_ref: 'mapping:example:payment-release',
    mapper_id: 'example:payment-release-mapper',
    resolver: {
      id: 'example:payment-release-resolver',
      version: '1.0.0',
      implementation_digest: digestAeb({ implementation: 'example:payment-release-resolver', version: '1.0.0' }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [],
    },
    profile_digest: digestAeb(null),
  };
  profile.profile_digest = mappingProfileDigest(profileId, profile);
  const entries = {
    'mapping:example:payment-release': registryEntry('mapping:example:payment-release', 'mapping-profile', { profile_digest: profile.profile_digest }),
    'role:human-authorization': registryEntry('role:human-authorization', 'evidence-role', { role: 'human-authorization', subject_kinds: ['human'] }),
  };
  const registry: AebPinnedConfig['registry'] = {
    '@version': 'EP-EVIDENCE-REGISTRY-v1',
    registry_id: 'registry:crossing-lab-example',
    epoch: 1,
    entries,
    registry_digest: digestAeb(null),
  };
  registry.registry_digest = unifiedRegistryDigest(registry);
  const adapterId = 'example:native-approval';
  const pin: AebPinnedAdapter = {
    version: '1.0.0',
    trust_roots: [{ key_id: 'issuer:example:001', algorithm: 'Ed25519', public_key: SAMPLE_NATIVE_PUBLIC_SPKI }],
    config: { mode: 'offline-example' },
    config_digest: digestAeb(null),
    max_status_age_sec: 300,
  };
  pin.config_digest = adapterPinDigest(adapterId, pin);
  return {
    '@version': 'AEB-ADAPTER-v1',
    relying_party_id: 'rp:crossing-lab-example',
    evaluator_keys: { [LAB_EVALUATOR_KEY_ID]: { public_key: LAB_EVALUATOR_PUBLIC_SPKI } },
    registry,
    accepted_mappers: [profile.mapper_id],
    adapters: { [adapterId]: pin },
    profiles: { [profileId]: profile },
    requirements: {
      'requirement:human-authorization': {
        '@version': 'AEB-REQUIREMENT-v1',
        all_of: ['human-authorization'],
        terms: [
          { type: 'initiator-exclusion', roles: ['human-authorization'] },
          { type: 'executor-exclusion', roles: ['human-authorization'] },
          { type: 'one-time-consumption' },
        ],
      },
    },
  };
}

export function initCrossingLab(targetDirectory: string): { directory: string; files: string[] } {
  const target = resolve(targetDirectory);
  if (existsSync(target)) throw new TypeError('refusing to overwrite an existing Crossing Lab workspace');
  const requestedParent = resolve(dirname(target));
  realpathSync(requestedParent);
  if (lstatSync(requestedParent).isSymbolicLink()) throw new TypeError('workspace parent must not be a symlink');
  mkdirSync(target, { mode: 0o700 });

  const action = { action_type: 'payment.release.1', amount: '500.00', currency: 'USD', payee_ref: 'vendor:example' };
  const hostileExpectedAction = { ...action, amount: '500.01' };
  const computed = computeCaid(action, {
    suite: SAMPLE_MAPPING_DEFINITION.suite,
    definitions: SAMPLE_MAPPING_DEFINITION.definitions,
  });
  if (!isObject(computed) || typeof computed.caid !== 'string' || typeof computed.digest !== 'string') {
    throw new Error('governed CAID implementation refused the Crossing Lab sample action');
  }
  const caid = computed.caid;
  const nativeBody = {
    '@version': 'EXAMPLE-NATIVE-APPROVAL-v1',
    native_id: 'approval:example:001',
    issuer_key_id: 'issuer:example:001',
    subject_id: 'human:alice',
    action,
  };
  const artifact = {
    ...nativeBody,
    signature: crypto.sign(
      null,
      Buffer.from(canonicalizeCrossingLab(nativeBody), 'utf8'),
      SAMPLE_NATIVE_PRIVATE,
    ).toString('base64url'),
  };
  const status: AebStatusInput & { unavailable: boolean } = {
    checked_at: '2027-01-15T07:59:00Z',
    expires_at: '2027-01-15T08:10:00Z',
    revocation_checked: true,
    revoked: false,
    consumed: false,
    unavailable: false,
  };
  const config = sampleAebConfig();
  const workspace = {
    '@version': CROSSING_LAB_WORKSPACE_VERSION,
    adapter: {
      id: 'example:native-approval',
      version: '1.0.0',
      module: 'adapter.mjs',
      module_digest: sha256Bytes(SAMPLE_ADAPTER),
    },
    artifact: 'artifact.json',
    artifact_digest: digestAeb(artifact),
    config,
    evaluated_at: '2027-01-15T08:00:00Z',
    evaluation: {
      operation_id: 'operation:crossing-lab:001',
      consumption_nonce: 'nonce:crossing-lab:001',
      initiator_id: 'agent:example',
      executor_id: 'executor:example',
      requirement_ref: 'requirement:human-authorization',
      profile_id: 'example:payment-release',
      artifact_ref: 'artifact:example-native:001',
      caid,
      status,
      status_digest: digestAeb(status),
    },
    expected_action: action,
    expected_action_digest: digestAeb(action),
    hostile_expected_action: hostileExpectedAction,
    hostile_expected_action_digest: digestAeb(hostileExpectedAction),
  };

  writeFileSync(resolve(target, 'adapter.mjs'), SAMPLE_ADAPTER, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  writeFileSync(resolve(target, 'artifact.json'), `${JSON.stringify(artifact, null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  writeFileSync(resolve(target, 'workspace.json'), `${JSON.stringify(workspace, null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  return { directory: target, files: ['adapter.mjs', 'artifact.json', 'workspace.json'] };
}

/**
 * Turn one owner-reviewed Scan selection into a deliberately unsealed Lab
 * workspace. The result is a bounded editing surface, not an executable
 * adapter: the operator must supply and review the native artifact, adapter,
 * trust roots, status source, relying party, and exact material values before
 * replacing the draft workspace with a sealable v1 workspace.
 */
export function initCrossingLabFromScanSeed(
  seedFile: string,
  targetDirectory: string,
): {
  directory: string;
  files: string[];
  profile_id: string;
  state: 'unsealed';
} {
  const seedPath = resolve(seedFile);
  const seedStat = lstatSync(seedPath);
  if (!seedStat.isFile() || seedStat.isSymbolicLink()) {
    throw new TypeError('Scan crossing seed must be a regular non-symlink file');
  }
  if (seedStat.nlink !== 1) throw new TypeError('Scan crossing seed must not be hard-linked');
  if (seedStat.size > CROSSING_LAB_LIMITS.max_file_bytes) throw new TypeError('Scan crossing seed exceeds file-size limit');
  assertNoUserSymlinkComponents(seedPath, 'Scan crossing seed path');
  const seedRoot = realpathSync(dirname(seedPath));
  const seedBytes = readFileSync(seedPath);
  const seed = parseStrictJson(seedBytes.toString('utf8'), basename(seedPath));
  validateScanCrossingSeed(seed);
  verifySeedManifest(seedRoot, seed);

  const target = resolve(targetDirectory);
  if (existsSync(target)) throw new TypeError('refusing to overwrite an existing Crossing Lab workspace');
  const requestedParent = resolve(dirname(target));
  assertNoUserSymlinkComponents(requestedParent, 'workspace parent');
  if (lstatSync(requestedParent).isSymbolicLink()) throw new TypeError('workspace parent must not be a symlink');

  const seedDigest = sha256Bytes(seedBytes);
  const materialValues = Object.fromEntries(
    seed.selected_action.material_fields.map((field: string) => [field, null]),
  );
  const workspace = {
    '@version': CROSSING_LAB_DRAFT_WORKSPACE_VERSION,
    state: 'UNSEALED_OPERATOR_INPUT_REQUIRED',
    profile_id: seed.profile_id,
    profile_contract: structuredClone(seed.profile_contract),
    profile_compatibility: seed.profile_compatibility,
    verify_version: seed.verify_version,
    source_seed: {
      file: basename(seedPath),
      sha256: seedDigest,
      reviewed_manifest_sha256: seed.reviewed_manifest.sha256,
    },
    selected_action: structuredClone(seed.selected_action),
    material_values: materialValues,
    required_inputs: [...SCAN_REQUIRED_OPERATOR_INPUTS],
    next_step: 'Replace all draft inputs with the selected profile artifacts, then run crossing-lab seal and crossing-lab run.',
    non_claims: [
      'authorization',
      'adapter_compatibility',
      'native_verification',
      'production_enforcement',
      'execution_evidence',
    ],
  };
  const artifact = {
    '@version': 'EP-AEB-CROSSING-LAB-NATIVE-DRAFT-v1',
    profile_id: seed.profile_id,
    profile_compatibility: seed.profile_compatibility,
    source_seed_sha256: seedDigest,
    native_artifact: null,
    status: 'operator_input_required',
  };
  const adapter = `// SPDX-License-Identifier: Apache-2.0
// Generated from an owner-reviewed Scan selection. This draft adapter refuses
// until the selected native profile is installed and reviewed.
const refuse = () => { throw new Error('scan_crossing_workspace_unsealed'); };
export default Object.freeze({
  id: ${JSON.stringify(`scan:${seed.profile_id}:pending`)},
  version: '0.0.0-draft',
  verifyNative: refuse,
  mapAction: refuse,
});
`;

  // Never roll back by pathname: a same-user concurrent process could replace
  // the just-created path between a failed write and cleanup. A rare partial
  // directory remains invalid and blocks reuse until the operator inspects it.
  mkdirSync(target, { mode: 0o700 });
  writeFileSync(resolve(target, 'adapter.mjs'), adapter, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  writeFileSync(resolve(target, 'artifact.json'), `${JSON.stringify(artifact, null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  writeFileSync(resolve(target, 'workspace.json'), `${JSON.stringify(workspace, null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  return {
    directory: target,
    files: ['adapter.mjs', 'artifact.json', 'workspace.json'],
    profile_id: seed.profile_id,
    state: 'unsealed',
  };
}

function recomputeConfigPins(config: AebPinnedConfig): void {
  for (const [id, pin] of Object.entries(config.adapters)) pin.config_digest = adapterPinDigest(id, pin);
  for (const [id, profile] of Object.entries(config.profiles)) profile.profile_digest = mappingProfileDigest(id, profile);
  for (const profile of Object.values(config.profiles)) {
    const entry = config.registry.entries[profile.registry_entry_ref];
    if (entry?.kind === 'mapping-profile' && isObject(entry.definition)) {
      entry.definition = { ...entry.definition, profile_digest: profile.profile_digest };
    }
  }
  for (const [id, entry] of Object.entries(config.registry.entries)) {
    entry.definition_digest = registryEntryDigest(id, entry);
  }
  config.registry.registry_digest = unifiedRegistryDigest(config.registry);
}

/**
 * Recompute local development pins after the author deliberately edits a
 * workspace. This does not validate native semantics, trust choices, or
 * material-field selection and never executes adapter code.
 */
export function sealCrossingLab(workspaceDirectory: string): { workspace_digest: Digest } {
  const rootStat = lstatSync(workspaceDirectory);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw new TypeError('workspace must be a non-symlink directory');
  const root = realpathSync(workspaceDirectory);
  const workspacePath = assertDirectFile(root, 'workspace.json', CROSSING_LAB_LIMITS.max_file_bytes);
  const parsed = parseStrictJson(readFileSync(workspacePath, 'utf8'), 'workspace.json');
  validateWorkspace(parsed);
  const workspace = structuredClone(parsed);
  const artifactPath = assertDirectFile(root, workspace.artifact, CROSSING_LAB_LIMITS.max_file_bytes);
  const adapterPath = assertDirectFile(root, workspace.adapter.module, CROSSING_LAB_LIMITS.max_adapter_bytes);
  const artifact = parseStrictJson(readFileSync(artifactPath, 'utf8'), workspace.artifact);
  const adapterBytes = readFileSync(adapterPath);

  recomputeConfigPins(workspace.config);
  workspace.adapter.module_digest = sha256Bytes(adapterBytes);
  workspace.artifact_digest = digestAeb(artifact);
  workspace.expected_action_digest = digestAeb(workspace.expected_action);
  workspace.hostile_expected_action_digest = digestAeb(workspace.hostile_expected_action);
  workspace.evaluation.status = normalizeStatusInput(workspace.evaluation.status);
  workspace.evaluation.status_digest = digestAeb(workspace.evaluation.status);
  const pinErrors = workspacePinErrors(workspace, artifact, adapterBytes);
  if (pinErrors.length > 0) throw new TypeError(`refusing to seal invalid workspace: ${pinErrors.join(',')}`);

  const temporary = resolve(root, `.workspace.json.seal-${process.pid}-${crypto.randomUUID()}`);
  let temporaryCreated = false;
  try {
    writeFileSync(temporary, `${JSON.stringify(workspace, null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    temporaryCreated = true;
    renameSync(temporary, workspacePath);
    temporaryCreated = false;
  } finally {
    if (temporaryCreated && existsSync(temporary)) unlinkSync(temporary);
  }
  return { workspace_digest: digestCrossingLab(workspace) };
}

export function writeCrossingLabReport(path: string, report: CrossingLabReport): void {
  writeFileSync(path, `${JSON.stringify(report, null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
}
