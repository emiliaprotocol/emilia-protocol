// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto, { type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';

// The CAID reference implementation intentionally has no TypeScript surface.
// @ts-expect-error -- independently cross-checked in this test.
import { computeCaid } from './vendor/caid.mjs';
import {
  AEB_ADAPTER_VERSION,
  AEB_REGISTRY_VERSION,
  AEB_REQUIREMENT_VERSION,
  InMemoryAebConsumptionStore,
  adapterPinDigest,
  authorizeAebExecution,
  digestAeb,
  evaluateAebEvidence,
  mappingProfileDigest,
  reconcileAebExecution,
  registryEntryDigest,
  unifiedRegistryDigest,
  verifyAebEvaluation,
  type AebAdapter,
  type AebAdapterInput,
  type AebPinnedAdapter,
  type AebPinnedConfig,
  type AebPinnedProfile,
  type AebRegistryEntry,
} from './aeb-adapter-contract.js';
import {
  CCS_AEB_ADAPTER_ID,
  CCS_AEB_ADAPTER_VERSION,
  CCS_AEB_CONFIG_VERSION,
  CCS_AEB_TRUST_ROOT_VERSION,
  CCS_CAID_MAPPER_ID,
  CCS_CAID_MAPPING_VERSION,
  CCS_PYPI_ARTIFACT_VERSION,
  CCS_PYPI_DISTRIBUTION_VERSION,
  CCS_PYPI_RUNTIME_VERSION,
  CCS_L1_AEB_ADAPTER_ID,
  CCS_L1_AEB_ADAPTER_VERSION,
  CCS_L1_AEB_CONFIG_VERSION,
  CCS_L1_AEB_TRUST_ROOT_VERSION,
  CCS_L1_CAID_MAPPER_ID,
  CCS_L1_CAID_MAPPING_VERSION,
  CCS_L1_PYPI_DISTRIBUTION_VERSION,
  CCS_L1_PYPI_SDIST_SHA256,
  CCS_L1_PYPI_SOURCE_LOCK,
  CCS_L1_PYPI_WHEEL_SHA256,
  CCS_L1_REFERENCE_VECTOR_SHA256,
  CCS_V13_AEB_ADAPTER_ID,
  CCS_V13_AEB_CONFIG_VERSION,
  CCS_V13_AEB_TRUST_ROOT_VERSION,
  CCS_V13_CAID_MAPPER_ID,
  CCS_V13_CAID_MAPPING_VERSION,
  CCS_V13_DRAFT_SHA256,
  CCS_V13_SOURCE_LOCK,
  createCcsV13AebActionDefinition,
  createCcsV13AebAdapter,
  createCcsL1AebActionDefinition,
  createCcsPyPiL1AebAdapter,
  createCcsAebActionDefinition,
  createCcsNativeActionDefinition,
  createCcsPyPiHmacAebAdapter,
  type CcsAebAdapterConfig,
  type CcsAebHmacTrustRoot,
  type CcsL1AebAdapterConfig,
  type CcsL1Ed25519TrustRoot,
  type CcsL1Receipt,
  type CcsV13AebAdapterConfig,
  type CcsV13Ed25519TrustRoot,
  type CcsV13Receipt,
  type CcsPyPiArtifact,
} from './aeb-ccs-adapter.js';

const NOW = '2026-08-10T19:00:00Z';
const NOW_SECONDS = Date.parse(NOW) / 1000;
const ACTION_TYPE = 'agent.tool-invocation.1';
const ISSUER = 'https://ccs.example/verifier';
const AUDIENCE = 'https://gate.example/admit';
const SECRET = Buffer.from('ccs-aeb-public-test-secret-32-bytes!!', 'utf8');
const PACKAGE_FIXTURE = JSON.parse(readFileSync(
  new URL('../../interop/ccs-aeb/fixtures/ccs-verifier-pypi-1.1.0.json', import.meta.url),
  'utf8',
)) as CcsPyPiArtifact;
const L1_VECTOR = JSON.parse(readFileSync(
  new URL('../../interop/ccs-aeb/fixtures/ccs-verifier-pypi-1.1.14-reference-signed-001.json', import.meta.url),
  'utf8',
)) as {
  package_version: string;
  public_key_fingerprint_sha256_16: string;
  public_key_raw_b64: string;
  receipt: CcsL1Receipt;
};

function spki(key: KeyObject): string {
  return key.export({ type: 'spki', format: 'der' }).toString('base64url');
}

function canonicalPythonSubset(value: unknown): string {
  function normalize(item: any): any {
    if (Array.isArray(item)) return item.map(normalize);
    if (item !== null && typeof item === 'object') {
      return Object.fromEntries(Object.keys(item).sort().map((key) => [key, normalize(item[key])]));
    }
    return item;
  }
  return JSON.stringify(normalize(value));
}

function paramsHash(params: Record<string, unknown>): string {
  return crypto.createHash('sha256').update(canonicalPythonSubset(params), 'utf8').digest('hex').slice(0, 16);
}

function statusDigest(status: {
  checked_at: string;
  expires_at: string;
  revocation_checked: boolean;
  revoked: boolean;
  consumed: boolean;
  unavailable?: boolean;
}): ReturnType<typeof digestAeb> {
  return digestAeb({
    checked_at: status.checked_at,
    expires_at: status.expires_at,
    revocation_checked: status.revocation_checked,
    revoked: status.revoked,
    consumed: status.consumed,
    unavailable: status.unavailable === true,
  });
}

function ruleSummary(artifact: CcsPyPiArtifact): string {
  return artifact.result.rule_results.map((result) => `${result.rule_name}=${result.verdict}`).join('|');
}

function signArtifact(artifact: CcsPyPiArtifact, secret = SECRET): CcsPyPiArtifact {
  artifact.result.params_hash = paramsHash(artifact.command.params);
  artifact.result.receipt = crypto.createHmac('sha256', secret).update([
    artifact.result.trace_id,
    artifact.result.verdict,
    String(artifact.result.verified_at),
    artifact.result.tool,
    artifact.result.params_hash,
    ruleSummary(artifact),
  ].join(':'), 'utf8').digest('hex').slice(0, 32);
  return artifact;
}

function mintArtifact(overrides: {
  trace_id?: string;
  verdict?: 'allow' | 'deny' | 'escalate';
  tool?: string;
  params?: Record<string, unknown>;
  verified_at?: number;
} = {}): CcsPyPiArtifact {
  const artifact = structuredClone(PACKAGE_FIXTURE);
  const traceId = overrides.trace_id ?? artifact.command.trace_id;
  const verdict = overrides.verdict ?? artifact.result.verdict;
  const tool = overrides.tool ?? artifact.command.tool;
  const params = overrides.params ?? artifact.command.params;
  artifact.command.trace_id = traceId;
  artifact.command.tool = tool;
  artifact.command.params = params;
  artifact.result.trace_id = traceId;
  artifact.result.verdict = verdict;
  artifact.result.block_reason = verdict === 'allow' ? '' : `${verdict} by policy`;
  artifact.result.rule_results = verdict === 'deny'
    ? [{ ...artifact.result.rule_results[0], verdict }]
    : artifact.result.rule_results.map((rule) => ({ ...rule, verdict }));
  artifact.result.verified_at = overrides.verified_at ?? artifact.result.verified_at;
  artifact.result.tool = tool;
  return signArtifact(artifact);
}

function profile(): AebPinnedProfile {
  const pin: AebPinnedProfile = {
    version: CCS_CAID_MAPPING_VERSION,
    definition: createCcsAebActionDefinition(ACTION_TYPE),
    registry_entry_ref: 'mapping:ccs-tool-invocation',
    mapper_id: CCS_CAID_MAPPER_ID,
    resolver: {
      id: CCS_CAID_MAPPER_ID,
      version: '1',
      implementation_digest: digestAeb({ implementation: CCS_CAID_MAPPER_ID, version: '1' }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [
        'command.agent_id', 'command.timestamp', 'command.trace_id',
        'result.block_reason', 'result.rule_results.reason', 'result.rule_results.latency_us',
        'result.error_code',
      ],
    },
    profile_digest: digestAeb(null),
  };
  pin.profile_digest = mappingProfileDigest('ccs-tool-invocation', pin);
  return pin;
}

function nativeActionProfile(actionType: string): AebPinnedProfile {
  const pin: AebPinnedProfile = {
    version: CCS_CAID_MAPPING_VERSION,
    definition: createCcsNativeActionDefinition(actionType),
    registry_entry_ref: 'mapping:ccs-native-action',
    mapper_id: CCS_CAID_MAPPER_ID,
    resolver: {
      id: CCS_CAID_MAPPER_ID,
      version: '1',
      implementation_digest: digestAeb({ implementation: CCS_CAID_MAPPER_ID, version: '1' }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [
        'command.agent_id', 'command.timestamp', 'command.trace_id',
        'result.block_reason', 'result.rule_results.reason', 'result.rule_results.latency_us',
        'result.error_code',
      ],
    },
    profile_digest: digestAeb(null),
  };
  pin.profile_digest = mappingProfileDigest('ccs-native-action', pin);
  return pin;
}

function fixture() {
  const config: CcsAebAdapterConfig = {
    '@version': CCS_AEB_CONFIG_VERSION,
    evidence_role: 'machine-policy-decision',
    subject: { id: 'system:ccs-local-verifier', kind: 'system' },
    issuer: ISSUER,
    audience: AUDIENCE,
    action_type: ACTION_TYPE,
    allowed_tools: ['release_payment'],
    required_rules: ['ssrf_protection', 'rce_protection'],
    max_receipt_age_seconds: 60,
    params_hash_bits: 64,
    deployment_scope: 'single-relying-party-local-hmac',
  };
  const root: CcsAebHmacTrustRoot = {
    '@version': CCS_AEB_TRUST_ROOT_VERSION,
    issuer: ISSUER,
    audience: AUDIENCE,
    key_id: 'ccs-local-hmac-test-1',
    algorithm: 'HMAC-SHA256-TRUNC128',
    secret_base64url: SECRET.toString('base64url'),
  };
  const artifact = mintArtifact();
  const action = {
    action_type: ACTION_TYPE,
    parameters: { tool: artifact.command.tool, arguments: artifact.command.params },
  };
  const adapter = createCcsPyPiHmacAebAdapter({ config, trust_roots: [root] });
  const input = {
    artifact,
    artifact_ref: 'ccs:result:0011223344556677',
    status: {
      checked_at: NOW,
      expires_at: '2026-08-10T19:01:00Z',
      revocation_checked: true,
      revoked: false,
      consumed: false,
    },
    trust_roots: [root],
    adapter_config: config,
    expected_action: action,
    now: NOW,
  } satisfies Omit<AebAdapterInput, 'profile'>;
  return { config, root, artifact, action, adapter, input };
}

function l1Profile(actionType = ACTION_TYPE): AebPinnedProfile {
  const pin: AebPinnedProfile = {
    version: CCS_L1_CAID_MAPPING_VERSION,
    definition: createCcsL1AebActionDefinition(actionType),
    registry_entry_ref: 'mapping:ccs-l1-tool-action',
    mapper_id: CCS_L1_CAID_MAPPER_ID,
    resolver: {
      id: CCS_L1_CAID_MAPPER_ID,
      version: '1',
      implementation_digest: digestAeb({ implementation: CCS_L1_CAID_MAPPER_ID, version: '1' }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [
        'trace_id', 'timestamp', 'tool_call_id', 'params_hash', 'rule_summary',
        'request_hash', 'response_hash', 'runtime_context_hash', 'config_hash',
        'verifier_source_class', 'deployment_mode', 'nonce', 'sequence',
        'issued_at', 'expires_at', 'max_clock_skew', 'verified_at', 'latency_us',
      ],
    },
    profile_digest: digestAeb(null),
  };
  pin.profile_digest = mappingProfileDigest('ccs-l1-tool-action', pin);
  return pin;
}

function l1Fixture() {
  const config: CcsL1AebAdapterConfig = {
    '@version': CCS_L1_AEB_CONFIG_VERSION,
    evidence_role: 'machine-policy-decision',
    subject: { id: 'system:ccs-reference-verifier', kind: 'system' },
    issuer: 'ccs-verifier/reference',
    audience: 'public',
    action_type: ACTION_TYPE,
    allowed_actions: ['shell.execute'],
    allowed_tools: ['shell'],
    required_rule_version: '1.1.14',
    max_receipt_age_seconds: 300,
    max_clock_skew_seconds: 5,
    deployment_scope: 'pinned-ed25519-issuer',
  };
  const root: CcsL1Ed25519TrustRoot = {
    '@version': CCS_L1_AEB_TRUST_ROOT_VERSION,
    issuer: 'ccs-verifier/reference',
    key_id: 'ccs-reference-ed25519-1',
    algorithm: 'Ed25519',
    public_key_raw_base64: L1_VECTOR.public_key_raw_b64,
    public_key_fingerprint_sha256_16: L1_VECTOR.public_key_fingerprint_sha256_16,
  };
  const action = {
    action_type: ACTION_TYPE,
    parameters: {
      action: 'shell.execute',
      tool: 'shell',
      arguments: { command: 'echo reference' },
    },
  };
  const adapter = createCcsPyPiL1AebAdapter({ config, trust_roots: [root] });
  const input = {
    artifact: structuredClone(L1_VECTOR.receipt),
    artifact_ref: 'ccs:l1:reference-signed-001',
    status: {
      checked_at: '2030-01-01T00:02:00Z',
      expires_at: '2030-01-01T00:04:00Z',
      revocation_checked: true,
      revoked: false,
      consumed: false,
    },
    trust_roots: [root],
    adapter_config: config,
    expected_action: action,
    now: '2030-01-01T00:02:00Z',
  } satisfies Omit<AebAdapterInput, 'profile'>;
  return { config, root, action, adapter, input };
}

test('CCS 1.1.14 source lock pins the exact published PyPI artifacts', () => {
  assert.equal(CCS_L1_PYPI_DISTRIBUTION_VERSION, '1.1.14');
  assert.equal(CCS_L1_PYPI_SDIST_SHA256, '9f75676e5b3d6ace8e91742d8b78b6d15b2d4250414326c17cc9e1aa361ec318');
  assert.equal(CCS_L1_PYPI_WHEEL_SHA256, '04a7857253bac2fca25611d17280cebf92fd0a7a2987a4d7ece973d492b17c83');
  assert.equal(CCS_L1_REFERENCE_VECTOR_SHA256, '5260e619c010d36729c57c5e8814613215e65e09abfba8a6a1d93f07e919762f');
  assert.match(CCS_L1_PYPI_SOURCE_LOCK, /1\.1\.14/);
  assert.equal(L1_VECTOR.package_version, CCS_L1_PYPI_DISTRIBUTION_VERSION);
});

test('CCS 1.1.14 Ed25519 receipt verifies, is accepted under the pinned issuer, and maps one exact action', () => {
  const f = l1Fixture();
  assert.equal(f.adapter.id, CCS_L1_AEB_ADAPTER_ID);
  assert.equal(f.adapter.version, CCS_L1_AEB_ADAPTER_VERSION);
  const native = f.adapter.verifyNative(f.input);
  assert.equal(native.native_verification, 'VERIFIED', JSON.stringify(native));
  assert.equal(native.acceptance, 'ACCEPTED', JSON.stringify(native));
  assert.equal(native.evidence_role, 'machine-policy-decision');
  const mapped = f.adapter.mapAction({ ...f.input, profile: l1Profile(), native });
  assert.equal(mapped.mapping, 'MATCH', JSON.stringify(mapped));
  assert.equal(mapped.action_digest, digestAeb(f.action));
  assert.match(mapped.caid ?? '', /^caid:1:agent\.tool-invocation\.1:jcs-sha256:/);
});

test('CCS 1.1.14 signature, issuer pin, expiry, exact arguments, action, and tool fail independently', () => {
  const f = l1Fixture();

  const signatureTamper = structuredClone(f.input.artifact) as CcsL1Receipt;
  signatureTamper.signature = `${signatureTamper.signature[0] === 'A' ? 'B' : 'A'}${signatureTamper.signature.slice(1)}`;
  const invalidSignature = f.adapter.verifyNative({ ...f.input, artifact: signatureTamper });
  assert.equal(invalidSignature.native_verification, 'FAILED');
  assert.ok(invalidSignature.reasons.includes('ccs:l1_signature_invalid'));

  const fractionalButTampered = structuredClone(f.input.artifact) as CcsL1Receipt;
  fractionalButTampered.latency_us = 0.5;
  const fractionalResult = f.adapter.verifyNative({ ...f.input, artifact: fractionalButTampered });
  assert.ok(fractionalResult.reasons.includes('ccs:l1_signature_invalid'));

  const wrongRoot: CcsL1Ed25519TrustRoot = {
    ...f.root,
    public_key_raw_base64: Buffer.alloc(32, 7).toString('base64'),
    public_key_fingerprint_sha256_16: crypto.createHash('sha256').update(Buffer.alloc(32, 7)).digest('hex').slice(0, 16),
  };
  const wrongRootAdapter = createCcsPyPiL1AebAdapter({ config: f.config, trust_roots: [wrongRoot] });
  const untrusted = wrongRootAdapter.verifyNative({
    ...f.input,
    adapter_config: f.config,
    trust_roots: [wrongRoot],
  });
  assert.equal(untrusted.native_verification, 'VERIFIED');
  assert.equal(untrusted.acceptance, 'REJECTED');
  assert.ok(untrusted.reasons.includes('ccs:l1_untrusted_signing_key'));

  const expired = f.adapter.verifyNative({ ...f.input, now: '2030-01-01T00:05:01Z' });
  assert.equal(expired.native_verification, 'VERIFIED');
  assert.equal(expired.acceptance, 'REJECTED');
  assert.ok(expired.reasons.includes('ccs:l1_receipt_expired'));

  const native = f.adapter.verifyNative(f.input);
  for (const expected_action of [
    { ...f.action, parameters: { ...f.action.parameters, arguments: { command: 'echo substituted' } } },
    { ...f.action, parameters: { ...f.action.parameters, action: 'shell.delete' } },
    { ...f.action, parameters: { ...f.action.parameters, tool: 'delete_repository' } },
  ]) {
    const mapped = f.adapter.mapAction({ ...f.input, expected_action, profile: l1Profile(), native });
    assert.equal(mapped.mapping, 'MISMATCH', JSON.stringify(mapped));
  }
});

test('CCS 1.1.14 status uncertainty and presenter pin replacement never become accepted evidence', () => {
  const f = l1Fixture();
  const unavailable = f.adapter.verifyNative({
    ...f.input,
    status: { ...f.input.status, unavailable: true },
  });
  assert.equal(unavailable.native_verification, 'VERIFIED');
  assert.equal(unavailable.acceptance, 'INDETERMINATE');

  const replacedConfig = { ...f.config, audience: 'attacker' };
  const pinSwap = f.adapter.verifyNative({ ...f.input, adapter_config: replacedConfig });
  assert.equal(pinSwap.acceptance, 'REJECTED');
  assert.ok(pinSwap.reasons.includes('ccs:l1_constructor_pin_mismatch'));

  const native = f.adapter.verifyNative(f.input);
  const resolverSwap = l1Profile();
  resolverSwap.resolver.implementation_digest = digestAeb({ implementation: 'attacker', version: '1' });
  resolverSwap.profile_digest = mappingProfileDigest('ccs-l1-tool-action', resolverSwap);
  const relabeledResolver = f.adapter.mapAction({
    ...f.input,
    profile: resolverSwap,
    native,
  });
  assert.equal(relabeledResolver.mapping, 'INDETERMINATE');
  assert.ok(relabeledResolver.reasons.includes('mapping_profile_invalid'));

  const digestSwap = l1Profile();
  digestSwap.profile_digest = digestAeb({ profile: 'attacker' });
  const relabeledProfile = f.adapter.mapAction({
    ...f.input,
    profile: digestSwap,
    native,
  });
  assert.equal(relabeledProfile.mapping, 'INDETERMINATE');
  assert.ok(relabeledProfile.reasons.includes('mapping_profile_invalid'));
});

const V13_PRIVATE_KEY = crypto.createPrivateKey({
  key: Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    crypto.createHash('sha256').update('emilia/ccs-05-v1.3-independent-interop/v1').digest(),
  ]),
  format: 'der',
  type: 'pkcs8',
});
const V13_PUBLIC_KEY = crypto.createPublicKey(V13_PRIVATE_KEY);
const V13_PUBLIC_RAW = V13_PUBLIC_KEY.export({ type: 'spki', format: 'der' }).subarray(-32);

function v13Hash(value: unknown): string {
  return crypto.createHash('sha256').update(canonicalPythonSubset(value), 'utf8').digest('hex');
}

function mintV13Receipt(params = { left: 19, right: 23 }): CcsV13Receipt {
  const fullParamsHash = v13Hash(params);
  const unsigned: Omit<CcsV13Receipt, 'signature'> = {
    trace_id: '0123456789abcdef',
    verdict: 'allow',
    timestamp: 1_914_451_200,
    tool: 'sum',
    params_hash: fullParamsHash.slice(0, 16),
    rule_summary: 'bounded_integer_inputs=allow',
    receipt: '00112233445566778899aabbccddeeff',
    verified_at: 1_914_451_200,
    block_reason: '',
    request_hash: `sha256:${v13Hash({
      agent_id: 'agent:emilia-interop',
      params,
      timestamp: 1_914_451_200,
      tool: 'sum',
      trace_id: '0123456789abcdef',
    })}`,
    response_hash: `sha256:${v13Hash({ result: params.left + params.right })}`,
    runtime_context_hash: `sha256:${v13Hash({ environment: 'local-live-run', tenant: 'public-interop' })}`,
    action: `ccs:tool-invoke:sum:${fullParamsHash}`,
    config_hash: `sha256:${v13Hash({ policy_floor: 'bounded-integer-sum-v1' })}`,
    issuer: 'https://emilia-protocol.example/interop/ccs-v13',
    audience: 'https://gate.example/admit',
    nonce: '00112233445566778899aabbccddeeff',
    sequence: 1,
    issued_at: 1_914_451_200,
    expires_at: 1_914_451_260,
    max_clock_skew: 5,
  };
  return {
    ...unsigned,
    signature: crypto.sign(
      null,
      Buffer.from(canonicalPythonSubset(unsigned), 'utf8'),
      V13_PRIVATE_KEY,
    ).toString('hex'),
  };
}

function v13Profile(actionType = ACTION_TYPE): AebPinnedProfile {
  const pin: AebPinnedProfile = {
    version: CCS_V13_CAID_MAPPING_VERSION,
    definition: createCcsV13AebActionDefinition(actionType),
    registry_entry_ref: 'mapping:ccs-v13-tool-action',
    mapper_id: CCS_V13_CAID_MAPPER_ID,
    resolver: {
      id: CCS_V13_CAID_MAPPER_ID,
      version: '1',
      implementation_digest: digestAeb({ implementation: CCS_V13_CAID_MAPPER_ID, version: '1' }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [
        'trace_id', 'verdict', 'timestamp', 'params_hash', 'rule_summary', 'receipt',
        'verified_at', 'block_reason', 'request_hash', 'response_hash',
        'runtime_context_hash', 'config_hash', 'issuer', 'audience', 'nonce',
        'sequence', 'issued_at', 'expires_at', 'max_clock_skew', 'signature',
      ],
    },
    profile_digest: digestAeb(null),
  };
  pin.profile_digest = mappingProfileDigest('ccs-v13-tool-action', pin);
  return pin;
}

function v13Fixture() {
  const config: CcsV13AebAdapterConfig = {
    '@version': CCS_V13_AEB_CONFIG_VERSION,
    evidence_role: 'machine-policy-decision',
    subject: { id: 'system:ccs-v13-independent-verifier', kind: 'system' },
    issuer: 'https://emilia-protocol.example/interop/ccs-v13',
    audience: 'https://gate.example/admit',
    action_type: ACTION_TYPE,
    allowed_tools: ['sum'],
    max_receipt_age_seconds: 300,
    max_clock_skew_seconds: 5,
    deployment_scope: 'pinned-ed25519-issuer',
  };
  const root: CcsV13Ed25519TrustRoot = {
    '@version': CCS_V13_AEB_TRUST_ROOT_VERSION,
    issuer: config.issuer,
    key_id: 'emilia-ccs-v13-public-test-key-1',
    algorithm: 'Ed25519',
    public_key_raw_base64: V13_PUBLIC_RAW.toString('base64'),
    public_key_fingerprint_sha256_16: crypto.createHash('sha256').update(V13_PUBLIC_RAW).digest('hex').slice(0, 16),
  };
  const action = {
    action_type: ACTION_TYPE,
    parameters: { tool: 'sum', arguments: { left: 19, right: 23 } },
  };
  const adapter = createCcsV13AebAdapter({ config, trust_roots: [root] });
  const input = {
    artifact: mintV13Receipt(),
    artifact_ref: 'ccs:v13:live-sum-001',
    status: {
      checked_at: '2030-09-01T00:00:20Z',
      expires_at: '2030-09-01T00:01:00Z',
      revocation_checked: true,
      revoked: false,
      consumed: false,
    },
    trust_roots: [root],
    adapter_config: config,
    expected_action: action,
    now: '2030-09-01T00:00:20Z',
  } satisfies Omit<AebAdapterInput, 'profile'>;
  return { config, root, action, adapter, input };
}

test('CCS-05 v1.3 source lock is distinct from the published 1.1.14 package profile', () => {
  assert.equal(CCS_V13_DRAFT_SHA256, 'c91f0fa31b1b9e5e2dfe79b99f3b554075d3a44d5309406e748b728f86767cb9');
  assert.match(CCS_V13_SOURCE_LOCK, /draft-correctover-ccs-05/);
  assert.notEqual(CCS_V13_SOURCE_LOCK, CCS_L1_PYPI_SOURCE_LOCK);
});

test('CCS-05 v1.3 receipt verifies under a pinned issuer and maps the executor-owned exact action', () => {
  const f = v13Fixture();
  assert.equal(f.adapter.id, CCS_V13_AEB_ADAPTER_ID);
  const native = f.adapter.verifyNative(f.input);
  assert.equal(native.native_verification, 'VERIFIED', JSON.stringify(native));
  assert.equal(native.acceptance, 'ACCEPTED', JSON.stringify(native));
  const mapped = f.adapter.mapAction({ ...f.input, profile: v13Profile(), native });
  assert.equal(mapped.mapping, 'MATCH', JSON.stringify(mapped));
  assert.equal(mapped.action_digest, digestAeb(f.action));
  assert.match(mapped.caid ?? '', /^caid:1:agent\.tool-invocation\.1:jcs-sha256:/);
});

test('CCS-05 v1.3 refuses signature, audience, freshness, full-digest, substitution, replay, and status uncertainty independently', () => {
  const f = v13Fixture();
  const tampered = structuredClone(f.input.artifact) as CcsV13Receipt;
  tampered.response_hash = `sha256:${'f'.repeat(64)}`;
  assert.deepEqual(f.adapter.verifyNative({ ...f.input, artifact: tampered }).reasons, ['ccs:v13_signature_invalid']);

  const wrongAudience = { ...f.config, audience: 'https://attacker.example/admit' };
  const wrongAudienceAdapter = createCcsV13AebAdapter({ config: wrongAudience, trust_roots: [f.root] });
  const audienceResult = wrongAudienceAdapter.verifyNative({
    ...f.input,
    adapter_config: wrongAudience,
    trust_roots: [f.root],
  });
  assert.ok(audienceResult.reasons.includes('ccs:v13_audience_mismatch'));

  const expired = f.adapter.verifyNative({ ...f.input, now: '2030-09-01T00:02:00Z' });
  assert.ok(expired.reasons.includes('ccs:v13_receipt_expired'));

  const native = f.adapter.verifyNative(f.input);
  const substituted = f.adapter.mapAction({
    ...f.input,
    expected_action: { ...f.action, parameters: { tool: 'sum', arguments: { left: 19, right: 24 } } },
    profile: v13Profile(),
    native,
  });
  assert.equal(substituted.mapping, 'MISMATCH');

  const shortDigestCollisionClaim = structuredClone(f.input.artifact) as CcsV13Receipt;
  shortDigestCollisionClaim.action = `${shortDigestCollisionClaim.action.slice(0, -48)}${'0'.repeat(48)}`;
  const unsigned = { ...shortDigestCollisionClaim } as Record<string, unknown>;
  delete unsigned.signature;
  shortDigestCollisionClaim.signature = crypto.sign(
    null,
    Buffer.from(canonicalPythonSubset(unsigned), 'utf8'),
    V13_PRIVATE_KEY,
  ).toString('hex');
  const fullDigestMismatchNative = f.adapter.verifyNative({ ...f.input, artifact: shortDigestCollisionClaim });
  assert.equal(fullDigestMismatchNative.native_verification, 'VERIFIED');
  const fullDigestMismatch = f.adapter.mapAction({
    ...f.input,
    artifact: shortDigestCollisionClaim,
    profile: v13Profile(),
    native: fullDigestMismatchNative,
  });
  assert.equal(fullDigestMismatch.mapping, 'MISMATCH');
  assert.ok(fullDigestMismatch.reasons.includes('ccs:v13_exact_action_projection_mismatch'));

  const consumed = f.adapter.verifyNative({
    ...f.input,
    status: { ...f.input.status, consumed: true },
  });
  assert.equal(consumed.acceptance, 'REJECTED');
  assert.ok(consumed.reasons.includes('evidence_consumed'));

  const unavailable = f.adapter.verifyNative({
    ...f.input,
    status: { ...f.input.status, unavailable: true },
  });
  assert.equal(unavailable.acceptance, 'INDETERMINATE');
});

test('source lock names the PyPI label and the runtime bytes separately', () => {
  assert.equal(CCS_PYPI_DISTRIBUTION_VERSION, '1.1.0');
  assert.equal(CCS_PYPI_RUNTIME_VERSION, '0.4.1');
  assert.equal(PACKAGE_FIXTURE.result.params_hash, '11841931cced17ab');
  assert.equal(PACKAGE_FIXTURE.result.receipt, '5712658439a2dc61ddda501aa82ff4af');
});

test('current CCS HMAC result becomes accepted machine-policy evidence for one exact action', () => {
  const f = fixture();
  const native = f.adapter.verifyNative(f.input);
  assert.equal(native.native_verification, 'VERIFIED');
  assert.equal(native.acceptance, 'ACCEPTED');
  assert.equal(native.evidence_role, 'machine-policy-decision');
  const mapping = f.adapter.mapAction({ ...f.input, profile: profile(), native });
  assert.equal(mapping.mapping, 'MATCH');
  assert.equal(mapping.action_digest, digestAeb(f.action));
  const computed = computeCaid(f.action, {
    suite: 'jcs-sha256', definitions: (profile().definition as any).definitions,
  });
  assert.equal(mapping.caid, computed.caid);
});

test('CCS maps its exact command into the shared native-action projection used by another evidence leg', () => {
  const f = fixture();
  const actionType = 'payment.transfer.1';
  const artifact = mintArtifact({
    tool: 'release_payment',
    params: { amount: '100.00', payee: 'acct_9' },
  });
  const config = { ...f.config, action_type: actionType };
  const expected_action = {
    action_type: actionType,
    native_action: {
      type: artifact.command.tool,
      parameters: artifact.command.params,
    },
  };
  const adapter = createCcsPyPiHmacAebAdapter({ config, trust_roots: [f.root] });
  const input = {
    ...f.input,
    artifact,
    adapter_config: config,
    expected_action,
  };
  const native = adapter.verifyNative(input);
  assert.equal(native.native_verification, 'VERIFIED');
  assert.equal(native.acceptance, 'ACCEPTED');
  const mapping = adapter.mapAction({
    ...input,
    profile: nativeActionProfile(actionType),
    native,
  });
  assert.equal(mapping.mapping, 'MATCH');
  assert.equal(mapping.action_digest, digestAeb(expected_action));
  assert.match(mapping.caid ?? '', /^caid:1:payment\.transfer\.1:jcs-sha256:/);
});

test('approve A execute B and changed command bytes fail independently', () => {
  const f = fixture();
  const native = f.adapter.verifyNative(f.input);
  const expected_action = structuredClone(f.action);
  expected_action.parameters.arguments.amount_minor = 999999;
  const mapped = f.adapter.mapAction({ ...f.input, expected_action, profile: profile(), native });
  assert.equal(mapped.mapping, 'MISMATCH');

  const tampered = structuredClone(f.artifact);
  tampered.command.params.amount_minor = 999999;
  const verified = f.adapter.verifyNative({ ...f.input, artifact: tampered });
  assert.equal(verified.acceptance, 'REJECTED');
  assert.ok(verified.reasons.includes('ccs:params_hash_mismatch'));
});

test('receipt tampering, tool substitution, rule removal, and presenter pin replacement fail closed', () => {
  const f = fixture();
  const receiptTamper = structuredClone(f.artifact);
  receiptTamper.result.receipt = `f${receiptTamper.result.receipt.slice(1)}`;
  assert.equal(f.adapter.verifyNative({ ...f.input, artifact: receiptTamper }).native_verification, 'FAILED');

  const toolSwap = structuredClone(f.artifact);
  toolSwap.command.tool = 'delete_repository';
  toolSwap.result.tool = 'delete_repository';
  signArtifact(toolSwap);
  const unpinnedTool = f.adapter.verifyNative({ ...f.input, artifact: toolSwap });
  assert.equal(unpinnedTool.native_verification, 'VERIFIED');
  assert.ok(unpinnedTool.reasons.includes('ccs:tool_not_pinned'));

  const ruleRemoval = structuredClone(f.artifact);
  ruleRemoval.result.rule_results.pop();
  signArtifact(ruleRemoval);
  const incompleteAllow = f.adapter.verifyNative({ ...f.input, artifact: ruleRemoval });
  assert.equal(incompleteAllow.native_verification, 'VERIFIED');
  assert.ok(incompleteAllow.reasons.includes('ccs:required_rules_mismatch'));

  const replacedRoot = { ...f.root, secret_base64url: crypto.randomBytes(32).toString('base64url') };
  assert.ok(f.adapter.verifyNative({ ...f.input, trust_roots: [replacedRoot] }).reasons.includes('ccs:constructor_pin_mismatch'));
});

test('deny, escalate, stale evidence, and unavailable status never reach accepted evidence', () => {
  for (const [verdict, acceptance] of [['deny', 'REJECTED'], ['escalate', 'INDETERMINATE']] as const) {
    const f = fixture();
    const artifact = mintArtifact({ verdict });
    const native = f.adapter.verifyNative({ ...f.input, artifact });
    assert.equal(native.native_verification, 'VERIFIED');
    assert.equal(native.acceptance, acceptance);
  }
  const stale = fixture();
  const oldArtifact = mintArtifact({ verified_at: NOW_SECONDS - 61 });
  assert.equal(stale.adapter.verifyNative({ ...stale.input, artifact: oldArtifact }).acceptance, 'INDETERMINATE');
  assert.equal(stale.adapter.verifyNative({
    ...stale.input,
    status: { ...stale.input.status, unavailable: true },
  }).acceptance, 'INDETERMINATE');
});

test('unknown post-effect fields are rejected instead of becoming execution evidence', () => {
  const f = fixture();
  const artifact = structuredClone(f.artifact) as any;
  artifact.result.outcome_status = 'confirmed';
  const native = f.adapter.verifyNative({ ...f.input, artifact });
  assert.equal(native.native_verification, 'FAILED');
  assert.equal(native.acceptance, 'REJECTED');
  assert.ok(native.reasons.includes('ccs:artifact_malformed'));
});

function registryEntry(id: string, kind: AebRegistryEntry['kind'], definition: unknown): AebRegistryEntry {
  const entry = { kind, version: '1', status: 'active' as const, definition } as AebRegistryEntry;
  entry.definition_digest = registryEntryDigest(id, entry);
  return entry;
}

test('a fresh CCS receipt cannot replay the same execution authority after an indeterminate attempt', () => {
  const f = fixture();
  const mapping = profile();
  const authorityAdapterId = 'native:test-execution-authority';
  const authorityConfig = { version: 'test-authority-v1', role: 'execution-authority' };
  const authorityRoot = { version: 'test-authority-root-v1', issuer: 'test-only' };
  const authorityArtifact = { authority_id: 'authority-payment-0001', action: f.action };
  const authorityAdapter: AebAdapter = {
    id: authorityAdapterId,
    version: '1',
    verifyNative(input) {
      const artifact = input.artifact as typeof authorityArtifact;
      const accepted = artifact?.authority_id === authorityArtifact.authority_id
        && digestAeb(artifact?.action) === digestAeb(input.expected_action);
      return {
        native_verification: accepted ? 'VERIFIED' : 'FAILED',
        acceptance: accepted ? 'ACCEPTED' : 'REJECTED',
        evidence_digest: digestAeb(input.artifact),
        status_digest: statusDigest(input.status),
        evidence_role: 'execution-authority',
        subject: { id: 'organization:owner', kind: 'organization' },
        replay_unit: digestAeb({ authority_id: artifact?.authority_id }),
        reasons: accepted ? [] : ['test_authority_invalid'],
      };
    },
    mapAction(input) {
      if (input.native.acceptance !== 'ACCEPTED') {
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['native_acceptance_required'] };
      }
      const artifact = input.artifact as typeof authorityArtifact;
      if (digestAeb(artifact.action) !== digestAeb(input.expected_action)) {
        return { mapping: 'MISMATCH', caid: null, action_digest: digestAeb(artifact.action), reasons: ['action_mismatch'] };
      }
      const computed = computeCaid(artifact.action, {
        suite: 'jcs-sha256', definitions: (mapping.definition as any).definitions,
      });
      return { mapping: 'MATCH', caid: computed.caid, action_digest: digestAeb(artifact.action), reasons: [] };
    },
  };

  const ccsPin: AebPinnedAdapter = {
    version: CCS_AEB_ADAPTER_VERSION,
    trust_roots: [f.root],
    config: f.config,
    config_digest: digestAeb(null),
    max_status_age_sec: 120,
  };
  ccsPin.config_digest = adapterPinDigest(CCS_AEB_ADAPTER_ID, ccsPin);
  const authorityPin: AebPinnedAdapter = {
    version: '1',
    trust_roots: [authorityRoot],
    config: authorityConfig,
    config_digest: digestAeb(null),
    max_status_age_sec: 120,
  };
  authorityPin.config_digest = adapterPinDigest(authorityAdapterId, authorityPin);

  const entries = {
    'mapping:ccs-tool-invocation': registryEntry(
      'mapping:ccs-tool-invocation', 'mapping-profile', { profile_digest: mapping.profile_digest },
    ),
    'role:machine-policy-decision': registryEntry(
      'role:machine-policy-decision', 'evidence-role',
      { role: 'machine-policy-decision', subject_kinds: ['system'] },
    ),
    'role:execution-authority': registryEntry(
      'role:execution-authority', 'evidence-role',
      { role: 'execution-authority', subject_kinds: ['organization'] },
    ),
  };
  const registry = {
    '@version': AEB_REGISTRY_VERSION,
    registry_id: 'registry:ccs-aeb-test',
    epoch: 1,
    entries,
    registry_digest: digestAeb(null),
  };
  registry.registry_digest = unifiedRegistryDigest(registry);
  const evaluator = crypto.generateKeyPairSync('ed25519');
  const config: AebPinnedConfig = {
    '@version': AEB_ADAPTER_VERSION,
    relying_party_id: 'rp:ccs-aeb-example',
    evaluator_keys: { 'evaluator:ccs-aeb': { public_key: spki(evaluator.publicKey) } },
    registry,
    accepted_mappers: [CCS_CAID_MAPPER_ID],
    adapters: { [CCS_AEB_ADAPTER_ID]: ccsPin, [authorityAdapterId]: authorityPin },
    profiles: { 'ccs-tool-invocation': mapping },
    requirements: {
      'requirement:policy-plus-authority': {
        '@version': AEB_REQUIREMENT_VERSION,
        all_of: ['machine-policy-decision', 'execution-authority'],
        terms: [{ type: 'one-time-consumption' }],
      },
    },
  };
  const computed = computeCaid(f.action, {
    suite: 'jcs-sha256', definitions: (mapping.definition as any).definitions,
  });
  const status = f.input.status;
  const makeEvaluation = (artifact: CcsPyPiArtifact, operationId: string) => evaluateAebEvidence({
    config,
    adapters: { [CCS_AEB_ADAPTER_ID]: f.adapter, [authorityAdapterId]: authorityAdapter },
    operation_id: operationId,
    consumption_nonce: `consume-${operationId}`,
    initiator_id: 'workload:agent-overnight-1',
    executor_id: 'workload:gate',
    requirement_ref: 'requirement:policy-plus-authority',
    caid: computed.caid,
    expected_action: f.action,
    evaluated_at: NOW,
    signer: { key_id: 'evaluator:ccs-aeb', private_key: evaluator.privateKey },
    legs: [
      {
        adapter_id: CCS_AEB_ADAPTER_ID,
        profile_id: 'ccs-tool-invocation',
        artifact_ref: `ccs:${artifact.result.trace_id}`,
        artifact,
        status,
      },
      {
        adapter_id: authorityAdapterId,
        profile_id: 'ccs-tool-invocation',
        artifact_ref: 'authority:payment-0001',
        artifact: authorityArtifact,
        status,
      },
    ],
  });

  const first = makeEvaluation(f.artifact, 'operation-1');
  assert.equal(first.valid, true, JSON.stringify(first, null, 2));
  const firstVerification = verifyAebEvaluation(first.record, {
    config,
    adapters: { [CCS_AEB_ADAPTER_ID]: f.adapter, [authorityAdapterId]: authorityAdapter },
    artifacts: {
      [`ccs:${f.artifact.result.trace_id}`]: f.artifact,
      'authority:payment-0001': authorityArtifact,
    },
    mode: 'execution',
    now: NOW,
    expected_action: f.action,
    current_statuses: {
      [`ccs:${f.artifact.result.trace_id}`]: status,
      'authority:payment-0001': status,
    },
  });
  assert.equal(firstVerification.execution_authorizing, true, JSON.stringify(firstVerification, null, 2));
  const store = new InMemoryAebConsumptionStore();
  const admitted = authorizeAebExecution(first.record, {
    verification: firstVerification,
    local_authorization: true,
    store,
  });
  assert.equal(admitted.state, 'AUTHORIZED');
  assert.ok(admitted.reservation_key);
  assert.equal(
    reconcileAebExecution(store, admitted.reservation_key!, 'INDETERMINATE').state,
    'RECONCILIATION_REQUIRED',
  );

  const secondArtifact = mintArtifact({ trace_id: '8899aabbccddeeff', verified_at: NOW_SECONDS });
  const second = makeEvaluation(secondArtifact, 'operation-2');
  assert.equal(second.valid, true, JSON.stringify(second, null, 2));
  const secondVerification = verifyAebEvaluation(second.record, {
    config,
    adapters: { [CCS_AEB_ADAPTER_ID]: f.adapter, [authorityAdapterId]: authorityAdapter },
    artifacts: {
      [`ccs:${secondArtifact.result.trace_id}`]: secondArtifact,
      'authority:payment-0001': authorityArtifact,
    },
    mode: 'execution',
    now: NOW,
    expected_action: f.action,
    current_statuses: {
      [`ccs:${secondArtifact.result.trace_id}`]: status,
      'authority:payment-0001': status,
    },
  });
  const replay = authorizeAebExecution(second.record, {
    verification: secondVerification,
    local_authorization: true,
    store,
  });
  assert.equal(replay.state, 'REFUSED');
  assert.equal(replay.reason, 'consumption_conflict');
});
