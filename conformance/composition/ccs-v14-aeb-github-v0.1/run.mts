// SPDX-License-Identifier: Apache-2.0
// @ts-nocheck -- executable conformance runner imports built JavaScript package surfaces.
/** CCS v1.4 public vectors to one governed GitHub issue-update consequence. */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  adapterPinDigest,
  canonicalizeAeb,
  digestAeb,
  evaluateAebEvidence,
  mappingProfileDigest,
  registryEntryDigest,
  unifiedRegistryDigest,
  type AebAdapter,
  type AebPinnedAdapter,
  type AebPinnedConfig,
  type AebPinnedProfile,
  type AebRegistryEntry,
  type AebRegistryEntryKind,
  type AebStatusInput,
  type AebUnifiedRegistry,
} from '../../../packages/verify/aeb-adapter-contract.js';
import {
  CCS_V14_AEB_CONFIG_VERSION,
  CCS_V14_AEB_TRUST_ROOT_VERSION,
  CCS_V14_CAID_MAPPER_ID,
  CCS_V14_CAID_MAPPING_VERSION,
  CCS_V14_SOURCE_LOCK,
  CCS_V14_VECTOR_COMMIT,
  CCS_V14_VECTOR_MANIFEST_SHA256,
  CCS_V14_VECTOR_REPOSITORY,
  createCcsV14AebActionDefinition,
  createCcsV14AebAdapter,
  type CcsV14AebAdapterConfig,
  type CcsV14Artifact,
  type CcsV14Ed25519TrustRoot,
  type CcsV14Receipt,
} from '../../../packages/verify/aeb-ccs-v14-adapter.js';
import { canonicalizeFiniteJson } from '../../../packages/verify/strict-json.js';
import { computeCaid } from '../../../packages/verify/vendor/caid.mjs';
import {
  createConsequenceBoundary,
  type ConsequenceBoundaryAttemptBinding,
  type ConsequenceBoundaryAttemptReference,
  type ConsequenceBoundaryProviderEvidence,
} from '../../../packages/gate/consequence-boundary.js';

export const PROFILE = 'CCS-V1.4-AEB-GITHUB-CONSEQUENCE-v0.1';
const REPORT_VERSION = 'CCS-V1.4-AEB-GITHUB-REFERENCE-REPORT-v1';
const VECTOR_VERSION = 'CCS-V1.4-AEB-GITHUB-REFERENCE-VECTORS-v1';
const HERE = dirname(fileURLToPath(import.meta.url));
const REPORT_PATH = resolve(HERE, 'report.reference.json');
const VECTOR_PATH = resolve(HERE, 'vectors.reference.json');
const UPSTREAM_RECEIPT_PATH = resolve(HERE, 'upstream-01-allow.receipt.json');
const NOW = '2025-06-15T16:00:30.000Z';
const EVALUATED_AT = '2025-06-15T16:00:29.000Z';
const NOW_SECONDS = Date.parse(NOW) / 1000;
const EXECUTOR = 'executor:emilia-github-gate';
const RELYING_PARTY = 'rp:emilia-github-gate';
const ACTION_TYPE = 'github.issue-update.1';
const PROVIDER = Object.freeze({
  tenant_id: 'tenant:emilia-protocol',
  provider_id: 'provider:github',
  provider_account_id: 'account:futureenterprises',
  environment: 'test-fixture',
});
const GITHUB_ARGUMENTS = Object.freeze({
  repository: 'emiliaprotocol/emilia-protocol',
  issue_number: 538,
  title: 'Record missing-evidence disposition',
  body: 'Evidence unavailable; no execution authority inferred.',
  state: 'open',
});
const GITHUB_ACTION = Object.freeze({
  action_type: ACTION_TYPE,
  parameters: {
    tool: 'github_issue_update',
    arguments: GITHUB_ARGUMENTS,
  },
});

type Obj = Record<string, any>;
type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type CaseResult = {
  id: string;
  category: 'source' | 'positive' | 'hostile' | 'boundary';
  passed: boolean;
  expected: string;
  observed: Record<string, Json>;
};

const CCS_PRIVATE = crypto.createPrivateKey({
  key: Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    crypto.createHash('sha256')
      .update('ccs-conformance-vectors/v1/independent-checker')
      .digest(),
  ]),
  format: 'der',
  type: 'pkcs8',
});
const CCS_PUBLIC_RAW = crypto.createPublicKey(CCS_PRIVATE)
  .export({ type: 'spki', format: 'der' }).subarray(-32);
const EVALUATOR_PRIVATE = crypto.createPrivateKey({
  key: Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    crypto.createHash('sha256').update('emilia/ccs-v14-aeb-evaluator/v1').digest(),
  ]),
  format: 'der',
  type: 'pkcs8',
});
const EVALUATOR_PUBLIC_SPKI = crypto.createPublicKey(EVALUATOR_PRIVATE)
  .export({ type: 'spki', format: 'der' }).toString('base64url');

function sha256Bytes(value: string | Buffer): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function hashJson(value: unknown): string {
  return sha256Bytes(canonicalizeFiniteJson(value));
}

function signReceipt(unsigned: Omit<CcsV14Receipt, 'signature'>): CcsV14Receipt {
  return {
    ...unsigned,
    signature: crypto.sign(
      null,
      Buffer.from(canonicalizeFiniteJson(unsigned), 'utf8'),
      CCS_PRIVATE,
    ).toString('base64'),
  };
}

function githubArtifact(input: {
  audience?: string;
  arguments?: Record<string, unknown>;
} = {}): CcsV14Artifact {
  const args = input.arguments ?? GITHUB_ARGUMENTS;
  const request = { tool: 'github_issue_update', arguments: args };
  const response = {
    issue_url: 'https://github.com/emiliaprotocol/emilia-protocol/issues/538',
    updated: true,
  };
  return {
    receipt: signReceipt({
      trace_id: 'ccs-v14-emilia-github-trace',
      receipt_version: '1.4',
      verdict: 'allow',
      timestamp: NOW_SECONDS - 20,
      tool: 'github_issue_update',
      tool_call_id: 'call-ccs-v14-emilia-001',
      params_hash: hashJson(request),
      args_digest: hashJson(args),
      rule_summary: 'github-issue-update-conformance',
      rule_version: '1.4.0-conformance',
      request_hash: hashJson(request),
      response_hash: hashJson(response),
      runtime_context_hash: hashJson({ environment: 'test', relying_party: RELYING_PARTY }),
      config_hash: hashJson({ policy: 'ccs-v14-emilia-github-v1' }),
      verifier_source_class: 'EMILIAIndependentComposition',
      deployment_mode: 'test-in-process',
      issuer: 'ccs-conformance/v1.4.0',
      audience: input.audience ?? RELYING_PARTY,
      nonce: 'ccs-v14-emilia-nonce-001',
      sequence: 0,
      issued_at: NOW_SECONDS - 20,
      expires_at: NOW_SECONDS + 60,
      max_clock_skew: 30,
      action: 'github_issue_update.execute',
      signing_algorithm: 'Ed25519',
      public_key_fingerprint: sha256Bytes(CCS_PUBLIC_RAW).slice(0, 16),
      public_key: CCS_PUBLIC_RAW.toString('base64'),
      verified_at: NOW_SECONDS - 20,
      latency_us: 842,
    }),
    tool_args: args,
    response_body: response,
  };
}

function mappingProfile(): AebPinnedProfile {
  const profile: AebPinnedProfile = {
    version: CCS_V14_CAID_MAPPING_VERSION,
    definition: createCcsV14AebActionDefinition(ACTION_TYPE),
    registry_entry_ref: 'mapping:ccs-v14-github-action',
    mapper_id: CCS_V14_CAID_MAPPER_ID,
    resolver: {
      id: CCS_V14_CAID_MAPPER_ID,
      version: '1',
      implementation_digest: digestAeb({ implementation: CCS_V14_CAID_MAPPER_ID, version: '1' }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [
        'trace_id', 'receipt_version', 'verdict', 'timestamp', 'tool_call_id',
        'params_hash', 'rule_summary', 'rule_version', 'request_hash',
        'response_hash', 'runtime_context_hash', 'config_hash',
        'verifier_source_class', 'deployment_mode', 'issuer', 'audience',
        'nonce', 'sequence', 'issued_at', 'expires_at', 'max_clock_skew',
        'action', 'signature', 'signing_algorithm', 'public_key_fingerprint',
        'public_key', 'verified_at', 'latency_us',
      ],
    },
    profile_digest: digestAeb(null),
  };
  profile.profile_digest = mappingProfileDigest('ccs-v14-github-action', profile);
  return profile;
}

function registryEntry(
  entryId: string,
  kind: AebRegistryEntryKind,
  definition: unknown,
): AebRegistryEntry {
  const entry: AebRegistryEntry = {
    kind,
    version: '1',
    status: 'active',
    definition,
    definition_digest: digestAeb(null),
  };
  entry.definition_digest = registryEntryDigest(entryId, entry);
  return entry;
}

function caidFor(action: typeof GITHUB_ACTION, profile: AebPinnedProfile): string {
  const definition = profile.definition as Obj;
  const computed = computeCaid(action, {
    suite: 'jcs-sha256',
    definitions: definition.definitions,
  });
  if (!computed || typeof computed.caid !== 'string') {
    throw new Error(`CAID failed: ${JSON.stringify(computed)}`);
  }
  return computed.caid;
}

function evaluationFixture(operationId: string) {
  const artifact = githubArtifact();
  const profile = mappingProfile();
  const caid = caidFor(GITHUB_ACTION, profile);
  const adapterConfig: CcsV14AebAdapterConfig = {
    '@version': CCS_V14_AEB_CONFIG_VERSION,
    evidence_role: 'machine-policy-decision',
    subject: { id: 'system:correctover-ccs-v14', kind: 'system' },
    issuer: 'ccs-conformance/v1.4.0',
    audience: RELYING_PARTY,
    action_type: ACTION_TYPE,
    allowed_actions: ['github_issue_update.execute'],
    allowed_tools: ['github_issue_update'],
    required_rule_version: '1.4.0-conformance',
    max_receipt_age_seconds: 300,
    max_status_age_seconds: 300,
    max_clock_skew_seconds: 30,
    deployment_scope: 'pinned-ed25519-issuer',
  };
  const root: CcsV14Ed25519TrustRoot = {
    '@version': CCS_V14_AEB_TRUST_ROOT_VERSION,
    issuer: adapterConfig.issuer,
    key_id: 'ccs-v14-independent-checker',
    algorithm: 'Ed25519',
    public_key_raw_base64: CCS_PUBLIC_RAW.toString('base64'),
    public_key_fingerprint_sha256_16: sha256Bytes(CCS_PUBLIC_RAW).slice(0, 16),
  };
  const adapter = createCcsV14AebAdapter({ config: adapterConfig, trust_roots: [root] });
  const entries: Record<string, AebRegistryEntry> = {
    'mapping:ccs-v14-github-action': registryEntry(
      'mapping:ccs-v14-github-action',
      'mapping-profile',
      { profile_digest: profile.profile_digest },
    ),
    'role:machine-policy-decision': registryEntry(
      'role:machine-policy-decision',
      'evidence-role',
      { role: 'machine-policy-decision', subject_kinds: ['system'] },
    ),
  };
  const registry: AebUnifiedRegistry = {
    '@version': 'EP-EVIDENCE-REGISTRY-v1',
    registry_id: 'registry:ccs-v14-aeb-github',
    epoch: 1,
    entries,
    registry_digest: digestAeb(null),
  };
  registry.registry_digest = unifiedRegistryDigest(registry);
  const pin: AebPinnedAdapter = {
    version: adapter.version,
    trust_roots: [root],
    config: adapterConfig,
    config_digest: digestAeb(null),
    max_status_age_sec: 300,
  };
  pin.config_digest = adapterPinDigest(adapter.id, pin);
  const config: AebPinnedConfig = {
    '@version': 'AEB-ADAPTER-v1',
    relying_party_id: RELYING_PARTY,
    evaluator_keys: { 'evaluator:ccs-v14-aeb': { public_key: EVALUATOR_PUBLIC_SPKI } },
    registry,
    accepted_mappers: [profile.mapper_id],
    adapters: { [adapter.id]: pin },
    profiles: { 'ccs-v14-github-action': profile },
    requirements: {
      'requirement:ccs-machine-policy': {
        '@version': 'AEB-REQUIREMENT-v1',
        all_of: ['machine-policy-decision'],
        terms: [{ type: 'one-time-consumption' }],
      },
    },
  };
  const status: AebStatusInput = {
    checked_at: EVALUATED_AT,
    expires_at: '2025-06-15T16:02:00.000Z',
    revocation_checked: true,
    revoked: false,
    consumed: false,
  };
  const artifactRef = 'artifact:ccs-v14-github-allow';
  const evaluated = evaluateAebEvidence({
    config,
    adapters: { [adapter.id]: adapter },
    operation_id: operationId,
    consumption_nonce: `nonce:${operationId}`,
    initiator_id: 'agent:issue-maintainer',
    executor_id: EXECUTOR,
    requirement_ref: 'requirement:ccs-machine-policy',
    caid,
    expected_action: GITHUB_ACTION,
    legs: [{
      adapter_id: adapter.id,
      profile_id: 'ccs-v14-github-action',
      artifact_ref: artifactRef,
      artifact,
      status,
    }],
    evaluated_at: EVALUATED_AT,
    signer: { key_id: 'evaluator:ccs-v14-aeb', private_key: EVALUATOR_PRIVATE },
  });
  assert.equal(evaluated.valid, true, JSON.stringify(evaluated.reasons));
  return {
    action: GITHUB_ACTION,
    artifact,
    config,
    adapters: { [adapter.id]: adapter } satisfies Record<string, AebAdapter>,
    evaluation: evaluated.record,
    artifacts: { [artifactRef]: artifact },
    statuses: { [artifactRef]: status },
    artifactRef,
    caid,
  };
}

function aebStore() {
  const rows = new Map<string, 'RESERVED' | 'CONSUMED'>();
  const replay = new Map<string, string>();
  return {
    durable: true as const,
    ownershipFenced: true as const,
    permanentConsumption: true as const,
    atomicReplayFenced: true as const,
    async reserve(key: string, replayKeys: readonly string[]) {
      if (rows.has(key)) return 'CONSUMPTION_CONFLICT' as const;
      if (replayKeys.some((item) => replay.has(item))) return 'NATIVE_REPLAY_CONFLICT' as const;
      rows.set(key, 'RESERVED');
      for (const item of replayKeys) replay.set(item, key);
      return 'RESERVED' as const;
    },
    async commit(key: string) {
      if (rows.get(key) !== 'RESERVED') return false;
      rows.set(key, 'CONSUMED');
      return true;
    },
    async release(key: string) {
      if (rows.get(key) !== 'RESERVED') return false;
      rows.delete(key);
      for (const [item, owner] of replay) if (owner === key) replay.delete(item);
      return true;
    },
  };
}

function attemptStore() {
  const rows = new Map<string, {
    binding: ConsequenceBoundaryAttemptBinding;
    owner: string;
    state: 'RESERVED' | 'INVOKING' | 'INDETERMINATE' | 'COMMITTED' | 'RELEASED';
  }>();
  return {
    durable: true as const,
    ownershipFenced: true as const,
    compareAndSwap: true as const,
    atomicEvidenceBinding: true as const,
    rows,
    async reserve(binding: ConsequenceBoundaryAttemptBinding) {
      if (rows.has(binding.attempt_id)) return { reserved: false as const, reason: 'attempt_exists' };
      const owner = `owner:${binding.attempt_id}`;
      rows.set(binding.attempt_id, { binding: structuredClone(binding), owner, state: 'RESERVED' });
      return { reserved: true as const, owner: owner as any };
    },
    async transition(input: ConsequenceBoundaryAttemptReference & Obj) {
      const row = rows.get(input.attempt_id);
      if (!row || row.owner !== input.owner || row.state !== input.expected_state) return false;
      row.state = input.next_state;
      return true;
    },
    async reconcile(input: ConsequenceBoundaryAttemptReference & Obj) {
      const row = rows.get(input.attempt_id);
      if (!row || row.owner !== input.owner || row.state !== input.expected_state) return false;
      const evidence = input.evidence as ConsequenceBoundaryProviderEvidence;
      for (const field of [
        'tenant_id', 'provider_id', 'provider_account_id', 'environment',
        'attempt_id', 'request_digest', 'provider_idempotency_key',
      ] as const) if (evidence[field] !== row.binding[field]) return false;
      row.state = input.next_state;
      return true;
    },
  };
}

function boundaryInput(
  fixture: ReturnType<typeof evaluationFixture>,
  options: {
    action?: unknown;
    artifacts?: Record<string, unknown>;
    statuses?: Record<string, AebStatusInput>;
  } = {},
) {
  return {
    evaluation: fixture.evaluation,
    action: options.action ?? fixture.action,
    artifacts: options.artifacts ?? fixture.artifacts,
    current_statuses: options.statuses ?? fixture.statuses,
  };
}

function harness(
  fixture: ReturnType<typeof evaluationFixture>,
  options: {
    config?: AebPinnedConfig;
    local_authority?: boolean;
    lose_response?: boolean;
  } = {},
) {
  const store = aebStore();
  const attempts = attemptStore();
  let providerCalls = 0;
  const boundary = createConsequenceBoundary({
    executor_id: EXECUTOR,
    provider: PROVIDER,
    aeb: { config: options.config ?? fixture.config, adapters: fixture.adapters, store },
    attempts: {
      store: attempts,
      create_id: () => `attempt:${fixture.evaluation.operation_id}`,
      recover: ({ attempt, recovery_authorization }) => {
        if (recovery_authorization !== 'recovery:approved') return null;
        const row = attempts.rows.get(attempt.attempt_id);
        return row ? { ...structuredClone(row.binding), owner: row.owner as any } : null;
      },
    },
    local_authorize: () => options.local_authority !== false,
    invoke: async () => {
      providerCalls += 1;
      if (options.lose_response) throw new Error('synthetic_provider_response_lost');
      return {
        state: 'EXECUTED' as const,
        evidence: {
          evidence_id: `provider-evidence:${fixture.evaluation.operation_id}`,
          observed_at: '2025-06-15T16:00:31.000Z',
          evidence_digest: digestAeb({ provider: 'github', updated_issue: 538 }),
        },
        result: { issue_number: 538, updated: true },
      };
    },
    now: () => NOW,
  });
  return { boundary, providerCalls: () => providerCalls };
}

function verifyUpstreamVector() {
  const raw = readFileSync(UPSTREAM_RECEIPT_PATH);
  const receipt = JSON.parse(raw.toString('utf8')) as CcsV14Receipt;
  const unsigned = { ...receipt } as Obj;
  delete unsigned.signature;
  const rawPublic = Buffer.from(receipt.public_key, 'base64');
  const publicKey = crypto.createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), rawPublic]),
    format: 'der',
    type: 'spki',
  });
  const signatureValid = crypto.verify(
    null,
    Buffer.from(canonicalizeFiniteJson(unsigned), 'utf8'),
    publicKey,
    Buffer.from(receipt.signature, 'base64'),
  );
  const args = { customer_id: 'CUST-10042', include_history: true };
  const response = { customer_id: 'CUST-10042', name: 'Alice Zhang', tier: 'premium', active: true };
  return {
    raw_sha256: sha256Bytes(raw),
    signature_valid: signatureValid,
    args_digest_valid: receipt.args_digest === hashJson(args),
    response_hash_valid: receipt.response_hash === hashJson(response),
  };
}

function caseResult(
  id: string,
  category: CaseResult['category'],
  passed: boolean,
  expected: string,
  observed: Record<string, Json>,
): CaseResult {
  return { id, category, passed, expected, observed };
}

export function buildReferenceVectors() {
  const fixture = evaluationFixture('operation:ccs-v14:vectors');
  return {
    '@version': VECTOR_VERSION,
    source_lock: {
      repository: CCS_V14_VECTOR_REPOSITORY,
      commit: CCS_V14_VECTOR_COMMIT,
      manifest_sha256: CCS_V14_VECTOR_MANIFEST_SHA256,
      upstream_case: 'vectors/v1.4.0-conformance/01-allow',
      upstream_receipt_sha256: '889855dc9fcebdb642bd7e0f369651015781b4c004227aef510feb1fb7cb4361',
    },
    upstream_allow_receipt: JSON.parse(readFileSync(UPSTREAM_RECEIPT_PATH, 'utf8')),
    emilia_github_fixture: {
      action: fixture.action,
      caid: fixture.caid,
      ccs_artifact: fixture.artifact,
      relying_party: RELYING_PARTY,
      provider: PROVIDER,
    },
    limits: [
      'The upstream vector and local GitHub fixture use a public deterministic conformance key, not a production trust root.',
      'The local GitHub fixture is EMILIA-authored and source-compatible; it is not represented as a Correctover-issued upstream vector.',
      'CCS ALLOW is machine-policy evidence only. Separate relying-party authorization is required before provider entry.',
      'The provider is a counting test stub; no GitHub issue is changed.',
    ],
  };
}

export async function buildReferenceReport() {
  const cases: CaseResult[] = [];

  const upstream = verifyUpstreamVector();
  cases.push(caseResult(
    'CCS-V1.4-PUBLIC-VECTOR-PIN',
    'source',
    upstream.raw_sha256 === '889855dc9fcebdb642bd7e0f369651015781b4c004227aef510feb1fb7cb4361'
      && upstream.signature_valid && upstream.args_digest_valid && upstream.response_hash_valid,
    'byte-pinned public vector with valid Ed25519 and companion hashes',
    upstream,
  ));

  const throughFixture = evaluationFixture('operation:ccs-v14:through');
  const through = harness(throughFixture);
  const throughResult = await through.boundary.run(boundaryInput(throughFixture));
  cases.push(caseResult(
    'CCS-ALLOW-PLUS-EMILIA-AUTHORITY',
    'positive',
    throughResult.state === 'EXECUTED' && through.providerCalls() === 1,
    'one provider entry after CCS evidence, exact-action AEB evaluation, and separate local authority',
    { state: throughResult.state, provider_calls: through.providerCalls() },
  ));

  const tamperFixture = evaluationFixture('operation:ccs-v14:tamper');
  const tamperHarness = harness(tamperFixture);
  const tampered = structuredClone(tamperFixture.artifact);
  tampered.receipt.response_hash = 'f'.repeat(64);
  const tamperResult = await tamperHarness.boundary.run(boundaryInput(tamperFixture, {
    artifacts: { [tamperFixture.artifactRef]: tampered },
  }));
  cases.push(caseResult(
    'CCS-TAMPER-REFUSED',
    'hostile',
    tamperResult.state === 'REFUSED' && tamperHarness.providerCalls() === 0,
    'signed artifact mutation refused before provider entry',
    {
      state: tamperResult.state,
      reason: tamperResult.state === 'REFUSED' ? tamperResult.reason : null,
      provider_calls: tamperHarness.providerCalls(),
    },
  ));

  const rpFixture = evaluationFixture('operation:ccs-v14:wrong-rp');
  const rpHarness = harness(rpFixture, {
    config: { ...rpFixture.config, relying_party_id: 'rp:other-github-gate' },
  });
  const rpResult = await rpHarness.boundary.run(boundaryInput(rpFixture));
  cases.push(caseResult(
    'WRONG-RELYING-PARTY-REFUSED',
    'hostile',
    rpResult.state === 'REFUSED' && rpHarness.providerCalls() === 0,
    'evaluation pinned for another relying party refused before provider entry',
    {
      state: rpResult.state,
      reason: rpResult.state === 'REFUSED' ? rpResult.reason : null,
      provider_calls: rpHarness.providerCalls(),
    },
  ));

  const staleFixture = evaluationFixture('operation:ccs-v14:stale');
  const staleHarness = harness(staleFixture);
  const staleStatus = {
    ...staleFixture.statuses[staleFixture.artifactRef],
    checked_at: '2025-06-15T15:00:00.000Z',
  };
  const staleResult = await staleHarness.boundary.run(boundaryInput(staleFixture, {
    statuses: { [staleFixture.artifactRef]: staleStatus },
  }));
  cases.push(caseResult(
    'STALE-STATUS-REFUSED',
    'hostile',
    staleResult.state === 'REFUSED' && staleHarness.providerCalls() === 0,
    'stale status refused before provider entry',
    {
      state: staleResult.state,
      reason: staleResult.state === 'REFUSED' ? staleResult.reason : null,
      provider_calls: staleHarness.providerCalls(),
    },
  ));

  const substitutionFixture = evaluationFixture('operation:ccs-v14:substitution');
  const substitutionHarness = harness(substitutionFixture);
  const changedAction = {
    ...substitutionFixture.action,
    parameters: {
      tool: 'github_issue_update',
      arguments: { ...GITHUB_ARGUMENTS, issue_number: 539 },
    },
  };
  const substitutionResult = await substitutionHarness.boundary.run(boundaryInput(
    substitutionFixture,
    { action: changedAction },
  ));
  cases.push(caseResult(
    'ACTION-SUBSTITUTION-REFUSED',
    'hostile',
    substitutionResult.state === 'REFUSED' && substitutionHarness.providerCalls() === 0,
    'approved issue 538 cannot be substituted with issue 539',
    {
      state: substitutionResult.state,
      reason: substitutionResult.state === 'REFUSED' ? substitutionResult.reason : null,
      provider_calls: substitutionHarness.providerCalls(),
    },
  ));

  const noAuthorityFixture = evaluationFixture('operation:ccs-v14:no-authority');
  const noAuthorityHarness = harness(noAuthorityFixture, { local_authority: false });
  const noAuthorityResult = await noAuthorityHarness.boundary.run(boundaryInput(noAuthorityFixture));
  cases.push(caseResult(
    'MISSING-EMILIA-AUTHORITY-REFUSED',
    'boundary',
    noAuthorityResult.state === 'REFUSED'
      && noAuthorityResult.reason === 'local_authorization_denied'
      && noAuthorityHarness.providerCalls() === 0,
    'CCS ALLOW alone cannot enter the provider',
    {
      state: noAuthorityResult.state,
      reason: noAuthorityResult.state === 'REFUSED' ? noAuthorityResult.reason : null,
      provider_calls: noAuthorityHarness.providerCalls(),
    },
  ));

  const lostFixture = evaluationFixture('operation:ccs-v14:indeterminate');
  const lostHarness = harness(lostFixture, { lose_response: true });
  const first = await lostHarness.boundary.run(boundaryInput(lostFixture));
  const retry = await lostHarness.boundary.run(boundaryInput(lostFixture));
  cases.push(caseResult(
    'INDETERMINATE-BLOCKS-BLIND-RETRY',
    'boundary',
    first.state === 'INDETERMINATE' && first.retry_allowed === false
      && retry.state !== 'EXECUTED' && lostHarness.providerCalls() === 1,
    'one provider entry, INDETERMINATE result, and no blind second entry',
    { first: first.state, retry: retry.state, provider_calls: lostHarness.providerCalls() },
  ));

  const base = {
    '@version': REPORT_VERSION,
    profile: PROFILE,
    source_lock: {
      source: CCS_V14_SOURCE_LOCK,
      repository: CCS_V14_VECTOR_REPOSITORY,
      commit: CCS_V14_VECTOR_COMMIT,
      manifest_sha256: CCS_V14_VECTOR_MANIFEST_SHA256,
    },
    cases,
    passed: cases.every((entry) => entry.passed),
    composition: {
      evidence: 'CCS v1.4 Ed25519 receipt and full tool-argument digest',
      exact_action: 'CAID over executor-owned GitHub issue-update parameters',
      authority: 'separate relying-party local_authorize decision',
      consequence_boundary: 'AEB verification, durable one-time consumption, and counted provider entry',
    },
    known_limits: [
      'This is an EMILIA independent composition fixture, not a Correctover product certification.',
      'The public vector proves source-compatible verification only; it does not authorize execution.',
      'The GitHub provider is a test stub. No live issue or external account is changed.',
      'At-most-one provider entry is not exactly-once physical effect.',
      'An INDETERMINATE result requires authenticated reconciliation; blind retry remains prohibited.',
    ],
  };
  return { ...base, results_digest: `sha256:${sha256Bytes(canonicalizeAeb(base))}` };
}

export async function runProfile(runner = {
  name: 'EMILIA reference runner',
  affiliation: 'EMILIA Protocol',
  revision: 'ccs-v14-aeb-github-v0.1',
  executed_at: NOW,
}) {
  return { ...(await buildReferenceReport()), runner };
}

if (process.argv[1]
  && realpathSync(resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url))) {
  const report = await buildReferenceReport();
  if (process.argv.includes('--reference')) {
    writeFileSync(REPORT_PATH, `${JSON.stringify(report, null, 2)}\n`);
    writeFileSync(VECTOR_PATH, `${JSON.stringify(buildReferenceVectors(), null, 2)}\n`);
  }
  if (process.argv.includes('--check')) {
    assert.equal(readFileSync(REPORT_PATH, 'utf8'), `${JSON.stringify(report, null, 2)}\n`);
    assert.equal(readFileSync(VECTOR_PATH, 'utf8'), `${JSON.stringify(buildReferenceVectors(), null, 2)}\n`);
  }
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (!report.passed) process.exitCode = 1;
}
