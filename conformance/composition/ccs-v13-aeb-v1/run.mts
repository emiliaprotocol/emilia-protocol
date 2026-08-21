// SPDX-License-Identifier: Apache-2.0
/** CCS-05 v1.3 independent receipt implementation to AEB mapping runner. */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  digestAeb,
  mappingProfileDigest,
  type AebAdapterInput,
  type AebPinnedProfile,
} from '../../../packages/verify/aeb-adapter-contract.js';
import {
  CCS_V13_AEB_ADAPTER_ID,
  CCS_V13_AEB_ADAPTER_VERSION,
  CCS_V13_AEB_CONFIG_VERSION,
  CCS_V13_AEB_TRUST_ROOT_VERSION,
  CCS_V13_CAID_MAPPER_ID,
  CCS_V13_CAID_MAPPING_VERSION,
  CCS_V13_DRAFT_SHA256,
  CCS_V13_DRAFT_URL,
  CCS_V13_REFERENCE_CODEBERG_COMMIT,
  CCS_V13_REFERENCE_PYPI_VERSION,
  CCS_V13_SOURCE_LOCK,
  createCcsV13AebActionDefinition,
  createCcsV13AebAdapter,
  type CcsV13AebAdapterConfig,
  type CcsV13Ed25519TrustRoot,
  type CcsV13Receipt,
} from '../../../packages/verify/aeb-ccs-adapter.js';
import { canonicalizeFiniteJson } from '../../../packages/verify/strict-json.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPORT_PATH = resolve(HERE, 'report.reference.json');
const SAMPLE_PATH = resolve(HERE, 'sample-receipts.reference.json');
const ACTION_TYPE = 'agent.tool-invocation.1';
const NOW = '2030-09-01T00:00:20Z';
const NOW_SECONDS = Date.parse(NOW) / 1000;
const ISSUED_AT = NOW_SECONDS - 20;
const EXPIRES_AT = ISSUED_AT + 60;
const PRIVATE_KEY = crypto.createPrivateKey({
  key: Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    crypto.createHash('sha256').update('emilia/ccs-05-v1.3-independent-interop/v1').digest(),
  ]),
  format: 'der',
  type: 'pkcs8',
});
const PUBLIC_RAW = crypto.createPublicKey(PRIVATE_KEY)
  .export({ type: 'spki', format: 'der' }).subarray(-32);
const LEGACY_TEST_SECRET = crypto.createHash('sha256')
  .update('emilia/ccs-05-v1.3-legacy-hmac-test-key/v1').digest();

type Command = {
  intake_version: '1.3';
  agent_id: string;
  tool: string;
  params: Record<string, number>;
  timestamp: number;
  trace_id: string;
  runtime_context: Record<string, string>;
};

type Check = {
  id: string;
  layer: 'CCS' | 'AEB' | 'LIVE-RUN';
  description: string;
  passed: boolean;
  observed: unknown;
};

function sha256Bytes(value: string | Buffer): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function sha256Json(value: unknown): string {
  return sha256Bytes(canonicalizeFiniteJson(value));
}

function prefixedJsonDigest(value: unknown): string {
  return `sha256:${sha256Json(value)}`;
}

function canonicalRequest(command: Command): Record<string, unknown> {
  return {
    agent_id: command.agent_id,
    params: command.params,
    timestamp: command.timestamp,
    tool: command.tool,
    trace_id: command.trace_id,
  };
}

function legacyReceipt(unsigned: Omit<CcsV13Receipt, 'receipt' | 'signature'>): string {
  const payload = [
    unsigned.trace_id, unsigned.verdict, unsigned.timestamp, unsigned.tool,
    unsigned.params_hash, unsigned.rule_summary, unsigned.request_hash,
    unsigned.response_hash, unsigned.runtime_context_hash, unsigned.action,
    unsigned.config_hash, unsigned.issuer, unsigned.audience, unsigned.nonce,
    unsigned.sequence, unsigned.issued_at, unsigned.expires_at,
  ].join(':');
  return crypto.createHmac('sha256', LEGACY_TEST_SECRET)
    .update(payload, 'utf8').digest('hex').slice(0, 32);
}

function signReceipt(fields: Omit<CcsV13Receipt, 'signature'>): CcsV13Receipt {
  return {
    ...fields,
    signature: crypto.sign(
      null,
      Buffer.from(canonicalizeFiniteJson(fields), 'utf8'),
      PRIVATE_KEY,
    ).toString('hex'),
  };
}

function mintReceipt(input: {
  command: Command;
  verdict: CcsV13Receipt['verdict'];
  blockReason: string;
  response: Record<string, unknown> | null;
  nonce: string;
  sequence: number;
}): CcsV13Receipt {
  const fullParamsHash = sha256Json(input.command.params);
  const base = {
    trace_id: input.command.trace_id,
    verdict: input.verdict,
    timestamp: ISSUED_AT,
    tool: input.command.tool,
    params_hash: fullParamsHash.slice(0, 16),
    rule_summary: input.verdict === 'allow'
      ? 'bounded_integer_inputs=allow'
      : 'bounded_integer_inputs=deny',
    verified_at: ISSUED_AT,
    block_reason: input.blockReason,
    request_hash: prefixedJsonDigest(canonicalRequest(input.command)),
    response_hash: input.response === null ? '' : prefixedJsonDigest(input.response),
    runtime_context_hash: prefixedJsonDigest(input.command.runtime_context),
    action: `ccs:tool-invoke:${input.command.tool}:${fullParamsHash}`,
    config_hash: prefixedJsonDigest({ policy_floor: 'bounded-integer-sum-v1' }),
    issuer: 'https://emilia-protocol.example/interop/ccs-v13',
    audience: 'https://gate.example/admit',
    nonce: input.nonce,
    sequence: input.sequence,
    issued_at: ISSUED_AT,
    expires_at: EXPIRES_AT,
    max_clock_skew: 5,
  } satisfies Omit<CcsV13Receipt, 'receipt' | 'signature'>;
  return signReceipt({ ...base, receipt: legacyReceipt(base) });
}

function executeSum(params: Record<string, number>): { result: number } {
  assert.equal(Object.keys(params).sort().join(','), 'left,right');
  assert.equal(Number.isSafeInteger(params.left), true);
  assert.equal(Number.isSafeInteger(params.right), true);
  assert.equal(Math.abs(params.left) <= 1_000_000, true);
  assert.equal(Math.abs(params.right) <= 1_000_000, true);
  return { result: params.left + params.right };
}

function profile(): AebPinnedProfile {
  const pin: AebPinnedProfile = {
    version: CCS_V13_CAID_MAPPING_VERSION,
    definition: createCcsV13AebActionDefinition(ACTION_TYPE),
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

function fixture() {
  const command: Command = {
    intake_version: '1.3',
    agent_id: 'agent:emilia-independent-interop',
    tool: 'sum',
    params: { left: 19, right: 23 },
    timestamp: ISSUED_AT,
    trace_id: '0123456789abcdef',
    runtime_context: { environment: 'local-live-run', tenant: 'public-interop' },
  };
  const response = executeSum(command.params);
  const allowReceipt = mintReceipt({
    command,
    verdict: 'allow',
    blockReason: '',
    response,
    nonce: '00112233445566778899aabbccddeeff',
    sequence: 1,
  });
  const denyCommand: Command = {
    ...command,
    params: { left: 1_000_001, right: 23 },
    trace_id: 'fedcba9876543210',
  };
  const denyReceipt = mintReceipt({
    command: denyCommand,
    verdict: 'deny',
    blockReason: 'bounded_integer_inputs',
    response: null,
    nonce: 'ffeeddccbbaa99887766554433221100',
    sequence: 2,
  });
  const config: CcsV13AebAdapterConfig = {
    '@version': CCS_V13_AEB_CONFIG_VERSION,
    evidence_role: 'machine-policy-decision',
    subject: { id: 'system:ccs-v13-independent-verifier', kind: 'system' },
    issuer: allowReceipt.issuer,
    audience: allowReceipt.audience,
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
    public_key_raw_base64: PUBLIC_RAW.toString('base64'),
    public_key_fingerprint_sha256_16: sha256Bytes(PUBLIC_RAW).slice(0, 16),
  };
  const action = {
    action_type: ACTION_TYPE,
    parameters: { tool: command.tool, arguments: command.params },
  };
  const status = {
    checked_at: NOW,
    expires_at: '2030-09-01T00:01:00Z',
    revocation_checked: true,
    revoked: false,
    consumed: false,
  };
  const adapter = createCcsV13AebAdapter({ config, trust_roots: [root] });
  const input = {
    artifact: allowReceipt,
    artifact_ref: 'ccs:v13:live-sum-001',
    status,
    trust_roots: [root],
    adapter_config: config,
    expected_action: action,
    now: NOW,
  } satisfies Omit<AebAdapterInput, 'profile'>;
  return { command, response, allowReceipt, denyReceipt, config, root, action, adapter, input, profile: profile() };
}

function check(id: string, layer: Check['layer'], description: string, passed: boolean, observed: unknown): Check {
  return { id, layer, description, passed, observed };
}

export function sampleReceiptSet() {
  const f = fixture();
  return {
    '@version': 'CCS-05-V1.3-INDEPENDENT-SAMPLE-SET-v1',
    source_lock: {
      draft_url: CCS_V13_DRAFT_URL,
      draft_sha256: CCS_V13_DRAFT_SHA256,
      codeberg_reference_commit: CCS_V13_REFERENCE_CODEBERG_COMMIT,
      pypi_reference_version: CCS_V13_REFERENCE_PYPI_VERSION,
    },
    live_run: { command: f.command, response: f.response },
    receipts: [
      { id: 'allow-live-sum', receipt: f.allowReceipt },
      { id: 'deny-out-of-policy', receipt: f.denyReceipt },
    ],
    relying_party_trust_root: f.root,
    limits: [
      'The signing and legacy-HMAC keys are public deterministic test material.',
      'The CCS legacy receipt field is generated but AEB relies on the pinned Ed25519 signature for cross-domain verification.',
      'The allow receipt is machine-policy-decision evidence and is not human authorization or provider-effect proof.',
    ],
  };
}

export function runSuite() {
  const f = fixture();
  const native = f.adapter.verifyNative(f.input);
  const mapping = f.adapter.mapAction({ ...f.input, profile: f.profile, native });
  const signatureTamper = { ...f.allowReceipt, response_hash: `sha256:${'f'.repeat(64)}` };
  const signatureTamperResult = f.adapter.verifyNative({ ...f.input, artifact: signatureTamper });
  const wrongAudienceConfig = { ...f.config, audience: 'https://other.example/admit' };
  const wrongAudienceAdapter = createCcsV13AebAdapter({ config: wrongAudienceConfig, trust_roots: [f.root] });
  const audienceResult = wrongAudienceAdapter.verifyNative({
    ...f.input,
    adapter_config: wrongAudienceConfig,
    trust_roots: [f.root],
  });
  const expired = f.adapter.verifyNative({ ...f.input, now: '2030-09-01T00:02:00Z' });
  const substituted = f.adapter.mapAction({
    ...f.input,
    expected_action: { ...f.action, parameters: { tool: 'sum', arguments: { left: 19, right: 24 } } },
    profile: f.profile,
    native,
  });
  const fullDigestMismatchUnsigned = { ...f.allowReceipt } as Record<string, unknown>;
  delete fullDigestMismatchUnsigned.signature;
  fullDigestMismatchUnsigned.action = `${String(fullDigestMismatchUnsigned.action).slice(0, -48)}${'0'.repeat(48)}`;
  const fullDigestMismatch = signReceipt(fullDigestMismatchUnsigned as Omit<CcsV13Receipt, 'signature'>);
  const fullDigestMismatchNative = f.adapter.verifyNative({ ...f.input, artifact: fullDigestMismatch });
  const fullDigestMismatchMapping = f.adapter.mapAction({
    ...f.input,
    artifact: fullDigestMismatch,
    profile: f.profile,
    native: fullDigestMismatchNative,
  });
  const consumed = f.adapter.verifyNative({ ...f.input, status: { ...f.input.status, consumed: true } });
  const unavailable = f.adapter.verifyNative({ ...f.input, status: { ...f.input.status, unavailable: true } });
  const denyInput = { ...f.input, artifact: f.denyReceipt, artifact_ref: 'ccs:v13:deny-001' };
  const denyNative = f.adapter.verifyNative(denyInput);
  const denyMapping = f.adapter.mapAction({ ...denyInput, profile: f.profile, native: denyNative });
  const wrongRaw = Buffer.alloc(32, 7);
  const wrongRoot: CcsV13Ed25519TrustRoot = {
    ...f.root,
    public_key_raw_base64: wrongRaw.toString('base64'),
    public_key_fingerprint_sha256_16: sha256Bytes(wrongRaw).slice(0, 16),
  };
  const wrongKeyAdapter = createCcsV13AebAdapter({ config: f.config, trust_roots: [wrongRoot] });
  const wrongKeyResult = wrongKeyAdapter.verifyNative({ ...f.input, trust_roots: [wrongRoot] });

  const checks: Check[] = [
    check('CCS-V13-SOURCE-PIN', 'CCS', 'The official CCS-05 bytes and current public implementation coordinates are pinned.',
      CCS_V13_DRAFT_SHA256 === 'c91f0fa31b1b9e5e2dfe79b99f3b554075d3a44d5309406e748b728f86767cb9',
      { source: CCS_V13_SOURCE_LOCK, draft_sha256: CCS_V13_DRAFT_SHA256 }),
    check('CCS-V13-SHAPE-SEPARATION', 'CCS', 'The v1.3 draft shape is not relabeled as the published package v1.1 receipt.',
      CCS_V13_REFERENCE_PYPI_VERSION === '1.1.14' && !('receipt_version' in f.allowReceipt),
      { package_version: CCS_V13_REFERENCE_PYPI_VERSION, receipt_fields: Object.keys(f.allowReceipt).length }),
    check('LIVE-SUM-EXECUTED', 'LIVE-RUN', 'The protected local operation executed and returned the response bound by the receipt.',
      f.response.result === 42 && f.allowReceipt.response_hash === prefixedJsonDigest(f.response),
      { response: f.response, response_hash: f.allowReceipt.response_hash }),
    check('CCS-V13-ED25519-ACCEPT', 'CCS', 'The 22-field receipt verifies under the relying-party-pinned Ed25519 issuer.',
      native.native_verification === 'VERIFIED' && native.acceptance === 'ACCEPTED', native),
    check('AEB-V13-EXACT-ACTION-MAP', 'AEB', 'The full receipt action digest maps to the executor-owned exact action and CAID.',
      mapping.mapping === 'MATCH', mapping),
    check('CCS-V13-SIGNATURE-TAMPER', 'CCS', 'Changing a signed response binding invalidates the receipt.',
      signatureTamperResult.native_verification === 'FAILED', signatureTamperResult),
    check('CCS-V13-UNTRUSTED-KEY', 'CCS', 'A relying-party root replacement cannot validate the receipt.',
      wrongKeyResult.native_verification === 'FAILED', wrongKeyResult),
    check('CCS-V13-AUDIENCE', 'CCS', 'A valid receipt is rejected for a different relying-party audience.',
      audienceResult.native_verification === 'VERIFIED' && audienceResult.acceptance === 'REJECTED', audienceResult),
    check('CCS-V13-EXPIRY', 'CCS', 'A signed receipt outside its freshness window is rejected.',
      expired.native_verification === 'VERIFIED' && expired.acceptance === 'REJECTED', expired),
    check('AEB-V13-PARAM-SUBSTITUTION', 'AEB', 'Changing executor-owned arguments produces an exact-action mismatch.',
      substituted.mapping === 'MISMATCH', substituted),
    check('AEB-V13-FULL-DIGEST', 'AEB', 'A signed action preserving the 16-hex prefix but changing the full digest is refused.',
      fullDigestMismatchNative.native_verification === 'VERIFIED' && fullDigestMismatchMapping.mapping === 'MISMATCH',
      fullDigestMismatchMapping),
    check('AEB-V13-REPLAY', 'AEB', 'Consumed status prevents a second acceptance of the receipt replay unit.',
      consumed.acceptance === 'REJECTED' && consumed.reasons.includes('evidence_consumed'), consumed),
    check('AEB-V13-STATUS-UNKNOWN', 'AEB', 'Unavailable authenticated status remains INDETERMINATE.',
      unavailable.acceptance === 'INDETERMINATE', unavailable),
    check('AEB-V13-DENY-NONAUTHORIZING', 'AEB', 'A native deny never becomes a mappable action admission.',
      denyNative.acceptance === 'REJECTED' && denyMapping.mapping === 'INDETERMINATE', { denyNative, denyMapping }),
  ];
  const sample = sampleReceiptSet();
  const report: Record<string, unknown> = {
    '@version': 'CCS-05-V1.3-AEB-COMPOSITION-REPORT-v1',
    profile: 'ccs-v13-aeb-v1',
    pins: {
      draft_url: CCS_V13_DRAFT_URL,
      draft_sha256: CCS_V13_DRAFT_SHA256,
      source_lock: CCS_V13_SOURCE_LOCK,
      reference_codeberg_commit: CCS_V13_REFERENCE_CODEBERG_COMMIT,
      reference_pypi_version: CCS_V13_REFERENCE_PYPI_VERSION,
      adapter_id: CCS_V13_AEB_ADAPTER_ID,
      adapter_version: CCS_V13_AEB_ADAPTER_VERSION,
      mapping_profile_digest: f.profile.profile_digest,
      sample_set_digest: `sha256:${sha256Json(sample)}`,
    },
    checks,
    passed: checks.every((entry) => entry.passed),
    known_limits: [
      'This is an independent implementation of the CCS-05 v1.3 receipt profile, not a claim that ccs-verifier 1.1.14 emits the same shape.',
      'The public test keys are not production trust anchors.',
      'A CCS allow is machine-policy-decision evidence. It is not human authorization, AEB admission, provider entry, or effect proof.',
      'The adapter verifies the Ed25519 signature. The legacy HMAC receipt field is retained as signed issuer data, not a cross-domain trust root.',
      'A passing report is a self-attested reproduction package until an external operator independently runs it.',
    ],
  };
  report.report_digest = `sha256:${sha256Json(report)}`;
  return report;
}

function main() {
  const report = runSuite();
  const sample = sampleReceiptSet();
  const renderedReport = `${JSON.stringify(report, null, 2)}\n`;
  const renderedSample = `${JSON.stringify(sample, null, 2)}\n`;
  if (process.argv.includes('--write')) {
    writeFileSync(REPORT_PATH, renderedReport);
    writeFileSync(SAMPLE_PATH, renderedSample);
  }
  if (process.argv.includes('--check')) {
    if (readFileSync(REPORT_PATH, 'utf8') !== renderedReport) throw new Error('CCS-05 v1.3 report is stale');
    if (readFileSync(SAMPLE_PATH, 'utf8') !== renderedSample) throw new Error('CCS-05 v1.3 sample receipt set is stale');
  }
  process.stdout.write(renderedReport);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
