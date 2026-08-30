// SPDX-License-Identifier: Apache-2.0
/** Deterministic CCS draft-08 v1.3 Crossing Lab fixture and hostile suite. */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  readFileSync,
  readdirSync,
  writeFileSync,
} from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  adapterPinDigest,
  digestAeb,
  mappingProfileDigest,
  registryEntryDigest,
  unifiedRegistryDigest,
} from '../../../packages/verify/dist/aeb-adapter-contract.js';
import {
  digestCrossingLab,
  runCrossingLab,
} from '../../../packages/verify/dist/crossing-lab.js';
import { computeCaid } from '../../../packages/verify/vendor/caid.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../../..');
const WORKSPACE_DIR = resolve(ROOT, 'examples/aeb-crossing-lab/ccs-wang-draft08-v13');
const ADAPTER_PATH = resolve(WORKSPACE_DIR, 'adapter.mjs');
const ARTIFACT_PATH = resolve(WORKSPACE_DIR, 'artifact.json');
const WORKSPACE_PATH = resolve(WORKSPACE_DIR, 'workspace.json');
const SOURCE_LOCK_PATH = resolve(HERE, 'source-lock.json');
const VECTORS_PATH = resolve(HERE, 'vectors.reference.json');
const REPORT_PATH = resolve(HERE, 'report.reference.json');

const SOURCE_LOCK_ID = 'draft-correctover-ccs-08-v1.3-fbac2a025f11baec';
const DRAFT_SHA256 = 'fbac2a025f11baec104687ee04ba5c9fb0dad1b5bbb5ad38494965565a977cd3';
const ADAPTER_ID = 'native:ccs-draft08-v1.3-ed25519';
const ADAPTER_VERSION = '1.0.0';
const CONFIG_VERSION = 'AEB-CCS-DRAFT08-V1.3-CONFIG-v1';
const ROOT_VERSION = 'AEB-CCS-DRAFT08-V1.3-ROOT-v1';
const MAPPING_VERSION = 'AEB-CCS-DRAFT08-V1.3-TOOL-ACTION-MAPPING-v1';
const MAPPER_ID = 'mapper:ccs-draft08-v1.3-tool-action-v1';
const PROFILE_ID = 'ccs-draft08-v13-tool-action';
const MAPPING_REGISTRY_REF = 'mapping:ccs-draft08-v13-tool-action';
const ACTION_TYPE = 'agent.tool-invocation.1';
const EVALUATED_AT = '2030-09-01T00:00:20Z';
const ISSUED_AT = Date.parse('2030-09-01T00:00:00Z') / 1000;
const EXPIRES_AT = Date.parse('2030-09-01T00:01:00Z') / 1000;
const LAB_EVALUATOR_PUBLIC_SPKI = 'MCowBQYDK2VwAyEAc_kUSHs4ymdA65GF3OV8C3PDWhelodqfOvCmFe-6oUI';
const TEST_PRIVATE_JWK = Object.freeze({
  crv: 'Ed25519',
  d: 'QzzaMDIcqR2vZMuzJ9nvFKFg-xCDZUqNoLoOFJ7GbpQ',
  x: 'J44hPfhth6DPuhIaicostxApd060k-EmfHhKGlrxasA',
  kty: 'OKP',
});
const PRIVATE_KEY = crypto.createPrivateKey({ key: TEST_PRIVATE_JWK, format: 'jwk' });
const PUBLIC_RAW = crypto.createPublicKey(PRIVATE_KEY)
  .export({ type: 'spki', format: 'der' }).subarray(-32);
const LEGACY_TEST_SECRET = crypto.createHash('sha256')
  .update('emilia/ccs-wang-draft08-v13-legacy-receipt/v1').digest();

const OMITTED_NONMATERIAL_FIELDS = [
  'trace_id', 'verdict', 'timestamp', 'params_hash', 'rule_summary', 'receipt',
  'verified_at', 'block_reason', 'request_hash', 'response_hash',
  'runtime_context_hash', 'config_hash', 'issuer', 'audience', 'nonce',
  'sequence', 'issued_at', 'expires_at', 'max_clock_skew', 'signature',
];

function jcs(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('non-finite JSON number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${jcs(value[key])}`).join(',')}}`;
  }
  throw new TypeError('non-JSON value');
}

function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function prefixedJsonDigest(value) {
  return `sha256:${sha256Hex(jcs(value))}`;
}

function legacyReceipt(unsigned) {
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

function signBody(body) {
  return {
    ...body,
    signature: crypto.sign(null, Buffer.from(jcs(body), 'utf8'), PRIVATE_KEY).toString('hex'),
  };
}

function requestFor(command) {
  return {
    agent_id: command.agent_id,
    params: command.params,
    timestamp: command.timestamp,
    tool: command.tool,
    trace_id: command.trace_id,
  };
}

function makeReceipt({ command, verdict, blockReason, response, nonce, sequence, actionOverride }) {
  const fullParamsHash = sha256Hex(jcs(command.params));
  const base = {
    trace_id: command.trace_id,
    verdict,
    timestamp: ISSUED_AT + 20,
    tool: command.tool,
    params_hash: fullParamsHash.slice(0, 16),
    rule_summary: verdict === 'allow' ? 'bounded_integer_inputs=allow' : `bounded_integer_inputs=${verdict}`,
    verified_at: ISSUED_AT + 20,
    block_reason: blockReason,
    request_hash: prefixedJsonDigest(requestFor(command)),
    response_hash: response === null ? '' : prefixedJsonDigest(response),
    runtime_context_hash: prefixedJsonDigest(command.runtime_context),
    action: actionOverride ?? `ccs:tool-invoke:${command.tool}:${fullParamsHash}`,
    config_hash: prefixedJsonDigest({ policy_floor: 'bounded-integer-sum-v1' }),
    issuer: 'https://correctover.example/ccs/draft08/test',
    audience: 'https://gate.example/admission/ccs-wang-draft08',
    nonce,
    sequence,
    issued_at: ISSUED_AT,
    expires_at: EXPIRES_AT,
    max_clock_skew: 5,
  };
  return signBody({ ...base, receipt: legacyReceipt(base) });
}

function executeSum(params) {
  assert.deepEqual(Object.keys(params).sort(), ['left', 'right']);
  assert.equal(Number.isSafeInteger(params.left), true);
  assert.equal(Number.isSafeInteger(params.right), true);
  assert.equal(Math.abs(params.left) <= 1_000_000, true);
  assert.equal(Math.abs(params.right) <= 1_000_000, true);
  return { result: params.left + params.right };
}

function mappingDefinition() {
  return {
    '@version': MAPPING_VERSION,
    source: SOURCE_LOCK_ID,
    source_media_type: 'application/x-ccs-receipt+json',
    projection: 'ccs-v13-signed-tool-and-full-params-digest-v1',
    action_type: ACTION_TYPE,
    suite: 'jcs-sha256',
    definitions: [{
      action_type: ACTION_TYPE,
      required_fields: [
        { name: 'action_type', type: 'string' },
        { name: 'parameters', type: 'object' },
      ],
      optional_fields: [],
    }],
  };
}

function registryEntry(id, kind, definition) {
  const entry = { kind, version: '1', status: 'active', definition, definition_digest: digestAeb(null) };
  entry.definition_digest = registryEntryDigest(id, entry);
  return entry;
}

function fixtures() {
  const command = {
    intake_version: '1.3',
    agent_id: 'agent:ccs-wang-public-vector',
    tool: 'sum',
    params: { left: 19, right: 23 },
    timestamp: ISSUED_AT,
    trace_id: '0123456789abcdef',
    runtime_context: { environment: 'local-crossing-lab', tenant: 'public-interop' },
  };
  const response = executeSum(command.params);
  const positive = makeReceipt({
    command, verdict: 'allow', blockReason: '', response,
    nonce: '00112233445566778899aabbccddeeff', sequence: 1,
  });
  const deny = makeReceipt({
    command, verdict: 'deny', blockReason: 'bounded_integer_inputs', response: null,
    nonce: '11112222333344445555666677778888', sequence: 2,
  });
  const escalate = makeReceipt({
    command, verdict: 'escalate', blockReason: 'operator_review_required', response: null,
    nonce: '9999aaaabbbbccccddddeeeeffff0000', sequence: 3,
  });
  const fullParamsHash = sha256Hex(jcs(command.params));
  const samePrefixDifferentFullDigest = makeReceipt({
    command, verdict: 'allow', blockReason: '', response,
    nonce: 'abcdefabcdefabcdefabcdefabcdefab', sequence: 4,
    actionOverride: `ccs:tool-invoke:${command.tool}:${fullParamsHash.slice(0, 16)}${'0'.repeat(48)}`,
  });
  return { command, response, positive, deny, escalate, samePrefixDifferentFullDigest };
}

function buildWorkspace() {
  const f = fixtures();
  const action = {
    action_type: ACTION_TYPE,
    parameters: { tool: f.command.tool, arguments: f.command.params },
  };
  const hostileAction = {
    action_type: ACTION_TYPE,
    parameters: { tool: f.command.tool, arguments: { left: 19, right: 24 } },
  };
  const definition = mappingDefinition();
  const profile = {
    version: MAPPING_VERSION,
    definition,
    registry_entry_ref: MAPPING_REGISTRY_REF,
    mapper_id: MAPPER_ID,
    resolver: {
      id: MAPPER_ID,
      version: '1.0.0',
      implementation_digest: digestAeb({ implementation: MAPPER_ID, version: '1.0.0' }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: OMITTED_NONMATERIAL_FIELDS,
    },
    profile_digest: digestAeb(null),
  };
  profile.profile_digest = mappingProfileDigest(PROFILE_ID, profile);
  const entries = {
    [MAPPING_REGISTRY_REF]: registryEntry(MAPPING_REGISTRY_REF, 'mapping-profile', { profile_digest: profile.profile_digest }),
    'role:machine-policy-decision': registryEntry(
      'role:machine-policy-decision',
      'evidence-role',
      { role: 'machine-policy-decision', subject_kinds: ['system'] },
    ),
  };
  const registry = {
    '@version': 'EP-EVIDENCE-REGISTRY-v1',
    registry_id: 'registry:ccs-wang-draft08-crossing-lab',
    epoch: 1,
    entries,
    registry_digest: digestAeb(null),
  };
  registry.registry_digest = unifiedRegistryDigest(registry);
  const config = {
    '@version': CONFIG_VERSION,
    evidence_role: 'machine-policy-decision',
    subject: { id: 'system:ccs-wang-draft08-public-vector', kind: 'system' },
    issuer: f.positive.issuer,
    audience: f.positive.audience,
    action_type: ACTION_TYPE,
    allowed_tools: ['sum'],
    max_receipt_age_seconds: 300,
    max_clock_skew_seconds: 5,
    deployment_scope: 'pinned-ed25519-issuer',
  };
  const trustRoot = {
    '@version': ROOT_VERSION,
    issuer: config.issuer,
    key_id: 'ccs-wang-draft08-public-test-key-1',
    algorithm: 'Ed25519',
    public_key_raw_base64: PUBLIC_RAW.toString('base64'),
    public_key_fingerprint_sha256_16: sha256Hex(PUBLIC_RAW).slice(0, 16),
  };
  const adapterPin = {
    version: ADAPTER_VERSION,
    trust_roots: [trustRoot],
    config,
    config_digest: digestAeb(null),
    max_status_age_sec: 300,
  };
  adapterPin.config_digest = adapterPinDigest(ADAPTER_ID, adapterPin);
  const status = {
    checked_at: '2030-09-01T00:00:00Z',
    expires_at: '2030-09-01T00:01:00Z',
    revocation_checked: true,
    revoked: false,
    consumed: false,
    unavailable: false,
  };
  const caid = computeCaid(action, { suite: definition.suite, definitions: definition.definitions });
  assert.equal(typeof caid.caid, 'string');
  assert.equal(typeof caid.digest, 'string');
  const adapterBytes = readFileSync(ADAPTER_PATH);
  const workspace = {
    '@version': 'EMILIA-CROSSING-LAB-LOCAL-WORKSPACE-v1',
    adapter: {
      id: ADAPTER_ID,
      version: ADAPTER_VERSION,
      module: 'adapter.mjs',
      module_digest: `sha256:${sha256Hex(adapterBytes)}`,
    },
    artifact: 'artifact.json',
    artifact_digest: digestAeb(f.positive),
    config: {
      '@version': 'AEB-ADAPTER-v1',
      relying_party_id: 'rp:emilia:ccs-wang-draft08',
      evaluator_keys: {
        'crossing-lab:self-test': { public_key: LAB_EVALUATOR_PUBLIC_SPKI },
      },
      registry,
      accepted_mappers: [MAPPER_ID],
      adapters: { [ADAPTER_ID]: adapterPin },
      profiles: { [PROFILE_ID]: profile },
      requirements: {
        'requirement:machine-policy-decision': {
          '@version': 'AEB-REQUIREMENT-v1',
          all_of: ['machine-policy-decision'],
          terms: [{ type: 'one-time-consumption' }],
        },
      },
    },
    evaluated_at: EVALUATED_AT,
    evaluation: {
      operation_id: 'operation:ccs-wang-draft08:allow-live-sum',
      consumption_nonce: 'nonce:ccs-wang-draft08:allow-live-sum',
      initiator_id: 'agent:ccs-wang-public-vector',
      executor_id: 'executor:crossing-lab',
      requirement_ref: 'requirement:machine-policy-decision',
      profile_id: PROFILE_ID,
      artifact_ref: 'ccs:draft08:v13:allow-live-sum',
      caid: caid.caid,
      status,
      status_digest: digestAeb(status),
    },
    expected_action: action,
    expected_action_digest: digestAeb(action),
    hostile_expected_action: hostileAction,
    hostile_expected_action_digest: digestAeb(hostileAction),
  };
  return { ...f, action, hostileAction, config, trustRoot, profile, status, workspace };
}

function vectorSet() {
  const f = buildWorkspace();
  return {
    '@version': 'CCS-DRAFT08-V1.3-CROSSING-VECTORS-v1',
    source_lock: SOURCE_LOCK_ID,
    public_test_material: true,
    warnings: [
      'The deterministic private key is public test material and MUST NOT be trusted in production.',
      'A valid CCS allow is machine-policy-decision evidence, not authorization or effect proof.',
    ],
    command: f.command,
    observed_response: f.response,
    artifacts: {
      'allow-live-sum': f.positive,
      'deny-policy': f.deny,
      'escalate-operator-review': f.escalate,
      'same-prefix-different-full-digest': f.samePrefixDifferentFullDigest,
    },
  };
}

function check(id, layer, description, passed, observed) {
  return { id, layer, description, passed, observed };
}

async function runSuite() {
  const sourceLock = JSON.parse(readFileSync(SOURCE_LOCK_PATH, 'utf8'));
  const f = buildWorkspace();
  const adapterUrl = `${pathToFileURL(ADAPTER_PATH).href}?suite=${crypto.randomUUID()}`;
  const adapter = (await import(adapterUrl)).default;
  const input = {
    artifact: f.positive,
    artifact_ref: f.workspace.evaluation.artifact_ref,
    status: f.status,
    trust_roots: [f.trustRoot],
    adapter_config: f.config,
    profile: f.profile,
    expected_action: f.action,
    now: EVALUATED_AT,
  };
  const positiveNative = adapter.verifyNative(input);
  const positiveMap = adapter.mapAction({ ...input, native: positiveNative });
  const lab = runCrossingLab(WORKSPACE_DIR);

  const tampered = { ...f.positive, response_hash: `sha256:${'f'.repeat(64)}` };
  const signatureTamper = adapter.verifyNative({ ...input, artifact: tampered });
  const unknownMember = adapter.verifyNative({ ...input, artifact: { ...f.positive, delegated_authority: true } });
  const wrongAudienceConfig = { ...f.config, audience: 'https://other.example/admission' };
  const audienceResult = adapter.verifyNative({ ...input, adapter_config: wrongAudienceConfig });
  const wrongRaw = Buffer.alloc(32, 7);
  const wrongRoot = {
    ...f.trustRoot,
    public_key_raw_base64: wrongRaw.toString('base64'),
    public_key_fingerprint_sha256_16: sha256Hex(wrongRaw).slice(0, 16),
  };
  const wrongRootResult = adapter.verifyNative({ ...input, trust_roots: [wrongRoot] });
  const expired = adapter.verifyNative({ ...input, now: '2030-09-01T00:02:00Z' });
  const unavailable = adapter.verifyNative({ ...input, status: { ...f.status, unavailable: true } });
  const consumed = adapter.verifyNative({ ...input, status: { ...f.status, consumed: true } });
  const denyNative = adapter.verifyNative({ ...input, artifact: f.deny });
  const denyMap = adapter.mapAction({ ...input, artifact: f.deny, native: denyNative });
  const escalateNative = adapter.verifyNative({ ...input, artifact: f.escalate });
  const prefixNative = adapter.verifyNative({ ...input, artifact: f.samePrefixDifferentFullDigest });
  const prefixMap = adapter.mapAction({
    ...input,
    artifact: f.samePrefixDifferentFullDigest,
    native: prefixNative,
  });
  const substitutedProfile = {
    ...f.profile,
    semantic_equivalence: {
      ...f.profile.semantic_equivalence,
      omitted_material_fields: ['parameters'],
    },
  };
  const profileSubstitution = adapter.mapAction({
    ...input,
    profile: substitutedProfile,
    native: positiveNative,
  });
  const exactFiles = readdirSync(WORKSPACE_DIR).sort();
  const checks = [
    check('CCS-08-SOURCE-LOCK', 'SOURCE', 'The published draft-08 bytes are pinned by URL, byte length, and SHA-256.',
      sourceLock.draft?.name === 'draft-correctover-ccs-08'
        && sourceLock.draft?.bytes === 153156
        && sourceLock.draft?.sha256 === DRAFT_SHA256,
      sourceLock.draft),
    check('CCS-08-EXACT-WORKSPACE', 'LAB', 'The runnable public workspace contains exactly the three pinned Lab inputs.',
      JSON.stringify(exactFiles) === JSON.stringify(['adapter.mjs', 'artifact.json', 'workspace.json']), exactFiles),
    check('CCS-08-22-FIELD-SHAPE', 'CCS', 'The fixture is the exact 22-field v1.3 receipt shape.',
      Object.keys(f.positive).length === 22 && !Object.hasOwn(f.positive, 'receipt_version'), Object.keys(f.positive).sort()),
    check('CCS-08-ED25519-ACCEPT', 'CCS', 'The receipt verifies under the relying-party-pinned Ed25519 issuer and audience.',
      positiveNative.native_verification === 'VERIFIED' && positiveNative.acceptance === 'ACCEPTED', positiveNative),
    check('CCS-08-EXACT-ACTION-CAID', 'AEB', 'Both the truncated params_hash and signed full digest bind the executor-owned action and CAID.',
      positiveMap.mapping === 'MATCH'
        && positiveMap.caid === f.workspace.evaluation.caid
        && positiveMap.action_digest === f.workspace.expected_action_digest, positiveMap),
    check('CCS-08-LIVE-RESPONSE-BINDING', 'LIVE-FIXTURE', 'The local sum result matches the signed response_hash.',
      f.response.result === 42 && f.positive.response_hash === prefixedJsonDigest(executeSum(f.command.params)),
      { response: f.response, response_hash: f.positive.response_hash }),
    check('CCS-08-SIGNATURE-TAMPER', 'HOSTILE', 'Changing a signed response hash invalidates the receipt.',
      signatureTamper.native_verification === 'FAILED' && signatureTamper.acceptance === 'REJECTED', signatureTamper),
    check('CCS-08-UNKNOWN-FIELD', 'HOSTILE', 'An unsigned extra member cannot smuggle authority into the closed 22-field receipt.',
      unknownMember.native_verification === 'FAILED' && unknownMember.acceptance === 'REJECTED', unknownMember),
    check('CCS-08-RP-AUDIENCE', 'HOSTILE', 'A cryptographically valid receipt is refused under a different relying-party audience.',
      audienceResult.native_verification === 'VERIFIED' && audienceResult.acceptance === 'REJECTED', audienceResult),
    check('CCS-08-TRUST-SUBSTITUTION', 'HOSTILE', 'Replacing the relying-party-pinned issuer key cannot validate the receipt.',
      wrongRootResult.native_verification === 'FAILED' && wrongRootResult.acceptance === 'REJECTED', wrongRootResult),
    check('CCS-08-FRESHNESS', 'HOSTILE', 'A signed receipt outside its native freshness window is refused.',
      expired.native_verification === 'VERIFIED' && expired.acceptance === 'REJECTED', expired),
    check('CCS-08-FULL-DIGEST', 'HOSTILE', 'Preserving params_hash while changing the signed full digest cannot match the exact action.',
      prefixNative.native_verification === 'VERIFIED'
        && prefixNative.acceptance === 'ACCEPTED'
        && prefixMap.mapping === 'MISMATCH', { native: prefixNative, mapping: prefixMap }),
    check('CCS-08-PROFILE-SUBSTITUTION', 'HOSTILE', 'A mapping profile that omits a material action field is refused.',
      profileSubstitution.mapping === 'INDETERMINATE'
        && profileSubstitution.reasons.includes('mapping_profile_invalid'), profileSubstitution),
    check('CCS-08-STATUS-UNAVAILABLE', 'HOSTILE', 'Unavailable authenticated status remains indeterminate.',
      unavailable.native_verification === 'VERIFIED' && unavailable.acceptance === 'INDETERMINATE', unavailable),
    check('CCS-08-REPLAY-CONSUMED', 'HOSTILE', 'Consumed status refuses a second acceptance of the issuer-plus-nonce replay unit.',
      consumed.native_verification === 'VERIFIED' && consumed.acceptance === 'REJECTED', consumed),
    check('CCS-08-DENY-NONAUTHORIZING', 'BOUNDARY', 'A valid CCS deny remains rejected and cannot map an admitted action.',
      denyNative.native_verification === 'VERIFIED'
        && denyNative.acceptance === 'REJECTED'
        && denyMap.mapping === 'INDETERMINATE', { native: denyNative, mapping: denyMap }),
    check('CCS-08-ESCALATE-INDETERMINATE', 'BOUNDARY', 'A valid CCS escalate remains indeterminate rather than becoming an allow.',
      escalateNative.native_verification === 'VERIFIED' && escalateNative.acceptance === 'INDETERMINATE', escalateNative),
    check('CCS-08-LAB-ROWS', 'LAB', 'Every standard Lab adapter row and harness self-test passes.',
      lab.lab_passed === true && lab.summary.adapter_rows === 6 && lab.summary.failed === 0 && lab.summary.harness_failed === 0,
      lab.summary),
    check('CCS-08-CLAIM-BOUNDARY', 'BOUNDARY', 'The Lab keeps authorization and execution evidence outside this composition claim.',
      f.config.evidence_role === 'machine-policy-decision'
        && lab.non_claims.includes('authorization')
        && lab.non_claims.includes('execution_evidence'),
      { evidence_role: f.config.evidence_role, non_claims: lab.non_claims }),
  ];
  const body = {
    '@version': 'CCS-DRAFT08-V1.3-CROSSING-LAB-REPORT-v1',
    profile: 'ccs-draft08-v13-crossing-lab-v1',
    source_lock: {
      id: SOURCE_LOCK_ID,
      draft_url: sourceLock.draft.url,
      draft_bytes: sourceLock.draft.bytes,
      draft_sha256: sourceLock.draft.sha256,
      source_lock_digest: digestAeb(sourceLock),
    },
    workspace: {
      path: 'examples/aeb-crossing-lab/ccs-wang-draft08-v13',
      workspace_digest: digestCrossingLab(f.workspace),
      artifact_digest: f.workspace.artifact_digest,
      adapter_module_digest: f.workspace.adapter.module_digest,
      mapping_profile_digest: f.profile.profile_digest,
    },
    crossing_lab: lab,
    checks,
    passed: checks.every((entry) => entry.passed),
    claim_boundary: {
      native_contribution: 'signed machine-policy-decision evidence for one pinned issuer, audience, and exact action',
      relying_party_decision: 'Gate admission remains a separate local decision',
      response_hash: 'signed response-byte commitment, not physical or application effect proof',
      authorization: false,
      certification: false,
      deployment_evidence: false,
      independent_interoperability: false,
    },
    adoption_gates: [
      'Wang or another native author confirms the mapping preserves CCS semantics.',
      'A second runner reproduces the pinned report.',
      'One real system installs the profile beside its CCS verifier and Gate deployment.',
    ],
  };
  return { ...body, report_digest: digestAeb(body) };
}

function rendered(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

async function main() {
  const f = buildWorkspace();
  const vectors = vectorSet();
  if (process.argv.includes('--write')) {
    writeFileSync(ARTIFACT_PATH, rendered(f.positive));
    writeFileSync(WORKSPACE_PATH, rendered(f.workspace));
    writeFileSync(VECTORS_PATH, rendered(vectors));
  }
  if (process.argv.includes('--check')) {
    assert.equal(readFileSync(ARTIFACT_PATH, 'utf8'), rendered(f.positive), 'CCS artifact fixture is stale');
    assert.equal(readFileSync(WORKSPACE_PATH, 'utf8'), rendered(f.workspace), 'CCS Crossing Lab workspace is stale');
    assert.equal(readFileSync(VECTORS_PATH, 'utf8'), rendered(vectors), 'CCS hostile vectors are stale');
  }
  const report = await runSuite();
  if (process.argv.includes('--write')) writeFileSync(REPORT_PATH, rendered(report));
  if (process.argv.includes('--check')) {
    assert.equal(readFileSync(REPORT_PATH, 'utf8'), rendered(report), 'CCS Crossing Lab report is stale');
  }
  process.stdout.write(rendered(report));
  if (!report.passed) process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}

export { buildWorkspace, runSuite, vectorSet };
