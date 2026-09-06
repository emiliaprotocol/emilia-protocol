// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  AGENT_EVALUATION_EVIDENCE_PREDICATE, CANDIDATE_MANIFEST_VERSION,
  EVALUATION_CAMPAIGN_PREDICATE, IN_TOTO_PAYLOAD_TYPE, IN_TOTO_STATEMENT_V1,
  QUALIFICATION_PROPERTY, QUALIFICATION_STATEMENT_PREDICATE,
  QUALIFICATION_STATUS_PAYLOAD_TYPE, QUALIFICATION_STATUS_VERSION,
  RUNTIME_CANDIDATE_MEASUREMENT_VERSION, RUNTIME_MEASUREMENT_PAYLOAD_TYPE,
  TEST_RESULT_PREDICATE, canonicalizeQualification, dsseSigningBytes,
  qualificationGraphDigest, qualificationPayloadDigest, terminalOutcomesRoot,
} from '../packages/verify/gate-qualification.js';

import {
  evaluateMarketplaceQualification,
  MARKETPLACE_QUALIFICATION_CONFIG_VERSION,
  MARKETPLACE_QUALIFICATION_MAX_BYTES,
  readHostedQualificationConfiguration,
  validateMarketplaceQualificationRequest,
} from '../lib/works/marketplace-qualification';
import QualificationForm, { QualificationResult } from '../app/works/qualification/QualificationForm';
import { isQualificationResponseProjection, qualificationDisplayDeadline, qualificationDisplayRemaining, qualificationWindowRemaining } from '../app/works/qualification/display-window';

const rate = vi.hoisted(() => vi.fn());
vi.mock('@/lib/rate-limit', () => ({ checkRateLimit: rate, getClientIP: () => 'trusted-test-ip' }));

const digest = `sha256:${'a'.repeat(64)}`;
const envelope = {
  payloadType: 'application/vnd.in-toto+json',
  payload: 'e30=',
  signatures: [{ keyid: 'untrusted-upload', sig: 'YQ==' }],
};
const request = () => ({
  scope_id: 'refunds-test-v1',
  evidence: {
    candidate_manifest: {
      profile: 'EP-CANDIDATE-MANIFEST-v1', candidate_id: 'refund-agent',
      static: {
        code_digests: [digest], dependency_digests: [],
        prompt_template_digests: [digest], tool_definition_digests: [digest],
        effective_permissions_digest: digest,
        model: { provider: 'test', identity: 'test', version: '1', artifact_digest: digest, pinning_strength: 'IMMUTABLE_DIGEST' },
        retrieval_configuration_digest: digest, builder_orchestrator_digest: digest,
      },
    },
    campaigns: [structuredClone(envelope)], test_results: [],
    agent_evaluation_evidence: [structuredClone(envelope)],
    qualification_statement: structuredClone(envelope),
    runtime_measurement: { ...structuredClone(envelope), payloadType: 'application/vnd.emilia.runtime-candidate-measurement+json' },
  },
});

afterEach(() => vi.unstubAllEnvs());

describe('marketplace qualification trust boundary', () => {
  it('validates an evidence-shaped request but fails closed when hosted trust is absent', () => {
    expect(validateMarketplaceQualificationRequest(request()).ok).toBe(true);
    const result = evaluateMarketplaceQualification(request(), null, new Date('2026-09-05T12:00:00Z'));
    expect(result.status).toBe('UNAVAILABLE');
    expect(result.reason).toBe('qualification_not_configured');
    expect(result.result).toBeNull();
    expect(result.display).toBeNull();
  });

  it.each(['qualified', 'verdict', 'paid', 'installed', 'scan', 'trust', 'context', 'now', 'status'])('rejects presenter-controlled %s', (field) => {
    const input = { ...request(), [field]: true };
    expect(validateMarketplaceQualificationRequest(input).ok).toBe(false);
    expect(evaluateMarketplaceQualification(input, null).status).toBe('INVALID_REQUEST');
  });

  it('rejects uploaded current-status observations and status chains', () => {
    for (const field of ['qualification_status_chain', 'qualification_status_observation']) {
      const input = request();
      Object.assign(input.evidence, { [field]: {} });
      expect(validateMarketplaceQualificationRequest(input).ok).toBe(false);
    }
  });

  it('rejects malformed, boolean and cyclic inputs without throwing or invoking accessors', () => {
    let reads = 0;
    const getter = Object.defineProperty({}, 'scope_id', { enumerable: true, get() { reads += 1; throw new Error('private'); } });
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    for (const input of [true, false, null, {}, [], 'QUALIFIED', getter, cyclic]) {
      expect(evaluateMarketplaceQualification(input, null).status).toBe('INVALID_REQUEST');
    }
    expect(reads).toBe(0);
  });

  it('does not silently replace malformed operator configuration with demo trust', () => {
    vi.stubEnv('EMILIA_WORKS_QUALIFICATION_CONFIG_JSON', '{not-json');
    const result = evaluateMarketplaceQualification(request(), readHostedQualificationConfiguration());
    expect(result.status).toBe('UNAVAILABLE');
    expect(result.reason).toBe('qualification_configuration_invalid');
    expect(JSON.stringify(result)).not.toContain('not-json');
  });
});

describe('qualification display lifetime and copy', () => {
  it('renders unknown proxy reason keys as plain result codes, never object properties', () => {
    for (const reason of ['__proto__', 'constructor', 'toString']) {
      const response = { ...evaluateMarketplaceQualification(request(), null), reason };
      const html = renderToStaticMarkup(createElement(QualificationResult, { response, remaining: 0 }));
      expect(html).toContain('No qualification result available');
      expect(html).toContain('The verifier did not establish a current qualification');
      expect(html).toContain(`<code>${reason}</code>`);
    }
  });
  it('expires across foreground device sleep and wall-clock rollback without relying on clock accuracy', () => {
    const window = { deadline: 30_100, monotonicStartedAt: 100, wallStartedAt: 1_000_000 };
    expect(qualificationWindowRemaining(window, 1100, 1_001_000)).toBe(29);
    expect(qualificationWindowRemaining(window, 1100, 1_300_000)).toBe(0);
    expect(qualificationWindowRemaining(window, 5100, 1_001_000)).toBe(0);
    expect(qualificationWindowRemaining(window, 1100, 999_999)).toBe(0);
    expect(qualificationWindowRemaining(window, 99, 1_001_000)).toBe(0);
    expect(qualificationWindowRemaining(window, NaN, 1_001_000)).toBe(0);
  });

  it('rejects malformed proxy JSON and partially qualified display projections', () => {
    expect(isQualificationResponseProjection({ status: 'UNAVAILABLE', reason: 'proxy_error', result: {}, display: null })).toBe(false);
    expect(isQualificationResponseProjection({ status: 'QUALIFIED', reason: 'okay', result: {}, display: {} })).toBe(false);
    const value = fixture();
    const result = evaluateMarketplaceQualification(value.input, value.config, NOW);
    expect(isQualificationResponseProjection(result)).toBe(true);
    for (const dimension of ['verification', 'acceptance', 'candidate_match', 'assignment_scope', 'currentness', 'campaign_graph']) {
      const broken = structuredClone(result);
      broken.result![dimension] = undefined;
      expect(isQualificationResponseProjection(broken)).toBe(false);
    }
    const broken = structuredClone(result);
    broken.display!.candidate_manifest_digest = '<private-payload>';
    expect(isQualificationResponseProjection(broken)).toBe(false);
    expect(isQualificationResponseProjection(evaluateMarketplaceQualification(value.input, null, NOW))).toBe(true);
  });
  it('uses server TTL minus the full request round trip, without a browser wall clock', () => {
    const checkedAt = '2026-09-05T12:00:00Z';
    const expiresAt = '2026-09-05T12:00:30Z';
    expect(qualificationDisplayDeadline(checkedAt, expiresAt, 100, 5_100)).toBe(30_100);
    expect(qualificationDisplayRemaining(30_100, 5_100)).toBe(25);
    expect(qualificationDisplayRemaining(30_100, 30_099)).toBe(1);
    expect(qualificationDisplayRemaining(30_100, 30_100)).toBe(0);
    expect(qualificationDisplayRemaining(30_100, 70_000)).toBe(0);
  });

  it.each([
    ['invalid', '2026-09-05T12:00:30Z', 0, 1],
    ['2026-09-05T12:00:00Z', 'invalid', 0, 1],
    ['2026-09-05T12:00:00Z', '2026-09-05T12:00:00Z', 0, 1],
    ['2026-09-05T12:00:00Z', '2026-09-05T12:00:30Z', 0, 30_000],
    ['2026-09-05T12:00:00Z', '2026-09-05T12:00:30Z', 100, 99],
    ['2026-09-05T12:00:00Z', '2026-09-05T12:06:00Z', 0, 1],
    ['2026-09-05T12:00:00Z', '2026-09-05T12:00:30Z', -1, 1],
  ] as const)('refuses malformed, excessive or already elapsed display windows %#', (checked, expires, start, received) => {
    expect(qualificationDisplayDeadline(checked, expires, start, received)).toBeNull();
  });

  it('does not render a qualification label after the display window closes', () => {
    const value = fixture();
    const response = evaluateMarketplaceQualification(value.input, value.config, NOW);
    const valid = renderToStaticMarkup(createElement(QualificationResult, { response, remaining: 30 }));
    expect(valid).toContain('Qualified for this test scope');
    expect(valid).toContain(response.display!.candidate_manifest_digest);
    expect(valid).toContain('current only as observed');
    const expired = renderToStaticMarkup(createElement(QualificationResult, { response, remaining: 0 }));
    expect(expired).not.toContain('Qualified for this test scope');
    expect(expired).toContain('No qualification result available');
    expect(expired).not.toContain(response.display!.candidate_manifest_digest);
  });

  it('keeps negative and unavailable results distinct with no badge or false deployment claim', () => {
    const value = fixture();
    value.config.scopes[0].context.expected_assignment_digest = d('a different job');
    const response = evaluateMarketplaceQualification(value.input, value.config, NOW);
    const html = renderToStaticMarkup(createElement(QualificationResult, { response, remaining: 30 }));
    expect(html).toContain('Not qualified for this test scope');
    expect(html).toContain('OUT OF SCOPE');
    expect(html).toContain('Payment cannot change the result');
    const unavailable = renderToStaticMarkup(createElement(QualificationResult, {
      response: evaluateMarketplaceQualification(value.input, null, NOW), remaining: 30,
    }));
    expect(unavailable).toContain('Hosted verification is not configured');
    expect(unavailable).not.toContain('Qualified for this test scope');
  });

  it('requires explicit evidence upload consent and exposes no client trust editor', () => {
    const html = renderToStaticMarkup(createElement(QualificationForm));
    expect(html).toContain('leaves my browser when I click Verify');
    expect(html).toContain('disabled=""');
    expect(html).toContain('Do not include status observations, private keys, credentials or customer data');
    expect(html).not.toContain('NEXT_PUBLIC_');
    const source = readFileSync(new URL('../app/works/qualification/QualificationForm.tsx', import.meta.url), 'utf8');
    expect(source).toContain("import type { MarketplaceQualificationResponse }");
    expect(source).not.toMatch(/(?:localStorage|sessionStorage|console\.(?:log|error)|EMILIA_WORKS_QUALIFICATION_CONFIG_JSON)/);
    expect(source).toContain('current !== generation.current || abort.signal.aborted');
    expect(source).toContain("document.visibilityState === 'hidden'");
    expect(source).toContain('controller.current?.abort()');
    expect(source).toContain('onChange={(event) => { invalidate(); setScopeId(');
    expect(source).toContain('onChange={(event) => { invalidate(); setEvidence(');
  });
});

const NOW = new Date('2026-09-05T12:00:00Z');
const d = (text: string) => `sha256:${crypto.createHash('sha256').update(text).digest('hex')}`;
const resource = (name: string, value: string) => ({ name, digest: { sha256: value.slice(7) } });
const roles = ['campaign', 'test_result', 'agent_evidence', 'qualification_statement', 'qualification_status', 'runtime_measurement'] as const;
const signers = Object.fromEntries(roles.map((role) => [role, crypto.generateKeyPairSync('ed25519')]));
type Json = Record<string, any>;
const decode = (value: Json): Json => JSON.parse(Buffer.from(value.payload, 'base64').toString('utf8'));
function sign(body: Json, role: typeof roles[number], payloadType = IN_TOTO_PAYLOAD_TYPE) {
  const bytes = Buffer.from(canonicalizeQualification(body));
  return {
    payloadType, payload: bytes.toString('base64'),
    signatures: [{ keyid: role, sig: crypto.sign(null, dsseSigningBytes(payloadType, bytes), signers[role].privateKey).toString('base64') }],
  };
}

function fixture() {
  const manifest = request().evidence.candidate_manifest;
  manifest.profile = CANDIDATE_MANIFEST_VERSION;
  const candidate = qualificationPayloadDigest(manifest);
  const assignment = d('refund assignment');
  const policy = d('test policy');
  const campaignPredicate = {
    campaign_id: 'campaign:refunds:1', candidate_manifest_digest: candidate,
    assignment_digest: assignment, qualification_policy_digest: policy,
    harness_digest: d('harness'), evaluator_configuration_digest: d('evaluator'),
    environment_digest: d('environment'),
    hidden_challenges: { scheme: 'SALTED_SHA256_SET', commitments: [d('challenge')] },
    scenario_selection_commitment_digest: d('selection'), planned_batches: 1,
    maximum_batches: 1, attempt_ceiling: 1, not_before: '2026-09-05T10:00:00Z',
    not_after: '2026-09-05T11:00:00Z', predecessor_campaign_payload_digest: null,
  };
  const statement = (predicateType: string, predicate: Json, subject = [resource('candidate-manifest', candidate)]) => ({
    _type: IN_TOTO_STATEMENT_V1, subject, predicateType, predicate,
  });
  const campaign = statement(EVALUATION_CAMPAIGN_PREDICATE, campaignPredicate);
  const campaignDigest = qualificationPayloadDigest(campaign);
  const testResult = statement(TEST_RESULT_PREDICATE, {
    result: 'PASSED', passedTests: ['refund scope test'],
    configuration: [
      resource('environment', campaignPredicate.environment_digest),
      resource('evaluator-configuration', campaignPredicate.evaluator_configuration_digest),
      resource('harness', campaignPredicate.harness_digest),
    ],
  });
  const testDigest = qualificationPayloadDigest(testResult);
  const terminal = [{
    batch: 1, challenge_index: 0, attempt: 1, challenge_commitment: d('challenge'),
    challenge_proof: [], scenario_selection_commitment_digest: d('selection'),
    outcome: 'PASS', test_result_payload_digest: testDigest,
    terminal_evidence_payload_digest: testDigest,
    started_at: '2026-09-05T10:01:00Z', finished_at: '2026-09-05T10:01:30Z',
  }];
  const evidence = statement(AGENT_EVALUATION_EVIDENCE_PREDICATE, {
    campaign_payload_digest: campaignDigest, candidate_manifest_digest: candidate,
    assignment_digest: assignment, qualification_policy_digest: policy,
    completed_batches: 1, issued_challenges: 1, terminal_outcomes: terminal,
    outcome_counts: { PASS: 1, FAIL: 0, ABORTED: 0, EXPIRED: 0 },
    terminal_outcomes_root: terminalOutcomesRoot(terminal), measurements: [],
    started_at: '2026-09-05T10:00:00Z', completed_at: '2026-09-05T10:10:00Z',
  });
  const qualification = statement(QUALIFICATION_STATEMENT_PREDICATE, {
    verifier: { id: 'https://test.invalid/qualifier', policies: [resource('assignment', assignment), resource('qualification-policy', policy)] },
    timeCreated: '2026-09-05T10:15:00Z', properties: [QUALIFICATION_PROPERTY],
  }, [resource('candidate-manifest', candidate), resource('evaluation-campaign', campaignDigest), resource('qualification-graph', qualificationGraphDigest({
    campaign_payload_digests: [campaignDigest], test_result_payload_digests: [testDigest],
    agent_evaluation_evidence_payload_digests: [qualificationPayloadDigest(evidence)],
  }))]);
  const status = {
    profile: QUALIFICATION_STATUS_VERSION, authority_id: 'test-status-authority',
    qualification_statement_payload_digest: qualificationPayloadDigest(qualification),
    candidate_manifest_digest: candidate, assignment_digest: assignment,
    qualification_policy_digest: policy, status: 'QUALIFIED', sequence: 0,
    previous_status_payload_digest: null, issued_at: '2026-09-05T10:16:00Z',
    next_update: '2026-09-05T12:05:00Z', valid_until: '2026-09-06T00:00:00Z',
  };
  const runtime = {
    profile: RUNTIME_CANDIDATE_MEASUREMENT_VERSION, measurement_id: 'test-runtime-1',
    authority_id: 'test-runtime-authority', measurement_mechanism_digest: d('measurement'),
    candidate_manifest_digest: candidate, assignment_digest: assignment,
    measured_at: '2026-09-05T11:59:30Z', candidate_influence_cutoff: '2026-09-05T11:59:45Z',
    remains_in_execution_path: true, static: structuredClone(manifest.static),
    dynamic_retrieval_root: d('retrieval'), memory_state_snapshot_digest: d('memory'),
    user_input_digest: d('input'), protected_request_digest: d('protected request'),
  };
  const input = {
    scope_id: 'refunds-test-v1', evidence: {
      candidate_manifest: manifest, campaigns: [sign(campaign, 'campaign')],
      test_results: [sign(testResult, 'test_result')],
      agent_evaluation_evidence: [sign(evidence, 'agent_evidence')],
      qualification_statement: sign(qualification, 'qualification_statement'),
      runtime_measurement: sign(runtime, 'runtime_measurement', RUNTIME_MEASUREMENT_PAYLOAD_TYPE),
    },
  };
  const config = { version: MARKETPLACE_QUALIFICATION_CONFIG_VERSION, scopes: [{
    scope_id: input.scope_id, scope_label: 'Refund assignment test policy v1',
    context: {
      expected_candidate_manifest_digest: candidate, expected_assignment_digest: assignment,
      expected_qualification_policy_digest: policy, expected_protected_request_digest: runtime.protected_request_digest,
      expected_runtime_measurement_authority_id: runtime.authority_id,
      expected_runtime_measurement_mechanism_digest: runtime.measurement_mechanism_digest,
      expected_status_authority_id: status.authority_id, minimum_status_sequence: 0,
      max_status_observation_age_seconds: 60, max_runtime_measurement_age_seconds: 60,
      minimum_model_pinning_strength: 'VERSION_PINNED',
      trust: Object.fromEntries(roles.map((role) => [role, {
        keys: { [role]: signers[role].publicKey.export({ format: 'der', type: 'spki' }).toString('base64url') },
        accepted_keyids: [role], threshold: 1,
      }])),
    },
    qualification_status_chain: [sign(status, 'qualification_status', QUALIFICATION_STATUS_PAYLOAD_TYPE)],
    qualification_status_observation: {
      authority_id: status.authority_id, head_payload_digest: qualificationPayloadDigest(status),
      sequence: 0, observed_at: '2026-09-05T11:59:50Z',
    },
  }] };
  return { input, config };
}

function changeStatus(value: ReturnType<typeof fixture>, mutate: (body: Json) => void) {
  const scope = value.config.scopes[0];
  const status = decode(scope.qualification_status_chain[0]);
  mutate(status);
  scope.qualification_status_chain[0] = sign(status, 'qualification_status', QUALIFICATION_STATUS_PAYLOAD_TYPE);
  scope.qualification_status_observation.head_payload_digest = qualificationPayloadDigest(status);
}

describe('real qualification verification and projection', () => {
  it('verifies six signing roles and emits only an exact, expiring result without mutating inputs', () => {
    const { input, config } = fixture();
    const before = JSON.stringify({ input, config });
    const result = evaluateMarketplaceQualification(input, config, NOW);
    expect(result.status, result.reason).toBe('QUALIFIED');
    expect(result.result).toMatchObject({ verification: 'VERIFIED', acceptance: 'ACCEPTED', candidate_match: 'EXACT_MATCH', currentness: 'CURRENT_AS_OBSERVED', assignment_scope: 'IN_SCOPE', campaign_graph: 'COMPLETE', remeasure_at_begin_invocation: true });
    expect(result.display).toMatchObject({ scope_id: input.scope_id, candidate_manifest_digest: config.scopes[0].context.expected_candidate_manifest_digest, expires_at: '2026-09-05T12:00:30.000Z' });
    expect(JSON.stringify({ input, config })).toBe(before);
    const projection = JSON.stringify(result);
    expect(projection).not.toContain(input.evidence.runtime_measurement.payload);
    expect(projection).not.toContain(config.scopes[0].context.trust.campaign.keys.campaign);
  });

  it.each(['campaigns', 'test_results', 'agent_evaluation_evidence', 'qualification_statement', 'runtime_measurement'])('rejects a forged %s signature', (field) => {
    const { input, config } = fixture();
    const artifact = (input.evidence as Json)[field];
    const target = Array.isArray(artifact) ? artifact[0] : artifact;
    target.signatures[0].sig = Buffer.alloc(64).toString('base64');
    const result = evaluateMarketplaceQualification(input, config, NOW);
    expect(result.status).toBe('INDETERMINATE');
    expect(result.reason).toBe('invalid_artifact_signature');
    expect(result.display).toBeNull();
  });

  it('refuses an unsigned installation claim in place of a measured runtime', () => {
    const { input, config } = fixture();
    (input.evidence as Json).runtime_measurement = { installed: true, gate: true };
    expect(evaluateMarketplaceQualification(input, config, NOW).status).toBe('INVALID_REQUEST');
  });

  it('does not accept a known but unaccepted signer or an unknown key', () => {
    for (const unknown of [true, false]) {
      const { input, config } = fixture();
      const trust = config.scopes[0].context.trust.campaign;
      if (unknown) input.evidence.campaigns[0].signatures[0].keyid = 'attacker';
      else {
        trust.keys.allowed = signers.test_result.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
        trust.accepted_keyids = ['allowed'];
      }
      const result = evaluateMarketplaceQualification(input, config, NOW);
      expect(result.reason).toBe(unknown ? 'untrusted_verification_key' : 'artifact_not_accepted');
      expect(result.display).toBeNull();
    }
  });

  it.each(['expected_candidate_manifest_digest', 'expected_assignment_digest', 'expected_qualification_policy_digest', 'expected_protected_request_digest'])('cannot reuse proof against another server-pinned %s', (field) => {
    const { input, config } = fixture();
    (config.scopes[0].context as Json)[field] = d(`different ${field}`);
    const result = evaluateMarketplaceQualification(input, config, NOW);
    expect(result.status).toBe('NOT_QUALIFIED');
    expect(result.display).toBeNull();
  });

  it('refuses signed candidate drift instead of relabeling old evidence', () => {
    const { input, config } = fixture();
    const body = decode(input.evidence.runtime_measurement);
    body.static.effective_permissions_digest = d('wider permissions');
    input.evidence.runtime_measurement = sign(body, 'runtime_measurement', RUNTIME_MEASUREMENT_PAYLOAD_TYPE);
    const result = evaluateMarketplaceQualification(input, config, NOW);
    expect(result.result?.candidate_match).toBe('MISMATCH');
    expect(result.reason).toBe('runtime_candidate_mismatch');
    expect(result.display).toBeNull();
  });

  it.each(['REVOKED', 'SUSPENDED', 'EXPIRED'])('preserves server-observed %s status', (status) => {
    const value = fixture();
    changeStatus(value, (body) => { body.status = status; });
    const result = evaluateMarketplaceQualification(value.input, value.config, NOW);
    expect(result.status).toBe('NOT_QUALIFIED');
    expect(result.result?.currentness).toBe(status);
    expect(result.display).toBeNull();
  });

  it('refuses a forged server status, stale observations and rollback below the pinned floor', () => {
    const forged = fixture();
    forged.config.scopes[0].qualification_status_chain[0].signatures[0].sig = Buffer.alloc(64).toString('base64');
    expect(evaluateMarketplaceQualification(forged.input, forged.config, NOW).reason).toBe('invalid_artifact_signature');
    const stale = fixture();
    stale.config.scopes[0].qualification_status_observation.observed_at = '2026-09-05T11:58:00Z';
    expect(evaluateMarketplaceQualification(stale.input, stale.config, NOW).result?.currentness).toBe('STALE');
    const rollback = fixture();
    rollback.config.scopes[0].context.minimum_status_sequence = 1;
    expect(evaluateMarketplaceQualification(rollback.input, rollback.config, NOW).reason).toBe('qualification_status_observation_mismatch');
  });

  it('cannot retain a display past measurement freshness or a signed expiry', () => {
    const value = fixture();
    expect(evaluateMarketplaceQualification(value.input, value.config, new Date('2026-09-05T12:00:30Z')).display).toBeNull();
    expect(evaluateMarketplaceQualification(value.input, value.config, new Date('2026-09-05T12:00:31Z')).result?.candidate_match).toBe('STALE');
    changeStatus(value, (body) => { body.valid_until = '2026-09-05T11:59:59Z'; });
    expect(evaluateMarketplaceQualification(value.input, value.config, NOW).result?.currentness).toBe('EXPIRED');
  });

  it('refuses incomplete campaign evidence, statement substitution and open envelopes', () => {
    const missing = fixture();
    missing.input.evidence.test_results = [];
    expect(evaluateMarketplaceQualification(missing.input, missing.config, NOW).reason).toBe('test_result_reference_mismatch');
    const changed = fixture();
    const statement = decode(changed.input.evidence.qualification_statement);
    statement.subject[0] = resource('candidate-manifest', d('other candidate'));
    changed.input.evidence.qualification_statement = sign(statement, 'qualification_statement');
    expect(evaluateMarketplaceQualification(changed.input, changed.config, NOW).reason).toBe('qualification_statement_binding_mismatch');
    Object.assign(changed.input.evidence.qualification_statement, { qualified: true });
    expect(evaluateMarketplaceQualification(changed.input, changed.config, NOW).status).toBe('INVALID_REQUEST');
  });

  it('refuses invalid, overly broad and duplicate server configuration without exposing it', () => {
    for (const mutate of [
      (c: Json) => { c.scopes[0].context.now = NOW.toISOString(); },
      (c: Json) => { c.scopes[0].context.max_status_observation_age_seconds = 3600; },
      (c: Json) => { c.scopes[0].context.minimum_model_pinning_strength = 'MUTABLE_ALIAS'; },
      (c: Json) => { c.scopes.push(structuredClone(c.scopes[0])); },
      (c: Json) => { c.scopes[0].context.trust.campaign = true; },
    ]) {
      const value = fixture();
      mutate(value.config);
      const result = evaluateMarketplaceQualification(value.input, value.config, NOW);
      expect(result.reason).toBe('qualification_configuration_invalid');
      expect(result.display).toBeNull();
    }
  });

  it('treats an unregistered scope as unavailable, not a failed test', () => {
    const value = fixture();
    value.input.scope_id = 'not-registered';
    expect(evaluateMarketplaceQualification(value.input, value.config, NOW).reason).toBe('qualification_scope_unavailable');
  });
});

describe('hosted qualification route', () => {
  beforeEach(() => {
    vi.stubEnv('WORKS_V0', '1');
    vi.stubEnv('EMILIA_WORKS_QUALIFICATION_CONFIG_JSON', '');
    rate.mockReset().mockResolvedValue({ allowed: true, remaining: 59, reset: 60 });
  });
  const url = 'https://www.emiliaprotocol.ai/api/works/qualification';
  const post = async (body: unknown, headers: Record<string, string> = { 'content-type': 'application/json' }) => {
    const { POST } = await import('../app/api/works/qualification/route');
    return POST(new Request(url, { method: 'POST', headers, body: typeof body === 'string' ? body : JSON.stringify(body) }));
  };

  it('keeps the surface dark when Works is disabled', async () => {
    vi.stubEnv('WORKS_V0', '0');
    expect((await post(request())).status).toBe(404);
    expect(rate).not.toHaveBeenCalled();
  });

  it('validates input and explicitly refuses absent hosted configuration', async () => {
    const response = await post(request());
    expect(response.status).toBe(503);
    expect(response.headers.get('cache-control')).toContain('no-store');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect(await response.json()).toMatchObject({ status: 'UNAVAILABLE', reason: 'qualification_not_configured', display: null });
    expect(rate).toHaveBeenCalledWith('works-qualification:trusted-test-ip', 'mcp_tool_call', { requireDurable: true });
    expect((await post({ qualified: true, paid: true })).status).toBe(400);
  });

  it('checks a real signed graph using the server clock and configuration', async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(NOW);
      const value = fixture();
      vi.stubEnv('EMILIA_WORKS_QUALIFICATION_CONFIG_JSON', JSON.stringify(value.config));
      const response = await post(value.input);
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({ status: 'QUALIFIED', display: { scope_id: value.input.scope_id } });
    } finally { vi.useRealTimers(); }
  });

  it('rejects duplicate JSON fields, malformed JSON and non-JSON requests', async () => {
    expect((await post('{"scope_id":"a","scope_id":"b","evidence":{}}')).status).toBe(400);
    expect((await post('{')).status).toBe(400);
    expect((await post(request(), { 'content-type': 'text/plain' })).status).toBe(415);
  });

  it('caps streamed input without trusting Content-Length', async () => {
    const response = await post(' '.repeat(MARKETPLACE_QUALIFICATION_MAX_BYTES + 1), { 'content-type': 'application/json', 'content-length': '1' });
    expect(response.status).toBe(413);
  });

  it('refuses rate-limit outages and prevents any body read after throttling', async () => {
    rate.mockResolvedValue({ allowed: false, remaining: 0, reset: 30 });
    const response = await post('{private-malformed-input');
    expect(response.status).toBe(429);
    expect(response.headers.get('retry-after')).toBe('30');
    expect(await response.text()).not.toContain('private-malformed-input');
    rate.mockResolvedValue({ allowed: false, remaining: 0, reset: 60, error: 'durable_rate_limit_required' });
    expect((await post(request())).status).toBe(503);
    rate.mockRejectedValue(new Error('private backend URL or token'));
    const failed = await post(request());
    expect(failed.status).toBe(503);
    expect(await failed.text()).not.toContain('private backend');
  });

  it('has no fetch, publication, billing or scan promotion in the verifier module', () => {
    const source = readFileSync(new URL('../lib/works/marketplace-qualification.ts', import.meta.url), 'utf8');
    expect(source).not.toMatch(/\bfetch\s*\(|from ['"].*(?:billing|scan|store|seed)/);
    expect(source).toContain("from '../../packages/verify/gate-qualification.js'");
  });
});
