// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto, { type KeyObject } from 'node:crypto';
import fs from 'node:fs';
import test from 'node:test';

// The CAID reference implementation intentionally has no TypeScript surface.
// @ts-expect-error -- independently recomputed in the test.
import { computeCaid } from './vendor/caid.mjs';
import {
  AEB_ADAPTER_VERSION,
  AEB_REGISTRY_VERSION,
  AEB_REQUIREMENT_VERSION,
  InMemoryAebConsumptionStore,
  adapterPinDigest,
  authorizeAebExecution,
  canonicalizeAeb,
  digestAeb,
  evaluateAebEvidence,
  mappingProfileDigest,
  registryEntryDigest,
  unifiedRegistryDigest,
  type AebAdapterInput,
  type AebPinnedAdapter,
  type AebPinnedConfig,
  type AebPinnedProfile,
  type AebRegistryEntry,
} from './aeb-adapter-contract.js';
import {
  AUTHORIZATION_SERVER_CONFIRMATION_ADAPTER_ID,
  AUTHORIZATION_SERVER_CONFIRMATION_ADAPTER_VERSION,
  AUTHORIZATION_SERVER_CONFIRMATION_ARTIFACT_VERSION,
  AUTHORIZATION_SERVER_CONFIRMATION_CONFIG_VERSION,
  AUTHORIZATION_SERVER_CONFIRMATION_MAPPING_VERSION,
  AUTHORIZATION_SERVER_CONFIRMATION_MAPPER_ID,
  AUTHORIZATION_SERVER_CONFIRMATION_TOKEN_VERSION,
  AUTHORIZATION_SERVER_CONFIRMATION_TRUST_ROOT_VERSION,
  createAuthorizationServerConfirmationActionDefinition,
  createAuthorizationServerConfirmationAdapter,
  signAuthorizationServerConfirmation,
  type AuthorizationServerConfirmationAdapterConfig,
  type AuthorizationServerConfirmationArtifact,
  type AuthorizationServerConfirmationClaims,
  type AuthorizationServerConfirmationTrustRoot,
} from './authorization-server-confirmation.js';

type Obj = Record<string, any>;

const NOW = '2026-08-04T18:00:00Z';
const NOW_SECONDS = Math.floor(Date.parse(NOW) / 1000);
const ACTION_TYPE = 'payment.release.1';
const ISSUER = 'https://authorization.example';
const AUDIENCE = 'https://gate.example/admit';
const RESOURCE_SERVER_KEY_ID = 'gate-kms-2026-08';
const RESOURCE_SERVER_KEY_DIGEST = digestAeb({ public_key: 'gate-kms-public-key-2026-08' });
const HUMAN_ID = 'employee:alice.example.com';
const cases = JSON.parse(fs.readFileSync(
  new URL('./authorization-server-confirmation.v1.json', import.meta.url), 'utf8',
));

test('Authorization Server confirmation profile publishes the hostile case inventory without claiming external interop', () => {
  assert.equal(cases['@version'], 'EP-AUTHORIZATION-SERVER-CONFIRMATION-CASES-v1');
  assert.equal(cases.status, 'implementation-profile-cases');
  assert.match(cases.claim_boundary, /not an independent implementation/i);
  assert.equal(cases.cases.length, 15);
  assert.equal(new Set(cases.cases.map((entry: Obj) => entry.id)).size, 15);
});

function spki(key: KeyObject): string {
  return key.export({ type: 'spki', format: 'der' }).toString('base64url');
}

function profile(): AebPinnedProfile {
  const definition = createAuthorizationServerConfirmationActionDefinition(ACTION_TYPE);
  return {
    version: AUTHORIZATION_SERVER_CONFIRMATION_MAPPING_VERSION,
    definition,
    registry_entry_ref: 'mapping:as-confirmation-payment-release',
    mapper_id: AUTHORIZATION_SERVER_CONFIRMATION_MAPPER_ID,
    resolver: {
      id: AUTHORIZATION_SERVER_CONFIRMATION_MAPPER_ID,
      version: '1',
      implementation_digest: digestAeb({
        implementation: AUTHORIZATION_SERVER_CONFIRMATION_MAPPER_ID,
        version: '1',
      }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [
        'iss', 'aud', 'iat', 'nbf', 'exp', 'jti', 'policy_digest',
        'directory_digest', 'directory_observation_basis', 'directory_observed_at',
        'resource_server_key_id', 'resource_server_key_digest',
        'human_evidence_digest',
      ],
    },
    profile_digest: digestAeb(null),
  };
}

function makeFixture(overrides: Partial<AuthorizationServerConfirmationClaims> = {}) {
  const asKey = crypto.generateKeyPairSync('ed25519');
  const attacker = crypto.generateKeyPairSync('ed25519');
  const config: AuthorizationServerConfirmationAdapterConfig = {
    '@version': AUTHORIZATION_SERVER_CONFIRMATION_CONFIG_VERSION,
    evidence_role: 'authorization-server-confirmation',
    human_evidence_role: 'human-authorization',
    issuer: ISSUER,
    audience: AUDIENCE,
    resource_server_key_id: RESOURCE_SERVER_KEY_ID,
    resource_server_key_digest: RESOURCE_SERVER_KEY_DIGEST,
    action_type: ACTION_TYPE,
    clock_skew_seconds: 2,
    max_token_age_seconds: 300,
    max_directory_snapshot_age_seconds: 300,
  };
  const root: AuthorizationServerConfirmationTrustRoot = {
    '@version': AUTHORIZATION_SERVER_CONFIRMATION_TRUST_ROOT_VERSION,
    use: 'authorization-server',
    issuer: ISSUER,
    key_id: 'as-ed25519-2026-08',
    algorithm: 'EdDSA',
    public_key: spki(asKey.publicKey),
  };
  const humanEvidence = {
    '@type': 'EP-HUMAN-AUTHORIZATION-TEST-v1',
    action_digest: digestAeb({
      action_type: ACTION_TYPE,
      parameters: { amount_minor: 12550, currency: 'USD', payee: 'merchant:7' },
    }),
    approver: HUMAN_ID,
    nonce: 'approval-nonce-1',
  };
  const action = {
    action_type: ACTION_TYPE,
    parameters: { amount_minor: 12550, currency: 'USD', payee: 'merchant:7' },
  };
  const claims: AuthorizationServerConfirmationClaims = {
    ep_version: AUTHORIZATION_SERVER_CONFIRMATION_TOKEN_VERSION,
    iss: ISSUER,
    sub: HUMAN_ID,
    aud: AUDIENCE,
    iat: NOW_SECONDS - 10,
    nbf: NOW_SECONDS - 10,
    exp: NOW_SECONDS + 120,
    jti: 'as-grant-0001',
    authorization_server_decision: 'AUTHORIZED',
    action,
    action_digest: digestAeb(action),
    human_evidence_digest: digestAeb(humanEvidence),
    policy_digest: digestAeb({ policy: 'payments-v4' }),
    directory_digest: digestAeb({ epoch: 42, subject: HUMAN_ID }),
    directory_observation_basis: 'AUTHORIZATION_SERVER_OBSERVED_SNAPSHOT',
    directory_observed_at: NOW_SECONDS - 30,
    resource_server_key_id: RESOURCE_SERVER_KEY_ID,
    resource_server_key_digest: RESOURCE_SERVER_KEY_DIGEST,
    ...overrides,
  };
  const artifact: AuthorizationServerConfirmationArtifact = {
    '@version': AUTHORIZATION_SERVER_CONFIRMATION_ARTIFACT_VERSION,
    grant: signAuthorizationServerConfirmation(claims, {
      key_id: root.key_id,
      private_key: asKey.privateKey,
    }),
    human_evidence: humanEvidence,
  };
  const adapter = createAuthorizationServerConfirmationAdapter({ config, trust_roots: [root] });
  const mappingProfile = profile();
  mappingProfile.profile_digest = digestAeb({
    id: 'as-confirmation',
    pin: {
      version: mappingProfile.version,
      definition: mappingProfile.definition,
      registry_entry_ref: mappingProfile.registry_entry_ref,
      mapper_id: mappingProfile.mapper_id,
      resolver: mappingProfile.resolver,
      semantic_equivalence: mappingProfile.semantic_equivalence,
    },
  });
  const status = {
    checked_at: '2026-08-04T17:59:30Z',
    expires_at: '2026-08-04T18:02:00Z',
    revocation_checked: true,
    revoked: false,
    consumed: false,
  };
  const input: Omit<AebAdapterInput, 'profile'> = {
    artifact,
    artifact_ref: 'urn:ep:as-confirmation:as-grant-0001',
    status,
    trust_roots: [root],
    adapter_config: config,
    expected_action: action,
    now: NOW,
  };
  return { adapter, artifact, asKey, attacker, claims, config, root, humanEvidence, action, mappingProfile, input };
}

test('authorization server confirmation is an independently pinned AEB leg bound to exact human evidence and action', () => {
  const fixture = makeFixture();
  assert.equal(fixture.adapter.id, AUTHORIZATION_SERVER_CONFIRMATION_ADAPTER_ID);
  assert.equal(fixture.adapter.version, AUTHORIZATION_SERVER_CONFIRMATION_ADAPTER_VERSION);

  const native = fixture.adapter.verifyNative(fixture.input);
  assert.equal(native.native_verification, 'VERIFIED');
  assert.equal(native.acceptance, 'ACCEPTED');
  assert.equal(native.evidence_role, 'authorization-server-confirmation');
  assert.deepEqual(native.subject, { id: HUMAN_ID, kind: 'human' });
  assert.deepEqual(native.evidence_bindings, [{
    role: 'human-authorization',
    evidence_digest: digestAeb(fixture.humanEvidence),
  }]);

  const mapped = fixture.adapter.mapAction({ ...fixture.input, profile: fixture.mappingProfile, native });
  assert.equal(mapped.mapping, 'MATCH');
  assert.equal(mapped.action_digest, digestAeb(fixture.action));
  const definition = createAuthorizationServerConfirmationActionDefinition(ACTION_TYPE) as Obj;
  assert.equal(mapped.caid, computeCaid(fixture.action, {
    suite: 'jcs-sha256',
    definitions: definition.definitions,
  }).caid);
});

test('confirmation fails closed for a different human artifact, audience, resource-server key, or stale grant', () => {
  const base = makeFixture();
  const mutations: Array<[string, (fixture: ReturnType<typeof makeFixture>) => void]> = [
    ['human evidence', (fixture) => { fixture.artifact.human_evidence = { different: true }; }],
    ['audience', (fixture) => {
      fixture.artifact.grant = signAuthorizationServerConfirmation({
        ...fixture.claims,
        aud: 'https://attacker.example',
      }, { key_id: fixture.root.key_id, private_key: fixture.asKey.privateKey });
    }],
    ['resource server key', (fixture) => {
      fixture.artifact.grant = signAuthorizationServerConfirmation({
        ...fixture.claims,
        resource_server_key_id: 'attacker-key',
      }, { key_id: fixture.root.key_id, private_key: fixture.asKey.privateKey });
    }],
    ['stale grant', (fixture) => { fixture.input.now = '2026-08-04T19:00:00Z'; }],
  ];
  assert.equal(base.adapter.verifyNative(base.input).native_verification, 'VERIFIED');
  for (const [label, mutate] of mutations) {
    const fixture = makeFixture();
    mutate(fixture);
    const native = fixture.adapter.verifyNative(fixture.input);
    assert.notEqual(native.acceptance, 'ACCEPTED', label);
  }
});

test('fresh AS token cannot launder an old directory snapshot into current standing', () => {
  const fixture = makeFixture();
  const config = { ...fixture.config };
  const claims = {
    ...fixture.claims,
    directory_observation_basis: 'AUTHORIZATION_SERVER_OBSERVED_SNAPSHOT',
    directory_observed_at: NOW_SECONDS - 3_600,
  };
  const grant = signAuthorizationServerConfirmation(claims as never, {
    key_id: fixture.root.key_id,
    private_key: fixture.asKey.privateKey,
  });
  const adapter = createAuthorizationServerConfirmationAdapter({
    config: config as never,
    trust_roots: [fixture.root],
  });
  const native = adapter.verifyNative({
    ...fixture.input,
    artifact: { ...fixture.artifact, grant },
    adapter_config: config,
  });
  assert.equal(native.native_verification, 'VERIFIED');
  assert.equal(native.acceptance, 'INDETERMINATE');
  assert.deepEqual(native.reasons, ['as-confirmation:directory_snapshot_too_old']);
});

test('a valid AS signature over a different action is accepted only as native evidence and fails exact-action mapping', () => {
  const fixture = makeFixture();
  const expectedAction = {
    ...fixture.action,
    parameters: { ...fixture.action.parameters, amount_minor: 9999999 },
  };
  fixture.input.expected_action = expectedAction;
  const native = fixture.adapter.verifyNative(fixture.input);
  assert.equal(native.acceptance, 'ACCEPTED');
  const mapped = fixture.adapter.mapAction({
    ...fixture.input,
    profile: fixture.mappingProfile,
    native,
  });
  assert.equal(mapped.mapping, 'MISMATCH');
  assert.deepEqual(mapped.reasons, ['exact_action_projection_mismatch']);
});

test('presenter cannot nominate an AS key, downgrade the algorithm, or use the agent orchestrator as the AS', () => {
  const fixture = makeFixture();
  const attackerRoot = { ...fixture.root, key_id: 'attacker', public_key: spki(fixture.attacker.publicKey) };
  const attackerClaims = { ...fixture.claims, iss: 'https://orchestrator.example' };
  const attackerGrant = signAuthorizationServerConfirmation(attackerClaims, {
    key_id: attackerRoot.key_id,
    private_key: fixture.attacker.privateKey,
  });
  const unpinned = fixture.adapter.verifyNative({
    ...fixture.input,
    artifact: { ...fixture.artifact, grant: attackerGrant },
    trust_roots: [attackerRoot],
  });
  assert.equal(unpinned.native_verification, 'FAILED');

  const [header, payload] = fixture.artifact.grant.split('.');
  const downgradedHeader = Buffer.from(canonicalizeAeb({ alg: 'none', typ: 'ep-as-confirmation+jwt', kid: fixture.root.key_id })).toString('base64url');
  const downgraded = fixture.adapter.verifyNative({
    ...fixture.input,
    artifact: { ...fixture.artifact, grant: `${downgradedHeader}.${payload}.AA` },
  });
  assert.equal(downgraded.native_verification, 'FAILED');
  assert.notEqual(header, downgradedHeader);
});

test('reference AS signer refuses open or internally inconsistent claims before signing', () => {
  const fixture = makeFixture();
  assert.throws(() => signAuthorizationServerConfirmation({
    ...fixture.claims,
    action_digest: digestAeb({ wrong: true }),
  }, {
    key_id: fixture.root.key_id,
    private_key: fixture.asKey.privateKey,
  }), /valid closed confirmation claims/);
  assert.throws(() => signAuthorizationServerConfirmation({
    ...fixture.claims,
    presenter_override: true,
  } as never, {
    key_id: fixture.root.key_id,
    private_key: fixture.asKey.privateKey,
  }), /valid closed confirmation claims/);
  assert.throws(() => signAuthorizationServerConfirmation({
    ...fixture.claims,
    directory_observed_at: fixture.claims.iat + 1,
  }, {
    key_id: fixture.root.key_id,
    private_key: fixture.asKey.privateKey,
  }), /valid closed confirmation claims/);
});

test('AS grant is evidence only: native verification never emits SATISFIED or AUTHORIZED', () => {
  const fixture = makeFixture();
  const native = fixture.adapter.verifyNative(fixture.input) as Obj;
  assert.equal(native.native_verification, 'VERIFIED');
  assert.equal(native.acceptance, 'ACCEPTED');
  assert.equal('verdict' in native, false);
  assert.equal('authorized' in native, false);
  assert.equal('satisfied' in native, false);
});

test('AEB/AEC authorizes only when independently verified human and AS legs are digest- and subject-linked', () => {
  const fixture = makeFixture();
  fixture.mappingProfile.profile_digest = mappingProfileDigest('as-confirmation', fixture.mappingProfile);
  const caid = computeCaid(fixture.action, {
    suite: 'jcs-sha256',
    definitions: (fixture.mappingProfile.definition as Obj).definitions,
  }).caid;
  const humanAdapter = {
    id: 'native:test-human-authorization',
    version: '1',
    verifyNative(input: Omit<AebAdapterInput, 'profile'>) {
      const artifact = input.artifact as Obj;
      return {
        native_verification: 'VERIFIED' as const,
        acceptance: 'ACCEPTED' as const,
        evidence_digest: digestAeb(artifact),
        status_digest: digestAeb({
          checked_at: input.status.checked_at,
          expires_at: input.status.expires_at,
          revocation_checked: input.status.revocation_checked,
          revoked: input.status.revoked,
          consumed: input.status.consumed,
          unavailable: input.status.unavailable === true,
        }),
        evidence_role: 'human-authorization',
        subject: { id: artifact.approver, kind: 'human' as const },
        replay_unit: digestAeb({ nonce: artifact.nonce }),
        reasons: [],
      };
    },
    mapAction(input: AebAdapterInput) {
      return {
        mapping: 'MATCH' as const,
        caid,
        action_digest: digestAeb(input.expected_action),
        reasons: [],
      };
    },
  };
  function entry(id: string, kind: AebRegistryEntry['kind'], definition: unknown): AebRegistryEntry {
    const value = { kind, version: '1', status: 'active' as const, definition } as AebRegistryEntry;
    value.definition_digest = registryEntryDigest(id, value);
    return value;
  }
  const entries = {
    'mapping:as-confirmation-payment-release': entry(
      'mapping:as-confirmation-payment-release', 'mapping-profile',
      { profile_digest: fixture.mappingProfile.profile_digest },
    ),
    'role:human-authorization': entry(
      'role:human-authorization', 'evidence-role',
      { role: 'human-authorization', subject_kinds: ['human'] },
    ),
    'role:authorization-server-confirmation': entry(
      'role:authorization-server-confirmation', 'evidence-role',
      { role: 'authorization-server-confirmation', subject_kinds: ['human'] },
    ),
  };
  const registry = {
    '@version': AEB_REGISTRY_VERSION,
    registry_id: 'registry:as-confirmation-test',
    epoch: 1,
    entries,
    registry_digest: digestAeb(null),
  };
  registry.registry_digest = unifiedRegistryDigest(registry);
  const asPin: AebPinnedAdapter = {
    version: AUTHORIZATION_SERVER_CONFIRMATION_ADAPTER_VERSION,
    trust_roots: [fixture.root],
    config: fixture.config,
    config_digest: digestAeb(null),
    max_status_age_sec: 120,
  };
  asPin.config_digest = adapterPinDigest(AUTHORIZATION_SERVER_CONFIRMATION_ADAPTER_ID, asPin);
  const humanPin: AebPinnedAdapter = {
    version: '1', trust_roots: ['human-test-root'], config: { profile: 'human-test-v1' },
    config_digest: digestAeb(null), max_status_age_sec: 120,
  };
  humanPin.config_digest = adapterPinDigest(humanAdapter.id, humanPin);
  const evaluator = crypto.generateKeyPairSync('ed25519');
  const config: AebPinnedConfig = {
    '@version': AEB_ADAPTER_VERSION,
    relying_party_id: 'rp:gate-example',
    evaluator_keys: {
      'evaluator:gate': { public_key: spki(evaluator.publicKey) },
    },
    registry,
    accepted_mappers: [AUTHORIZATION_SERVER_CONFIRMATION_MAPPER_ID],
    adapters: {
      [AUTHORIZATION_SERVER_CONFIRMATION_ADAPTER_ID]: asPin,
      [humanAdapter.id]: humanPin,
    },
    profiles: { 'as-confirmation': fixture.mappingProfile },
    requirements: {
      'requirement:human-plus-as': {
        '@version': AEB_REQUIREMENT_VERSION,
        all_of: ['human-authorization', 'authorization-server-confirmation'],
        terms: [
          {
            type: 'evidence-binding',
            source_role: 'authorization-server-confirmation',
            target_role: 'human-authorization',
            require_same_subject: true,
          },
          { type: 'initiator-exclusion', roles: ['human-authorization'] },
          { type: 'executor-exclusion', roles: ['human-authorization'] },
          { type: 'one-time-consumption' },
        ],
      },
    },
  };
  const result = evaluateAebEvidence({
    config,
    adapters: {
      [AUTHORIZATION_SERVER_CONFIRMATION_ADAPTER_ID]: fixture.adapter,
      [humanAdapter.id]: humanAdapter,
    },
    operation_id: 'operation:as-confirmation-1',
    consumption_nonce: 'consumption:as-confirmation-1',
    initiator_id: 'workload:agent-1',
    executor_id: 'workload:gate-1',
    requirement_ref: 'requirement:human-plus-as',
    caid,
    expected_action: fixture.action,
    evaluated_at: NOW,
    signer: { key_id: 'evaluator:gate', private_key: evaluator.privateKey },
    legs: [
      {
        adapter_id: humanAdapter.id,
        profile_id: 'as-confirmation',
        artifact_ref: 'urn:human:approval:1',
        artifact: fixture.humanEvidence,
        status: fixture.input.status,
      },
      {
        adapter_id: AUTHORIZATION_SERVER_CONFIRMATION_ADAPTER_ID,
        profile_id: 'as-confirmation',
        artifact_ref: 'urn:as:grant:1',
        artifact: fixture.artifact,
        status: fixture.input.status,
      },
    ],
  });
  assert.equal(result.valid, true, JSON.stringify(result, null, 2));
  assert.equal(result.record.verdict, 'SATISFIED');
  assert.equal(result.record.composition.satisfied, true);
  assert.equal(result.record.authority_constraints.one_time_consumption, true);
  const store = new InMemoryAebConsumptionStore();
  const admitted = authorizeAebExecution(result.record, {
    verification: { valid: true, execution_authorizing: true, record_digest: digestAeb(result.record) },
    local_authorization: true,
    store,
  });
  assert.equal(admitted.invoke_allowed, true);
  const replay = authorizeAebExecution(result.record, {
    verification: { valid: true, execution_authorizing: true, record_digest: digestAeb(result.record) },
    local_authorization: true,
    store,
  });
  assert.equal(replay.invoke_allowed, false);
  assert.equal(replay.reason, 'consumption_conflict');

  const wrongHuman = structuredClone(fixture.humanEvidence);
  wrongHuman.nonce = 'different-human-evidence';
  const refused = evaluateAebEvidence({
    ...({
      config,
      adapters: {
        [AUTHORIZATION_SERVER_CONFIRMATION_ADAPTER_ID]: fixture.adapter,
        [humanAdapter.id]: humanAdapter,
      },
      operation_id: 'operation:as-confirmation-2',
      consumption_nonce: 'consumption:as-confirmation-2',
      initiator_id: 'workload:agent-1',
      executor_id: 'workload:gate-1',
      requirement_ref: 'requirement:human-plus-as',
      caid,
      expected_action: fixture.action,
      evaluated_at: NOW,
      signer: { key_id: 'evaluator:gate', private_key: evaluator.privateKey },
    }),
    legs: [
      {
        adapter_id: humanAdapter.id, profile_id: 'as-confirmation',
        artifact_ref: 'urn:human:approval:2', artifact: wrongHuman, status: fixture.input.status,
      },
      {
        adapter_id: AUTHORIZATION_SERVER_CONFIRMATION_ADAPTER_ID, profile_id: 'as-confirmation',
        artifact_ref: 'urn:as:grant:1', artifact: fixture.artifact, status: fixture.input.status,
      },
    ],
  });
  assert.equal(refused.record.verdict, 'UNSATISFIED');
  assert.match(refused.record.reasons.join('\n'), /evidence_binding_not_met/);
});
