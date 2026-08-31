// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto, { type KeyObject } from 'node:crypto';
import test from 'node:test';

import { digestAeb, type AebAdapterInput, type AebPinnedProfile } from './aeb-adapter-contract.js';
import {
  OAUTH_TXN_CHALLENGE_AEB_ADAPTER_ID,
  OAUTH_TXN_CHALLENGE_AEB_ADAPTER_VERSION,
  OAUTH_TXN_CHALLENGE_CONFIG_VERSION,
  OAUTH_TXN_CHALLENGE_DRAFT_REVISION,
  OAUTH_TXN_CHALLENGE_MAPPING_VERSION,
  OAUTH_TXN_CHALLENGE_MAPPER_ID,
  OAUTH_TXN_CHALLENGE_REPLAY_NAMESPACE,
  OAUTH_TXN_CHALLENGE_TRUST_ROOT_VERSION,
  createOAuthTransactionChallengeActionDefinition,
  createOAuthTransactionChallengeAebAdapter,
  type OAuthTransactionChallengeAdapterConfig,
  type OAuthTransactionChallengeDetailsVerifier,
  type OAuthTransactionChallengeTrustRoot,
} from './aeb-oauth-transaction-challenge-adapter.js';

type Obj = Record<string, any>;

const NOW = '2026-08-06T12:00:30Z';
const NOW_SECONDS = Math.floor(Date.parse(NOW) / 1000);
const RESOURCE = 'https://payments.example';
const AUTHORIZATION_SERVER = 'https://as.example';
const CLIENT_ID = 'agent-client-42';
const SUBJECT = 'principal:customer-42';
const TXN = '97053963-771d-49cc-a4e3-20aad399c312';
const ACTION_TYPE = 'payment.initiate.1';

function spki(key: KeyObject): string {
  return key.export({ type: 'spki', format: 'der' }).toString('base64url');
}

function compactEs256(header: Obj, claims: Obj, privateKey: KeyObject): string {
  const encodedHeader = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
  const encodedClaims = Buffer.from(JSON.stringify(claims), 'utf8').toString('base64url');
  const input = `${encodedHeader}.${encodedClaims}`;
  const signature = crypto.sign('sha256', Buffer.from(input, 'ascii'), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  return `${input}.${signature.toString('base64url')}`;
}

function makeFixture(): Obj {
  const resourceKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const asKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const authorizationDetails = [{
    type: 'payment',
    actions: ['initiate'],
    locations: ['https://payments.example/accounts/123'],
    instructedAmount: { currency: 'GBP', amount: '5000.00' },
    creditorName: 'Example Ltd',
  }];
  const challengeClaims = {
    iss: RESOURCE,
    aud: AUTHORIZATION_SERVER,
    iat: NOW_SECONDS - 20,
    exp: NOW_SECONDS + 40,
    jti: 'challenge-jti-1',
    txn: TXN,
    authorization_details: authorizationDetails,
    reason: 'Approve this exact payment',
    act: { sub: 'workload:payment-agent' },
  };
  const accessClaims = {
    iss: AUTHORIZATION_SERVER,
    sub: SUBJECT,
    aud: RESOURCE,
    iat: NOW_SECONDS - 5,
    exp: NOW_SECONDS + 115,
    jti: 'access-token-jti-1',
    client_id: CLIENT_ID,
    txn: TXN,
    authorization_details: authorizationDetails,
    act: challengeClaims.act,
  };
  const artifact = {
    challenge_jwt: compactEs256(
      { alg: 'ES256', typ: 'txn-authz-challenge+jwt', kid: 'resource-es256-1' },
      challengeClaims,
      resourceKey.privateKey,
    ),
    access_token_jwt: compactEs256(
      { alg: 'ES256', typ: 'at+jwt', kid: 'as-es256-1' },
      accessClaims,
      asKey.privateKey,
    ),
  };
  const verifierDescriptor = {
    id: 'test:oauth-rar-narrowing',
    version: '1',
    implementation_digest: digestAeb({ implementation: 'test:oauth-rar-narrowing', version: '1' }),
  };
  const config: OAuthTransactionChallengeAdapterConfig = {
    '@version': OAUTH_TXN_CHALLENGE_CONFIG_VERSION,
    evidence_role: 'transaction-authorization',
    subject: { id: 'organization:authorization-server', kind: 'organization', native_id: AUTHORIZATION_SERVER },
    action_type: ACTION_TYPE,
    protected_resource: RESOURCE,
    authorization_server: AUTHORIZATION_SERVER,
    oauth_client_id: CLIENT_ID,
    oauth_subject: SUBJECT,
    require_actor_context: true,
    replay_equivalence: 'nonreusable-protected-resource-transaction',
    clock_skew_seconds: 2,
    max_challenge_lifetime_seconds: 120,
    max_access_token_lifetime_seconds: 180,
    max_status_age_seconds: 120,
    details_verifier: verifierDescriptor,
  };
  const trustRoots: OAuthTransactionChallengeTrustRoot[] = [
    {
      '@version': OAUTH_TXN_CHALLENGE_TRUST_ROOT_VERSION,
      use: 'protected-resource-challenge',
      issuer: RESOURCE,
      key_id: 'resource-es256-1',
      algorithm: 'ES256',
      public_key: spki(resourceKey.publicKey),
    },
    {
      '@version': OAUTH_TXN_CHALLENGE_TRUST_ROOT_VERSION,
      use: 'authorization-server-access-token',
      issuer: AUTHORIZATION_SERVER,
      key_id: 'as-es256-1',
      algorithm: 'ES256',
      public_key: spki(asKey.publicKey),
    },
  ];
  const detailsVerifier: OAuthTransactionChallengeDetailsVerifier = {
    ...verifierDescriptor,
    verify(input) {
      return digestAeb(input.granted) === digestAeb(input.expected)
        && digestAeb(input.requested) === digestAeb(input.granted)
        ? { verified: true, reason: null }
        : { verified: false, reason: 'authorization_details_broadened_or_mismatched' };
    },
  };
  const expectedAction = {
    action_type: ACTION_TYPE,
    oauth_transaction: {
      txn: TXN,
      authorization_details: authorizationDetails,
      actor: challengeClaims.act,
      verified_context: {
        challenge_issuer: RESOURCE,
        challenge_audience: AUTHORIZATION_SERVER,
        access_token_issuer: AUTHORIZATION_SERVER,
        access_token_subject: SUBJECT,
        access_token_audience: RESOURCE,
        access_token_client_id: CLIENT_ID,
      },
    },
  };
  return {
    resourceKey, asKey, artifact, challengeClaims, accessClaims,
    authorizationDetails, config, trustRoots, detailsVerifier, expectedAction,
  };
}

function profile(): AebPinnedProfile {
  return {
    version: OAUTH_TXN_CHALLENGE_MAPPING_VERSION,
    definition: createOAuthTransactionChallengeActionDefinition(ACTION_TYPE, true),
    registry_entry_ref: 'mapping:oauth-transaction-payment',
    mapper_id: OAUTH_TXN_CHALLENGE_MAPPER_ID,
    resolver: {
      id: OAUTH_TXN_CHALLENGE_MAPPER_ID,
      version: '2',
      implementation_digest: digestAeb({ implementation: OAUTH_TXN_CHALLENGE_MAPPER_ID, version: '2' }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [
        'challenge.header.alg', 'challenge.header.kid', 'challenge.header.typ',
        'challenge.iat', 'challenge.exp', 'challenge.jti', 'challenge.reason',
        'challenge.reason_uri',
        'access_token.header.alg', 'access_token.header.kid', 'access_token.header.typ',
        'access_token.iat', 'access_token.exp', 'access_token.jti',
      ],
    },
    profile_digest: digestAeb(null),
  };
}

function input(fixture: Obj, overrides: Partial<Omit<AebAdapterInput, 'profile'>> = {}): Omit<AebAdapterInput, 'profile'> {
  return {
    artifact: fixture.artifact,
    artifact_ref: 'oauth-txn:payment:test-1',
    status: {
      checked_at: '2026-08-06T12:00:29Z',
      expires_at: '2026-08-06T12:01:00Z',
      revocation_checked: true,
      revoked: false,
      consumed: false,
    },
    trust_roots: fixture.trustRoots,
    adapter_config: fixture.config,
    expected_action: fixture.expectedAction,
    now: NOW,
    ...overrides,
  };
}

test('OAuth transaction-challenge -00 verifies challenge plus issued access token and maps', () => {
  const fixture = makeFixture();
  const adapter = createOAuthTransactionChallengeAebAdapter({
    config: fixture.config,
    trust_roots: fixture.trustRoots,
    details_verifier: fixture.detailsVerifier,
  });
  assert.equal(adapter.id, OAUTH_TXN_CHALLENGE_AEB_ADAPTER_ID);
  assert.equal(adapter.version, OAUTH_TXN_CHALLENGE_AEB_ADAPTER_VERSION);
  const native = adapter.verifyNative(input(fixture));
  assert.equal(native.native_verification, 'VERIFIED');
  assert.equal(native.acceptance, 'ACCEPTED');
  assert.deepEqual(native.reasons, []);
  const mapped = adapter.mapAction({ ...input(fixture), profile: profile(), native });
  assert.equal(mapped.mapping, 'MATCH');
  assert.match(mapped.caid ?? '', /^caid:1:payment\.initiate\.1:jcs-sha256:/);
});

test('verified issuer, audience, subject, and client context is material to the exact action', () => {
  const fixture = makeFixture();
  const adapter = createOAuthTransactionChallengeAebAdapter({
    config: fixture.config,
    trust_roots: fixture.trustRoots,
    details_verifier: fixture.detailsVerifier,
  });
  const changed = structuredClone(fixture.expectedAction);
  changed.oauth_transaction.verified_context.access_token_client_id = 'agent-client-other';

  const native = adapter.verifyNative(input(fixture, { expected_action: changed }));
  assert.equal(native.native_verification, 'FAILED');
  assert.equal(native.acceptance, 'REJECTED');
  assert.deepEqual(native.reasons, ['oauth-txn:verified_context_mismatch']);

  const changedActor = structuredClone(fixture.expectedAction);
  changedActor.oauth_transaction.actor.sub = 'workload:other-agent';
  const actorResult = adapter.verifyNative(input(fixture, { expected_action: changedActor }));
  assert.equal(actorResult.acceptance, 'REJECTED');
  assert.deepEqual(actorResult.reasons, ['oauth-txn:actor_context_mismatch']);
});

test('the mapping pins a complete semantic-loss declaration with relying-party bases', () => {
  const fixture = makeFixture();
  const adapter = createOAuthTransactionChallengeAebAdapter({
    config: fixture.config,
    trust_roots: fixture.trustRoots,
    details_verifier: fixture.detailsVerifier,
  });
  const native = adapter.verifyNative(input(fixture));
  const complete = profile();
  const definition = complete.definition as Obj;
  assert.deepEqual(definition.semantic_loss_contract.verified_action_fields, [
    'challenge.iss', 'challenge.aud', 'challenge.txn', 'challenge.authorization_details',
    'challenge.act', 'access_token.iss', 'access_token.sub', 'access_token.aud',
    'access_token.client_id', 'access_token.txn', 'access_token.authorization_details',
    'access_token.act',
  ]);
  assert.ok(definition.semantic_loss_contract.omitted_nonmaterial_fields.every(
    (entry: Obj) => typeof entry.path === 'string' && typeof entry.relying_party_basis === 'string',
  ));

  const incomplete = structuredClone(complete);
  incomplete.semantic_equivalence.omitted_nonmaterial_fields =
    incomplete.semantic_equivalence.omitted_nonmaterial_fields.slice(1);
  incomplete.profile_digest = digestAeb(null);
  const mapped = adapter.mapAction({ ...input(fixture), profile: incomplete, native });
  assert.equal(mapped.mapping, 'INDETERMINATE');
  assert.deepEqual(mapped.reasons, ['mapping_profile_or_action_invalid']);
});

test('an actor claim is refused when the selected mapping does not carry actor context', () => {
  const fixture = makeFixture();
  const config = { ...fixture.config, require_actor_context: false };
  const adapter = createOAuthTransactionChallengeAebAdapter({
    config,
    trust_roots: fixture.trustRoots,
    details_verifier: fixture.detailsVerifier,
  });
  const expectedAction = structuredClone(fixture.expectedAction);
  delete expectedAction.oauth_transaction.actor;
  const native = adapter.verifyNative(input(fixture, {
    adapter_config: config,
    expected_action: expectedAction,
  }));
  assert.equal(native.acceptance, 'REJECTED');
  assert.deepEqual(native.reasons, ['oauth-txn:actor_context_requires_material_mapping']);
});

test('challenge alone and an asynchronous pending response are never authorization evidence', () => {
  const fixture = makeFixture();
  const adapter = createOAuthTransactionChallengeAebAdapter({
    config: fixture.config,
    trust_roots: fixture.trustRoots,
    details_verifier: fixture.detailsVerifier,
  });
  const challengeOnly = adapter.verifyNative(input(fixture, {
    artifact: { challenge_jwt: fixture.artifact.challenge_jwt },
  }));
  assert.equal(challengeOnly.native_verification, 'FAILED');
  assert.equal(challengeOnly.acceptance, 'REJECTED');
  assert.ok(challengeOnly.reasons.includes('oauth-txn:challenge_and_access_token_required'));

  const pending = adapter.verifyNative(input(fixture, {
    artifact: {
      challenge_jwt: fixture.artifact.challenge_jwt,
      transaction_authorization_id: 'txn-authz-abc123',
    },
  }));
  assert.equal(pending.acceptance, 'REJECTED');
});

test('OAuth transaction adapter refuses txn mismatch and broadened authorization details', () => {
  const fixture = makeFixture();
  const adapter = createOAuthTransactionChallengeAebAdapter({
    config: fixture.config,
    trust_roots: fixture.trustRoots,
    details_verifier: fixture.detailsVerifier,
  });
  const wrongTxn = structuredClone(fixture.expectedAction);
  wrongTxn.oauth_transaction.txn = 'other-txn';
  const mismatch = adapter.verifyNative(input(fixture, { expected_action: wrongTxn }));
  assert.equal(mismatch.acceptance, 'REJECTED');
  assert.ok(mismatch.reasons.includes('oauth-txn:exact_action_mismatch'));

  const refusing: OAuthTransactionChallengeDetailsVerifier = {
    ...fixture.detailsVerifier,
    verify: () => ({ verified: false, reason: 'authorization_details_broadened_or_mismatched' }),
  };
  const refusingAdapter = createOAuthTransactionChallengeAebAdapter({
    config: fixture.config,
    trust_roots: fixture.trustRoots,
    details_verifier: refusing,
  });
  const broadened = refusingAdapter.verifyNative(input(fixture));
  assert.equal(broadened.acceptance, 'REJECTED');
  assert.ok(broadened.reasons.includes('oauth-txn:authorization_details_broadened_or_mismatched'));
});

test('OAuth transaction access token is fenced as single-use evidence', () => {
  const fixture = makeFixture();
  const adapter = createOAuthTransactionChallengeAebAdapter({
    config: fixture.config,
    trust_roots: fixture.trustRoots,
    details_verifier: fixture.detailsVerifier,
  });
  const consumed = adapter.verifyNative(input(fixture, {
    status: { ...input(fixture).status, consumed: true },
  }));
  assert.equal(consumed.native_verification, 'VERIFIED');
  assert.equal(consumed.acceptance, 'REJECTED');
  assert.ok(consumed.reasons.includes('evidence_consumed'));
});

test('a second access token for the same protected-resource transaction shares one replay unit', () => {
  const fixture = makeFixture();
  const adapter = createOAuthTransactionChallengeAebAdapter({
    config: fixture.config,
    trust_roots: fixture.trustRoots,
    details_verifier: fixture.detailsVerifier,
  });
  const first = adapter.verifyNative(input(fixture));
  const twinClaims = {
    ...fixture.accessClaims,
    iat: fixture.accessClaims.iat + 1,
    exp: fixture.accessClaims.exp + 1,
    jti: 'access-token-jti-2',
  };
  const twin = adapter.verifyNative(input(fixture, {
    artifact: {
      ...fixture.artifact,
      access_token_jwt: compactEs256(
        { alg: 'ES256', typ: 'at+jwt', kid: 'as-es256-1' },
        twinClaims,
        fixture.asKey.privateKey,
      ),
    },
  }));

  assert.equal(first.acceptance, 'ACCEPTED');
  assert.equal(twin.acceptance, 'ACCEPTED');
  assert.equal(
    fixture.config.replay_equivalence,
    'nonreusable-protected-resource-transaction',
  );
  assert.equal(first.replay_unit, twin.replay_unit);
});

test('authorization-server migration cannot create another spend for one protected-resource transaction', () => {
  const fixture = makeFixture();
  const firstAdapter = createOAuthTransactionChallengeAebAdapter({
    config: fixture.config,
    trust_roots: fixture.trustRoots,
    details_verifier: fixture.detailsVerifier,
  });
  const first = firstAdapter.verifyNative(input(fixture));

  const alternateAuthorizationServer = 'https://as-migrated.example';
  const alternateKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const alternateConfig: OAuthTransactionChallengeAdapterConfig = {
    ...fixture.config,
    subject: {
      ...fixture.config.subject,
      native_id: alternateAuthorizationServer,
    },
    authorization_server: alternateAuthorizationServer,
  };
  const alternateRoots: OAuthTransactionChallengeTrustRoot[] = [
    {
      ...fixture.trustRoots[0],
      issuer: RESOURCE,
    },
    {
      ...fixture.trustRoots[1],
      issuer: alternateAuthorizationServer,
      key_id: 'as-migrated-es256-1',
      public_key: spki(alternateKey.publicKey),
    },
  ];
  const alternateArtifact = {
    challenge_jwt: compactEs256(
      { alg: 'ES256', typ: 'txn-authz-challenge+jwt', kid: 'resource-es256-1' },
      {
        ...fixture.challengeClaims,
        aud: alternateAuthorizationServer,
        jti: 'challenge-jti-migrated-as',
      },
      fixture.resourceKey.privateKey,
    ),
    access_token_jwt: compactEs256(
      { alg: 'ES256', typ: 'at+jwt', kid: 'as-migrated-es256-1' },
      {
        ...fixture.accessClaims,
        iss: alternateAuthorizationServer,
        jti: 'access-token-jti-migrated-as',
      },
      alternateKey.privateKey,
    ),
  };
  const alternateAdapter = createOAuthTransactionChallengeAebAdapter({
    config: alternateConfig,
    trust_roots: alternateRoots,
    details_verifier: fixture.detailsVerifier,
  });
  const alternate = alternateAdapter.verifyNative(input(fixture, {
    artifact: alternateArtifact,
    adapter_config: alternateConfig,
    trust_roots: alternateRoots,
    expected_action: {
      ...fixture.expectedAction,
      oauth_transaction: {
        ...fixture.expectedAction.oauth_transaction,
        verified_context: {
          ...fixture.expectedAction.oauth_transaction.verified_context,
          challenge_audience: alternateAuthorizationServer,
          access_token_issuer: alternateAuthorizationServer,
        },
      },
    },
  }));

  assert.equal(first.acceptance, 'ACCEPTED');
  assert.equal(alternate.acceptance, 'ACCEPTED');
  assert.equal(first.replay_unit, alternate.replay_unit);
});

test('OAuth transaction source lock is the reviewed -00 draft', () => {
  assert.equal(OAUTH_TXN_CHALLENGE_DRAFT_REVISION, 'draft-rosomakho-oauth-txn-challenge-00');
  assert.equal(OAUTH_TXN_CHALLENGE_AEB_ADAPTER_VERSION, '3');
  assert.equal(OAUTH_TXN_CHALLENGE_MAPPING_VERSION, 'AEB-OAUTH-TXN-CHALLENGE-CAID-MAPPING-v2');
  assert.equal(
    OAUTH_TXN_CHALLENGE_REPLAY_NAMESPACE,
    'emilia:oauth-txn-challenge:protected-resource-transaction:v1',
  );
});
