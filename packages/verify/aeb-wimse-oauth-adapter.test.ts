// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto, { type KeyObject } from 'node:crypto';
import fs from 'node:fs';
import test from 'node:test';

// The CAID reference implementation intentionally has no TypeScript surface.
// @ts-expect-error -- exercised as the independent CAID recomputation.
import { computeCaid } from './vendor/caid.mjs';
import {
  InMemoryAebConsumptionStore,
  canonicalizeAeb,
  digestAeb,
  type AebAdapterInput,
  type AebPinnedProfile,
} from './aeb-adapter-contract.js';
import {
  OAUTH_TRANSACTION_TOKENS_REVISION,
  WIMSE_OAUTH_SPT_AEB_ADAPTER_ID,
  WIMSE_OAUTH_SPT_AEB_ADAPTER_VERSION,
  WIMSE_OAUTH_SPT_AEB_CONFIG_VERSION,
  WIMSE_OAUTH_SPT_CAID_MAPPER_ID,
  WIMSE_OAUTH_SPT_CAID_MAPPING_VERSION,
  WIMSE_OAUTH_SPT_TRUST_ROOT_VERSION,
  createWimseOAuthSptAebAdapter,
  createWimseOAuthSptActionDefinition,
  type WimseOAuthSptAdapterConfig,
  type WimseOAuthSptTrustRoot,
} from './aeb-wimse-oauth-adapter.js';
import {
  WIMSE_OAUTH_PRINCIPAL_BINDING_CLAIM,
  WIMSE_OAUTH_PRINCIPAL_BINDING_VERSION,
  WIMSE_OAUTH_PRINCIPAL_CONFIG_VERSION,
  createWimseOAuthPrincipalAebAdapter,
  type WimseOAuthPrincipalAdapterConfig,
} from './aeb-wimse-oauth-principal-adapter.js';

type Obj = Record<string, any>;

const NOW = '2026-07-24T12:00:00Z';
const NOW_SECONDS = Math.floor(Date.parse(NOW) / 1000);
const WORKLOAD_SUBJECT = 'wimse://payments.example/workloads/release-agent';
const WIMSE_AUDIENCE = 'https://payments.example/commit';
const OAUTH_AUDIENCE = 'payments.example';
const OAUTH_SUBJECT = 'principal:customer-42';
const OAUTH_SCOPE = 'payment.release';
const SPT_AUDIENCE = 'https://payments.example/pep';
const ACTION_TYPE = 'payment.release.1';

interface FixtureOptions {
  witAlg?: string;
  witSigner?: 'issuer' | 'attacker';
  witSubject?: string;
  wptAudience?: string;
  wptTth?: string;
  wptTimes?: { iat: number; nbf: number; exp: number };
  oauthAudience?: string;
  oauthTimes?: { iat: number; nbf: number; exp: number };
  sptIntentDigest?: string;
  signatureAudience?: string;
  signatureComponents?: string[];
  includeSpt?: boolean;
  includePrincipalBinding?: boolean;
  principalBindingOverrides?: Obj;
  principalBindingDelete?: string[];
  oauthSubject?: string;
  principalPinsOverrides?: Obj;
}

interface Fixture {
  adapter: ReturnType<typeof createWimseOAuthSptAebAdapter>;
  artifact: Obj;
  config: WimseOAuthSptAdapterConfig;
  trustRoots: WimseOAuthSptTrustRoot[];
  expectedAction: Obj;
  profile: AebPinnedProfile;
  input: Omit<AebAdapterInput, 'profile'>;
  principalBinding: Obj;
}

function spki(key: KeyObject): string {
  return key.export({ type: 'spki', format: 'der' }).toString('base64url');
}

function compactJws(header: Obj, claims: Obj, privateKey: KeyObject): string {
  const protectedHeader = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
  const payload = Buffer.from(JSON.stringify(claims), 'utf8').toString('base64url');
  const signingInput = `${protectedHeader}.${payload}`;
  const signature = crypto.sign(null, Buffer.from(signingInput, 'ascii'), privateKey).toString('base64url');
  return `${signingInput}.${signature}`;
}

function sha256Base64url(value: string): string {
  // OAuth token-binding test commitment, not password or credential storage.
  // codeql[js/insufficient-password-hash]
  return crypto.createHash('sha256').update(Buffer.from(value, 'ascii')).digest('base64url');
}

function holderJkt(jwk: JsonWebKey): string {
  assert.equal(jwk.kty, 'OKP');
  assert.equal(jwk.crv, 'Ed25519');
  assert.equal(typeof jwk.x, 'string');
  return crypto.createHash('sha256')
    .update(Buffer.from(canonicalizeAeb({ crv: jwk.crv, kty: jwk.kty, x: jwk.x }), 'utf8'))
    .digest('base64url');
}

function contentDigest(body: string): string {
  return `sha-256=:${crypto.createHash('sha256').update(Buffer.from(body, 'utf8')).digest('base64')}:`;
}

function sptIntentDigest(intent: Obj): string {
  return crypto.createHash('sha256')
    .update(Buffer.from('spt-txn-intent-v1', 'utf8'))
    .update(Buffer.from([0]))
    .update(Buffer.from(canonicalizeAeb(intent), 'utf8'))
    .digest('base64url');
}

function mappingProfile(): AebPinnedProfile {
  return {
    version: WIMSE_OAUTH_SPT_CAID_MAPPING_VERSION,
    definition: createWimseOAuthSptActionDefinition(ACTION_TYPE),
    registry_entry_ref: 'mapping:wimse-oauth-spt-payment-release',
    mapper_id: WIMSE_OAUTH_SPT_CAID_MAPPER_ID,
    resolver: {
      id: WIMSE_OAUTH_SPT_CAID_MAPPER_ID,
      version: '1',
      implementation_digest: digestAeb({
        implementation: WIMSE_OAUTH_SPT_CAID_MAPPER_ID,
        version: '1',
      }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [
        'wit.iss',
        'wit.sub',
        'oauth.iss',
        'oauth.aud',
        'oauth.sub',
        'oauth.txn',
        'oauth.req_wl',
        'spt.human_anchor',
        'spt.jti',
      ],
    },
    profile_digest: digestAeb(null),
  };
}

function signatureBase(
  components: string[],
  signatureParams: string,
  method: string,
  requestTarget: string,
  headers: Obj,
): string {
  const normalized = new Map(
    Object.entries(headers).map(([name, value]) => [name.toLowerCase(), String(value).trim()]),
  );
  const lines = components.map((component) => {
    const value = component === '@method'
      ? method
      : component === '@request-target'
        ? requestTarget
        : normalized.get(component);
    assert.notEqual(value, undefined, `test signer cannot resolve ${component}`);
    return `${JSON.stringify(component)}: ${value}`;
  });
  lines.push(`"@signature-params": ${signatureParams}`);
  return lines.join('\n');
}

function makeFixture(options: FixtureOptions = {}): Fixture {
  const witIssuer = crypto.generateKeyPairSync('ed25519');
  const oauthIssuer = crypto.generateKeyPairSync('ed25519');
  const sptIssuer = crypto.generateKeyPairSync('ed25519');
  const holder = crypto.generateKeyPairSync('ed25519');
  const attacker = crypto.generateKeyPairSync('ed25519');
  const holderJwk = holder.publicKey.export({ format: 'jwk' });
  assert.equal(holderJwk.kty, 'OKP');
  assert.equal(holderJwk.crv, 'Ed25519');
  assert.equal(typeof holderJwk.x, 'string');
  const holderKeyId = 'workload-ed25519-2026-07';
  const holderKeyPin = `holder:${holderJwk.x}`;
  const config: WimseOAuthSptAdapterConfig = {
    '@version': WIMSE_OAUTH_SPT_AEB_CONFIG_VERSION,
    evidence_role: 'delegated-workload',
    subject: {
      id: 'workload:payment-release-agent',
      kind: 'workload',
      native_id: WORKLOAD_SUBJECT,
    },
    trust_domain: 'payments.example',
    wimse_audience: WIMSE_AUDIENCE,
    oauth_audience: OAUTH_AUDIENCE,
    oauth_subject: OAUTH_SUBJECT,
    oauth_scope: OAUTH_SCOPE,
    spt_audience: SPT_AUDIENCE,
    spt_subject: WORKLOAD_SUBJECT,
    spt_holder_key: holderKeyPin,
    action_type: ACTION_TYPE,
    clock_skew_seconds: 2,
    max_age_seconds: {
      wit: 3_600,
      wpt: 300,
      oauth_txn: 600,
      spt_txn: 180,
      http_signature: 120,
      status: 120,
    },
  };
  const trustRoots: WimseOAuthSptTrustRoot[] = [
    {
      '@version': WIMSE_OAUTH_SPT_TRUST_ROOT_VERSION,
      use: 'wit-issuer',
      issuer: 'https://identity.payments.example',
      key_id: 'wit-issuer-ed25519-1',
      algorithm: 'EdDSA',
      public_key: spki(witIssuer.publicKey),
    },
    {
      '@version': WIMSE_OAUTH_SPT_TRUST_ROOT_VERSION,
      use: 'oauth-transaction-token-issuer',
      issuer: 'https://tts.payments.example',
      key_id: 'tts-ed25519-1',
      algorithm: 'EdDSA',
      public_key: spki(oauthIssuer.publicKey),
    },
    {
      '@version': WIMSE_OAUTH_SPT_TRUST_ROOT_VERSION,
      use: 'spt-transaction-token-issuer',
      issuer: 'https://spt.payments.example',
      key_id: 'spt-ed25519-1',
      algorithm: 'EdDSA',
      public_key: spki(sptIssuer.publicKey),
    },
    {
      '@version': WIMSE_OAUTH_SPT_TRUST_ROOT_VERSION,
      use: 'workload-holder',
      subject: WORKLOAD_SUBJECT,
      key_id: holderKeyId,
      algorithm: 'EdDSA',
      public_key: spki(holder.publicKey),
    },
  ];

  const witClaims = {
    iss: trustRoots[0].use === 'wit-issuer' ? trustRoots[0].issuer : '',
    sub: options.witSubject ?? WORKLOAD_SUBJECT,
    iat: NOW_SECONDS - 30,
    nbf: NOW_SECONDS - 30,
    exp: NOW_SECONDS + 1_800,
    jti: 'wit-2026-07-24-0001',
    cnf: {
      jwk: {
        kty: 'OKP',
        crv: 'Ed25519',
        alg: 'EdDSA',
        kid: holderKeyId,
        x: holderJwk.x,
      },
    },
  };
  const wit = compactJws({
    alg: options.witAlg ?? 'EdDSA',
    typ: 'wit+jwt',
    kid: 'wit-issuer-ed25519-1',
  }, witClaims, options.witSigner === 'attacker' ? attacker.privateKey : witIssuer.privateKey);

  const transactionContext = {
    effect: 'payment.release',
    target_id: 'escrow_4821',
    amount_minor: '50000',
    currency: 'USD',
  };
  const principalBinding: Obj = {
    '@version': WIMSE_OAUTH_PRINCIPAL_BINDING_VERSION,
    logical_agent_id: 'wimse://payments.example/agents/release-agent',
    workload_instance_id: WORKLOAD_SUBJECT,
    wimse_subject_semantics: 'workload-instance',
    workload_confirmation_jkt: holderJkt(holderJwk),
    oauth_client_id: 'client:release-agent-runtime',
    oauth_grant_type: 'urn:example:grant:delegated-payment',
    oauth_sub_semantics: 'delegating-principal',
    delegating_principal: {
      id: OAUTH_SUBJECT,
      kind: 'human',
    },
    executor_id: 'executor:payments-commit',
    tool_id: 'payment.release',
  };
  Object.assign(principalBinding, options.principalBindingOverrides ?? {});
  for (const key of options.principalBindingDelete ?? []) delete principalBinding[key];
  const oauthTimes = options.oauthTimes ?? {
    iat: NOW_SECONDS - 10,
    nbf: NOW_SECONDS - 10,
    exp: NOW_SECONDS + 300,
  };
  const oauthClaims = {
    iss: 'https://tts.payments.example',
    sub: options.oauthSubject ?? OAUTH_SUBJECT,
    aud: options.oauthAudience ?? OAUTH_AUDIENCE,
    ...oauthTimes,
    txn: 'txn-payment-release-0001',
    scope: OAUTH_SCOPE,
    req_wl: WORKLOAD_SUBJECT,
    tctx: transactionContext,
  };
  if (options.includePrincipalBinding === true) {
    oauthClaims[WIMSE_OAUTH_PRINCIPAL_BINDING_CLAIM] = principalBinding;
  }
  const txnToken = compactJws({
    alg: 'EdDSA',
    typ: 'txntoken+jwt',
    kid: 'tts-ed25519-1',
  }, oauthClaims, oauthIssuer.privateKey);

  const sptIntent = {
    tool: 'payment.release',
    params: {
      amount_minor: '50000',
      currency: 'USD',
      escrow_id: 'escrow_4821',
    },
    target: 'payments.example/escrow_4821',
  };
  const sptClaims = {
    iss: 'https://spt.payments.example',
    sub: WORKLOAD_SUBJECT,
    aud: SPT_AUDIENCE,
    iat: NOW_SECONDS - 5,
    nbf: NOW_SECONDS - 5,
    exp: NOW_SECONDS + 90,
    jti: 'spt-txn-payment-release-0001',
    txn_token_type: 'TXN',
    human_anchor: 'opaque-anchor-not-a-human-authorization-role',
    holder_key: holderKeyPin,
    spt_intent_digest: options.sptIntentDigest ?? sptIntentDigest(sptIntent),
  };
  const sptTxn = compactJws({
    alg: 'EdDSA',
    kid: 'spt-ed25519-1',
  }, sptClaims, sptIssuer.privateKey);

  const wptTimes = options.wptTimes ?? {
    iat: NOW_SECONDS - 5,
    nbf: NOW_SECONDS - 5,
    exp: NOW_SECONDS + 90,
  };
  const wptClaims = {
    aud: options.wptAudience ?? WIMSE_AUDIENCE,
    ...wptTimes,
    jti: 'wpt-payment-release-0001',
    wth: sha256Base64url(wit),
    tth: options.wptTth ?? sha256Base64url(txnToken),
  };
  const wpt = compactJws({
    alg: 'EdDSA',
    typ: 'wpt+jwt',
  }, wptClaims, holder.privateKey);

  const body = '{"amount_minor":"50000","currency":"USD","escrow_id":"escrow_4821"}';
  const method = 'POST';
  const targetUri = 'https://payments.example/commit?mode=atomic';
  const requestTarget = '/commit?mode=atomic';
  const components = options.signatureComponents ?? [
    '@method',
    '@request-target',
    'content-type',
    'content-digest',
    'txn-token',
    'workload-identity-token',
  ];
  const signatureParams = `(${components.map((component) => JSON.stringify(component)).join(' ')})`
    + `;created=${NOW_SECONDS - 3};expires=${NOW_SECONDS + 57}`
    + ';nonce="wimse-nonce-payment-release-0001"'
    + ';tag="wimse-workload-to-workload"'
    + `;wimse-aud="${options.signatureAudience ?? WIMSE_AUDIENCE}"`;
  const headers: Obj = {
    'Content-Type': 'application/json',
    'Content-Digest': contentDigest(body),
    'Txn-Token': txnToken,
    'Workload-Identity-Token': wit,
    'Workload-Proof-Token': wpt,
    'Signature-Input': `wimse=${signatureParams}`,
  };
  const requestSignature = crypto.sign(
    null,
    Buffer.from(signatureBase(components, signatureParams, method, requestTarget, headers), 'utf8'),
    holder.privateKey,
  ).toString('base64');
  headers.Signature = `wimse=:${requestSignature}:`;

  const includeSpt = options.includeSpt !== false;
  const artifact: Obj = {
    wit,
    wpt,
    txn_token: txnToken,
    request: {
      method,
      target_uri: targetUri,
      headers,
      body,
    },
  };
  if (includeSpt) {
    artifact.spt_txn = sptTxn;
    artifact.spt_intent = sptIntent;
  }
  const expectedAction: Obj = {
    action_type: ACTION_TYPE,
    http: {
      method,
      request_target: requestTarget,
      content_digest: headers['Content-Digest'],
      wimse_audience: options.signatureAudience ?? WIMSE_AUDIENCE,
    },
    transaction: {
      scope: OAUTH_SCOPE,
      context: transactionContext,
    },
  };
  if (includeSpt) expectedAction.spt_intent = sptIntent;
  const profile = mappingProfile();
  const adapter = createWimseOAuthSptAebAdapter({
    config,
    trust_roots: trustRoots,
  });
  const input: Omit<AebAdapterInput, 'profile'> = {
    artifact,
    artifact_ref: 'artifact:wimse-oauth-spt-1',
    status: {
      checked_at: '2026-07-24T11:59:30Z',
      expires_at: '2026-07-24T12:01:00Z',
      revocation_checked: true,
      revoked: false,
      consumed: false,
    },
    trust_roots: trustRoots,
    adapter_config: config,
    expected_action: expectedAction,
    now: NOW,
  };
  return {
    adapter,
    artifact,
    config,
    trustRoots,
    expectedAction,
    profile,
    input,
    principalBinding,
  };
}

function makeV2Fixture(options: FixtureOptions = {}) {
  const fixture = makeFixture({ ...options, includePrincipalBinding: options.includePrincipalBinding ?? true });
  const principalPins: Obj = {
    '@version': WIMSE_OAUTH_PRINCIPAL_BINDING_VERSION,
    logical_agent_id: 'wimse://payments.example/agents/release-agent',
    workload_instance_id: WORKLOAD_SUBJECT,
    wimse_subject_semantics: 'workload-instance',
    workload_confirmation_jkt: fixture.principalBinding.workload_confirmation_jkt,
    oauth_client_id: 'client:release-agent-runtime',
    oauth_grant_type: 'urn:example:grant:delegated-payment',
    oauth_sub_semantics: 'delegating-principal',
    delegating_principal: {
      id: OAUTH_SUBJECT,
      kind: 'human',
    },
    executor_id: 'executor:payments-commit',
    tool_id: 'payment.release',
  };
  Object.assign(principalPins, options.principalPinsOverrides ?? {});
  const config: WimseOAuthPrincipalAdapterConfig = {
    '@version': WIMSE_OAUTH_PRINCIPAL_CONFIG_VERSION,
    base: fixture.config,
    principal_binding: principalPins as unknown as WimseOAuthPrincipalAdapterConfig['principal_binding'],
  };
  const adapter = createWimseOAuthPrincipalAebAdapter({
    config,
    trust_roots: fixture.trustRoots,
  });
  return {
    ...fixture,
    adapter,
    v2Config: config,
    input: { ...fixture.input, adapter_config: config },
  };
}

function verifyFixture(fixture: Fixture) {
  return fixture.adapter.verifyNative(fixture.input);
}

test('real Ed25519 WIT, WPT, OAuth Txn, SPT intent, and HTTP signature map to one recomputed CAID', () => {
  const fixture = makeFixture();
  assert.equal(fixture.adapter.id, WIMSE_OAUTH_SPT_AEB_ADAPTER_ID);
  assert.equal(fixture.adapter.version, WIMSE_OAUTH_SPT_AEB_ADAPTER_VERSION);
  const native = verifyFixture(fixture);
  assert.equal(native.native_verification, 'VERIFIED', native.reasons.join('; '));
  assert.equal(native.acceptance, 'ACCEPTED', native.reasons.join('; '));
  assert.equal(native.evidence_role, 'delegated-workload');
  assert.deepEqual(native.subject, {
    id: 'workload:payment-release-agent',
    kind: 'workload',
  });
  assert.match(native.replay_unit, /^sha256:[0-9a-f]{64}$/);

  const mapped = fixture.adapter.mapAction({
    ...fixture.input,
    profile: fixture.profile,
    native,
  });
  assert.equal(mapped.mapping, 'MATCH', mapped.reasons.join('; '));
  assert.equal(mapped.action_digest, digestAeb(fixture.expectedAction));
  const definition = fixture.profile.definition as Obj;
  const independentlyComputed = computeCaid(fixture.expectedAction, {
    suite: 'jcs-sha256',
    definitions: definition.definitions,
  });
  assert.equal(mapped.caid, independentlyComputed.caid);
  assert.match(mapped.caid ?? '', /^caid:1:payment\.release\.1:jcs-sha256:[A-Za-z0-9_-]{43}$/);
});

test('SPT is optional, but its intent binding is mandatory whenever the token is present', () => {
  const withoutSpt = makeFixture({ includeSpt: false });
  const native = verifyFixture(withoutSpt);
  assert.equal(native.native_verification, 'VERIFIED', native.reasons.join('; '));
  assert.equal(native.acceptance, 'ACCEPTED');
  const mapped = withoutSpt.adapter.mapAction({
    ...withoutSpt.input,
    profile: withoutSpt.profile,
    native,
  });
  assert.equal(mapped.mapping, 'MATCH', mapped.reasons.join('; '));
  assert.equal(Object.hasOwn(withoutSpt.expectedAction, 'spt_intent'), false);

  const incomplete = makeFixture();
  delete incomplete.artifact.spt_intent;
  const incompleteResult = verifyFixture(incomplete);
  assert.equal(incompleteResult.native_verification, 'FAILED');
  assert.equal(incompleteResult.acceptance, 'INDETERMINATE');
});

test('malformed, unexpected-algorithm, and wrong-key compact JWS inputs fail closed', () => {
  const malformed = makeFixture();
  malformed.artifact.wit = 'malformed.compact-jws';
  malformed.artifact.request.headers['Workload-Identity-Token'] = malformed.artifact.wit;
  const badAlg = makeFixture({ witAlg: 'ES256' });
  const wrongKey = makeFixture({ witSigner: 'attacker' });
  for (const fixture of [malformed, badAlg, wrongKey]) {
    const native = verifyFixture(fixture);
    assert.equal(native.native_verification, 'FAILED');
    assert.equal(native.acceptance, 'REJECTED');
  }
});

test('constructor-pinned audiences, trust domain, and workload subject cannot be substituted', () => {
  const wrongWptAudience = makeFixture({ wptAudience: 'https://attacker.example/commit' });
  const wrongOauthAudience = makeFixture({ oauthAudience: 'attacker.example' });
  const wrongSubject = makeFixture({ witSubject: 'wimse://attacker.example/workloads/release-agent' });
  const wrongSignatureAudience = makeFixture({ signatureAudience: 'https://attacker.example/commit' });
  for (const fixture of [
    wrongWptAudience,
    wrongOauthAudience,
    wrongSubject,
    wrongSignatureAudience,
  ]) {
    const native = verifyFixture(fixture);
    assert.equal(native.native_verification, 'FAILED');
    assert.equal(native.acceptance, 'REJECTED');
  }
});

test('iat, nbf, exp, and constructor-pinned maximum ages are all enforced', () => {
  const expired = makeFixture({
    wptTimes: {
      iat: NOW_SECONDS - 100,
      nbf: NOW_SECONDS - 100,
      exp: NOW_SECONDS - 10,
    },
  });
  const notYetValid = makeFixture({
    wptTimes: {
      iat: NOW_SECONDS - 1,
      nbf: NOW_SECONDS + 60,
      exp: NOW_SECONDS + 120,
    },
  });
  const stale = makeFixture({
    oauthTimes: {
      iat: NOW_SECONDS - 700,
      nbf: NOW_SECONDS - 700,
      exp: NOW_SECONDS + 10,
    },
  });
  for (const fixture of [expired, notYetValid, stale]) {
    const native = verifyFixture(fixture);
    assert.equal(native.native_verification, 'FAILED');
    assert.equal(native.acceptance, 'REJECTED');
  }
});

test('HTTP method, target, content digest, wimse-aud, and Txn-Token coverage fail closed', () => {
  const complete = [
    '@method',
    '@request-target',
    'content-type',
    'content-digest',
    'txn-token',
    'workload-identity-token',
  ];
  const missingCoverage = complete.map((omitted) => makeFixture({
    signatureComponents: complete.filter((component) => component !== omitted),
  }));
  const changedBody = makeFixture();
  changedBody.artifact.request.body = '{"amount_minor":"90000"}';
  for (const fixture of [...missingCoverage, changedBody]) {
    const native = verifyFixture(fixture);
    assert.equal(native.native_verification, 'FAILED');
    assert.equal(native.acceptance, 'REJECTED');
  }
});

test('WPT tth and optional SPT intent transaction binding reject signed mismatches', () => {
  const wrongTth = makeFixture({ wptTth: sha256Base64url('different-transaction-token') });
  const wrongSptIntent = makeFixture({ sptIntentDigest: sha256Base64url('different-intent') });
  for (const fixture of [wrongTth, wrongSptIntent]) {
    const native = verifyFixture(fixture);
    assert.equal(native.native_verification, 'FAILED');
    assert.equal(native.acceptance, 'REJECTED');
  }
});

test('missing exact action is INDETERMINATE and a different exact action is MISMATCH', () => {
  const fixture = makeFixture();
  const native = verifyFixture(fixture);
  assert.equal(native.acceptance, 'ACCEPTED');
  const missing = fixture.adapter.mapAction({
    ...fixture.input,
    expected_action: undefined,
    profile: fixture.profile,
    native,
  });
  assert.equal(missing.mapping, 'INDETERMINATE');
  assert.equal(missing.caid, null);
  assert.ok(missing.reasons.includes('missing_or_ambiguous_exact_action'));

  const changedAction = structuredClone(fixture.expectedAction);
  changedAction.transaction.context.amount_minor = '90000';
  const mismatch = fixture.adapter.mapAction({
    ...fixture.input,
    expected_action: changedAction,
    profile: fixture.profile,
    native,
  });
  assert.equal(mismatch.mapping, 'MISMATCH');
  assert.equal(mismatch.caid, null);
  assert.ok(mismatch.reasons.includes('exact_action_projection_mismatch'));
});

test('OAuth txn creates a stable native replay ID across AEB wrappers and is fenced', () => {
  const fixture = makeFixture();
  const first = verifyFixture(fixture);
  const second = fixture.adapter.verifyNative({
    ...fixture.input,
    artifact_ref: 'artifact:wimse-oauth-spt-second-wrapper',
  });
  assert.equal(first.native_verification, 'VERIFIED');
  assert.equal(second.native_verification, 'VERIFIED');
  assert.equal(first.replay_unit, second.replay_unit);
  assert.equal(first.replay_unit, digestAeb({
    native_protocol: OAUTH_TRANSACTION_TOKENS_REVISION,
    trust_domain: OAUTH_AUDIENCE,
    txn: 'txn-payment-release-0001',
  }));

  const store = new InMemoryAebConsumptionStore();
  assert.equal(store.reserve('aeb:operation:first', [first.replay_unit]), true);
  assert.equal(store.reserve('aeb:operation:second', [second.replay_unit]), false);
});

test('identity, possession, OAuth context, and SPT human_anchor cannot substitute a human authorization role', () => {
  const fixture = makeFixture();
  const native = verifyFixture(fixture);
  assert.equal(native.native_verification, 'VERIFIED');
  assert.equal(native.evidence_role, 'delegated-workload');
  assert.equal(native.subject.kind, 'workload');

  const substitutedConfig = structuredClone(fixture.config) as Obj;
  substitutedConfig.evidence_role = 'human-authorization';
  const substituted = fixture.adapter.verifyNative({
    ...fixture.input,
    adapter_config: substitutedConfig,
  });
  assert.equal(substituted.native_verification, 'FAILED');
  assert.equal(substituted.acceptance, 'INDETERMINATE');
  assert.ok(substituted.reasons.includes('wimse-oauth-spt:constructor_pin_mismatch'));

  assert.throws(() => createWimseOAuthSptAebAdapter({
    config: substitutedConfig as WimseOAuthSptAdapterConfig,
    trust_roots: fixture.trustRoots,
  }), /constructor config/);
});

test('v2 pins six distinct principals without adding identity to the CAID action', () => {
  const fixture = makeV2Fixture();
  const native = verifyFixture(fixture);
  assert.equal(native.native_verification, 'VERIFIED', native.reasons.join('; '));
  assert.equal(native.acceptance, 'ACCEPTED', native.reasons.join('; '));
  assert.equal(native.evidence_role, 'delegated-workload');
  assert.equal(native.subject.kind, 'workload');

  const mapped = fixture.adapter.mapAction({
    ...fixture.input,
    profile: fixture.profile,
    native,
  });
  assert.equal(mapped.mapping, 'MATCH', mapped.reasons.join('; '));
  assert.equal(mapped.action_digest, digestAeb(fixture.expectedAction));
  assert.equal(JSON.stringify(fixture.expectedAction).includes('logical_agent'), false);
  assert.equal(JSON.stringify(fixture.expectedAction).includes('delegating_principal'), false);
});

test('v2 identity changes alter acceptance pins but never the material-action CAID', () => {
  const first = makeV2Fixture();
  const changed = {
    logical_agent_id: 'wimse://payments.example/agents/release-agent-v2',
    oauth_client_id: 'client:release-agent-runtime-v2',
  };
  const second = makeV2Fixture({
    principalBindingOverrides: changed,
    principalPinsOverrides: changed,
  });
  const results = [first, second].map((fixture) => {
    const native = verifyFixture(fixture);
    assert.equal(native.acceptance, 'ACCEPTED', native.reasons.join('; '));
    return fixture.adapter.mapAction({
      ...fixture.input,
      profile: fixture.profile,
      native,
    });
  });
  assert.equal(results[0].mapping, 'MATCH');
  assert.equal(results[1].mapping, 'MATCH');
  assert.equal(results[0].caid, results[1].caid);
  assert.equal(results[0].action_digest, results[1].action_digest);
});

test('v2 returns INDETERMINATE when a required relationship is absent or malformed', () => {
  const missing = makeV2Fixture({ includePrincipalBinding: false });
  const malformed = makeV2Fixture({ principalBindingDelete: ['oauth_sub_semantics'] });
  for (const fixture of [missing, malformed]) {
    const native = verifyFixture(fixture);
    assert.equal(native.native_verification, 'VERIFIED', native.reasons.join('; '));
    assert.equal(native.acceptance, 'INDETERMINATE');
    assert.match(native.reasons.join(';'), /principal_binding_(missing|malformed)/);
  }
});

test('v2 rejects same logical agent with a substituted live workload instance', () => {
  const fixture = makeV2Fixture({
    principalBindingOverrides: {
      workload_instance_id: 'wimse://payments.example/workloads/release-agent-2',
    },
  });
  const native = verifyFixture(fixture);
  assert.equal(native.native_verification, 'VERIFIED');
  assert.equal(native.acceptance, 'REJECTED');
  assert.ok(native.reasons.includes('wimse-oauth-principal:workload_instance_mismatch'));
});

test('v2 rejects the same OAuth sub under a substituted client or changed grant semantics', () => {
  const client = makeV2Fixture({
    principalBindingOverrides: { oauth_client_id: 'client:attacker-runtime' },
  });
  const grant = makeV2Fixture({
    principalBindingOverrides: { oauth_grant_type: 'client_credentials' },
  });
  for (const [fixture, reason] of [
    [client, 'wimse-oauth-principal:oauth_client_mismatch'],
    [grant, 'wimse-oauth-principal:oauth_grant_semantics_mismatch'],
  ] as const) {
    const native = verifyFixture(fixture);
    assert.equal(native.native_verification, 'VERIFIED');
    assert.equal(native.acceptance, 'REJECTED');
    assert.ok(native.reasons.includes(reason));
  }
});

test('v2 rejects confirmation-key rotation that is not reflected in the pinned instance binding', () => {
  const fixture = makeV2Fixture({
    principalBindingOverrides: {
      workload_confirmation_jkt: 'A'.repeat(43),
    },
  });
  const native = verifyFixture(fixture);
  assert.equal(native.native_verification, 'VERIFIED');
  assert.equal(native.acceptance, 'REJECTED');
  assert.ok(native.reasons.includes('wimse-oauth-principal:workload_confirmation_key_mismatch'));
});

test('v2 rejects tool and resource-server substitution independently', () => {
  const tool = makeV2Fixture({
    principalBindingOverrides: { tool_id: 'payment.refund' },
  });
  const executor = makeV2Fixture({
    principalBindingOverrides: { executor_id: 'executor:attacker' },
  });
  for (const [fixture, reason] of [
    [tool, 'wimse-oauth-principal:tool_mismatch'],
    [executor, 'wimse-oauth-principal:executor_mismatch'],
  ] as const) {
    const native = verifyFixture(fixture);
    assert.equal(native.native_verification, 'VERIFIED');
    assert.equal(native.acceptance, 'REJECTED');
    assert.ok(native.reasons.includes(reason));
  }
});

test('v2 never infers human from OAuth sub and enforces the declared subject semantics', () => {
  const fixture = makeV2Fixture({
    principalBindingOverrides: { oauth_sub_semantics: 'oauth-client' },
  });
  const native = verifyFixture(fixture);
  assert.equal(native.native_verification, 'VERIFIED');
  assert.equal(native.acceptance, 'REJECTED');
  assert.ok(native.reasons.includes('wimse-oauth-principal:oauth_sub_semantics_mismatch'));
  assert.equal(native.evidence_role, 'delegated-workload');
  assert.equal(native.subject.kind, 'workload');
});

test('v2 mapper re-verifies principal acceptance instead of trusting a forged native result', () => {
  const fixture = makeV2Fixture({
    principalBindingOverrides: { oauth_client_id: 'client:attacker-runtime' },
  });
  const rejected = verifyFixture(fixture);
  assert.equal(rejected.acceptance, 'REJECTED');
  const forged = { ...rejected, acceptance: 'ACCEPTED' as const, reasons: [] };
  const mapped = fixture.adapter.mapAction({
    ...fixture.input,
    profile: fixture.profile,
    native: forged,
  });
  assert.equal(mapped.mapping, 'INDETERMINATE');
  assert.equal(mapped.caid, null);
  assert.ok(mapped.reasons.includes('native_acceptance_required'));
});

test('v2 treats discovered authorization-server metadata as input, not trust', () => {
  const fixture = makeV2Fixture();
  const discoveredRoots = structuredClone(fixture.trustRoots);
  discoveredRoots[1].issuer = 'https://discovered-as.example';
  const native = fixture.adapter.verifyNative({
    ...fixture.input,
    trust_roots: discoveredRoots,
  });
  assert.equal(native.native_verification, 'FAILED');
  assert.equal(native.acceptance, 'INDETERMINATE');
  assert.ok(native.reasons.includes('wimse-oauth-principal:constructor_pin_mismatch'));
});

test('checked-in vector enumerates the positive and required hostile classes', () => {
  const vectorPath = new URL('../../conformance/vectors/wimse-oauth-spt-aeb.v1.json', import.meta.url);
  const vector = JSON.parse(fs.readFileSync(vectorPath, 'utf8')) as Obj;
  const ids = new Set((vector.vectors as Obj[]).map((entry) => entry.id));
  for (const id of [
    'accept_real_ed25519_native_bundle',
    'reject_malformed_compact_jws',
    'reject_unexpected_algorithm',
    'reject_wrong_constructor_key',
    'reject_wrong_audience',
    'reject_wrong_workload_subject',
    'reject_expired_or_stale_token',
    'reject_tth_mismatch',
    'reject_spt_intent_mismatch',
    'indeterminate_missing_exact_action',
    'reject_native_replay_across_aeb_wrappers',
    'reject_human_role_substitution',
  ]) {
    assert.ok(ids.has(id), `missing vector ${id}`);
  }
});

test('v2 checked-in vector covers every principal-confusion class', () => {
  const vectorPath = new URL(
    '../../conformance/vectors/wimse-oauth-principal-aeb.v2.json',
    import.meta.url,
  );
  const vector = JSON.parse(fs.readFileSync(vectorPath, 'utf8')) as Obj;
  const ids = new Set((vector.vectors as Obj[]).map((entry) => entry.id));
  for (const id of [
    'accept_separated_principals',
    'indeterminate_missing_principal_relationship',
    'reject_same_agent_different_instance',
    'reject_same_sub_different_client',
    'reject_changed_grant_semantics',
    'reject_unpinned_key_rotation',
    'reject_discovered_unpinned_authorization_server',
    'reject_tool_substitution',
    'reject_resource_server_substitution',
  ]) {
    assert.ok(ids.has(id), `missing v2 vector ${id}`);
  }
});
