// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';

import {
  OAUTH_TRANSACTION_TOKEN_REPLAY_NAMESPACE,
  OAUTH_TRANSACTION_TOKENS_REVISION,
  SPT_TRANSACTION_TOKENS_REVISION,
  WIMSE_HTTP_SIGNATURE_REVISION,
  WIMSE_OAUTH_SPT_AEB_ADAPTER_ID,
  WIMSE_OAUTH_SPT_AEB_ADAPTER_VERSION,
  WIMSE_OAUTH_SPT_AEB_CONFIG_VERSION,
  WIMSE_OAUTH_SPT_CAID_MAPPER_ID,
  WIMSE_OAUTH_SPT_CAID_MAPPING_VERSION,
  WIMSE_OAUTH_SPT_TRUST_ROOT_VERSION,
  WIMSE_WORKLOAD_CREDS_REVISION,
  WIMSE_WPT_REVISION,
  createWimseOAuthSptAebAdapter,
  createWimseOAuthSptActionDefinition,
  deriveOAuthTransactionTokenReplayUnit,
  verifyWimseWpt02TokenBindingClaims,
} from '../../../packages/verify/aeb-wimse-oauth-adapter.js';
import { canonicalizeStrictJson } from '../../../packages/verify/dist/strict-json.js';

export const PROFILE = 'WIMSE-WPT02-OAUTH-TXN-AEB-v0.1';
export const REPORT_VERSION = 'WIMSE-WPT02-OAUTH-TXN-AEB-REPORT-v0.1';
export const SOURCE_LOCK = JSON.parse(readFileSync(new URL('./source-lock.json', import.meta.url), 'utf8'));
export const VECTORS = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'));
export const OAUTH_FIXTURE = JSON.parse(readFileSync(
  new URL('../oauth-txn-challenge-aeb-v0.1/native-fixture.json', import.meta.url),
  'utf8',
));

export const EXACT_NONCLAIMS = Object.freeze([
  'wpt_does_not_authorize',
  'wpt_does_not_establish_local_admission',
  'wpt_does_not_prove_provider_entry_execution_or_effect',
  'wpt_does_not_validate_oauth_transaction_challenge_semantics',
  'candidate_other_header_does_not_satisfy_oauth_bearer_presentation',
  'exact_wpt02_and_oauth_txn_challenge_http_presentation_are_not_directly_composable',
  'oauth_access_token_does_not_prove_named_human_identity',
  'http_message_signature_does_not_make_wpt_authorizing',
  'wimse_response_signature_negotiation_not_supported',
  'txn_token_rctx_not_mapped',
  'strict_application_subset_not_general_txn_tokens_11_or_wimse_06_conformance',
  'artifact_header_object_does_not_prove_raw_wire_singleton_cardinality',
  'target_uri_projection_does_not_prove_raw_wire_request_target_bytes',
  'adapter_does_not_cache_http_signature_nonce_or_wpt_jti',
  'adapter_emits_replay_identity_without_reserving_it',
  'test_harness_is_not_independent_implementation_or_production_mediation',
  'internet_draft_is_not_ietf_adoption_or_endorsement',
]);

const NOW = VECTORS.evaluated_at;
const NOW_SECONDS = Math.floor(Date.parse(NOW) / 1000);
const WORKLOAD_SUBJECT = 'wimse://payments.example/workloads/payment-agent';
const WIMSE_AUDIENCE = 'https://payments.example/execute';
const OAUTH_AUDIENCE = 'payments.example';
const OAUTH_SUBJECT = 'principal:customer-42';
const OAUTH_SCOPE = 'payment.initiate';
const ACTION_TYPE = 'payment.initiate.1';
const TXN = '97053963-771d-49cc-a4e3-20aad399c312';
const OAUTH_ACCESS_HEADER = 'oauth-transaction-access-token';
const OAUTH_CHALLENGE_HEADER = 'oauth-transaction-challenge';
const UNDERSTOOD_OTHER_TOKEN_HEADERS = Object.freeze([
  OAUTH_ACCESS_HEADER,
  OAUTH_CHALLENGE_HEADER,
]);

function deterministicEd25519(label) {
  // Public conformance-only material. It is not a deployment credential.
  const seed = crypto.createHash('sha256').update(`emilia-conformance:${label}`, 'utf8').digest();
  const prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([prefix, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  return { privateKey, publicKey: crypto.createPublicKey(privateKey) };
}

function spki(key) {
  return key.export({ type: 'spki', format: 'der' }).toString('base64url');
}

function compactJws(header, claims, privateKey) {
  const protectedHeader = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
  const payload = Buffer.from(JSON.stringify(claims), 'utf8').toString('base64url');
  const signingInput = `${protectedHeader}.${payload}`;
  const signature = crypto.sign(null, Buffer.from(signingInput, 'ascii'), privateKey).toString('base64url');
  return `${signingInput}.${signature}`;
}

function decodeClaims(token) {
  const payload = token.split('.')[1];
  assert.ok(payload);
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
}

function sha256Base64url(value) {
  return crypto.createHash('sha256').update(Buffer.from(value, 'ascii')).digest('base64url');
}

function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function digestAeb(value) {
  return `sha256:${sha256Hex(Buffer.from(canonicalizeStrictJson(value), 'utf8'))}`;
}

class InMemoryAebConsumptionStore {
  constructor() {
    this.entries = new Set();
    this.replayOwners = new Map();
  }

  reserve(operationId, replayUnits) {
    if (this.entries.has(operationId)
        || replayUnits.some((replayUnit) => this.replayOwners.has(replayUnit))) return false;
    this.entries.add(operationId);
    for (const replayUnit of replayUnits) this.replayOwners.set(replayUnit, operationId);
    return true;
  }
}

function contentDigest(body) {
  return `sha-256=:${crypto.createHash('sha256').update(Buffer.from(body, 'utf8')).digest('base64')}:`;
}

function signatureBase(components, signatureParams, method, requestTarget, headers) {
  const normalized = new Map(
    Object.entries(headers).map(([name, value]) => [name.toLowerCase(), String(value).trim()]),
  );
  const lines = components.map((component) => {
    const value = component === '@method'
      ? method
      : component === '@request-target'
        ? requestTarget
        : normalized.get(component);
    assert.notEqual(value, undefined, `missing signed component: ${component}`);
    return `${JSON.stringify(component)}: ${value}`;
  });
  lines.push(`"@signature-params": ${signatureParams}`);
  return lines.join('\n');
}

function mappingProfile() {
  return {
    version: WIMSE_OAUTH_SPT_CAID_MAPPING_VERSION,
    definition: createWimseOAuthSptActionDefinition(ACTION_TYPE),
    registry_entry_ref: 'mapping:wimse-wpt02-oauth-txn-payment',
    mapper_id: WIMSE_OAUTH_SPT_CAID_MAPPER_ID,
    resolver: {
      id: WIMSE_OAUTH_SPT_CAID_MAPPER_ID,
      version: '2',
      implementation_digest: digestAeb({
        implementation: WIMSE_OAUTH_SPT_CAID_MAPPER_ID,
        version: '2',
      }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [
        'wpt.jti',
        'wpt.tth',
        'wpt.oth',
        'oauth_transaction_challenge.jwt_bytes',
        'oauth_access_token.jwt_bytes',
      ],
    },
    profile_digest: digestAeb(null),
  };
}

function buildFixture(mutation = 'NONE') {
  const witIssuer = deterministicEd25519('wpt02-wit-issuer');
  const txnIssuer = deterministicEd25519('wpt02-txn-issuer');
  const sptIssuer = deterministicEd25519('wpt02-spt-unused-issuer');
  const holder = deterministicEd25519('wpt02-workload-holder');
  const holderJwk = holder.publicKey.export({ format: 'jwk' });
  const holderKeyId = 'wpt02-holder-static-1';
  const holderKeyPin = `holder:${holderJwk.x}`;
  const config = {
    '@version': WIMSE_OAUTH_SPT_AEB_CONFIG_VERSION,
    evidence_role: 'delegated-workload',
    subject: {
      id: 'workload:payment-agent',
      kind: 'workload',
      native_id: WORKLOAD_SUBJECT,
    },
    trust_domain: 'payments.example',
    wimse_audience: WIMSE_AUDIENCE,
    oauth_audience: OAUTH_AUDIENCE,
    oauth_subject: OAUTH_SUBJECT,
    oauth_scope: OAUTH_SCOPE,
    spt_audience: 'https://payments.example/spt-unused',
    spt_subject: WORKLOAD_SUBJECT,
    spt_holder_key: holderKeyPin,
    other_token_headers: [...UNDERSTOOD_OTHER_TOKEN_HEADERS],
    action_type: ACTION_TYPE,
    clock_skew_seconds: 2,
    max_age_seconds: {
      wit: 3600,
      wpt: 300,
      oauth_txn: 600,
      spt_txn: 180,
      http_signature: 120,
      status: 120,
    },
  };
  const trustRoots = [
    {
      '@version': WIMSE_OAUTH_SPT_TRUST_ROOT_VERSION,
      use: 'wit-issuer',
      issuer: 'https://identity.payments.example',
      key_id: 'wpt02-wit-issuer-static-1',
      algorithm: 'EdDSA',
      public_key: spki(witIssuer.publicKey),
    },
    {
      '@version': WIMSE_OAUTH_SPT_TRUST_ROOT_VERSION,
      use: 'oauth-transaction-token-issuer',
      issuer: 'https://tts.payments.example',
      key_id: 'wpt02-txn-issuer-static-1',
      algorithm: 'EdDSA',
      public_key: spki(txnIssuer.publicKey),
    },
    {
      '@version': WIMSE_OAUTH_SPT_TRUST_ROOT_VERSION,
      use: 'spt-transaction-token-issuer',
      issuer: 'https://spt.payments.example',
      key_id: 'wpt02-spt-issuer-static-1',
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
  const wit = compactJws({
    alg: 'EdDSA', typ: 'wit+jwt', kid: 'wpt02-wit-issuer-static-1',
  }, {
    iss: 'https://identity.payments.example',
    sub: WORKLOAD_SUBJECT,
    iat: NOW_SECONDS - 30,
    nbf: NOW_SECONDS - 30,
    exp: NOW_SECONDS + 300,
    jti: 'wpt02-wit-static-1',
    cnf: {
      jwk: {
        kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA', kid: holderKeyId, x: holderJwk.x,
      },
    },
  }, witIssuer.privateKey);

  const transactionContext = {
    txn: TXN,
    oauth_transaction_challenge_sha256: OAUTH_FIXTURE.sha256.challenge_jwt,
    authorization_details_sha256: sha256Hex(JSON.stringify(decodeClaims(
      OAUTH_FIXTURE.challenge_jwt,
    ).authorization_details)),
  };
  const txnClaims = {
    iss: 'https://tts.payments.example',
    sub: OAUTH_SUBJECT,
    aud: OAUTH_AUDIENCE,
    iat: NOW_SECONDS - 10,
    nbf: NOW_SECONDS - 10,
    exp: NOW_SECONDS + 120,
    txn: TXN,
    scope: OAUTH_SCOPE,
    req_wl: WORKLOAD_SUBJECT,
    tctx: transactionContext,
  };
  if (mutation === 'TXN_RCTX_PRESENT') {
    txnClaims.rctx = {
      request_ip: '192.0.2.10',
      risk_tier: 'elevated',
    };
  }
  const txnToken = compactJws({
    alg: 'EdDSA', typ: 'txntoken+jwt', kid: 'wpt02-txn-issuer-static-1',
  }, txnClaims, txnIssuer.privateKey);

  const presentedAccessToken = mutation === 'SUBSTITUTE_OAUTH_ACCESS_TOKEN'
    ? OAUTH_FIXTURE.twin_access_token_jwt
    : OAUTH_FIXTURE.access_token_jwt;
  let oth = {
    [OAUTH_ACCESS_HEADER]: sha256Base64url(OAUTH_FIXTURE.access_token_jwt),
    [OAUTH_CHALLENGE_HEADER]: sha256Base64url(OAUTH_FIXTURE.challenge_jwt),
  };
  if (mutation === 'REVERSE_OTH_MEMBER_ORDER') {
    oth = {
      [OAUTH_CHALLENGE_HEADER]: sha256Base64url(OAUTH_FIXTURE.challenge_jwt),
      [OAUTH_ACCESS_HEADER]: sha256Base64url(OAUTH_FIXTURE.access_token_jwt),
    };
  }
  if (mutation === 'OMIT_OTH_CHALLENGE') delete oth[OAUTH_CHALLENGE_HEADER];
  if (mutation === 'MISMATCH_OTH_CHALLENGE') {
    oth[OAUTH_CHALLENGE_HEADER] = sha256Base64url('substituted.challenge.token');
  }
  if (mutation === 'ADD_UNKNOWN_OTH_ENTRY') {
    oth['unknown-authorization-token'] = sha256Base64url('unknown.token');
  }
  const wptClaims = {
    aud: WIMSE_AUDIENCE,
    exp: NOW_SECONDS + 90,
    jti: 'wpt02-proof-static-1',
    wth: sha256Base64url(wit),
    oth,
  };
  if (mutation !== 'OMIT_TTH') {
    wptClaims.tth = mutation === 'MISMATCH_TTH'
      ? sha256Base64url('different.txn.token')
      : sha256Base64url(txnToken);
  }
  const wpt = compactJws({ alg: 'EdDSA', typ: 'wpt+jwt' }, wptClaims, holder.privateKey);

  const method = 'POST';
  const targetUri = mutation === 'SUBSTITUTE_TARGET_AUTHORITY'
    ? 'https://attacker.example/execute?mode=atomic'
    : mutation === 'SUBSTITUTE_TARGET_PATH'
      ? 'https://payments.example/admin?mode=atomic'
      : mutation === 'NONCANONICAL_TARGET_URI'
        ? 'https://payments.example/a/../execute?mode=atomic'
      : `${WIMSE_AUDIENCE}?mode=atomic`;
  const parsedTarget = new URL(targetUri);
  const requestTarget = `${parsedTarget.pathname}${parsedTarget.search}`;
  const body = '{"action":"payment.initiate","transaction":"97053963-771d-49cc-a4e3-20aad399c312"}';
  const components = [
    '@method',
    '@request-target',
    'content-type',
    'content-digest',
    'txn-token',
    'workload-identity-token',
    'authorization',
    OAUTH_ACCESS_HEADER,
    OAUTH_CHALLENGE_HEADER,
  ];
  const signatureParams = `(${components.map((component) => JSON.stringify(component)).join(' ')})`
    + `;created=${NOW_SECONDS - 3};expires=${NOW_SECONDS + 57}`
    + ';nonce="wpt02-http-signature-static-1"'
    + ';tag="wimse-workload-to-workload"'
    + `;wimse-aud="${WIMSE_AUDIENCE}"`
    + (mutation === 'REQUEST_SIGNED_RESPONSE' ? ';wimse-sign-response' : '');
  const headers = {
    'Content-Type': 'application/json',
    'Content-Digest': contentDigest(body),
    'Txn-Token': txnToken,
    'Workload-Identity-Token': wit,
    Authorization: `WPT ${wpt}`,
    'OAuth-Transaction-Access-Token': presentedAccessToken,
    'OAuth-Transaction-Challenge': OAUTH_FIXTURE.challenge_jwt,
    'Signature-Input': `wimse=${signatureParams}`,
  };
  if (mutation === 'DUPLICATE_CASE_VARIANT_HEADER') headers['txn-token'] = txnToken;
  const signature = crypto.sign(
    null,
    Buffer.from(signatureBase(components, signatureParams, method, requestTarget, headers), 'utf8'),
    holder.privateKey,
  ).toString('base64');
  headers.Signature = `wimse=:${signature}:`;
  const artifact = {
    wit,
    wpt,
    txn_token: txnToken,
    request: { method, target_uri: targetUri, headers, body },
  };
  const expectedAction = {
    action_type: ACTION_TYPE,
    http: {
      method,
      request_target: requestTarget,
      content_digest: headers['Content-Digest'],
      wimse_audience: WIMSE_AUDIENCE,
    },
    transaction: { scope: OAUTH_SCOPE, context: transactionContext },
  };
  const input = {
    artifact,
    artifact_ref: `urn:emilia:wpt02-oauth-txn:${mutation.toLowerCase()}`,
    status: {
      checked_at: '2026-08-31T19:00:00Z',
      expires_at: '2026-08-31T19:02:00Z',
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
    adapter: createWimseOAuthSptAebAdapter({ config, trust_roots: trustRoots }),
    input,
    profile: mappingProfile(),
    claims: decodeClaims(wpt),
  };
}

function runFullCase(vector) {
  const fixture = buildFixture(vector.mutation);
  const binding = verifyWimseWpt02TokenBindingClaims(
    fixture.claims,
    fixture.input.artifact.request.headers,
    UNDERSTOOD_OTHER_TOKEN_HEADERS,
  );
  const native = fixture.adapter.verifyNative(fixture.input);
  const mapping = native.native_verification === 'VERIFIED' && native.acceptance === 'ACCEPTED'
    ? fixture.adapter.mapAction({ ...fixture.input, profile: fixture.profile, native })
    : null;
  const observed = {
    token_binding: binding,
    native: {
      verification: native.native_verification,
      acceptance: native.acceptance,
      evidence_role: native.evidence_role,
      subject_kind: native.subject.kind,
      reasons: native.reasons,
    },
    mapping: mapping?.mapping ?? 'NOT_EVALUATED',
    native_oauth_transaction_challenge_presentation: 'NOT_COMPLIANT_CUSTOM_HEADER_CANDIDATE_ONLY',
    direct_same_request_composition: 'UNAVAILABLE_AUTHORIZATION_SCHEME_COLLISION',
    wpt_authorization: 'NOT_EVALUATED',
    local_admission: 'NOT_EVALUATED',
    provider_entry: 'NOT_EVALUATED',
    effect: 'NOT_EVALUATED',
  };
  let passed = false;
  if (vector.expected === 'VERIFIED') {
    passed = binding.verification === 'VERIFIED'
      && native.native_verification === 'VERIFIED'
      && native.acceptance === 'ACCEPTED'
      && native.evidence_role === 'delegated-workload'
      && mapping?.mapping === 'MATCH';
  } else if (vector.expected === 'NATIVE_FAILED') {
    passed = binding.verification === 'VERIFIED'
      && native.native_verification === 'FAILED'
      && native.acceptance === 'REJECTED';
  } else {
    passed = binding.verification === 'FAILED'
      && native.native_verification === 'FAILED'
      && native.acceptance === 'REJECTED';
  }
  return { ...vector, passed, observed };
}

function runReplayRevisionMigrationCase(vector) {
  const fixture = buildFixture('NONE');
  const native = fixture.adapter.verifyNative(fixture.input);
  const current = {
    source_revision: OAUTH_TRANSACTION_TOKENS_REVISION,
    replay_unit: deriveOAuthTransactionTokenReplayUnit(OAUTH_AUDIENCE, TXN),
  };
  const nextReview = {
    source_revision: 'draft-ietf-oauth-transaction-tokens-next-review-label',
    replay_unit: deriveOAuthTransactionTokenReplayUnit(OAUTH_AUDIENCE, TXN),
  };
  const store = new InMemoryAebConsumptionStore();
  const firstReservation = store.reserve('aeb:operation:current-revision', [current.replay_unit]);
  const secondReservation = store.reserve('aeb:operation:next-revision', [nextReview.replay_unit]);
  return {
    ...vector,
    passed: vector.expected === 'REFUSED_SECOND_SPEND'
      && native.native_verification === 'VERIFIED'
      && native.replay_unit === current.replay_unit
      && current.source_revision !== nextReview.source_revision
      && current.replay_unit === nextReview.replay_unit
      && firstReservation
      && !secondReservation,
    observed: {
      native: {
        verification: native.native_verification,
        acceptance: native.acceptance,
        replay_unit: native.replay_unit,
      },
      replay_namespace: OAUTH_TRANSACTION_TOKEN_REPLAY_NAMESPACE,
      identity_fields: ['aud_trust_domain', 'txn'],
      excluded_identity_fields: ['draft_revision', 'iss'],
      current,
      next_review: nextReview,
      first_reservation: firstReservation,
      second_reservation: secondReservation,
      second_decision: secondReservation ? 'UNEXPECTEDLY_RESERVED' : 'NATIVE_EVIDENCE_REPLAY',
      local_admission: 'NOT_EVALUATED',
      provider_entry: 'NOT_EVALUATED',
      effect: 'NOT_EVALUATED',
    },
  };
}

function runAuthorizationCollisionCase(vector) {
  const wptAuthorization = 'Authorization: WPT <wpt-jwt>';
  const oauthAuthorization = 'Authorization: Bearer <transaction-access-token>';
  return {
    ...vector,
    passed: vector.expected === 'REFUSED',
    observed: {
      wpt02_requirement: wptAuthorization,
      oauth_transaction_challenge_00_requirement: oauthAuthorization,
      one_authorization_field: true,
      direct_same_request_composition: 'REFUSED_AUTHORIZATION_SCHEME_COLLISION',
      candidate_other_header_status: 'NONSTANDARD_AND_NOT_NATIVE_OAUTH_PRESENTATION',
      wpt_authorization: 'NOT_EVALUATED',
      local_admission: 'NOT_EVALUATED',
      provider_entry: 'NOT_EVALUATED',
      effect: 'NOT_EVALUATED',
    },
  };
}

function runClaimOnlyCase(vector) {
  const headers = {
    'OAuth-Transaction-Access-Token': OAUTH_FIXTURE.access_token_jwt,
    'OAuth-Transaction-Challenge': OAUTH_FIXTURE.challenge_jwt,
  };
  const claims = {
    oth: {
      [OAUTH_ACCESS_HEADER]: sha256Base64url(OAUTH_FIXTURE.access_token_jwt),
      [OAUTH_CHALLENGE_HEADER]: sha256Base64url(OAUTH_FIXTURE.challenge_jwt),
    },
  };
  if (vector.mutation === 'CLAIM_ONLY_NO_TXN_WITH_TTH') {
    claims.tth = sha256Base64url('orphan.txn.token');
  }
  const binding = verifyWimseWpt02TokenBindingClaims(
    claims,
    headers,
    UNDERSTOOD_OTHER_TOKEN_HEADERS,
  );
  return {
    ...vector,
    passed: binding.verification === vector.expected,
    observed: {
      token_binding: binding,
      native: 'NOT_EVALUATED_CLAIM_LEVEL_RULE_ONLY',
      wpt_authorization: 'NOT_EVALUATED',
      local_admission: 'NOT_EVALUATED',
      provider_entry: 'NOT_EVALUATED',
      effect: 'NOT_EVALUATED',
    },
  };
}

export function verifySourceLock() {
  const failures = [];
  const expectedUpstream = new Map([
    [WIMSE_WPT_REVISION, [43002, '6a629ffd6bcc0e75ae1deb3e2ddd543ef09d0da6f108e85d085b09d2b9b42f82']],
    [WIMSE_HTTP_SIGNATURE_REVISION, [45388, 'e44e2bc1340854e1c3aab3887bba4e9d89f4b9edb54865c43bfbd9c0e7d40f44']],
    [WIMSE_WORKLOAD_CREDS_REVISION, [58413, 'b111e4e85a7f3bc5c844560db87276c184a04db28ffeaccb057c13eb034dbed5']],
    [OAUTH_TRANSACTION_TOKENS_REVISION, [80218, '937eeaac88c19eb00c7a3581f3de850c79c32aa7e4484ded329c15c123718364']],
    [SPT_TRANSACTION_TOKENS_REVISION, [32752, '5ebba0db429816a7fe887128f08d51c3840209bf17de74d66581ce935966e195']],
    ['draft-rosomakho-oauth-txn-challenge-00', [70435, 'a50c1fee4ce4ae486aa6e6739e9927586dc5c14a209434f44f76200354a8cead']],
  ]);
  if (!Array.isArray(SOURCE_LOCK.upstream)
      || SOURCE_LOCK.upstream.length !== expectedUpstream.size) {
    failures.push('upstream_source_set_mismatch');
  }
  for (const [id, [bytes, sha256]] of expectedUpstream) {
    const source = SOURCE_LOCK.upstream?.find((entry) => entry.id === id);
    if (!source
        || source.url !== `https://www.ietf.org/archive/id/${id}.txt`
        || source.bytes !== bytes
        || source.sha256 !== sha256) failures.push(`upstream_source_lock_mismatch:${id}`);
  }

  const expectedRuntimeClosure = [
    'conformance/composition/wimse-wpt02-oauth-txn-aeb-v0.1/run.mjs',
    'packages/verify/aeb-wimse-oauth-adapter.js',
    'packages/verify/dist/aeb-wimse-oauth-adapter.js',
    'packages/verify/dist/strict-json.js',
    'packages/verify/vendor/caid.mjs',
  ];
  if (JSON.stringify(SOURCE_LOCK.local_runtime_closure) !== JSON.stringify(expectedRuntimeClosure)) {
    failures.push('local_runtime_closure_mismatch');
  }
  const expectedCompatibilitySurfaces = [
    'packages/verify/aeb-adapter-contract.js',
    'packages/verify/dist/aeb-adapter-contract.js',
  ];
  if (JSON.stringify(SOURCE_LOCK.local_compatibility_surfaces)
      !== JSON.stringify(expectedCompatibilitySurfaces)) {
    failures.push('local_compatibility_surface_set_mismatch');
  }

  const expectedLocalPaths = new Set([
    'packages/verify/src/aeb-wimse-oauth-adapter.ts',
    'packages/verify/aeb-wimse-oauth-adapter.js',
    'packages/verify/dist/aeb-wimse-oauth-adapter.js',
    'packages/verify/aeb-adapter-contract.js',
    'packages/verify/dist/aeb-adapter-contract.js',
    'packages/verify/dist/strict-json.js',
    'packages/verify/vendor/caid.mjs',
    'conformance/composition/wimse-wpt02-oauth-txn-aeb-v0.1/run.mjs',
    'conformance/composition/wimse-wpt02-oauth-txn-aeb-v0.1/vectors.json',
    'conformance/composition/oauth-txn-challenge-aeb-v0.1/native-fixture.json',
  ]);
  if (!Array.isArray(SOURCE_LOCK.local_artifacts)
      || SOURCE_LOCK.local_artifacts.length !== expectedLocalPaths.size) {
    failures.push('local_artifact_set_mismatch');
  }
  for (const artifact of SOURCE_LOCK.local_artifacts ?? []) {
    if (!expectedLocalPaths.delete(artifact.path)) {
      failures.push(`unexpected_local_artifact:${String(artifact.path)}`);
      continue;
    }
    const artifactBytes = readFileSync(new URL(`../../../${artifact.path}`, import.meta.url));
    if (artifactBytes.length !== artifact.bytes
        || sha256Hex(artifactBytes) !== artifact.sha256) {
      failures.push(`local_artifact_digest_mismatch:${artifact.path}`);
    }
  }
  for (const missing of expectedLocalPaths) failures.push(`missing_local_artifact:${missing}`);
  return { valid: failures.length === 0, failures };
}

export function runSuite() {
  const sourceLock = verifySourceLock();
  const cases = VECTORS.cases.map((vector) => (
    vector.mutation === 'EXACT_DRAFT_AUTHORIZATION_COLLISION'
      ? runAuthorizationCollisionCase(vector)
      : vector.mutation === 'REPLAY_REVISION_MIGRATION'
        ? runReplayRevisionMigrationCase(vector)
      : vector.mutation.startsWith('CLAIM_ONLY_')
      ? runClaimOnlyCase(vector)
      : runFullCase(vector)
  ));
  const passed = cases.filter((entry) => entry.passed).length;
  const core = {
    '@version': REPORT_VERSION,
    profile: PROFILE,
    evaluated_at: NOW,
    source_lock: sourceLock,
    implementation: {
      wpt_revision: WIMSE_WPT_REVISION,
      workload_credentials_revision: WIMSE_WORKLOAD_CREDS_REVISION,
      wimse_http_signature_revision: WIMSE_HTTP_SIGNATURE_REVISION,
      oauth_transaction_token_revision: OAUTH_TRANSACTION_TOKENS_REVISION,
      spt_transaction_token_revision: SPT_TRANSACTION_TOKENS_REVISION,
      adapter_id: WIMSE_OAUTH_SPT_AEB_ADAPTER_ID,
      adapter_version: WIMSE_OAUTH_SPT_AEB_ADAPTER_VERSION,
      deterministic_fixture: true,
      network_required: false,
      independent_implementation: false,
      production_mediation: false,
    },
    semantics: {
      tth: 'required exactly when a Txn-Token is present; hashes its ASCII token value',
      oth: 'exact understood lower-case header set; hashes each trimmed ASCII header field value; JSON member order is not semantic',
      wpt_role: 'proof of possession and request token binding only',
      oauth_transaction_challenge_http_composition: 'not directly available: WPT-02 and transaction-challenge -00 require mutually exclusive Authorization schemes',
      candidate_wrapper: 'oth can bind candidate custom-header bytes, but that is not native OAuth transaction-challenge presentation',
      wpt_audience: 'exact canonical HTTPS origin and path; query ignored; fragments, rewrites, and aliases refused',
      replay_identity: 'stable native namespace plus Txn-Token aud Trust Domain and txn; draft revision and optional iss excluded',
      wimse_http_signature_profile: 'draft -06 request verification only; optional signed-response negotiation is refused because this adapter cannot enforce the response',
      rctx: 'refused when present because the closed action mapping does not classify or project downstream request context',
      application_subset: 'strict EMILIA request subset, not general Txn-Tokens-11 or WIMSE HTTP Message Signatures -06 conformance',
      request_target: 'canonical HTTPS target_uri projected to origin-form path and query; not raw-wire target-byte evidence',
      header_observation: 'closed object/map observation with case-folded duplicates refused; not proof of raw-wire singleton cardinality',
      replay_enforcement: 'adapter emits a stable replay identity only; downstream AEB consumption storage must reserve it and separately cache nonce or WPT jti when policy requires',
    },
    claim_scope: { exclusions: [...EXACT_NONCLAIMS] },
    summary: { total: cases.length, passed, failed: cases.length - passed },
    cases,
  };
  return { ...core, report_digest: digestAeb(core) };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const report = runSuite();
  if (process.argv.includes('--check')) {
    if (!report.source_lock.valid || report.summary.failed !== 0) process.exitCode = 1;
  } else {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  }
}
