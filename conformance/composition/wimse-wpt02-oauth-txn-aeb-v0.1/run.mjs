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
  WIMSE_OAUTH_SPT_TRUST_ROOT_VERSION,
  WIMSE_WORKLOAD_CREDS_REVISION,
  WIMSE_WORKLOAD_IDENTIFIER_REVISION,
  WIMSE_WPT_REVISION,
  createWimseOAuthSptAebAdapter,
  createWimseOAuthSptMappingProfile,
  deriveOAuthTransactionTokenReplayUnit,
  verifyWimseWpt02TokenBindingClaims,
} from '../../../packages/verify/aeb-wimse-oauth-adapter.js';
import { canonicalizeStrictJson } from '../../../packages/verify/dist/strict-json.js';

/** @typedef {import('../../../packages/verify/dist/aeb-wimse-oauth-adapter.js').WimseOAuthSptAdapterConfig} WimseOAuthSptAdapterConfig */
/** @typedef {import('../../../packages/verify/dist/aeb-wimse-oauth-adapter.js').WimseOAuthSptTrustRoot} WimseOAuthSptTrustRoot */

export const PROFILE = 'WIMSE-WPT02-OAUTH-TXN-AEB-v0.1';
export const REPORT_VERSION = 'WIMSE-WPT02-OAUTH-TXN-AEB-REPORT-v0.1';
export const SOURCE_LOCK_VERSION = 'WIMSE-WPT02-OAUTH-TXN-AEB-SOURCE-LOCK-v0.1';
export const REPORT_REFERENCE_VERSION = 'WIMSE-WPT02-OAUTH-TXN-AEB-REPORT-REFERENCE-v0.1';
const SOURCE_LOCK_BYTES = readFileSync(new URL('./source-lock.json', import.meta.url));
export const SOURCE_LOCK = JSON.parse(SOURCE_LOCK_BYTES.toString('utf8'));
export const SOURCE_LOCK_FILE_SHA256 = `sha256:${crypto.createHash('sha256').update(SOURCE_LOCK_BYTES).digest('hex')}`;
export const REPORT_REFERENCE = JSON.parse(readFileSync(
  new URL('./report.reference.json', import.meta.url),
  'utf8',
));
export const VECTORS = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'));
export const OAUTH_FIXTURE = JSON.parse(readFileSync(
  new URL('./oauth-txn-challenge-native-fixture.json', import.meta.url),
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
const RECEIVING_WORKLOAD = 'wimse://payments.example/workloads/payment-executor';
const SECOND_RECEIVING_WORKLOAD = 'wimse://payments.example/workloads/ledger-writer';
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

function exactObjectKeys(value, expected) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.keys(value).length === expected.size
    && Object.keys(value).every((key) => expected.has(key));
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
  return createWimseOAuthSptMappingProfile(ACTION_TYPE);
}

function buildFixture(mutation = 'NONE', options = {}) {
  const scenarioId = options.scenarioId ?? mutation.toLowerCase();
  const workloadSubject = options.workloadSubject ?? WORKLOAD_SUBJECT;
  const receivingWorkload = options.receivingWorkload ?? RECEIVING_WORKLOAD;
  const oauthRequestingWorkload = options.oauthRequestingWorkload ?? workloadSubject;
  const holderLabel = options.holderLabel ?? 'wpt02-workload-holder';
  const holderKeyId = options.holderKeyId ?? 'wpt02-holder-static-1';
  const witJti = options.witJti ?? `wpt02-wit-${scenarioId}`;
  const wptJti = options.wptJti ?? `wpt02-proof-${scenarioId}`;
  const signatureNonce = options.signatureNonce ?? `wpt02-http-signature-${scenarioId}`;
  const txnIssuerLabel = options.txnIssuerLabel ?? 'wpt02-txn-issuer';
  const txnIssuerUrl = options.txnIssuerUrl ?? 'https://tts.payments.example';
  const txnIssuerKeyId = options.txnIssuerKeyId ?? 'wpt02-txn-issuer-static-1';
  const witIssuer = deterministicEd25519('wpt02-wit-issuer');
  const txnIssuer = deterministicEd25519(txnIssuerLabel);
  const sptIssuer = deterministicEd25519('wpt02-spt-unused-issuer');
  const holder = deterministicEd25519(holderLabel);
  const holderJwk = holder.publicKey.export({ format: 'jwk' });
  const holderKeyPin = `holder:${holderJwk.x}`;
  /** @type {WimseOAuthSptAdapterConfig} */
  const config = {
    '@version': WIMSE_OAUTH_SPT_AEB_CONFIG_VERSION,
    evidence_role: 'delegated-workload',
    subject: {
      id: options.subjectId ?? 'workload:payment-agent',
      kind: 'workload',
      native_id: workloadSubject,
    },
    trust_domain: 'payments.example',
    receiving_workload: receivingWorkload,
    oauth_requesting_workload: oauthRequestingWorkload,
    wimse_audience: WIMSE_AUDIENCE,
    oauth_audience: OAUTH_AUDIENCE,
    oauth_subject: OAUTH_SUBJECT,
    oauth_scope: OAUTH_SCOPE,
    spt_audience: 'https://payments.example/spt-unused',
    spt_subject: workloadSubject,
    spt_holder_key: holderKeyPin,
    other_token_headers: options.otherTokenHeaders
      ?? [...UNDERSTOOD_OTHER_TOKEN_HEADERS],
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
  /** @type {WimseOAuthSptTrustRoot[]} */
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
      issuer: txnIssuerUrl,
      key_id: txnIssuerKeyId,
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
      subject: workloadSubject,
      key_id: holderKeyId,
      algorithm: 'EdDSA',
      public_key: spki(holder.publicKey),
    },
  ];
  const wit = compactJws({
    alg: 'EdDSA', typ: 'wit+jwt', kid: 'wpt02-wit-issuer-static-1',
  }, {
    iss: 'https://identity.payments.example',
    sub: workloadSubject,
    iat: NOW_SECONDS - 30,
    nbf: NOW_SECONDS - 30,
    exp: NOW_SECONDS + 300,
    jti: witJti,
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
  const txnTimes = options.txnTimes ?? {
    iat: NOW_SECONDS - 10,
    nbf: NOW_SECONDS - 10,
    exp: NOW_SECONDS + 120,
  };
  const txnClaims = {
    iss: txnIssuerUrl,
    sub: OAUTH_SUBJECT,
    aud: OAUTH_AUDIENCE,
    ...txnTimes,
    txn: TXN,
    scope: OAUTH_SCOPE,
    req_wl: oauthRequestingWorkload,
    tctx: transactionContext,
  };
  if (mutation === 'TXN_RCTX_PRESENT') {
    txnClaims.rctx = {
      request_ip: '192.0.2.10',
      risk_tier: 'elevated',
    };
  }
  const txnToken = compactJws({
    alg: 'EdDSA', typ: 'txntoken+jwt', kid: txnIssuerKeyId,
  }, txnClaims, txnIssuer.privateKey);

  const presentedAccessToken = mutation === 'SUBSTITUTE_OAUTH_ACCESS_TOKEN'
    ? OAUTH_FIXTURE.twin_access_token_jwt
    : OAUTH_FIXTURE.access_token_jwt;
  /** @type {Record<string, string>} */
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
    jti: wptJti,
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
    + `;nonce="${signatureNonce}"`
    + ';tag="wimse-workload-to-workload"'
    + `;wimse-aud="${WIMSE_AUDIENCE}"`
    + (mutation === 'REQUEST_SIGNED_RESPONSE' ? ';wimse-sign-response' : '');
  const headers = {
    'Content-Type': mutation === 'SUBSTITUTE_SIGNED_CONTENT_TYPE'
      ? 'application/cbor'
      : 'application/json',
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
  if (mutation === 'ADD_UNSIGNED_SEMANTIC_HEADER') {
    headers['X-HTTP-Method-Override'] = 'DELETE';
  }
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
      content_type: 'application/json',
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
    txn_claims: decodeClaims(txnToken),
    txn_token: txnToken,
    workload_subject: workloadSubject,
    receiving_workload: receivingWorkload,
    oauth_requesting_workload: oauthRequestingWorkload,
  };
}

function runFullCase(vector) {
  const fixture = buildFixture(vector.mutation, { scenarioId: vector.id });
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
  } else if (vector.expected === 'MAPPING_MISMATCH') {
    passed = binding.verification === 'VERIFIED'
      && native.native_verification === 'VERIFIED'
      && native.acceptance === 'ACCEPTED'
      && mapping?.mapping === 'MISMATCH';
  } else {
    passed = binding.verification === 'FAILED'
      && native.native_verification === 'FAILED'
      && native.acceptance === 'REJECTED';
  }
  return { ...vector, passed, observed };
}

function runReplayRevisionMigrationCase(vector) {
  const fixture = buildFixture('NONE', { scenarioId: `${vector.id}-current` });
  const migratedFixture = buildFixture('NONE', {
    scenarioId: `${vector.id}-migrated`,
    txnIssuerLabel: 'wpt02-txn-issuer-v2',
    txnIssuerUrl: 'https://tts-v2.payments.example',
    txnIssuerKeyId: 'wpt02-txn-issuer-v2-static-1',
    wptJti: 'wpt02-proof-migrated-1',
    signatureNonce: 'wpt02-http-signature-migrated-1',
  });
  const native = fixture.adapter.verifyNative(fixture.input);
  const migratedNative = migratedFixture.adapter.verifyNative(migratedFixture.input);
  const current = {
    source_revision: OAUTH_TRANSACTION_TOKENS_REVISION,
    issuer: fixture.txn_claims.iss,
    replay_unit: native.replay_unit,
  };
  const nextReview = {
    source_revision: 'draft-ietf-oauth-transaction-tokens-next-review-label',
    issuer: migratedFixture.txn_claims.iss,
    replay_unit: migratedNative.replay_unit,
  };
  const replayGolden = 'sha256:43a7d11c29783fb801d7f4b901a628c6c39382495762222fbf1c905d33833cf5';
  const derivedReplayGolden = deriveOAuthTransactionTokenReplayUnit(
    OAUTH_AUDIENCE,
    RECEIVING_WORKLOAD,
    TXN,
  );
  const store = new InMemoryAebConsumptionStore();
  const firstReservation = store.reserve('aeb:operation:current-revision', [current.replay_unit]);
  const secondReservation = store.reserve('aeb:operation:next-revision', [nextReview.replay_unit]);
  return {
    ...vector,
    passed: vector.expected === 'REFUSED_SECOND_SPEND'
      && native.native_verification === 'VERIFIED'
      && native.acceptance === 'ACCEPTED'
      && migratedNative.native_verification === 'VERIFIED'
      && migratedNative.acceptance === 'ACCEPTED'
      && fixture.txn_token !== migratedFixture.txn_token
      && current.issuer !== nextReview.issuer
      && current.source_revision !== nextReview.source_revision
      && current.replay_unit === nextReview.replay_unit
      && derivedReplayGolden === replayGolden
      && current.replay_unit === replayGolden
      && firstReservation
      && !secondReservation,
    observed: {
      native: {
        verification: native.native_verification,
        acceptance: native.acceptance,
        replay_unit: native.replay_unit,
      },
      replay_namespace: OAUTH_TRANSACTION_TOKEN_REPLAY_NAMESPACE,
      identity_fields: ['aud_trust_domain', 'receiving_workload', 'txn'],
      excluded_identity_fields: ['draft_revision', 'iss', 'token_bytes'],
      replay_golden: replayGolden,
      derived_replay_golden: derivedReplayGolden,
      distinct_valid_token_bytes: fixture.txn_token !== migratedFixture.txn_token,
      current,
      next_review: nextReview,
      migrated_native: {
        verification: migratedNative.native_verification,
        acceptance: migratedNative.acceptance,
        replay_unit: migratedNative.replay_unit,
      },
      first_reservation: firstReservation,
      second_reservation: secondReservation,
      second_decision: secondReservation ? 'UNEXPECTEDLY_RESERVED' : 'NATIVE_EVIDENCE_REPLAY',
      local_admission: 'NOT_EVALUATED',
      provider_entry: 'NOT_EVALUATED',
      effect: 'NOT_EVALUATED',
    },
  };
}

function runReplayReceiverScopeCase(vector) {
  const sameReceivingWorkload = vector.mutation === 'REPLAY_SAME_RECEIVING_WORKLOAD';
  const firstFixture = buildFixture('NONE', { scenarioId: `${vector.id}-first` });
  const secondFixture = sameReceivingWorkload
    ? buildFixture('NONE', {
      scenarioId: `${vector.id}-second`,
      witJti: 'wpt02-wit-repeat-1',
      wptJti: 'wpt02-proof-repeat-1',
      signatureNonce: 'wpt02-http-signature-repeat-1',
    })
    : buildFixture('NONE', {
      scenarioId: `${vector.id}-second`,
      subjectId: 'workload:payment-executor',
      workloadSubject: RECEIVING_WORKLOAD,
      receivingWorkload: SECOND_RECEIVING_WORKLOAD,
      oauthRequestingWorkload: WORKLOAD_SUBJECT,
      holderLabel: 'wpt02-payment-executor-holder',
      holderKeyId: 'wpt02-payment-executor-holder-static-1',
      witJti: 'wpt02-wit-hop2-1',
      wptJti: 'wpt02-proof-hop2-1',
      signatureNonce: 'wpt02-http-signature-hop2-1',
    });
  const firstNative = firstFixture.adapter.verifyNative(firstFixture.input);
  const secondNative = secondFixture.adapter.verifyNative(secondFixture.input);
  const firstReplayUnit = firstNative.replay_unit;
  const secondReplayUnit = secondNative.replay_unit;
  const store = new InMemoryAebConsumptionStore();
  const firstReservation = store.reserve('aeb:operation:first-receiver', [firstReplayUnit]);
  const secondReservation = store.reserve('aeb:operation:second-receiver', [secondReplayUnit]);
  const expectedSecondReservation = vector.expected === 'ALLOWED_SECOND_WORKLOAD_RESERVATION';
  return {
    ...vector,
    passed: firstNative.native_verification === 'VERIFIED'
      && firstNative.acceptance === 'ACCEPTED'
      && secondNative.native_verification === 'VERIFIED'
      && secondNative.acceptance === 'ACCEPTED'
      && firstFixture.txn_token === secondFixture.txn_token
      && secondFixture.txn_claims.req_wl === WORKLOAD_SUBJECT
      && secondFixture.oauth_requesting_workload === WORKLOAD_SUBJECT
      && (sameReceivingWorkload
        ? secondFixture.workload_subject === WORKLOAD_SUBJECT
        : secondFixture.workload_subject !== secondFixture.oauth_requesting_workload)
      && firstReservation
      && secondReservation === expectedSecondReservation
      && (sameReceivingWorkload
        ? firstReplayUnit === secondReplayUnit
        : firstReplayUnit !== secondReplayUnit),
    observed: {
      replay_namespace: OAUTH_TRANSACTION_TOKEN_REPLAY_NAMESPACE,
      identity_fields: ['aud_trust_domain', 'receiving_workload', 'txn'],
      trust_domain: OAUTH_AUDIENCE,
      txn: TXN,
      unchanged_txn_token_bytes: firstFixture.txn_token === secondFixture.txn_token,
      original_requesting_workload: secondFixture.oauth_requesting_workload,
      first_immediate_sender: firstFixture.workload_subject,
      second_immediate_sender: secondFixture.workload_subject,
      first_native: {
        verification: firstNative.native_verification,
        acceptance: firstNative.acceptance,
      },
      second_native: {
        verification: secondNative.native_verification,
        acceptance: secondNative.acceptance,
      },
      first_receiving_workload: RECEIVING_WORKLOAD,
      second_receiving_workload: secondFixture.receiving_workload,
      first_replay_unit: firstReplayUnit,
      second_replay_unit: secondReplayUnit,
      first_reservation: firstReservation,
      second_reservation: secondReservation,
      second_decision: secondReservation
        ? 'DISTINCT_RECEIVING_WORKLOAD_RESERVED'
        : 'SAME_RECEIVING_WORKLOAD_REPLAY_REFUSED',
      local_admission: 'NOT_EVALUATED',
      provider_entry: 'NOT_EVALUATED',
      effect: 'NOT_EVALUATED',
    },
  };
}

function runAuthorizationCollisionCase(vector) {
  const requirements = [
    {
      source: WIMSE_WPT_REVISION,
      field: 'authorization',
      scheme: 'WPT',
      exclusive: true,
    },
    {
      source: 'draft-rosomakho-oauth-txn-challenge-00',
      field: 'authorization',
      scheme: 'Bearer',
      exclusive: false,
    },
  ];
  const [wptRequirement, oauthRequirement] = requirements;
  const collision = wptRequirement.field === oauthRequirement.field
    && wptRequirement.scheme !== oauthRequirement.scheme
    && (wptRequirement.exclusive || oauthRequirement.exclusive);
  return {
    ...vector,
    passed: vector.expected === 'REFUSED' && collision,
    observed: {
      interpretation: 'SOURCE_PINNED_REQUIREMENT_MODEL_NOT_DRAFT_TEXT_EXECUTION',
      requirements,
      one_authorization_field: wptRequirement.field === oauthRequirement.field,
      mutually_exclusive_schemes: collision,
      direct_same_request_composition: collision
        ? 'REFUSED_AUTHORIZATION_SCHEME_COLLISION'
        : 'NO_COLLISION_DERIVED',
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

function runConfiguredSemanticHeaderCase(vector) {
  let refusal = null;
  try {
    buildFixture('NONE', {
      scenarioId: vector.id,
      otherTokenHeaders: [...UNDERSTOOD_OTHER_TOKEN_HEADERS, 'if-match'],
    });
  } catch (error) {
    refusal = error instanceof Error ? error.message : String(error);
  }
  return {
    ...vector,
    passed: vector.expected === 'REFUSED'
      && typeof refusal === 'string'
      && /constructor config/.test(refusal),
    observed: {
      configured_header: 'if-match',
      decision: refusal === null ? 'UNEXPECTEDLY_ACCEPTED' : 'REFUSED_BY_FIXED_PROFILE',
      reason: refusal,
      native: 'NOT_EVALUATED_CONSTRUCTOR_REFUSED',
      local_admission: 'NOT_EVALUATED',
      provider_entry: 'NOT_EVALUATED',
      effect: 'NOT_EVALUATED',
    },
  };
}

export function verifySourceLock() {
  const failures = [];
  const expectedTopLevelKeys = new Set([
    '@version',
    'upstream',
    'local_runtime_closure',
    'local_compatibility_surfaces',
    'local_artifacts',
  ]);
  if (!exactObjectKeys(SOURCE_LOCK, expectedTopLevelKeys)
      || SOURCE_LOCK['@version'] !== SOURCE_LOCK_VERSION) {
    failures.push('source_lock_shape_or_version_mismatch');
  }
  const expectedUpstream = new Map([
    [WIMSE_WPT_REVISION, [43002, '6a629ffd6bcc0e75ae1deb3e2ddd543ef09d0da6f108e85d085b09d2b9b42f82', [
      'Section 2 aud, tth, and oth', 'Section 2 WPT validation', 'Section 2.2 Authorization exclusivity',
    ]]],
    [WIMSE_HTTP_SIGNATURE_REVISION, [45388, 'e44e2bc1340854e1c3aab3887bba4e9d89f4b9edb54865c43bfbd9c0e7d40f44', [
      'Section 3 request signatures', 'Section 3.1 wimse-aud',
    ]]],
    [WIMSE_WORKLOAD_CREDS_REVISION, [58413, 'b111e4e85a7f3bc5c844560db87276c184a04db28ffeaccb057c13eb034dbed5', [
      'Section 5 workload identity token', 'Section 5.1 JWT WIT',
    ]]],
    [WIMSE_WORKLOAD_IDENTIFIER_REVISION, [25443, '3789600b5295bed271970fc318d1bcbd317b46883aab42f58e5620ab31a766b8', [
      'Section 4.1 URI requirements', 'Section 4.3 trust-domain association',
      'Section 4.5 stability and uniqueness', 'Section 7.1 URI parsing and processing',
    ]]],
    [OAUTH_TRANSACTION_TOKENS_REVISION, [80218, '937eeaac88c19eb00c7a3581f3de850c79c32aa7e4484ded329c15c123718364', [
      'Section 9.2 aud, txn, and req_wl', 'Section 12.2 forward unchanged',
      'Section 13.2 unique transaction identifier',
    ]]],
    [SPT_TRANSACTION_TOKENS_REVISION, [32752, '5ebba0db429816a7fe887128f08d51c3840209bf17de74d66581ce935966e195', [
      'Section 4 SPT transaction token', 'Section 6 intent binding',
    ]]],
    ['draft-rosomakho-oauth-txn-challenge-00', [70435, 'a50c1fee4ce4ae486aa6e6739e9927586dc5c14a209434f44f76200354a8cead', [
      'Section 4 transaction challenge', 'Section 6 access-token presentation',
    ]]],
  ]);
  const upstreamEntries = Array.isArray(SOURCE_LOCK.upstream) ? SOURCE_LOCK.upstream : [];
  if (upstreamEntries.length !== expectedUpstream.size) {
    failures.push('upstream_source_set_mismatch');
  }
  if (JSON.stringify(upstreamEntries.map((entry) => entry?.id))
      !== JSON.stringify([...expectedUpstream.keys()])) {
    failures.push('upstream_source_order_mismatch');
  }
  for (const [id, [bytes, sha256, anchors]] of expectedUpstream) {
    const source = upstreamEntries.find((entry) => entry?.id === id);
    if (!exactObjectKeys(source, new Set(['id', 'url', 'bytes', 'sha256', 'anchors']))
        || source.url !== `https://www.ietf.org/archive/id/${id}.txt`
        || source.bytes !== bytes
        || source.sha256 !== sha256
        || JSON.stringify(source.anchors) !== JSON.stringify(anchors)) {
      failures.push(`upstream_source_lock_mismatch:${id}`);
    }
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
    'conformance/composition/wimse-wpt02-oauth-txn-aeb-v0.1/oauth-txn-challenge-native-fixture.json',
  ]);
  const localArtifacts = Array.isArray(SOURCE_LOCK.local_artifacts)
    ? SOURCE_LOCK.local_artifacts
    : [];
  if (localArtifacts.length !== expectedLocalPaths.size) {
    failures.push('local_artifact_set_mismatch');
  }
  for (const artifact of localArtifacts) {
    if (!exactObjectKeys(artifact, new Set(['path', 'bytes', 'sha256']))) {
      failures.push(`local_artifact_shape_mismatch:${String(artifact?.path)}`);
      continue;
    }
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
      : vector.mutation === 'CONFIGURE_SEMANTIC_OTHER_HEADER'
        ? runConfiguredSemanticHeaderCase(vector)
      : vector.mutation === 'REPLAY_SAME_RECEIVING_WORKLOAD'
          || vector.mutation === 'REPLAY_DIFFERENT_RECEIVING_WORKLOAD'
        ? runReplayReceiverScopeCase(vector)
      : vector.mutation.startsWith('CLAIM_ONLY_')
      ? runClaimOnlyCase(vector)
      : runFullCase(vector)
  ));
  const passed = cases.filter((entry) => entry.passed).length;
  const core = {
    '@version': REPORT_VERSION,
    profile: PROFILE,
    evaluated_at: NOW,
    source_lock: {
      ...sourceLock,
      version: SOURCE_LOCK_VERSION,
      file_sha256: SOURCE_LOCK_FILE_SHA256,
    },
    implementation: {
      wpt_revision: WIMSE_WPT_REVISION,
      workload_credentials_revision: WIMSE_WORKLOAD_CREDS_REVISION,
      workload_identifier_revision: WIMSE_WORKLOAD_IDENTIFIER_REVISION,
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
      replay_identity: 'stable native namespace plus Txn-Token aud Trust Domain, constructor-pinned receiving logical workload, and txn; draft revision and optional iss excluded',
      receiving_workload_scope: 'constructor-pinned relying-party identity; not presenter input and not a Txn-Token claim',
      requesting_workload_scope: 'constructor-pinned original Txn-Token req_wl; preserved across hops and distinct from the immediate WIT sender when the call chain advances',
      wimse_http_signature_profile: 'draft -06 request verification only; optional signed-response negotiation is refused because this adapter cannot enforce the response',
      rctx: 'refused when present because the closed action mapping does not classify or project downstream request context',
      application_subset: 'strict EMILIA request subset, not general Txn-Tokens-11 or WIMSE HTTP Message Signatures -06 conformance',
      request_target: 'canonical HTTPS target_uri projected to origin-form path and query; not raw-wire target-byte evidence',
      header_observation: 'closed object/map observation with case-folded duplicates refused; not proof of raw-wire singleton cardinality',
      request_header_profile: 'exact required request-header set; unknown headers are refused and signed Content-Type remains material to the mapped action',
      replay_enforcement: 'adapter emits a receiver-scoped replay identity only; a shared downstream AEB store refuses reuse at the same logical workload without blocking legitimate use at another workload and separately caches nonce or WPT jti when policy requires',
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
    const referenceValid = exactObjectKeys(
      REPORT_REFERENCE,
      new Set(['@version', 'report_digest', 'source_lock_file_sha256']),
    )
      && REPORT_REFERENCE['@version'] === REPORT_REFERENCE_VERSION
      && REPORT_REFERENCE.report_digest === report.report_digest
      && REPORT_REFERENCE.source_lock_file_sha256 === SOURCE_LOCK_FILE_SHA256;
    if (!report.source_lock.valid || report.summary.failed !== 0 || !referenceValid) {
      process.exitCode = 1;
    }
  } else {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  }
}
