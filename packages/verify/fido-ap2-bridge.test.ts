// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

// @ts-expect-error -- the CAID reference implementation intentionally has no TS surface.
import { computeCaid } from './vendor/caid.mjs';
import {
  AEB_NATIVE_VERIFICATION_ATTESTATION_VERSION,
  adapterPinDigest,
  canonicalizeAeb,
  createAebNativeVerificationAttestationAdapter,
  digestAeb,
  evaluateAebEvidence,
  registryEntryDigest,
  signAebNativeVerificationAttestation,
  unifiedRegistryDigest,
  verifyAebEvaluation,
  type AebPinnedProfile,
} from './aeb-adapter-contract.js';
import {
  FIDO_AP2_ACTION_TYPE,
  FIDO_AP2_AEB_ADAPTER_ID,
  FIDO_AP2_AEB_CONFIG_VERSION,
  FIDO_AP2_AEB_TRUST_ROOT_VERSION,
  FIDO_AP2_CAID_ACTION_DEFINITIONS,
  FIDO_AP2_CAID_MAPPER_ID,
  FIDO_AP2_CAID_MAPPING_VERSION,
  FIDO_AP2_CAID_PROFILE_ID,
  FIDO_AP2_NATIVE_PROTOCOL_ID,
  FIDO_AP2_SOURCE_BYTES_DOMAIN,
  FIDO_AP2_SOURCE_REVISION,
  createFidoAp2AebAdapter,
  createFidoAp2NativeSourceBinding,
  createFidoAp2PinnedProfile,
  projectFidoAp2PaymentAction,
} from './fido-ap2-bridge.js';

type Obj = Record<string, any>;

const NOW = '2026-07-31T18:00:00.000Z';
const SOURCE_IAT = Math.floor(Date.parse('2026-07-31T17:59:00.000Z') / 1_000);
const CHECKOUT_EXP = Math.floor(Date.parse('2026-07-31T18:05:00.000Z') / 1_000);
const PAYMENT_EXP = Math.floor(Date.parse('2026-07-31T18:04:00.000Z') / 1_000);
const RP_ID = 'payments.example.test';
const ORIGIN = 'https://payments.example.test';
const TENANT_ID = 'tenant:buyer-7';
const RELYING_PARTY_ID = 'rp:fido-ap2:test';
const AUDIENCE = 'urn:emilia:gate:payments';
const OPERATION_ID = 'operation:fido-ap2:001';
const EFFECT_REQUEST_DIGEST = sha256Text('provider-effect-request:fido-ap2:001');
const PROVIDER = Object.freeze({
  provider_id: 'provider:payment-processor',
  account_id: 'account:merchant-acme',
  environment: 'production',
});
const APPROVER_ID = 'human:approver-7';
const CREDENTIAL_ID = 'credential:approver-7:p256';
const NONCE = 'fido-ap2-20260731-0001';
const NATIVE_PROTOCOL = FIDO_AP2_NATIVE_PROTOCOL_ID;
const NATIVE_ADAPTER_ID = 'bridge:ap2-native-verifier';
const NATIVE_KEY_ID = 'native-verifier:ap2:test';
const EVALUATOR_KEY_ID = 'evaluator:fido-ap2:test';

const webauthnSigner = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const nativeVerifierSigner = crypto.generateKeyPairSync('ed25519');
const evaluatorSigner = crypto.generateKeyPairSync('ed25519');

function sha256Text(value: string): string {
  return `sha256:${crypto.createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function sha256Base64url(value: string): string {
  return crypto.createHash('sha256').update(value, 'ascii').digest('base64url');
}

function hashBase64url(
  algorithm: 'sha-256' | 'sha-384' | 'sha-512',
  value: string,
): string {
  return crypto.createHash(algorithm.replace('-', ''))
    .update(value, 'ascii').digest('base64url');
}

function base64urlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function compactJwt(label: string, payload: unknown): string {
  return [
    base64urlJson({ alg: 'ES256', kid: `key:${label}`, typ: 'JWT' }),
    base64urlJson(payload),
    Buffer.from(`deterministic-signature:${label}`, 'utf8').toString('base64url'),
  ].join('.');
}

function canonicalSdJwt(label: string, payload: unknown): string {
  return `${compactJwt(label, payload)}~`;
}

function sourceBytesDigest(label: string, value: string): string {
  const bytes = Buffer.from(value, 'ascii');
  const hash = crypto.createHash('sha256');
  hash.update(FIDO_AP2_SOURCE_BYTES_DOMAIN, 'utf8');
  hash.update('\0', 'utf8');
  hash.update(label, 'utf8');
  hash.update('\0', 'utf8');
  hash.update(String(bytes.length), 'utf8');
  hash.update(':', 'utf8');
  hash.update(bytes);
  return `sha256:${hash.digest('hex')}`;
}

interface RawOptions {
  seed?: string;
  checkoutExp?: number;
  paymentExp?: number;
  checkoutHashAlgorithm?: 'sha-256' | 'sha-384' | 'sha-512';
}

function rawAp2(options: RawOptions = {}) {
  const seed = options.seed ?? '001';
  const checkoutJwt = compactJwt(`checkout-payload:${seed}`, {
    cart_id: `cart-${seed}`,
    line_items: [{ description: 'Industrial sensor', quantity: 1, amount_minor: 12_550 }],
    total: { amount: 12_550, currency: 'USD' },
  });
  const checkoutHashAlgorithm = options.checkoutHashAlgorithm ?? 'sha-256';
  const checkoutHash = hashBase64url(checkoutHashAlgorithm, checkoutJwt);
  const checkout = {
    vct: 'mandate.checkout.1',
    checkout_jwt: checkoutJwt,
    checkout_hash: checkoutHash,
    iat: SOURCE_IAT,
    exp: options.checkoutExp ?? CHECKOUT_EXP,
  };
  const payment: Obj = {
    vct: 'mandate.payment.1',
    transaction_id: checkoutHash,
    payee: { id: 'merchant:acme', name: 'Acme Industrial' },
    payment_amount: { amount: 12_550, currency: 'USD' },
    payment_instrument: { id: 'instrument:visa-4242', type: 'CARD' },
    iat: SOURCE_IAT,
    exp: options.paymentExp ?? PAYMENT_EXP,
  };
  const checkoutMandateToken = canonicalSdJwt(
    `checkout-mandate:${seed}`,
    checkoutHashAlgorithm === 'sha-256'
      ? checkout
      : { ...checkout, _sd_alg: checkoutHashAlgorithm },
  );
  const paymentMandateToken = canonicalSdJwt(`payment-mandate:${seed}`, payment);
  const sourceBinding = createFidoAp2NativeSourceBinding({
    checkout_mandate_token: checkoutMandateToken,
    payment_mandate_token: paymentMandateToken,
    checkout_mandate_payload: checkout,
    payment_mandate_payload: payment,
  });
  return {
    checkout_mandate: checkout,
    payment_mandate: payment,
    source_binding: sourceBinding,
    checkout_mandate_token: checkoutMandateToken,
    payment_mandate_token: paymentMandateToken,
  };
}

function projectionInput(raw: ReturnType<typeof rawAp2>): Obj {
  return {
    checkout_mandate: raw.checkout_mandate,
    payment_mandate: raw.payment_mandate,
    source_binding: raw.source_binding,
  };
}

function expectedProjection(raw: ReturnType<typeof rawAp2>): Obj {
  const sourceExpiry = new Date(Math.min(
    raw.checkout_mandate.exp,
    raw.payment_mandate.exp,
  ) * 1_000).toISOString();
  return {
    action_type: FIDO_AP2_ACTION_TYPE,
    checkout_mandate_digest: raw.source_binding.checkout_mandate_token_digest,
    payment_mandate_digest: raw.source_binding.payment_mandate_token_digest,
    checkout_payload_jwt_digest: sourceBytesDigest(
      'checkout-payload-jwt',
      raw.checkout_mandate.checkout_jwt,
    ),
    transaction_id: raw.payment_mandate.transaction_id,
    amount_minor: raw.payment_mandate.payment_amount.amount,
    currency: raw.payment_mandate.payment_amount.currency,
    payee_id: raw.payment_mandate.payee.id,
    payee_name: raw.payment_mandate.payee.name,
    payee_website_digest: digestAeb(raw.payment_mandate.payee.website ?? null),
    pisp_digest: digestAeb(raw.payment_mandate.pisp ?? null),
    payment_instrument_id: raw.payment_mandate.payment_instrument.id,
    payment_instrument_type: raw.payment_mandate.payment_instrument.type,
    payment_instrument_description_digest: digestAeb(
      raw.payment_mandate.payment_instrument.description ?? null,
    ),
    risk_data_digest: digestAeb(raw.payment_mandate.risk_data ?? null),
    execution: 'immediate',
    source_expires_at: sourceExpiry,
  };
}

function disclosureFor(action: Obj): Obj {
  return {
    checkout_commitment: action.checkout_mandate_digest,
    payment_commitment: action.payment_mandate_digest,
    checkout_payload_jwt_commitment: action.checkout_payload_jwt_digest,
    transaction_id: action.transaction_id,
    amount_minor: action.amount_minor,
    currency: action.currency,
    payee_id: action.payee_id,
    payee_name: action.payee_name,
    payment_instrument_id: action.payment_instrument_id,
    payment_instrument_type: action.payment_instrument_type,
    execution: action.execution,
    source_expires_at: action.source_expires_at,
  };
}

function localCaid(action: Obj): string {
  const result = computeCaid(action, {
    suite: 'jcs-sha256',
    definitions: FIDO_AP2_CAID_ACTION_DEFINITIONS,
  });
  assert.equal(typeof result.caid, 'string');
  return result.caid;
}

function webauthnAssertion(
  context: Obj,
  options: { rpId?: string; origin?: string; flags?: number; signCount?: number } = {},
): Obj {
  const challenge = crypto.createHash('sha256')
    .update(canonicalizeAeb(context), 'utf8').digest('base64url');
  const clientData = Buffer.from(JSON.stringify({
    type: 'webauthn.get',
    challenge,
    origin: options.origin ?? ORIGIN,
  }), 'utf8');
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(options.signCount ?? 42);
  const authenticatorData = Buffer.concat([
    crypto.createHash('sha256').update(options.rpId ?? RP_ID, 'utf8').digest(),
    Buffer.from([options.flags ?? 0x05]),
    counter,
  ]);
  const signedData = Buffer.concat([
    authenticatorData,
    crypto.createHash('sha256').update(clientData).digest(),
  ]);
  return {
    credential_id: CREDENTIAL_ID,
    authenticator_data: authenticatorData.toString('base64url'),
    client_data_json: clientData.toString('base64url'),
    signature: crypto.sign('sha256', signedData, webauthnSigner.privateKey).toString('base64url'),
  };
}

interface FixtureOptions extends RawOptions {
  contextOverrides?: Obj;
  artifactOverrides?: Obj;
  commitmentOverrides?: Obj;
  actionOverrides?: Obj;
  disclosureOverrides?: Obj;
  rpId?: string;
  origin?: string;
  flags?: number;
  signCount?: number;
  rootStatus?: string;
  statusOverrides?: Obj;
}

function fixture(options: FixtureOptions = {}) {
  const raw = rawAp2(options);
  const expectedAction = {
    ...projectFidoAp2PaymentAction(projectionInput(raw)),
    ...options.actionOverrides,
  };
  const disclosure = { ...disclosureFor(expectedAction), ...options.disclosureOverrides };
  const profile = createFidoAp2PinnedProfile();
  const caid = localCaid(expectedAction);
  const nativeAttestation = signAebNativeVerificationAttestation({
    '@version': AEB_NATIVE_VERIFICATION_ATTESTATION_VERSION,
    protocol_id: NATIVE_PROTOCOL,
    audience: AUDIENCE,
    native_artifact_ref: 'fixture:ap2-native-pair:001',
    native_artifact_digest: raw.source_binding.native_artifact_digest,
    evidence_role: 'ap2-native-authorization',
    subject: { id: 'verifier:ap2-native', kind: 'system' },
    verified_at: '2026-07-31T17:59:30.000Z',
    expires_at: '2026-07-31T18:03:00.000Z',
    mapping: {
      profile_digest: profile.profile_digest,
      mapper_id: profile.mapper_id,
      resolver_digest: profile.resolver.implementation_digest,
      caid,
      normalized_action_digest: digestAeb(expectedAction),
    },
  }, { key_id: NATIVE_KEY_ID, private_key: nativeVerifierSigner.privateKey });
  const sourceCommitments = {
    checkout_mandate_token_digest: raw.source_binding.checkout_mandate_token_digest,
    payment_mandate_token_digest: raw.source_binding.payment_mandate_token_digest,
    native_verification_attestation_digest: digestAeb(nativeAttestation),
    ...options.commitmentOverrides,
  };
  const context = {
    source_revision: FIDO_AP2_SOURCE_REVISION,
    tenant_id: TENANT_ID,
    relying_party_id: RELYING_PARTY_ID,
    audience: AUDIENCE,
    operation_id: OPERATION_ID,
    effect_request_digest: EFFECT_REQUEST_DIGEST,
    provider: { ...PROVIDER },
    source_commitments: structuredClone(sourceCommitments),
    normalized_action_digest: digestAeb(expectedAction),
    caid,
    disclosure_digest: digestAeb(disclosure),
    approver_id: APPROVER_ID,
    nonce: NONCE,
    expires_at: '2026-07-31T18:03:00.000Z',
    ...options.contextOverrides,
  };
  const artifact = {
    '@version': 'EP-FIDO-AP2-EVIDENCE-v1',
    source_revision: FIDO_AP2_SOURCE_REVISION,
    tenant_id: TENANT_ID,
    relying_party_id: RELYING_PARTY_ID,
    audience: AUDIENCE,
    operation_id: OPERATION_ID,
    effect_request_digest: EFFECT_REQUEST_DIGEST,
    provider: { ...PROVIDER },
    source_commitments: sourceCommitments,
    normalized_action: expectedAction,
    disclosure,
    signoff: {
      context,
      webauthn: webauthnAssertion(context, options),
    },
    ...options.artifactOverrides,
  };
  const config = {
    '@version': FIDO_AP2_AEB_CONFIG_VERSION,
    source_revision: FIDO_AP2_SOURCE_REVISION,
    evidence_role: 'human_authorization',
    subject: { id: APPROVER_ID, kind: 'human', native_id: CREDENTIAL_ID },
    tenant_id: TENANT_ID,
    relying_party_id: RELYING_PARTY_ID,
    audience: AUDIENCE,
    action_type: FIDO_AP2_ACTION_TYPE,
    rp_id: RP_ID,
    allowed_origins: [ORIGIN],
    expected_nonce: NONCE,
    max_status_age_seconds: 120,
    sign_count_policy: 'above-enrollment-and-one-time',
    allow_backup_eligible: false,
    allow_backup_state: false,
  };
  const root = {
    '@version': FIDO_AP2_AEB_TRUST_ROOT_VERSION,
    source_revision: FIDO_AP2_SOURCE_REVISION,
    approver_id: APPROVER_ID,
    credential_id: CREDENTIAL_ID,
    public_key_spki: webauthnSigner.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    rp_id: RP_ID,
    key_class: 'A',
    status: options.rootStatus ?? 'active',
    sign_count: 41,
  };
  const status = {
    checked_at: '2026-07-31T17:59:45.000Z',
    expires_at: '2026-07-31T18:04:00.000Z',
    revocation_checked: true,
    revoked: false,
    consumed: false,
    ...options.statusOverrides,
  };
  return {
    ...raw,
    artifact,
    config,
    root,
    status,
    expectedAction,
    context,
    nativeAttestation,
    profile,
  };
}

function evaluate(
  f: ReturnType<typeof fixture>,
  expectedAction: Obj = f.expectedAction,
  profile: AebPinnedProfile = createFidoAp2PinnedProfile(),
) {
  const adapter = createFidoAp2AebAdapter();
  const common = {
    artifact: f.artifact,
    artifact_ref: 'fixture:fido-ap2-human:001',
    status: f.status,
    trust_roots: [f.root],
    adapter_config: f.config,
    expected_action: expectedAction,
    now: NOW,
  };
  const native = adapter.verifyNative(common);
  const mapping = adapter.mapAction({ ...common, profile, native });
  return { adapter, native, mapping };
}

function assertRefused(f: ReturnType<typeof fixture>): void {
  const { native, mapping } = evaluate(f);
  assert.notEqual(native.acceptance, 'ACCEPTED');
  assert.notEqual(mapping.mapping, 'MATCH');
  assert.equal(mapping.caid, null);
}

function registryEntry(id: string, kind: string, version: string, definition: Obj): Obj {
  const entry: Obj = { kind, version, status: 'active', definition };
  entry.definition_digest = registryEntryDigest(id, entry as any);
  return entry;
}

test('projection implements the current AP2 v0.2 closed CheckoutMandate and PaymentMandate', () => {
  const raw = rawAp2();
  assert.equal(
    FIDO_AP2_SOURCE_REVISION,
    'google-agentic-commerce/AP2@e1ea56db72a6385bce3e5c1112b3a56ce60acb43',
  );
  assert.deepEqual(Object.keys(raw.checkout_mandate).sort(), [
    'checkout_hash', 'checkout_jwt', 'exp', 'iat', 'vct',
  ]);
  assert.deepEqual(Object.keys(raw.payment_mandate).sort(), [
    'exp', 'iat', 'payee', 'payment_amount', 'payment_instrument',
    'transaction_id', 'vct',
  ]);
  assert.equal(raw.payment_mandate.transaction_id, raw.checkout_mandate.checkout_hash);
  assert.deepEqual(projectFidoAp2PaymentAction(projectionInput(raw)), expectedProjection(raw));

  const withTypedOptionals = rawAp2();
  withTypedOptionals.payment_mandate.payee.website = 'https://merchant.example';
  withTypedOptionals.payment_mandate.pisp = {
    legal_name: 'Example Payments LLC',
    brand_name: 'Example Pay',
    domain_name: 'payments.example',
  };
  withTypedOptionals.payment_mandate.payment_instrument.description = 'Corporate card';
  withTypedOptionals.payment_mandate.risk_data = { score: 'low' };
  withTypedOptionals.source_binding = createFidoAp2NativeSourceBinding({
    checkout_mandate_token: withTypedOptionals.checkout_mandate_token,
    payment_mandate_token: withTypedOptionals.payment_mandate_token,
    checkout_mandate_payload: withTypedOptionals.checkout_mandate,
    payment_mandate_payload: withTypedOptionals.payment_mandate,
  });
  assert.deepEqual(
    projectFidoAp2PaymentAction(projectionInput(withTypedOptionals)),
    expectedProjection(withTypedOptionals),
  );

  const f = fixture();
  assert.equal(f.expectedAction.amount_minor, 12_550);
  assert.equal(f.expectedAction.execution, 'immediate');
  assert.equal(f.expectedAction.source_expires_at, '2026-07-31T18:04:00.000Z');
  assert.equal(f.config.sign_count_policy, 'above-enrollment-and-one-time');
  assert.deepEqual(f.artifact.disclosure, disclosureFor(f.expectedAction));
  assert.doesNotThrow(() => digestAeb(f.artifact));

  const profile = createFidoAp2PinnedProfile();
  assert.equal(profile.version, FIDO_AP2_CAID_MAPPING_VERSION);
  assert.equal(profile.mapper_id, FIDO_AP2_CAID_MAPPER_ID);
  assert.match(profile.profile_digest, /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(profile.semantic_equivalence.omitted_material_fields, []);
  assert.deepEqual(profile.semantic_equivalence.omitted_nonmaterial_fields, []);
  assert.deepEqual(
    ['action_type', ...FIDO_AP2_CAID_ACTION_DEFINITIONS[0].required_fields.map((field) => field.name)],
    Object.keys(f.expectedAction),
  );

  const { adapter, native, mapping } = evaluate(f);
  assert.equal(adapter.id, FIDO_AP2_AEB_ADAPTER_ID);
  assert.equal(native.native_verification, 'VERIFIED');
  assert.equal(native.acceptance, 'ACCEPTED', JSON.stringify(native.reasons));
  assert.deepEqual(native.subject, { id: APPROVER_ID, kind: 'human' });
  assert.equal(native.evidence_role, 'human_authorization');
  assert.equal(mapping.mapping, 'MATCH');
  assert.equal(mapping.action_digest, digestAeb(f.expectedAction));
  assert.equal(mapping.caid, f.context.caid);
});

test('projection binds verified AP2 token payloads and honors the authenticated hash algorithm', () => {
  const good = rawAp2();
  const spliced = projectionInput(good);
  spliced.payment_mandate = structuredClone(good.payment_mandate);
  spliced.payment_mandate.payee = { id: 'merchant:evil', name: 'Evil Merchant' };
  spliced.payment_mandate.payment_amount = { amount: 999_999, currency: 'USD' };
  assert.throws(
    () => projectFidoAp2PaymentAction(spliced),
    /verified AP2 payment payload binding mismatch/,
  );

  for (const checkoutHashAlgorithm of ['sha-384', 'sha-512'] as const) {
    const fixture = rawAp2({ checkoutHashAlgorithm });
    assert.deepEqual(
      projectFidoAp2PaymentAction(projectionInput(fixture)),
      expectedProjection(fixture),
    );
  }
});

test('native source binding commits deterministic canonical AP2 SD-JWT token strings', () => {
  const raw = rawAp2();
  assert.match(raw.checkout_mandate_token, /^[^.]+\.[^.]+\.[A-Za-z0-9_-]+~$/);
  assert.match(raw.payment_mandate_token, /^[^.]+\.[^.]+\.[A-Za-z0-9_-]+~$/);
  const same = createFidoAp2NativeSourceBinding({
    checkout_mandate_token: raw.checkout_mandate_token,
    payment_mandate_token: raw.payment_mandate_token,
    checkout_mandate_payload: raw.checkout_mandate,
    payment_mandate_payload: raw.payment_mandate,
  });
  assert.deepEqual(same, raw.source_binding);
  assert.match(same.native_artifact_digest, /^sha256:[0-9a-f]{64}$/);

  const alternate = rawAp2({ seed: 'alternate' });
  assert.notEqual(
    same.checkout_mandate_token_digest,
    alternate.source_binding.checkout_mandate_token_digest,
  );
  assert.notEqual(same.native_artifact_digest, alternate.source_binding.native_artifact_digest);

  for (const malformed of [
    { checkout_mandate_token: raw.checkout_mandate_token.slice(0, -1), payment_mandate_token: raw.payment_mandate_token },
    { checkout_mandate_token: `${raw.checkout_mandate_token}~`, payment_mandate_token: raw.payment_mandate_token },
    { checkout_mandate_token: ` ${raw.checkout_mandate_token}`, payment_mandate_token: raw.payment_mandate_token },
    { checkout_mandate_token: `bad%.payload.signature~`, payment_mandate_token: raw.payment_mandate_token },
    { checkout_mandate_token: `a.payload.signature~`, payment_mandate_token: raw.payment_mandate_token },
    { checkout_mandate_token: raw.checkout_mandate_token, payment_mandate_token: '' },
  ]) assert.throws(() => createFidoAp2NativeSourceBinding(malformed));

  for (const [checkoutPayload, paymentPayload] of [
    [new Date('2026-07-31T18:00:00.000Z'), new Map([['payee', 'merchant:evil']])],
    [new Set(['checkout']), /payment/],
    [[, 'sparse'], { transaction_id: 'payment:001' }],
  ]) {
    assert.throws(
      () => createFidoAp2NativeSourceBinding({
        checkout_mandate_token: raw.checkout_mandate_token,
        payment_mandate_token: raw.payment_mandate_token,
        checkout_mandate_payload: checkoutPayload,
        payment_mandate_payload: paymentPayload,
      }),
      /strict JSON AP2 payloads required/,
    );
  }

  let getterInvoked = false;
  const accessor = {
    get checkout_mandate_token() {
      getterInvoked = true;
      return raw.checkout_mandate_token;
    },
    payment_mandate_token: raw.payment_mandate_token,
  };
  assert.throws(() => createFidoAp2NativeSourceBinding(accessor));
  assert.equal(getterInvoked, false);

  let proxyGetInvoked = false;
  const proxied = new Proxy({
    checkout_mandate_token: raw.checkout_mandate_token,
    payment_mandate_token: raw.payment_mandate_token,
    checkout_mandate_payload: raw.checkout_mandate,
    payment_mandate_payload: raw.payment_mandate,
  }, {
    get(target, property, receiver) {
      proxyGetInvoked = true;
      return Reflect.get(target, property, receiver);
    },
  });
  assert.deepEqual(createFidoAp2NativeSourceBinding(proxied), same);
  assert.equal(proxyGetInvoked, false);
});

test('projection explicitly rejects the legacy CartMandate model', () => {
  const raw = rawAp2();
  const legacy = {
    cart_mandate: {
      contents: {
        id: 'cart-legacy',
        payment_request: { details: { total: { amount: { currency: 'USD', value: 125.5 } } } },
        merchant_name: 'Acme Industrial',
      },
      merchant_authorization: 'opaque',
    },
    payment_mandate: {
      payment_mandate_contents: {
        payment_mandate_id: 'legacy-payment',
        payment_details_total: { amount: { currency: 'USD', value: 125.5 } },
      },
      user_authorization: 'opaque',
    },
    source_binding: raw.source_binding,
  };
  assert.throws(
    () => projectFidoAp2PaymentAction(legacy),
    /unsupported or inconsistent closed AP2 payment mandate/,
  );
});

test('projection rejects open or recurring execution and transaction mismatch', () => {
  const attacks: Array<(raw: ReturnType<typeof rawAp2>) => void> = [
    ({ checkout_mandate: checkout }) => { checkout.vct = 'mandate.checkout.open.1'; },
    ({ payment_mandate: payment }) => { payment.vct = 'mandate.payment.open.1'; },
    ({ payment_mandate: payment }) => { payment.execution_date = '2026-08-01T00:00:00Z'; },
    ({ payment_mandate: payment }) => { payment.execution_date = null; },
    ({ payment_mandate: payment }) => { payment.pisp = null; },
    ({ payment_mandate: payment }) => { payment.risk_data = null; },
    ({ payment_mandate: payment }) => { payment.payee.website = null; },
    ({ payment_mandate: payment }) => { payment.payment_instrument.description = null; },
    ({ payment_mandate: payment }) => { (payment as Obj).recurrence = { frequency: 'monthly' }; },
    ({ payment_mandate: payment }) => { payment.transaction_id = 'checkout:attacker'; },
  ];
  for (const attack of attacks) {
    const raw = rawAp2();
    attack(raw);
    assert.throws(
      () => projectFidoAp2PaymentAction(projectionInput(raw)),
      /unsupported or inconsistent closed AP2 payment mandate/,
    );
  }
});

test('projection rejects a stale or spliced source binding', () => {
  const raw = rawAp2();
  const alternate = rawAp2({ seed: 'alternate' });
  raw.source_binding = {
    ...raw.source_binding,
    checkout_mandate_token_digest: alternate.source_binding.checkout_mandate_token_digest,
  };
  assert.throws(
    () => projectFidoAp2PaymentAction(projectionInput(raw)),
    /unsupported or inconsistent closed AP2 payment mandate/,
  );
});

test('mutation of every material action field and source digest is refused', () => {
  const actionFields = [
    'action_type',
    ...FIDO_AP2_CAID_ACTION_DEFINITIONS[0].required_fields.map((field) => field.name),
  ];
  const expectedFields = [
    'action_type', 'checkout_mandate_digest', 'payment_mandate_digest',
    'checkout_payload_jwt_digest', 'transaction_id', 'amount_minor', 'currency',
    'payee_id', 'payee_name', 'payee_website_digest', 'pisp_digest',
    'payment_instrument_id', 'payment_instrument_type',
    'payment_instrument_description_digest', 'risk_data_digest', 'execution',
    'source_expires_at',
  ];
  assert.deepEqual(actionFields, expectedFields);
  for (const field of actionFields) {
    const f = fixture();
    if (field.endsWith('_digest')) f.artifact.normalized_action[field] = digestAeb({ changed: field });
    else if (field === 'amount_minor') f.artifact.normalized_action[field] += 1;
    else if (field === 'source_expires_at') f.artifact.normalized_action[field] = '2026-07-31T18:03:59.000Z';
    else if (field === 'execution') f.artifact.normalized_action[field] = 'scheduled';
    else if (field === 'currency') f.artifact.normalized_action[field] = 'EUR';
    else f.artifact.normalized_action[field] = `${field}:attacker`;
    assertRefused(f);
  }

  for (const field of [
    'checkout_mandate_token_digest',
    'payment_mandate_token_digest',
    'native_verification_attestation_digest',
  ]) {
    const f = fixture();
    f.artifact.source_commitments[field] = digestAeb({ changed: field });
    assertRefused(f);
  }
});

test('post-signing disclosure, scope, provider, and effect tampering is refused', () => {
  for (const [path, value] of [
    ['disclosure.payee_id', 'merchant:evil'],
    ['tenant_id', 'tenant:attacker'],
    ['relying_party_id', 'rp:attacker'],
    ['operation_id', 'operation:attacker'],
    ['effect_request_digest', digestAeb({ request: 'attacker' })],
  ] as const) {
    const f = fixture();
    if (path.startsWith('disclosure.')) f.artifact.disclosure[path.slice(11)] = value;
    else f.artifact[path] = value;
    assertRefused(f);
  }
  for (const field of ['provider_id', 'account_id', 'environment']) {
    const f = fixture();
    f.artifact.provider[field] = `${field}:attacker`;
    assertRefused(f);
  }
});

test('every signed WebAuthn context binding is relying-party checked', () => {
  const base = fixture();
  const wrongCommitments = structuredClone(base.context.source_commitments);
  wrongCommitments.payment_mandate_token_digest = digestAeb({ wrong: 'payment' });
  const wrongBindings: Obj[] = [
    { source_revision: 'ap2:other-revision' },
    { tenant_id: 'tenant:attacker' },
    { relying_party_id: 'rp:attacker' },
    { audience: 'urn:wrong:audience' },
    { operation_id: 'operation:attacker' },
    { effect_request_digest: digestAeb({ request: 'attacker' }) },
    { provider: { ...PROVIDER, provider_id: 'provider:attacker' } },
    { provider: { ...PROVIDER, account_id: 'account:attacker' } },
    { provider: { ...PROVIDER, environment: 'staging' } },
    { source_commitments: wrongCommitments },
    { normalized_action_digest: digestAeb({ wrong: 'action' }) },
    { caid: `caid:1:${FIDO_AP2_ACTION_TYPE}:jcs-sha256:${'A'.repeat(43)}` },
    { disclosure_digest: digestAeb({ wrong: 'disclosure' }) },
    { approver_id: 'human:attacker' },
    { nonce: 'wrong-nonce' },
    { expires_at: '2026-07-31T17:59:59.000Z' },
  ];
  for (const contextOverrides of wrongBindings) assertRefused(fixture({ contextOverrides }));
});

test('source expiry bounds authorization context and current acceptance', () => {
  assertRefused(fixture({
    contextOverrides: { expires_at: '2026-07-31T18:04:00.001Z' },
  }));
  assertRefused(fixture({
    checkoutExp: Math.floor(Date.parse('2026-07-31T17:59:59.000Z') / 1_000),
    paymentExp: Math.floor(Date.parse('2026-07-31T18:02:00.000Z') / 1_000),
    contextOverrides: { expires_at: '2026-07-31T17:59:59.000Z' },
  }));
});

test('wrong origin, RP ID, signature, credential, key status, or freshness is refused', () => {
  assertRefused(fixture({ origin: 'https://evil.example' }));
  assertRefused(fixture({ rpId: 'evil.example' }));
  assertRefused(fixture({ rootStatus: 'revoked' }));
  assertRefused(fixture({ statusOverrides: { revoked: true } }));
  assertRefused(fixture({ statusOverrides: { checked_at: '2026-07-31T17:00:00.000Z' } }));
  assertRefused(fixture({ statusOverrides: { checked_at: '2026-07-31T18:00:00.000001Z' } }));

  const badSignature = fixture();
  const signature = Buffer.from(badSignature.artifact.signoff.webauthn.signature, 'base64url');
  signature[signature.length - 1] ^= 0x01;
  badSignature.artifact.signoff.webauthn.signature = signature.toString('base64url');
  assertRefused(badSignature);

  const wrongCredential = fixture();
  wrongCredential.artifact.signoff.webauthn.credential_id = 'credential:attacker';
  assertRefused(wrongCredential);
});

test('closed WebAuthn policy enforces UV, enrollment counter, backup flags, and no extensions', () => {
  assertRefused(fixture({ flags: 0x01 }));
  assertRefused(fixture({ signCount: 41 }));
  assertRefused(fixture({ signCount: 40 }));
  assertRefused(fixture({ flags: 0x0d }));
  assertRefused(fixture({ flags: 0x1d }));
  const extension = fixture();
  const bytes = Buffer.from(extension.artifact.signoff.webauthn.authenticator_data, 'base64url');
  extension.artifact.signoff.webauthn.authenticator_data = Buffer.concat([
    bytes,
    Buffer.from([0xa0]),
  ]).toString('base64url');
  assertRefused(extension);
});

test('exact effect bindings define distinct signed replay domains', () => {
  const baseline = evaluate(fixture()).native;
  assert.equal(baseline.acceptance, 'ACCEPTED');
  const variants: Obj[] = [
    { operation_id: 'operation:fido-ap2:002' },
    { effect_request_digest: digestAeb({ request: 'provider-effect-request:002' }) },
    { provider: { ...PROVIDER, provider_id: 'provider:alternate' } },
    { provider: { ...PROVIDER, account_id: 'account:alternate' } },
    { provider: { ...PROVIDER, environment: 'staging' } },
  ];
  for (const bindings of variants) {
    const f = fixture({ contextOverrides: bindings, artifactOverrides: bindings });
    const native = evaluate(f).native;
    assert.equal(native.acceptance, 'ACCEPTED', JSON.stringify(native.reasons));
    assert.notEqual(native.replay_unit, baseline.replay_unit);
  }
});

test('expected-action mismatch is separate from successful WebAuthn verification', () => {
  const f = fixture();
  const wrongAction = { ...f.expectedAction, amount_minor: 1 };
  const { native, mapping } = evaluate(f, wrongAction);
  assert.equal(native.native_verification, 'VERIFIED');
  assert.equal(native.acceptance, 'ACCEPTED');
  assert.equal(mapping.mapping, 'MISMATCH');
  assert.equal(mapping.caid, null);

  const profile = structuredClone(createFidoAp2PinnedProfile());
  profile.mapper_id = 'mapper:untrusted';
  const wrongProfile = evaluate(f, f.expectedAction, profile);
  assert.equal(wrongProfile.mapping.mapping, 'INDETERMINATE');
  assert.equal(wrongProfile.mapping.caid, null);
});

test('commitment-only artifact rejects raw AP2, unknown keys, and poisoned values', () => {
  const withRaw = fixture();
  (withRaw.artifact as Obj).checkout_mandate = withRaw.checkout_mandate;
  assertRefused(withRaw);

  const unknown = fixture();
  (unknown.artifact.source_commitments as Obj).unknown = digestAeb({ extension: true });
  assertRefused(unknown);

  const oversizedClientData = fixture();
  oversizedClientData.artifact.signoff.webauthn.client_data_json = 'A'.repeat(12_000);
  assertRefused(oversizedClientData);

  const poisonedOrigins = fixture();
  Object.defineProperty(poisonedOrigins.config.allowed_origins, '4294967295', {
    enumerable: true,
    value: 'https://attacker.example',
  });
  assertRefused(poisonedOrigins);

  const nonJson = fixture();
  (nonJson.artifact as Obj).extra = undefined;
  assert.doesNotThrow(() => assertRefused(nonJson));

  const emptyOperation = fixture();
  emptyOperation.artifact.operation_id = '';
  assertRefused(emptyOperation);
});

function twoLegAeb(f: ReturnType<typeof fixture>, expectedAction = f.expectedAction, caid = f.context.caid) {
  const humanAdapter = createFidoAp2AebAdapter();
  const nativeAdapter = createAebNativeVerificationAttestationAdapter({
    id: NATIVE_ADAPTER_ID,
    version: '1',
  });
  const entries: Obj = {
    [f.profile.registry_entry_ref]: registryEntry(
      f.profile.registry_entry_ref,
      'mapping-profile',
      f.profile.version,
      { profile_digest: f.profile.profile_digest },
    ),
    'role:ap2-native-authorization': registryEntry(
      'role:ap2-native-authorization',
      'evidence-role',
      '1',
      { role: 'ap2-native-authorization', subject_kinds: ['system'] },
    ),
    'role:human_authorization': registryEntry(
      'role:human_authorization',
      'evidence-role',
      '1',
      { role: 'human_authorization', subject_kinds: ['human'] },
    ),
  };
  const registry: Obj = {
    '@version': 'EP-EVIDENCE-REGISTRY-v1',
    registry_id: 'registry:fido-ap2:test',
    epoch: 1,
    entries,
  };
  registry.registry_digest = unifiedRegistryDigest(registry as any);
  const humanPin: Obj = {
    version: humanAdapter.version,
    trust_roots: [f.root],
    config: f.config,
    max_status_age_sec: 120,
  };
  humanPin.config_digest = adapterPinDigest(humanAdapter.id, humanPin as any);
  const nativePin: Obj = {
    version: nativeAdapter.version,
    trust_roots: [{
      key_id: NATIVE_KEY_ID,
      public_key: nativeVerifierSigner.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    }],
    config: { audience: AUDIENCE, accepted_protocols: [NATIVE_PROTOCOL] },
    max_status_age_sec: 120,
  };
  nativePin.config_digest = adapterPinDigest(nativeAdapter.id, nativePin as any);
  const config: Obj = {
    '@version': 'AEB-ADAPTER-v1',
    relying_party_id: RELYING_PARTY_ID,
    evaluator_keys: {
      [EVALUATOR_KEY_ID]: {
        public_key: evaluatorSigner.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      },
    },
    registry,
    accepted_mappers: [FIDO_AP2_CAID_MAPPER_ID],
    adapters: { [humanAdapter.id]: humanPin, [nativeAdapter.id]: nativePin },
    profiles: { [FIDO_AP2_CAID_PROFILE_ID]: f.profile },
    requirements: {
      'requirement:fido-ap2:two-leg': {
        '@version': 'AEB-REQUIREMENT-v1',
        all_of: ['ap2-native-authorization', 'human_authorization'],
        terms: [
          { type: 'initiator-exclusion', roles: ['human_authorization'] },
          { type: 'one-time-consumption' },
        ],
      },
    },
  };
  const legs = [
    {
      adapter_id: nativeAdapter.id,
      profile_id: FIDO_AP2_CAID_PROFILE_ID,
      artifact_ref: 'artifact:ap2-native:001',
      artifact: f.nativeAttestation,
      status: f.status,
    },
    {
      adapter_id: humanAdapter.id,
      profile_id: FIDO_AP2_CAID_PROFILE_ID,
      artifact_ref: 'artifact:fido-human:001',
      artifact: f.artifact,
      status: f.status,
    },
  ];
  const result = evaluateAebEvidence({
    config: config as any,
    adapters: { [humanAdapter.id]: humanAdapter, [nativeAdapter.id]: nativeAdapter },
    operation_id: OPERATION_ID,
    consumption_nonce: 'consumption:fido-ap2:001',
    initiator_id: 'agent:buyer',
    requirement_ref: 'requirement:fido-ap2:two-leg',
    caid,
    expected_action: expectedAction,
    legs,
    evaluated_at: NOW,
    signer: { key_id: EVALUATOR_KEY_ID, private_key: evaluatorSigner.privateKey },
  });
  return { config, humanAdapter, nativeAdapter, legs, result };
}

test('AEB composes separate AP2-native and WebAuthn-human legs for one exact action', () => {
  const f = fixture();
  assert.equal(
    f.artifact.source_commitments.native_verification_attestation_digest,
    digestAeb(f.nativeAttestation),
  );
  assert.equal(f.nativeAttestation.native_artifact_digest, f.source_binding.native_artifact_digest);
  const composed = twoLegAeb(f);
  assert.equal(composed.result.record.verdict, 'SATISFIED', JSON.stringify(composed.result.record.reasons));
  assert.equal(composed.result.valid, true, JSON.stringify(composed.result.record.reasons));

  const verified = verifyAebEvaluation(composed.result.record, {
    mode: 'execution',
    config: composed.config as any,
    adapters: {
      [composed.humanAdapter.id]: composed.humanAdapter,
      [composed.nativeAdapter.id]: composed.nativeAdapter,
    },
    artifacts: {
      'artifact:ap2-native:001': f.nativeAttestation,
      'artifact:fido-human:001': f.artifact,
    },
    current_statuses: {
      'artifact:ap2-native:001': f.status,
      'artifact:fido-human:001': f.status,
    },
    expected_action: f.expectedAction,
    now: NOW,
  });
  assert.equal(verified.valid, true, JSON.stringify(verified));
  assert.equal(verified.execution_authorizing, true);
});
