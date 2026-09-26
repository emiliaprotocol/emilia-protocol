// SPDX-License-Identifier: Apache-2.0
//
// EP's WebAuthn call sites against the REAL @simplewebauthn/server verifier.
//
// Every other WebAuthn test in this repo mocks the library, so a major bump of
// it (v13 -> v14) could change what EP accepts without a single test noticing.
// This file drives a software authenticator (real P-256 signatures, real CBOR)
// through the enrollment, signoff-approval, mobile-pairing, mobile-passkey and
// Release Lock call sites with the library unmocked, and pins each property EP
// relies on with one positive case and one negative case per check:
//
//   origin, RP ID, challenge, user verification, signature counter (replay and
//   rollback), signature integrity, the ES256-only algorithm policy, and the
//   cross-origin (iframe) rule v14 added.
//
// Only the database, auth, and signoff-loading seams are mocked.

import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  generateRegistrationOptions,
  SettingsService,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import {
  buildCeremonyBinding,
  signoffCeremonyPolicy,
  signoffConfirmationPhrase,
} from '../lib/signoff/ceremony-policy.js';
import {
  createSoftAuthenticator,
  ed25519CoseKey,
  FLAG_UP,
  FLAG_UV,
  mlDsa44CoseKey,
} from './helpers/soft-webauthn-authenticator.js';
import {
  isWebAuthnAuthenticatorTransport,
  WEBAUTHN_AUTHENTICATOR_TRANSPORTS,
} from '../lib/webauthn-transports.js';

const RP = Object.freeze({ rpName: 'EMILIA Protocol', rpID: 'example.com', origin: 'https://example.com' });
const EVIL_ORIGIN = 'https://evil.example';
const EVIL_RP_ID = 'evil.example';

const CHALLENGE_BYTES = Buffer.from('signed-context-challenge-v14-migration');
const CHALLENGE = CHALLENGE_BYTES.toString('base64url');
const ACTION_HASH = `sha256:${'a'.repeat(64)}`;
const ACTION_TYPE = 'large_payment_release';
const REVIEW_STARTED_AT = '2026-08-03T12:00:00.000Z';
const ISSUED_AT = '2026-08-03T12:00:10.000Z';
const SIGNOFF_ID = `sig_${'a'.repeat(32)}`;

const mocks = vi.hoisted(() => ({
  getGuardedClient: vi.fn(),
  authenticateRequest: vi.fn(),
  resolveEnrollmentBasis: vi.fn(),
  loadSignoffForSigning: vi.fn(),
  loadMobilePairingIdentityContext: vi.fn(),
  exchangePairingVerified: vi.fn(),
}));

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: (...args) => mocks.getGuardedClient(...args),
}));
vi.mock('@/lib/supabase', () => ({
  authenticateRequest: (...args) => mocks.authenticateRequest(...args),
}));
vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));
vi.mock('@/lib/scim/directory-anchor.js', () => ({
  resolveEnrollmentBasis: (...args) => mocks.resolveEnrollmentBasis(...args),
}));
vi.mock('@/lib/webauthn-signoff', () => ({
  loadSignoffForSigning: (...args) => mocks.loadSignoffForSigning(...args),
}));
vi.mock('@/lib/signoff/quorum-session.js', () => ({ canAccept: () => ({ ok: true }) }));
vi.mock('@/lib/signoff/attestation-members.js', () => ({
  decisionToMember: () => ({}),
  decisionsToMembers: () => [],
}));
vi.mock('@/lib/rate-limit.js', () => ({
  checkRateLimit: async () => ({ allowed: true }),
  getClientIP: () => '203.0.113.7',
}));
vi.mock('@/lib/mobile/store.js', () => ({
  loadMobilePairingIdentityContext: (...args) => mocks.loadMobilePairingIdentityContext(...args),
  exchangePairingVerified: (...args) => mocks.exchangePairingVerified(...args),
  mobilePairingIdentityChallenge: () => CHALLENGE,
}));
// Real COSE->SPKI conversion; only the RP config and the context hash (the
// signoff challenge derivation, covered by its own tests) are pinned.
vi.mock('@/lib/webauthn', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/webauthn.js')>()),
  getRpConfig: () => ({ ...RP }),
  contextHashBytes: () => CHALLENGE_BYTES,
}));

const RegisterVerify = await import('../app/api/v1/approvers/webauthn/register-verify/route.js');
const ApproveWebAuthn = await import('../app/api/v1/signoffs/[signoffId]/approve-webauthn/route.js');
const MobileExchange = await import('../app/api/v1/mobile/pairings/exchange/route.js');
const { verifyMobilePasskeyRegistration } = await import('../lib/mobile/attestation.js');
const {
  createReleaseLockRegistrationOptions,
  verifyReleaseLockRegistration,
} = await import('../lib/release-lock/registration.js');

function jsonReq(body: unknown) {
  return { json: () => Promise.resolve(body ?? {}) } as any;
}

// ── Shared fixtures ────────────────────────────────────────────────────────

type Authenticator = ReturnType<typeof createSoftAuthenticator>;

/** The canonical good ceremony; each negative case bends exactly one field. */
function goodCeremony(overrides: Record<string, unknown> = {}) {
  return { challenge: CHALLENGE, origin: RP.origin, rpId: RP.rpID, flags: FLAG_UP | FLAG_UV, ...overrides };
}

const REGISTRATION_NEGATIVES: Array<[string, Record<string, unknown>, RegExp]> = [
  ['wrong origin', { origin: EVIL_ORIGIN }, /origin/i],
  ['wrong RP ID', { rpId: EVIL_RP_ID }, /RP ID/i],
  ['wrong challenge', { challenge: Buffer.from('another-ceremony').toString('base64url') }, /challenge/i],
  ['user verification absent (UP only)', { flags: FLAG_UP }, /user.*verif/i],
  ['wrong ceremony type', { clientData: { type: 'webauthn.get' } }, /type/i],
];

const ALGORITHM_NEGATIVES: Array<[string, () => Map<number | string, unknown>]> = [
  ['EdDSA (-8), which the v13 library default admitted', ed25519CoseKey],
  ['ML-DSA-44 (-48), which the v14 default offers first on PQC runtimes', mlDsa44CoseKey],
];

// ── 1. Registration: library options policy ───────────────────────────────

describe('registration options: EP pins ES256 independent of the v14 runtime-dependent default', () => {
  it('documents the v14 default EP refuses to inherit', async () => {
    const options = await generateRegistrationOptions({
      rpName: RP.rpName,
      rpID: RP.rpID,
      userName: 'probe',
    });
    const algs = options.pubKeyCredParams.map((p) => p.alg);
    // v13 offered [-8, -7, -257]; v14 prepends ML-DSA-44 where WebCrypto can
    // verify it. EP call sites therefore never rely on this default.
    expect(algs).toEqual(SettingsService.runtimeSupportsPQC() ? [-48, -8, -7, -257] : [-8, -7, -257]);
  });

  it('Release Lock registration options offer ES256 only, with UV required', async () => {
    const session = {
      lock_id: `rlk_${'a'.repeat(32)}`,
      role: 'customer',
      contact_binding_id: '11111111-1111-4111-8111-111111111111',
      expires_at: '2999-01-01T00:10:00.000Z',
      lock_expires_at: '2999-01-02T00:00:00.000Z',
    };
    const created = await createReleaseLockRegistrationOptions({
      session,
      existingCredentials: [{ credential_id: 'existing_credential_0001', transports: ['usb', 'nfc'] }],
      rpConfig: RP,
    });
    expect(created.options.pubKeyCredParams).toEqual([{ alg: -7, type: 'public-key' }]);
    expect(created.options.authenticatorSelection).toMatchObject({ userVerification: 'required' });
    expect(created.options.excludeCredentials).toEqual([
      { id: 'existing_credential_0001', type: 'public-key', transports: ['usb', 'nfc'] },
    ]);
  });
});

// ── 2. Registration: mobile passkey enrollment ─────────────────────────────

describe('verifyMobilePasskeyRegistration against the real verifier', () => {
  let authenticator: Authenticator;
  beforeEach(() => { authenticator = createSoftAuthenticator(); });

  function verify(response: unknown) {
    return verifyMobilePasskeyRegistration({
      response,
      expectedChallenge: CHALLENGE,
      expectedOrigin: RP.origin,
      expectedRPID: RP.rpID,
    });
  }

  it.each(['none', 'packed'] as const)('accepts an ES256, UV registration (fmt %s)', async (fmt) => {
    const result = await verify(authenticator.register({ ...goodCeremony(), fmt }));
    expect(result).toMatchObject({
      valid: true,
      algorithm: 'ES256',
      credential_id: authenticator.credentialId,
      public_key_spki: authenticator.spkiB64u,
      sign_count: 0,
      attestation_format: fmt,
    });
  });

  it.each(REGISTRATION_NEGATIVES)('refuses %s', async (_label, bend, reason) => {
    await expect(verify(authenticator.register(goodCeremony(bend)))).rejects.toThrow(reason);
  });

  it.each(ALGORITHM_NEGATIVES)('refuses %s', async (_label, key) => {
    await expect(verify(authenticator.register({ ...goodCeremony(), coseKeyOverride: key() as any })))
      .rejects.toThrow(/Unexpected public key alg/);
  });
});

// ── 3. Registration: Release Lock passkey enrollment ──────────────────────

describe('verifyReleaseLockRegistration against the real verifier', () => {
  let authenticator: Authenticator;
  beforeEach(() => { authenticator = createSoftAuthenticator(); });

  const stored = { challenge: CHALLENGE, rp_id: RP.rpID, origin: RP.origin };

  it('accepts an ES256, UV registration and stores the P-256 SPKI', async () => {
    const result = await verifyReleaseLockRegistration({
      challenge: stored,
      attestation: authenticator.register(goodCeremony()),
      rpConfig: RP,
    });
    expect(result).toMatchObject({
      credentialId: authenticator.credentialId,
      publicKeySpki: authenticator.spkiB64u,
      publicKeyCose: authenticator.cosePublicKeyB64u,
      signCount: 0,
      transports: ['internal'],
      attestationFormat: 'none',
    });
  });

  it.each([...REGISTRATION_NEGATIVES.map(([l, b]) => [l, b] as const)])('refuses %s', async (_label, bend) => {
    await expect(verifyReleaseLockRegistration({
      challenge: stored,
      attestation: authenticator.register(goodCeremony(bend)),
      rpConfig: RP,
    })).rejects.toMatchObject({ status: 400, code: 'attestation_invalid' });
  });

  it.each(ALGORITHM_NEGATIVES)('refuses %s at the library gate', async (_label, key) => {
    await expect(verifyReleaseLockRegistration({
      challenge: stored,
      attestation: authenticator.register({ ...goodCeremony(), coseKeyOverride: key() as any }),
      rpConfig: RP,
    })).rejects.toMatchObject({ status: 400, code: 'attestation_invalid' });
  });
});

// ── 4. Registration: Class-A approver enrollment route ────────────────────

function enrollmentClient() {
  const calls = { rpcs: [] as any[] };
  const builder = () => {
    const b: any = {
      select: () => b,
      eq: () => b,
      is: () => b,
      order: () => b,
      limit: () => b,
      then: (resolve) => resolve({
        data: [{ id: 'ch_1', challenge: CHALLENGE, expires_at: '2999-01-01T00:00:00.000Z' }],
        error: null,
      }),
    };
    return b;
  };
  return {
    calls,
    client: {
      from: builder,
      rpc: vi.fn(async (name, params) => {
        calls.rpcs.push({ name, params });
        return {
          data: { credential_id: params.p_credential.credential_id, enrollment_basis: 'operator_attested' },
          error: null,
        };
      }),
    },
  };
}

describe('POST /api/v1/approvers/webauthn/register-verify against the real verifier', () => {
  let authenticator: Authenticator;
  let db: ReturnType<typeof enrollmentClient>;
  beforeEach(() => {
    authenticator = createSoftAuthenticator();
    db = enrollmentClient();
    mocks.getGuardedClient.mockReset().mockReturnValue(db.client);
    mocks.authenticateRequest.mockReset().mockResolvedValue({
      entity: { entity_id: 'ep_entity_acme', organization_id: 'org_acme' },
      permissions: ['approver.enroll'],
    });
    mocks.resolveEnrollmentBasis.mockReset().mockResolvedValue({
      basis: 'operator_attested',
      storedApproverId: 'cfo@acme.example',
      directoryUserId: null,
      hasDirectory: false,
    });
  });

  function post(attestation: unknown) {
    return RegisterVerify.POST(jsonReq({ approver_id: 'cfo@acme.example', attestation }));
  }

  it('enrolls an ES256, UV credential and stores the real COSE key and derived SPKI', async () => {
    const res = await post(authenticator.register(goodCeremony()));
    expect(res.status).toBe(201);
    expect(db.calls.rpcs).toHaveLength(1);
    expect(db.calls.rpcs[0].params.p_credential).toMatchObject({
      credential_id: authenticator.credentialId,
      public_key_cose: authenticator.cosePublicKeyB64u,
      public_key_spki: authenticator.spkiB64u,
      sign_count: 0,
      transports: ['internal'],
      attestation_fmt: 'none',
      key_class: 'A',
    });
  });

  it.each(REGISTRATION_NEGATIVES)('refuses %s without consuming the challenge', async (_label, bend, reason) => {
    const res = await post(authenticator.register(goodCeremony(bend)));
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.type).toContain('attestation_invalid');
    expect(body.detail).toMatch(reason);
    expect(db.calls.rpcs).toHaveLength(0);
  });

  it.each(ALGORITHM_NEGATIVES)('refuses %s without consuming the challenge', async (_label, key) => {
    const res = await post(authenticator.register({ ...goodCeremony(), coseKeyOverride: key() as any }));
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.type).toContain('attestation_invalid');
    expect(body.detail).toMatch(/Unexpected public key alg/);
    expect(db.calls.rpcs).toHaveLength(0);
  });
});

// ── 5. Authentication: Class-A signoff approval route ─────────────────────

function signoffClient({ signCount }: { signCount: number }) {
  const calls = { updates: [] as any[], inserts: [] as any[], rpcs: [] as any[] };
  const ceremony = buildCeremonyBinding({
    policy: signoffCeremonyPolicy(),
    phrase: signoffConfirmationPhrase(ACTION_TYPE, ACTION_HASH),
    reviewStartedAt: REVIEW_STARTED_AT,
  });
  let authenticator: Authenticator | null = null;
  function builder(table: string) {
    const state = { operation: 'select' };
    const b: any = {
      select: () => b,
      eq: () => b,
      is: () => b,
      in: () => b,
      order: () => b,
      limit: () => b,
      update(patch) { state.operation = 'update'; calls.updates.push({ table, patch }); return b; },
      insert(payload) { calls.inserts.push({ table, payload }); return Promise.resolve({ data: null, error: null }); },
      upsert() { return Promise.resolve({ data: null, error: null }); },
      single() { return Promise.resolve({ data: null, error: null }); },
      then(resolve) {
        if (table === 'webauthn_challenges') {
          if (state.operation === 'update') return resolve({ data: [{ id: 'ch_1' }], error: null });
          return resolve({
            data: [{
              id: 'ch_1',
              challenge: CHALLENGE,
              context: {
                action_hash: ACTION_HASH,
                display_hash: 'sha256:display',
                decision: 'approved',
                issued_at: ISSUED_AT,
                ceremony,
              },
              context_hash: 'sha256:context',
              expires_at: '2999-01-01T00:00:00.000Z',
            }],
            error: null,
          });
        }
        if (table === 'approver_credentials' && state.operation === 'select') {
          return resolve({
            data: [{
              credential_id: authenticator!.credentialId,
              public_key_cose: authenticator!.cosePublicKeyB64u,
              public_key_spki: authenticator!.spkiB64u,
              sign_count: signCount,
              transports: ['internal'],
              approver_id: 'cfo@example.com',
              approver_name: 'CFO',
              enrollment_basis: 'operator_attested',
              valid_from: null,
              valid_to: null,
              organization_id: 'org_1',
            }],
            error: null,
          });
        }
        return resolve({ data: [], error: null });
      },
    };
    return b;
  }
  return {
    calls,
    bind(a: Authenticator) { authenticator = a; },
    client: {
      from: builder,
      rpc: vi.fn(async (name, args) => {
        calls.rpcs.push({ name, args });
        return { data: { ok: true }, error: null };
      }),
    },
  };
}

// Each check with its authentication-side negative. The counter cases are
// evaluated against a stored sign_count of 5.
const AUTHENTICATION_NEGATIVES: Array<[string, Record<string, unknown>, RegExp]> = [
  ['wrong origin', { origin: EVIL_ORIGIN }, /origin "https:\/\/evil\.example"/],
  ['wrong RP ID', { rpId: EVIL_RP_ID }, /RP ID/],
  ['wrong challenge', { challenge: Buffer.from('another-ceremony').toString('base64url') }, /challenge/],
  ['user verification absent (UP only)', { flags: FLAG_UP }, /User verification required/],
  ['replayed counter (equal to stored)', { counter: 5 }, /counter value 5 was lower than expected 5/],
  ['rolled-back counter (below stored)', { counter: 3 }, /counter value 3 was lower than expected 5/],
  ['wrong ceremony type', { clientData: { type: 'webauthn.create' } }, /type/],
  ['a cross-origin iframe assertion (crossOrigin + topOrigin, new in v14)', {
    clientData: { crossOrigin: true, topOrigin: EVIL_ORIGIN },
  }, /cross-origin/],
  ['topOrigin without crossOrigin (spec violation, new in v14)', {
    clientData: { topOrigin: EVIL_ORIGIN },
  }, /top origin/],
];

describe('POST /api/v1/signoffs/:id/approve-webauthn against the real verifier', () => {
  let authenticator: Authenticator;
  beforeEach(() => {
    authenticator = createSoftAuthenticator();
    mocks.getGuardedClient.mockReset();
    mocks.loadSignoffForSigning.mockReset().mockResolvedValue({
      signoffId: SIGNOFF_ID,
      receiptId: `tr_${'b'.repeat(32)}`,
      organizationId: 'org_1',
      requestEvent: { after_state: { approver_id: 'cfo@example.com', required_assurance: 'A' } },
      createdState: { organization_id: 'org_1', action_type: ACTION_TYPE, action_hash: ACTION_HASH, required_assurance: 'A' },
      initiatorId: 'ep_entity_initiator',
      actionHash: ACTION_HASH,
      requestExpiresAt: '2999-01-01T00:00:00.000Z',
      alreadyDecided: false,
    });
  });

  async function approve(signCount: number, ceremonyOverrides: Record<string, unknown>) {
    const db = signoffClient({ signCount });
    db.bind(authenticator);
    mocks.getGuardedClient.mockReturnValue(db.client);
    const assertion = authenticator.assert(goodCeremony(ceremonyOverrides));
    const res = await ApproveWebAuthn.POST(
      jsonReq({ approver_id: 'cfo@example.com', decision: 'approved', assertion }),
      { params: Promise.resolve({ signoffId: SIGNOFF_ID }) },
    );
    return { res, db };
  }

  it('approves with a real assertion and forwards the new sign count', async () => {
    const { res, db } = await approve(5, { counter: 6 });
    expect(res.status).toBe(200);
    expect((await res.json())).toMatchObject({ decision: 'approved', key_class: 'A' });
    expect(db.calls.updates.find((u) => u.table === 'approver_credentials')?.patch).toEqual({ sign_count: 6 });
    expect(db.calls.inserts.find((i) => i.table === 'audit_events')?.payload.event_type).toBe('guard.signoff.approved');
  });

  it('keeps the counterless-authenticator rule: 0 after a stored 0 is accepted', async () => {
    const { res, db } = await approve(0, { counter: 0 });
    expect(res.status).toBe(200);
    expect(db.calls.updates.find((u) => u.table === 'approver_credentials')?.patch).toEqual({ sign_count: 0 });
  });

  it('accepts a same-origin assertion that states crossOrigin: false with no topOrigin', async () => {
    const { res } = await approve(5, { counter: 6, clientData: { crossOrigin: false } });
    expect(res.status).toBe(200);
  });

  it.each(AUTHENTICATION_NEGATIVES)('refuses %s and leaves challenge and counter untouched', async (_label, bend, reason) => {
    const { res, db } = await approve(5, { counter: 6, ...bend });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.type).toContain('assertion_invalid');
    expect(body.detail).toMatch(reason);
    expect(db.calls.updates).toHaveLength(0);
    expect(db.calls.inserts).toHaveLength(0);
    expect(db.calls.rpcs).toHaveLength(0);
  });

  it('refuses a tampered signature', async () => {
    const db = signoffClient({ signCount: 5 });
    db.bind(authenticator);
    mocks.getGuardedClient.mockReturnValue(db.client);
    const assertion = authenticator.assert(goodCeremony({ counter: 6 }));
    const sig = Buffer.from(assertion.response.signature, 'base64url');
    sig[sig.length - 1] ^= 0x01;
    assertion.response.signature = sig.toString('base64url');
    const res = await ApproveWebAuthn.POST(
      jsonReq({ approver_id: 'cfo@example.com', decision: 'approved', assertion }),
      { params: Promise.resolve({ signoffId: SIGNOFF_ID }) },
    );
    expect(res.status).toBe(400);
    expect(db.calls.updates).toHaveLength(0);
  });
});

// ── 6. Authentication: mobile pairing identity exchange ───────────────────

describe('POST /api/v1/mobile/pairings/exchange against the real verifier', () => {
  let authenticator: Authenticator;
  beforeEach(() => {
    authenticator = createSoftAuthenticator();
    mocks.getGuardedClient.mockReset().mockReturnValue({ service: true });
    mocks.exchangePairingVerified.mockReset().mockResolvedValue({
      ok: true,
      expires_at: '2999-01-01T00:00:00.000Z',
      approver_id: 'ep:approver:supervisor',
      profile_id: 'profile-1',
    });
  });

  async function exchange(signCount: number, ceremonyOverrides: Record<string, unknown>) {
    mocks.loadMobilePairingIdentityContext.mockReset().mockResolvedValue({
      entityRef: 'entity-1',
      organizationId: 'org_1',
      approverId: 'ep:approver:supervisor',
      credential: {
        credential_id: authenticator.credentialId,
        public_key_cose: authenticator.cosePublicKeyB64u,
        sign_count: signCount,
        // An unknown stored hint is dropped, a known one kept (closed set).
        transports: ['internal', 'carrier-pigeon'],
      },
    });
    return MobileExchange.POST(new Request('https://www.emiliaprotocol.ai/api/v1/mobile/pairings/exchange', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pairing_code: '2345-6789-ABCD',
        platform: 'ios',
        app_id: 'ai.emiliaprotocol.approver',
        identity_assertion: authenticator.assert(goodCeremony(ceremonyOverrides)),
      }),
    }) as any);
  }

  it('exchanges the code for a verified identity assertion and forwards the new sign count', async () => {
    const res = await exchange(5, { counter: 9 });
    expect(res.status).toBe(201);
    expect(mocks.exchangePairingVerified).toHaveBeenCalledWith({ service: true }, expect.objectContaining({
      credentialId: authenticator.credentialId,
      newSignCount: 9,
    }));
  });

  it.each(AUTHENTICATION_NEGATIVES)('refuses %s and never consumes the pairing', async (_label, bend) => {
    const res = await exchange(5, { counter: 9, ...bend });
    expect(res.status).toBe(400);
    expect((await res.json()).type).toContain('pairing_identity_invalid');
    expect(mocks.exchangePairingVerified).not.toHaveBeenCalled();
  });
});

// ── 7. Authentication: the multi-origin form Release Lock uses ────────────

describe('verifyAuthenticationResponse with an allowed-origin list (Release Lock form)', () => {
  it('accepts a listed origin and refuses an unlisted one', async () => {
    const authenticator = createSoftAuthenticator();
    const verify = (origin: string) => verifyAuthenticationResponse({
      response: authenticator.assert(goodCeremony({ origin, counter: 2 })) as any,
      expectedChallenge: CHALLENGE,
      expectedOrigin: [RP.origin],
      expectedRPID: RP.rpID,
      credential: { id: authenticator.credentialId, publicKey: authenticator.cosePublicKey, counter: 1 },
      requireUserVerification: true,
    });
    await expect(verify(RP.origin)).resolves.toMatchObject({
      verified: true,
      authenticationInfo: { newCounter: 2, userVerified: true },
    });
    await expect(verify(EVIL_ORIGIN)).rejects.toThrow(/origin/i);
  });
});

// ── 8. Transport hints: EP keeps the closed set v14 stopped typing ────────

describe('WebAuthn transport allowlist', () => {
  it('is exactly the v13 AuthenticatorTransportFuture union', () => {
    expect([...WEBAUTHN_AUTHENTICATOR_TRANSPORTS]).toEqual([
      'ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb',
    ]);
    expect(Object.isFrozen(WEBAUTHN_AUTHENTICATOR_TRANSPORTS)).toBe(true);
  });

  it.each([
    ['internal', true],
    ['smart-card', true],
    ['carrier-pigeon', false],
    ['INTERNAL', false],
    ['', false],
    [null, false],
    [['usb'], false],
    [7, false],
  ])('classifies %j as %s', (value, expected) => {
    expect(isWebAuthnAuthenticatorTransport(value)).toBe(expected);
  });
});
