// SPDX-License-Identifier: Apache-2.0
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  MOBILE_ANDROID_DEBUG_KEY_HASH,
  getMobileConfig,
  mobileAndroidOrigin,
  normalizeAndroidSigningCertificate,
} from '@/lib/mobile/config.js';
import {
  authenticateMobileToken,
  commitMobileActionDecision,
  createDemoAction,
  createGraceMobileActionGroup,
  createMobileAuditLog,
  createMobileCounterStore,
  createMobileEnrollmentDirectory,
  createMobileStateBackend,
  createPairing,
  exchangePairing,
  exchangePairingVerified,
  listMobilePairingIdentityCredentials,
  loadMobilePairingIdentityContext,
  listMobileActions,
  lookupMobileCeremonyResult,
  mobilePairingIdentityChallenge,
  registerMobileActionChallenge,
  resolveMobileAction,
  revokeMobileSession,
  sha256Hex,
} from '@/lib/mobile/store.js';
import { mobileSessionAuthorizes } from '@/lib/mobile/runtime.js';
import { verifyEvidenceRecord } from '@/packages/gate/evidence.js';
import { hashCanonical } from '@/packages/mobile/index.js';

const RELEASE_CERTIFICATE_HEX = '05'.repeat(32);
const PRESENTATION = Object.freeze({
  '@version': 'EP-MOBILE-PRESENTATION-v1',
  title: 'Release funds',
  summary: 'Release the pending treasury disbursement.',
  risk: 'high',
  consequence: 'Funds will be transferred to the approved destination.',
  material_fields: Object.freeze({ amount: '$125,000' }),
});

function signedDecisionEvidence({
  decision = 'approved',
  actionReference = 'mobile-action-reference-0001',
  actionCaid = `caid:1:emilia.mobile.authorized-action.1:jcs-sha256:${'A'.repeat(43)}`,
  actionDigest = `sha256:${'c'.repeat(64)}`,
  actionHash = `sha256:${'a'.repeat(64)}`,
  profileHash = `sha256:${'b'.repeat(64)}`,
  approverId = 'approver-1',
  deviceKeyId = 'device-1',
} = {}) {
  const context = {
    ep_version: '1.0',
    context_type: 'ep.signoff.v1',
    action_reference: actionReference,
    action_caid: actionCaid,
    action_digest: actionDigest,
    action_hash: actionHash,
    policy_id: 'policy-1',
    policy_hash: null,
    initiator: 'agent-1',
    approver: approverId,
    approver_index: 1,
    required_approvals: 1,
    nonce: 'sig_0123456789abcdef0123456789abcdef',
    issued_at: '2026-07-16T20:00:00.000Z',
    expires_at: '2026-07-16T20:05:00.000Z',
    decision,
    display_hash: `sha256:${'d'.repeat(64)}`,
    mobile_binding: {
      profile: 'EP-MOBILE-CHALLENGE-v2',
      profile_hash: profileHash,
      platform: 'ios',
      app_id: 'ai.emiliaprotocol.approver',
      device_key_id: deviceKeyId,
      credential_id: 'Y3JlZGVudGlhbC0x',
      attestation_key_id: 'apple-key-1',
    },
  };
  return {
    context,
    signoff: {
      context_hash: hashCanonical(context),
      key_class: 'A',
      approver_key_id: deviceKeyId,
      signed_at: context.issued_at,
      webauthn: {
        authenticator_data: 'YXV0aC1kYXRh',
        client_data_json: 'Y2xpZW50LWRhdGE',
        signature: 'c2lnbmF0dXJl',
      },
    },
  };
}

function decisionAuditEntry(evidence, challengeId = 'challenge-0001') {
  return {
    event_type: 'mobile.ceremony.decision',
    challenge_id: challengeId,
    action_hash: evidence.context.action_hash,
    profile_hash: evidence.context.mobile_binding.profile_hash,
    verdict: 'verified',
    decision: evidence.context.decision,
    approver_id: evidence.context.approver,
    device_key_id: evidence.context.mobile_binding.device_key_id,
    context_hash: evidence.signoff.context_hash,
  };
}

function chain(result) {
  const value = {};
  for (const method of ['insert', 'update', 'select', 'eq', 'is', 'gt', 'gte', 'lte', 'order', 'limit']) {
    value[method] = vi.fn(() => value);
  }
  value.maybeSingle = vi.fn(async () => result);
  value.single = vi.fn(async () => result);
  value.then = (resolve, reject) => Promise.resolve(result).then(resolve, reject);
  return value;
}

describe('mobile production configuration', () => {
  it('pins the permanent app identities and the directly served www relying party', () => {
    const config = getMobileConfig({ env: {}, production: false });
    expect(config.iosBundleId).toBe('ai.emiliaprotocol.approver');
    expect(config.androidPackageName).toBe('ai.emiliaprotocol.approver');
    expect(config.rpId).toBe('www.emiliaprotocol.ai');
    expect(config.iosOrigin).toBe('https://www.emiliaprotocol.ai');
    expect(config.androidOrigins).toEqual([mobileAndroidOrigin(MOBILE_ANDROID_DEBUG_KEY_HASH)]);
    expect(config.appleEnvironment).toBe('development');
  });

  it('does not silently trust a debug Android identity in production', () => {
    expect(() => getMobileConfig({ env: {}, production: true })).toThrow(/MOBILE_ANDROID_SIGNING_CERT_SHA256/);
  });

  it('derives every Android trust surface from one normalized signing certificate', () => {
    const normalized = normalizeAndroidSigningCertificate(RELEASE_CERTIFICATE_HEX);
    const config = getMobileConfig({
      env: { MOBILE_ANDROID_SIGNING_CERT_SHA256: normalized.assetLinks },
      production: true,
    });
    expect(config.androidSigningCertificateSha256Hex).toBe(normalized.hex);
    expect(config.androidKeyHashes).toEqual([normalized.base64url]);
    expect(config.androidCertificateDigests).toEqual([normalized.base64url]);
    expect(config.androidOrigins).toEqual([mobileAndroidOrigin(normalized.base64url)]);
    expect(config.androidAssetLinksFingerprints).toEqual([normalized.assetLinks]);
    for (const legacyName of [
      'MOBILE_ANDROID_APK_KEY_HASHES',
      'MOBILE_ANDROID_CERTIFICATE_DIGESTS',
      'MOBILE_ANDROID_ASSETLINKS_CERT_SHA256',
    ]) {
      expect(() => getMobileConfig({
        env: {
          MOBILE_ANDROID_SIGNING_CERT_SHA256: RELEASE_CERTIFICATE_HEX,
          [legacyName]: '06'.repeat(32),
        },
        production: true,
      })).toThrow(/does not match/);
    }
  });

  it('rejects malformed platform pins', () => {
    expect(() => mobileAndroidOrigin()).toThrow(/APK key hash/);
    expect(() => mobileAndroidOrigin('short')).toThrow(/APK key hash/);
    expect(() => getMobileConfig({ env: { MOBILE_APPLE_TEAM_ID: 'bad' } })).toThrow(/Team ID/);
    expect(() => getMobileConfig({ env: { MOBILE_IOS_ORIGIN: 'http://example.com' } })).toThrow(/HTTPS/);
    expect(() => getMobileConfig({ env: { MOBILE_ANDROID_APK_KEY_HASHES: 'bad' } })).toThrow(/MOBILE_ANDROID_APK_KEY_HASHES/);
    expect(() => getMobileConfig({ env: { MOBILE_ANDROID_CERTIFICATE_DIGESTS: '!' } })).toThrow(/MOBILE_ANDROID_CERTIFICATE_DIGESTS/);
    expect(() => getMobileConfig({ env: { MOBILE_IOS_BUNDLE_ID: 'not-a-bundle' } })).toThrow(/reverse-domain/);
    expect(() => getMobileConfig({ env: { MOBILE_RP_ID: 'HTTPS://EXAMPLE.COM' } })).toThrow(/lowercase DNS/);
    expect(() => getMobileConfig({ env: { MOBILE_IOS_ORIGIN: 'https://www.emiliaprotocol.ai/path' } })).toThrow(/HTTPS origin/);
    expect(() => getMobileConfig({ env: { MOBILE_CHALLENGE_TTL_MS: '999999999' } })).toThrow(/MOBILE_CHALLENGE_TTL_MS/);
    expect(() => getMobileConfig({ env: { MOBILE_PROFILE_ID: 'bad profile!' } })).toThrow(/PROFILE_ID/);
    expect(() => getMobileConfig({ env: { MOBILE_IOS_ORIGIN: 'not a URL' } })).toThrow(/HTTPS origin/);
    expect(() => getMobileConfig({ env: { MOBILE_ANDROID_ALLOWED_VERSION_CODES: '0' } })).toThrow(/positive safe integers/);
    expect(() => getMobileConfig({ env: { MOBILE_APPLE_ALLOWED_VALIDATION_CATEGORIES: '7' } })).toThrow(/reserved or unknown/);
    expect(() => getMobileConfig({ env: { MOBILE_APPLE_ALLOWED_BUNDLE_VERSIONS: 'bad version' } })).toThrow(/invalid version/);
    expect(() => getMobileConfig({ env: { MOBILE_APPLE_REQUIRE_RUNTIME_SIGNALS: 'sometimes' } })).toThrow(/true or false/);
  });

  it('parses explicit boolean and version-list policy without weakening pins', () => {
    const strict = getMobileConfig({
      env: {
        MOBILE_ANDROID_SIGNING_CERT_SHA256: RELEASE_CERTIFICATE_HEX,
        MOBILE_APPLE_REQUIRE_RUNTIME_SIGNALS: 'true',
        MOBILE_ANDROID_REQUIRE_PLAY_PROTECT: 'false',
        MOBILE_ANDROID_ALLOWED_VERSION_CODES: '1,2,2',
        MOBILE_APPLE_ALLOWED_VALIDATION_CATEGORIES: '2,4',
      },
      production: true,
    });
    expect(strict.appleRequireRuntimeSignals).toBe(true);
    expect(strict.androidRequirePlayProtect).toBe(false);
    expect(strict.androidAllowedVersionCodes).toEqual([1, 2]);
  });

  it('retains mandatory app-version and validation-category pins when an environment value is blank', () => {
    const config = getMobileConfig({
      env: {
        MOBILE_ANDROID_SIGNING_CERT_SHA256: RELEASE_CERTIFICATE_HEX,
        MOBILE_ANDROID_ALLOWED_VERSION_CODES: '',
        MOBILE_APPLE_ALLOWED_VALIDATION_CATEGORIES: '',
      },
      production: true,
    });
    expect(config.androidAllowedVersionCodes).toEqual([1]);
    expect(config.appleAllowedValidationCategories).toEqual([2, 4]);
  });
});

describe('mobile session authorization', () => {
  const session = {
    approver_id: 'approver-1',
    profile_id: 'profile-1',
    platform: 'ios',
    app_id: 'ai.emiliaprotocol.approver',
    device_key_id: 'ep:key:device-1',
  };

  it('binds every ceremony to the exact enrolled device and session identity', () => {
    expect(mobileSessionAuthorizes(session, {
      approver_id: 'approver-1',
      profile_id: 'profile-1',
      platform: 'ios',
      app_id: 'ai.emiliaprotocol.approver',
      device_key_id: 'ep:key:device-1',
    })).toBe(true);
    for (const mutation of [
      { approver_id: 'attacker' },
      { profile_id: 'weaker-profile' },
      { platform: 'android' },
      { app_id: 'attacker.app' },
      { device_key_id: 'ep:key:device-2' },
      { device_key_id: null },
    ]) {
      expect(mobileSessionAuthorizes(session, {
        approver_id: 'approver-1',
        profile_id: 'profile-1',
        platform: 'ios',
        app_id: 'ai.emiliaprotocol.approver',
        device_key_id: 'ep:key:device-1',
        ...mutation,
      })).toBe(false);
    }
  });

  it('permits enrollment only while the paired session is still unbound', () => {
    const unbound = { ...session, device_key_id: null };
    const input = {
      approver_id: 'approver-1',
      profile_id: 'profile-1',
      platform: 'ios',
      app_id: 'ai.emiliaprotocol.approver',
      device_key_id: null,
    };
    expect(mobileSessionAuthorizes(unbound, input)).toBe(true);
    expect(mobileSessionAuthorizes(session, input)).toBe(false);
    expect(mobileSessionAuthorizes(null, input)).toBe(false);
  });
});

describe('durable mobile storage adapters', () => {
  let from;
  let rpc;

  beforeEach(() => {
    from = vi.fn();
    rpc = vi.fn();
  });

  it('uses compare-and-set state and refuses database ambiguity', async () => {
    const found = chain({ data: { state_key: 'challenge:1' }, error: null });
    from.mockReturnValueOnce(found);
    rpc
      .mockResolvedValueOnce({ data: true, error: null })
      .mockResolvedValueOnce({ data: true, error: null });
    const backend = createMobileStateBackend({ from, rpc });
    expect(backend.durable).toBe(true);
    expect(await backend.addIfAbsent('challenge:0123456789', 'issued')).toBe(true);
    expect(await backend.compareAndSet('challenge:0123456789', 'issued', 'consumed')).toBe(true);
    expect(await backend.has('challenge:0123456789')).toBe(true);
    expect(rpc).toHaveBeenNthCalledWith(1, 'mobile_state_add_if_absent', {
      p_state_key: 'challenge:0123456789',
      p_state_value: 'issued',
    });
    expect(rpc).toHaveBeenNthCalledWith(2, 'mobile_state_compare_and_set', expect.objectContaining({
      p_state_key: 'challenge:0123456789',
      p_expected: 'issued',
      p_replacement: 'consumed',
    }));

    const duplicate = createMobileStateBackend({ from, rpc: vi.fn().mockResolvedValue({ data: false, error: null }) });
    expect(await duplicate.addIfAbsent('challenge:0123456789', 'issued')).toBe(false);
    const broken = createMobileStateBackend({
      from,
      rpc: vi.fn().mockResolvedValue({ data: null, error: { code: '08006', message: 'down' } }),
    });
    await expect(broken.addIfAbsent('challenge:0123456789', 'issued')).rejects.toThrow(/mobile state insert failed/);

    expect(() => createMobileStateBackend(null)).toThrow(/Supabase client/);
    const compareUnavailable = createMobileStateBackend({
      from,
      rpc: vi.fn().mockResolvedValue({ data: null, error: { code: '08006' } }),
    });
    await expect(compareUnavailable.compareAndSet(
      'challenge:0123456789',
      'issued',
      'consumed',
    )).rejects.toThrow(/08006/);
    const lookupUnavailable = createMobileStateBackend({
      from: vi.fn(() => chain({ data: null, error: {} })),
      rpc,
    });
    await expect(lookupUnavailable.has('challenge:0123456789')).rejects.toThrow(/database operation failed/);
  });

  it('advances hardware counters and appends the verifier-native portable record', async () => {
    let persisted = null;
    rpc.mockImplementation(async (name, args) => {
      if (name === 'advance_mobile_counter') return { data: true, error: null };
      if (name === 'append_mobile_evidence_record') {
        persisted = structuredClone(args.p_record);
        return { data: true, error: null };
      }
      throw new Error(`unexpected RPC ${name}`);
    });
    from
      .mockReturnValueOnce(chain({ data: null, error: null }))
      .mockReturnValueOnce(chain({ data: null, error: null }))
      .mockImplementationOnce(() => chain({ data: { record: persisted }, error: null }));
    expect(await createMobileCounterStore({ rpc }).advance('device-1', 4)).toBe(true);
    expect(await createMobileCounterStore({ rpc }).advance('', -1)).toBe(false);
    const event = { event_type: 'mobile.test', nested: { stable: true } };
    const auditLog = createMobileAuditLog({ rpc, from }, 'entity-1');
    const record = await auditLog.record(event);
    expect(record.record_id).toMatch(/^mar_[0-9a-f]{32}$/);
    expect(record.seq).toBe(0);
    expect(record.prev_hash).toBe('genesis');
    expect(verifyEvidenceRecord(record, { atomicRequired: true, expectedEntry: event })).toBe(true);
    expect(rpc).toHaveBeenCalledWith('append_mobile_evidence_record', expect.objectContaining({
      p_entity_ref: 'entity-1',
      p_expected_hash: null,
      p_record: record,
      p_canonical_body: expect.any(String),
    }));
    from
      .mockReturnValueOnce(chain({ data: [{ record }], error: null }))
      .mockReturnValueOnce(chain({ data: [{ record }], error: null }))
      .mockReturnValueOnce(chain({
        data: { record, record_hash: record.hash },
        error: null,
      }));
    await expect(auditLog.all()).resolves.toEqual([record]);
    await expect(auditLog.verify()).resolves.toEqual({
      ok: true,
      length: 1,
      head: record.hash,
    });

    expect(() => createMobileCounterStore({})).toThrow(/Supabase client/);
    await expect(createMobileCounterStore({
      rpc: vi.fn().mockResolvedValue({ data: null, error: { code: '08006' } }),
    }).advance('device-1', 5)).rejects.toThrow(/mobile counter advance failed/);
    expect(() => createMobileAuditLog({ rpc: vi.fn() }, 'entity-1')).toThrow(/entityRef/);

    const recordLookupUnavailable = createMobileAuditLog({
      from: vi.fn(() => chain({ data: null, error: { code: '08006' } })),
      rpc: vi.fn(),
    }, 'entity-1');
    await expect(recordLookupUnavailable.record({ event_type: 'mobile.test' })).rejects.toThrow(/record lookup failed/);

    const headFrom = vi.fn()
      .mockReturnValueOnce(chain({ data: null, error: null }))
      .mockReturnValueOnce(chain({ data: null, error: { code: '08006' } }));
    const headUnavailable = createMobileAuditLog({
      from: headFrom,
      rpc: vi.fn(),
    }, 'entity-1');
    await expect(headUnavailable.record({ event_type: 'mobile.test' })).rejects.toThrow(/head lookup failed/);

    const appendUnavailable = createMobileAuditLog({
      from: vi.fn(() => chain({ data: null, error: null })),
      rpc: vi.fn().mockResolvedValue({ data: null, error: { code: '08006' } }),
    }, 'entity-1');
    await expect(appendUnavailable.record({ event_type: 'mobile.test' })).rejects.toThrow(/append_indeterminate/);

    const historyUnavailable = createMobileAuditLog({
      from: vi.fn(() => chain({ data: null, error: { code: '08006' } })),
      rpc: vi.fn(),
    }, 'entity-1');
    await expect(historyUnavailable.all()).rejects.toThrow(/mobile evidence history lookup failed/);
  });

  it('loads only active enrollments and preserves each platform public key', async () => {
    const active = chain({ data: [{ device_key_id: 'device-1' }], error: null });
    const apple = chain({ data: { platform_public_key: 'pem', status: 'active' }, error: null });
    from.mockReturnValueOnce(active).mockReturnValueOnce(apple);
    rpc.mockResolvedValueOnce({ data: true, error: null });
    const directory = createMobileEnrollmentDirectory({ from, rpc }, 'entity-1', 'session-1');
    expect(await directory.active()).toEqual([{ device_key_id: 'device-1' }]);
    expect((await directory.platformKey('apple-key', 'ios')).platform_public_key).toBe('pem');
    expect(await directory.enrollAtomically({ enrollment: {}, event: {} })).toBe(true);
    expect(rpc).toHaveBeenCalledWith('enroll_mobile_device', expect.objectContaining({ p_session_id: 'session-1' }));

    expect(() => createMobileEnrollmentDirectory(null, 'entity-1', 'session-1')).toThrow(/Supabase client/);
    await expect(directory.platformKey('apple-key', 'web')).rejects.toThrow(/platform key lookup is malformed/);

    const enrollmentUnavailable = createMobileEnrollmentDirectory({
      from: vi.fn(() => chain({ data: null, error: { code: '08006' } })),
      rpc: vi.fn().mockResolvedValue({ data: null, error: { code: '08006' } }),
    }, 'entity-1', 'session-1');
    await expect(enrollmentUnavailable.enrollAtomically({
      enrollment: {},
      event: {},
    })).rejects.toThrow(/enrollment insert failed/);
    await expect(enrollmentUnavailable.active()).rejects.toThrow(/directory unavailable/);
    await expect(enrollmentUnavailable.platformKey('apple-key', 'ios')).rejects.toThrow(/platform key lookup failed/);

    const emptyDirectory = createMobileEnrollmentDirectory({
      from: vi.fn(() => chain({ data: null, error: null })),
      rpc,
    }, 'entity-1', 'session-1');
    expect(await emptyDirectory.active()).toEqual([]);
    expect(await emptyDirectory.platformKey('apple-key', 'ios')).toBeNull();
  });

  it('hashes pairings and mobile bearer tokens without storing either secret', async () => {
    const sessionLookup = chain({
      data: {
        session_id: '00000000-0000-0000-0000-000000000001',
        entity_ref: 'entity-1',
        approver_id: 'approver-1',
        profile_id: 'profile-1',
        platform: 'ios',
        app_id: 'ai.emiliaprotocol.approver',
        device_key_id: 'ep:key:mobile-device-1',
        expires_at: '2026-08-15T00:00:00.000Z',
      },
      error: null,
    });
    from.mockReturnValueOnce(sessionLookup);
    rpc.mockImplementation(async (name) => {
      if (name === 'create_mobile_pairing_verified') return { data: true, error: null };
      if (name === 'touch_mobile_session_verified') return { data: true, error: null };
      throw new Error(`unexpected RPC ${name}`);
    });
    const supabase = { from, rpc };
    await createPairing(supabase, {
      code: 'ABCD-EFGH-JKLM',
      entityRef: 'entity-1',
      organizationId: '@org:entity-1',
      approverId: 'approver-1',
      directoryUserId: '00000000-0000-0000-0000-000000000099',
      profileId: 'profile-1',
      allowedApps: { ios: ['ai.emiliaprotocol.approver'], android: [] },
      expiresAt: '2026-07-15T01:00:00.000Z',
      sessionExpiresAt: '2026-08-15T00:00:00.000Z',
    });
    expect(rpc).toHaveBeenCalledWith('create_mobile_pairing_verified', expect.objectContaining({
      p_code_hash: sha256Hex('ABCD-EFGH-JKLM'),
      p_organization_id: '@org:entity-1',
      p_directory_user_id: '00000000-0000-0000-0000-000000000099',
      p_allowed_apps: { ios: ['ai.emiliaprotocol.approver'], android: [] },
    }));
    await expect(exchangePairing(supabase, {
      code: 'ABCD-EFGH-JKLM',
      token: `ep_mobile_${'a'.repeat(43)}`,
      platform: 'ios',
      appId: 'ai.emiliaprotocol.approver',
    })).rejects.toThrow('unverified_mobile_pairing_exchange_disabled');
    expect(await authenticateMobileToken(supabase, `Bearer ep_mobile_${'a'.repeat(43)}`)).toMatchObject({ entity_ref: 'entity-1' });
    expect(rpc).toHaveBeenCalledWith('touch_mobile_session_verified', expect.objectContaining({
      p_token_hash: sha256Hex(`ep_mobile_${'a'.repeat(43)}`),
    }));
    expect(await authenticateMobileToken(supabase, 'Bearer attacker-token')).toBeNull();
    expect(await authenticateMobileToken(supabase)).toBeNull();

    const pairingInput = {
      code: 'ABCD-EFGH-JKLM',
      entityRef: 'entity-1',
      organizationId: '@org:entity-1',
      approverId: 'approver-1',
      directoryUserId: '00000000-0000-0000-0000-000000000099',
      profileId: 'profile-1',
      allowedApps: { ios: ['ai.emiliaprotocol.approver'], android: [] },
      expiresAt: '2026-07-15T01:00:00.000Z',
      sessionExpiresAt: '2026-08-15T00:00:00.000Z',
    };
    await expect(createPairing({
      rpc: vi.fn().mockResolvedValue({ data: null, error: { code: '08006' } }),
    }, pairingInput)).rejects.toThrow(/pairing creation failed/);
    await expect(createPairing({
      rpc: vi.fn().mockResolvedValue({ data: false, error: null }),
    }, pairingInput)).rejects.toThrow(/pairing creation refused/);
    await expect(exchangePairing({ rpc: vi.fn() }, {
      code: pairingInput.code,
      token: `ep_mobile_${'a'.repeat(43)}`,
      platform: 'ios',
      appId: 'ai.emiliaprotocol.approver',
    })).rejects.toThrow('unverified_mobile_pairing_exchange_disabled');

    await expect(authenticateMobileToken({
      from: vi.fn(() => chain({ data: null, error: { code: '08006' } })),
      rpc: vi.fn(),
    }, `Bearer ep_mobile_${'a'.repeat(43)}`)).rejects.toThrow(/session lookup failed/);
    expect(await authenticateMobileToken({
      from: vi.fn(() => chain({ data: null, error: null })),
      rpc: vi.fn(),
    }, `Bearer ep_mobile_${'a'.repeat(43)}`)).toBeNull();
    await expect(authenticateMobileToken({
      from: vi.fn(() => chain({
        data: {
          session_id: '00000000-0000-0000-0000-000000000001',
          expires_at: '2999-01-01T00:00:00.000Z',
        },
        error: null,
      })),
      rpc: vi.fn().mockResolvedValue({ data: null, error: { code: '08006' } }),
    }, `Bearer ep_mobile_${'a'.repeat(43)}`)).rejects.toThrow(/session update failed/);
  });

  it('derives a canonical, code-bound mobile pairing identity challenge', () => {
    const challenge = mobilePairingIdentityChallenge('  abcd-efgh-jklm  ');
    expect(challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(challenge).toBe(mobilePairingIdentityChallenge('ABCD-EFGH-JKLM'));
    expect(challenge).not.toBe(mobilePairingIdentityChallenge('ABCD-EFGH-JKLN'));
  });

  it('lists only live directory-backed Class-A pairing credentials', async () => {
    const credentials = chain({
      data: [
        {
          credential_id: 'credential-live-1',
          transports: ['internal', 'hybrid'],
          directory_user_id: 'directory-user-1',
          valid_from: '2026-08-01T00:00:00.000Z',
          valid_to: '2026-09-01T00:00:00.000Z',
        },
        {
          credential_id: 'credential-live-2',
          transports: [],
          directory_user_id: 'directory-user-1',
          valid_from: null,
          valid_to: null,
        },
        {
          credential_id: 'credential-expired',
          transports: ['internal'],
          directory_user_id: 'directory-user-1',
          valid_from: '2026-07-01T00:00:00.000Z',
          valid_to: '2026-08-26T11:59:59.999Z',
        },
        {
          credential_id: 'credential-future',
          transports: null,
          directory_user_id: 'directory-user-1',
          valid_from: '2026-08-26T12:00:00.001Z',
          valid_to: null,
        },
        {
          credential_id: 'credential-unbound',
          transports: null,
          directory_user_id: null,
          valid_from: null,
          valid_to: null,
        },
      ],
      error: null,
    });
    const supabase = { from: vi.fn(() => credentials) };

    await expect(listMobilePairingIdentityCredentials(supabase, {
      organizationId: '@org:entity-1',
      approverId: 'approver-1',
      directoryUserId: 'directory-user-1',
      now: '2026-08-26T12:00:00.000Z',
    })).resolves.toEqual([
      { id: 'credential-live-1', type: 'public-key', transports: ['internal', 'hybrid'] },
      { id: 'credential-live-2', type: 'public-key' },
    ]);
    expect(supabase.from).toHaveBeenCalledWith('approver_credentials');
    expect(credentials.eq).toHaveBeenCalledWith('organization_id', '@org:entity-1');
    expect(credentials.eq).toHaveBeenCalledWith('approver_id', 'approver-1');
    expect(credentials.eq).toHaveBeenCalledWith('directory_user_id', 'directory-user-1');
    expect(credentials.eq).toHaveBeenCalledWith('key_class', 'A');
    expect(credentials.eq).toHaveBeenCalledWith('enrollment_basis', 'directory');
    expect(credentials.is).toHaveBeenCalledWith('revoked_at', null);

    const invalidNow = await listMobilePairingIdentityCredentials({
      from: vi.fn(() => chain({
        data: [{
          credential_id: 'credential-live-1',
          transports: ['internal'],
          directory_user_id: 'directory-user-1',
          valid_from: null,
          valid_to: null,
        }],
        error: null,
      })),
    }, {
      organizationId: '@org:entity-1',
      approverId: 'approver-1',
      directoryUserId: 'directory-user-1',
      now: 'not-an-instant',
    });
    expect(invalidNow).toEqual([]);

    await expect(listMobilePairingIdentityCredentials({
      from: vi.fn(() => chain({ data: null, error: { message: 'directory offline' } })),
    }, {
      organizationId: '@org:entity-1',
      approverId: 'approver-1',
      directoryUserId: 'directory-user-1',
    })).rejects.toThrow(/mobile pairing credential directory failed: directory offline/);
  });

  it('loads the exact live directory identity bound to a mobile pairing', async () => {
    const pairing = {
      entity_ref: 'entity-1',
      organization_id: '@org:entity-1',
      approver_id: 'approver-1',
      directory_user_id: 'directory-user-1',
      expires_at: '2026-08-26T12:05:00.000Z',
      consumed_at: null,
    };
    const entity = {
      entity_id: 'entity-1',
      organization_id: '@org:entity-1',
      status: 'active',
    };
    const directoryUser = {
      id: 'directory-user-1',
      tenant_id: 'tenant-1',
      user_name: 'approver-1',
      active: true,
    };
    const credential = {
      credential_id: 'credential-1',
      public_key_cose: 'cose-public-key',
      sign_count: '7',
      transports: ['internal'],
      approver_id: 'approver-1',
      organization_id: '@org:entity-1',
      key_class: 'A',
      enrollment_basis: 'directory',
      directory_user_id: 'directory-user-1',
      valid_from: '2026-08-01T00:00:00.000Z',
      valid_to: '2026-09-01T00:00:00.000Z',
      revoked_at: null,
    };
    const rows = {
      mobile_pairings: { data: pairing, error: null },
      entities: { data: entity, error: null },
      scim_users: { data: directoryUser, error: null },
      scim_provisioning_tokens: { data: { id: 'token-1' }, error: null },
      approver_credentials: { data: credential, error: null },
    };
    const supabase = {
      from: vi.fn((table) => chain(rows[table])),
    };

    await expect(loadMobilePairingIdentityContext(supabase, {
      code: 'ABCD-EFGH-JKLM',
      credentialId: 'credential-1',
      now: '2026-08-26T12:00:00.000Z',
    })).resolves.toEqual({
      entityRef: 'entity-1',
      organizationId: '@org:entity-1',
      approverId: 'approver-1',
      credential: {
        credential_id: 'credential-1',
        public_key_cose: 'cose-public-key',
        sign_count: 7,
        transports: ['internal'],
      },
    });
    expect(supabase.from).toHaveBeenNthCalledWith(1, 'mobile_pairings');
    expect(supabase.from).toHaveBeenNthCalledWith(2, 'entities');
    expect(supabase.from).toHaveBeenNthCalledWith(3, 'scim_users');
    expect(supabase.from).toHaveBeenNthCalledWith(4, 'scim_provisioning_tokens');
    expect(supabase.from).toHaveBeenNthCalledWith(5, 'approver_credentials');
  });

  it('rejects stale or cross-directory mobile pairing identity contexts', async () => {
    const valid = {
      mobile_pairings: {
        data: {
          entity_ref: 'entity-1',
          organization_id: '@org:entity-1',
          approver_id: 'approver-1',
          directory_user_id: 'directory-user-1',
          expires_at: '2026-08-26T12:05:00.000Z',
          consumed_at: null,
        },
        error: null,
      },
      entities: {
        data: { entity_id: 'entity-1', organization_id: '@org:entity-1', status: 'active' },
        error: null,
      },
      scim_users: {
        data: {
          id: 'directory-user-1', tenant_id: 'tenant-1', user_name: 'approver-1', active: true,
        },
        error: null,
      },
      scim_provisioning_tokens: { data: { id: 'token-1' }, error: null },
      approver_credentials: {
        data: {
          credential_id: 'credential-1',
          public_key_cose: 'cose-public-key',
          sign_count: 0,
          transports: null,
          approver_id: 'approver-1',
          organization_id: '@org:entity-1',
          key_class: 'A',
          enrollment_basis: 'directory',
          directory_user_id: 'directory-user-1',
          valid_from: null,
          valid_to: null,
          revoked_at: null,
        },
        error: null,
      },
    };
    const load = async (overrides = {}, now = '2026-08-26T12:00:00.000Z') => {
      const rows = { ...valid, ...overrides };
      return loadMobilePairingIdentityContext({
        from: vi.fn((table) => chain(rows[table])),
      }, { code: 'ABCD-EFGH-JKLM', credentialId: 'credential-1', now });
    };

    await expect(load({
      mobile_pairings: {
        data: { ...valid.mobile_pairings.data, consumed_at: '2026-08-26T11:59:00.000Z' },
        error: null,
      },
    })).resolves.toBeNull();
    await expect(load({}, '2026-08-26T12:06:00.000Z')).resolves.toBeNull();
    await expect(load({
      entities: {
        data: { ...valid.entities.data, organization_id: '@org:attacker' },
        error: null,
      },
    })).resolves.toBeNull();
    await expect(load({
      scim_users: {
        data: { ...valid.scim_users.data, user_name: 'different-approver' },
        error: null,
      },
    })).resolves.toBeNull();
    await expect(load({ scim_provisioning_tokens: { data: null, error: null } })).resolves.toBeNull();
    await expect(load({
      approver_credentials: {
        data: { ...valid.approver_credentials.data, organization_id: '@org:attacker' },
        error: null,
      },
    })).resolves.toBeNull();
    await expect(load({}, 'not-an-instant')).resolves.toBeNull();
  });

  it('fails closed when any mobile pairing identity directory lookup fails', async () => {
    const tableOrder = [
      'mobile_pairings',
      'entities',
      'scim_users',
      'scim_provisioning_tokens',
      'approver_credentials',
    ];
    const successfulRows = {
      mobile_pairings: {
        entity_ref: 'entity-1',
        organization_id: '@org:entity-1',
        approver_id: 'approver-1',
        directory_user_id: 'directory-user-1',
        expires_at: '2026-08-26T12:05:00.000Z',
        consumed_at: null,
      },
      entities: { entity_id: 'entity-1', organization_id: '@org:entity-1', status: 'active' },
      scim_users: {
        id: 'directory-user-1', tenant_id: 'tenant-1', user_name: 'approver-1', active: true,
      },
      scim_provisioning_tokens: { id: 'token-1' },
      approver_credentials: {
        credential_id: 'credential-1',
        public_key_cose: 'cose-public-key',
        sign_count: 1,
        transports: null,
        approver_id: 'approver-1',
        organization_id: '@org:entity-1',
        key_class: 'A',
        enrollment_basis: 'directory',
        directory_user_id: 'directory-user-1',
        valid_from: null,
        valid_to: null,
        revoked_at: null,
      },
    };
    for (const failedTable of tableOrder) {
      const supabase = {
        from: vi.fn((table) => chain(table === failedTable
          ? { data: null, error: { message: `${table} unavailable` } }
          : { data: successfulRows[table], error: null })),
      };
      await expect(loadMobilePairingIdentityContext(supabase, {
        code: 'ABCD-EFGH-JKLM',
        credentialId: 'credential-1',
        now: '2026-08-26T12:00:00.000Z',
      })).rejects.toThrow(/mobile pairing .* lookup failed/);
    }
  });

  it('exchanges a pairing only through the proof-bound verified RPC', async () => {
    const input = {
      code: 'ABCD-EFGH-JKLM',
      token: `ep_mobile_${'a'.repeat(43)}`,
      platform: 'ios',
      appId: 'ai.emiliaprotocol.approver',
      credentialId: 'credential-1',
      approverId: 'approver-1',
      newSignCount: 8,
      identityProofDigest: `sha256:${'b'.repeat(64)}`,
    };
    const rpc = vi.fn().mockResolvedValue({
      data: { ok: true, session_id: 'session-1' },
      error: null,
    });
    await expect(exchangePairingVerified({ rpc }, input)).resolves.toEqual({
      ok: true,
      session_id: 'session-1',
    });
    expect(rpc).toHaveBeenCalledWith('exchange_mobile_pairing_verified', {
      p_code_hash: sha256Hex(input.code),
      p_token_hash: sha256Hex(input.token),
      p_platform: 'ios',
      p_app_id: 'ai.emiliaprotocol.approver',
      p_credential_id: 'credential-1',
      p_expected_approver_id: 'approver-1',
      p_new_sign_count: 8,
      p_identity_proof_digest: input.identityProofDigest,
    });
    await expect(exchangePairingVerified({
      rpc: vi.fn().mockResolvedValue({ data: null, error: null }),
    }, input)).resolves.toEqual({ ok: false, reason: 'invalid_or_expired' });
    await expect(exchangePairingVerified({
      rpc: vi.fn().mockResolvedValue({ data: null, error: { code: '40001' } }),
    }, input)).rejects.toThrow(/verified mobile pairing exchange failed: 40001/);
  });

  it('rejects non-canonical identity evidence before a mobile decision can reach storage', async () => {
    const base = signedDecisionEvidence();
    const malformedInstant = structuredClone(base);
    malformedInstant.context.issued_at = '2026-07-16T20:00:00Z';
    await expect(commitMobileActionDecision({}, {
      entityRef: 'entity-1',
      sessionId: 'session-1',
      challengeId: 'challenge-0001',
      actionHash: base.context.action_hash,
      decision: 'approved',
      verdict: 'verified',
      decisionEvidence: malformedInstant,
      auditEntry: decisionAuditEntry(base),
    })).rejects.toThrow(/stored approved mobile decision evidence is malformed/);

    const oversizedCredential = structuredClone(base);
    oversizedCredential.context.mobile_binding.credential_id = 'A'.repeat(3000);
    oversizedCredential.signoff.context_hash = hashCanonical(oversizedCredential.context);
    await expect(commitMobileActionDecision({}, {
      entityRef: 'entity-1',
      sessionId: 'session-1',
      challengeId: 'challenge-0001',
      actionHash: base.context.action_hash,
      decision: 'approved',
      verdict: 'verified',
      decisionEvidence: oversizedCredential,
      auditEntry: {
        ...decisionAuditEntry(oversizedCredential),
        context_hash: oversizedCredential.signoff.context_hash,
      },
    })).rejects.toThrow(/stored approved mobile decision evidence is malformed/);

    const nonCanonicalContext = structuredClone(base);
    nonCanonicalContext.context.policy_id = 1n;
    await expect(commitMobileActionDecision({}, {
      entityRef: 'entity-1',
      sessionId: 'session-1',
      challengeId: 'challenge-0001',
      actionHash: base.context.action_hash,
      decision: 'approved',
      verdict: 'verified',
      decisionEvidence: nonCanonicalContext,
      auditEntry: decisionAuditEntry(base),
    })).rejects.toThrow(/stored approved mobile decision evidence is malformed/);
  });

  it('surfaces a failed atomic challenge registration instead of treating it as denial', async () => {
    await expect(registerMobileActionChallenge({
      rpc: vi.fn().mockResolvedValue({ data: null, error: { message: 'database unavailable' } }),
    }, {
      entityRef: 'entity-1',
      sessionId: 'session-1',
      actionReference: 'action-0001',
      approverId: 'approver-1',
      challengeId: 'challenge-0001',
      actionHash: `sha256:${'a'.repeat(64)}`,
      decision: 'approved',
      expiresAt: '2026-07-15T01:00:00.000Z',
    })).rejects.toThrow(/mobile action challenge registration failed: database unavailable/);
  });

  it('refuses recovery rows that lack typed evidence or a terminal decision', async () => {
    const session = {
      entityRef: 'entity-1',
      sessionId: 'session-1',
      approverId: 'approver-1',
      platform: 'ios',
      appId: 'ai.emiliaprotocol.approver',
      deviceKeyId: 'device-1',
      challengeId: 'challenge-0001',
    };
    const challenge = {
      challenge_id: session.challengeId,
      session_id: session.sessionId,
      action_reference: 'action-0001',
      entity_ref: session.entityRef,
      approver_id: session.approverId,
      decision: 'approved',
      action_hash: `sha256:${'a'.repeat(64)}`,
      created_at: '2026-07-16T20:00:00.000Z',
      consumed_at: '2026-07-16T20:01:00.000Z',
      expires_at: '2026-07-16T20:05:00.000Z',
    };
    const action = {
      action_reference: 'action-0001',
      entity_ref: session.entityRef,
      approver_id: session.approverId,
      status: 'approved',
      decision_challenge_id: session.challengeId,
      decision_verdict: 'verified',
      decision_evidence: null,
      decided_at: challenge.consumed_at,
    };
    const lookup = (challengeRow, actionRow) => lookupMobileCeremonyResult({
      from: vi.fn()
        .mockReturnValueOnce(chain({ data: challengeRow, error: null }))
        .mockReturnValueOnce(chain({ data: actionRow, error: null }))
        .mockReturnValueOnce(chain({ data: { record: {} }, error: null })),
    }, session);

    await expect(lookup(challenge, action)).resolves.toBeNull();
    await expect(lookup(
      { ...challenge, decision: 'pending' },
      { ...action, status: 'pending', decision_evidence: {} },
    )).resolves.toBeNull();
  });

  it('refuses a token when its session is revoked between lookup and touch', async () => {
    from.mockReturnValueOnce(chain({
      data: {
        session_id: '00000000-0000-0000-0000-000000000001',
        entity_ref: 'entity-1',
        expires_at: '2999-01-01T00:00:00.000Z',
      },
      error: null,
    }));
    rpc.mockResolvedValueOnce({ data: false, error: null });
    expect(await authenticateMobileToken(
      { from, rpc },
      `Bearer ep_mobile_${'a'.repeat(43)}`,
    )).toBeNull();
  });

  it('revokes sessions and atomically binds then commits terminal action decisions', async () => {
    let persisted = null;
    rpc
      .mockResolvedValueOnce({ data: true, error: null })
      .mockResolvedValueOnce({ data: true, error: null })
      .mockImplementationOnce(async (name, args) => {
        expect(name).toBe('commit_mobile_action_decision');
        persisted = structuredClone(args.p_record);
        return { data: { ok: true }, error: null };
      });
    from
      .mockReturnValueOnce(chain({ data: null, error: null }))
      .mockImplementationOnce(() => chain({ data: { record: persisted }, error: null }));
    const supabase = { from, rpc };
    expect(await revokeMobileSession(supabase, { sessionId: 'session-1', entityRef: 'entity-1' })).toBe(true);
    expect(rpc).toHaveBeenNthCalledWith(1, 'revoke_mobile_session', expect.objectContaining({
      p_entity_ref: 'entity-1',
      p_session_id: 'session-1',
    }));
    expect(await revokeMobileSession(supabase, { sessionId: '', entityRef: 'entity-1' })).toBe(false);
    await expect(revokeMobileSession({
      rpc: vi.fn().mockResolvedValue({ data: null, error: { code: '08006' } }),
    }, {
      sessionId: 'session-1',
      entityRef: 'entity-1',
    })).rejects.toThrow(/session revocation failed/);
    expect(await registerMobileActionChallenge(supabase, {
      entityRef: 'entity-1',
      sessionId: 'session-1',
      actionReference: 'action-0001',
      approverId: 'approver-1',
      challengeId: 'challenge-0001',
      actionHash: `sha256:${'a'.repeat(64)}`,
      decision: 'approved',
      expiresAt: '2026-07-15T01:00:00.000Z',
    })).toBe(true);
    const decisionEvidence = signedDecisionEvidence();
    const committed = await commitMobileActionDecision(supabase, {
      entityRef: 'entity-1',
      sessionId: 'session-1',
      challengeId: 'challenge-0001',
      actionHash: `sha256:${'a'.repeat(64)}`,
      decision: 'approved',
      verdict: 'verified',
      decisionEvidence,
      auditEntry: decisionAuditEntry(decisionEvidence),
    });
    expect(committed).toMatchObject({ committed: true, audit_record: persisted });
    expect(persisted.session_id).toBe('session-1');
    expect(verifyEvidenceRecord(committed.audit_record, { atomicRequired: true })).toBe(true);
  });

  it('recovers an atomic action/evidence commit when the database response is lost', async () => {
    let persisted = null;
    rpc.mockImplementationOnce(async (_name, args) => {
      persisted = structuredClone(args.p_record);
      return { data: null, error: { code: '08006', message: 'response lost after commit' } };
    });
    from
      .mockReturnValueOnce(chain({ data: null, error: null }))
      .mockImplementationOnce(() => chain({ data: { record: persisted }, error: null }));
    const decisionEvidence = signedDecisionEvidence();
    const result = await commitMobileActionDecision({ from, rpc }, {
      entityRef: 'entity-1',
      sessionId: 'session-1',
      challengeId: 'challenge-0001',
      actionHash: `sha256:${'a'.repeat(64)}`,
      decision: 'approved',
      verdict: 'verified',
      decisionEvidence,
      auditEntry: decisionAuditEntry(decisionEvidence),
    });
    expect(result).toMatchObject({ committed: true, audit_record: persisted });

    await expect(commitMobileActionDecision({
      from: vi.fn(() => chain({ data: null, error: null })),
      rpc: vi.fn().mockResolvedValue({
        data: null,
        error: { code: '08006', message: 'commit did not become visible' },
      }),
    }, {
      entityRef: 'entity-1',
      sessionId: 'session-1',
      challengeId: 'challenge-0001',
      actionHash: `sha256:${'a'.repeat(64)}`,
      decision: 'approved',
      verdict: 'verified',
      decisionEvidence,
      auditEntry: decisionAuditEntry(decisionEvidence),
    })).rejects.toThrow(/mobile action decision commit failed/);
  });

  it('commits full signed denial evidence while refusing it for an approval', async () => {
    let persisted = null;
    rpc.mockImplementationOnce(async (name, args) => {
      expect(name).toBe('commit_mobile_action_decision');
      persisted = structuredClone(args.p_record);
      return { data: { ok: true }, error: null };
    });
    from
      .mockReturnValueOnce(chain({ data: null, error: null }))
      .mockImplementationOnce(() => chain({ data: { record: persisted }, error: null }));
    const denialEvidence = signedDecisionEvidence({ decision: 'denied' });
    const auditEntry = decisionAuditEntry(denialEvidence, 'challenge-denied-1');
    const input = {
      entityRef: 'entity-1',
      sessionId: 'session-1',
      challengeId: auditEntry.challenge_id,
      actionHash: denialEvidence.context.action_hash,
      decision: 'denied',
      verdict: 'verified',
      decisionEvidence: denialEvidence,
      auditEntry,
    };

    const committed = await commitMobileActionDecision({ from, rpc }, input);
    expect(committed).toMatchObject({ committed: true, audit_record: persisted });
    expect(rpc).toHaveBeenCalledWith('commit_mobile_action_decision', expect.objectContaining({
      p_decision: 'denied',
      p_decision_evidence: denialEvidence,
      p_record: expect.objectContaining({ decision_evidence: denialEvidence }),
    }));

    await expect(commitMobileActionDecision({ from, rpc }, {
      ...input,
      decision: 'approved',
      auditEntry: { ...auditEntry, decision: 'approved' },
    })).rejects.toThrow(/stored approved mobile decision evidence is malformed/);
    expect(rpc).toHaveBeenCalledTimes(1);
  });

  it('fails closed on missing or mismatched terminal decision evidence inputs', async () => {
    const decisionEvidence = signedDecisionEvidence();
    const base = {
      entityRef: 'entity-1',
      sessionId: 'session-1',
      challengeId: 'challenge-0001',
      actionHash: `sha256:${'a'.repeat(64)}`,
      decision: 'approved',
      verdict: 'verified',
      decisionEvidence,
      auditEntry: decisionAuditEntry(decisionEvidence),
    };
    await expect(commitMobileActionDecision({}, {
      ...base,
      auditEntry: null,
    })).rejects.toThrow(/audit entry is required/);
    await expect(commitMobileActionDecision({}, {
      ...base,
      decisionEvidence: null,
    })).rejects.toThrow(/decision evidence is required/);
    await expect(commitMobileActionDecision({}, {
      ...base,
      auditEntry: { ...base.auditEntry, challenge_id: 'challenge-other' },
    })).rejects.toThrow(/audit entry is malformed/);
  });

  it('refuses unknown database outcomes and exhausts bounded head contention', async () => {
    const decisionEvidence = signedDecisionEvidence();
    const input = {
      entityRef: 'entity-1',
      sessionId: 'session-1',
      challengeId: 'challenge-0001',
      actionHash: `sha256:${'a'.repeat(64)}`,
      decision: 'approved',
      verdict: 'verified',
      decisionEvidence,
      auditEntry: decisionAuditEntry(decisionEvidence),
    };
    await expect(commitMobileActionDecision({
      from: vi.fn(() => chain({ data: null, error: null })),
      rpc: vi.fn().mockResolvedValue({
        data: { ok: false, reason: 'unexpected' },
        error: null,
      }),
    }, input)).rejects.toThrow(/refused: unexpected/);

    await expect(commitMobileActionDecision({
      from: vi.fn(() => chain({ data: null, error: null })),
      rpc: vi.fn().mockResolvedValue({
        data: { ok: true },
        error: null,
      }),
    }, input)).rejects.toThrow(/not observable after commit/);

    const contendedRpc = vi.fn().mockResolvedValue({
      data: { ok: false, reason: 'head_changed' },
      error: null,
    });
    await expect(commitMobileActionDecision({
      from: vi.fn(() => chain({ data: null, error: null })),
      rpc: contendedRpc,
    }, input)).rejects.toThrow(/contention limit/);
    expect(contendedRpc).toHaveBeenCalledTimes(32);
  });

  it('distinguishes a terminal action conflict from evidence-head contention', async () => {
    rpc
      .mockResolvedValueOnce({ data: { ok: false, reason: 'head_changed' }, error: null })
      .mockResolvedValueOnce({ data: { ok: false, reason: 'action_conflict' }, error: null });
    from
      .mockReturnValueOnce(chain({ data: null, error: null }))
      .mockReturnValueOnce(chain({ data: null, error: null }));
    const decisionEvidence = signedDecisionEvidence();
    const result = await commitMobileActionDecision({ from, rpc }, {
      entityRef: 'entity-1',
      sessionId: 'session-1',
      challengeId: 'challenge-0001',
      actionHash: `sha256:${'a'.repeat(64)}`,
      decision: 'approved',
      verdict: 'verified',
      decisionEvidence,
      auditEntry: decisionAuditEntry(decisionEvidence),
    });
    expect(result).toBe(false);
    expect(rpc).toHaveBeenCalledTimes(2);
  });

  it('refuses an otherwise valid terminal decision after its bound session is revoked', async () => {
    rpc.mockResolvedValueOnce({ data: { ok: false, reason: 'session_inactive' }, error: null });
    from.mockReturnValueOnce(chain({ data: null, error: null }));
    const decisionEvidence = signedDecisionEvidence();
    const result = await commitMobileActionDecision({ from, rpc }, {
      entityRef: 'entity-1',
      sessionId: 'session-1',
      challengeId: 'challenge-0001',
      actionHash: `sha256:${'a'.repeat(64)}`,
      decision: 'approved',
      verdict: 'verified',
      decisionEvidence,
      auditEntry: decisionAuditEntry(decisionEvidence),
    });
    expect(result).toBe(false);
    expect(rpc).toHaveBeenCalledWith('commit_mobile_action_decision', expect.objectContaining({
      p_session_id: 'session-1',
      p_record: expect.objectContaining({ session_id: 'session-1' }),
    }));
  });

  it('reads and creates only entity-scoped action inbox records', async () => {
    const continuityRow = {
      action_reference: 'action-1',
      action: { kind: 'release' },
      presentation: PRESENTATION,
      policy: { policy_id: 'policy-1' },
      policy_id: 'policy-1',
      status: 'pending',
      expires_at: '2999-01-01T00:00:00.000Z',
      created_at: '2026-07-20T00:00:00.000Z',
      group_id: `mag_${'1'.repeat(32)}`,
      revision: 1,
      action_caid: `caid:1:emilia.mobile.authorized-action.1:jcs-sha256:${'A'.repeat(43)}`,
      action_digest: `sha256:${'a'.repeat(64)}`,
      group_state: 'open',
      required_approvals: 1,
      approved_count: 0,
      denied_count: 0,
      withdrawn_count: 0,
      events: [],
      alignments: [],
      operation: null,
    };
    rpc
      .mockResolvedValueOnce({ data: [continuityRow], error: null })
      .mockResolvedValueOnce({ data: [continuityRow], error: null })
      .mockResolvedValueOnce({ data: [{ ...continuityRow, status: 'approved' }], error: null })
      .mockResolvedValueOnce({ data: true, error: null });
    const supabase = { from, rpc };
    expect(await listMobileActions(supabase, { entityRef: 'entity-1', approverId: 'approver-1' })).toHaveLength(1);
    expect(await resolveMobileAction(supabase, { entityRef: 'entity-1', approverId: 'approver-1', actionReference: 'action-1' })).toMatchObject({ status: 'pending' });
    expect(await resolveMobileAction(supabase, { entityRef: 'entity-1', approverId: 'approver-1', actionReference: 'action-1' })).toBeNull();
    const demo = {
      action_reference: `mobact_${'2'.repeat(32)}`,
      entity_ref: 'entity-1',
      approver_id: 'approver-1',
      initiator_id: 'agent-1',
      action: { kind: 'release' },
      presentation: PRESENTATION,
      policy: { policy_id: 'policy-1' },
      policy_id: 'policy-1',
      expires_at: '2999-01-01T00:00:00.000Z',
    };
    expect(await createDemoAction(supabase, demo)).toBe(demo.action_reference);
    expect(rpc).toHaveBeenCalledWith('create_mobile_demo_action_v2', expect.objectContaining({
      p_entity_ref: 'entity-1',
      p_action_reference: demo.action_reference,
      p_action_caid: expect.stringMatching(/^caid:1:/),
      p_action_digest: expect.stringMatching(/^sha256:/),
    }));

    await expect(listMobileActions({
      rpc: vi.fn().mockResolvedValue({ data: null, error: { code: '08006' } }),
    }, {
      entityRef: 'entity-1',
      approverId: 'approver-1',
    })).rejects.toThrow(/action inbox unavailable/);
    expect(await listMobileActions({
      rpc: vi.fn().mockResolvedValue({ data: null, error: null }),
    }, {
      entityRef: 'entity-1',
      approverId: 'approver-1',
    })).toEqual([]);
    await expect(resolveMobileAction({
      rpc: vi.fn().mockResolvedValue({ data: null, error: { code: '08006' } }),
    }, {
      entityRef: 'entity-1',
      approverId: 'approver-1',
      actionReference: 'action-1',
    })).rejects.toThrow(/action lookup unavailable/);
    expect(await resolveMobileAction({
      rpc: vi.fn().mockResolvedValue({ data: null, error: null }),
    }, {
      entityRef: 'entity-1',
      approverId: 'approver-1',
      actionReference: 'action-1',
    })).toBeNull();
    expect(await resolveMobileAction({
      rpc: vi.fn().mockResolvedValue({
        data: [{
          ...continuityRow,
          action_reference: 'action-1',
          status: 'pending',
          expires_at: '2000-01-01T00:00:00.000Z',
        }],
        error: null,
      }),
    }, {
      entityRef: 'entity-1',
      approverId: 'approver-1',
      actionReference: 'action-1',
    })).toBeNull();
    await expect(createDemoAction({
      rpc: vi.fn().mockResolvedValue({ data: null, error: { code: '08006' } }),
    }, demo)).rejects.toThrow(/demo action creation failed/);
    await expect(createDemoAction({
      rpc: vi.fn().mockResolvedValue({ data: false, error: null }),
    }, demo)).rejects.toThrow(/demo action creation refused/);
  });

  it('creates a GRACE approval group through one atomic RPC using snapshots', async () => {
    rpc.mockResolvedValueOnce({ data: true, error: null });
    const assignments = [
      { action_reference: `mobact_${'1'.repeat(32)}`, approver_id: 'ep:approver:grid' },
      { action_reference: `mobact_${'2'.repeat(32)}`, approver_id: 'ep:approver:facility' },
    ];
    const result = await createGraceMobileActionGroup({ rpc }, {
      assignments,
      entityRef: 'entity-1',
      initiatorId: 'ep:agent:grid',
      action: { '@version': 'EP-GRACE-CURTAILMENT-ACTION-v1', action_type: 'grid.curtailment' },
      presentation: {
        ...PRESENTATION,
        title: 'Reduce load',
        summary: 'Reduce facility load for the requested grid interval.',
        consequence: 'Facility power use will be curtailed during the interval.',
      },
      policy: {
        policy_id: 'ep:grace:v1',
        required_approvals: 2,
        approvers: assignments.map((item) => item.approver_id),
      },
      policyId: 'ep:grace:v1',
      expiresAt: '2099-07-15T21:45:00.000Z',
    });
    assignments[0].approver_id = 'attacker';
    expect(result[0].approver_id).toBe('ep:approver:grid');
    expect(rpc).toHaveBeenCalledWith('create_grace_mobile_action_group_v2', expect.objectContaining({
      p_entity_ref: 'entity-1',
      p_group_id: expect.stringMatching(/^mag_[0-9a-f]{32}$/),
      p_action_caid: expect.stringMatching(/^caid:1:/),
      p_assignments: expect.arrayContaining([
        expect.objectContaining({ approver_id: 'ep:approver:grid' }),
      ]),
    }));

    const input = {
      assignments: [{ action_reference: `mobact_${'1'.repeat(32)}`, approver_id: 'ep:approver:grid' }],
      entityRef: 'entity-1',
      initiatorId: 'ep:agent:grid',
      action: { '@version': 'EP-GRACE-CURTAILMENT-ACTION-v1', action_type: 'grid.curtailment' },
      presentation: PRESENTATION,
      policy: { policy_id: 'ep:grace:v1', required_approvals: 1 },
      policyId: 'ep:grace:v1',
      expiresAt: '2099-07-15T21:45:00.000Z',
    };
    await expect(createGraceMobileActionGroup({ rpc }, {
      ...input,
      assignments: [],
    })).rejects.toThrow(/at least one mobile approval assignment/);
    await expect(createGraceMobileActionGroup({
      rpc: vi.fn().mockResolvedValue({ data: null, error: { code: '08006' } }),
    }, input)).rejects.toThrow(/GRACE mobile action group creation failed/);
    await expect(createGraceMobileActionGroup({
      rpc: vi.fn().mockResolvedValue({ data: false, error: null }),
    }, input)).rejects.toThrow(/GRACE mobile action group creation refused/);
  });
});
