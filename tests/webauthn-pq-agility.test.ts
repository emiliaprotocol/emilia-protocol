// SPDX-License-Identifier: Apache-2.0
// Class A signature-algorithm agility: ES256 regression + ML-DSA-65 readiness.
//
// EP DOES NOT SUPPORT POST-QUANTUM WEBAUTHN TODAY. No browser, platform
// passkey provider, or certified authenticator produces an ML-DSA WebAuthn
// assertion, and the FIDO Registry v2.3 defines no ALG_SIGN constant for
// ML-DSA. Every ML-DSA credential in this file is SYNTHETIC: minted here with
// node:crypto's own FIPS 204 support, in exactly the byte layout a real
// authenticator would have to produce. That is what makes these tests
// meaningful and what keeps them from being a claim of ecosystem support.
//
// What is proven here:
//   1. ES256 verification is byte-for-byte unchanged at every touched seam.
//   2. An ML-DSA-65 Class A assertion verifies, through EP-SIG-AGILITY-v1.
//   3. Every hostile input is a NAMED refusal, never a throw and never a pass.

import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { Encoder } from 'cbor-x';
import {
  verifyWebAuthnSignoff,
  webauthnSignatureAlgorithm,
  WEBAUTHN_SIGNATURE_ALGORITHMS,
} from '../packages/verify/index.js';
import { verifyQuorum } from '../packages/verify/quorum.js';
import {
  buildAuthorizationContext,
  contextHashBytes,
  coseToSpki,
  coseToSpkiP256,
  COSE_KEY_MAX_BYTES,
} from '../lib/webauthn.js';

const RP_ID = 'emiliaprotocol.ai';
const ORIGIN = 'https://www.emiliaprotocol.ai';
const ML_DSA_65_PUBLIC_KEY_BYTES = 1952;

// Node gained ML-DSA in node:crypto; on a runtime without it every PQ path
// must REFUSE, so the suite says which world it ran in rather than pretending.
const NODE_HAS_ML_DSA = (() => {
  try {
    crypto.generateKeyPairSync('ml-dsa-65');
    return true;
  } catch {
    return false;
  }
})();

function makeContext(overrides: Record<string, unknown> = {}): any {
  return buildAuthorizationContext({
    actionHash: 'a'.repeat(64),
    policyId: 'policy_default_large_payment_release',
    policyHash: 'b'.repeat(64),
    initiatorId: 'ent_agent_recon_7',
    approverId: 'ep:approver:jchen-controller',
    signoffId: `sig_${'c'.repeat(32)}`,
    issuedAt: '2026-06-09T17:21:05.000Z',
    expiresAt: '2026-06-09T17:26:05.000Z',
    decision: 'approved',
    ...overrides,
  } as any);
}

/**
 * Mint a real WebAuthn-shaped assertion. `alg` selects the key algorithm; the
 * SIGNED BYTES are identical either way (authData || SHA-256(clientDataJSON)),
 * which is the whole point of the dispatch.
 */
function makeAssertion(
  context: unknown,
  { alg = 'ES256', flags = 0x05, counter = 9, rpId = RP_ID, signOver = null as Buffer | null } = {},
) {
  const { privateKey, publicKey } = alg === 'ML-DSA-65'
    ? crypto.generateKeyPairSync('ml-dsa-65' as never)
    : crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });

  const challenge = contextHashBytes(context).toString('base64url');
  const clientData = Buffer.from(JSON.stringify({
    type: 'webauthn.get', challenge, origin: ORIGIN, crossOrigin: false,
  }), 'utf8');

  const authData = Buffer.concat([
    crypto.createHash('sha256').update(rpId, 'utf8').digest(),
    Buffer.from([flags]),
    (() => { const b = Buffer.alloc(4); b.writeUInt32BE(counter); return b; })(),
  ]);

  const signedData = signOver
    ?? Buffer.concat([authData, crypto.createHash('sha256').update(clientData).digest()]);
  // FIPS 204 pure ML-DSA takes no pre-hash (digest argument null); ES256 is
  // ECDSA over SHA-256. This asymmetry is exactly what the verifier dispatches.
  const signature = alg === 'ML-DSA-65'
    ? crypto.sign(null, signedData, privateKey)
    : crypto.sign('sha256', signedData, privateKey);

  return {
    signoff: {
      context,
      webauthn: {
        authenticator_data: authData.toString('base64url'),
        client_data_json: clientData.toString('base64url'),
        signature: signature.toString('base64url'),
      },
    },
    spkiB64u: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    privateKey,
    publicKey,
  };
}

const coseEncoder = new Encoder({ mapsAsObjects: false, useRecords: false, tagUint8Array: false });

/** A COSE EC2/ES256/P-256 key, the shape WebAuthn registration hands back. */
function es256CoseKey(overrides: Record<number, unknown> = {}): Buffer {
  const { publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const raw = publicKey.export({ type: 'spki', format: 'der' }).subarray(-65);
  const map = new Map<number, unknown>([
    [1, 2], [3, -7], [-1, 1],
    [-2, new Uint8Array(raw.subarray(1, 33))],
    [-3, new Uint8Array(raw.subarray(33, 65))],
  ]);
  for (const [k, v] of Object.entries(overrides)) map.set(Number(k), v);
  return Buffer.from(coseEncoder.encode(map));
}

/** A COSE AKP/ML-DSA-65 key (RFC 9964: kty 7, alg -49, public key at -1). */
function mldsaCoseKey(overrides: Record<number, unknown> = {}): { cose: Buffer; spki: Buffer } {
  const { publicKey } = crypto.generateKeyPairSync('ml-dsa-65' as never);
  const spki = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const raw = spki.subarray(spki.length - ML_DSA_65_PUBLIC_KEY_BYTES);
  const map = new Map<number, unknown>([[1, 7], [3, -49], [-1, new Uint8Array(raw)]]);
  for (const [k, v] of Object.entries(overrides)) map.set(Number(k), v);
  return { cose: Buffer.from(coseEncoder.encode(map)), spki };
}

// ---------------------------------------------------------------------------
// 1. ES256 regression: the pre-dispatch behavior, unchanged.
// ---------------------------------------------------------------------------

describe('ES256 regression: dispatch changes nothing for existing credentials', () => {
  it('a genuine ES256 signoff still verifies with the exact same result shape', () => {
    const { signoff, spkiB64u } = makeAssertion(makeContext());
    const result = verifyWebAuthnSignoff(signoff, spkiB64u, { rpId: RP_ID });
    expect(result.valid).toBe(true);
    expect(Object.keys(result).sort()).toEqual(['authenticator', 'checks', 'valid']);
    expect(result.checks).toEqual({
      challenge_binding: true,
      client_data_type: true,
      user_present: true,
      user_verified: true,
      rp_id_hash: true,
      signature: true,
    });
  });

  it('a tampered ES256 context still fails on challenge binding, not on algorithm', () => {
    const ctx = makeContext();
    const { signoff, spkiB64u } = makeAssertion(ctx);
    const tampered = { ...signoff, context: { ...ctx, action_hash: 'f'.repeat(64) } };
    const result = verifyWebAuthnSignoff(tampered, spkiB64u, { rpId: RP_ID });
    expect(result.valid).toBe(false);
    expect(result.checks.challenge_binding).toBe(false);
    expect(result.error).toBeUndefined();
  });

  it('a wrong ES256 key still fails on the signature check alone', () => {
    const { signoff } = makeAssertion(makeContext());
    const other = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const result = verifyWebAuthnSignoff(
      signoff, other.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'), { rpId: RP_ID },
    );
    expect(result.valid).toBe(false);
    expect(result.checks.signature).toBe(false);
    expect(result.checks.challenge_binding).toBe(true);
  });

  it('webauthnSignatureAlgorithm names an ES256 credential', () => {
    const { spkiB64u } = makeAssertion(makeContext());
    expect(webauthnSignatureAlgorithm(spkiB64u)).toBe('ES256');
    expect(WEBAUTHN_SIGNATURE_ALGORITHMS).toEqual(['ES256', 'ML-DSA-65']);
  });

  it('coseToSpkiP256 keeps its exact contract: same accepted keys, same errors, same 1 KiB cap', () => {
    const cose = es256CoseKey();
    const spki = coseToSpkiP256(cose);
    expect(crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' }).asymmetricKeyType).toBe('ec');
    // The ES256-pinned wrapper and the explicit ES256 call agree byte for byte.
    expect(coseToSpki(cose, { allowedAlgorithms: ['ES256'] }).equals(spki)).toBe(true);
    expect(COSE_KEY_MAX_BYTES.ES256).toBe(1024);
    expect(() => coseToSpkiP256(Buffer.alloc(1025))).toThrow(/COSE key too large \(1025 bytes, max 1024\)/);
    expect(() => coseToSpkiP256(Buffer.alloc(0))).toThrow(/COSE key is empty/);
    expect(() => coseToSpkiP256(es256CoseKey({ 1: 1 }))).toThrow(/kty/);
    expect(() => coseToSpkiP256(es256CoseKey({ 3: -8 }))).toThrow(/alg/);
    expect(() => coseToSpkiP256(es256CoseKey({ '-1': 6 }))).toThrow(/crv/);
    expect(() => coseToSpkiP256(es256CoseKey({ '-2': new Uint8Array(8) }))).toThrow(/x coordinate/);
    expect(() => coseToSpkiP256(es256CoseKey({ '-3': new Uint8Array(8) }))).toThrow(/y coordinate/);
  });

  it('the ES256 cap is NOT globally raised when ML-DSA-65 is allowed', () => {
    // An oversize ES256 key is refused under its OWN tight bound even though
    // the pre-decode cap for the pair is larger. The DoS guard stays per
    // algorithm; it is not relaxed by opting into a bigger algorithm.
    const padded = new Map<number, unknown>([
      [1, 2], [3, -7], [-1, 1],
      [-2, new Uint8Array(32)], [-3, new Uint8Array(32)],
      [99, new Uint8Array(1100)], // filler pushing the key past 1024 bytes
    ]);
    const bytes = Buffer.from(coseEncoder.encode(padded));
    expect(bytes.length).toBeGreaterThan(COSE_KEY_MAX_BYTES.ES256);
    expect(bytes.length).toBeLessThanOrEqual(COSE_KEY_MAX_BYTES['ML-DSA-65']);
    expect(() => coseToSpki(bytes, { allowedAlgorithms: ['ES256', 'ML-DSA-65'] }))
      .toThrow(/COSE key too large for ES256/);
  });
});

// ---------------------------------------------------------------------------
// 2. ML-DSA-65 readiness against synthetic credentials.
// ---------------------------------------------------------------------------

describe.runIf(NODE_HAS_ML_DSA)('ML-DSA-65 Class A verification (synthetic credential)', () => {
  it('verifies a synthetic ML-DSA-65 assertion end to end', () => {
    const { signoff, spkiB64u } = makeAssertion(makeContext(), { alg: 'ML-DSA-65' });
    expect(webauthnSignatureAlgorithm(spkiB64u)).toBe('ML-DSA-65');
    const result = verifyWebAuthnSignoff(signoff, spkiB64u, { rpId: RP_ID });
    expect(result.valid).toBe(true);
    expect(result.checks.signature).toBe(true);
  });

  it('refuses an ML-DSA-65 signature made over DIFFERENT bytes', () => {
    const { signoff, spkiB64u } = makeAssertion(makeContext(), {
      alg: 'ML-DSA-65', signOver: Buffer.from('some other message entirely'),
    });
    const result = verifyWebAuthnSignoff(signoff, spkiB64u, { rpId: RP_ID });
    expect(result.valid).toBe(false);
    expect(result.error).toBe('ml_dsa_65_signature_invalid');
  });

  it('an ML-DSA-65 credential does NOT throw ERR_OSSL_INVALID_DIGEST', () => {
    // The pre-dispatch verifier called crypto.verify('sha256', ...)
    // unconditionally, which throws on an ML-DSA key. Prove both halves: the
    // raw primitive still throws, and the verifier no longer does.
    const { signoff, spkiB64u, publicKey } = makeAssertion(makeContext(), { alg: 'ML-DSA-65' });
    expect(() => crypto.verify('sha256', Buffer.from('x'), publicKey, Buffer.alloc(3309)))
      .toThrow(/invalid digest/i);
    expect(() => verifyWebAuthnSignoff(signoff, spkiB64u, { rpId: RP_ID })).not.toThrow();
  });

  it('refuses when the ML-DSA backend is unavailable, never skipping the check', () => {
    const { signoff, spkiB64u } = makeAssertion(makeContext(), { alg: 'ML-DSA-65' });
    const result = verifyWebAuthnSignoff(signoff, spkiB64u, {
      rpId: RP_ID, agility: { mldsaBackend: { verify: undefined } },
    });
    expect(result.valid).toBe(false);
    expect(result.error).toBe('ml_dsa_65_pq_backend_unavailable');
  });

  it('converts an ML-DSA-65 COSE key only when explicitly allowed', () => {
    const { cose, spki } = mldsaCoseKey();
    expect(cose.length).toBeLessThanOrEqual(COSE_KEY_MAX_BYTES['ML-DSA-65']);
    // Fail-closed default: the ES256-pinned entry point refuses it outright.
    expect(() => coseToSpkiP256(cose)).toThrow(/COSE key too large|kty/);
    const converted = coseToSpki(cose, { allowedAlgorithms: ['ES256', 'ML-DSA-65'] });
    // The locally held SPKI prefix must equal what node itself emits, so the
    // hardcoded header cannot silently drift.
    expect(converted.equals(spki)).toBe(true);
    expect(webauthnSignatureAlgorithm(converted.toString('base64url'))).toBe('ML-DSA-65');
  });
});

// ---------------------------------------------------------------------------
// 2b. The browser twin refuses ML-DSA-65 uniformly, on every runtime.
// ---------------------------------------------------------------------------

describe.runIf(NODE_HAS_ML_DSA)('portable browser verifier: ES256 only, by design', () => {
  it('refuses an ML-DSA-65 signoff by name EVEN WHERE WebCrypto supports it', async () => {
    // This runtime's WebCrypto does carry ML-DSA-65 (Node marks it
    // experimental). Assert that first, so the refusal below is proven to be a
    // deliberate portability decision and not a missing capability.
    const probe = crypto.generateKeyPairSync('ml-dsa-65' as never);
    await expect(globalThis.crypto.subtle.importKey(
      'spki',
      probe.publicKey.export({ type: 'spki', format: 'der' }) as never,
      { name: 'ML-DSA-65' } as never, false, ['verify'],
    )).resolves.toBeDefined();

    const webVerifier = await import('../packages/verify/web.js');
    const { signoff, spkiB64u } = makeAssertion(makeContext(), { alg: 'ML-DSA-65' });
    // The Node verifier accepts the very same signoff.
    expect(verifyWebAuthnSignoff(signoff, spkiB64u, { rpId: RP_ID }).valid).toBe(true);
    const result = await webVerifier.verifyWebAuthnSignoff(signoff as never, spkiB64u, { rpId: RP_ID });
    expect(result.valid).toBe(false);
    expect(result.error).toBe('unsupported_signature_algorithm: ML-DSA-65 (no WebCrypto ML-DSA in browsers)');
  });

  it('the browser twin still verifies ES256 identically to the Node verifier', async () => {
    const webVerifier = await import('../packages/verify/web.js');
    const { signoff, spkiB64u } = makeAssertion(makeContext());
    const node = verifyWebAuthnSignoff(signoff, spkiB64u, { rpId: RP_ID });
    const web = await webVerifier.verifyWebAuthnSignoff(signoff as never, spkiB64u, { rpId: RP_ID });
    expect(web.valid).toBe(node.valid);
    expect(web.checks).toEqual(node.checks);
  });
});

// ---------------------------------------------------------------------------
// 3. Hostile matrix.
// ---------------------------------------------------------------------------

describe('hostile matrix: every bad input is a named refusal, never a throw', () => {
  it('an unknown pinned algorithm refuses by name', () => {
    const { signoff, spkiB64u } = makeAssertion(makeContext());
    const result = verifyWebAuthnSignoff(signoff, spkiB64u, { rpId: RP_ID, alg: 'RS256' });
    expect(result.valid).toBe(false);
    expect(result.error).toBe('unsupported_signature_algorithm: RS256');
  });

  it('a wrong algorithm LABEL against a real key refuses by name, and never verifies', () => {
    const { signoff, spkiB64u } = makeAssertion(makeContext());
    const result = verifyWebAuthnSignoff(signoff, spkiB64u, { rpId: RP_ID, alg: 'ML-DSA-65' });
    expect(result.valid).toBe(false);
    expect(result.checks.signature).toBe(false);
    expect(result.error).toMatch(/^signature_algorithm_mismatch: pinned ML-DSA-65, enrolled key is ES256$/);
  });

  it('a credential of an unsupported algorithm refuses instead of reaching a digest-hardcoded verify', () => {
    // An Ed25519 SPKI is well-formed and importable, so nothing throws on the
    // way in; it must still be refused rather than verified under ES256 rules.
    const { signoff } = makeAssertion(makeContext());
    const ed = crypto.generateKeyPairSync('ed25519');
    const result = verifyWebAuthnSignoff(
      signoff, ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'), { rpId: RP_ID },
    );
    expect(result.valid).toBe(false);
    expect(result.error).toBe('unsupported_signature_algorithm');
    expect(webauthnSignatureAlgorithm(ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url')))
      .toBeNull();
  });

  it('a garbage public key is a refusal, not a throw', () => {
    const { signoff } = makeAssertion(makeContext());
    expect(() => verifyWebAuthnSignoff(signoff, 'not-a-key', { rpId: RP_ID })).not.toThrow();
    expect(verifyWebAuthnSignoff(signoff, 'not-a-key', { rpId: RP_ID }).valid).toBe(false);
    expect(webauthnSignatureAlgorithm('not-a-key')).toBeNull();
    expect(webauthnSignatureAlgorithm('')).toBeNull();
    expect(webauthnSignatureAlgorithm(null)).toBeNull();
  });

  it('an oversize COSE key is refused before the CBOR decoder sees it', () => {
    const huge = Buffer.alloc(COSE_KEY_MAX_BYTES['ML-DSA-65'] + 1);
    expect(() => coseToSpki(huge, { allowedAlgorithms: ['ES256', 'ML-DSA-65'] }))
      .toThrow(/COSE key too large \(2049 bytes, max 2048\)/);
  });

  it('a truncated ML-DSA-65 COSE public key is refused', () => {
    const truncated = Buffer.from(coseEncoder.encode(
      new Map<number, unknown>([[1, 7], [3, -49], [-1, new Uint8Array(ML_DSA_65_PUBLIC_KEY_BYTES - 1)]]),
    ));
    expect(() => coseToSpki(truncated, { allowedAlgorithms: ['ES256', 'ML-DSA-65'] }))
      .toThrow(/Bad COSE ML-DSA-65 public key/);
  });

  it('an AKP key labelled with a different ML-DSA parameter set is refused', () => {
    // -48 (ML-DSA-44) and -50 (ML-DSA-87) are real IANA assignments outside
    // EP's closed registry: they refuse, they do not fall back to -49.
    for (const alg of [-48, -50]) {
      const wrong = Buffer.from(coseEncoder.encode(
        new Map<number, unknown>([[1, 7], [3, alg], [-1, new Uint8Array(ML_DSA_65_PUBLIC_KEY_BYTES)]]),
      ));
      expect(() => coseToSpki(wrong, { allowedAlgorithms: ['ES256', 'ML-DSA-65'] }))
        .toThrow(/Unsupported COSE alg/);
    }
  });

  it('an unknown allowedAlgorithms entry is refused', () => {
    expect(() => coseToSpki(es256CoseKey(), { allowedAlgorithms: ['RS256' as never] }))
      .toThrow(/Unsupported COSE algorithm "RS256"/);
    expect(() => coseToSpki(es256CoseKey(), { allowedAlgorithms: [] })).toThrow(/non-empty array/);
  });
});

// ---------------------------------------------------------------------------
// 4. Hybrid quorum policy (EP's design, not FIDO's).
// ---------------------------------------------------------------------------

describe('EP-QUORUM-v1 policy.required_algorithms: hybrid human authorization', () => {
  const ACTION = 'd'.repeat(64);
  const INITIATOR = 'ent_agent_recon_7';
  const ROSTER = [
    { role: 'controller', approver: 'ep:approver:alice' },
    { role: 'officer', approver: 'ep:approver:bob' },
  ];

  function memberFor(slot: { role: string; approver: string }, alg: string, minute: number) {
    const context = {
      ep_version: '1.0',
      context_type: 'ep.signoff.v1',
      action_hash: ACTION,
      policy_id: null,
      policy_hash: null,
      initiator: INITIATOR,
      approver: slot.approver,
      approver_index: 1,
      required_approvals: 1,
      nonce: `sig_${String(minute).padStart(32, '0')}`,
      issued_at: `2026-06-09T17:${String(20 + minute).padStart(2, '0')}:00.000Z`,
      expires_at: '2026-06-09T18:00:00.000Z',
      decision: 'approved' as const,
    };
    const { signoff, spkiB64u } = makeAssertion(context, { alg });
    return { role: slot.role, approver_public_key: spkiB64u, signoff };
  }

  const basePolicy = (extra: Record<string, unknown> = {}) => ({
    mode: 'threshold',
    required: 2,
    approvers: ROSTER,
    distinct_humans: true,
    window_sec: 900,
    ...extra,
  });

  const quorumDoc = (members: unknown[], policy: unknown) => ({
    '@type': 'ep.quorum', action_hash: ACTION, policy, members,
  });

  it('defaults OFF: an existing single-algorithm quorum is unaffected', () => {
    const members = [memberFor(ROSTER[0], 'ES256', 1), memberFor(ROSTER[1], 'ES256', 2)];
    const result = verifyQuorum(quorumDoc(members, basePolicy()), { rpId: RP_ID });
    expect(result.valid).toBe(true);
    expect(result.checks.required_algorithms_satisfied).toBe(true);
    expect('reason' in result).toBe(false);
  });

  it.runIf(NODE_HAS_ML_DSA)('authorizes when every approver signs under BOTH required algorithms', () => {
    const members = [
      memberFor(ROSTER[0], 'ES256', 1),
      memberFor(ROSTER[0], 'ML-DSA-65', 2),
      memberFor(ROSTER[1], 'ES256', 3),
      memberFor(ROSTER[1], 'ML-DSA-65', 4),
    ];
    const policy = basePolicy({ required_algorithms: ['ES256', 'ML-DSA-65'] });
    const result = verifyQuorum(quorumDoc(members, policy), { rpId: RP_ID });
    expect(result.valid).toBe(true);
    expect(result.checks.required_algorithms_satisfied).toBe(true);
    // The same approver in two seats is legitimate ONLY because the seats are
    // different algorithms; distinctness is over (approver, algorithm).
    expect(result.checks.distinct_humans).toBe(true);
    expect(result.checks.distinct_keys).toBe(true);
  });

  it.runIf(NODE_HAS_ML_DSA)('refuses by name when an approver has no credential for a required algorithm', () => {
    const members = [
      memberFor(ROSTER[0], 'ES256', 1),
      memberFor(ROSTER[0], 'ML-DSA-65', 2),
      memberFor(ROSTER[1], 'ES256', 3), // bob never enrolled a PQ credential
    ];
    const policy = basePolicy({ required_algorithms: ['ES256', 'ML-DSA-65'] });
    const result = verifyQuorum(quorumDoc(members, policy), { rpId: RP_ID });
    expect(result.valid).toBe(false);
    expect(result.checks.required_algorithms_satisfied).toBe(false);
    expect(result.reason).toContain('required_algorithms_missing');
    expect(result.reason).toContain('ML-DSA-65');
  });

  it('does NOT narrow the required set to what was presented', () => {
    // Only ES256 signoffs are presented. A verifier that narrowed the pin to
    // the presented set would authorize this; it must not.
    const members = [memberFor(ROSTER[0], 'ES256', 1), memberFor(ROSTER[1], 'ES256', 2)];
    const policy = basePolicy({ required_algorithms: ['ES256', 'ML-DSA-65'] });
    const result = verifyQuorum(quorumDoc(members, policy), { rpId: RP_ID });
    expect(result.valid).toBe(false);
    expect(result.checks.required_algorithms_satisfied).toBe(false);
  });

  it('refuses an unknown, duplicated, or malformed algorithm pin', () => {
    const members = [memberFor(ROSTER[0], 'ES256', 1), memberFor(ROSTER[1], 'ES256', 2)];
    const cases: Array<[unknown, string]> = [
      [['ES256', 'RS256'], 'required_algorithms_unknown:RS256'],
      [['ES256', 'ES256'], 'required_algorithms_duplicate:ES256'],
      [[], 'required_algorithms_malformed'],
      ['ES256', 'required_algorithms_malformed'],
    ];
    for (const [pin, expected] of cases) {
      const result = verifyQuorum(quorumDoc(members, basePolicy({ required_algorithms: pin })), { rpId: RP_ID });
      expect(result.valid).toBe(false);
      expect(result.reason).toBe(expected);
    }
  });

  it('refuses the hybrid + ordered combination rather than verifying a weaker predicate', () => {
    const members = [memberFor(ROSTER[0], 'ES256', 1), memberFor(ROSTER[1], 'ES256', 2)];
    const policy = basePolicy({ mode: 'ordered', required_algorithms: ['ES256'] });
    const result = verifyQuorum(quorumDoc(members, policy), { rpId: RP_ID });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('required_algorithms_ordered_unsupported');
  });
});
