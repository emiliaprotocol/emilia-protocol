// SPDX-License-Identifier: Apache-2.0
//
// EP-AUTHORIZATION-SERVER-CONFIRMATION-v2 hostile matrix. The PQ leg runs for
// real; this suite fails loudly if @noble/post-quantum is missing.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';

import { digestAeb } from '../packages/verify/src/aeb-adapter-contract.ts';
import {
  AUTHORIZATION_SERVER_CONFIRMATION_TOKEN_VERSION,
  AUTHORIZATION_SERVER_CONFIRMATION_ARTIFACT_VERSION,
  AUTHORIZATION_SERVER_CONFIRMATION_CONFIG_VERSION,
  AUTHORIZATION_SERVER_CONFIRMATION_V2_TOKEN_VERSION,
  AUTHORIZATION_SERVER_CONFIRMATION_V2_TYP,
  AUTHORIZATION_SERVER_CONFIRMATION_V2_REQUIRED_ALGORITHMS,
  authorizationServerConfirmationV2ProtectedHeader,
  signAuthorizationServerConfirmationV2,
  verifyAuthorizationServerConfirmationV2,
  createAuthorizationServerConfirmationAdapter,
  type AuthorizationServerConfirmationHybridGrant,
} from '../packages/verify/src/authorization-server-confirmation.ts';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');

const KEY_ID = 'as-key-1';
const PQ_KEY_ID = 'as-pq-key-1';
const PIN = { key_id: KEY_ID, public_key: edPubB64u, pq_key_id: PQ_KEY_ID, pq_public_key: pqPubB64u };
const SIGNER = {
  key_id: KEY_ID, private_key: ed.privateKey, pq_key_id: PQ_KEY_ID, pq_secret_key: pq.secretKey,
};

const ACTION = { action_type: 'payment.transfer.1', parameters: { amount: 100 } };
const RS_KEY_DIGEST = digestAeb({ rs: 'key' });

const CONFIG = {
  '@version': AUTHORIZATION_SERVER_CONFIRMATION_CONFIG_VERSION,
  evidence_role: 'authorization-server-confirmation',
  human_evidence_role: 'human-authorization',
  issuer: 'https://as.example',
  audience: 'https://gate.example',
  resource_server_key_id: 'rs-key-1',
  resource_server_key_digest: RS_KEY_DIGEST,
  action_type: 'payment.transfer.1',
  clock_skew_seconds: 60,
  max_token_age_seconds: 900,
  max_directory_snapshot_age_seconds: 3600,
} as any;

const CLAIMS = {
  ep_version: AUTHORIZATION_SERVER_CONFIRMATION_V2_TOKEN_VERSION,
  iss: 'https://as.example',
  sub: 'user:alice',
  aud: 'https://gate.example',
  iat: 1_770_000_000,
  nbf: 1_770_000_000,
  exp: 1_770_000_600,
  jti: 'jti-1',
  authorization_server_decision: 'AUTHORIZED',
  action: ACTION,
  action_digest: digestAeb(ACTION),
  human_evidence_digest: digestAeb({ human: 1 }),
  policy_digest: digestAeb({ policy: 1 }),
  directory_digest: digestAeb({ directory: 1 }),
  directory_observation_basis: 'AUTHORIZATION_SERVER_OBSERVED_SNAPSHOT',
  directory_observed_at: 1_769_999_000,
  resource_server_key_id: 'rs-key-1',
  resource_server_key_digest: RS_KEY_DIGEST,
} as any;

const build = () => signAuthorizationServerConfirmationV2(CLAIMS, SIGNER);
const clone = (g: AuthorizationServerConfirmationHybridGrant) =>
  JSON.parse(JSON.stringify(g)) as AuthorizationServerConfirmationHybridGrant;
const b64uJson = (v: unknown) => Buffer.from(JSON.stringify(v), 'utf8').toString('base64url');

describe('EP-AUTHORIZATION-SERVER-CONFIRMATION-v2 happy path', () => {
  it('the real ML-DSA-65 backend is present (never a silent skip)', () => {
    expect(pq.publicKey.length).toBe(1952);
  });

  it('round-trips a hybrid grant under both pinned keys', async () => {
    const grant = await build();
    expect(grant.signatures.map((s) => s.alg)).toEqual(['Ed25519', 'ML-DSA-65']);
    expect(Buffer.from(grant.signatures[1].sig, 'base64url').length).toBe(3309);
    const result = await verifyAuthorizationServerConfirmationV2(grant, PIN, CONFIG);
    expect(result.errors).toEqual([]);
    expect(result.valid).toBe(true);
    expect(result.claims?.sub).toBe('user:alice');
  });

  it('carries no JOSE alg header and commits the required set inside the signing input', async () => {
    const grant = await build();
    const header = JSON.parse(Buffer.from(grant.protected, 'base64url').toString('utf8'));
    expect(header.alg).toBeUndefined();
    expect(header.typ).toBe(AUTHORIZATION_SERVER_CONFIRMATION_V2_TYP);
    expect(header.required_algorithms)
      .toEqual([...AUTHORIZATION_SERVER_CONFIRMATION_V2_REQUIRED_ALGORITHMS]);
  });
});

describe('EP-AUTHORIZATION-SERVER-CONFIRMATION-v2 hostile matrix', () => {
  it('refuses a stripped ML-DSA leg with the set left intact', async () => {
    const grant = clone(await build());
    grant.signatures = grant.signatures.filter((s) => s.alg !== 'ML-DSA-65');
    const result = await verifyAuthorizationServerConfirmationV2(grant, PIN, CONFIG);
    expect(result.valid).toBe(false);
    expect(result.checks.legs_present).toBe(false);
  });

  it('refuses a narrowed required_algorithms set, and the surviving Ed25519 leg no longer verifies', async () => {
    const grant = clone(await build());
    grant.signatures = grant.signatures.filter((s) => s.alg !== 'ML-DSA-65');
    const header = JSON.parse(Buffer.from(grant.protected, 'base64url').toString('utf8'));
    header.required_algorithms = ['Ed25519'];
    grant.protected = b64uJson(header);
    const result = await verifyAuthorizationServerConfirmationV2(grant, PIN, CONFIG);
    expect(result.valid).toBe(false);
    expect(result.checks.algorithm_set).toBe(false);
    // The anti-stripping property: rewriting the set changed the signed bytes.
    expect(result.checks.signature_valid).toBe(false);
  });

  it('refuses a widened algorithm set', async () => {
    const grant = clone(await build());
    const header = JSON.parse(Buffer.from(grant.protected, 'base64url').toString('utf8'));
    header.required_algorithms = ['Ed25519', 'ML-DSA-65', 'Ed448'];
    grant.protected = b64uJson(header);
    const result = await verifyAuthorizationServerConfirmationV2(grant, PIN, CONFIG);
    expect(result.valid).toBe(false);
    expect(result.checks.algorithm_set).toBe(false);
  });

  it('refuses a wrong-length Ed25519 signature', async () => {
    const grant = clone(await build());
    grant.signatures[0].sig = Buffer.alloc(63).toString('base64url');
    const result = await verifyAuthorizationServerConfirmationV2(grant, PIN, CONFIG);
    expect(result.valid).toBe(false);
    expect(result.errors.join(' ')).toContain('malformed_signature');
  });

  it('refuses a wrong-length ML-DSA-65 signature', async () => {
    const grant = clone(await build());
    grant.signatures[1].sig = Buffer.alloc(3310).toString('base64url');
    const result = await verifyAuthorizationServerConfirmationV2(grant, PIN, CONFIG);
    expect(result.valid).toBe(false);
    expect(result.checks.signature_valid).toBe(false);
  });

  it('refuses an Ed448 SPKI pinned as the Ed25519 half', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const grant = await build();
    const result = await verifyAuthorizationServerConfirmationV2(
      grant,
      { ...PIN, public_key: ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url') },
      CONFIG,
    );
    expect(result.valid).toBe(false);
    expect(result.checks.as_key_pinned).toBe(false);
  });

  it('refuses a tampered payload', async () => {
    const grant = clone(await build());
    grant.payload = b64uJson({ ...CLAIMS, sub: 'user:mallory' });
    const result = await verifyAuthorizationServerConfirmationV2(grant, PIN, CONFIG);
    expect(result.valid).toBe(false);
    expect(result.checks.signature_valid).toBe(false);
    expect(result.checks.signature_binds_grant).toBe(false);
  });

  it('refuses pq_backend_unavailable rather than passing on the classical leg', async () => {
    const grant = await build();
    const result = await verifyAuthorizationServerConfirmationV2(
      grant, PIN, CONFIG, { mldsaBackendLoader: () => null },
    );
    expect(result.valid).toBe(false);
    expect(result.errors.join(' ')).toContain('pq_backend_unavailable');
  });

  it('refuses a kid that does not match the pin', async () => {
    const grant = await build();
    const result = await verifyAuthorizationServerConfirmationV2(
      grant, { ...PIN, key_id: 'other-key' }, CONFIG,
    );
    expect(result.valid).toBe(false);
    expect(result.checks.as_key_pinned).toBe(false);
  });

  it('never throws on hostile caller input', async () => {
    for (const bad of [null, undefined, 'x', 7, [], { protected: 1 }]) {
      const result = await verifyAuthorizationServerConfirmationV2(bad, PIN, CONFIG);
      expect(result.valid).toBe(false);
    }
  });

  it('refuses a v1-versioned header handed to the v2 verifier', async () => {
    const grant = clone(await build());
    const header = JSON.parse(Buffer.from(grant.protected, 'base64url').toString('utf8'));
    header.ep_version = AUTHORIZATION_SERVER_CONFIRMATION_TOKEN_VERSION;
    grant.protected = b64uJson(header);
    const result = await verifyAuthorizationServerConfirmationV2(grant, PIN, CONFIG);
    expect(result.valid).toBe(false);
    expect(result.checks.version).toBe(false);
  });

  it('the protected-header builder refuses a non-registered algorithm set', () => {
    expect(() => authorizationServerConfirmationV2ProtectedHeader(KEY_ID, PQ_KEY_ID, ['Ed25519']))
      .toThrow(/registered EP-AUTHORIZATION-SERVER-CONFIRMATION-v2 set/);
  });
});

describe('the unchanged v1 adapter refuses a v2 artifact on the version marker', () => {
  it('returns artifact_malformed without throwing', async () => {
    const grant = await build();
    const adapter = createAuthorizationServerConfirmationAdapter({
      config: CONFIG,
      trust_roots: [{
        '@version': 'EP-AUTHORIZATION-SERVER-CONFIRMATION-ROOT-v1',
        use: 'authorization-server',
        issuer: 'https://as.example',
        key_id: KEY_ID,
        algorithm: 'EdDSA',
        public_key: edPubB64u,
      }] as any,
    });
    const native = adapter.verifyNative({
      artifact: {
        '@version': 'EP-AUTHORIZATION-SERVER-CONFIRMATION-ARTIFACT-v2',
        grant_hybrid: grant,
        human_evidence: { human: 1 },
      },
      artifact_ref: 'artifact:1',
      status: {
        checked_at: '2026-08-17T10:30:00.000Z',
        expires_at: '2026-08-17T11:00:00.000Z',
        revocation_checked: true,
        revoked: false,
        consumed: false,
      },
      trust_roots: [{
        '@version': 'EP-AUTHORIZATION-SERVER-CONFIRMATION-ROOT-v1',
        use: 'authorization-server',
        issuer: 'https://as.example',
        key_id: KEY_ID,
        algorithm: 'EdDSA',
        public_key: edPubB64u,
      }],
      adapter_config: CONFIG,
      expected_action: ACTION,
      now: '2026-08-17T10:30:00.000Z',
    });
    expect(native.native_verification).toBe('FAILED');
    expect(native.reasons).toEqual(['as-confirmation:artifact_malformed']);
    expect(AUTHORIZATION_SERVER_CONFIRMATION_ARTIFACT_VERSION)
      .not.toBe('EP-AUTHORIZATION-SERVER-CONFIRMATION-ARTIFACT-v2');
  });
});
