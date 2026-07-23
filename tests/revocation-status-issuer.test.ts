// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import crypto, { type KeyObject } from 'node:crypto';

import {
  buildRevokerAuthorityCertificate,
  buildStatusArtifact,
  deriveRevokerKeyId,
  type ExternalEd25519Signer,
  type StatusSignerContext,
} from '../lib/revocation/status.js';
import {
  REVOCER_AUTHORITY_DOMAIN,
  STATUS_DOMAIN,
  revokerAuthorityCertificateDigest,
  statusArtifactDigest,
  verifyRevokerAuthorityCertificate,
  verifyStatusArtifact,
} from '../packages/verify/src/status.ts';

interface KeyPair {
  publicKey: KeyObject;
  privateKey: KeyObject;
}

const NOW = '2026-07-22T12:04:00Z';
const TARGET = {
  type: 'receipt' as const,
  id: 'receipt:payment-release:0001',
  digest: `sha256:${'a'.repeat(64)}`,
  usage: 'authorization' as const,
};

const authorityKeys = crypto.generateKeyPairSync('ed25519');
const revokerKeys = crypto.generateKeyPairSync('ed25519');

function publicKey(keyPair: KeyPair): string {
  return keyPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
}

function jcs(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object).sort()
    .map((key) => `${JSON.stringify(key)}:${jcs(object[key])}`).join(',')}}`;
}

const authorityPin = {
  authority_domain: 'status.acme.example',
  authority_id: 'org:acme',
  key_id: 'key:acme-status-root',
  public_key: publicKey(authorityKeys),
};

function externalSigner(
  keyPair: KeyPair,
  keyId: string,
  onSign?: (bytes: Uint8Array, context: StatusSignerContext) => void,
): ExternalEd25519Signer {
  return {
    algorithm: 'Ed25519',
    keyId,
    async sign(bytes, context) {
      onSign?.(bytes, context);
      return crypto.sign(null, Buffer.from(bytes), keyPair.privateKey).toString('base64url');
    },
  };
}

function authoritySigner(
  onSign?: (bytes: Uint8Array, context: StatusSignerContext) => void,
): ExternalEd25519Signer {
  return externalSigner(authorityKeys, authorityPin.key_id, onSign);
}

function revokerSigner(
  onSign?: (bytes: Uint8Array, context: StatusSignerContext) => void,
): ExternalEd25519Signer {
  return externalSigner(revokerKeys, deriveRevokerKeyId(publicKey(revokerKeys)), onSign);
}

function statusInput(authority: Awaited<ReturnType<typeof certificate>>, overrides: Record<string, unknown> = {}) {
  return {
    authorityPin,
    certificate: authority,
    target: TARGET,
    status: 'not_revoked',
    issuedAt: '2026-07-22T12:00:00Z',
    nextUpdate: '2026-07-22T12:05:00Z',
    signer: revokerSigner(),
    ...overrides,
  };
}

function resignStatus(status: Record<string, any>): void {
  const unsigned = structuredClone(status);
  delete unsigned.proof;
  status.proof.signature_b64u = crypto.sign(
    null,
    Buffer.from(`${STATUS_DOMAIN}${jcs(unsigned)}`),
    revokerKeys.privateKey,
  ).toString('base64url');
}

function certificateInput(overrides: Record<string, unknown> = {}) {
  return {
    certificateId: 'revoker-authority:acme:primary:v1',
    authorityPin,
    revokerId: 'revoker:acme:primary',
    revokerPublicKey: publicKey(revokerKeys),
    scope: {
      allowed_target_types: ['receipt', 'commit'] as const,
      allowed_usages: ['authorization', 'execution'] as const,
    },
    issuedAt: '2026-07-01T00:00:00Z',
    expiresAt: '2026-08-01T00:00:00Z',
    signer: authoritySigner(),
    ...overrides,
  };
}

async function certificate() {
  return buildRevokerAuthorityCertificate(certificateInput());
}

describe('EP status issuer', () => {
  it('builds exact domain-separated certificate and status artifacts that round-trip', async () => {
    let certificateSigningBytes: Buffer | null = null;
    const authority = await buildRevokerAuthorityCertificate(certificateInput({
      signer: authoritySigner((bytes, context) => {
        certificateSigningBytes = Buffer.from(bytes);
        expect(context).toEqual({
          artifact: 'revoker_authority_certificate',
          domain: REVOCER_AUTHORITY_DOMAIN,
          keyId: authorityPin.key_id,
        });
      }),
    }));

    const derivedRevokerKeyId = `ep:revoker-key:sha256:${crypto.createHash('sha256')
      .update(Buffer.from(publicKey(revokerKeys), 'base64url')).digest('hex')}`;
    expect(authority.revoker_key.key_id).toBe(derivedRevokerKeyId);
    expect(authority.revoker_key.key_id).toHaveLength('ep:revoker-key:sha256:'.length + 64);
    expect(Object.keys(authority)).toEqual([
      '@version', 'certificate_id', 'authority_domain', 'authority_id', 'revoker_id',
      'revoker_key', 'scope', 'issued_at', 'expires_at', 'proof',
    ]);

    const unsignedAuthority = structuredClone(authority) as Record<string, unknown>;
    delete unsignedAuthority.proof;
    expect(certificateSigningBytes?.toString('utf8'))
      .toBe(`${REVOCER_AUTHORITY_DOMAIN}${jcs(unsignedAuthority)}`);

    const authorityResult = verifyRevokerAuthorityCertificate(authority, {
      authorityPin,
      now: NOW,
    });
    expect(authorityResult.valid).toBe(true);

    let statusSigningBytes: Buffer | null = null;
    const status = await buildStatusArtifact({
      authorityPin,
      certificate: authority,
      target: TARGET,
      status: 'not_revoked',
      issuedAt: '2026-07-22T12:00:00Z',
      nextUpdate: '2026-07-22T12:05:00Z',
      signer: revokerSigner((bytes, context) => {
        statusSigningBytes = Buffer.from(bytes);
        expect(context).toEqual({
          artifact: 'status',
          domain: STATUS_DOMAIN,
          keyId: derivedRevokerKeyId,
        });
      }),
    });

    expect(status.sequence).toBe(0);
    expect(status.previous_status_digest).toBeNull();
    expect(status.revoker_authority_digest).toBe(revokerAuthorityCertificateDigest(authority));
    expect(Object.isFrozen(status)).toBe(true);
    expect(Object.isFrozen(status.target)).toBe(true);

    const unsignedStatus = structuredClone(status) as Record<string, unknown>;
    delete unsignedStatus.proof;
    expect(statusSigningBytes?.toString('utf8')).toBe(`${STATUS_DOMAIN}${jcs(unsignedStatus)}`);

    const result = verifyStatusArtifact(TARGET, status, {
      authorityPin,
      certificate: authority,
      now: NOW,
    });
    expect(result.valid).toBe(true);
    expect(result.outcome).toBe('current_not_revoked');
    expect(result.status_digest).toBe(statusArtifactDigest(status));
  });

  it('refuses a signer whose key ID is not the exact expected key ID', async () => {
    let certificateSignCalls = 0;
    await expect(buildRevokerAuthorityCertificate(certificateInput({
      signer: externalSigner(authorityKeys, 'key:wrong', () => { certificateSignCalls += 1; }),
    }))).rejects.toThrow(/signer key ID/i);
    expect(certificateSignCalls).toBe(0);

    const authority = await certificate();
    let statusSignCalls = 0;
    await expect(buildStatusArtifact({
      authorityPin,
      certificate: authority,
      target: TARGET,
      status: 'not_revoked',
      issuedAt: '2026-07-22T12:00:00Z',
      nextUpdate: '2026-07-22T12:05:00Z',
      signer: externalSigner(revokerKeys, `ep:revoker-key:sha256:${'0'.repeat(64)}`, () => {
        statusSignCalls += 1;
      }),
    })).rejects.toThrow(/signer key ID/i);
    expect(statusSignCalls).toBe(0);
  });

  it('binds monotonic sequence/predecessor state and refuses rollback or resurrection', async () => {
    const authority = await certificate();
    const first = await buildStatusArtifact({
      authorityPin,
      certificate: authority,
      target: TARGET,
      status: 'not_revoked',
      issuedAt: '2026-07-22T12:00:00Z',
      nextUpdate: '2026-07-22T12:05:00Z',
      signer: revokerSigner(),
    });
    const second = await buildStatusArtifact({
      authorityPin,
      certificate: authority,
      target: TARGET,
      status: 'not_revoked',
      issuedAt: '2026-07-22T12:01:00Z',
      nextUpdate: '2026-07-22T12:06:00Z',
      previousStatus: first,
      signer: revokerSigner(),
    });

    expect(second.sequence).toBe(1);
    expect(second.previous_status_digest).toBe(statusArtifactDigest(first));
    const rollback = verifyStatusArtifact(TARGET, first, {
      authorityPin,
      certificate: authority,
      previousStatus: second,
      now: NOW,
    });
    expect(rollback.valid).toBe(false);
    expect(rollback.reasons).toContain('sequence_not_monotonic');

    const revoked = await buildStatusArtifact({
      authorityPin,
      certificate: authority,
      target: TARGET,
      status: 'revoked',
      issuedAt: '2026-07-22T12:02:00Z',
      nextUpdate: null,
      previousStatus: second,
      signer: revokerSigner(),
    });
    const terminal = verifyStatusArtifact(TARGET, revoked, {
      authorityPin,
      certificate: authority,
      previousStatus: second,
      now: '2030-01-01T00:00:00Z',
    });
    expect(terminal.valid).toBe(true);
    expect(terminal.outcome).toBe('revoked');

    let resurrectionSignCalls = 0;
    await expect(buildStatusArtifact({
      authorityPin,
      certificate: authority,
      target: TARGET,
      status: 'not_revoked',
      issuedAt: '2026-07-22T12:03:00Z',
      nextUpdate: '2026-07-22T12:08:00Z',
      previousStatus: revoked,
      signer: revokerSigner(() => { resurrectionSignCalls += 1; }),
    })).rejects.toThrow(/terminal revocation/i);
    expect(resurrectionSignCalls).toBe(0);

    const terminalRollback = verifyStatusArtifact(TARGET, second, {
      authorityPin,
      certificate: authority,
      previousStatus: revoked,
      now: NOW,
    });
    expect(terminalRollback.valid).toBe(false);
    expect(terminalRollback.reasons).toContain('terminal_revocation');
  });

  it('refuses substituted targets and targets outside the certified scope', async () => {
    const authority = await certificate();
    let signCalls = 0;
    await expect(buildStatusArtifact({
      authorityPin,
      certificate: authority,
      target: { ...TARGET, type: 'delegation' },
      status: 'not_revoked',
      issuedAt: '2026-07-22T12:00:00Z',
      nextUpdate: '2026-07-22T12:05:00Z',
      signer: revokerSigner(() => { signCalls += 1; }),
    })).rejects.toThrow(/scope/i);
    expect(signCalls).toBe(0);

    const status = await buildStatusArtifact({
      authorityPin,
      certificate: authority,
      target: TARGET,
      status: 'not_revoked',
      issuedAt: '2026-07-22T12:00:00Z',
      nextUpdate: '2026-07-22T12:05:00Z',
      signer: revokerSigner(),
    });
    for (const substitutedTarget of [
      { ...TARGET, id: 'receipt:payment-release:other' },
      { ...TARGET, digest: `sha256:${'b'.repeat(64)}` },
      { ...TARGET, usage: 'execution' as const },
    ]) {
      const result = verifyStatusArtifact(substitutedTarget, status, {
        authorityPin,
        certificate: authority,
        now: NOW,
      });
      expect(result.valid).toBe(false);
      expect(result.checks.target).toBe(false);
    }
  });

  it('rejects malformed or unsafe time windows before signing', async () => {
    let certificateSignCalls = 0;
    await expect(buildRevokerAuthorityCertificate(certificateInput({
      issuedAt: '2026-02-30T00:00:00Z',
      signer: authoritySigner(() => { certificateSignCalls += 1; }),
    }))).rejects.toThrow(/issuedAt/i);
    expect(certificateSignCalls).toBe(0);

    const authority = await certificate();
    for (const times of [
      { issuedAt: '2026-02-30T12:00:00Z', nextUpdate: '2026-07-22T12:05:00Z' },
      { issuedAt: '2026-07-22T12:00:00Z', nextUpdate: '2026-07-22T12:00:00Z' },
      { issuedAt: '2026-08-01T00:00:00Z', nextUpdate: '2026-08-01T00:01:00Z' },
    ]) {
      let signCalls = 0;
      await expect(buildStatusArtifact({
        authorityPin,
        certificate: authority,
        target: TARGET,
        status: 'not_revoked',
        ...times,
        signer: revokerSigner(() => { signCalls += 1; }),
      })).rejects.toThrow(/issuedAt|time|window|certificate/i);
      expect(signCalls).toBe(0);
    }
  });

  it('propagates external signer failure and never returns a partial artifact', async () => {
    const failingAuthoritySigner: ExternalEd25519Signer = {
      algorithm: 'Ed25519',
      keyId: authorityPin.key_id,
      async sign() {
        throw new Error('kms unavailable');
      },
    };
    await expect(buildRevokerAuthorityCertificate(certificateInput({
      signer: failingAuthoritySigner,
    }))).rejects.toThrow(/kms unavailable/i);

    const authority = await certificate();
    const failingRevokerSigner: ExternalEd25519Signer = {
      algorithm: 'Ed25519',
      keyId: deriveRevokerKeyId(publicKey(revokerKeys)),
      async sign() {
        throw new Error('hsm refused request');
      },
    };
    await expect(buildStatusArtifact({
      authorityPin,
      certificate: authority,
      target: TARGET,
      status: 'revoked',
      issuedAt: '2026-07-22T12:00:00Z',
      nextUpdate: null,
      signer: failingRevokerSigner,
    })).rejects.toThrow(/hsm refused request/i);
  });

  it('rejects unknown fields, unsupported values, raw private keys, and bad signer output', async () => {
    await expect(buildRevokerAuthorityCertificate({
      ...certificateInput(),
      unknown: true,
    } as any)).rejects.toThrow(/unknown/i);

    await expect(buildRevokerAuthorityCertificate(certificateInput({
      signer: {
        ...authoritySigner(),
        privateKey: authorityKeys.privateKey,
      },
    }))).rejects.toThrow(/private key material/i);

    const authority = await certificate();
    let sequenceInjectionSignCalls = 0;
    await expect(buildStatusArtifact({
      authorityPin,
      certificate: authority,
      target: TARGET,
      status: 'not_revoked',
      issuedAt: '2026-07-22T12:00:00Z',
      nextUpdate: '2026-07-22T12:05:00Z',
      sequence: 42,
      signer: revokerSigner(() => { sequenceInjectionSignCalls += 1; }),
    } as any)).rejects.toThrow(/unknown.*sequence/i);
    expect(sequenceInjectionSignCalls).toBe(0);

    await expect(buildStatusArtifact({
      authorityPin,
      certificate: authority,
      target: { ...TARGET, unknown: true } as any,
      status: 'not_revoked',
      issuedAt: '2026-07-22T12:00:00Z',
      nextUpdate: '2026-07-22T12:05:00Z',
      signer: revokerSigner(),
    })).rejects.toThrow(/target.*unknown/i);

    await expect(buildStatusArtifact({
      authorityPin,
      certificate: authority,
      target: TARGET,
      status: 'not_revoked',
      issuedAt: '2026-07-22T12:00:00Z',
      nextUpdate: '2026-07-22T12:05:00Z',
      signer: {
        algorithm: 'Ed25519',
        keyId: deriveRevokerKeyId(publicKey(revokerKeys)),
        async sign() { return 'not-a-signature'; },
      },
    })).rejects.toThrow(/signature/i);
  });

  it('rejects missing, accessor-backed, and symbol-keyed issuer inputs', async () => {
    const missing = certificateInput() as Record<string, unknown>;
    delete missing.certificateId;
    await expect(buildRevokerAuthorityCertificate(missing as any)).rejects.toThrow(/missing.*certificateId/i);

    const accessor = certificateInput() as Record<string, unknown>;
    Object.defineProperty(accessor, 'certificateId', {
      enumerable: true,
      get() { return 'revoker-authority:acme:primary:v1'; },
    });
    await expect(buildRevokerAuthorityCertificate(accessor as any)).rejects.toThrow(/plain data object/i);

    const symbolKeyed = certificateInput() as Record<PropertyKey, unknown>;
    symbolKeyed[Symbol('hidden')] = true;
    await expect(buildRevokerAuthorityCertificate(symbolKeyed as any)).rejects.toThrow(/plain data object/i);
  });

  it('rejects malformed authority pins, keys, scopes, and certificate windows', async () => {
    const cases = [
      { authorityPin: { ...authorityPin, authority_domain: 'https://status.acme.example' } },
      { authorityPin: { ...authorityPin, authority_id: 'bad id' } },
      { authorityPin: { ...authorityPin, public_key: 'not-a-key' } },
      { revokerPublicKey: 'not-a-key' },
      { scope: { allowed_target_types: [], allowed_usages: ['authorization'] } },
      { scope: { allowed_target_types: ['receipt', 'receipt'], allowed_usages: ['authorization'] } },
      { scope: { allowed_target_types: ['unknown'], allowed_usages: ['authorization'] } },
      { scope: { allowed_target_types: ['receipt'], allowed_usages: ['unknown'] } },
      { issuedAt: '2026-08-01T00:00:00Z', expiresAt: '2026-08-01T00:00:00Z' },
      { issuedAt: '2026-07-01T00:00:00+24:00' },
    ];
    for (const overrides of cases) {
      await expect(buildRevokerAuthorityCertificate(certificateInput(overrides)))
        .rejects.toBeInstanceOf(Error);
    }

    const sparse = ['receipt'] as unknown[];
    sparse.length = 2;
    await expect(buildRevokerAuthorityCertificate(certificateInput({
      scope: { allowed_target_types: sparse, allowed_usages: ['authorization'] },
    }))).rejects.toThrow(/scope/i);
  });

  it('rejects malformed targets, statuses, and terminal/current windows', async () => {
    const authority = await certificate();
    const cases = [
      { target: { ...TARGET, type: 'unknown' } },
      { target: { ...TARGET, id: 'bad id' } },
      { target: { ...TARGET, digest: `sha256:${'A'.repeat(64)}` } },
      { target: { ...TARGET, usage: 'unknown' } },
      { status: 'maybe' },
      { status: 'revoked', nextUpdate: '2026-07-22T12:05:00Z' },
      { nextUpdate: '2026-09-01T00:00:00Z' },
      { issuedAt: '2026-07-22T12:00:00+00:99' },
    ];
    for (const overrides of cases) {
      await expect(buildStatusArtifact(statusInput(authority, overrides) as any))
        .rejects.toBeInstanceOf(Error);
    }
  });

  it('accepts raw signature bytes and rejects invalid bytes or non-Error signer failure', async () => {
    const byteSigner: ExternalEd25519Signer = {
      algorithm: 'Ed25519',
      keyId: authorityPin.key_id,
      async sign(bytes) {
        return new Uint8Array(crypto.sign(null, Buffer.from(bytes), authorityKeys.privateKey));
      },
    };
    const authority = await buildRevokerAuthorityCertificate(certificateInput({ signer: byteSigner }));
    expect(verifyRevokerAuthorityCertificate(authority, { authorityPin, now: NOW }).valid).toBe(true);

    for (const sign of [
      async () => new Uint8Array(63),
      async () => { throw 'kms offline'; },
    ]) {
      await expect(buildRevokerAuthorityCertificate(certificateInput({
        signer: { algorithm: 'Ed25519', keyId: authorityPin.key_id, sign },
      }))).rejects.toBeInstanceOf(Error);
    }
    await expect(buildRevokerAuthorityCertificate(certificateInput({
      signer: { algorithm: 'P-256', keyId: authorityPin.key_id, async sign() { return ''; } },
    }))).rejects.toThrow(/algorithm/i);
    await expect(buildRevokerAuthorityCertificate(certificateInput({
      signer: { algorithm: 'Ed25519', keyId: authorityPin.key_id } as any,
    }))).rejects.toThrow(/requires async sign/i);
  });

  it('detects round-trip signature substitution for both artifact classes', async () => {
    const attacker = crypto.generateKeyPairSync('ed25519');
    await expect(buildRevokerAuthorityCertificate(certificateInput({
      signer: externalSigner(attacker, authorityPin.key_id),
    }))).rejects.toThrow(/round-trip|verification/i);

    const authority = await certificate();
    await expect(buildStatusArtifact(statusInput(authority, {
      signer: externalSigner(attacker, deriveRevokerKeyId(publicKey(revokerKeys))),
    }) as any)).rejects.toThrow(/round-trip|verification/i);
  });

  it('refuses every malformed predecessor axis before successor signing', async () => {
    const authority = await certificate();
    const first = await buildStatusArtifact(statusInput(authority) as any);
    const mutations: Array<(value: Record<string, any>) => void> = [
      (value) => { value.authority_domain = 'status.other.example'; },
      (value) => { value.target.id = 'receipt:other'; },
      (value) => { value.status = 'unknown'; },
      (value) => { value.sequence = -1; },
      (value) => { value.previous_status_digest = 'bad'; },
      (value) => { value.issued_at = '2026-07-22T12:01:00Z'; },
      (value) => { value.next_update = '2026-07-22T11:59:00Z'; },
      (value) => { value.proof.algorithm = 'P-256'; },
      (value) => { value.proof.signature_b64u = 'invalid'; },
    ];
    for (const mutate of mutations) {
      const previous = structuredClone(first) as Record<string, any>;
      mutate(previous);
      await expect(buildStatusArtifact(statusInput(authority, {
        issuedAt: '2026-07-22T12:01:00Z',
        nextUpdate: '2026-07-22T12:06:00Z',
        previousStatus: previous,
      }) as any)).rejects.toBeInstanceOf(Error);
    }

    const exhausted = structuredClone(first) as Record<string, any>;
    exhausted.sequence = Number.MAX_SAFE_INTEGER;
    resignStatus(exhausted);
    await expect(buildStatusArtifact(statusInput(authority, {
      issuedAt: '2026-07-22T12:01:00Z',
      nextUpdate: '2026-07-22T12:06:00Z',
      previousStatus: exhausted,
    }) as any)).rejects.toThrow(/sequence/i);

    const malformedTerminal = structuredClone(first) as Record<string, any>;
    malformedTerminal.status = 'revoked';
    resignStatus(malformedTerminal);
    await expect(buildStatusArtifact(statusInput(authority, {
      issuedAt: '2026-07-22T12:01:00Z',
      nextUpdate: '2026-07-22T12:06:00Z',
      previousStatus: malformedTerminal,
    }) as any)).rejects.toThrow(/revoked previousStatus|terminal revocation/i);
  });
});
