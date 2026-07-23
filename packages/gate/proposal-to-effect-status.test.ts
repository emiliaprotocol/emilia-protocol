// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto, { type KeyObject } from 'node:crypto';
import test from 'node:test';

import type { AebDigest } from '@emilia-protocol/verify/aeb-adapter-contract';
import {
  REVOCER_AUTHORITY_DOMAIN,
  REVOCER_AUTHORITY_VERSION,
  STATUS_DOMAIN,
  STATUS_VERSION,
  revokerAuthorityCertificateDigest,
  statusArtifactDigest,
  type RevokerAuthorityPin,
  type StatusTarget,
} from '@emilia-protocol/verify/status';

import type { ProposalToEffectOptions } from './src/proposal-to-effect.ts';
import {
  createProposalToEffectStatusVerifier,
  type ProposalToEffectStatusVerifierOptions,
} from './proposal-to-effect-status.js';
import type {
  ProposalToEffectStatusHeadStore,
} from './proposal-to-effect-status-head-store.js';

type Obj = Record<string, any>;
interface KeyPair { publicKey: KeyObject; privateKey: KeyObject }

const NOW = '2026-07-22T12:04:00.000Z';
const NEXT_UPDATE = '2026-07-22T12:05:00Z';
const EXPECTED = Object.freeze({
  tenant_id: 'tenant:acme',
  executor_id: 'executor:gate-1',
  operation_id: 'operation:payment-release-1',
  caid: `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`,
  artifact_ref: 'receipt:payment-release:0001',
  evidence_digest: `sha256:${'a'.repeat(64)}` as AebDigest,
  replay_unit: `sha256:${'b'.repeat(64)}` as AebDigest,
});
const TARGET: StatusTarget = Object.freeze({
  type: 'receipt',
  id: EXPECTED.artifact_ref,
  digest: EXPECTED.evidence_digest,
  usage: 'authorization',
});

const authorityKeys = crypto.generateKeyPairSync('ed25519');
const revokerKeys = crypto.generateKeyPairSync('ed25519');

function jcs(value: any): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  return `{${Object.keys(value).sort()
    .map((key) => `${JSON.stringify(key)}:${jcs(value[key])}`).join(',')}}`;
}

function publicKey(keyPair: KeyPair): string {
  return keyPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
}

function keyId(prefix: string, keyPair: KeyPair): string {
  const der = keyPair.publicKey.export({ type: 'spki', format: 'der' });
  return `${prefix}${crypto.createHash('sha256').update(der).digest('hex')}`;
}

const authorityPin: RevokerAuthorityPin = Object.freeze({
  authority_domain: 'status.acme.example',
  authority_id: 'org:acme',
  key_id: 'key:acme-status-root',
  public_key: publicKey(authorityKeys),
});

function signBody(body: Obj, domain: string, signer: KeyPair): string {
  return crypto.sign(
    null,
    Buffer.from(`${domain}${jcs(body)}`, 'utf8'),
    signer.privateKey,
  ).toString('base64url');
}

function certificateBody(revoker: KeyPair = revokerKeys): Obj {
  return {
    '@version': REVOCER_AUTHORITY_VERSION,
    certificate_id: 'revoker-authority:acme:primary:v1',
    authority_domain: authorityPin.authority_domain,
    authority_id: authorityPin.authority_id,
    revoker_id: 'revoker:acme:primary',
    revoker_key: {
      algorithm: 'Ed25519',
      key_id: keyId('ep:revoker-key:sha256:', revoker),
      public_key: publicKey(revoker),
    },
    scope: {
      allowed_target_types: ['receipt'],
      allowed_usages: ['authorization'],
    },
    issued_at: '2026-07-01T00:00:00Z',
    expires_at: '2026-08-01T00:00:00Z',
  };
}

function signCertificate(body: Obj = certificateBody()): Obj {
  const unsigned = structuredClone(body);
  delete unsigned.proof;
  return {
    ...unsigned,
    proof: {
      algorithm: 'Ed25519',
      key_id: authorityPin.key_id,
      signature_b64u: signBody(unsigned, REVOCER_AUTHORITY_DOMAIN, authorityKeys),
    },
  };
}

function statusBody(certificate: Obj, overrides: Obj = {}): Obj {
  return {
    '@version': STATUS_VERSION,
    authority_domain: authorityPin.authority_domain,
    revoker_authority_digest: revokerAuthorityCertificateDigest(certificate),
    target: structuredClone(TARGET),
    status: 'not_revoked',
    sequence: 0,
    previous_status_digest: null,
    issued_at: '2026-07-22T12:00:00Z',
    next_update: NEXT_UPDATE,
    ...overrides,
  };
}

function signStatus(body: Obj, signer: KeyPair = revokerKeys): Obj {
  const unsigned = structuredClone(body);
  delete unsigned.proof;
  return {
    ...unsigned,
    proof: {
      algorithm: 'Ed25519',
      key_id: keyId('ep:revoker-key:sha256:', signer),
      signature_b64u: signBody(unsigned, STATUS_DOMAIN, signer),
    },
  };
}

const certificate = signCertificate();

function statusHeadStore(
  head: Obj | null = null,
  predecessor: Obj | null = null,
): ProposalToEffectStatusHeadStore {
  let acceptedHead = head === null ? null : structuredClone(head);
  let acceptedPredecessor = predecessor === null ? null : structuredClone(predecessor);
  return {
    durable: true,
    tenantId: EXPECTED.tenant_id,
    relyingPartyId: 'rp:gate-1',
    async accept({ status, verify }) {
      const candidate = structuredClone(status);
      const candidateDigest = statusArtifactDigest(candidate);
      const existing = acceptedHead !== null
        && candidateDigest === statusArtifactDigest(acceptedHead);
      const verification = await verify(existing
        ? acceptedPredecessor ?? undefined
        : acceptedHead ?? undefined);
      if (!verification.valid || verification.outcome === 'indeterminate') {
        return {
          accepted: false,
          source: null,
          reason: verification.reasons[0] ?? 'status_verification_failed',
          verification,
        };
      }
      if (existing) {
        return { accepted: true, source: 'existing', reason: null, verification };
      }
      acceptedPredecessor = acceptedHead;
      acceptedHead = candidate;
      return { accepted: true, source: 'advanced', reason: null, verification };
    },
  };
}

function verifier(
  overrides: Partial<ProposalToEffectStatusVerifierOptions> = {},
): ProposalToEffectOptions['aeb']['statusVerifier'] {
  return createProposalToEffectStatusVerifier({
    authorityPin,
    targetMapper: ({ expected }) => ({
      type: 'receipt',
      id: expected.artifact_ref,
      digest: expected.evidence_digest,
      usage: 'authorization',
    }),
    certificateResolver: async () => certificate,
    statusHeadStore: statusHeadStore(),
    consumptionStateResolver: async () => ({ authenticated: true, consumed: false }),
    ...overrides,
  });
}

async function check(
  statusArtifact: unknown,
  statusVerifier = verifier(),
) {
  return statusVerifier({
    status_artifact: statusArtifact,
    expected: EXPECTED,
    now: NOW,
  });
}

test('rejects the legacy caller-controlled previous-head resolver configuration', () => {
  assert.throws(
    () => createProposalToEffectStatusVerifier({
      authorityPin,
      targetMapper: () => TARGET,
      certificateResolver: async () => certificate,
      previousHeadResolver: async () => ({ authenticated: true, status: null }),
      consumptionStateResolver: async () => ({ authenticated: true, consumed: false }),
    } as unknown as ProposalToEffectStatusVerifierOptions),
    /proposal_to_effect_status_configuration_invalid/,
  );
});

test('gives durable custody no presenter-supplied predecessor input', async () => {
  const base = statusHeadStore();
  let acceptedInputKeys: string[] = [];
  const observingStore: ProposalToEffectStatusHeadStore = {
    ...base,
    async accept(input) {
      acceptedInputKeys = Object.keys(input).sort();
      return base.accept(input);
    },
  };

  const result = await check(
    signStatus(statusBody(certificate)),
    verifier({ statusHeadStore: observingStore }),
  );

  assert.equal(result.valid, true);
  assert.deepEqual(acceptedInputKeys, ['status', 'target', 'verify']);
});

test('returns one normalized unconsumed AEB status only for current non-revocation', async () => {
  const result = await check(signStatus(statusBody(certificate)));

  assert.deepEqual(result, {
    valid: true,
    outcome: 'current_not_revoked',
    status: {
      checked_at: NOW,
      expires_at: '2026-07-22T12:05:00.000Z',
      revocation_checked: true,
      revoked: false,
      consumed: false,
    },
  });
});

test('rejects presenter certificate substitution against the server-resolved certificate', async () => {
  const substitutedRevoker = crypto.generateKeyPairSync('ed25519');
  const substitutedCertificate = signCertificate(certificateBody(substitutedRevoker));
  const presented = signStatus(statusBody(substitutedCertificate), substitutedRevoker);

  const result = await check(presented);

  assert.equal(result.valid, false);
  assert.equal(result.outcome, 'indeterminate');
  assert.equal(result.status, null);
});

test('rejects rollback against the relying-party-held previous status head', async () => {
  const first = signStatus(statusBody(certificate));
  const next = signStatus(statusBody(certificate, {
    sequence: 1,
    previous_status_digest: statusArtifactDigest(first),
    issued_at: '2026-07-22T12:02:00Z',
    next_update: '2026-07-22T12:06:00Z',
  }));
  const statusVerifier = verifier({
    statusHeadStore: statusHeadStore(next, first),
  });

  const result = await check(first, statusVerifier);

  assert.equal(result.valid, false);
  assert.equal(result.outcome, 'indeterminate');
  assert.equal(result.status, null);
});

test('rejects stale affirmative status', async () => {
  const stale = signStatus(statusBody(certificate, {
    next_update: '2026-07-22T12:03:59Z',
  }));

  const result = await check(stale);

  assert.equal(result.valid, false);
  assert.equal(result.outcome, 'indeterminate');
  assert.equal(result.status, null);
});

test('rejects an authenticated terminal revocation without returning AEB status', async () => {
  const revoked = signStatus(statusBody(certificate, {
    status: 'revoked',
    next_update: null,
  }));

  const result = await check(revoked);

  assert.equal(result.valid, false);
  assert.equal(result.outcome, 'revoked');
  assert.equal(result.status, null);
});

test('requires authenticated local unconsumed state and never infers it from status', async () => {
  const current = signStatus(statusBody(certificate));
  const consumed = await check(current, verifier({
    consumptionStateResolver: async () => ({ authenticated: true, consumed: true }),
  }));
  const unknown = await check(current, verifier({
    consumptionStateResolver: async () => ({ authenticated: false, consumed: false }),
  }));

  assert.deepEqual(
    [consumed.valid, consumed.outcome, consumed.status],
    [false, 'indeterminate', null],
  );
  assert.deepEqual(
    [unknown.valid, unknown.outcome, unknown.status],
    [false, 'indeterminate', null],
  );
});

test('fails closed when any server-side resolver is unavailable', async () => {
  const current = signStatus(statusBody(certificate));
  const unavailableStore = statusHeadStore();
  unavailableStore.accept = async () => { throw new Error('head store down'); };
  const unavailable = [
    verifier({ certificateResolver: async () => { throw new Error('certificate store down'); } }),
    verifier({ statusHeadStore: unavailableStore }),
    verifier({ consumptionStateResolver: async () => { throw new Error('consumption store down'); } }),
  ];

  for (const statusVerifier of unavailable) {
    const result = await check(current, statusVerifier);
    assert.equal(result.valid, false);
    assert.equal(result.outcome, 'indeterminate');
    assert.equal(result.status, null);
  }
});

test('rejects exact target mismatch from the PTE expected binding', async () => {
  const mismatched = signStatus(statusBody(certificate, {
    target: { ...TARGET, id: 'receipt:payment-release:other' },
  }));

  const result = await check(mismatched);

  assert.equal(result.valid, false);
  assert.equal(result.outcome, 'indeterminate');
  assert.equal(result.status, null);
});

test('rejects malformed artifacts before consulting local consumption state', async () => {
  let consumptionChecks = 0;
  const result = await check({ malformed: true }, verifier({
    consumptionStateResolver: async () => {
      consumptionChecks += 1;
      return { authenticated: true, consumed: false };
    },
  }));

  assert.equal(result.valid, false);
  assert.equal(result.outcome, 'indeterminate');
  assert.equal(result.status, null);
  assert.equal(consumptionChecks, 0);
});
