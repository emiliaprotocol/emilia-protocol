// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto, { type KeyObject } from 'node:crypto';

import {
  REVOCER_AUTHORITY_DOMAIN,
  REVOCER_AUTHORITY_VERSION,
  STATUS_DOMAIN,
  STATUS_VERSION,
  revokerAuthorityCertificateDigest,
  statusArtifactDigest,
  verifyRevokerAuthorityCertificate,
  verifyStatusArtifact,
} from './status.js';

type Obj = Record<string, any>;
interface KeyPair { publicKey: KeyObject; privateKey: KeyObject }

const NOW = '2026-07-22T12:04:00Z';
const TARGET = {
  type: 'receipt',
  id: 'receipt:payment-release:0001',
  digest: `sha256:${'a'.repeat(64)}`,
  usage: 'authorization',
};

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

const authorityPin = {
  authority_domain: 'status.acme.example',
  authority_id: 'org:acme',
  key_id: 'key:acme-status-root',
  public_key: publicKey(authorityKeys),
};

function signBody(body: Obj, domain: string, signer: KeyPair): string {
  return crypto.sign(
    null,
    Buffer.from(`${domain}${jcs(body)}`, 'utf8'),
    signer.privateKey,
  ).toString('base64url');
}

function certificateBody(): Obj {
  return {
    '@version': REVOCER_AUTHORITY_VERSION,
    certificate_id: 'revoker-authority:acme:primary:v1',
    authority_domain: authorityPin.authority_domain,
    authority_id: authorityPin.authority_id,
    revoker_id: 'revoker:acme:primary',
    revoker_key: {
      algorithm: 'Ed25519',
      key_id: keyId('ep:revoker-key:sha256:', revokerKeys),
      public_key: publicKey(revokerKeys),
    },
    scope: {
      allowed_target_types: ['receipt', 'commit'],
      allowed_usages: ['authorization', 'execution'],
    },
    issued_at: '2026-07-01T00:00:00Z',
    expires_at: '2026-08-01T00:00:00Z',
  };
}

function signCertificate(
  body: Obj = certificateBody(),
  signer: KeyPair = authorityKeys,
): Obj {
  const unsigned = structuredClone(body);
  delete unsigned.proof;
  return {
    ...unsigned,
    proof: {
      algorithm: 'Ed25519',
      key_id: authorityPin.key_id,
      signature_b64u: signBody(unsigned, REVOCER_AUTHORITY_DOMAIN, signer),
    },
  };
}

function statusBody(certificate: Obj): Obj {
  return {
    '@version': STATUS_VERSION,
    authority_domain: authorityPin.authority_domain,
    revoker_authority_digest: revokerAuthorityCertificateDigest(certificate),
    target: structuredClone(TARGET),
    status: 'not_revoked',
    sequence: 0,
    previous_status_digest: null,
    issued_at: '2026-07-22T12:00:00Z',
    next_update: '2026-07-22T12:05:00Z',
  };
}

function signStatus(
  body: Obj,
  signer: KeyPair = revokerKeys,
  domain = STATUS_DOMAIN,
): Obj {
  const unsigned = structuredClone(body);
  delete unsigned.proof;
  return {
    ...unsigned,
    proof: {
      algorithm: 'Ed25519',
      key_id: keyId('ep:revoker-key:sha256:', revokerKeys),
      signature_b64u: signBody(unsigned, domain, signer),
    },
  };
}

function verify(status: Obj, certificate: Obj, extra: Obj = {}) {
  return verifyStatusArtifact(TARGET, status, {
    authorityPin,
    certificate,
    now: NOW,
    ...extra,
  });
}

test('accepts exact JCS/domain-separated Ed25519 shapes for current non-revocation', () => {
  const certificate = signCertificate();
  const status = signStatus(statusBody(certificate));

  const certResult = verifyRevokerAuthorityCertificate(certificate, {
    authorityPin,
    now: NOW,
  });
  assert.equal(certResult.valid, true, JSON.stringify(certResult));

  const result = verify(status, certificate);
  assert.equal(result.outcome, 'current_not_revoked', JSON.stringify(result));
  assert.equal(result.valid, true);
  assert.equal(result.status_digest, statusArtifactDigest(status));
  assert.deepEqual(result.checks, {
    structure: true,
    certificate: true,
    authority: true,
    target: true,
    scope: true,
    signature: true,
    freshness: true,
    sequence: true,
    terminal: true,
  });

  const unsigned = structuredClone(status);
  delete unsigned.proof;
  const noDomain = structuredClone(status);
  noDomain.proof.signature_b64u = crypto.sign(
    null,
    Buffer.from(jcs(unsigned), 'utf8'),
    revokerKeys.privateKey,
  ).toString('base64url');
  const domainFailure = verify(noDomain, certificate);
  assert.equal(domainFailure.outcome, 'indeterminate');
  assert.equal(domainFailure.checks.signature, false);
});

test('binds the certificate to a pinned authority domain, identity, key, and signature domain', () => {
  const certificate = signCertificate();
  const wrongDomainPin = { ...authorityPin, authority_domain: 'status.evil.example' };
  const domain = verifyRevokerAuthorityCertificate(certificate, {
    authorityPin: wrongDomainPin,
    now: NOW,
  });
  assert.equal(domain.valid, false);
  assert.equal(domain.checks.authority, false);

  const substitutedRoot = crypto.generateKeyPairSync('ed25519');
  const substituted = signCertificate(certificateBody(), substitutedRoot);
  const signature = verifyRevokerAuthorityCertificate(substituted, { authorityPin, now: NOW });
  assert.equal(signature.valid, false);
  assert.equal(signature.checks.signature, false);

  const wrongDomainBytes = structuredClone(certificate);
  const unsigned = structuredClone(wrongDomainBytes);
  delete unsigned.proof;
  wrongDomainBytes.proof.signature_b64u = signBody(unsigned, `${REVOCER_AUTHORITY_VERSION}:wrong\0`, authorityKeys);
  assert.equal(verifyRevokerAuthorityCertificate(wrongDomainBytes, {
    authorityPin,
    now: NOW,
  }).checks.signature, false);
});

test('binds the exact target and enforces fixed and certificate-scoped types and usages', () => {
  const certificate = signCertificate();
  const status = signStatus(statusBody(certificate));

  for (const target of [
    { ...TARGET, id: 'receipt:other' },
    { ...TARGET, digest: `sha256:${'b'.repeat(64)}` },
    { ...TARGET, type: 'commit' },
    { ...TARGET, usage: 'execution' },
  ]) {
    const result = verifyStatusArtifact(target, status, { authorityPin, certificate, now: NOW });
    assert.equal(result.outcome, 'indeterminate');
    assert.equal(result.checks.target, false);
  }

  const narrowBody = certificateBody();
  narrowBody.scope.allowed_target_types = ['delegation'];
  narrowBody.scope.allowed_usages = ['delegation'];
  const narrowCertificate = signCertificate(narrowBody);
  const scopedOut = signStatus(statusBody(narrowCertificate));
  const scope = verify(scopedOut, narrowCertificate);
  assert.equal(scope.outcome, 'indeterminate');
  assert.equal(scope.checks.scope, false);

  const unsupportedCertBody = certificateBody();
  unsupportedCertBody.scope.allowed_target_types = ['account'];
  const unsupportedCert = signCertificate(unsupportedCertBody);
  assert.equal(verifyRevokerAuthorityCertificate(unsupportedCert, {
    authorityPin,
    now: NOW,
  }).checks.scope, false);

  const unsupportedTarget = { ...TARGET, usage: 'authentication' };
  const unsupportedStatusBody = statusBody(certificate);
  unsupportedStatusBody.target = unsupportedTarget;
  const unsupportedStatus = signStatus(unsupportedStatusBody);
  const unsupported = verifyStatusArtifact(unsupportedTarget, unsupportedStatus, {
    authorityPin,
    certificate,
    now: NOW,
  });
  assert.equal(unsupported.outcome, 'indeterminate');
  assert.equal(unsupported.checks.target, false);
});

test('requires a fresh, ordered issued_at/next_update window for affirmative status', () => {
  const certificate = signCertificate();
  const body = statusBody(certificate);

  assert.equal(verify(signStatus(body), certificate, {
    now: body.next_update,
  }).outcome, 'indeterminate');

  const future = structuredClone(body);
  future.issued_at = '2026-07-22T12:04:01Z';
  future.next_update = '2026-07-22T12:06:00Z';
  assert.ok(verify(signStatus(future), certificate).reasons.includes('status_not_yet_valid'));

  const inverted = structuredClone(body);
  inverted.next_update = inverted.issued_at;
  assert.ok(verify(signStatus(inverted), certificate).reasons.includes('invalid_status_window'));

  const beyondAuthority = structuredClone(body);
  beyondAuthority.next_update = '2026-08-01T00:00:01Z';
  assert.ok(verify(signStatus(beyondAuthority), certificate).reasons.includes('status_window_exceeds_certificate'));

  const impossible = structuredClone(body);
  impossible.issued_at = '2026-02-30T12:00:00Z';
  assert.equal(verify(signStatus(impossible), certificate).checks.freshness, false);
});

test('enforces monotonic sequence and the digest of the relying-party-held predecessor', () => {
  const certificate = signCertificate();
  const first = signStatus(statusBody(certificate));
  const nextBody = statusBody(certificate);
  nextBody.sequence = 1;
  nextBody.previous_status_digest = statusArtifactDigest(first);
  nextBody.issued_at = '2026-07-22T12:03:00Z';
  nextBody.next_update = '2026-07-22T12:08:00Z';
  const next = signStatus(nextBody);

  const accepted = verify(next, certificate, { previousStatus: first });
  assert.equal(accepted.outcome, 'current_not_revoked', JSON.stringify(accepted));

  const missing = verify(next, certificate);
  assert.equal(missing.outcome, 'indeterminate');
  assert.ok(missing.reasons.includes('missing_previous_status'));

  const wrongDigestBody = structuredClone(nextBody);
  wrongDigestBody.previous_status_digest = `sha256:${'f'.repeat(64)}`;
  const wrongDigest = verify(signStatus(wrongDigestBody), certificate, { previousStatus: first });
  assert.equal(wrongDigest.checks.sequence, false);
  assert.ok(wrongDigest.reasons.includes('previous_status_digest_mismatch'));

  const rollback = verify(first, certificate, { previousStatus: next });
  assert.equal(rollback.outcome, 'indeterminate');
  assert.equal(rollback.checks.sequence, false);
  assert.ok(rollback.reasons.includes('sequence_not_monotonic'));

  const sameTimeBody = structuredClone(nextBody);
  sameTimeBody.issued_at = first.issued_at;
  sameTimeBody.next_update = '2026-07-22T12:08:00Z';
  assert.ok(verify(signStatus(sameTimeBody), certificate, {
    previousStatus: first,
  }).reasons.includes('status_issued_at_not_monotonic'));
});

test('returns revoked for an effective terminal state and never lets it age out or roll back', () => {
  const certificate = signCertificate();
  const first = signStatus(statusBody(certificate));
  const revokedBody = statusBody(certificate);
  revokedBody.status = 'revoked';
  revokedBody.sequence = 1;
  revokedBody.previous_status_digest = statusArtifactDigest(first);
  revokedBody.issued_at = '2026-07-22T12:03:00Z';
  revokedBody.next_update = null;
  const revoked = signStatus(revokedBody);

  const terminal = verify(revoked, certificate, {
    previousStatus: first,
    now: '2030-01-01T00:00:00Z',
  });
  assert.equal(terminal.outcome, 'revoked', JSON.stringify(terminal));
  assert.equal(terminal.valid, true);

  const resurrectionBody = statusBody(certificate);
  resurrectionBody.sequence = 2;
  resurrectionBody.previous_status_digest = statusArtifactDigest(revoked);
  resurrectionBody.issued_at = '2026-07-22T12:04:00Z';
  resurrectionBody.next_update = '2026-07-22T12:09:00Z';
  const resurrection = verify(signStatus(resurrectionBody), certificate, {
    previousStatus: revoked,
  });
  assert.equal(resurrection.outcome, 'indeterminate');
  assert.equal(resurrection.checks.terminal, false);
  assert.ok(resurrection.reasons.includes('terminal_revocation'));

  const rollback = verify(first, certificate, { previousStatus: revoked });
  assert.equal(rollback.outcome, 'indeterminate');
  assert.ok(rollback.reasons.includes('terminal_revocation'));
});

test('rejects stale, future, or malformed revoked states instead of treating them as terminal', () => {
  const certificate = signCertificate();
  const body = statusBody(certificate);
  body.status = 'revoked';
  body.next_update = '2026-07-22T12:05:00Z';
  assert.ok(verify(signStatus(body), certificate).reasons.includes('revoked_status_has_next_update'));

  body.next_update = null;
  body.issued_at = '2026-07-22T12:04:01Z';
  assert.equal(verify(signStatus(body), certificate).outcome, 'indeterminate');
});

test('rejects unknown fields at every signed object boundary', () => {
  const baseCertificate = signCertificate();
  const baseStatus = signStatus(statusBody(baseCertificate));

  for (const mutate of [
    (value: Obj) => { value.unsigned_extension = true; },
    (value: Obj) => { value.target.unknown = true; },
    (value: Obj) => { value.proof.unknown = true; },
  ]) {
    const candidate = structuredClone(baseStatus);
    mutate(candidate);
    const result = verify(candidate, baseCertificate);
    assert.equal(result.outcome, 'indeterminate');
    assert.equal(result.checks.structure, false);
  }

  for (const mutate of [
    (value: Obj) => { value.unknown = true; },
    (value: Obj) => { value.revoker_key.unknown = true; },
    (value: Obj) => { value.scope.unknown = true; },
    (value: Obj) => { value.proof.unknown = true; },
  ]) {
    const candidate = structuredClone(baseCertificate);
    mutate(candidate);
    const result = verifyRevokerAuthorityCertificate(candidate, { authorityPin, now: NOW });
    assert.equal(result.valid, false);
    assert.equal(result.checks.structure, false);
  }
});

test('rejects certificate substitution, field tampering, noncanonical encodings, and non-Ed25519 keys', () => {
  const certificate = signCertificate();
  const status = signStatus(statusBody(certificate));

  const substitutedBody = certificateBody();
  substitutedBody.certificate_id = 'revoker-authority:acme:substituted';
  const substitutedCertificate = signCertificate(substitutedBody);
  const substituted = verify(status, substitutedCertificate);
  assert.equal(substituted.outcome, 'indeterminate');
  assert.ok(substituted.reasons.includes('revoker_authority_digest_mismatch'));

  const tampered = structuredClone(status);
  tampered.status = 'revoked';
  tampered.next_update = null;
  assert.equal(verify(tampered, certificate).checks.signature, false);

  const padded = structuredClone(status);
  padded.proof.signature_b64u += '=';
  assert.equal(verify(padded, certificate).checks.structure, false);

  const p256 = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const wrongKeyBody = certificateBody();
  wrongKeyBody.revoker_key.public_key = publicKey(p256);
  wrongKeyBody.revoker_key.key_id = keyId('ep:revoker-key:sha256:', p256);
  const wrongKey = signCertificate(wrongKeyBody);
  assert.equal(verifyRevokerAuthorityCertificate(wrongKey, {
    authorityPin,
    now: NOW,
  }).checks.structure, false);
});
