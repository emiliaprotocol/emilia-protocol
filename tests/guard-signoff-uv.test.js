// SPDX-License-Identifier: Apache-2.0
// Unit contract for deriveSignoffUserVerification: the REAL WebAuthn UV signal
// re-derived from a recorded Class-A signoff decision. Fail-closed on every
// missing/invalid input; true ONLY for a UV-flagged, action-bound, signature-
// valid, RP-scoped assertion.

import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { deriveSignoffUserVerification } from '../lib/guard-signoff-uv.js';

const RP_ID = 'emiliaprotocol.ai';
const ACTION_HASH = 'a'.repeat(64);

function canon(v) {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`;
  if (typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`;
  }
  return JSON.stringify(v);
}

// Build a real P-256 assertion + enrolled SPKI, mirroring approve-webauthn.
function build({ flags = 0x05, actionHash = ACTION_HASH, rpId = RP_ID } = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const context = {
    ep_version: '1.0', context_type: 'ep.signoff.v1',
    action_hash: actionHash, approver: 'ap_controller', initiator: 'user_1',
    nonce: 'sig_' + 'c'.repeat(32),
    issued_at: '2026-06-09T17:21:05.000Z', expires_at: '2026-06-09T17:26:05.000Z',
  };
  const challenge = crypto.createHash('sha256').update(canon(context), 'utf8').digest().toString('base64url');
  const clientData = Buffer.from(
    JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://www.emiliaprotocol.ai' }), 'utf8',
  );
  const authData = Buffer.concat([
    crypto.createHash('sha256').update(rpId, 'utf8').digest(),
    Buffer.from([flags]), Buffer.from([0, 0, 0, 9]),
  ]);
  const signed = Buffer.concat([authData, crypto.createHash('sha256').update(clientData).digest()]);
  const signature = crypto.sign('sha256', signed, privateKey);
  return {
    decision: {
      key_class: 'A', context,
      webauthn: {
        credential_id: 'cred_1',
        authenticator_data: authData.toString('base64url'),
        client_data_json: clientData.toString('base64url'),
        signature: signature.toString('base64url'),
      },
    },
    spki: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

describe('deriveSignoffUserVerification', () => {
  it('verifies a genuine UV (0x05) assertion bound to the action', () => {
    const { decision, spki } = build({ flags: 0x05 });
    const r = deriveSignoffUserVerification({
      decision, approverPublicKeySpki: spki, expectedActionHash: ACTION_HASH, rpId: RP_ID,
    });
    expect(r.verified).toBe(true);
    expect(r.reason).toBe('user_verified');
    expect(r.checks.user_verified).toBe(true);
  });

  it('refuses a present-only (0x01, no UV) assertion', () => {
    const { decision, spki } = build({ flags: 0x01 });
    const r = deriveSignoffUserVerification({
      decision, approverPublicKeySpki: spki, expectedActionHash: ACTION_HASH, rpId: RP_ID,
    });
    expect(r.verified).toBe(false);
    expect(r.reason).toBe('user_verification_absent');
  });

  it('refuses when the signed context binds a DIFFERENT action', () => {
    const { decision, spki } = build({ flags: 0x05, actionHash: 'b'.repeat(64) });
    const r = deriveSignoffUserVerification({
      decision, approverPublicKeySpki: spki, expectedActionHash: ACTION_HASH, rpId: RP_ID,
    });
    expect(r.verified).toBe(false);
    expect(r.reason).toBe('action_hash_mismatch');
  });

  it('refuses when the assertion was scoped to a DIFFERENT relying party', () => {
    const { decision, spki } = build({ flags: 0x05, rpId: 'evil.example.com' });
    const r = deriveSignoffUserVerification({
      decision, approverPublicKeySpki: spki, expectedActionHash: ACTION_HASH, rpId: RP_ID,
    });
    expect(r.verified).toBe(false);
  });

  it('refuses when the enrolled key does not match the signature', () => {
    const { decision } = build({ flags: 0x05 });
    const other = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
      .publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const r = deriveSignoffUserVerification({
      decision, approverPublicKeySpki: other, expectedActionHash: ACTION_HASH, rpId: RP_ID,
    });
    expect(r.verified).toBe(false);
  });

  it('fails closed on missing decision / assertion / key', () => {
    expect(deriveSignoffUserVerification({}).verified).toBe(false);
    expect(deriveSignoffUserVerification({ decision: {} }).reason).toBe('missing_assertion_evidence');
    const { decision, spki } = build();
    expect(deriveSignoffUserVerification({ decision: { key_class: 'A', context: decision.context } }).reason)
      .toBe('missing_assertion_evidence');
    expect(deriveSignoffUserVerification({ decision, approverPublicKeySpki: null, expectedActionHash: ACTION_HASH }).reason)
      .toBe('missing_approver_key');
    expect(spki).toBeTruthy();
  });
});
