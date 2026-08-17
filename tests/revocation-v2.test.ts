// SPDX-License-Identifier: Apache-2.0
//
// EP-REVOCATION-v2, the lib twin: the ISSUER half (buildRevocationV2) plus the
// lockstep property. The verifier half is not duplicated here on purpose --
// lib/revocation/revocation.ts composes the published verifier rather than
// re-implementing it, and this suite asserts that composition is literally the
// same function object, which is a stronger lockstep guarantee than comparing
// two parallel bodies by eye. The verifier's own hostile matrix lives in
// packages/verify/revocation-v2.test.ts.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';

import {
  REVOCATION_VERSION,
  buildRevocation,
  verifyRevocation,
  buildRevocationV2,
  REVOCATION_V2_VERSION,
  REVOCATION_V2_REQUIRED_ALGORITHMS,
  revocationV2SignedPayload,
  verifyRevocationV2,
  verifyRevocationStatement,
  isRevokedAny,
} from '../lib/revocation/revocation.js';
import * as publishedRevocation from '../packages/verify/revocation.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const TARGET = { target_type: 'receipt', target_id: 'rcpt_twin_1', action_hash: `sha256:${'d'.repeat(64)}` };
const REVOKER_ID = 'ep:revoker:twin_operator';
const NOW = '2026-08-17T12:00:00.000Z';
const REVOKED_AT = '2026-06-20T12:00:00.000Z';

const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');

const SIGNER = {
  privateKey: ed.privateKey,
  publicKeyB64u: edPubB64u,
  pqSecretKey: pq.secretKey,
  pqPublicKeyB64u: pq.publicKey,
};
const PINS = { [REVOKER_ID]: { public_key: edPubB64u, pq_public_key: pqPubB64u } };

const build = (overrides = {}) => buildRevocationV2({
  target: TARGET, revoker_id: REVOKER_ID, revoked_at: REVOKED_AT, reason: 'authority withdrawn',
  signer: SIGNER, ...overrides,
});

describe('lockstep with the published verifier', () => {
  it('re-exports the SAME v2 verifier the offline package ships (no second body to drift)', () => {
    expect(verifyRevocationV2).toBe(publishedRevocation.verifyRevocationV2);
    expect(verifyRevocationStatement).toBe(publishedRevocation.verifyRevocationStatement);
    expect(isRevokedAny).toBe(publishedRevocation.isRevokedAny);
    expect(revocationV2SignedPayload).toBe(publishedRevocation.revocationV2SignedPayload);
    expect(REVOCATION_V2_VERSION).toBe(publishedRevocation.REVOCATION_V2_VERSION);
  });
});

describe('buildRevocationV2', () => {
  it('mints a statement the published verifier accepts under both pinned keys', async () => {
    const stmt = await build();
    expect(stmt['@version']).toBe(REVOCATION_V2_VERSION);
    expect(stmt.proof.required_algorithms).toEqual([...REVOCATION_V2_REQUIRED_ALGORITHMS]);
    expect(stmt.proof.signatures.map((s) => s.alg)).toEqual([...REVOCATION_V2_REQUIRED_ALGORITHMS]);

    const res = await verifyRevocationV2(TARGET, stmt, { revokerKeys: PINS, now: NOW });
    expect(res.valid).toBe(true);
    expect(res.errors).toEqual([]);
  });

  it('derives both key identifiers from the presented key material', async () => {
    const stmt = await build();
    expect(stmt.proof.revoker_key_id).toBe(
      `ep:revoker-key:sha256:${crypto.createHash('sha256').update(Buffer.from(edPubB64u, 'base64url')).digest('hex')}`,
    );
    expect(stmt.proof.pq_key_id).toBe(
      `ep:revoker-key:ml-dsa-65:sha256:${crypto.createHash('sha256').update(Buffer.from(pqPubB64u, 'base64url')).digest('hex')}`,
    );
  });

  it('both legs sign the SAME bytes, and those bytes carry the algorithm set', async () => {
    const stmt = await build();
    const bytes = revocationV2SignedPayload(stmt);
    expect(bytes.toString('utf8')).toContain('"required_algorithms":["Ed25519","ML-DSA-65"]');
    const [edLeg, pqLeg] = stmt.proof.signatures;
    expect(crypto.verify(null, bytes, ed.publicKey, Buffer.from(edLeg.sig, 'base64url'))).toBe(true);
    expect(ml_dsa65.verify(
      new Uint8Array(Buffer.from(pqLeg.sig, 'base64url')), new Uint8Array(bytes), pq.publicKey,
    )).toBe(true);
  });

  it('the deterministic variant reproduces byte-identical signatures', async () => {
    const a = await build({ deterministic: true });
    const b = await build({ deterministic: true });
    expect(a.proof.signatures).toEqual(b.proof.signatures);
  });

  it('honesty gate: refuses an incomplete target', async () => {
    await expect(build({ target: { target_type: 'receipt', target_id: 'x' } }))
      .rejects.toThrow(/fail-closed honesty gate/);
  });

  it('refuses a signer missing either half', async () => {
    await expect(build({ signer: { privateKey: ed.privateKey, publicKeyB64u: edPubB64u } }))
      .rejects.toThrow(/pqSecretKey/);
    await expect(build({ signer: { ...SIGNER, pqPublicKeyB64u: new Uint8Array(10) } }))
      .rejects.toThrow(/1952/);
  });

  it('refuses a malformed revoked_at anchor', async () => {
    await expect(build({ revoked_at: 'yesterday' })).rejects.toThrow(/RFC 3339/);
  });
});

describe('v1 / v2 coexistence in the lib twin', () => {
  it('the twin v1 verifier refuses a v2 statement CLEANLY on the version marker', async () => {
    const stmt = await build();
    const res = verifyRevocation(TARGET, stmt, {
      revokerKeys: { [REVOKER_ID]: { public_key: edPubB64u } }, now: NOW,
    });
    expect(res.valid).toBe(false);
    expect(res.checks.version).toBe(false);
    expect(res.errors).toContain(`unsupported version: ${REVOCATION_V2_VERSION}`);
  });

  it('the twin v1 builder and verifier still round-trip a v1 statement unchanged', () => {
    const stmt = buildRevocation({
      target: TARGET, revoker_id: REVOKER_ID, revoked_at: REVOKED_AT, reason: 'authority withdrawn',
      signer: { privateKey: ed.privateKey, publicKeyB64u: edPubB64u },
    });
    expect(stmt['@version']).toBe(REVOCATION_VERSION);
    const res = verifyRevocation(TARGET, stmt, {
      revokerKeys: { [REVOKER_ID]: { public_key: edPubB64u } }, now: NOW,
    });
    expect(res.valid).toBe(true);
  });

  it('the router and the aggregate handle a mixed bag', async () => {
    const v2 = await build();
    const v1 = buildRevocation({
      target: TARGET, revoker_id: REVOKER_ID, revoked_at: REVOKED_AT, reason: null,
      signer: { privateKey: ed.privateKey, publicKeyB64u: edPubB64u },
    });
    expect((await verifyRevocationStatement(TARGET, v2, { revokerKeys: PINS, now: NOW })).valid).toBe(true);
    expect((await verifyRevocationStatement(TARGET, v1, {
      revokerKeys: { [REVOKER_ID]: { public_key: edPubB64u } }, now: NOW,
    })).valid).toBe(true);
    expect(await isRevokedAny(TARGET, [{ junk: true }, v2], { revokerKeys: PINS, now: NOW })).toBe(true);
  });
});
