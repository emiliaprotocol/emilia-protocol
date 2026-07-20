// SPDX-License-Identifier: Apache-2.0
// Generator for executable EP-REVOCATION-v1 and EP-TIME-ATTESTATION-v1 conformance
// vectors. Each carries a REAL Ed25519 signature + the pinned keys / target / opts
// the verifier needs, so JS, Python, and Go verify the SAME bytes identically.
// Run: node generate-revtime.mjs
import crypto from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { verifyRevocation } from '../../packages/verify/index.js';

const canon = (v) => v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v);

let signerOrdinal = 0;
function newSigner() {
  // Fixed, unique Ed25519 seeds make committed vectors byte-reproducible while
  // still exercising real signatures. Never use these test keys outside this
  // conformance generator.
  const seed = Buffer.alloc(32, ++signerOrdinal);
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = crypto.createPublicKey(/** @type {any} */ (privateKey));
  return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}
const sign = (obj, priv) => crypto.sign(null, Buffer.from(canon(obj), 'utf8'), priv).toString('base64url');
const digest = (value) => `sha256:${crypto.createHash('sha256')
  .update(Buffer.from(canon(value), 'utf8')).digest('hex')}`;
const revokerKeyId = (publicKeyB64u) => `ep:revoker-key:sha256:${crypto
  .createHash('sha256').update(Buffer.from(publicKeyB64u, 'base64url')).digest('hex')}`;

// ── EP-REVOCATION-v1 ─────────────────────────────────────────────────────────
const RV = 'EP-REVOCATION-v1';
const TARGET = { target_type: 'receipt', target_id: 'rcpt_x', action_hash: 'sha256:' + 'a'.repeat(64) };
const REVOKER = 'ep:revoker:ig_okafor';
const REVOKED_AT = '2026-06-20T12:00:00.000Z';

/**
 * @param {{
 *   signer: any,
 *   target?: any,
 *   actionHash?: string,
 *   reason?: string,
 *   revokedAt?: string|null,
 *   revokerId?: any,
 * }} opts
 */
function revStatement({
  signer,
  target = TARGET,
  actionHash = target.action_hash,
  reason = 'authority withdrawn',
  revokedAt = REVOKED_AT,
  revokerId = REVOKER,
}) {
  const signed = { '@version': RV, action_hash: actionHash ?? null, reason, revoked_at: revokedAt ?? null, revoker_id: revokerId, target_id: target.target_id ?? null, target_type: target.target_type ?? null };
  return { '@version': RV, target_type: target.target_type, target_id: target.target_id, action_hash: actionHash, revoker_id: revokerId, revoked_at: revokedAt, reason, proof: { algorithm: 'Ed25519', revoker_key_id: revokerKeyId(signer.pub), public_key: signer.pub, signature_b64u: sign(signed, signer.privateKey) } };
}
const pinR = (s) => ({ [REVOKER]: { public_key: s.pub, key_id: revokerKeyId(s.pub) } });

const RVEC = [];
const addR = (id, expectValid, vec) => RVEC.push({ id, expect: { valid: expectValid }, ...vec });
{
  const s = newSigner();
  addR('accept_pinned_exact_binding', true, { target: TARGET, revocation: revStatement({ signer: s }), revoker_keys: pinR(s) });
}
{ const s = newSigner(); addR('reject_unpinned_revoker', false, { target: TARGET, revocation: revStatement({ signer: s }), revoker_keys: {} }); }
{ const s = newSigner(); const o = newSigner(); addR('reject_key_substitution', false, { target: TARGET, revocation: revStatement({ signer: s }), revoker_keys: pinR(o) }); }
{ const s = newSigner(); const other = { ...TARGET, target_id: 'rcpt_other' }; addR('reject_different_target_id', false, { target: TARGET, revocation: revStatement({ signer: s, target: other }), revoker_keys: pinR(s) }); }
{ const s = newSigner(); addR('reject_revoke_a_for_b', false, { target: TARGET, revocation: revStatement({ signer: s, actionHash: 'sha256:' + 'b'.repeat(64) }), revoker_keys: pinR(s) }); }
{ const s = newSigner(); const st = revStatement({ signer: s }); st['@version'] = 'EP-REVOCATION-v2'; addR('reject_wrong_version', false, { target: TARGET, revocation: st, revoker_keys: pinR(s) }); }
{ const s = newSigner(); const st = revStatement({ signer: s }); st.reason = 'tampered after signing'; addR('reject_tampered_field', false, { target: TARGET, revocation: st, revoker_keys: pinR(s) }); }
{ const s = newSigner(); addR('reject_missing_revoked_at', false, { target: TARGET, revocation: revStatement({ signer: s, revokedAt: null }), revoker_keys: pinR(s) }); }
{ const s = newSigner(); addR('reject_future_effective_instant', false, { target: TARGET, revocation: revStatement({ signer: s, revokedAt: '2026-06-21T12:00:00.000Z' }), revoker_keys: pinR(s), now: '2026-06-20T12:00:00.000Z' }); }
{ const s = newSigner(); const malformed = { target_type: 'receipt', target_id: '', action_hash: 'not-a-digest' }; addR('reject_malformed_target_shape', false, { target: malformed, revocation: revStatement({ signer: s, target: malformed }), revoker_keys: pinR(s) }); }
{ const s = newSigner(); const st = revStatement({ signer: s }); st.proof.algorithm = 'ES256'; addR('reject_algorithm_label_mismatch', false, { target: TARGET, revocation: st, revoker_keys: pinR(s) }); }
{ const s = newSigner(); const st = revStatement({ signer: s }); st.proof.revoker_key_id = 'ep:revoker-key:sha256:' + 'f'.repeat(64); addR('reject_revoker_key_id_substitution', false, { target: TARGET, revocation: st, revoker_keys: pinR(s) }); }
{ const s = newSigner(); const st = revStatement({ signer: s }); st.scope_note = 'unsigned'; addR('reject_unsigned_top_level_member', false, { target: TARGET, revocation: st, revoker_keys: pinR(s) }); }
{ const s = newSigner(); const st = revStatement({ signer: s }); st.proof.signed_payload_b64u = Buffer.from('unsigned').toString('base64url'); addR('reject_unsigned_proof_member', false, { target: TARGET, revocation: st, revoker_keys: pinR(s) }); }
{ const s = newSigner(); addR('accept_old_terminal_revocation', true, { target: TARGET, revocation: revStatement({ signer: s, revokedAt: '2020-01-01T00:00:00.000Z' }), revoker_keys: pinR(s), max_age_seconds: 3600, now: '2026-06-20T12:00:00.000Z' }); }
{
  const s = newSigner();
  const st = revStatement({ signer: s });
  st.proof.revoker_key_id = 'rk1';
  addR('accept_historical_v1_key_label_with_exact_pinned_spki', true, {
    target: TARGET,
    revocation: st,
    revoker_keys: { [REVOKER]: { public_key: s.pub } },
  });
}
{
  const s = newSigner();
  const st = revStatement({ signer: s });
  st.proof.public_key = '';
  st.proof.revoker_key_id = `ep:revoker-key:sha256:${crypto.createHash('sha256').digest('hex')}`;
  addR('reject_empty_presented_key_even_when_signature_matches_pin', false, {
    target: TARGET,
    revocation: st,
    revoker_keys: { [REVOKER]: { public_key: s.pub } },
  });
}
{
  const s = newSigner();
  const hostileRevokerId = /** @type {any} */ ({ tenant: REVOKER });
  addR('reject_non_string_revoker_id_without_crash', false, {
    target: TARGET,
    revocation: revStatement({ signer: s, revokerId: hostileRevokerId }),
    revoker_keys: { [REVOKER]: { public_key: s.pub } },
  });
}
{
  const s = newSigner();
  addR('reject_timestamp_with_more_than_nine_fractional_digits', false, {
    target: TARGET,
    revocation: revStatement({ signer: s, revokedAt: '2026-06-20T12:00:00.1234567890Z' }),
    revoker_keys: pinR(s),
  });
}

for (const vector of RVEC) {
  const result = verifyRevocation(vector.target, vector.revocation, {
    revokerKeys: vector.revoker_keys,
    maxAgeSeconds: vector.max_age_seconds,
    now: vector.now,
  });
  if (result.valid !== vector.expect.valid) {
    throw new Error(`${vector.id}: generator self-check failed: ${JSON.stringify(result)}`);
  }
  const exactResult = {
    valid: result.valid,
    checks: result.checks,
    reasons: Object.entries(result.checks)
      .filter(([, passed]) => !passed)
      .map(([check]) => check),
    target_digest: digest(vector.target),
    revocation_digest: digest(vector.revocation),
  };
  vector.expect = {
    ...exactResult,
    result_digest: digest(exactResult),
  };
}

const revSuite = {
  suite: 'EP-REVOCATION-v1',
  profile: 'Executable revocation-statement vectors (real Ed25519, closed schema, full digest-derived revoker key identifiers, exact-pinned historical-v1 compatibility). Conformance requires the complete typed valid/check/reason/input/result-digest expectation.',
  vectors_version: '2.3.0',
  count: RVEC.length,
  vectors: RVEC,
};
writeFileSync(new URL('./revocation.exec.v2.json', import.meta.url), JSON.stringify(revSuite, null, 2) + '\n');

// ── EP-TIME-ATTESTATION-v1 ───────────────────────────────────────────────────
const TV = 'EP-TIME-ATTESTATION-v1';
const TSA = 'ep:tsa:roughtime-1';
const HASH = 'sha256:' + 'c'.repeat(64);
const TIME = '2026-06-20T12:00:00.000Z';

function timeAtt({ signer, time = TIME, hashed = HASH }) {
  const signed = { '@version': TV, hashed, time, ts_authority_id: TSA };
  return { '@version': TV, ts_authority_id: TSA, hashed, time, proof: { algorithm: 'Ed25519', ts_key_id: 'tk1', public_key: signer.pub, signature_b64u: sign(signed, signer.privateKey) } };
}
const pinT = (s) => ({ [TSA]: { public_key: s.pub } });

const TVEC = [];
const addT = (id, expectValid, vec) => TVEC.push({ id, expect: { valid: expectValid }, ...vec });
{ const s = newSigner(); addT('accept_pinned_hash_bounds', true, { time_attestation: timeAtt({ signer: s }), tsa_keys: pinT(s), expected_hash: HASH, not_before: '2026-06-01T00:00:00.000Z', not_after: '2026-07-01T00:00:00.000Z' }); }
{ const s = newSigner(); addT('reject_unpinned_tsa', false, { time_attestation: timeAtt({ signer: s }), tsa_keys: {} }); }
{ const s = newSigner(); const o = newSigner(); addT('reject_tsa_key_substitution', false, { time_attestation: timeAtt({ signer: s }), tsa_keys: pinT(o) }); }
{ const s = newSigner(); const a = timeAtt({ signer: s }); a.time = '2030-01-01T00:00:00.000Z'; addT('reject_tampered_time', false, { time_attestation: a, tsa_keys: pinT(s) }); }
{ const s = newSigner(); addT('reject_wrong_covered_hash', false, { time_attestation: timeAtt({ signer: s }), tsa_keys: pinT(s), expected_hash: 'sha256:' + 'd'.repeat(64) }); }
{ const s = newSigner(); addT('reject_out_of_bounds_time', false, { time_attestation: timeAtt({ signer: s }), tsa_keys: pinT(s), not_after: '2026-06-01T00:00:00.000Z' }); }

const timeSuite = {
  suite: 'EP-TIME-ATTESTATION-v1',
  profile: 'Executable trusted-time attestation vectors (real Ed25519). verifyTimeAttestation(att, opts) must return expect.valid.',
  vectors_version: '2.0.0',
  count: TVEC.length,
  vectors: TVEC,
};
writeFileSync(new URL('./time-attestation.v2.json', import.meta.url), JSON.stringify(timeSuite, null, 2) + '\n');
console.log(`wrote revocation.exec.v2.json (${RVEC.length}) + time-attestation.v2.json (${TVEC.length})`);
