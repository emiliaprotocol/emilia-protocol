// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import {
  buildEyeSet,
  verifyEyeSet,
  EYE_SET_VERSION,
  EYE_SET_TYP,
  EYE_ADVISORY_EVENT_URI,
} from '../lib/eye/eye-set.js';

import {
  canonicalize,
  generateEd25519KeyPair,
} from '../packages/issue/index.js';

/**
 * EP-EYE-SET-v1 — live-crypto adversarial conformance suite.
 *
 * For each attack catalogued in conformance/vectors/eye-set.v1.json we build a
 * SET that MUST verify { valid:false } on the catalogued failing_check, plus the
 * two well-formed positives that MUST verify { valid:true }. Every keypair and
 * every signature is minted LIVE (real Ed25519 over the real JWS signing input)
 * so each negative is a genuine forgery / tamper / confusion attempt, not
 * hand-edited JSON that would have failed for some unrelated reason.
 *
 * The EP-EYE-SET emission is ADDITIVE over Eye's advisory path: it composes the
 * frozen canonicalize() and adds exactly one new primitive — a detached EdDSA/JWS
 * over node:crypto. An Eye SET INFORMS; verifyEyeSet returns a POSTURE, never
 * allow/deny, and never authorizes. FAIL CLOSED on alg confusion, an unpinned or
 * substituted emitter key, a forged/tampered signature, a missing claim, an
 * audience mismatch, staleness, a non-actionable status, or a missing
 * never-sole-gate marker.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VECTORS = JSON.parse(
  readFileSync(path.join(__dirname, '..', 'conformance', 'vectors', 'eye-set.v1.json'), 'utf8'),
);
const byId = (list, id) => list.find((v) => v.id === id);

// ── reference material ─────────────────────────────────────────────────────────

const EMITTER_KID = 'ep:eye:emitter#1';
const EMITTER_ISS = 'ep:eye:emitter#1';
const AUDIENCE = 'rp:bank-a';

const emitterKp = generateEd25519KeyPair();

/** Pinned-key map a verifier trusts (identified-AND-pinned). */
function pinnedKeys(kp = emitterKp, kid = EMITTER_KID) {
  return { [kid]: { public_key: kp.publicKeyB64u } };
}

/** signer for buildEyeSet using a raw private KeyObject. */
function signer(kp = emitterKp, kid = EMITTER_KID, iss = EMITTER_ISS) {
  return { kid, iss, privateKey: kp.privateKey };
}

/** A fresh, well-formed actionable advisory (elevated). */
function elevatedAdvisory() {
  return {
    status: 'elevated',
    reason_codes: ['device_fingerprint_changed', 'high_severity_signal_active'],
    recommended_policy_action: 'step_up_auth',
    scope_binding_hash: 'sha256:' + 'a'.repeat(64),
    advisory_hash: 'sha256:' + 'b'.repeat(64),
    expires_at: new Date(Date.now() + 3600_000).toISOString(),
  };
}

/** A fresh, well-formed review_required advisory (most-tightening). */
function reviewRequiredAdvisory() {
  return {
    status: 'review_required',
    reason_codes: ['critical_signal_active'],
    recommended_policy_action: 'require_signoff',
    scope_binding_hash: 'sha256:' + 'c'.repeat(64),
    advisory_hash: 'sha256:' + 'd'.repeat(64),
    expires_at: new Date(Date.now() + 3600_000).toISOString(),
  };
}

const NOW_SEC = Math.floor(Date.now() / 1000);

// base64url helpers mirroring the lib (kept local so the test does not import lib internals).
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const encodeSeg = (obj) => b64u(Buffer.from(canonicalize(obj), 'utf8'));

/** Split a compact SET into [header, payload, signature] objects/segments. */
function parts(compact) {
  const [h, p, s] = compact.split('.');
  return {
    headerSeg: h,
    payloadSeg: p,
    signatureSeg: s,
    header: JSON.parse(Buffer.from(h, 'base64url').toString('utf8')),
    payload: JSON.parse(Buffer.from(p, 'base64url').toString('utf8')),
  };
}

/** Re-encode a header.payload pair and sign it live under kp (a genuine signature). */
function mint(header, payload, kp = emitterKp) {
  const headerSeg = encodeSeg(header);
  const payloadSeg = encodeSeg(payload);
  const signingInput = `${headerSeg}.${payloadSeg}`;
  const sig = crypto.sign(null, Buffer.from(signingInput, 'ascii'), kp.privateKey).toString('base64url');
  return `${signingInput}.${sig}`;
}

// ── version + assembly ──────────────────────────────────────────────────────────

describe('EP-EYE-SET-v1 — version + assembly', () => {
  it('exposes the wire version, typ, and event URI', () => {
    expect(EYE_SET_VERSION).toBe('EP-EYE-SET-v1');
    expect(EYE_SET_TYP).toBe('secevent+jwt');
    expect(EYE_ADVISORY_EVENT_URI).toBe('https://schemas.emiliaprotocol.ai/secevent/eye-advisory');
  });

  it('buildEyeSet emits a 3-segment secevent+jwt with the redacted, scope-bound shape', () => {
    const adv = elevatedAdvisory();
    const compact = buildEyeSet(adv, { signer: signer(), audience: AUDIENCE });
    const { header, payload } = parts(compact);
    expect(compact.split('.')).toHaveLength(3);
    expect(header).toMatchObject({ alg: 'EdDSA', typ: 'secevent+jwt', kid: EMITTER_KID });
    // sub_id is the scope_binding_hash, NOT a raw identifier.
    expect(payload.sub_id).toBe(adv.scope_binding_hash);
    expect(payload).toMatchObject({ iss: EMITTER_ISS, aud: AUDIENCE });
    expect(typeof payload.iat).toBe('number');
    expect(typeof payload.jti).toBe('string');
    const event = payload.events[EYE_ADVISORY_EVENT_URI];
    expect(event).toMatchObject({
      status: 'elevated',
      recommended_policy_action: 'step_up_auth',
      advisory_hash: adv.advisory_hash,
      expires_at: adv.expires_at,
      never_sole_gate: true,
    });
    // NO raw subject/actor/target/issuer refs anywhere in the wire bytes.
    const wire = JSON.stringify(payload);
    expect(wire).not.toMatch(/subject_ref|actor_ref|target_ref|issuer_ref/);
  });

  it('buildEyeSet accepts the advisory-spec recommended_action as the source field', () => {
    const adv = { ...elevatedAdvisory(), recommended_policy_action: undefined, recommended_action: 'escalate' };
    const compact = buildEyeSet(adv, { signer: signer(), audience: AUDIENCE });
    const { payload } = parts(compact);
    expect(payload.events[EYE_ADVISORY_EVENT_URI].recommended_policy_action).toBe('escalate');
  });

  it('buildEyeSet refuses to emit a clear status (build-time, §3.4)', () => {
    const adv = { ...elevatedAdvisory(), status: 'clear', reason_codes: [] };
    expect(() => buildEyeSet(adv, { signer: signer(), audience: AUDIENCE })).toThrow(/clear/i);
  });

  it('buildEyeSet refuses an unknown / non-actionable status', () => {
    const adv = { ...elevatedAdvisory(), status: 'banana' };
    expect(() => buildEyeSet(adv, { signer: signer(), audience: AUDIENCE })).toThrow(/actionable/i);
  });

  it('buildEyeSet validates required arguments and advisory fields', () => {
    expect(() => buildEyeSet(null, { signer: signer() })).toThrow(/advisory object/i);
    expect(() => buildEyeSet(elevatedAdvisory(), {})).toThrow(/signer/i);
    expect(() => buildEyeSet(elevatedAdvisory(), { signer: { kid: EMITTER_KID } })).toThrow(/privateKey|sign/i);
    expect(() => buildEyeSet({ ...elevatedAdvisory(), scope_binding_hash: undefined }, { signer: signer() }))
      .toThrow(/scope_binding_hash/i);
    expect(() => buildEyeSet({ ...elevatedAdvisory(), reason_codes: [] }, { signer: signer() }))
      .toThrow(/reason_codes/i);
    expect(() => buildEyeSet({ ...elevatedAdvisory(), recommended_policy_action: undefined, recommended_action: undefined }, { signer: signer() }))
      .toThrow(/recommended_policy_action/i);
    expect(() => buildEyeSet({ ...elevatedAdvisory(), advisory_hash: undefined }, { signer: signer() }))
      .toThrow(/advisory_hash/i);
    expect(() => buildEyeSet({ ...elevatedAdvisory(), expires_at: undefined }, { signer: signer() }))
      .toThrow(/expires_at/i);
  });

  it('buildEyeSet supports a sign(callback) so EP need not hold the key', () => {
    const adv = elevatedAdvisory();
    const cbSigner = {
      kid: EMITTER_KID,
      iss: EMITTER_ISS,
      sign: (input) => crypto.sign(null, Buffer.from(input, 'ascii'), emitterKp.privateKey).toString('base64url'),
    };
    const compact = buildEyeSet(adv, { signer: cbSigner, audience: AUDIENCE });
    const r = verifyEyeSet(compact, { pinnedKeys: pinnedKeys(), audience: AUDIENCE, requireFresh: true });
    expect(r.valid).toBe(true);
  });
});

// ── must_reject vectors (each MUST verify valid:false on its failing_check) ──────

describe('EP-EYE-SET-v1 — must_reject vectors', () => {
  it('a_forged_jws_signature — signature over UNRELATED bytes', () => {
    const compact = buildEyeSet(elevatedAdvisory(), { signer: signer(), audience: AUDIENCE });
    const { headerSeg, payloadSeg } = parts(compact);
    // A genuine Ed25519 signature, but over unrelated bytes (not the signing input).
    const forged = crypto.sign(null, Buffer.from('unrelated-bytes', 'ascii'), emitterKp.privateKey)
      .toString('base64url');
    const tampered = `${headerSeg}.${payloadSeg}.${forged}`;
    const r = verifyEyeSet(tampered, { pinnedKeys: pinnedKeys(), audience: AUDIENCE, requireFresh: true });
    expect(r.valid).toBe(false);
    expect(r.checks.jws_signature_valid).toBe(false);
    expect(byId(VECTORS.must_reject, 'a_forged_jws_signature').expected.failing_check)
      .toBe('jws_signature_valid');
  });

  it('b_unpinned_emitter_kid — signature verifies under the producer key, but kid is UNPINNED', () => {
    // Genuinely valid SET signed by a freshly minted keypair whose kid is not pinned.
    const otherKp = generateEd25519KeyPair();
    const compact = buildEyeSet(elevatedAdvisory(), {
      signer: signer(otherKp, 'ep:eye:rogue#1', 'ep:eye:rogue#1'),
      audience: AUDIENCE,
    });
    // The verifier pins only the legitimate emitter — the rogue kid confers nothing.
    const r = verifyEyeSet(compact, { pinnedKeys: pinnedKeys(), audience: AUDIENCE, requireFresh: true });
    expect(r.valid).toBe(false);
    expect(r.checks.emitter_key_pinned).toBe(false);
    expect(byId(VECTORS.must_reject, 'b_unpinned_emitter_kid').expected.failing_check)
      .toBe('emitter_key_pinned');
  });

  it('c_wrong_pinned_key_substitution — kid is pinned, but signed by a DIFFERENT key', () => {
    const wrongKp = generateEd25519KeyPair();
    // Sign with the wrong key under the legitimate kid; verify under the PINNED key.
    const compact = buildEyeSet(elevatedAdvisory(), {
      signer: signer(wrongKp, EMITTER_KID, EMITTER_ISS),
      audience: AUDIENCE,
    });
    const r = verifyEyeSet(compact, { pinnedKeys: pinnedKeys(emitterKp), audience: AUDIENCE, requireFresh: true });
    expect(r.valid).toBe(false);
    expect(r.checks.emitter_key_pinned).toBe(true); // the kid IS pinned…
    expect(r.checks.jws_signature_valid).toBe(false); // …but the substituted key fails the math.
    expect(byId(VECTORS.must_reject, 'c_wrong_pinned_key_substitution').expected.failing_check)
      .toBe('jws_signature_valid');
  });

  it("d_alg_none_confusion — alg:'none' is rejected BEFORE any verification", () => {
    const adv = elevatedAdvisory();
    const compact = buildEyeSet(adv, { signer: signer(), audience: AUDIENCE });
    const { payload } = parts(compact);
    // Forge an unsecured token: alg 'none', empty signature segment.
    const header = { alg: 'none', typ: EYE_SET_TYP, kid: EMITTER_KID };
    const unsecured = `${encodeSeg(header)}.${encodeSeg(payload)}.`;
    const r = verifyEyeSet(unsecured, { pinnedKeys: pinnedKeys(), audience: AUDIENCE, requireFresh: true });
    expect(r.valid).toBe(false);
    expect(r.checks.alg_is_eddsa).toBe(false);
    expect(byId(VECTORS.must_reject, 'd_alg_none_confusion').expected.failing_check)
      .toBe('alg_is_eddsa');

    // Also a non-EdDSA alg (algorithm confusion) is rejected on the same gate.
    const hs256 = { alg: 'HS256', typ: EYE_SET_TYP, kid: EMITTER_KID };
    const confused = mint(hs256, payload, emitterKp);
    const r2 = verifyEyeSet(confused, { pinnedKeys: pinnedKeys(), audience: AUDIENCE, requireFresh: true });
    expect(r2.valid).toBe(false);
    expect(r2.checks.alg_is_eddsa).toBe(false);
  });

  it('e_tampered_payload_status_downgrade — status downgraded AFTER signing', () => {
    const compact = buildEyeSet(elevatedAdvisory(), { signer: signer(), audience: AUDIENCE });
    const { header, payload, signatureSeg } = parts(compact);
    // Downgrade the posture in the payload, but keep the ORIGINAL signature.
    const downgraded = JSON.parse(JSON.stringify(payload));
    downgraded.events[EYE_ADVISORY_EVENT_URI].status = 'caution';
    const tampered = `${encodeSeg(header)}.${encodeSeg(downgraded)}.${signatureSeg}`;
    const r = verifyEyeSet(tampered, { pinnedKeys: pinnedKeys(), audience: AUDIENCE, requireFresh: true });
    expect(r.valid).toBe(false);
    expect(r.checks.jws_signature_valid).toBe(false);
    expect(byId(VECTORS.must_reject, 'e_tampered_payload_status_downgrade').expected.failing_check)
      .toBe('jws_signature_valid');
  });

  it('f_audience_mismatch — aud != opts.audience when an audience is pinned', () => {
    // Minted for bank-a; presented to a verifier pinning bank-b.
    const compact = buildEyeSet(elevatedAdvisory(), { signer: signer(), audience: 'rp:bank-a' });
    const r = verifyEyeSet(compact, { pinnedKeys: pinnedKeys(), audience: 'rp:bank-b', requireFresh: true });
    expect(r.valid).toBe(false);
    expect(r.checks.audience_match).toBe(false);
    expect(byId(VECTORS.must_reject, 'f_audience_mismatch').expected.failing_check)
      .toBe('audience_match');
  });

  it('g_expired_set_exp_past — expires_at in the past when freshness required', () => {
    const adv = { ...elevatedAdvisory(), expires_at: new Date(Date.now() - 3600_000).toISOString() };
    const compact = buildEyeSet(adv, { signer: signer(), audience: AUDIENCE });
    const r = verifyEyeSet(compact, { pinnedKeys: pinnedKeys(), audience: AUDIENCE, requireFresh: true, now: NOW_SEC });
    expect(r.valid).toBe(false);
    expect(r.checks.fresh).toBe(false);
    expect(byId(VECTORS.must_reject, 'g_expired_set_exp_past').expected.failing_check).toBe('fresh');
  });

  it('h_iat_too_old — iat older than maxAgeSec when freshness required', () => {
    const oldIat = NOW_SEC - 10_000;
    // expires_at still in the future so ONLY the iat-age check trips.
    const adv = { ...elevatedAdvisory(), expires_at: new Date((NOW_SEC + 3600) * 1000).toISOString() };
    const compact = buildEyeSet(adv, { signer: signer(), audience: AUDIENCE, iat: oldIat });
    const r = verifyEyeSet(compact, {
      pinnedKeys: pinnedKeys(), audience: AUDIENCE, requireFresh: true, maxAgeSec: 300, now: NOW_SEC,
    });
    expect(r.valid).toBe(false);
    expect(r.checks.fresh).toBe(false);
    expect(byId(VECTORS.must_reject, 'h_iat_too_old').expected.failing_check).toBe('fresh');
  });

  it('i_missing_never_sole_gate_marker — marker omitted / not true', () => {
    const adv = elevatedAdvisory();
    const compact = buildEyeSet(adv, { signer: signer(), audience: AUDIENCE });
    const { header, payload } = parts(compact);
    // Strip the in-band marker and RE-SIGN live, so this fails ONLY on the marker
    // check, not on the signature (a genuine, correctly signed SET that is
    // malformed for this profile).
    const stripped = JSON.parse(JSON.stringify(payload));
    delete stripped.events[EYE_ADVISORY_EVENT_URI].never_sole_gate;
    const reSigned = mint(header, stripped, emitterKp);
    const r = verifyEyeSet(reSigned, { pinnedKeys: pinnedKeys(), audience: AUDIENCE, requireFresh: true });
    expect(r.valid).toBe(false);
    expect(r.checks.jws_signature_valid).toBe(true); // genuinely signed…
    expect(r.checks.never_sole_gate_present).toBe(false); // …but missing the marker.
    expect(byId(VECTORS.must_reject, 'i_missing_never_sole_gate_marker').expected.failing_check)
      .toBe('never_sole_gate_present');

    // A non-true marker is equally rejected.
    const nonTrue = JSON.parse(JSON.stringify(payload));
    nonTrue.events[EYE_ADVISORY_EVENT_URI].never_sole_gate = 'yes';
    const reSigned2 = mint(header, nonTrue, emitterKp);
    const r2 = verifyEyeSet(reSigned2, { pinnedKeys: pinnedKeys(), audience: AUDIENCE, requireFresh: true });
    expect(r2.valid).toBe(false);
    expect(r2.checks.never_sole_gate_present).toBe(false);
  });

  it('j_clear_status_emitted_as_event — a signed clear event is rejected by the verifier', () => {
    // buildEyeSet refuses clear, so forge a correctly-signed clear SET directly to
    // exercise the verifier's independent status_is_actionable gate.
    const adv = elevatedAdvisory();
    const compact = buildEyeSet(adv, { signer: signer(), audience: AUDIENCE });
    const { header, payload } = parts(compact);
    const cleared = JSON.parse(JSON.stringify(payload));
    cleared.events[EYE_ADVISORY_EVENT_URI].status = 'clear';
    const reSigned = mint(header, cleared, emitterKp);
    const r = verifyEyeSet(reSigned, { pinnedKeys: pinnedKeys(), audience: AUDIENCE, requireFresh: true });
    expect(r.valid).toBe(false);
    expect(r.checks.jws_signature_valid).toBe(true); // genuinely signed…
    expect(r.checks.status_is_actionable).toBe(false); // …but 'clear' is not a posture event.
    expect(byId(VECTORS.must_reject, 'j_clear_status_emitted_as_event').expected.failing_check)
      .toBe('status_is_actionable');
  });
});

// ── must_accept vectors (each MUST verify valid:true; posture, never allow/deny) ──

describe('EP-EYE-SET-v1 — must_accept vectors', () => {
  it('z_well_formed_elevated_set_pinned_fresh — verifies and returns the posture', () => {
    const adv = elevatedAdvisory();
    const compact = buildEyeSet(adv, { signer: signer(), audience: AUDIENCE });
    const r = verifyEyeSet(compact, { pinnedKeys: pinnedKeys(), audience: AUDIENCE, requireFresh: true, maxAgeSec: 3600 });
    expect(r.errors, JSON.stringify(r, null, 2)).toEqual([]);
    expect(r.valid).toBe(true);
    for (const [k, v] of Object.entries(r.checks)) {
      expect(v, `check ${k} should pass`).toBe(true);
    }
    // The verifier returns a POSTURE — never allow/deny, no decision vocabulary.
    expect(r.posture).toMatchObject({
      status: 'elevated',
      recommended_policy_action: 'step_up_auth',
      scope_binding_hash: adv.scope_binding_hash,
      advisory_hash: adv.advisory_hash,
      never_sole_gate: true,
    });
    expect(r.posture).not.toHaveProperty('allow');
    expect(r.posture).not.toHaveProperty('deny');
    expect(r.posture).not.toHaveProperty('decision');
    expect(byId(VECTORS.must_accept, 'z_well_formed_elevated_set_pinned_fresh').expected.valid).toBe(true);
  });

  it('z2_well_formed_review_required_no_audience_pin — accepted with no audience pin', () => {
    const adv = reviewRequiredAdvisory();
    const compact = buildEyeSet(adv, { signer: signer(), audience: AUDIENCE });
    // opts.audience UNSET — audience is not gated; everything else still fails closed.
    const r = verifyEyeSet(compact, { pinnedKeys: pinnedKeys(), requireFresh: true, maxAgeSec: 3600 });
    expect(r.errors, JSON.stringify(r, null, 2)).toEqual([]);
    expect(r.valid).toBe(true);
    expect(r.checks.audience_match).toBe(true); // vacuously true when unset
    expect(r.posture.status).toBe('review_required');
    expect(r.posture.recommended_policy_action).toBe('require_signoff');
    expect(byId(VECTORS.must_accept, 'z2_well_formed_review_required_no_audience_pin').expected.valid).toBe(true);
  });

  it('accepts a fresh SET resolved by iss when the kid is not the pinned map key', () => {
    // Pin under iss instead of kid: resolvePinnedKey falls back to iss.
    const adv = elevatedAdvisory();
    const compact = buildEyeSet(adv, { signer: { kid: 'kid-not-in-map', iss: EMITTER_ISS, privateKey: emitterKp.privateKey }, audience: AUDIENCE });
    const r = verifyEyeSet(compact, { pinnedKeys: { [EMITTER_ISS]: { public_key: emitterKp.publicKeyB64u } }, audience: AUDIENCE, requireFresh: true });
    expect(r.valid).toBe(true);
  });

  it('accepts a bare-string pinned key entry', () => {
    const adv = elevatedAdvisory();
    const compact = buildEyeSet(adv, { signer: signer(), audience: AUDIENCE });
    const r = verifyEyeSet(compact, { pinnedKeys: { [EMITTER_KID]: emitterKp.publicKeyB64u }, audience: AUDIENCE, requireFresh: true });
    expect(r.valid).toBe(true);
  });

  it('skips freshness gating when requireFresh is not set (stale SET still parses)', () => {
    const adv = { ...elevatedAdvisory(), expires_at: new Date(Date.now() - 3600_000).toISOString() };
    const compact = buildEyeSet(adv, { signer: signer(), audience: AUDIENCE });
    const r = verifyEyeSet(compact, { pinnedKeys: pinnedKeys(), audience: AUDIENCE });
    // No freshness required → fresh stays vacuously true; the rest still pass.
    expect(r.valid).toBe(true);
    expect(r.checks.fresh).toBe(true);
  });
});

// ── malformed-input fail-closed (defensive parsing branches) ────────────────────

describe('EP-EYE-SET-v1 — malformed input fails closed (never throws)', () => {
  it('rejects a non-string / empty compact SET', () => {
    for (const bad of [null, undefined, 123, '', {}]) {
      const r = verifyEyeSet(bad, { pinnedKeys: pinnedKeys() });
      expect(r.valid).toBe(false);
      expect(r.posture).toBeNull();
    }
  });

  it('rejects the wrong number of segments', () => {
    const r = verifyEyeSet('only.two', { pinnedKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.alg_is_eddsa).toBe(false);
  });

  it('rejects an undecodable header / payload', () => {
    const r1 = verifyEyeSet('!!!.also-bad.sig', { pinnedKeys: pinnedKeys() });
    expect(r1.valid).toBe(false);
    expect(r1.checks.alg_is_eddsa).toBe(false);

    // Good header, junk payload: alg+typ pass, payload decode fails.
    const goodHeader = encodeSeg({ alg: 'EdDSA', typ: EYE_SET_TYP, kid: EMITTER_KID });
    const r2 = verifyEyeSet(`${goodHeader}.@@@.sig`, { pinnedKeys: pinnedKeys() });
    expect(r2.valid).toBe(false);
    expect(r2.checks.claims_present).toBe(false);
  });

  it('rejects a missing pinnedKeys map (no key resolvable → unpinned)', () => {
    const compact = buildEyeSet(elevatedAdvisory(), { signer: signer(), audience: AUDIENCE });
    const r = verifyEyeSet(compact, {});
    expect(r.valid).toBe(false);
    expect(r.checks.emitter_key_pinned).toBe(false);
  });

  it('rejects a SET missing required claims (no aud) — re-signed so signature is genuine', () => {
    const adv = elevatedAdvisory();
    const compact = buildEyeSet(adv, { signer: signer() }); // no audience → no aud
    const r = verifyEyeSet(compact, { pinnedKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.jws_signature_valid).toBe(true);
    expect(r.checks.claims_present).toBe(false);
    expect(r.errors.some((e) => /aud/.test(e))).toBe(true);
  });

  it('rejects an events map that is not exactly one expected-URI member', () => {
    const adv = elevatedAdvisory();
    const compact = buildEyeSet(adv, { signer: signer(), audience: AUDIENCE });
    const { header, payload } = parts(compact);
    // Two event members → not exactly one.
    const twoEvents = JSON.parse(JSON.stringify(payload));
    twoEvents.events['https://example.com/other'] = { foo: 'bar' };
    const r = verifyEyeSet(mint(header, twoEvents), { pinnedKeys: pinnedKeys(), audience: AUDIENCE });
    expect(r.valid).toBe(false);
    expect(r.checks.claims_present).toBe(false);

    // Wrong URI key → rejected.
    const wrongUri = { ...payload, events: { 'https://example.com/wrong': payload.events[EYE_ADVISORY_EVENT_URI] } };
    const r2 = verifyEyeSet(mint(header, wrongUri), { pinnedKeys: pinnedKeys(), audience: AUDIENCE });
    expect(r2.valid).toBe(false);
    expect(r2.checks.claims_present).toBe(false);
  });

  it('rejects an unparseable expires_at when freshness is required', () => {
    const adv = elevatedAdvisory();
    const compact = buildEyeSet(adv, { signer: signer(), audience: AUDIENCE });
    const { header, payload } = parts(compact);
    const bad = JSON.parse(JSON.stringify(payload));
    bad.events[EYE_ADVISORY_EVENT_URI].expires_at = 'not-a-date';
    const r = verifyEyeSet(mint(header, bad), { pinnedKeys: pinnedKeys(), audience: AUDIENCE, requireFresh: true });
    expect(r.valid).toBe(false);
    expect(r.checks.fresh).toBe(false);
  });

  it('enforces a top-level JWT exp when present and freshness required', () => {
    const adv = elevatedAdvisory();
    // exp in the past, but event expires_at in the future: the exp gate must trip.
    const compact = buildEyeSet(adv, { signer: signer(), audience: AUDIENCE, exp: NOW_SEC - 100 });
    const r = verifyEyeSet(compact, { pinnedKeys: pinnedKeys(), audience: AUDIENCE, requireFresh: true, now: NOW_SEC });
    expect(r.valid).toBe(false);
    expect(r.checks.fresh).toBe(false);
  });

  it('accepts a future top-level JWT exp when freshness required (exp gate passes)', () => {
    const adv = elevatedAdvisory();
    const compact = buildEyeSet(adv, { signer: signer(), audience: AUDIENCE, exp: NOW_SEC + 3600 });
    const r = verifyEyeSet(compact, { pinnedKeys: pinnedKeys(), audience: AUDIENCE, requireFresh: true, now: NOW_SEC, maxAgeSec: 3600 });
    expect(r.valid).toBe(true);
    expect(r.checks.fresh).toBe(true);
  });

  it('rejects a wrong typ on the typ gate', () => {
    const adv = elevatedAdvisory();
    const compact = buildEyeSet(adv, { signer: signer(), audience: AUDIENCE });
    const { payload } = parts(compact);
    const wrongTyp = mint({ alg: 'EdDSA', typ: 'JWT', kid: EMITTER_KID }, payload);
    const r = verifyEyeSet(wrongTyp, { pinnedKeys: pinnedKeys(), audience: AUDIENCE });
    expect(r.valid).toBe(false);
    expect(r.checks.typ_ok).toBe(false);
  });

  it('fails closed when the pinned key bytes are not a valid public key (createPublicKey throws)', () => {
    const adv = elevatedAdvisory();
    const compact = buildEyeSet(adv, { signer: signer(), audience: AUDIENCE });
    // A pinned entry whose bytes are not a decodable SPKI key → verifyEd25519
    // catches the createPublicKey throw and returns false (fail closed).
    const r = verifyEyeSet(compact, {
      pinnedKeys: { [EMITTER_KID]: { public_key: 'AAAA' } },
      audience: AUDIENCE,
    });
    expect(r.valid).toBe(false);
    expect(r.checks.emitter_key_pinned).toBe(true); // an entry WAS resolved…
    expect(r.checks.jws_signature_valid).toBe(false); // …but it is not a usable key.
  });

  it('rejects an events member that is not an object', () => {
    const adv = elevatedAdvisory();
    const compact = buildEyeSet(adv, { signer: signer(), audience: AUDIENCE });
    const { header, payload } = parts(compact);
    const badMember = { ...payload, events: { [EYE_ADVISORY_EVENT_URI]: 'not-an-object' } };
    const r = verifyEyeSet(mint(header, badMember), { pinnedKeys: pinnedKeys(), audience: AUDIENCE });
    expect(r.valid).toBe(false);
    expect(r.checks.claims_present).toBe(false);
  });

  it('rejects an events value that is an array (not a map)', () => {
    const adv = elevatedAdvisory();
    const compact = buildEyeSet(adv, { signer: signer(), audience: AUDIENCE });
    const { header, payload } = parts(compact);
    const arrEvents = { ...payload, events: [payload.events[EYE_ADVISORY_EVENT_URI]] };
    const r = verifyEyeSet(mint(header, arrEvents), { pinnedKeys: pinnedKeys(), audience: AUDIENCE });
    expect(r.valid).toBe(false);
    expect(r.checks.claims_present).toBe(false);
  });

  it('rejects a non-integer iat as a missing claim', () => {
    const adv = elevatedAdvisory();
    const compact = buildEyeSet(adv, { signer: signer(), audience: AUDIENCE });
    const { header, payload } = parts(compact);
    const badIat = { ...payload, iat: 'soon' };
    const r = verifyEyeSet(mint(header, badIat), { pinnedKeys: pinnedKeys(), audience: AUDIENCE });
    expect(r.valid).toBe(false);
    expect(r.checks.claims_present).toBe(false);
    expect(r.errors.some((e) => /iat/.test(e))).toBe(true);
  });

  it('ignores a non-integer opts.maxAgeSec (iat age not gated) and a non-integer opts.now (uses wall clock)', () => {
    const adv = elevatedAdvisory();
    const compact = buildEyeSet(adv, { signer: signer(), audience: AUDIENCE });
    // maxAgeSec not an integer → iat-age branch skipped; now not an integer → wall clock.
    const r = verifyEyeSet(compact, {
      pinnedKeys: pinnedKeys(), audience: AUDIENCE, requireFresh: true, maxAgeSec: 'lots', now: 'whenever',
    });
    expect(r.valid).toBe(true);
    expect(r.checks.fresh).toBe(true);
  });

  it('treats an empty / null pinned entry as unpinned', () => {
    const adv = elevatedAdvisory();
    const compact = buildEyeSet(adv, { signer: signer(), audience: AUDIENCE });
    expect(verifyEyeSet(compact, { pinnedKeys: { [EMITTER_KID]: '' } }).checks.emitter_key_pinned).toBe(false);
    expect(verifyEyeSet(compact, { pinnedKeys: { [EMITTER_KID]: { public_key: 123 } } }).checks.emitter_key_pinned).toBe(false);
    expect(verifyEyeSet(compact, { pinnedKeys: 'not-a-map' }).checks.emitter_key_pinned).toBe(false);
  });
});

// ── catalogue parity (every vector id is asserted by name) ───────────────────────

describe('EP-EYE-SET-v1 — vectors catalogue parity', () => {
  it('catalogue is the expected wire tag and lengths', () => {
    expect(VECTORS.wire_tag).toBe('EP-EYE-SET-v1');
    expect(VECTORS.must_reject).toHaveLength(10);
    expect(VECTORS.must_accept).toHaveLength(2);
  });

  it('every catalogued vector id is asserted by name in this suite', () => {
    // The set of ids this suite explicitly drives (matches the it() titles above).
    const asserted = new Set([
      'a_forged_jws_signature',
      'b_unpinned_emitter_kid',
      'c_wrong_pinned_key_substitution',
      'd_alg_none_confusion',
      'e_tampered_payload_status_downgrade',
      'f_audience_mismatch',
      'g_expired_set_exp_past',
      'h_iat_too_old',
      'i_missing_never_sole_gate_marker',
      'j_clear_status_emitted_as_event',
      'z_well_formed_elevated_set_pinned_fresh',
      'z2_well_formed_review_required_no_audience_pin',
    ]);
    const catalogued = [
      ...VECTORS.must_reject.map((v) => v.id),
      ...VECTORS.must_accept.map((v) => v.id),
    ];
    for (const id of catalogued) {
      expect(asserted.has(id), `vector ${id} must be asserted by name`).toBe(true);
    }
    // And no asserted id is stale (not in the catalogue).
    for (const id of asserted) {
      expect(catalogued.includes(id), `asserted id ${id} must exist in the catalogue`).toBe(true);
    }
    expect(catalogued).toHaveLength(asserted.size);
  });

  it('each must_reject vector names a failing_check the verifier exposes', () => {
    const exposed = new Set(Object.keys(
      verifyEyeSet('x.y.z', { pinnedKeys: pinnedKeys() }).checks,
    ));
    for (const v of VECTORS.must_reject) {
      expect(exposed.has(v.expected.failing_check), `${v.id} → ${v.expected.failing_check}`).toBe(true);
    }
  });
});
