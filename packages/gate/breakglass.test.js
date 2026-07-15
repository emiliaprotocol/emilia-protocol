// SPDX-License-Identifier: Apache-2.0
/**
 * @emilia-protocol/gate — break-glass tests (EP-GATE-BREAKGLASS-v1).
 * Run with `node --test`.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  mintBreakGlassAuthorization,
  verifyBreakGlass,
  consumeBreakGlass,
  buildBreakGlassEvidence,
  BREAKGLASS_VERSION,
  BREAKGLASS_EVIDENCE_KIND,
} from './breakglass.js';
import { MemoryConsumptionStore } from './store.js';
import { createEvidenceLog } from './evidence.js';

function makeSigner(kid) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { kid, privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}

const alice = makeSigner('kid-alice');
const bob = makeSigner('kid-bob');
const carol = makeSigner('kid-carol');
const ISSUERS = { [alice.kid]: alice.pub, [bob.kid]: bob.pub, [carol.kid]: carol.pub };

const NBF = '2026-07-04T00:00:00.000Z';
const EXP = '2026-07-04T04:00:00.000Z';
const IN_WINDOW = Date.parse('2026-07-04T01:00:00.000Z');
const FIELDS = {
  scope: { action_types: ['db.restore', 'feature.kill_switch'] },
  window: { not_before: NBF, expires_at: EXP },
  reason: 'primary region down, restoring from snapshot',
  incident_ref: 'INC-2026-0704-01',
  threshold: 2,
};

function grant2of2(fields = {}) {
  return mintBreakGlassAuthorization([alice, bob], { ...FIELDS, ...fields });
}
function verify(g, opts = {}) {
  return verifyBreakGlass(g, { issuerKeys: ISSUERS, now: IN_WINDOW, actionType: 'db.restore', ...opts });
}

// ---------------------------------------------------------------- happy path

test('2-of-2 grant verifies in-window and in-scope', () => {
  const g = grant2of2();
  assert.equal(g['@version'], BREAKGLASS_VERSION);
  const out = verify(g);
  assert.equal(out.valid, true);
  assert.equal(out.reason, 'breakglass_verified');
  assert.equal(out.threshold, 2);
  assert.deepEqual(out.signer_kids, ['kid-alice', 'kid-bob']);
  assert.equal(out.incident_ref, 'INC-2026-0704-01');
  assert.match(out.grant_id, /^bg_[0-9a-f]{64}$/);
});

test('grant_id is content-derived and deterministic', () => {
  assert.equal(grant2of2().payload.grant_id, grant2of2().payload.grant_id);
  assert.notEqual(grant2of2().payload.grant_id, grant2of2({ incident_ref: 'INC-other' }).payload.grant_id);
});

test('threshold-of-N: 2-of-3 verifies with any two distinct signers', () => {
  const g = mintBreakGlassAuthorization([alice, carol], FIELDS);
  const out = verify(g);
  assert.equal(out.valid, true);
  assert.deepEqual(out.signer_kids, ['kid-alice', 'kid-carol']);
});

test('accepts a JSON string and an injected clock function', () => {
  const g = grant2of2();
  const out = verifyBreakGlass(JSON.stringify(g), {
    issuerKeys: ISSUERS, now: () => IN_WINDOW, actionType: 'feature.kill_switch',
  });
  assert.equal(out.valid, true);
});

test('refuses duplicate-member JSON before signature semantics are evaluated', () => {
  const g = grant2of2();
  const raw = `{"@version":"${BREAKGLASS_VERSION}","payload":${JSON.stringify(g.payload)},"payload":${JSON.stringify(g.payload)},"signatures":${JSON.stringify(g.signatures)}}`;
  const out = verifyBreakGlass(raw, { issuerKeys: ISSUERS, now: IN_WINDOW, actionType: 'db.restore' });
  assert.equal(out.valid, false);
  assert.equal(out.reason, 'grant_unparseable');
});

// ---------------------------------------------------------------- mint refuses to issue malformed grants

test('mint throws on duplicate signer kids — one principal cannot fill two slots', () => {
  assert.throws(() => mintBreakGlassAuthorization([alice, { ...bob, kid: alice.kid }], FIELDS), /distinct/);
});

test('mint throws on threshold exceeding signer count', () => {
  assert.throws(() => mintBreakGlassAuthorization([alice], FIELDS), /exceeds signer count/);
});

test('mint throws on empty scope, missing reason, missing incident_ref, inverted window', () => {
  assert.throws(() => grant2of2({ scope: { action_types: [] } }), /action_types/);
  assert.throws(() => grant2of2({ reason: '' }), /reason/);
  assert.throws(() => grant2of2({ incident_ref: undefined }), /incident_ref/);
  assert.throws(() => grant2of2({ window: { not_before: EXP, expires_at: NBF } }), /after/);
  assert.throws(() => grant2of2({ threshold: 0 }), /threshold/);
});

// ---------------------------------------------------------------- fail-closed refusals

test('threshold unmet: fewer signatures than threshold -> refused', () => {
  const g = grant2of2();
  g.signatures = g.signatures.slice(0, 1); // payload untouched, sig still valid — just not enough of them
  const out = verify(g);
  assert.equal(out.valid, false);
  assert.equal(out.reason, 'threshold_unmet');
  assert.equal(out.threshold, 2);
  assert.equal(out.signatures, 1);
});

test('non-distinct signer kids: same signature twice -> refused, not counted twice', () => {
  const g = grant2of2();
  g.signatures = [g.signatures[0], g.signatures[0]]; // 2 slots, 1 principal
  const out = verify(g);
  assert.equal(out.valid, false);
  assert.equal(out.reason, 'duplicate_signer');
  assert.equal(out.kid, 'kid-alice');
});

test('expired grant -> refused', () => {
  const out = verify(grant2of2(), { now: Date.parse(EXP) + 1 });
  assert.equal(out.valid, false);
  assert.equal(out.reason, 'expired');
});

test('not-yet-valid grant -> refused', () => {
  const out = verify(grant2of2(), { now: Date.parse(NBF) - 1 });
  assert.equal(out.valid, false);
  assert.equal(out.reason, 'not_yet_valid');
});

test('out-of-scope action_type -> refused', () => {
  const out = verify(grant2of2(), { actionType: 'payment.release' });
  assert.equal(out.valid, false);
  assert.equal(out.reason, 'out_of_scope');
  assert.equal(out.action_type, 'payment.release');
});

test('missing actionType -> refused (scope cannot be checked)', () => {
  const out = verify(grant2of2(), { actionType: undefined });
  assert.equal(out.valid, false);
  assert.equal(out.reason, 'action_type_required');
});

test('tampered payload -> bad_signature (scope widening does not survive)', () => {
  const g = grant2of2();
  g.payload.scope.action_types.push('payment.release');
  const out = verify(g, { actionType: 'payment.release' });
  assert.equal(out.valid, false);
  assert.equal(out.reason, 'bad_signature');
});

test('tampered window -> bad_signature (timestamps are authenticated)', () => {
  const g = grant2of2();
  g.payload.window.expires_at = '2027-01-01T00:00:00.000Z';
  const out = verify(g);
  assert.equal(out.valid, false);
  assert.equal(out.reason, 'bad_signature');
});

test('unknown kid -> refused even if other signatures are fine', () => {
  const g = grant2of2();
  const out = verifyBreakGlass(g, {
    issuerKeys: { [alice.kid]: alice.pub }, // bob is not pinned
    now: IN_WINDOW, actionType: 'db.restore',
  });
  assert.equal(out.valid, false);
  assert.equal(out.reason, 'unknown_kid');
  assert.equal(out.kid, 'kid-bob');
});

test('no pinned keys at all -> refused (grant cannot nominate its own keys)', () => {
  const out = verifyBreakGlass(grant2of2(), { now: IN_WINDOW, actionType: 'db.restore' });
  assert.equal(out.valid, false);
  assert.equal(out.reason, 'unknown_kid');
});

test('one bad signature refuses the whole grant', () => {
  const g = mintBreakGlassAuthorization([alice, bob, carol], FIELDS); // 2-of-3 style: threshold 2, 3 sigs
  g.signatures[2].value = g.signatures[2].value.slice(0, -4) + 'AAAA';
  const out = verify(g);
  assert.equal(out.valid, false);
  assert.equal(out.reason, 'bad_signature');
  assert.equal(out.kid, 'kid-carol');
});

test('malformed artifacts never throw, always refuse', () => {
  assert.equal(verify(null).reason, 'no_grant');
  assert.equal(verify('not json{').reason, 'grant_unparseable');
  assert.equal(verify(42).reason, 'grant_malformed');
  assert.equal(verify({ '@version': 'EP-GATE-BREAKGLASS-v0' }).reason, 'unsupported_version');
  const noSigs = { ...grant2of2(), signatures: [] };
  assert.equal(verify(noSigs).reason, 'grant_malformed');
  const g = grant2of2();
  g.signatures[0].algorithm = 'RS256';
  assert.equal(verify(g).reason, 'unsupported_algorithm');
});

test('grant with stripped reason or incident_ref -> refused', () => {
  const g1 = grant2of2();
  delete g1.payload.reason;
  assert.equal(verify(g1).reason, 'missing_reason');
  const g2 = grant2of2();
  g2.payload.incident_ref = '';
  assert.equal(verify(g2).reason, 'missing_incident_ref');
});

// ---------------------------------------------------------------- single-use consumption

test('consume: first use succeeds, double-consume refused', async () => {
  const g = grant2of2();
  const store = new MemoryConsumptionStore();
  const first = await consumeBreakGlass(g, store);
  assert.equal(first.consumed, true);
  assert.equal(first.key, `breakglass:${g.payload.grant_id}`);
  const second = await consumeBreakGlass(g, store);
  assert.equal(second.consumed, false);
  assert.equal(second.reason, 'already_consumed');
});

test('consume: re-minted identical grant shares the consumption key (no refresh trick)', async () => {
  const store = new MemoryConsumptionStore();
  assert.equal((await consumeBreakGlass(grant2of2(), store)).consumed, true);
  assert.equal((await consumeBreakGlass(grant2of2(), store)).consumed, false);
});

test('consume fails closed: no store, missing grant_id, store error', async () => {
  const g = grant2of2();
  assert.equal((await consumeBreakGlass(g, null)).reason, 'no_consumption_store');
  assert.equal((await consumeBreakGlass({ payload: {} }, new MemoryConsumptionStore())).reason, 'missing_grant_id');
  const broken = { consume: async () => { throw new Error('redis down'); } };
  const out = await consumeBreakGlass(g, broken);
  assert.equal(out.consumed, false);
  assert.equal(out.reason, 'store_error');
});

test('consume accepts the verified result too', async () => {
  const g = grant2of2();
  const verified = verify(g);
  const store = new MemoryConsumptionStore();
  assert.equal((await consumeBreakGlass(verified, store)).consumed, true);
  assert.equal((await consumeBreakGlass(g, store)).consumed, false); // same key
});

// ---------------------------------------------------------------- evidence: no entry, no override

test('evidence entry has kind breakglass and commits to the exact grant', async () => {
  const g = grant2of2();
  const entry = buildBreakGlassEvidence(g, { allow: true, reason: 'breakglass_verified', action_type: 'db.restore' },
    { now: IN_WINDOW });
  assert.equal(entry.kind, BREAKGLASS_EVIDENCE_KIND);
  assert.equal(entry['@version'], BREAKGLASS_VERSION);
  assert.equal(entry.grant_id, g.payload.grant_id);
  assert.equal(entry.incident_ref, 'INC-2026-0704-01');
  assert.deepEqual(entry.signer_kids, ['kid-alice', 'kid-bob']);
  assert.match(entry.grant_hash, /^[0-9a-f]{64}$/);
  assert.equal(entry.at, '2026-07-04T01:00:00.000Z');
  assert.equal(entry.decision.allow, true);
  // a tampered grant hashes differently — the log pins the exact artifact
  const tampered = grant2of2();
  tampered.payload.reason = 'edited later';
  assert.notEqual(buildBreakGlassEvidence(tampered, {}).grant_hash, entry.grant_hash);
  // and it chains cleanly into the tamper-evident evidence log
  const log = createEvidenceLog();
  await log.record(entry);
  assert.equal(log.verify().ok, true);
});

test('refusals are loggable too, and a missing decision records allow:false (fail closed)', () => {
  const entry = buildBreakGlassEvidence(null, undefined, { now: IN_WINDOW });
  assert.equal(entry.kind, BREAKGLASS_EVIDENCE_KIND);
  assert.equal(entry.grant_id, null);
  assert.equal(entry.decision.allow, false);
  assert.equal(entry.decision.reason, 'unspecified');
  const notQuiteAllow = buildBreakGlassEvidence(grant2of2(), { allow: 'yes' });
  assert.equal(notQuiteAllow.decision.allow, false);
});

test('no evidence entry, no override: strict log sink failure blocks the flow', async () => {
  const g = grant2of2();
  const log = createEvidenceLog({ strict: true, sink: async () => { throw new Error('disk full'); } });
  const entry = buildBreakGlassEvidence(g, { allow: true, reason: 'breakglass_verified', action_type: 'db.restore' });
  let overrideRan = false;
  await assert.rejects(async () => {
    await log.record(entry); // throws — the entry was NOT durably recorded
    overrideRan = true; // must never be reached: no evidence entry, no override
  }, /evidence_sink_failed/);
  assert.equal(overrideRan, false);
});

// ---------------------------------------------------------------- full flow

test('end-to-end: verify -> consume -> evidence -> replay refused', async () => {
  const g = grant2of2();
  const store = new MemoryConsumptionStore();
  const log = createEvidenceLog();

  const verified = verify(g);
  assert.equal(verified.valid, true);
  const consumed = await consumeBreakGlass(verified, store); // committed BEFORE use
  assert.equal(consumed.consumed, true);
  const rec = await log.record(buildBreakGlassEvidence(g, {
    allow: true, reason: verified.reason, action_type: 'db.restore',
  }, { now: IN_WINDOW }));
  assert.equal(rec.kind, 'breakglass');
  // ... override executes here, and ONLY here ...

  // replay: same grant, second presentation — refused and the refusal is logged
  const replay = await consumeBreakGlass(g, store);
  assert.equal(replay.consumed, false);
  await log.record(buildBreakGlassEvidence(g, {
    allow: false, reason: replay.reason, action_type: 'db.restore',
  }, { now: IN_WINDOW }));
  assert.equal(log.verify().ok, true);
  assert.equal(log.all().length, 2);
  assert.equal(log.all()[1].decision.allow, false);
  assert.equal(log.all()[1].decision.reason, 'already_consumed');
});
