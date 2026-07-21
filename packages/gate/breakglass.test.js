// SPDX-License-Identifier: Apache-2.0
// Generated from breakglass.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * @emilia-protocol/gate — break-glass tests (EP-GATE-BREAKGLASS-v1).
 * Run with `node --test`.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mintBreakGlassAuthorization, verifyBreakGlass, consumeBreakGlass, buildBreakGlassEvidence, runBreakGlass, BREAKGLASS_VERSION, BREAKGLASS_EVIDENCE_KIND, } from './breakglass.js';
import { MemoryConsumptionStore, createDurableConsumptionStore, createMemoryBackend, } from './store.js';
import { createEvidenceLog } from './evidence.js';
function makeSigner(kid) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    return { kid, privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}
const alice = makeSigner('kid-alice');
const bob = makeSigner('kid-bob');
const carol = makeSigner('kid-carol');
const ISSUERS = { [alice.kid]: alice.pub, [bob.kid]: bob.pub, [carol.kid]: carol.pub };
function pinnedPolicy(signers = [alice, bob, carol], minimumThreshold = 2) {
    return {
        minimum_threshold: minimumThreshold,
        roster: signers.map((signer) => ({
            kid: signer.kid,
            principal_id: signer.principal_id || `principal:${signer.kid}`,
            key: signer.pub,
        })),
    };
}
const POLICY = pinnedPolicy();
function durableStore() {
    const backend = createMemoryBackend();
    backend.durable = true;
    return createDurableConsumptionStore(backend);
}
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
    return verifyBreakGlass(g, {
        issuerKeys: ISSUERS,
        policy: POLICY,
        now: IN_WINDOW,
        actionType: 'db.restore',
        ...opts,
    });
}
function rawGrant(signers, fields) {
    const core = {
        scope: { action_types: fields.scope.action_types.slice() },
        window: { ...fields.window },
        reason: fields.reason,
        incident_ref: fields.incident_ref,
        threshold: fields.threshold,
    };
    const canonical = (value) => {
        if (value === null)
            return 'null';
        if (Array.isArray(value))
            return `[${value.map(canonical).join(',')}]`;
        if (typeof value === 'object') {
            return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
        }
        return JSON.stringify(value);
    };
    const grant_id = `bg_${crypto.createHash('sha256').update(canonical(core)).digest('hex')}`;
    const payload = { grant_id, ...core };
    const bytes = Buffer.from(canonical(payload), 'utf8');
    return {
        '@version': BREAKGLASS_VERSION,
        payload,
        signatures: signers.map((signer) => ({
            kid: signer.kid,
            algorithm: 'Ed25519',
            value: crypto.sign(null, bytes, signer.privateKey).toString('base64url'),
        })),
    };
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
        issuerKeys: ISSUERS, policy: POLICY, now: () => IN_WINDOW, actionType: 'feature.kill_switch',
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
test('mint throws when one SPKI is presented under two kids', () => {
    assert.throws(() => mintBreakGlassAuthorization([alice, { ...alice, kid: 'kid-alice-alias' }], FIELDS), /SPKI keys must be distinct/);
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
test('relying-party minimum defeats a presenter self-declaring threshold=1', () => {
    const g = rawGrant([alice], { ...FIELDS, threshold: 1 });
    const out = verify(g);
    assert.equal(out.valid, false);
    assert.equal(out.reason, 'policy_threshold_unmet');
    assert.equal(out.required_threshold, 2);
});
test('pinned roster refuses an otherwise valid signer selected by the presenter', () => {
    const g = rawGrant([alice, carol], FIELDS);
    const out = verify(g, { policy: pinnedPolicy([alice, bob]) });
    assert.equal(out.valid, false);
    assert.equal(out.reason, 'signer_not_in_roster');
    assert.equal(out.kid, carol.kid);
});
test('two kids for one principal cannot fill two break-glass slots', () => {
    const aliceSecondKey = { ...carol, kid: 'kid-alice-secondary', principal_id: 'principal:alice' };
    const alicePrimary = { ...alice, principal_id: 'principal:alice' };
    const g = rawGrant([alicePrimary, aliceSecondKey], FIELDS);
    const out = verify(g, { policy: pinnedPolicy([alicePrimary, aliceSecondKey, bob]) });
    assert.equal(out.valid, false);
    assert.equal(out.reason, 'duplicate_signer_principal');
    assert.equal(out.principal_id, 'principal:alice');
});
test('the same SPKI under two kids cannot fill two break-glass slots', () => {
    const alias = { ...alice, kid: 'kid-alice-alias', principal_id: 'principal:alias-record' };
    const alicePrimary = { ...alice, principal_id: 'principal:alice' };
    const g = rawGrant([alicePrimary, alias], FIELDS);
    const out = verify(g, { policy: pinnedPolicy([alicePrimary, alias, bob]) });
    assert.equal(out.valid, false);
    assert.equal(out.reason, 'duplicate_signer_key');
    assert.match(out.spki_fingerprint, /^sha256:[0-9a-f]{64}$/);
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
test('an incomplete pinned key policy is invalid even if one signature is fine', () => {
    const g = grant2of2();
    const out = verifyBreakGlass(g, {
        issuerKeys: { [alice.kid]: alice.pub },
        policy: pinnedPolicy([alice]), // bob is not on the relying-party roster
        now: IN_WINDOW, actionType: 'db.restore',
    });
    assert.equal(out.valid, false);
    assert.equal(out.reason, 'invalid_policy');
});
test('missing relying-party policy is refused even when every issuer key is pinned', () => {
    const out = verifyBreakGlass(grant2of2(), {
        issuerKeys: ISSUERS,
        now: IN_WINDOW,
        actionType: 'db.restore',
    });
    assert.equal(out.valid, false);
    assert.equal(out.reason, 'missing_policy');
});
test('roster omission is reported for a policy that can otherwise meet quorum', () => {
    const out = verifyBreakGlass(grant2of2(), {
        policy: pinnedPolicy([alice, carol, { ...carol, kid: 'kid-dave', principal_id: 'principal:dave' }]),
        now: IN_WINDOW,
        actionType: 'db.restore',
    });
    assert.equal(out.valid, false);
    assert.equal(out.reason, 'signer_not_in_roster');
    assert.equal(out.kid, 'kid-bob');
});
test('no relying-party policy at all -> refused (grant cannot nominate its own trust policy)', () => {
    const out = verifyBreakGlass(grant2of2(), { now: IN_WINDOW, actionType: 'db.restore' });
    assert.equal(out.valid, false);
    assert.equal(out.reason, 'missing_policy');
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
    const entry = buildBreakGlassEvidence(g, { allow: true, reason: 'breakglass_verified', action_type: 'db.restore' }, { now: IN_WINDOW });
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
test('runBreakGlass enforces verify -> permanent consumption -> evidence -> effect order', async () => {
    const events = [];
    const baseStore = durableStore();
    const store = {
        ...baseStore,
        async consume(key) {
            events.push('consume');
            return baseStore.consume(key);
        },
    };
    const baseEvidence = createEvidenceLog({ strict: true });
    const evidence = {
        ...baseEvidence,
        async record(entry) {
            events.push('evidence');
            return baseEvidence.record(entry);
        },
    };
    const out = await runBreakGlass({
        grant: grant2of2(),
        policy: POLICY,
        actionType: 'db.restore',
        store,
        evidence,
        now: IN_WINDOW,
    }, async ({ verification, evidence: record }) => {
        events.push('effect');
        assert.equal(verification.valid, true);
        assert.equal(record.kind, BREAKGLASS_EVIDENCE_KIND);
        return 'restored';
    });
    assert.equal(out.ok, true);
    assert.equal(out.result, 'restored');
    assert.deepEqual(events, ['consume', 'evidence', 'effect']);
});
test('runBreakGlass never invokes the effect without a successful strict evidence record', async () => {
    const store = durableStore();
    const evidence = createEvidenceLog({
        strict: true,
        sink: async () => { throw new Error('evidence unavailable'); },
    });
    let effects = 0;
    const grant = grant2of2();
    const out = await runBreakGlass({
        grant,
        policy: POLICY,
        actionType: 'db.restore',
        store,
        evidence,
        now: IN_WINDOW,
    }, async () => { effects += 1; });
    assert.equal(out.ok, false);
    assert.equal(out.reason, 'evidence_record_failed');
    assert.equal(effects, 0);
    assert.equal((await consumeBreakGlass(grant, store)).reason, 'already_consumed', 'failed evidence burns the grant');
});
test('runBreakGlass refuses ephemeral consumption and non-strict evidence before any effect', async () => {
    const grant = grant2of2();
    let effects = 0;
    const effect = async () => { effects += 1; };
    const ephemeral = await runBreakGlass({
        grant,
        policy: POLICY,
        actionType: 'db.restore',
        store: new MemoryConsumptionStore(),
        evidence: createEvidenceLog({ strict: true }),
        now: IN_WINDOW,
    }, effect);
    assert.equal(ephemeral.ok, false);
    assert.equal(ephemeral.reason, 'secure_consumption_store_required');
    const nonStrict = await runBreakGlass({
        grant,
        policy: POLICY,
        actionType: 'db.restore',
        store: durableStore(),
        evidence: createEvidenceLog({ strict: false }),
        now: IN_WINDOW,
    }, effect);
    assert.equal(nonStrict.ok, false);
    assert.equal(nonStrict.reason, 'strict_evidence_required');
    assert.equal(effects, 0);
});
test('runBreakGlass treats a malformed evidence acknowledgement as no evidence', async () => {
    let effects = 0;
    const out = await runBreakGlass({
        grant: grant2of2(),
        policy: POLICY,
        actionType: 'db.restore',
        store: durableStore(),
        evidence: { strict: true, record: async () => ({ kind: 'not-an-evidence-record' }) },
        now: IN_WINDOW,
    }, async () => { effects += 1; });
    assert.equal(out.ok, false);
    assert.equal(out.reason, 'evidence_record_failed');
    assert.equal(effects, 0);
});
