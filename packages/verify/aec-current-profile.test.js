// SPDX-License-Identifier: Apache-2.0
// Generated from aec-current-profile.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import * as aec from './dist/evidence-chain.js';
import { canonicalizeStrictJson } from './dist/strict-json.js';
const NOW = '2026-09-06T12:00:00Z';
const action = { action_type: 'payment.release', amount: 100, destination: 'merchant:one' };
const digest = (value) => `sha256:${crypto.createHash('sha256').update(canonicalizeStrictJson(value)).digest('hex')}`;
const ACTION = digest(action);
const pair = crypto.generateKeyPairSync('ed25519');
const publicKey = pair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
const requirement = (extra = {}) => ({
    '@version': 'EP-AEC-REQUIREMENT-v1', requirement_id: 'payment-evidence@1',
    expression: 'approval AND permit',
    freshness_sec: { approval: 300, permit: 300 },
    role_constraints: [{ type: 'distinct-subject-quorum', component_type: 'approval', threshold: 2, subject_id_source: 'native-verifier' }],
    required_bindings: [{ from_type: 'permit', relation: 'permits', to_type: 'approval' }],
    ...extra,
});
function signed(subject, extra = {}) {
    const payload = {
        format_revision: 'example-signed-v1', action_digest: ACTION, issuer: 'issuer:one', audience: 'executor:one',
        issued_at: '2026-09-06T11:59:00Z', expires_at: '2026-09-06T12:05:00Z',
        subject_ids: [subject], bindings: [], ...extra,
    };
    return { payload, signature: crypto.sign(null, Buffer.from(canonicalizeStrictJson(payload)), pair.privateKey).toString('base64url') };
}
function verify(evidence, context) {
    const key = context.trust_snapshot.public_key;
    if (!crypto.verify(null, Buffer.from(canonicalizeStrictJson(evidence.payload)), key, Buffer.from(evidence.signature, 'base64url')))
        return { valid: false, reason: 'signature_invalid' };
    if (evidence.payload.issuer !== 'issuer:one' || evidence.payload.audience !== 'executor:one')
        return { valid: false, reason: 'native_scope_invalid' };
    return { valid: true, ...evidence.payload };
}
function registration(override = {}) {
    return { profile: { id: 'example-signed', revision: '1', native_format_revision: 'example-signed-v1' }, trustSnapshot: { public_key: publicKey }, verify, ...override };
}
function fixture() {
    const first = signed('person:one');
    const second = signed('person:two');
    const permit = signed('policy:one', { bindings: [{ relation: 'permits', target_evidence_digest: digest(first) }] });
    return { '@version': 'EP-AEC-v1', action, components: [
            { type: 'approval', evidence: first }, { type: 'approval', evidence: second }, { type: 'permit', evidence: permit },
        ] };
}
function evaluator(req = requirement(), overrides = {}) {
    assert.equal(typeof aec.createAuthorizationChainEvaluator, 'function', 'current AEC profile API must exist');
    return aec.createAuthorizationChainEvaluator({
        requirement: req,
        nativeVerifiers: { approval: registration(), permit: registration() },
        ...overrides,
    });
}
const inputs = () => ({ expectedAction: action, verificationTime: NOW });
test('AEC05: structured requirement enforces real signatures, native subjects, bindings and emits replay', async () => {
    const chain = fixture();
    const result = await evaluator().evaluate(chain, inputs());
    assert.equal(result.satisfied, true, JSON.stringify(result));
    assert.equal(result.allow, result.satisfied);
    assert.equal(result.authorization_decision, false);
    assert.equal(result.replay['@version'], 'EP-AEC-REPLAY-v1');
    assert.equal(result.replay.aec_digest, digest(chain));
    assert.equal(result.replay.requirement_profile_digest, digest(requirement()));
    assert.equal(result.replay_digest, digest(result.replay));
    assert.deepEqual(result.replay.facts.map((f) => f.component_index), [0, 1, 2]);
    assert.deepEqual(result.replay.facts[0].subject_ids, ['person:one']);
    assert.equal(result.replay.facts[0].native_verifier_profile_digest, digest(registration().profile));
    assert.equal(result.replay.facts[0].trust_snapshot_digest, digest(registration().trustSnapshot));
});
for (const [name, mutate] of [
    ['a repeated native person despite different keys/labels', (c) => { c.components[1].evidence = signed('person:one'); c.components[1].label = 'person:two'; }],
    ['an unsigned claimed subject', (c) => { c.components[1].evidence.payload.subject_ids = ['person:three']; }],
    ['an unbacked presenter relation', (c) => { c.components[2].evidence = signed('policy:one'); c.components[2].label = 'permits approval'; }],
    ['a signed relation to the wrong bytes', (c) => { c.components[2].evidence = signed('policy:one', { bindings: [{ relation: 'permits', target_evidence_digest: `sha256:${'f'.repeat(64)}` }] }); }],
    ['an ineligible relation target', (c) => { c.components[0].evidence = signed('person:one', { action_digest: `sha256:${'f'.repeat(64)}` }); }],
    ['a false presented evidence digest', (c) => { c.components[1].evidence_digest = `sha256:${'f'.repeat(64)}`; }],
    ['future issuance', (c) => { c.components[1].evidence = signed('person:two', { issued_at: '2026-09-06T12:01:00Z' }); }],
    ['expired evidence', (c) => { c.components[1].evidence = signed('person:two', { expires_at: '2026-09-06T11:59:59Z' }); }],
    ['missing protected time', (c) => { c.components[1].evidence = signed('person:two', { issued_at: null }); }],
    ['too-old evidence', (c) => { c.components[1].evidence = signed('person:two', { issued_at: '2026-09-06T11:50:00Z' }); }],
    ['wrong native format revision', (c) => { c.components[1].evidence = signed('person:two', { format_revision: 'example-signed-v2' }); }],
]) {
    test(`AEC05 refuses ${name}`, async () => {
        const chain = fixture();
        mutate(chain);
        const result = await evaluator().evaluate(chain, inputs());
        assert.equal(result.satisfied, false, JSON.stringify(result));
        assert.equal(result.allow, false);
    });
}
test('AEC05 refuses unknown/partial role constraints and malformed complete requirements at construction', () => {
    for (const req of [
        requirement({ role_constraints: [{ type: 'initiator-exclusion' }] }),
        requirement({ role_constraints: [{ type: 'distinct-subject-quorum', component_type: 'approval', threshold: 2, subject_id_source: 'signer-key' }] }),
        requirement({ role_constraints: [{ type: 'distinct-subject-quorum', component_type: 'approval', threshold: 1, subject_id_source: 'native-verifier' }] }),
        requirement({ role_constraints: [{ type: 'distinct-subject-quorum', component_type: 'approval', threshold: 2, subject_id_source: 'native-verifier', extra: true }] }),
        requirement({ required_bindings: [{ from_type: 'permit', relation: 'permits' }] }),
        requirement({ freshness_sec: { approval: -1 } }),
        requirement({ expression: 'approval OR' }),
        requirement({ expression: 'approval', arbitrary: true }),
        requirement({ '@version': 'EP-AEC-REQUIREMENT-v99' }),
    ])
        assert.throws(() => evaluator(req), TypeError);
});
test('AEC05 pins configuration and refuses transaction-scoped trust or requirement overrides', async () => {
    const req = requirement();
    const registrations = { approval: registration(), permit: registration() };
    const ev = evaluator(req, { nativeVerifiers: registrations });
    req.expression = 'permit';
    req.role_constraints = [];
    req.required_bindings = [];
    registrations.approval.verify = () => ({ valid: true });
    const chain = fixture();
    chain.components[1].evidence = signed('person:one');
    assert.equal((await ev.evaluate(chain, inputs())).satisfied, false);
    assert.equal((await ev.evaluate(fixture(), { ...inputs(), requirement: requirement() })).satisfied, false);
    assert.equal((await ev.evaluate(fixture(), { ...inputs(), nativeVerifiers: registrations })).satisfied, false);
});
test('AEC05 status requires native authentication, active disposition and current bound snapshot', async () => {
    const snapshot = { status: 'active', checked_at: '2026-09-06T11:59:30Z', expires_at: '2026-09-06T12:01:00Z' };
    const good = { authenticated: true, ...snapshot, snapshot_digest: digest(snapshot) };
    for (const status of [good, { ...good, authenticated: false }, { ...good, status: 'revoked' }, { ...good, status: 'unknown' }, { ...good, checked_at: '2026-09-06T11:50:00Z' }, { ...good, snapshot_digest: 'bogus' }, { ...good, expires_at: '2026-09-06T11:59:59Z' }]) {
        const chain = fixture();
        chain.components[2].evidence = signed('policy:one', { status });
        const ev = evaluator(requirement({ status_required: ['permit'], required_bindings: [] }), { nativeVerifiers: { approval: registration(), permit: registration({ statusMaxAgeSec: 60 }) } });
        const result = await ev.evaluate(chain, inputs());
        assert.equal(result.satisfied, status === good, JSON.stringify(result));
        if (status === good)
            assert.equal(result.replay.facts[2].status.snapshot_digest, digest(snapshot));
    }
});
test('AEC05 uses only pinned mapping after native verification and checks expected CAID', async () => {
    const caid = `caid:1:payment.release.1:jcs-sha256:${Buffer.alloc(32, 7).toString('base64url')}`;
    let maps = 0;
    const reg = registration({ mapping: { profile: { id: 'mapping:one', revision: '1' }, map: (native) => { maps++; return { verdict: native.native_payload.destination === 'merchant:one' ? 'EQUIVALENT_UNDER_PROFILE' : 'NOT_EQUIVALENT', caid }; } } });
    const ev = evaluator(requirement({ expression: 'mapped', freshness_sec: {}, role_constraints: [], required_bindings: [] }), { nativeVerifiers: { mapped: reg } });
    const chain = { '@version': 'EP-AEC-v1', action, action_caid: caid, components: [{ type: 'mapped', evidence: signed('one', { action_digest: null, native_payload: { destination: 'merchant:one' } }) }] };
    assert.equal((await ev.evaluate(chain, { ...inputs(), expectedCaid: caid })).satisfied, true);
    assert.equal(maps, 1);
    chain.components[0].evidence.signature = 'invalid';
    assert.equal((await ev.evaluate(chain, { ...inputs(), expectedCaid: caid })).satisfied, false);
    assert.equal(maps, 1, 'mapping must never inspect an unverified native result');
});
test('AEC05 produces stable digests and replay re-verifies rather than trusting recorded facts', async () => {
    const ev = evaluator();
    const chain = fixture();
    const a = await ev.evaluate(chain, inputs());
    const b = await ev.evaluate(JSON.parse(JSON.stringify(chain)), inputs());
    assert.equal(a.replay_digest, b.replay_digest);
    assert.equal((await ev.replay(chain, a.replay, inputs())).matches, true);
    const forged = structuredClone(a.replay);
    forged.facts[0].subject_ids = ['invented'];
    assert.equal((await ev.replay(chain, forged, inputs())).matches, false);
    const changed = evaluator(requirement({ purpose: 'different exact profile' }));
    assert.notEqual((await changed.evaluate(chain, inputs())).replay_digest, a.replay_digest);
});
test('AEC05 parses raw JSON strictly and refuses hostile objects and resource overflow', async () => {
    const ev = evaluator();
    assert.equal((await ev.evaluate(JSON.stringify(fixture()), inputs())).satisfied, true);
    const raw = JSON.stringify(fixture()).replace('"@version":', '"@version":"EP-AEC-v1","@version":');
    assert.equal((await ev.evaluate(raw, inputs())).satisfied, false);
    for (const value of [NaN, 1.25, '\ud800', () => true, undefined]) {
        const chain = fixture();
        chain.action = { ...action, extra: value };
        assert.equal((await ev.evaluate(chain, inputs())).satisfied, false);
    }
    const accessor = fixture();
    Object.defineProperty(accessor, 'action', { get() { throw new Error('hostile'); }, enumerable: true });
    assert.equal((await ev.evaluate(accessor, inputs())).satisfied, false);
    const cycle = fixture();
    cycle.components.push(cycle);
    assert.equal((await ev.evaluate(cycle, inputs())).satisfied, false);
    assert.equal((await evaluator(requirement(), { limits: { maxComponents: 2 } }).evaluate(fixture(), inputs())).satisfied, false);
});
test('AEC05 requires explicit boundary action and time and keeps unknown types ineligible', async () => {
    const ev = evaluator();
    for (const input of [{ verificationTime: NOW }, { expectedAction: action }, { ...inputs(), verificationTime: '2026-02-30T12:00:00Z' }, { ...inputs(), expectedAction: { ...action, amount: 101 } }])
        assert.equal((await ev.evaluate(fixture(), input)).satisfied, false);
    const chain = fixture();
    chain.components[1].type = 'unknown';
    assert.equal((await ev.evaluate(chain, inputs())).satisfied, false);
});
test('AEC05 native verifier exceptions, malformed results and deadline never become partial success', async () => {
    for (const verify of [() => { throw new Error('secret'); }, () => ({ valid: 'true' }), () => new Promise(() => { })]) {
        const ev = evaluator(requirement(), { nativeVerifiers: { approval: registration({ verify }), permit: registration() }, limits: { maxVerifierDurationMs: 20 } });
        const result = await ev.evaluate(fixture(), inputs());
        assert.equal(result.satisfied, false);
        assert.ok(!JSON.stringify(result).includes('secret'));
    }
});
test('AEC05 oversized aggregate replay emits a bounded refusal instead of throwing from finish', async () => {
    const subjects = Array.from({ length: 64 }, (_, i) => `subject:${i}:${'x'.repeat(1980)}`);
    const ev = evaluator(requirement({ expression: 'approval', freshness_sec: {}, role_constraints: [], required_bindings: [] }), {
        nativeVerifiers: { approval: registration({ verify: () => ({ valid: true,
                    format_revision: 'example-signed-v1', action_digest: ACTION, subject_ids: subjects }) }) },
    });
    const chain = { '@version': 'EP-AEC-v1', action,
        components: Array.from({ length: 10 }, () => ({ type: 'approval', evidence: {} })) };
    const result = await ev.evaluate(chain, inputs());
    assert.equal(result.satisfied, false);
    assert.deepEqual(result.reasons, ['aec_replay_resource_limit']);
    assert.deepEqual(result.replay.facts, []);
    assert.equal(result.replay_digest, digest(result.replay));
    assert.ok(Buffer.byteLength(JSON.stringify(result.replay)) < 2048);
});
test('AEC05 human built-ins cannot be overridden by a custom verifier', () => {
    assert.throws(() => evaluator(requirement(), { nativeVerifiers: { 'ep-receipt': registration() } }), TypeError);
    assert.throws(() => evaluator(requirement(), { nativeVerifiers: { 'ep-quorum': registration() } }), TypeError);
});
test('AEC05 a logged but unsigned receipt context cannot supply another human subject', async () => {
    const corpus = JSON.parse(fs.readFileSync(new URL('../../conformance/vectors/aec-role.v1.json', import.meta.url), 'utf8'));
    const v = structuredClone(corpus.vectors.find((c) => c.id === 'accept_pinned_human_receipt'));
    const receipt = v.aec_chain.components[0].evidence;
    receipt.contexts.push({ ...receipt.contexts[0], approver: 'ep:approver:never-signed', approver_index: 2 });
    // A genuine transparency log signature authenticates inclusion, not a new
    // human ceremony. Preserve the original valid human signature unchanged.
    delete receipt.log_proof;
    const logKey = crypto.generateKeyPairSync('ed25519');
    v.policies_by_type['ep-receipt'].log_public_key = logKey.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const leaf = `sha256:${crypto.createHash('sha256').update(Buffer.concat([Buffer.from([0]), Buffer.from(canonicalizeStrictJson(receipt))])).digest('hex')}`;
    const checkpoint = { tree_size: 1, root_hash: leaf, log_key_id: 'review-test-log', merkle_alg: 'EP-MERKLE-v2' };
    checkpoint.log_signature = crypto.sign(null, crypto.createHash('sha256').update(canonicalizeStrictJson(checkpoint)).digest(), logKey.privateKey).toString('base64url');
    receipt.log_proof = { alg: 'EP-MERKLE-v2', leaf_hash: leaf, leaf_index: 0, inclusion_path: [], checkpoint };
    const ev = aec.createAuthorizationChainEvaluator({
        requirement: requirement({ expression: 'ep-receipt', freshness_sec: {}, required_bindings: [],
            role_constraints: [{ type: 'distinct-subject-quorum', component_type: 'ep-receipt', threshold: 2, subject_id_source: 'native-verifier' }] }),
        nativeVerifiers: { 'ep-receipt': { profile: { id: 'native-receipt', revision: '1', native_format_revision: 'Trust-Receipt' },
                trustSnapshot: { policy: v.policies_by_type['ep-receipt'] } } },
    });
    const result = await ev.evaluate(v.aec_chain, { expectedAction: v.aec_chain.action, verificationTime: v.verification_time });
    assert.equal(result.replay.facts[0].native_valid, true, JSON.stringify(result));
    assert.equal(result.satisfied, false, 'log inclusion cannot manufacture a second completed human signoff');
    assert.deepEqual(result.replay.facts[0].subject_ids, ['ep:approver:dir']);
});
test('AEC06 additive Bundle role verifies real native evidence without becoming a terminal receipt', async () => {
    const corpus = JSON.parse(fs.readFileSync(new URL('../../conformance/vectors/authorization-bundle.v1.json', import.meta.url), 'utf8'));
    const v = corpus.cases.find((c) => c.id === 'valid-two-of-three-oauth-bound-bundle');
    const profile = Object.fromEntries(Object.entries({ audience: v.audience, approverKeys: v.approver_keys, expectedApprovers: v.expected_approvers, acceptedKeyClasses: v.accepted_key_classes, currentPolicy: v.current_policy, expectedAuthorizationInstance: v.expected_authorization_instance, expectedAuthorizationBinding: v.expected_authorization_binding, requireAuthorizationBinding: v.require_authorization_binding, currentStatus: v.current_status, requireCurrentStatus: v.require_current_status }).filter(([, value]) => value !== undefined));
    const config = { requirement: requirement({ expression: 'ep-authorization-bundle', freshness_sec: {}, role_constraints: [], required_bindings: [] }), nativeVerifiers: { 'ep-authorization-bundle': { profile: { id: 'receipts-12-bundle', revision: '1', native_format_revision: 'EP-AUTHORIZATION-BUNDLE-v1' }, trustSnapshot: profile } } };
    const ev = aec.createAuthorizationChainEvaluator(config);
    const chain = { '@version': 'EP-AEC-v1', action: v.expected_action, components: [{ type: 'ep-authorization-bundle', evidence: v.bundle }] };
    const result = await ev.evaluate(chain, { expectedAction: v.expected_action, verificationTime: v.now });
    assert.equal(result.satisfied, true, JSON.stringify(result));
    const terminal = aec.createAuthorizationChainEvaluator({ ...config, requirement: { ...config.requirement, expression: 'ep-receipt' } });
    assert.equal((await terminal.evaluate(chain, { expectedAction: v.expected_action, verificationTime: v.now })).satisfied, false);
});
