// SPDX-License-Identifier: Apache-2.0
// Generated from aec-current-profile.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import * as aec from './dist/evidence-chain.js';
import { canonicalizeStrictJson } from './dist/strict-json.js';
import { EP_PLATFORM_ATTESTATION_COMPONENT, EP_PLATFORM_ATTESTATION_PROFILE, EP_PLATFORM_ATTESTATION_VERSION } from './dist/platform-attestation.js';
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
// The signature check is the VERIFIED result; the pinned issuer and audience
// are ACCEPTED inputs. The two are reported separately (AEC-07 Section 6).
function verify(evidence, context) {
    const key = context.trust_snapshot.public_key;
    if (!crypto.verify(null, Buffer.from(canonicalizeStrictJson(evidence.payload)), key, Buffer.from(evidence.signature, 'base64url')))
        return { verified: false, accepted: false, reason: 'signature_invalid' };
    if (evidence.payload.issuer !== 'issuer:one' || evidence.payload.audience !== 'executor:one')
        return { verified: true, accepted: false, reason: 'native_scope_invalid' };
    return { verified: true, accepted: true, ...evidence.payload };
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
    assert.equal(result.replay.algorithm_revision, 'EP-AEC-EVALUATOR-08-v1');
    for (const fact of result.replay.facts) {
        assert.equal(fact.native_verification, 'VERIFIED');
        assert.equal(fact.acceptance, 'ACCEPTED');
        assert.equal('native_valid' in fact, false, 'the 05 combined field must not survive');
    }
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
    registrations.approval.verify = () => ({ verified: true, accepted: true });
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
    const caid = `canactid:1:payment.release.1:jcs-sha256:${Buffer.alloc(32, 7).toString('base64url')}`;
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
    for (const verify of [() => { throw new Error('secret'); }, () => ({ valid: 'true' }), () => ({ verified: 'true', accepted: true }), () => new Promise(() => { })]) {
        const ev = evaluator(requirement(), { nativeVerifiers: { approval: registration({ verify }), permit: registration() }, limits: { maxVerifierDurationMs: 20 } });
        const result = await ev.evaluate(fixture(), inputs());
        assert.equal(result.satisfied, false);
        assert.ok(!JSON.stringify(result).includes('secret'));
    }
});
test('AEC05 oversized aggregate replay emits a bounded refusal instead of throwing from finish', async () => {
    const subjects = Array.from({ length: 64 }, (_, i) => `subject:${i}:${'x'.repeat(1980)}`);
    const ev = evaluator(requirement({ expression: 'approval', freshness_sec: {}, role_constraints: [], required_bindings: [] }), {
        nativeVerifiers: { approval: registration({ verify: () => ({ verified: true, accepted: true,
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
    assert.equal(result.replay.facts[0].native_verification, 'VERIFIED', JSON.stringify(result));
    assert.equal(result.replay.facts[0].acceptance, 'ACCEPTED', JSON.stringify(result));
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
// ---------------------------------------------------------------------------
// AEC-07: VERIFIED (cryptographic and structural checks) and ACCEPTED (the
// relying party's pinned trust inputs) are separate results in every fact.
// ---------------------------------------------------------------------------
test('AEC07 a verified artifact outside the pinned trust inputs is VERIFIED and not ACCEPTED', async () => {
    const chain = fixture();
    chain.components[1].evidence = signed('person:two', { issuer: 'issuer:unpinned' });
    const result = await evaluator().evaluate(chain, inputs());
    assert.equal(result.satisfied, false, JSON.stringify(result));
    const fact = result.replay.facts[1];
    assert.equal(fact.native_verification, 'VERIFIED');
    assert.equal(fact.acceptance, 'REJECTED');
    assert.deepEqual(fact.reasons, ['native_acceptance_refused']);
    assert.equal(fact.eligible, false);
    assert.deepEqual(fact.subject_ids, [], 'an unaccepted artifact contributes no subject');
});
test('AEC07 a broken signature is not VERIFIED and acceptance is never evaluated', async () => {
    const chain = fixture();
    chain.components[1].evidence.signature = signed('person:three').signature;
    const result = await evaluator().evaluate(chain, inputs());
    assert.equal(result.satisfied, false);
    const fact = result.replay.facts[1];
    assert.equal(fact.native_verification, 'FAILED');
    assert.equal(fact.acceptance, 'NOT_EVALUATED');
    assert.deepEqual(fact.reasons, ['native_verification_failed']);
});
test('AEC07 unaccepted and unverified evidence produce distinguishable replay records', async () => {
    const unaccepted = fixture();
    unaccepted.components[1].evidence = signed('person:two', { audience: 'executor:other' });
    const unverified = fixture();
    unverified.components[1].evidence = { ...signed('person:two', { audience: 'executor:other' }), signature: signed('x').signature };
    const a = await evaluator().evaluate(unaccepted, inputs());
    const b = await evaluator().evaluate(unverified, inputs());
    assert.equal(a.satisfied, false);
    assert.equal(b.satisfied, false);
    assert.notEqual(a.replay_digest, b.replay_digest);
    assert.deepEqual([a.replay.facts[1].native_verification, a.replay.facts[1].acceptance], ['VERIFIED', 'REJECTED']);
    assert.deepEqual([b.replay.facts[1].native_verification, b.replay.facts[1].acceptance], ['FAILED', 'NOT_EVALUATED']);
});
test('AEC07 refuses the 5.x combined valid field, inconsistent results and non-Boolean results by name', async () => {
    const cases = [
        [() => ({ valid: true, format_revision: 'example-signed-v1', action_digest: ACTION }), 'native_result_legacy_valid_field'],
        [() => ({ verified: true, accepted: true, valid: true, format_revision: 'example-signed-v1', action_digest: ACTION }), 'native_result_legacy_valid_field'],
        [() => ({ verified: false, accepted: true, format_revision: 'example-signed-v1', action_digest: ACTION }), 'native_result_inconsistent'],
        [() => ({ verified: 1, accepted: 1, format_revision: 'example-signed-v1', action_digest: ACTION }), 'native_result_shape_invalid'],
        [() => ({ verified: true, format_revision: 'example-signed-v1', action_digest: ACTION }), 'native_result_shape_invalid'],
    ];
    for (const [verify, reason] of cases) {
        const ev = evaluator(requirement({ expression: 'approval', freshness_sec: {}, role_constraints: [], required_bindings: [] }), { nativeVerifiers: { approval: registration({ verify }) } });
        const result = await ev.evaluate({ '@version': 'EP-AEC-v1', action, components: [{ type: 'approval', evidence: {} }] }, inputs());
        assert.equal(result.satisfied, false, reason);
        assert.deepEqual(result.replay.facts[0].reasons, [reason]);
        assert.equal(result.replay.facts[0].native_verification, 'NOT_EVALUATED');
        assert.equal(result.replay.facts[0].acceptance, 'NOT_EVALUATED');
    }
});
test('AEC07 the pinned native format revision is an acceptance check', async () => {
    const chain = fixture();
    chain.components[1].evidence = signed('person:two', { format_revision: 'example-signed-v2' });
    const fact = (await evaluator().evaluate(chain, inputs())).replay.facts[1];
    assert.deepEqual([fact.native_verification, fact.acceptance, fact.reasons], ['VERIFIED', 'REJECTED', ['native_format_revision_mismatch']]);
});
test('AEC07 action mapping never runs on a VERIFIED artifact that is not ACCEPTED', async () => {
    const caid = `canactid:1:payment.release.1:jcs-sha256:${Buffer.alloc(32, 7).toString('base64url')}`;
    let maps = 0;
    const reg = registration({ mapping: { profile: { id: 'mapping:one', revision: '1' }, map: () => { maps++; return { verdict: 'EQUIVALENT_UNDER_PROFILE', caid }; } } });
    const ev = evaluator(requirement({ expression: 'mapped', freshness_sec: {}, role_constraints: [], required_bindings: [] }), { nativeVerifiers: { mapped: reg } });
    const chain = { '@version': 'EP-AEC-v1', action, components: [{ type: 'mapped', evidence: signed('one', { action_digest: null, issuer: 'issuer:unpinned', native_payload: { destination: 'merchant:one' } }) }] };
    const result = await ev.evaluate(chain, { ...inputs(), expectedCaid: caid });
    assert.equal(result.satisfied, false);
    assert.equal(result.replay.facts[0].acceptance, 'REJECTED');
    assert.equal(maps, 0);
});
// A quorum carries its members' public keys, so its integrity is checkable
// without the relying party's directory. An attacker's self-built quorum
// verifies under its own keys and is still not accepted.
function selfSignedQuorumMember(rpId) {
    const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const approver_public_key = kp.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const context = {
        ep_version: '1.0', context_type: 'ep.signoff.v1', action_hash: ACTION,
        policy: 'presenter-policy', nonce: 'n1', approver: 'ep:approver:attacker',
        initiator: 'ep:agent:other', issued_at: '2026-09-06T11:59:00.000Z', expires_at: '2026-09-06T12:05:00.000Z',
    };
    const challenge = crypto.createHash('sha256').update(canonicalizeStrictJson(context), 'utf8').digest().toString('base64url');
    const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: `https://${rpId}` }));
    const authData = Buffer.concat([crypto.createHash('sha256').update(rpId).digest(), Buffer.from([0x05, 0, 0, 0, 0])]);
    const signedBytes = Buffer.concat([authData, crypto.createHash('sha256').update(clientData).digest()]);
    return { role: 'a', approver_public_key, signoff: { '@type': 'ep.signoff.webauthn', context, webauthn: {
                authenticator_data: authData.toString('base64url'), client_data_json: clientData.toString('base64url'),
                signature: crypto.sign('sha256', signedBytes, kp.privateKey).toString('base64url')
            } } };
}
test('AEC07 built-in ep-quorum: an attacker quorum is VERIFIED under its carried keys and not ACCEPTED', async () => {
    const quorum = { '@type': 'ep.quorum', action_hash: ACTION,
        policy: { mode: 'threshold', required: 1, distinct_humans: true, window_sec: 3600, approvers: [{ role: 'a', approver: 'ep:approver:attacker' }] },
        members: [selfSignedQuorumMember('attacker.example')] };
    const pinned = {
        policy: { mode: 'threshold', required: 2, distinct_humans: true, window_sec: 3600,
            approvers: [{ role: 'a', approver: 'ep:approver:one' }, { role: 'b', approver: 'ep:approver:two' }] },
        rp_id: 'rp.example', context_policy: 'pinned-policy', allowed_origins: ['https://rp.example'],
        max_age_sec: 300, registry_checked_at: '2026-09-06T11:59:30Z', max_registry_age_sec: 300, approvers: {},
    };
    const ev = aec.createAuthorizationChainEvaluator({
        requirement: requirement({ expression: 'ep-quorum', freshness_sec: {}, role_constraints: [], required_bindings: [] }),
        nativeVerifiers: { 'ep-quorum': { profile: { id: 'native-quorum', revision: '1', native_format_revision: 'EP-QUORUM-v1' }, trustSnapshot: { policy: pinned } } },
    });
    const chain = { '@version': 'EP-AEC-v1', action, components: [{ type: 'ep-quorum', evidence: quorum }] };
    const good = await ev.evaluate(chain, inputs());
    assert.equal(good.satisfied, false);
    assert.deepEqual([good.replay.facts[0].native_verification, good.replay.facts[0].acceptance], ['VERIFIED', 'REJECTED']);
    const tampered = structuredClone(chain);
    tampered.components[0].evidence.members[0].signoff.context.nonce = 'n2';
    const bad = await ev.evaluate(tampered, inputs());
    assert.deepEqual([bad.replay.facts[0].native_verification, bad.replay.facts[0].acceptance], ['FAILED', 'NOT_EVALUATED']);
});
test('AEC07 built-in ep-receipt: a pin mismatch is VERIFIED and not ACCEPTED; a broken signature is not VERIFIED', async () => {
    const corpus = JSON.parse(fs.readFileSync(new URL('../../conformance/vectors/aec-role.v1.json', import.meta.url), 'utf8'));
    const v = corpus.vectors.find((c) => c.id === 'accept_pinned_human_receipt');
    const run = async (profile, chain) => {
        const ev = aec.createAuthorizationChainEvaluator({
            requirement: requirement({ expression: 'ep-receipt', freshness_sec: {}, role_constraints: [], required_bindings: [] }),
            nativeVerifiers: { 'ep-receipt': { profile: { id: 'native-receipt', revision: '1', native_format_revision: 'Trust-Receipt' }, trustSnapshot: { policy: profile } } },
        });
        return ev.evaluate(chain, { expectedAction: v.aec_chain.action, verificationTime: v.verification_time });
    };
    const base = await run(v.policies_by_type['ep-receipt'], v.aec_chain);
    assert.equal(base.satisfied, true, JSON.stringify(base));
    assert.deepEqual([base.replay.facts[0].native_verification, base.replay.facts[0].acceptance], ['VERIFIED', 'ACCEPTED']);
    const wrongOrigin = await run({ ...v.policies_by_type['ep-receipt'], allowed_origins: ['https://other.example'] }, v.aec_chain);
    assert.equal(wrongOrigin.satisfied, false);
    assert.deepEqual([wrongOrigin.replay.facts[0].native_verification, wrongOrigin.replay.facts[0].acceptance], ['VERIFIED', 'REJECTED']);
    const wrongRp = await run({ ...v.policies_by_type['ep-receipt'], rp_id: 'other.example' }, v.aec_chain);
    assert.deepEqual([wrongRp.replay.facts[0].native_verification, wrongRp.replay.facts[0].acceptance], ['VERIFIED', 'REJECTED']);
    const broken = structuredClone(v.aec_chain);
    const sig = broken.components[0].evidence.signoffs[0].webauthn.signature;
    broken.components[0].evidence.signoffs[0].webauthn.signature = (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1);
    const refused = await run(v.policies_by_type['ep-receipt'], broken);
    assert.equal(refused.satisfied, false);
    assert.deepEqual([refused.replay.facts[0].native_verification, refused.replay.facts[0].acceptance], ['FAILED', 'NOT_EVALUATED']);
});
test('AEC07 built-in ep-authorization-bundle: a different pinned audience is VERIFIED and not ACCEPTED', async () => {
    const corpus = JSON.parse(fs.readFileSync(new URL('../../conformance/vectors/authorization-bundle.v1.json', import.meta.url), 'utf8'));
    const v = corpus.cases.find((c) => c.id === 'valid-two-of-three-oauth-bound-bundle');
    const profile = (audience) => Object.fromEntries(Object.entries({ audience, approverKeys: v.approver_keys, expectedApprovers: v.expected_approvers, acceptedKeyClasses: v.accepted_key_classes, currentPolicy: v.current_policy, expectedAuthorizationInstance: v.expected_authorization_instance, expectedAuthorizationBinding: v.expected_authorization_binding, requireAuthorizationBinding: v.require_authorization_binding, currentStatus: v.current_status, requireCurrentStatus: v.require_current_status }).filter(([, value]) => value !== undefined));
    const run = (audience) => aec.createAuthorizationChainEvaluator({
        requirement: requirement({ expression: 'ep-authorization-bundle', freshness_sec: {}, role_constraints: [], required_bindings: [] }),
        nativeVerifiers: { 'ep-authorization-bundle': { profile: { id: 'receipts-13-bundle', revision: '1', native_format_revision: 'EP-AUTHORIZATION-BUNDLE-v1' }, trustSnapshot: profile(audience) } },
    }).evaluate({ '@version': 'EP-AEC-v1', action: v.expected_action, components: [{ type: 'ep-authorization-bundle', evidence: v.bundle }] }, { expectedAction: v.expected_action, verificationTime: v.now });
    const base = await run(v.audience);
    assert.deepEqual([base.satisfied, base.replay.facts[0].native_verification, base.replay.facts[0].acceptance], [true, 'VERIFIED', 'ACCEPTED']);
    const other = await run('https://other-audience.example');
    assert.deepEqual([other.satisfied, other.replay.facts[0].native_verification, other.replay.facts[0].acceptance], [false, 'VERIFIED', 'REJECTED']);
});
test('AEC07 built-in platform attestation: a claim-pin mismatch is VERIFIED and not ACCEPTED; a wrong key is FAILED; an unknown key is NOT_EVALUATED; another action is not MATCH', async () => {
    const issuer = 'https://attestation.example/verifiers/primary';
    const audience = 'https://gate.example/authorize';
    const kid = 'platform-attester-2026-09';
    const nonce = 'R4ndomGateNonce-20260906';
    const measurement = `sha256:${'b'.repeat(64)}`;
    const attester = crypto.generateKeyPairSync('ed25519');
    const substitute = crypto.generateKeyPairSync('ed25519');
    const nowSeconds = Date.parse(NOW) / 1000;
    const token = (key = attester.privateKey, headerKid = kid, actionDigest = ACTION) => {
        const enc = (v) => Buffer.from(JSON.stringify(v), 'utf8').toString('base64url');
        const input = `${enc({ alg: 'EdDSA', kid: headerKid, typ: 'eat+jwt' })}.${enc({
            iss: issuer, aud: audience, iat: nowSeconds - 30, exp: nowSeconds + 90, eat_nonce: nonce,
            eat_profile: EP_PLATFORM_ATTESTATION_PROFILE, measres: [['ep-build', [[measurement, 'success']]]],
            ep_action_digest: actionDigest
        })}`;
        return { '@version': EP_PLATFORM_ATTESTATION_VERSION, token: `${input}.${crypto.sign(null, Buffer.from(input, 'ascii'), key).toString('base64url')}` };
    };
    const trust = (expectedAudience = audience) => ({
        keys: { [issuer]: { [kid]: attester.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url') } },
        policy: { expected_profile: EP_PLATFORM_ATTESTATION_PROFILE, expected_audience: expectedAudience, expected_nonce: nonce,
            reference_measurements: [measurement], max_age_sec: 120 },
    });
    const run = (evidence, trustSnapshot) => aec.createAuthorizationChainEvaluator({
        requirement: requirement({ expression: EP_PLATFORM_ATTESTATION_COMPONENT, freshness_sec: {}, role_constraints: [], required_bindings: [] }),
        nativeVerifiers: { [EP_PLATFORM_ATTESTATION_COMPONENT]: { profile: { id: 'native-platform', revision: '1', native_format_revision: EP_PLATFORM_ATTESTATION_VERSION }, trustSnapshot } },
    }).evaluate({ '@version': 'EP-AEC-v1', action, components: [{ type: EP_PLATFORM_ATTESTATION_COMPONENT, evidence }] }, inputs());
    const pair = (r) => [r.satisfied, r.replay.facts[0].native_verification, r.replay.facts[0].acceptance];
    assert.deepEqual(pair(await run(token(), trust())), [true, 'VERIFIED', 'ACCEPTED']);
    assert.deepEqual(pair(await run(token(), trust('https://other.example/authorize'))), [false, 'VERIFIED', 'REJECTED']);
    assert.deepEqual(pair(await run(token(substitute.privateKey), trust())), [false, 'FAILED', 'NOT_EVALUATED']);
    // An attester key id the relying party cannot resolve: VERIFIED was never
    // evaluated, so the record differs from the forged-signature record above.
    const unknown = await run(token(attester.privateKey, 'unknown-kid'), trust());
    assert.deepEqual(pair(unknown), [false, 'NOT_EVALUATED', 'NOT_EVALUATED']);
    assert.deepEqual(unknown.replay.facts[0].reasons, ['native_key_unresolved']);
    // A trusted token for another action is VERIFIED and ACCEPTED, and fails MATCH.
    const elsewhere = await run(token(attester.privateKey, kid, digest({ ...action, amount: 999 })), trust());
    assert.deepEqual([...pair(elsewhere), elsewhere.replay.facts[0].mapping_verdict, elsewhere.replay.facts[0].reasons], [false, 'VERIFIED', 'ACCEPTED', 'NOT_EQUIVALENT', ['material_action_not_matched']]);
});
test('AEC07 built-in ep-receipt: an unresolvable key id is NOT_EVALUATED; directory status of a resolved key is an ACCEPTED input', async () => {
    const corpus = JSON.parse(fs.readFileSync(new URL('../../conformance/vectors/aec-role.v1.json', import.meta.url), 'utf8'));
    const v = corpus.vectors.find((c) => c.id === 'accept_pinned_human_receipt');
    const base = v.policies_by_type['ep-receipt'];
    const keyId = v.aec_chain.components[0].evidence.signoffs[0].approver_key_id;
    const run = async (profile) => aec.createAuthorizationChainEvaluator({
        requirement: requirement({ expression: 'ep-receipt', freshness_sec: {}, role_constraints: [], required_bindings: [] }),
        nativeVerifiers: { 'ep-receipt': { profile: { id: 'native-receipt', revision: '1', native_format_revision: 'Trust-Receipt' }, trustSnapshot: { policy: profile } } },
    }).evaluate(v.aec_chain, { expectedAction: v.aec_chain.action, verificationTime: v.verification_time });
    const fact = (r) => [r.satisfied, r.replay.facts[0].native_verification, r.replay.facts[0].acceptance, r.replay.facts[0].reasons];
    const withEntry = (patch) => ({ ...base, approver_keys: { ...base.approver_keys, [keyId]: { ...base.approver_keys[keyId], ...patch } } });
    const { [keyId]: _dropped, ...rest } = base.approver_keys;
    assert.deepEqual(fact(await run({ ...base, approver_keys: { ...rest, 'ep:key:other#1': base.approver_keys[keyId] } })), [false, 'NOT_EVALUATED', 'NOT_EVALUATED', ['native_key_unresolved']]);
    assert.deepEqual(fact(await run(withEntry({ compromised_at: '2026-01-02T00:00:00Z' }))), [false, 'VERIFIED', 'REJECTED', ['native_acceptance_refused']]);
    assert.deepEqual(fact(await run(withEntry({ valid_to: '2026-01-02T00:00:00Z' }))), [false, 'VERIFIED', 'REJECTED', ['native_acceptance_refused']]);
    assert.deepEqual(fact(await run(withEntry({ key_class: 'B' }))), [false, 'VERIFIED', 'REJECTED', ['native_acceptance_refused']]);
    assert.deepEqual(fact(await run(withEntry({ approver_id: 'ep:approver:someone-else' }))), [false, 'VERIFIED', 'REJECTED', ['native_acceptance_refused']]);
});
test('AEC07 built-in ep-authorization-bundle: unresolvable key is NOT_EVALUATED, key status is ACCEPTED, and another action is VERIFIED, ACCEPTED and not MATCH', async () => {
    const corpus = JSON.parse(fs.readFileSync(new URL('../../conformance/vectors/authorization-bundle.v1.json', import.meta.url), 'utf8'));
    const v = corpus.cases.find((c) => c.id === 'valid-two-of-three-oauth-bound-bundle');
    const profile = (keys) => Object.fromEntries(Object.entries({ audience: v.audience, approverKeys: keys, expectedApprovers: v.expected_approvers, acceptedKeyClasses: v.accepted_key_classes, currentPolicy: v.current_policy, expectedAuthorizationInstance: v.expected_authorization_instance, expectedAuthorizationBinding: v.expected_authorization_binding, requireAuthorizationBinding: v.require_authorization_binding, currentStatus: v.current_status, requireCurrentStatus: v.require_current_status }).filter(([, value]) => value !== undefined));
    const run = (keys, expected = v.expected_action) => aec.createAuthorizationChainEvaluator({
        requirement: requirement({ expression: 'ep-authorization-bundle', freshness_sec: {}, role_constraints: [], required_bindings: [] }),
        nativeVerifiers: { 'ep-authorization-bundle': { profile: { id: 'receipts-13-bundle', revision: '1', native_format_revision: 'EP-AUTHORIZATION-BUNDLE-v1' }, trustSnapshot: profile(keys) } },
    }).evaluate({ '@version': 'EP-AEC-v1', action: expected, components: [{ type: 'ep-authorization-bundle', evidence: v.bundle }] }, { expectedAction: expected, verificationTime: v.now });
    const fact = (r) => [r.satisfied, r.replay.facts[0].native_verification, r.replay.facts[0].acceptance, r.replay.facts[0].mapping_verdict, r.replay.facts[0].reasons];
    const signer = v.bundle.signoffs[0].approver_key_id;
    const { [signer]: _dropped, ...rest } = v.approver_keys;
    assert.deepEqual(fact(await run(rest)), [false, 'NOT_EVALUATED', 'NOT_EVALUATED', 'INDETERMINATE', ['native_key_unresolved']]);
    const compromised = { ...v.approver_keys, [signer]: { ...v.approver_keys[signer], compromised_at: '2026-01-02T00:00:00Z' } };
    assert.deepEqual(fact(await run(compromised)), [false, 'VERIFIED', 'REJECTED', 'INDETERMINATE', ['native_acceptance_refused']]);
    const forged = structuredClone(v.bundle);
    const sig = forged.signoffs[0].signature;
    forged.signoffs[0].signature = (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1);
    const forgedResult = await aec.createAuthorizationChainEvaluator({
        requirement: requirement({ expression: 'ep-authorization-bundle', freshness_sec: {}, role_constraints: [], required_bindings: [] }),
        nativeVerifiers: { 'ep-authorization-bundle': { profile: { id: 'receipts-13-bundle', revision: '1', native_format_revision: 'EP-AUTHORIZATION-BUNDLE-v1' }, trustSnapshot: profile(v.approver_keys) } },
    }).evaluate({ '@version': 'EP-AEC-v1', action: v.expected_action, components: [{ type: 'ep-authorization-bundle', evidence: forged }] }, { expectedAction: v.expected_action, verificationTime: v.now });
    assert.deepEqual(fact(forgedResult), [false, 'FAILED', 'NOT_EVALUATED', 'INDETERMINATE', ['native_verification_failed']]);
    const other = structuredClone(v.expected_action);
    other.action_type = `${other.action_type}.other`;
    assert.deepEqual(fact(await run(v.approver_keys, other)), [false, 'VERIFIED', 'ACCEPTED', 'NOT_EQUIVALENT', ['material_action_not_matched']]);
    // A Class A signoff with no Class A verifier configured: the signature
    // check could not run, so VERIFIED is NOT_EVALUATED rather than FAILED.
    const classA = structuredClone(v.bundle);
    classA.signoffs[0].key_class = 'A';
    const unavailable = await aec.createAuthorizationChainEvaluator({
        requirement: requirement({ expression: 'ep-authorization-bundle', freshness_sec: {}, role_constraints: [], required_bindings: [] }),
        nativeVerifiers: { 'ep-authorization-bundle': { profile: { id: 'receipts-13-bundle', revision: '1', native_format_revision: 'EP-AUTHORIZATION-BUNDLE-v1' },
                trustSnapshot: profile({ ...v.approver_keys, [signer]: { ...v.approver_keys[signer], key_class: 'A' } }) } },
    }).evaluate({ '@version': 'EP-AEC-v1', action: v.expected_action, components: [{ type: 'ep-authorization-bundle', evidence: classA }] }, { expectedAction: v.expected_action, verificationTime: v.now });
    assert.deepEqual(fact(unavailable), [false, 'NOT_EVALUATED', 'NOT_EVALUATED', 'INDETERMINATE', ['native_verification_not_evaluated']]);
});
test('AEC07 a native result that could not evaluate VERIFIED is NOT_EVALUATED, never FAILED', async () => {
    const cases = [
        [() => ({ verified: null, accepted: false, reason: 'key_unresolved' }), 'native_key_unresolved'],
        [() => ({ verified: null, accepted: false }), 'native_verification_not_evaluated'],
        [() => ({ verified: null, accepted: true, format_revision: 'example-signed-v1', action_digest: ACTION }), 'native_result_inconsistent'],
        [() => ({ verified: true, accepted: true, format_revision: 'example-signed-v1', action_digest: 'not-a-digest' }), 'native_fact_shape_invalid'],
        [() => ({ verified: true, accepted: true, format_revision: 'example-signed-v1', action_digest: ACTION, subject_ids: [7] }), 'native_fact_shape_invalid'],
    ];
    for (const [verify, reason] of cases) {
        const ev = evaluator(requirement({ expression: 'approval', freshness_sec: {}, role_constraints: [], required_bindings: [] }), { nativeVerifiers: { approval: registration({ verify }) } });
        const fact = (await ev.evaluate({ '@version': 'EP-AEC-v1', action, components: [{ type: 'approval', evidence: {} }] }, inputs())).replay.facts[0];
        assert.deepEqual([fact.native_verification, fact.acceptance, fact.reasons, fact.eligible], ['NOT_EVALUATED', 'NOT_EVALUATED', [reason], false], reason);
    }
});
