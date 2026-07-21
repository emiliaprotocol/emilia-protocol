// SPDX-License-Identifier: Apache-2.0
// Generated from admissibility-profile.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// Admissibility-profile PINNING at the Gate (architecture choice (b)): the Gate
// does NOT re-evaluate raw evidence and does NOT define the bar. The relying
// party's own evaluator (lib/evidence/admissibility-profiles.js) computes the
// verdict OFFLINE against ITS pinned profile and produces a reliance packet; the
// Gate only CHECKS that the presented packet's profile_hash equals the hash the
// relying party pinned AND the verdict is exactly 'admissible'. Fail-closed:
// mismatched hash, non-admissible verdict, missing/unrecognized verdict, and a
// pin with no presented packet all refuse. No profile pinned => byte-for-byte
// unchanged behavior.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createTrustedActionFirewall, createEg1Harness, buildReliancePacket, verifyAdmissibilityAgainstPinnedProfile, ADMISSIBILITY_VERDICTS, EG1_DEFAULT_SELECTOR, } from './index.js';
// A stand-in for the relying party's evaluator output. In production this is
// produced by lib/evidence/admissibility-profiles.js against the pinned profile;
// the Gate only ever sees this pre-computed block, never raw evidence.
function admissibilityBlock({ profileHash, verdict = 'admissible' } = {}) {
    return {
        admissibility_profile: { id: 'ep:profile:reliance-test', version: '1' },
        profile_hash: profileHash,
        verdict,
        replay_digest: 'sha256:deadbeef',
        challenge_id: 'chal-1',
    };
}
const PINNED_HASH = 'sha256:' + 'a'.repeat(64);
const OTHER_HASH = 'sha256:' + 'b'.repeat(64);
function gateTrustingHarness(harness, { verifyAdmissibilityPacket = async ({ presented }) => presented } = {}) {
    return createTrustedActionFirewall({
        trustedKeys: [harness.publicKey],
        approverKeys: harness.approverKeys,
        rpId: harness.rpId,
        allowedOrigins: harness.allowedOrigins,
        verifyAdmissibilityPacket,
        allowEphemeralStore: true,
    });
}
// ── The four required scenarios, driven end-to-end through gate.run(). ──
test('pinned profile + admissible packet with MATCHING hash => allowed', async () => {
    const harness = createEg1Harness();
    const gate = gateTrustingHarness(harness);
    const receipt = harness.mint(); // valid class_a receipt
    const out = await gate.run({
        selector: EG1_DEFAULT_SELECTOR,
        receipt,
        observedAction: harness.action,
        admissibilityProfile: { id: 'ep:profile:reliance-test', profile_hash: PINNED_HASH },
        admissibility: admissibilityBlock({ profileHash: PINNED_HASH, verdict: 'admissible' }),
    }, async () => ({ ran: true }));
    assert.equal(out.ok, true, JSON.stringify(out.authorization?.reason));
    assert.equal(out.authorization.allow, true);
    assert.equal(out.authorization.reason, 'allow');
    // The reliance packet embeds the admissible verdict and reads as rely.
    assert.equal(out.packet.verdict, 'rely');
    assert.equal(out.packet.admissibility.admissible, true);
    assert.equal(out.packet.admissibility.profile_hash, PINNED_HASH);
    assert.equal(out.packet.summary.admissibility_verdict, 'admissible');
});
test('a presenter cannot self-assert an admissible verdict without a trusted evaluator', async () => {
    const harness = createEg1Harness();
    const gate = gateTrustingHarness(harness, { verifyAdmissibilityPacket: null });
    const out = await gate.run({
        selector: EG1_DEFAULT_SELECTOR,
        receipt: harness.mint(),
        observedAction: harness.action,
        admissibilityProfile: { id: 'ep:profile:reliance-test', profile_hash: PINNED_HASH },
        admissibility: admissibilityBlock({ profileHash: PINNED_HASH, verdict: 'admissible' }),
    }, async () => ({ ran: true }));
    assert.equal(out.ok, false);
    assert.equal(out.authorization.reason, 'admissibility_verifier_required');
});
test('pinned profile + MISMATCHED hash => refused (profile_hash_mismatch), receipt NOT consumed', async () => {
    const harness = createEg1Harness();
    const gate = gateTrustingHarness(harness);
    const receipt = harness.mint();
    const out = await gate.run({
        selector: EG1_DEFAULT_SELECTOR,
        receipt,
        observedAction: harness.action,
        admissibilityProfile: { id: 'ep:profile:reliance-test', profile_hash: PINNED_HASH },
        admissibility: admissibilityBlock({ profileHash: OTHER_HASH, verdict: 'admissible' }),
    }, async () => ({ ran: true }));
    assert.equal(out.ok, false);
    assert.equal(out.authorization.allow, false);
    assert.equal(out.authorization.reason, 'profile_hash_mismatch');
    assert.equal(out.authorization.status, 428);
    // The mismatch is checked BEFORE consumption, so the receipt is still fresh and
    // a corrected packet can be retried on the SAME receipt.
    const retry = await gate.run({
        selector: EG1_DEFAULT_SELECTOR,
        receipt,
        observedAction: harness.action,
        admissibilityProfile: { id: 'ep:profile:reliance-test', profile_hash: PINNED_HASH },
        admissibility: admissibilityBlock({ profileHash: PINNED_HASH, verdict: 'admissible' }),
    }, async () => ({ ran: true }));
    assert.equal(retry.ok, true, 'a hash mismatch must not burn the receipt');
});
test('pinned profile + NON-ADMISSIBLE verdict => refused (verdict named)', async () => {
    const harness = createEg1Harness();
    const gate = gateTrustingHarness(harness);
    for (const verdict of ['missing_evidence', 'stale', 'conflicted', 'unverifiable']) {
        const out = await gate.run({
            selector: EG1_DEFAULT_SELECTOR,
            receipt: harness.mint(),
            observedAction: harness.action,
            admissibilityProfile: { id: 'ep:profile:reliance-test', profile_hash: PINNED_HASH },
            admissibility: admissibilityBlock({ profileHash: PINNED_HASH, verdict }),
        }, async () => ({ ran: true }));
        assert.equal(out.ok, false, `verdict ${verdict} must refuse`);
        assert.equal(out.authorization.reason, `admissibility_not_admissible:${verdict}`);
    }
});
test('NO profile pinned => behavior byte-for-byte unchanged (allowed, no admissibility gating)', async () => {
    const harness = createEg1Harness();
    // Same receipt, same selector, run through two independent gates: one with a
    // pinned admissibility profile absent (this test), one is the pristine baseline.
    const gateA = gateTrustingHarness(harness);
    const receiptA = harness.mint();
    const withoutProfile = await gateA.run({ selector: EG1_DEFAULT_SELECTOR, receipt: receiptA, observedAction: harness.action }, async () => ({ ran: true }));
    assert.equal(withoutProfile.ok, true);
    assert.equal(withoutProfile.authorization.reason, 'allow');
    // No admissibility block was presented, so the decision carries none and the
    // reliance packet's admissibility gate is inert (null), not a failure.
    assert.equal(withoutProfile.authorization.evidence?.admissibility ?? null, null);
    assert.equal(withoutProfile.packet.admissibility, null);
    assert.equal(withoutProfile.packet.verdict, 'rely');
    // The admissibility check surfaces as null (not-applicable), never false.
    const admCheck = withoutProfile.packet.checks.find((c) => c.id === 'admissibility_verdict_admissible');
    assert.equal(admCheck.ok, null);
    // Prove equivalence to the pre-admissibility contract: a gate check with no
    // admissibility args produces the identical allow reason and packet verdict.
    const gateB = gateTrustingHarness(harness);
    const receiptB = harness.mint();
    const baseline = await gateB.run({ selector: EG1_DEFAULT_SELECTOR, receipt: receiptB, observedAction: harness.action }, async () => ({ ran: true }));
    assert.equal(baseline.authorization.reason, withoutProfile.authorization.reason);
    assert.equal(baseline.packet.verdict, withoutProfile.packet.verdict);
});
// ── Pure verifier unit coverage (the gate's only admissibility primitive). ──
test('verifyAdmissibilityAgainstPinnedProfile: matching hash + admissible => ok', () => {
    const r = verifyAdmissibilityAgainstPinnedProfile({ id: 'p', profile_hash: PINNED_HASH }, { admissibility: admissibilityBlock({ profileHash: PINNED_HASH }) });
    assert.equal(r.ok, true);
    assert.equal(r.reason, null);
    assert.equal(r.verdict, 'admissible');
});
test('verifyAdmissibilityAgainstPinnedProfile: fail-closed refusals are distinct and named', () => {
    const pin = { id: 'p', profile_hash: PINNED_HASH };
    // mismatched hash
    assert.equal(verifyAdmissibilityAgainstPinnedProfile(pin, admissibilityBlock({ profileHash: OTHER_HASH })).reason, 'profile_hash_mismatch');
    // non-admissible verdict names the verdict
    assert.equal(verifyAdmissibilityAgainstPinnedProfile(pin, admissibilityBlock({ profileHash: PINNED_HASH, verdict: 'stale' })).reason, 'admissibility_not_admissible:stale');
    // unrecognized verdict (outside the closed set) refuses, never passes
    assert.equal(verifyAdmissibilityAgainstPinnedProfile(pin, admissibilityBlock({ profileHash: PINNED_HASH, verdict: 'looks_fine' })).reason, 'admissibility_verdict_unrecognized');
    // pin present but NOTHING presented => refuse
    assert.equal(verifyAdmissibilityAgainstPinnedProfile(pin, null).reason, 'admissibility_profile_pinned_but_absent');
    // a pin with no hash is a misconfiguration => refuse, never silently pass
    assert.equal(verifyAdmissibilityAgainstPinnedProfile({ id: 'p' }, admissibilityBlock({ profileHash: PINNED_HASH })).reason, 'pinned_profile_missing_hash');
});
test('closed verdict set is exactly the five admissibility verdicts', () => {
    assert.deepEqual([...ADMISSIBILITY_VERDICTS].sort(), ['admissible', 'conflicted', 'missing_evidence', 'stale', 'unverifiable'].sort());
});
test('buildReliancePacket fails closed: a non-admissible block can never read as rely', async () => {
    const decision = { allow: true, reason: 'allow', action: 'x', evidence: { hash: 'h', receipt_id: 'r' } };
    const packet = await buildReliancePacket({
        decision,
        admissibility: admissibilityBlock({ profileHash: PINNED_HASH, verdict: 'conflicted' }),
    });
    assert.equal(packet.verdict, 'do_not_rely');
    assert.equal(packet.admissibility.admissible, false);
    // And a bare/malformed block (no verdict) is also non-admissible, not a pass.
    const bare = await buildReliancePacket({ decision, admissibility: { profile_hash: PINNED_HASH } });
    assert.equal(bare.verdict, 'do_not_rely');
    assert.equal(bare.admissibility.admissible, false);
});
