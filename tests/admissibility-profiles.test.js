// SPDX-License-Identifier: Apache-2.0
//
// Conformance-style proof for lib/evidence/admissibility-profiles.js.
//
// The load-bearing property: the RELYING PARTY authors and pins the bar; the
// verdict + replay_digest are computed OFFLINE and deterministically against
// THAT pinned profile. Two relying parties with different bars over the SAME
// evidence must reach different, each-reproducible verdicts, and nobody may
// swap the bar under a pinned hash.

import { describe, it, expect } from 'vitest';
import {
  defineAdmissibilityProfile,
  computeProfileHash,
  verifyProfileHash,
  evaluateAdmissibilityProfile,
} from '../lib/evidence/admissibility-profiles.js';
import {
  POLICY_PACKS,
  computePolicyPackHash,
  verifyPolicyPackHash,
} from '../lib/evidence/policy-packs.js';

const NOW = '2026-07-05T12:00:00.000Z';
const nowMs = Date.parse(NOW);
const iso = (msAgo) => new Date(nowMs - msAgo).toISOString();

// ── A single evidence bundle. Two different relying-party profiles below judge
//    this SAME bundle and reach different verdicts. ──────────────────────────
function baseBundle() {
  return {
    items: [
      {
        evidence: 'authorization_receipt',
        digest: 'sha256:aaaa1111',
        signature_valid: true,
        assurance: 'high',
        issued_at: iso(60_000), // 60s old
        revoked: false,
        action_digest: 'sha256:action-x',
      },
      {
        evidence: 'policy_permit',
        digest: 'sha256:bbbb2222',
        signature_valid: true,
        assurance: 'verified',
        issued_at: iso(120_000), // 120s old
        revoked: false,
        action_digest: 'sha256:action-x',
      },
    ],
  };
}

// Relying party A: only needs an authorization_receipt (with revocation check).
const profileA = defineAdmissibilityProfile({
  id: 'ep:admissibility:auth-only:v1',
  authored_by: 'Bank-of-Example Risk (relying party)',
  version: 1,
  requires: [
    { evidence: 'authorization_receipt', min_assurance: 'high', max_staleness_sec: 300, checks: ['revocation_checked'] },
  ],
});

// Relying party B: needs BOTH an authorization_receipt AND a fresh
// execution_attestation. The bundle has no execution_attestation.
const profileB = defineAdmissibilityProfile({
  id: 'ep:admissibility:auth-plus-exec:v1',
  authored_by: 'Clearing-House Settlement (relying party)',
  version: 1,
  requires: [
    { evidence: 'authorization_receipt', min_assurance: 'high', max_staleness_sec: 300, checks: ['revocation_checked'] },
    { evidence: 'execution_attestation', max_staleness_sec: 300 },
  ],
});

describe('profile hashing', () => {
  it('computes a self-verifying profile_hash over JCS(profile) minus profile_hash', () => {
    expect(profileA.profile_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(computeProfileHash(profileA)).toBe(profileA.profile_hash);
    expect(verifyProfileHash(profileA)).toBe(true);
  });

  it('two different bars have different hashes', () => {
    expect(profileA.profile_hash).not.toBe(profileB.profile_hash);
  });

  it('a tampered profile no longer verifies', () => {
    const tampered = { ...profileA, requires: [{ evidence: 'nothing' }] };
    expect(verifyProfileHash(tampered)).toBe(false);
  });
});

describe('SAME bundle, TWO bars -> different verdicts, different digests', () => {
  it('profile A -> admissible; profile B -> missing_evidence; digests DIFFER', () => {
    const bundle = baseBundle();
    const a = evaluateAdmissibilityProfile(profileA, bundle, { now: NOW });
    const b = evaluateAdmissibilityProfile(profileB, bundle, { now: NOW });

    expect(a.verdict).toBe('admissible');
    expect(b.verdict).toBe('missing_evidence');

    // The whole point: different bar -> different replayable digest.
    expect(a.replay_digest).not.toBe(b.replay_digest);
    expect(a.replay_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(b.replay_digest).toMatch(/^sha256:[0-9a-f]{64}$/);

    // B's missing leg is named in the requirement results.
    const execRow = b.requirement_results.find((r) => r.evidence === 'execution_attestation');
    expect(execRow.satisfied).toBe(false);
    expect(execRow.reason).toMatch(/absent/);
  });

  it('each verdict + digest is reproducible across two evaluations (determinism)', () => {
    const a1 = evaluateAdmissibilityProfile(profileA, baseBundle(), { now: NOW });
    const a2 = evaluateAdmissibilityProfile(profileA, baseBundle(), { now: NOW });
    expect(a2.replay_digest).toBe(a1.replay_digest);
    expect(a2.verdict).toBe(a1.verdict);

    const b1 = evaluateAdmissibilityProfile(profileB, baseBundle(), { now: NOW });
    const b2 = evaluateAdmissibilityProfile(profileB, baseBundle(), { now: NOW });
    expect(b2.replay_digest).toBe(b1.replay_digest);
    expect(b2.verdict).toBe(b1.verdict);
  });

  it('evaluated_at is OUTSIDE the digest: different now, same inputs -> same digest when staleness unaffected', () => {
    // Move `now` forward 10s; both items still well within their staleness bounds,
    // so the verdict and consulted-item facts are unchanged -> digest unchanged.
    const a1 = evaluateAdmissibilityProfile(profileA, baseBundle(), { now: NOW });
    const a2 = evaluateAdmissibilityProfile(profileA, baseBundle(), { now: nowMs + 10_000 });
    expect(a2.verdict).toBe(a1.verdict);
    expect(a2.replay_digest).toBe(a1.replay_digest);
    expect(a2.evaluated_at).not.toBe(a1.evaluated_at); // the timestamp itself DID move
  });
});

describe('fail-closed refusals', () => {
  it('profile_hash_mismatch -> REFUSE unverifiable', () => {
    const res = evaluateAdmissibilityProfile(profileA, baseBundle(), {
      now: NOW,
      expectedProfileHash: 'sha256:' + '0'.repeat(64),
    });
    expect(res.verdict).toBe('unverifiable');
    expect(res.refused).toBe(true);
    expect(res.reason).toBe('profile_hash_mismatch');
    expect(res.requirement_results[0].reason).toBe('profile_hash_mismatch');
  });

  it('matching pinned hash proceeds to a normal verdict', () => {
    const res = evaluateAdmissibilityProfile(profileA, baseBundle(), {
      now: NOW,
      expectedProfileHash: profileA.profile_hash,
    });
    expect(res.refused).toBeUndefined();
    expect(res.verdict).toBe('admissible');
  });

  it('a profile whose self-hash was swapped is refused (tamper)', () => {
    const swapped = { ...profileA, profile_hash: 'sha256:' + 'f'.repeat(64) };
    const res = evaluateAdmissibilityProfile(swapped, baseBundle(), { now: NOW });
    expect(res.verdict).toBe('unverifiable');
    expect(res.reason).toBe('profile_self_hash_mismatch');
  });
});

describe('staleness', () => {
  it('a receipt older than max_staleness_sec yields stale', () => {
    const bundle = baseBundle();
    // authorization_receipt now 10 minutes old; profile A allows 300s.
    bundle.items[0].issued_at = iso(600_000);
    const res = evaluateAdmissibilityProfile(profileA, bundle, { now: NOW });
    expect(res.verdict).toBe('stale');
    const row = res.requirement_results.find((r) => r.evidence === 'authorization_receipt');
    expect(row.satisfied).toBe(false);
    expect(row.reason).toMatch(/staler than 300s/);
  });
});

describe('optional requirements', () => {
  const profileOpt = defineAdmissibilityProfile({
    id: 'ep:admissibility:auth-opt-transparency:v1',
    authored_by: 'Auditor (relying party)',
    requires: [
      { evidence: 'authorization_receipt', min_assurance: 'high', max_staleness_sec: 300, checks: ['revocation_checked'] },
      { evidence: 'transparency', optional: true },
    ],
  });

  it('optional-ABSENT stays admissible (no downgrade)', () => {
    const res = evaluateAdmissibilityProfile(profileOpt, baseBundle(), { now: NOW });
    expect(res.verdict).toBe('admissible');
    const t = res.requirement_results.find((r) => r.evidence === 'transparency');
    expect(t.satisfied).toBe(true);
    expect(t.reason).toMatch(/optional requirement absent/);
  });

  it('optional-PRESENT-but-invalid DOWNGRADES (contributes a conflict/unverifiable)', () => {
    const bundle = baseBundle();
    bundle.items.push({
      evidence: 'transparency',
      digest: 'sha256:cccc3333',
      signature_valid: false, // present but its own verification fails
      assurance: 'basic',
      issued_at: iso(30_000),
      revoked: false,
    });
    const res = evaluateAdmissibilityProfile(profileOpt, bundle, { now: NOW });
    // A present-but-invalid item is caught by admissibility.js precedence.
    expect(res.verdict).toBe('unverifiable');
    const t = res.requirement_results.find((r) => r.evidence === 'transparency');
    expect(t.satisfied).toBe(false);
  });
});

describe('revocation check fails closed', () => {
  it('unknown revocation state fails the revocation_checked gate', () => {
    const bundle = baseBundle();
    delete bundle.items[0].revoked; // revocation state never established
    const res = evaluateAdmissibilityProfile(profileA, bundle, { now: NOW });
    expect(res.verdict).toBe('unverifiable');
    const row = res.requirement_results.find((r) => r.evidence === 'authorization_receipt');
    expect(row.reason).toMatch(/revocation state unknown/);
  });

  it('an actively revoked item is caught (conflicted via revoked outcome)', () => {
    const bundle = baseBundle();
    bundle.items[0].revoked = true;
    const res = evaluateAdmissibilityProfile(profileA, bundle, { now: NOW });
    expect(res.verdict).not.toBe('admissible');
  });
});

describe('policy packs are pinnable objects', () => {
  it('every shipped pack carries a self-verifying policy_hash == profile_hash', () => {
    for (const pack of Object.values(POLICY_PACKS)) {
      expect(pack.policy_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(pack.profile_hash).toBe(pack.policy_hash);
      expect(computePolicyPackHash(pack)).toBe(pack.policy_hash);
      expect(verifyPolicyPackHash(pack)).toBe(true);
    }
  });

  it('pack semantics are unchanged by the hash field (requirement/freshness intact)', () => {
    const wire = POLICY_PACKS['ep:pack:wire-transfer:v1'];
    expect(wire.requirement).toBe('authorization_receipt AND policy_permit AND workload_identity');
    expect(wire.freshness_sec.authorization_receipt).toBe(300);
    expect(wire.revocation_required).toEqual(['authorization_receipt']);
  });

  it('computePolicyPackHash on a non-object throws (fail closed)', () => {
    expect(() => computePolicyPackHash(null)).toThrow(/pack must be an object/);
    expect(() => computePolicyPackHash('nope')).toThrow(/pack must be an object/);
  });

  it('verifyPolicyPackHash is false (never throws) for a non-object or a hashless pack', () => {
    // Non-object: the inner computePolicyPackHash throws -> caught -> false.
    expect(verifyPolicyPackHash(null)).toBe(false);
    expect(verifyPolicyPackHash(42)).toBe(false);
    // A pack object with no policy_hash string is simply not verifiable -> false.
    expect(verifyPolicyPackHash({ policy_id: 'ep:x:v1' })).toBe(false);
  });
});

// ── Fail-closed guard coverage. Each test below drives a specific defensive
//    branch to its CORRECT fail-closed outcome (throw / refuse / weakest verdict),
//    never a coverage no-op. ──────────────────────────────────────────────────

describe('defineAdmissibilityProfile — input validation fails closed', () => {
  it('a non-object spec throws', () => {
    expect(() => defineAdmissibilityProfile(null)).toThrow(/spec must be an object/);
    expect(() => defineAdmissibilityProfile('nope')).toThrow(/spec must be an object/);
  });

  it('a missing / blank id throws', () => {
    expect(() => defineAdmissibilityProfile({ authored_by: 'rp', requires: [{ evidence: 'x' }] }))
      .toThrow(/profile id is required/);
    expect(() => defineAdmissibilityProfile({ id: '   ', authored_by: 'rp', requires: [{ evidence: 'x' }] }))
      .toThrow(/profile id is required/);
  });

  it('a missing / blank authored_by throws (EMILIA does not author the bar)', () => {
    expect(() => defineAdmissibilityProfile({ id: 'ep:x:v1', requires: [{ evidence: 'x' }] }))
      .toThrow(/authored_by/);
    expect(() => defineAdmissibilityProfile({ id: 'ep:x:v1', authored_by: '  ', requires: [{ evidence: 'x' }] }))
      .toThrow(/authored_by/);
  });

  it('an empty / non-array requires throws (a bar must require something)', () => {
    expect(() => defineAdmissibilityProfile({ id: 'ep:x:v1', authored_by: 'rp', requires: [] }))
      .toThrow(/at least one requirement/);
    expect(() => defineAdmissibilityProfile({ id: 'ep:x:v1', authored_by: 'rp', requires: 'x' }))
      .toThrow(/at least one requirement/);
  });

  it('a requirement without a non-empty evidence type throws', () => {
    expect(() => defineAdmissibilityProfile({ id: 'ep:x:v1', authored_by: 'rp', requires: [{ min_assurance: 'high' }] }))
      .toThrow(/non-empty `evidence` type/);
    expect(() => defineAdmissibilityProfile({ id: 'ep:x:v1', authored_by: 'rp', requires: [{ evidence: '   ' }] }))
      .toThrow(/non-empty `evidence` type/);
  });

  it('opaque relying-party params are preserved into the profile (and hashed)', () => {
    const p = defineAdmissibilityProfile({
      id: 'ep:x:v1',
      authored_by: 'rp',
      version: 3,
      requires: [{ evidence: 'authorization_receipt', params: { jurisdiction: 'US' } }],
    });
    expect(p.version).toBe(3);
    expect(p.requires[0].params).toEqual({ jurisdiction: 'US' });
    expect(verifyProfileHash(p)).toBe(true);
  });

  it('a non-finite version defaults to 1', () => {
    const p = defineAdmissibilityProfile({
      id: 'ep:x:v1', authored_by: 'rp', version: 'abc',
      requires: [{ evidence: 'authorization_receipt' }],
    });
    expect(p.version).toBe(1);
  });
});

describe('computeProfileHash / assurance ordering — fail closed', () => {
  it('computeProfileHash on a non-object throws', () => {
    expect(() => computeProfileHash(null)).toThrow(/profile must be an object/);
    expect(() => computeProfileHash(42)).toThrow(/profile must be an object/);
  });

  it('an unknown min_assurance floor is UNSATISFIABLE (unknown class is the weakest)', () => {
    const profileUnknownFloor = defineAdmissibilityProfile({
      id: 'ep:admissibility:unknown-floor:v1',
      authored_by: 'rp',
      requires: [{ evidence: 'authorization_receipt', min_assurance: 'ultra_max', checks: ['revocation_checked'] }],
    });
    const res = evaluateAdmissibilityProfile(profileUnknownFloor, baseBundle(), { now: NOW });
    expect(res.verdict).not.toBe('admissible');
    const row = res.requirement_results.find((r) => r.evidence === 'authorization_receipt');
    expect(row.reason).toMatch(/assurance below ultra_max/);
  });

  it('an item whose OWN assurance class is unknown fails a real floor', () => {
    const bundle = baseBundle();
    bundle.items[0].assurance = 'made_up_class'; // rank -1, below any real floor
    const res = evaluateAdmissibilityProfile(profileA, bundle, { now: NOW });
    expect(res.verdict).not.toBe('admissible');
    const row = res.requirement_results.find((r) => r.evidence === 'authorization_receipt');
    expect(row.reason).toMatch(/assurance below high/);
  });
});

describe('resolveRequirement — problem-reason branches and item identity', () => {
  it('a denied item is flagged as a denial (conflicted-class problem)', () => {
    const bundle = baseBundle();
    bundle.items[0].outcome = 'deny';
    const res = evaluateAdmissibilityProfile(profileA, bundle, { now: NOW });
    expect(res.verdict).not.toBe('admissible');
    const row = res.requirement_results.find((r) => r.evidence === 'authorization_receipt');
    expect(row.reason).toMatch(/denial/);
  });

  it('a required non-revocation check that is absent/false fails the item', () => {
    const profileChecked = defineAdmissibilityProfile({
      id: 'ep:admissibility:sig-check:v1',
      authored_by: 'rp',
      requires: [{ evidence: 'authorization_receipt', min_assurance: 'high', checks: ['revocation_checked', 'signature_valid'] }],
    });
    const bundle = baseBundle();
    // item.checks map is absent -> the 'signature_valid' member check is not true.
    const res = evaluateAdmissibilityProfile(profileChecked, bundle, { now: NOW });
    expect(res.verdict).not.toBe('admissible');
    const row = res.requirement_results.find((r) => r.evidence === 'authorization_receipt');
    expect(row.reason).toMatch(/required check failed/);
  });

  it('the member check passes when the item explicitly reports it true', () => {
    const profileChecked = defineAdmissibilityProfile({
      id: 'ep:admissibility:sig-check2:v1',
      authored_by: 'rp',
      requires: [{ evidence: 'authorization_receipt', min_assurance: 'high', checks: ['revocation_checked', 'signature_valid'] }],
    });
    const bundle = baseBundle();
    bundle.items[0].checks = { signature_valid: true };
    const res = evaluateAdmissibilityProfile(profileChecked, bundle, { now: NOW });
    expect(res.verdict).toBe('admissible');
  });

  it('an item with neither digest nor id still resolves (identified by a JCS fingerprint of its fields)', () => {
    // Drop both digest and id -> itemIdentifier() falls through to hashObject().
    // The identity feeds the replay digest, so a valid item still admits and the
    // digest is a stable sha256 (the fingerprint path ran).
    const bundle = {
      items: [{
        evidence: 'authorization_receipt',
        signature_valid: true, assurance: 'high', issued_at: iso(60_000), revoked: false,
        outcome: 'allow',
      }],
    };
    const res = evaluateAdmissibilityProfile(profileA, bundle, { now: NOW });
    expect(res.verdict).toBe('admissible');
    expect(res.replay_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('the item-identity fallbacks are distinct: id-identified vs fingerprint-identified differ in the replay digest', () => {
    // Same decision-relevant fields, but one item carries an explicit `id` and the
    // other does not. itemIdentifier() takes the id for the first and a JCS
    // fingerprint for the second -> different consulted identities -> different digest.
    const withId = {
      items: [{
        evidence: 'authorization_receipt', id: 'item-42',
        signature_valid: true, assurance: 'high', issued_at: iso(60_000), revoked: false,
      }],
    };
    const withoutId = {
      items: [{
        evidence: 'authorization_receipt',
        signature_valid: true, assurance: 'high', issued_at: iso(60_000), revoked: false,
      }],
    };
    const a = evaluateAdmissibilityProfile(profileA, withId, { now: NOW });
    const b = evaluateAdmissibilityProfile(profileA, withoutId, { now: NOW });
    expect(a.verdict).toBe('admissible');
    expect(b.verdict).toBe('admissible');
    expect(a.replay_digest).not.toBe(b.replay_digest);
  });

  it('an item with no issued_at has no derived staleness (never spuriously stale)', () => {
    const bundle = baseBundle();
    delete bundle.items[0].issued_at; // ageSec resolves to null -> not stale
    const res = evaluateAdmissibilityProfile(profileA, bundle, { now: NOW });
    // still admissible (no freshness violation, everything else clears)
    expect(res.verdict).toBe('admissible');
  });
});

describe('findItem — accepts items[] | components[] | a bare array', () => {
  it('finds a requirement item under a `components` array', () => {
    const bundle = {
      components: [{
        evidence: 'authorization_receipt', digest: 'sha256:comp1',
        signature_valid: true, assurance: 'high', issued_at: iso(60_000), revoked: false,
      }],
    };
    const res = evaluateAdmissibilityProfile(profileA, bundle, { now: NOW });
    expect(res.verdict).toBe('admissible');
  });

  it('finds a requirement item in a bare array bundle (by `type` alias)', () => {
    const bundle = [{
      type: 'authorization_receipt', digest: 'sha256:arr1',
      signature_valid: true, assurance: 'high', issued_at: iso(60_000), revoked: false,
    }];
    const res = evaluateAdmissibilityProfile(profileA, bundle, { now: NOW });
    expect(res.verdict).toBe('admissible');
  });
});

describe('evaluateAdmissibilityProfile — top-level refusals fail closed', () => {
  it('an uncanonicalizable profile is refused (profile_uncanonicalizable, null hash)', () => {
    const evil = { requires: [{ evidence: 'x' }] };
    evil.self = evil; // circular -> canonicalize throws inside computeProfileHash
    const res = evaluateAdmissibilityProfile(evil, baseBundle(), { now: NOW });
    expect(res.verdict).toBe('unverifiable');
    expect(res.reason).toBe('profile_uncanonicalizable');
    expect(res.profile_hash).toBeNull();
    expect(res.replay_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(res.requirement_results[0].evidence).toBeNull();
  });

  it('a profile with an empty requires[] is refused (profile_has_no_requirements)', () => {
    // A raw object (bypassing defineAdmissibilityProfile) with a MATCHING self-hash
    // but no requirements: it passes the pin/self-hash checks, then fails closed
    // on the empty-requirements guard.
    const raw = { id: 'ep:x:v1', requires: [] };
    raw.profile_hash = computeProfileHash(raw);
    const res = evaluateAdmissibilityProfile(raw, baseBundle(), { now: NOW });
    expect(res.verdict).toBe('unverifiable');
    expect(res.reason).toBe('profile_has_no_requirements');
    expect(res.refused).toBe(true);
  });

  it('an invalid `now` falls back to a real evaluated_at timestamp', () => {
    const res = evaluateAdmissibilityProfile(profileA, baseBundle(), { now: 'not-a-date' });
    // now is unparseable -> nowMs NaN -> evaluated_at defaults to Date.now().
    expect(res.evaluated_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    // With no finite now, staleness cannot be computed, so no spurious stale.
    const row = res.requirement_results.find((r) => r.evidence === 'authorization_receipt');
    expect(row.reason).not.toMatch(/staler/);
  });
});

describe('only-optional profiles — the vacuous-bar path', () => {
  const profileAllOptional = defineAdmissibilityProfile({
    id: 'ep:admissibility:all-optional:v1',
    authored_by: 'rp',
    requires: [
      { evidence: 'transparency', optional: true },
      { evidence: 'recourse_reference', optional: true },
    ],
  });

  it('every requirement optional-and-absent -> vacuously admissible (empty bar cleared)', () => {
    const res = evaluateAdmissibilityProfile(profileAllOptional, { items: [] }, { now: NOW });
    expect(res.verdict).toBe('admissible');
    // Both optional legs reported satisfied-because-absent.
    for (const row of res.requirement_results) {
      expect(row.satisfied).toBe(true);
      expect(row.reason).toMatch(/optional requirement absent/);
    }
  });

  it('an only-optional profile with a PRESENT-but-invalid optional item is caught (no mandatory bar, present fact judged)', () => {
    const bundle = {
      items: [{
        evidence: 'transparency', digest: 'sha256:opt-bad',
        signature_valid: false, assurance: 'basic', issued_at: iso(30_000), revoked: false,
      }],
    };
    const res = evaluateAdmissibilityProfile(profileAllOptional, bundle, { now: NOW });
    // No mandatory requirements, but a present invalid optional item enters `facts`
    // and is classified by admissibility.js precedence -> not admissible.
    expect(res.verdict).not.toBe('admissible');
  });
});
