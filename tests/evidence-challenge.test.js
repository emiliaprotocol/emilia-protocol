// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';
import {
  CHALLENGE_VERSION, createEvidenceChallenge, createFollowupEvidenceChallenge,
  evaluatePresentation, deriveRequiredEvidence,
} from '../lib/negotiate/evidence-challenge.js';
import { EVIDENCE_GRAPH_VERSION, artifactDigest } from '../lib/evidence/evidence-graph.js';
import { getPolicyPack } from '../lib/evidence/policy-packs.js';

const policy = getPolicyPack('ep:pack:wire-transfer:v1');
const ACTION = { type: 'urn:ep:action:payments.wire_transfer', amount: '250000.00', currency: 'USD' };
const AS_OF = '2026-07-03T12:01:00Z';
const EXPIRES = '2026-07-03T12:10:00Z';

const mk = (type, extra = {}) => ({ typ: type, action: artifactDigest(ACTION), issued_at: '2026-07-03T12:00:00Z', ...extra });
const verifiers = {
  authorization_receipt: (a) => ({ valid: true, action_digest: a.action, issued_at: a.issued_at, revoked: false }),
  policy_permit: (a) => ({ valid: true, action_digest: a.action, issued_at: a.issued_at }),
  workload_identity: (a) => ({ valid: true, action_digest: a.action, issued_at: a.issued_at }),
};

function graphFor(types, overrides = {}) {
  const arts = types.map((t) => mk(t, overrides[t] ?? {}));
  const auth = arts.find((a) => a.typ === 'authorization_receipt');
  const nodes = arts.map((a) => ({ id: artifactDigest(a), type: a.typ, artifact: a }));
  const edges = [];
  const permit = arts.find((a) => a.typ === 'policy_permit');
  if (permit && auth) {
    permit.permits_receipt = artifactDigest(auth);
    const pid = nodes.find((n) => n.type === 'policy_permit');
    pid.id = artifactDigest(permit); pid.artifact = permit;
    edges.push({ from: pid.id, rel: 'permits', to: artifactDigest(auth) });
  }
  return { '@version': EVIDENCE_GRAPH_VERSION, action_digest: artifactDigest(ACTION), nodes, edges };
}

describe('AE-CHALLENGE — the negotiation loop', () => {
  it('derives the go-get list from the policy, with freshness and revocation flags', () => {
    const req = deriveRequiredEvidence(policy);
    const types = req.map((r) => r.type);
    expect(types).toContain('authorization_receipt');
    expect(types).toContain('policy_permit');
    expect(types).toContain('workload_identity');
    expect(req.find((r) => r.type === 'authorization_receipt').fresh_max_sec).toBe(300);
    expect(req.find((r) => r.type === 'authorization_receipt').revocation_checked).toBe(true);
  });

  it('carries per-type assurance constraints when the policy supplies them', () => {
    const req = deriveRequiredEvidence({
      ...policy,
      required_assurance: { authorization_receipt: 'class_a' },
    });
    expect(req.find((r) => r.type === 'authorization_receipt').assurance_class).toBe('class_a');
    expect(req.find((r) => r.type === 'policy_permit').assurance_class).toBeUndefined();
  });

  it('the full circuit: challenge -> partial present -> next_challenge lists ONLY the missing -> complete present -> admissible', () => {
    const nonces = new Set();
    const ch = createEvidenceChallenge(ACTION, policy, { expires_at: EXPIRES, nonce: 'n1' });
    expect(ch['@version']).toBe(CHALLENGE_VERSION);
    expect(ch.action_digest).toBe(artifactDigest(ACTION));

    const partial = evaluatePresentation(ch, graphFor(['authorization_receipt']), policy,
      { verifiers, as_of: AS_OF, consumedNonces: nonces, nonce: 'n2' });
    expect(partial.verdict).toBe('missing_evidence');
    const missing = partial.next_challenge.required_evidence.map((r) => r.type);
    expect(missing).toContain('policy_permit');
    expect(missing).toContain('workload_identity');
    expect(missing).not.toContain('authorization_receipt');
    expect(partial.next_challenge.action_digest).toBe(ch.action_digest);

    const done = evaluatePresentation(partial.next_challenge,
      graphFor(['authorization_receipt', 'policy_permit', 'workload_identity']), policy,
      { verifiers, as_of: AS_OF, consumedNonces: nonces });
    expect(done.verdict).toBe('admissible');
    expect(done.next_challenge).toBeNull();
  });

  it('a challenge nonce is single-use: the second presentation is refused before policy runs', () => {
    const nonces = new Set();
    const ch = createEvidenceChallenge(ACTION, policy, { expires_at: EXPIRES, nonce: 'n1' });
    const g = graphFor(['authorization_receipt', 'policy_permit', 'workload_identity']);
    expect(evaluatePresentation(ch, g, policy, { verifiers, as_of: AS_OF, consumedNonces: nonces }).verdict).toBe('admissible');
    const replay = evaluatePresentation(ch, g, policy, { verifiers, as_of: AS_OF, consumedNonces: nonces });
    expect(replay.verdict).toBe('refused');
    expect(replay.reasons.join(' ')).toContain('replay');
  });

  it('an expired challenge is refused', () => {
    const ch = createEvidenceChallenge(ACTION, policy, { expires_at: '2026-07-03T12:00:30Z' });
    const r = evaluatePresentation(ch, graphFor(['authorization_receipt']), policy,
      { verifiers, as_of: AS_OF, consumedNonces: new Set() });
    expect(r.verdict).toBe('refused');
    expect(r.reasons.join(' ')).toContain('expired');
  });

  it('TOCTOU action swap: a graph binding a different action is refused outright', () => {
    const ch = createEvidenceChallenge(ACTION, policy, { expires_at: EXPIRES });
    const swapped = graphFor(['authorization_receipt', 'policy_permit', 'workload_identity']);
    swapped.action_digest = 'sha256:' + 'e'.repeat(64);
    const r = evaluatePresentation(ch, swapped, policy, { verifiers, as_of: AS_OF, consumedNonces: new Set() });
    expect(r.verdict).toBe('refused');
    expect(r.reasons.join(' ')).toContain('action swap');
  });

  it('challenges MUST expire and MUST have a nonce ledger — both fail closed', () => {
    expect(() => createEvidenceChallenge(ACTION, policy, {})).toThrow(/expires_at/);
    const ch = createEvidenceChallenge(ACTION, policy, { expires_at: EXPIRES });
    const r = evaluatePresentation(ch, graphFor(['authorization_receipt']), policy, { verifiers, as_of: AS_OF });
    expect(r.verdict).toBe('refused');
    expect(r.reasons.join(' ')).toContain('nonce ledger');
  });

  it('malformed challenges fail closed before consuming a nonce', () => {
    const nonces = new Set();
    const ch = createEvidenceChallenge(ACTION, policy, { expires_at: EXPIRES, nonce: 'n1' });
    const g = graphFor(['authorization_receipt']);

    const missingNonce = { ...ch };
    delete missingNonce.nonce;
    const r1 = evaluatePresentation(missingNonce, g, policy, { verifiers, as_of: AS_OF, consumedNonces: nonces });
    expect(r1.verdict).toBe('refused');
    expect(r1.reasons.join(' ')).toContain('nonce');
    expect(nonces.size).toBe(0);

    const badExpiry = evaluatePresentation({ ...ch, expires_at: 'not-a-date' }, g, policy,
      { verifiers, as_of: AS_OF, consumedNonces: nonces });
    expect(badExpiry.verdict).toBe('refused');
    expect(badExpiry.reasons.join(' ')).toContain('expires_at');
    expect(nonces.size).toBe(0);

    const badAsOf = evaluatePresentation(ch, g, policy, { verifiers, as_of: 'not-a-date', consumedNonces: nonces });
    expect(badAsOf.verdict).toBe('refused');
    expect(badAsOf.reasons.join(' ')).toContain('as_of');
    expect(nonces.size).toBe(0);
  });

  it('stale evidence remains in the follow-up challenge as evidence to refresh', () => {
    const nonces = new Set();
    const ch = createEvidenceChallenge(ACTION, policy, { expires_at: EXPIRES, nonce: 'n1' });
    const staleAuth = graphFor(['authorization_receipt', 'policy_permit', 'workload_identity'], {
      authorization_receipt: { issued_at: '2026-07-03T11:50:00Z' },
    });
    const r = evaluatePresentation(ch, staleAuth, policy,
      { verifiers, as_of: AS_OF, consumedNonces: nonces, nonce: 'n2' });
    expect(r.verdict).toBe('stale');
    const missing = r.next_challenge.required_evidence.map((x) => x.type);
    expect(missing).toEqual(['authorization_receipt']);
    expect(r.next_challenge.action_digest).toBe(ch.action_digest);
  });

  it('the next challenge derives its action from the ORIGINAL challenge, never the presentation', () => {
    const nonces = new Set();
    const ch = createEvidenceChallenge(ACTION, policy, { expires_at: EXPIRES, nonce: 'n1' });
    const g = graphFor(['authorization_receipt']);
    const r = evaluatePresentation(ch, g, policy, { verifiers, as_of: AS_OF, consumedNonces: nonces, nonce: 'n2' });
    expect(r.next_challenge.action_digest).toBe(artifactDigest(ACTION));
    expect(r.next_challenge.nonce).toBe('n2');
    expect(r.next_challenge.nonce).not.toBe(ch.nonce);
  });
});

// ── Fail-closed guard coverage. Each drives a specific defensive branch. ──────

describe('mintChallengeForDigest guards (via createEvidenceChallenge/createFollowup)', () => {
  it('an invalid action_digest reaching the minter throws (MUST be a sha256 digest)', () => {
    // A follow-up copies the prior challenge's action_digest verbatim. Corrupt it
    // to a non-digest and the minter fails closed.
    const ch = createEvidenceChallenge(ACTION, policy, { expires_at: EXPIRES, nonce: 'n1' });
    const corrupt = { ...ch, action_digest: 'not-a-digest' };
    expect(() => createFollowupEvidenceChallenge(corrupt, policy, null, { nonce: 'n2' }))
      .toThrow(/action_digest MUST be a sha256 digest/);
  });

  it('a non-string / blank nonce override throws', () => {
    expect(() => createEvidenceChallenge(ACTION, policy, { expires_at: EXPIRES, nonce: 123 }))
      .toThrow(/nonce MUST be a non-empty string/);
    expect(() => createEvidenceChallenge(ACTION, policy, { expires_at: EXPIRES, nonce: '   ' }))
      .toThrow(/nonce MUST be a non-empty string/);
  });

  it('an auto-generated nonce is used when none is supplied (base64url, non-empty)', () => {
    const ch = createEvidenceChallenge(ACTION, policy, { expires_at: EXPIRES });
    expect(typeof ch.nonce).toBe('string');
    expect(ch.nonce.length).toBeGreaterThan(0);
    expect(ch.challenge_id).toMatch(/^[0-9a-f-]{36}$/); // auto UUID
  });

  it('a null policy yields null reliance_purpose / policy_id (fallbacks), not a throw', () => {
    const ch = createEvidenceChallenge(ACTION, null, { expires_at: EXPIRES, nonce: 'n1' });
    expect(ch.reliance_purpose).toBeNull();
    expect(ch.policy_id).toBeNull();
    expect(ch.required_evidence).toEqual([]); // no requirement string -> empty go-get list
  });
});

describe('createFollowupEvidenceChallenge guards', () => {
  it('a wrong challenge @version throws', () => {
    expect(() => createFollowupEvidenceChallenge({ '@version': 'AE-CHALLENGE-vWRONG' }, policy, null))
      .toThrow(/unknown challenge version/);
  });

  it('the follow-up inherits expires_at from the prior challenge when opts omits it', () => {
    const ch = createEvidenceChallenge(ACTION, policy, { expires_at: EXPIRES, nonce: 'n1' });
    const next = createFollowupEvidenceChallenge(ch, policy, null, { nonce: 'n2' });
    expect(next.expires_at).toBe(EXPIRES);
  });

  it('a follow-up nonce EQUAL to the prior nonce is dropped (fresh nonce auto-minted)', () => {
    const ch = createEvidenceChallenge(ACTION, policy, { expires_at: EXPIRES, nonce: 'n1' });
    // opts.nonce === challenge.nonce -> the reused nonce is discarded, a new one minted.
    const next = createFollowupEvidenceChallenge(ch, policy, null, { nonce: 'n1' });
    expect(next.nonce).not.toBe('n1');
    expect(typeof next.nonce).toBe('string');
    expect(next.nonce.length).toBeGreaterThan(0);
  });
});

describe('deriveRequiredEvidence — edge cases fail safe', () => {
  it('a policy with no requirement string yields an empty go-get list', () => {
    expect(deriveRequiredEvidence({})).toEqual([]);
    expect(deriveRequiredEvidence(null)).toEqual([]);
  });

  it('a prior result already satisfying a type removes it from the go-get list', () => {
    const req = deriveRequiredEvidence(policy, { satisfied_by: ['authorization_receipt'] });
    const types = req.map((r) => r.type);
    expect(types).not.toContain('authorization_receipt');
    expect(types).toContain('policy_permit');
  });

  it('a type with no freshness bound simply omits fresh_max_sec', () => {
    // workload_identity has a 3600s bound in the wire pack; a bespoke policy without
    // any freshness_sec entry omits the field entirely.
    const req = deriveRequiredEvidence({ requirement: 'authorization_receipt AND policy_permit' });
    for (const r of req) expect(r.fresh_max_sec).toBeUndefined();
    expect(req.map((r) => r.type)).toEqual(['authorization_receipt', 'policy_permit']);
  });
});

describe('evaluatePresentation — structural refusals before any policy runs', () => {
  it('a wrong challenge @version is refused', () => {
    const ch = createEvidenceChallenge(ACTION, policy, { expires_at: EXPIRES, nonce: 'n1' });
    const r = evaluatePresentation({ ...ch, '@version': 'AE-CHALLENGE-vWRONG' },
      graphFor(['authorization_receipt']), policy,
      { verifiers, as_of: AS_OF, consumedNonces: new Set() });
    expect(r.verdict).toBe('refused');
    expect(r.reasons.join(' ')).toContain('unknown challenge version');
  });

  it('a challenge whose action_digest is not a sha256 digest is refused (no nonce consumed)', () => {
    const nonces = new Set();
    const ch = createEvidenceChallenge(ACTION, policy, { expires_at: EXPIRES, nonce: 'n1' });
    const r = evaluatePresentation({ ...ch, action_digest: 'not-a-digest' },
      graphFor(['authorization_receipt']), policy,
      { verifiers, as_of: AS_OF, consumedNonces: nonces });
    expect(r.verdict).toBe('refused');
    expect(r.reasons.join(' ')).toContain('action_digest missing or invalid');
    expect(nonces.size).toBe(0);
  });
});
