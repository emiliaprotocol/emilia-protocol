// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';
import {
  CHALLENGE_VERSION, createEvidenceChallenge, evaluatePresentation, deriveRequiredEvidence,
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
