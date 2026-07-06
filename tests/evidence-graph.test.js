// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  EVIDENCE_GRAPH_VERSION, RELIANCE_RESULT_VERSION, EDGE_RELS, artifactDigest, graphDigest,
  evaluateEvidenceGraph, signRelianceResult, verifyRelianceResult,
} from '../lib/evidence/evidence-graph.js';
import { POLICY_PACKS, POLICY_PACK_IDS, getPolicyPack } from '../lib/evidence/policy-packs.js';

const ACTION = 'sha256:' + 'a'.repeat(64);

// Synthetic artifacts: each carries the digests it genuinely binds, so the
// byte-grounded edge check has something real to find.
const mk = (type, extra = {}) => ({ typ: type, action: ACTION, ...extra });

function buildGraph() {
  const auth = mk('authorization_receipt', { approver: 'alice', issued_at: '2026-07-02T00:00:00Z' });
  const authId = artifactDigest(auth);
  const permit = mk('policy_permit', { authorizes_receipt: authId, issued_at: '2026-07-02T00:00:00Z' });
  const permitId = artifactDigest(permit);
  const wl = mk('workload_identity', { spiffe_id: 'spiffe://x/agent', issued_at: '2026-07-02T00:00:00Z' });
  const wlId = artifactDigest(wl);
  return {
    doc: {
      '@version': EVIDENCE_GRAPH_VERSION,
      action_digest: ACTION,
      nodes: [
        { id: authId, type: 'authorization_receipt', artifact: auth },
        { id: permitId, type: 'policy_permit', artifact: permit },
        { id: wlId, type: 'workload_identity', artifact: wl },
      ],
      edges: [{ from: permitId, rel: 'permits', to: authId }],
    },
    ids: { authId, permitId, wlId },
  };
}

const verifiers = {
  authorization_receipt: (a) => ({ valid: true, action_digest: a.action, issued_at: a.issued_at, revoked: a.revoked === true }),
  quorum_receipt: (a) => ({ valid: true, action_digest: a.action, issued_at: a.issued_at }),
  policy_permit: (a) => ({ valid: a.tampered !== true, action_digest: a.action, issued_at: a.issued_at }),
  workload_identity: (a) => ({ valid: true, action_digest: a.action, issued_at: a.issued_at }),
};
const AS_OF = '2026-07-02T00:02:00Z';
const wirePack = getPolicyPack('ep:pack:wire-transfer:v1');

describe('EP-AEG — evidence graph evaluation', () => {
  it('a complete, honestly-edged graph is admissible under the wire-transfer pack', () => {
    const { doc } = buildGraph();
    const r = evaluateEvidenceGraph(doc, wirePack, { verifiers, as_of: AS_OF });
    expect(r.verdict).toBe('admissible');
    expect(r.graph.nodes).toBe(3);
  });

  it('graph identity is disclosure-independent: stripping artifacts does not change graph_digest', () => {
    const { doc } = buildGraph();
    const stripped = { ...doc, nodes: doc.nodes.map(({ id, type }) => ({ id, type })) };
    expect(graphDigest(stripped)).toBe(graphDigest(doc));
  });

  it('shape-only disclosure of a required node fails closed (missing/unverifiable, never admissible)', () => {
    const { doc } = buildGraph();
    doc.nodes[0] = { id: doc.nodes[0].id, type: doc.nodes[0].type }; // authorization undisclosed
    const r = evaluateEvidenceGraph(doc, wirePack, { verifiers, as_of: AS_OF });
    expect(r.verdict).not.toBe('admissible');
  });

  it('an inline artifact that does not hash to its node id is refused', () => {
    const { doc } = buildGraph();
    doc.nodes[0].artifact = { ...doc.nodes[0].artifact, approver: 'mallory' };
    const r = evaluateEvidenceGraph(doc, wirePack, { verifiers, as_of: AS_OF });
    expect(r.verdict).not.toBe('admissible');
    expect(r.reasons.join(' ')).toContain('does not hash to its id');
  });

  it('a claimed-but-unbacked edge poisons the verdict (a lying graph is unverifiable)', () => {
    const { doc, ids } = buildGraph();
    // presenter claims workload -attests_runtime-> auth, but the workload
    // artifact contains no such binding
    doc.edges.push({ from: ids.wlId, rel: 'attests_runtime', to: ids.authId });
    const r = evaluateEvidenceGraph(doc, wirePack, { verifiers, as_of: AS_OF });
    expect(r.verdict).toBe('unverifiable');
    expect(r.reasons.join(' ')).toContain('unbacked_edge_claim');
  });

  it('a required edge that is absent strips the source type (missing_evidence)', () => {
    const { doc } = buildGraph();
    doc.edges = []; // permit no longer provably permits THIS authorization
    const r = evaluateEvidenceGraph(doc, wirePack, { verifiers, as_of: AS_OF });
    expect(r.verdict).toBe('missing_evidence');
  });

  it('stale authorization degrades the verdict under the pack freshness bound', () => {
    const { doc } = buildGraph();
    const r = evaluateEvidenceGraph(doc, wirePack, { verifiers, as_of: '2026-07-02T01:00:00Z' });
    expect(r.verdict).toBe('stale');
  });

  it('unknown edge rel and missing policy are structural failures', () => {
    const { doc } = buildGraph();
    doc.edges[0].rel = 'vouches_for';
    expect(evaluateEvidenceGraph(doc, wirePack, { verifiers }).verdict).toBe('unverifiable');
    const { doc: doc2 } = buildGraph();
    expect(evaluateEvidenceGraph(doc2, null, { verifiers }).verdict).toBe('unverifiable');
  });

  it('replay: same graph + same policy + same as_of gives the same verdict and replay_digest', () => {
    const { doc } = buildGraph();
    const a = evaluateEvidenceGraph(doc, wirePack, { verifiers, as_of: AS_OF });
    const b = evaluateEvidenceGraph(JSON.parse(JSON.stringify(doc)), wirePack, { verifiers, as_of: AS_OF });
    expect(a.verdict).toBe(b.verdict);
    expect(a.replay_digest).toBe(b.replay_digest);
  });

  it('a verifier that throws is contained per-node, never fatal', () => {
    const { doc } = buildGraph();
    const throwing = { ...verifiers, authorization_receipt: () => { throw new Error('boom'); } };
    const r = evaluateEvidenceGraph(doc, wirePack, { verifiers: throwing, as_of: AS_OF });
    expect(r.verdict).not.toBe('admissible');
    expect(r.reasons.join(' ')).toContain('verifier threw');
  });

  it('honors a custom per-rel edge checker over the default byte check', () => {
    const { doc } = buildGraph();
    const r = evaluateEvidenceGraph(doc, wirePack, {
      verifiers, as_of: AS_OF, edgeCheckers: { permits: () => true },
    });
    expect(r.graph.edge_rows.find((e) => e.rel === 'permits').backed).toBe(true);
  });

  it('a policy with no required_edges strips nothing (|| [] fallback)', () => {
    const { doc } = buildGraph();
    const noReq = { ...wirePack, required_edges: undefined };
    const r = evaluateEvidenceGraph(doc, noReq, { verifiers, as_of: AS_OF });
    expect(r.reasons.join(' ')).not.toContain('required edge missing');
  });
});

// ── Step 6: ceremony_evidence + effect_attestation node types ───────────────

// A ceremony node carries the signing-ceremony timeline (issued/viewed/approved
// + approver). Its verifier surfaces that telemetry alongside signature state.
const CEREMONY_VERIFIER = (a) => ({
  valid: a.tampered !== true,
  action_digest: a.action,
  issued_at: a.issued_at,
  approver: a.approver,
  viewed_at: a.viewed_at,
  approved_at: a.approved_at,
});
// An effect_attestation is executor-signed {receipt_id, observed_effect_digest}.
// The verifier reports the observed effect and (when it could read it out of the
// referenced authorization) the approved committed effect. valid:false models a
// bad executor signature or an unpinned executor key — fail-closed at source.
const EFFECT_VERIFIER = (a) => ({
  valid: a.bad_sig !== true && a.unpinned_key !== true,
  action_digest: a.action,
  issued_at: a.issued_at,
  receipt_id: a.receipt_id,
  observed_effect_digest: a.observed_effect_digest,
  committed_effect_digest: a.committed_effect_digest,
});

// A ceremony-only policy: require the ceremony node, set a review-latency floor.
const ceremonyPolicy = (floorSec) => ({
  policy_id: 'ep:test:ceremony',
  reliance_purpose: 'audit',
  requirement: 'ceremony_evidence',
  ceremony_min_review_sec: floorSec,
});
// An effect policy: require the effect attestation, optionally pin the approved
// effect digest (relying-party-supplied, never presenter-chosen).
const effectPolicy = (expected_effect_digest) => ({
  policy_id: 'ep:test:effect',
  reliance_purpose: 'regulated_execution',
  requirement: 'effect_attestation',
  ...(expected_effect_digest ? { expected_effect_digest } : {}),
});

function ceremonyGraph({ viewed_at, approved_at, approver = 'alice', tampered = false } = {}) {
  const cer = mk('ceremony_evidence', {
    approver, issued_at: '2026-07-02T00:00:00Z', viewed_at, approved_at,
    ...(tampered ? { tampered: true } : {}),
  });
  const id = artifactDigest(cer);
  return {
    '@version': EVIDENCE_GRAPH_VERSION, action_digest: ACTION,
    nodes: [{ id, type: 'ceremony_evidence', artifact: cer }], edges: [],
  };
}
function effectGraph({ observed, committed, bad_sig = false, unpinned_key = false } = {}) {
  const att = mk('effect_attestation', {
    receipt_id: 'tr_effect_1', issued_at: '2026-07-02T00:00:00Z',
    observed_effect_digest: observed, committed_effect_digest: committed,
    ...(bad_sig ? { bad_sig: true } : {}), ...(unpinned_key ? { unpinned_key: true } : {}),
  });
  const id = artifactDigest(att);
  return {
    '@version': EVIDENCE_GRAPH_VERSION, action_digest: ACTION,
    nodes: [{ id, type: 'effect_attestation', artifact: att }], edges: [],
  };
}
const EFFECT_X = 'sha256:' + 'e'.repeat(64); // approved effect
const EFFECT_Y = 'sha256:' + 'f'.repeat(64); // executed-but-different effect

describe('EP-AEG — ceremony_evidence (review-latency floor)', () => {
  const V = { ...verifiers, ceremony_evidence: CEREMONY_VERIFIER };

  it('an above-floor ceremony is admissible (genuine review)', () => {
    const doc = ceremonyGraph({ viewed_at: '2026-07-02T00:00:00Z', approved_at: '2026-07-02T00:01:00Z' }); // 60s
    const r = evaluateEvidenceGraph(doc, ceremonyPolicy(30), { verifiers: V, as_of: AS_OF });
    expect(r.verdict).toBe('admissible');
  });

  it('a below-floor ceremony downgrades the verdict to conflicted (rubber-stamped)', () => {
    const doc = ceremonyGraph({ viewed_at: '2026-07-02T00:00:00Z', approved_at: '2026-07-02T00:00:02Z' }); // 2s
    const r = evaluateEvidenceGraph(doc, ceremonyPolicy(30), { verifiers: V, as_of: AS_OF });
    expect(r.verdict).toBe('conflicted');
    expect(r.reasons.join(' ')).toContain('rubber_stamped_ceremony');
  });

  it('a review-latency floor with unusable telemetry fails closed (conflicted, never admissible)', () => {
    const doc = ceremonyGraph({ viewed_at: undefined, approved_at: '2026-07-02T00:01:00Z' });
    const r = evaluateEvidenceGraph(doc, ceremonyPolicy(30), { verifiers: V, as_of: AS_OF });
    expect(r.verdict).toBe('conflicted');
    expect(r.reasons.join(' ')).toContain('ceremony_telemetry_missing');
  });

  it('no floor set means the ceremony telemetry is not judged (admissible)', () => {
    const doc = ceremonyGraph({ viewed_at: '2026-07-02T00:00:00Z', approved_at: '2026-07-02T00:00:02Z' }); // 2s
    const noFloor = { policy_id: 'ep:test:ceremony', reliance_purpose: 'audit', requirement: 'ceremony_evidence' };
    const r = evaluateEvidenceGraph(doc, noFloor, { verifiers: V, as_of: AS_OF });
    expect(r.verdict).toBe('admissible');
  });

  it('an unverifiable ceremony is not softened to conflicted (precedence: unverifiable > conflicted)', () => {
    const doc = ceremonyGraph({ viewed_at: '2026-07-02T00:00:00Z', approved_at: '2026-07-02T00:00:02Z', tampered: true });
    const r = evaluateEvidenceGraph(doc, ceremonyPolicy(30), { verifiers: V, as_of: AS_OF });
    expect(r.verdict).toBe('unverifiable');
  });
});

describe('EP-AEG — effect_attestation (approved X, executed Y)', () => {
  const V = { ...verifiers, effect_attestation: EFFECT_VERIFIER };

  it('an effect digest matching the approved committed effect admits', () => {
    const doc = effectGraph({ observed: EFFECT_X, committed: EFFECT_X });
    const r = evaluateEvidenceGraph(doc, effectPolicy(), { verifiers: V, as_of: AS_OF });
    expect(r.verdict).toBe('admissible');
  });

  it('a diverging effect digest surfaces conflict (approved X, executed Y)', () => {
    const doc = effectGraph({ observed: EFFECT_Y, committed: EFFECT_X });
    const r = evaluateEvidenceGraph(doc, effectPolicy(), { verifiers: V, as_of: AS_OF });
    expect(r.verdict).toBe('conflicted');
    expect(r.reasons.join(' ')).toContain('effect_divergence');
  });

  it('a relying-party-pinned expected effect overrides the verifier-read committed digest', () => {
    // Verifier reports committed==observed==X, but the relying party pins Y as
    // the effect it approved: divergence still surfaces (pinned bar wins).
    const doc = effectGraph({ observed: EFFECT_X, committed: EFFECT_X });
    const r = evaluateEvidenceGraph(doc, effectPolicy(EFFECT_Y), { verifiers: V, as_of: AS_OF });
    expect(r.verdict).toBe('conflicted');
    expect(r.reasons.join(' ')).toContain('effect_divergence');
  });

  it('a verified effect with no committed effect to compare fails closed (conflicted)', () => {
    const doc = effectGraph({ observed: EFFECT_X, committed: undefined });
    const r = evaluateEvidenceGraph(doc, effectPolicy(), { verifiers: V, as_of: AS_OF });
    expect(r.verdict).toBe('conflicted');
    expect(r.reasons.join(' ')).toContain('effect_commitment_missing');
  });

  it('a bad executor signature is inadmissible evidence (unverifiable, not weighed as effect)', () => {
    const doc = effectGraph({ observed: EFFECT_Y, committed: EFFECT_X, bad_sig: true });
    const r = evaluateEvidenceGraph(doc, effectPolicy(), { verifiers: V, as_of: AS_OF });
    expect(r.verdict).toBe('unverifiable');
    // Divergence is NOT the reason — the signature failed first (fail closed).
    expect(r.reasons.join(' ')).not.toContain('effect_divergence');
  });

  it('an unpinned executor key is inadmissible evidence (unverifiable)', () => {
    const doc = effectGraph({ observed: EFFECT_X, committed: EFFECT_X, unpinned_key: true });
    const r = evaluateEvidenceGraph(doc, effectPolicy(), { verifiers: V, as_of: AS_OF });
    expect(r.verdict).toBe('unverifiable');
  });
});

describe('EP-RELIANCE-RESULT — the verdict as signed evidence', () => {
  const { privateKey } = crypto.generateKeyPairSync('ed25519');

  function signed() {
    const { doc } = buildGraph();
    const r = evaluateEvidenceGraph(doc, wirePack, { verifiers, as_of: AS_OF });
    return signRelianceResult(r, wirePack, privateKey, { evaluated_at: AS_OF });
  }

  it('signs and verifies; acceptance requires a pinned verifier key', () => {
    const doc = signed();
    const un = verifyRelianceResult(doc, []);
    expect(un.verified).toBe(true);
    expect(un.accepted).toBe(false);
    const pinned = verifyRelianceResult(doc, [doc.verifier_key]);
    expect(pinned.accepted).toBe(true);
  });

  it('a tampered verdict breaks the signature', () => {
    const doc = signed();
    doc.payload.verdict = 'conflicted';
    const r = verifyRelianceResult(doc, [doc.verifier_key]);
    expect(r.verified).toBe(false);
  });

  it('carries the replay digest so the decision is recomputable, not takable-on-trust', () => {
    const doc = signed();
    const { doc: g } = buildGraph();
    const recomputed = evaluateEvidenceGraph(g, wirePack, { verifiers, as_of: AS_OF });
    expect(doc.payload.replay_digest).toBe(recomputed.replay_digest);
  });

  it('fails closed on a structurally-invalid doc, before any crypto (every guard branch)', () => {
    const V = RELIANCE_RESULT_VERSION;
    const bad = [
      null,
      undefined,
      {},                                                                 // no payload
      { payload: { '@version': 'EP-RELIANCE-RESULT-vWRONG' }, sig: 'x', verifier_key: 'y' }, // wrong version
      { payload: { '@version': V }, sig: 123, verifier_key: 'y' },        // non-string sig
      { payload: { '@version': V }, sig: 'x', verifier_key: 123 },        // non-string verifier_key
    ];
    for (const doc of bad) {
      const r = verifyRelianceResult(doc, []);
      expect(r.verified).toBe(false);
      expect(r.accepted).toBe(false);
      expect(r.checks.structure).toBe(false);
    }
  });

  it('a verifier_key that is not a valid SPKI key fails closed (structure ok, unverified)', () => {
    const doc = signed();
    doc.verifier_key = Buffer.from('not-a-real-spki-key').toString('base64url');
    const r = verifyRelianceResult(doc, [doc.verifier_key]);
    expect(r.checks.structure).toBe(true);
    expect(r.verified).toBe(false);
    expect(r.accepted).toBe(false);
  });

  it('an unserializable payload is caught, not thrown (signature=false, never crashes)', () => {
    const doc = signed();
    doc.payload.evil = 1n; // BigInt -> canon() throws inside verify's try block
    const r = verifyRelianceResult(doc, [doc.verifier_key]);
    expect(r.checks.structure).toBe(true);
    expect(r.checks.signature).toBe(false);
    expect(r.verified).toBe(false);
  });

  it('signs a bare result: missing graph / policy-id / evaluated_at fall back to null', () => {
    const bare = signRelianceResult(
      { verdict: 'admissible', reasons: [], action_digest: ACTION, replay_digest: 'sha256:' + '0'.repeat(64) },
      {},          // policy with no policy_id / reliance_purpose
      privateKey,  // no opts -> evaluated_at defaults to null
    );
    expect(bare.payload.graph_digest).toBe(null);
    expect(bare.payload.policy_id).toBe(null);
    expect(bare.payload.reliance_purpose).toBe(null);
    expect(bare.payload.evaluated_at).toBe(null);
    const r = verifyRelianceResult(bare, [bare.verifier_key]);
    expect(r.verified).toBe(true);
    expect(r.accepted).toBe(true);
  });
});

describe('policy packs', () => {
  it('ships six packs, all frozen, with fail-closed lookup', () => {
    expect(POLICY_PACK_IDS.length).toBe(6);
    for (const id of POLICY_PACK_IDS) {
      const p = POLICY_PACKS[id];
      expect(Object.isFrozen(p)).toBe(true);
      expect(p.requirement).toBeTruthy();
      expect(p.revocation_required.length).toBeGreaterThan(0);
      expect(p.action_family.startsWith('urn:ep:action:')).toBe(true);
    }
    expect(() => getPolicyPack('ep:pack:nonexistent:v1')).toThrow(/unknown policy pack/);
  });

  it('vendor-bank-change demands a quorum, not a single approver', () => {
    const pack = getPolicyPack('ep:pack:vendor-bank-change:v1');
    const { doc } = buildGraph(); // has authorization_receipt, NOT quorum_receipt
    const r = evaluateEvidenceGraph(doc, pack, { verifiers, as_of: AS_OF });
    expect(r.verdict).toBe('missing_evidence');
  });

  it('every EDGE_RELS entry used by a pack is registered', () => {
    for (const p of Object.values(POLICY_PACKS)) {
      for (const e of p.required_edges) expect(EDGE_RELS).toContain(e.rel);
    }
  });
});
