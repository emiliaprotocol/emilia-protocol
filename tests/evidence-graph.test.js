// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  EVIDENCE_GRAPH_VERSION, EDGE_RELS, artifactDigest, graphDigest,
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
