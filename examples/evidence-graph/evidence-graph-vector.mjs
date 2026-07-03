// SPDX-License-Identifier: Apache-2.0
// EP-AEG-v1 worked vector — deterministic; regenerate with:
//   node examples/evidence-graph/evidence-graph-vector.mjs --emit
// The same objects appear in Appendix B of
// draft-schrock-ep-action-evidence-graph. Bytes here are canonical.
import crypto from 'node:crypto';
import {
  EVIDENCE_GRAPH_VERSION, artifactDigest, evaluateEvidenceGraph,
  signRelianceResult, verifyRelianceResult,
} from '../../lib/evidence/evidence-graph.js';
import { getPolicyPack } from '../../lib/evidence/policy-packs.js';

// Deterministic Ed25519 from a fixed seed (vector stability; NEVER reuse
// this pattern for real keys).
const seed = Buffer.from('11'.repeat(32), 'hex');
const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
const signingKey = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });

const action = {
  type: 'urn:ep:action:payments.wire_transfer',
  amount: '250000.00', currency: 'USD',
  beneficiary_account_digest: 'sha256:' + 'b'.repeat(64),
};
const ACTION_DIGEST = artifactDigest(action);

const authorization = {
  typ: 'authorization_receipt', action_digest: ACTION_DIGEST,
  approver: 'ops-lead@example.com', issued_at: '2026-07-02T12:00:00Z',
};
const AUTH_ID = artifactDigest(authorization);
const permit = {
  typ: 'policy_permit', action_digest: ACTION_DIGEST,
  permits_receipt: AUTH_ID, decision: 'allow',
  issued_at: '2026-07-02T12:00:05Z',
};
const PERMIT_ID = artifactDigest(permit);
const workload = {
  typ: 'workload_identity', action_digest: ACTION_DIGEST,
  spiffe_id: 'spiffe://example.org/payments-agent',
  issued_at: '2026-07-02T11:30:00Z',
};
const WL_ID = artifactDigest(workload);

export const graph = {
  '@version': EVIDENCE_GRAPH_VERSION,
  action_digest: ACTION_DIGEST,
  nodes: [
    { id: AUTH_ID, type: 'authorization_receipt', artifact: authorization },
    { id: PERMIT_ID, type: 'policy_permit', artifact: permit },
    { id: WL_ID, type: 'workload_identity', artifact: workload },
  ],
  edges: [{ from: PERMIT_ID, rel: 'permits', to: AUTH_ID }],
};

export const policy = getPolicyPack('ep:pack:wire-transfer:v1');
const AS_OF = '2026-07-02T12:03:00Z';

const verifiers = {
  authorization_receipt: (a) => ({ valid: true, action_digest: a.action_digest, issued_at: a.issued_at, revoked: false }),
  policy_permit: (a) => ({ valid: true, action_digest: a.action_digest, issued_at: a.issued_at, outcome: a.decision }),
  workload_identity: (a) => ({ valid: true, action_digest: a.action_digest, issued_at: a.issued_at }),
};

export const result = evaluateEvidenceGraph(graph, policy, { verifiers, as_of: AS_OF });
export const reliance = signRelianceResult(result, policy, signingKey, { evaluated_at: AS_OF });

const check = verifyRelianceResult(reliance, [reliance.verifier_key]);
if (result.verdict !== 'admissible') throw new Error(`expected admissible, got ${result.verdict}: ${result.reasons}`);
if (!check.accepted) throw new Error('reliance result did not verify+accept');

// Negative: stale under the same policy, later as_of
const stale = evaluateEvidenceGraph(graph, policy, { verifiers, as_of: '2026-07-02T13:30:00Z' });
if (stale.verdict !== 'stale') throw new Error(`expected stale, got ${stale.verdict}`);

if (process.argv.includes('--emit')) {
  const out = { graph, policy, as_of: AS_OF, result: { verdict: result.verdict, replay_digest: result.replay_digest, graph_digest: result.graph.graph_digest }, reliance };
  console.log(JSON.stringify(out, null, 2));
}
console.error('EVIDENCE-GRAPH VECTOR OK');
