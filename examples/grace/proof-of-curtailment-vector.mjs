#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * GRACE proof-of-curtailment — the full circuit through one synthetic grid
 * event, deterministic end to end. Run: node examples/grace/proof-of-curtailment-vector.mjs [--emit]
 *
 *   envelope (human authorizes participation, bounded)
 *     -> grid event: ISO issues a bounded curtailment ORDER
 *     -> facility checks Order ⊆ Envelope (fail-closed BEFORE execution)
 *     -> settlement authority mints an AE-CHALLENGE naming the evidence
 *     -> facility executes, meter independently records
 *     -> facility presents the evidence graph
 *     -> policy replay -> admissible -> signed reliance result
 *     -> compliance computed from the METER leg -> what should be paid
 *
 * Negatives enforced: out-of-bounds order refused pre-execution; missing
 * meter leg -> missing_evidence; tampered order -> unverifiable; facility
 * self-attestation can never substitute for the meter.
 */
import crypto from 'node:crypto';
import { EVIDENCE_GRAPH_VERSION, artifactDigest, evaluateEvidenceGraph, signRelianceResult, verifyRelianceResult } from '../../lib/evidence/evidence-graph.js';
import { createEvidenceChallenge, evaluatePresentation } from '../../lib/negotiate/evidence-challenge.js';
import { FLEX_ENVELOPE_VERSION, CURTAILMENT_SETTLEMENT_POLICY, checkOrderWithinEnvelope, computeCompliance } from '../../lib/grace/curtailment.js';

// Deterministic keys (vector stability; NEVER this pattern for real keys).
const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const keyFor = (label) => crypto.createPrivateKey({
  key: Buffer.concat([PKCS8, crypto.createHash('sha256').update(`ep:grace-vector:v1:${label}`).digest()]),
  format: 'der', type: 'pkcs8',
});
const pub = (k) => crypto.createPublicKey(k).export({ type: 'spki', format: 'der' }).toString('base64url');
const isoKey = keyFor('iso'), facilityKey = keyFor('facility'), meterKey = keyFor('meter'), settlementKey = keyFor('settlement');

// ── The event ────────────────────────────────────────────────────────────────
const EVENT = {
  type: 'urn:ep:action:grid.curtailment',
  event_id: 'ercot-2026-07-15-0001',
  mw: '12.0',
  window: { start: '2026-07-15T15:00:00Z', end: '2026-07-15T19:00:00Z' },
};
const EVENT_DIGEST = artifactDigest(EVENT);

// ── The envelope a named human authorized once, for the season ──────────────
export const envelope = {
  '@version': FLEX_ENVELOPE_VERSION,
  facility: 'dc-west-04.example',
  program: 'ercot-flex-2026-summer',
  bounds: {
    max_mw: 15,
    min_notice_minutes: 10,
    max_event_hours: 6,
    window: { start: '2026-06-01T00:00:00Z', end: '2026-09-30T23:59:59Z' },
  },
  authorized_by: 'vp-infrastructure@dc-west.example',
};

// ── The four evidence legs, each binding EVENT_DIGEST, each byte-linked ─────
const mkSigned = (payload, key, keyField) => {
  const artifact = { payload, sig: crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), key).toString('base64url') };
  artifact[keyField] = pub(key);
  return artifact;
};
function canonicalize(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalize(v[k])}`).join(',')}}`;
}

const orderPayload = {
  typ: 'curtailment_order', action_digest: EVENT_DIGEST,
  event_id: EVENT.event_id, mw: EVENT.mw, notice_minutes: 30,
  window: EVENT.window, price_usd_per_mwh: '185.00',
  issued_at: '2026-07-15T14:30:00Z',
};
const order = mkSigned(orderPayload, isoKey, 'issuer_key');
const ORDER_ID = artifactDigest(order);

const authPayload = {
  typ: 'authorization_receipt', action_digest: EVENT_DIGEST,
  envelope_digest: artifactDigest(envelope), order_digest: ORDER_ID,
  approver: envelope.authorized_by, issued_at: '2026-07-15T14:35:00Z',
};
const authorization = mkSigned(authPayload, facilityKey, 'approver_key');
const AUTH_ID = artifactDigest(authorization);

const execPayload = {
  typ: 'execution_attestation', action_digest: EVENT_DIGEST,
  executes_authorization: AUTH_ID, event_id: EVENT.event_id,
  commanded_reduction_mw: EVENT.mw, method: 'checkpoint-and-shed',
  issued_at: '2026-07-15T19:05:00Z',
};
const execution = mkSigned(execPayload, facilityKey, 'facility_key');
const EXEC_ID = artifactDigest(execution);

const meterPayload = {
  typ: 'meter_statement', action_digest: EVENT_DIGEST,
  records_execution: EXEC_ID, meter_id: 'utility-meter-77121',
  baseline_mw: 14.2, intervals_mw: [2.4, 2.1, 2.2, 2.3],
  issued_at: '2026-07-15T20:00:00Z',
};
const meter = mkSigned(meterPayload, meterKey, 'meter_key');
const METER_ID = artifactDigest(meter);

export const graph = {
  '@version': EVIDENCE_GRAPH_VERSION,
  action_digest: EVENT_DIGEST,
  nodes: [
    { id: ORDER_ID, type: 'curtailment_order', artifact: order },
    { id: AUTH_ID, type: 'authorization_receipt', artifact: authorization },
    { id: EXEC_ID, type: 'execution_attestation', artifact: execution },
    { id: METER_ID, type: 'meter_statement', artifact: meter },
  ],
  edges: [
    { from: EXEC_ID, rel: 'executes', to: AUTH_ID },
    { from: METER_ID, rel: 'records', to: EXEC_ID },
  ],
};

const verifiers = Object.fromEntries(['curtailment_order', 'authorization_receipt', 'execution_attestation', 'meter_statement'].map((t) => [t, (a) => {
  let valid = false;
  try {
    const keyB64 = a.issuer_key ?? a.approver_key ?? a.facility_key ?? a.meter_key;
    const k = crypto.createPublicKey({ key: Buffer.from(keyB64, 'base64url'), type: 'spki', format: 'der' });
    valid = crypto.verify(null, Buffer.from(canonicalize(a.payload), 'utf8'), k, Buffer.from(a.sig, 'base64url'));
  } catch { valid = false; }
  return { valid, action_digest: a.payload?.action_digest, issued_at: a.payload?.issued_at, revoked: false };
}]));

const AS_OF = '2026-07-16T09:00:00Z';

// ── 1. Fail-closed BEFORE execution: Order ⊆ Envelope ───────────────────────
const within = checkOrderWithinEnvelope(orderPayload, envelope);
if (!within.within) throw new Error('in-bounds order refused: ' + within.violations);
const oversized = checkOrderWithinEnvelope({ ...orderPayload, mw: '22.0' }, envelope);
if (oversized.within) throw new Error('OUT-OF-BOUNDS ORDER NOT REFUSED');
const shortNotice = checkOrderWithinEnvelope({ ...orderPayload, notice_minutes: 3 }, envelope);
if (shortNotice.within) throw new Error('SHORT-NOTICE ORDER NOT REFUSED');

// ── 2. The negotiation loop: settlement authority challenges, facility presents ──
const nonces = new Set();
const challenge = createEvidenceChallenge(EVENT, CURTAILMENT_SETTLEMENT_POLICY, { expires_at: '2026-07-22T00:00:00Z', nonce: 'grace-n1' });
const presented = evaluatePresentation(challenge, graph, CURTAILMENT_SETTLEMENT_POLICY, { verifiers, as_of: AS_OF, consumedNonces: nonces });
if (presented.verdict !== 'admissible') throw new Error(`expected admissible, got ${presented.verdict}: ${presented.reasons}`);

// ── 3. The signed reliance result + independent re-verification ─────────────
export const reliance = signRelianceResult(presented.result, CURTAILMENT_SETTLEMENT_POLICY, settlementKey, { evaluated_at: AS_OF });
const check = verifyRelianceResult(reliance, [reliance.verifier_key]);
if (!check.accepted) throw new Error('reliance result failed verification');

// ── 4. Compliance from the METER leg (independent telemetry) ────────────────
export const compliance = computeCompliance(orderPayload, meterPayload);
if (!compliance.computable || !compliance.compliant) throw new Error('expected compliant event: ' + JSON.stringify(compliance));
// facility self-attestation can never substitute for the meter:
const noMeter = { ...graph, nodes: graph.nodes.filter((n) => n.type !== 'meter_statement'), edges: graph.edges.filter((e) => e.rel !== 'records') };
const insufficient = evaluateEvidenceGraph(noMeter, CURTAILMENT_SETTLEMENT_POLICY, { verifiers, as_of: AS_OF });
if (insufficient.verdict !== 'missing_evidence') throw new Error(`meterless bundle should be missing_evidence, got ${insufficient.verdict}`);

// ── 5. Tampered order (price inflated after signing) -> unverifiable ─────────
const tampered = JSON.parse(JSON.stringify(graph));
tampered.nodes[0].artifact.payload.price_usd_per_mwh = '985.00';
const broken = evaluateEvidenceGraph(tampered, CURTAILMENT_SETTLEMENT_POLICY, { verifiers, as_of: AS_OF });
if (broken.verdict === 'admissible') throw new Error('tampered order accepted');

if (process.argv.includes('--emit')) {
  console.log(JSON.stringify({ event: EVENT, envelope, graph, policy: CURTAILMENT_SETTLEMENT_POLICY, verdict: presented.verdict, replay_digest: presented.replay_digest, compliance, reliance }, null, 2));
}
console.error(`PROOF-OF-CURTAILMENT OK — ordered ${compliance.ordered_mw} MW, meter-verified ${compliance.delivered_mw} MW (ratio ${compliance.compliance_ratio}); verdict admissible; out-of-bounds/meterless/tampered all refused.`);
