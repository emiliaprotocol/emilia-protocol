// SPDX-License-Identifier: Apache-2.0
// Generated from policy-packs.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * EP policy packs — canonical, versioned evidence policies for the concrete
 * irreversible action classes relying parties actually face. A pack is a
 * STARTING POINT the relying party adopts and owns (pin your own trust
 * anchors, tighten freshness to your risk appetite); it is never read from a
 * presented graph. Packs make the admissibility layer adoptable in an
 * afternoon: pick the pack for your action class, pin issuer keys, done.
 *
 * Component-type vocabulary (matches lib/evidence/admissibility.js):
 *   authorization_receipt | quorum_receipt | delegation | policy_permit |
 *   workload_identity | execution_attestation | transparency | recourse_reference
 *
 * Freshness numbers are deliberate defaults, not laws: pre-execution release
 * gates get minutes (the approval must be ABOUT now); post-hoc audit purposes
 * get days. Every pack requires action agreement and revocation checks on the
 * authorization leg — no pack ever waives fail-closed behavior.
 */
import crypto from 'node:crypto';
import { canonicalize } from '../canonical-json.js';
const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');
const packs = {
    'ep:pack:wire-transfer:v1': {
        policy_id: 'ep:pack:wire-transfer:v1',
        reliance_purpose: 'money_movement',
        action_family: 'urn:ep:action:payments.wire_transfer',
        requirement: 'authorization_receipt AND policy_permit AND workload_identity',
        freshness_sec: { authorization_receipt: 300, policy_permit: 600, workload_identity: 3600 },
        revocation_required: ['authorization_receipt'],
        required_edges: [
            { from_type: 'policy_permit', rel: 'permits', to_type: 'authorization_receipt' },
        ],
        trust_anchor_slots: ['authorization_receipt', 'policy_permit'],
    },
    'ep:pack:vendor-bank-change:v1': {
        // The #1 BEC / payment-fraud vector: changing WHERE money goes. Stricter
        // than the wire itself — a distinct-human quorum, not one approver.
        policy_id: 'ep:pack:vendor-bank-change:v1',
        reliance_purpose: 'money_movement',
        action_family: 'urn:ep:action:payments.payee_details_change',
        requirement: 'quorum_receipt AND policy_permit',
        freshness_sec: { quorum_receipt: 900, policy_permit: 900 },
        revocation_required: ['quorum_receipt'],
        required_edges: [
            { from_type: 'policy_permit', rel: 'permits', to_type: 'quorum_receipt' },
        ],
        trust_anchor_slots: ['quorum_receipt', 'policy_permit'],
    },
    'ep:pack:credential-rotation:v1': {
        policy_id: 'ep:pack:credential-rotation:v1',
        reliance_purpose: 'security_operation',
        action_family: 'urn:ep:action:security.credential_rotation',
        requirement: 'authorization_receipt AND workload_identity',
        freshness_sec: { authorization_receipt: 600, workload_identity: 3600 },
        revocation_required: ['authorization_receipt'],
        required_edges: [],
        trust_anchor_slots: ['authorization_receipt'],
    },
    'ep:pack:production-delete:v1': {
        policy_id: 'ep:pack:production-delete:v1',
        reliance_purpose: 'destructive_operation',
        action_family: 'urn:ep:action:data.production_delete',
        requirement: 'authorization_receipt AND policy_permit',
        freshness_sec: { authorization_receipt: 300, policy_permit: 600 },
        revocation_required: ['authorization_receipt'],
        required_edges: [
            { from_type: 'policy_permit', rel: 'permits', to_type: 'authorization_receipt' },
        ],
        trust_anchor_slots: ['authorization_receipt', 'policy_permit'],
    },
    'ep:pack:regulated-trade:v1': {
        // Post-hoc reliance (settlement / compliance): the execution record must
        // provably reference the authorization it acted under, and the whole
        // thing must be on a transparency log.
        policy_id: 'ep:pack:regulated-trade:v1',
        reliance_purpose: 'regulated_execution',
        action_family: 'urn:ep:action:trading.order_execution',
        requirement: 'authorization_receipt AND policy_permit AND execution_attestation AND transparency',
        freshness_sec: { authorization_receipt: 3600 },
        revocation_required: ['authorization_receipt'],
        required_edges: [
            { from_type: 'execution_attestation', rel: 'executes', to_type: 'authorization_receipt' },
            { from_type: 'transparency', rel: 'records', to_type: 'execution_attestation' },
        ],
        trust_anchor_slots: ['authorization_receipt', 'policy_permit', 'transparency'],
    },
    'ep:pack:healthcare-export:v1': {
        policy_id: 'ep:pack:healthcare-export:v1',
        reliance_purpose: 'data_disclosure',
        action_family: 'urn:ep:action:health.record_export',
        requirement: 'authorization_receipt AND delegation AND policy_permit AND transparency',
        freshness_sec: { authorization_receipt: 900, delegation: 86400, policy_permit: 900 },
        revocation_required: ['authorization_receipt', 'delegation'],
        required_edges: [
            { from_type: 'delegation', rel: 'delegates', to_type: 'authorization_receipt' },
            { from_type: 'transparency', rel: 'records', to_type: 'authorization_receipt' },
        ],
        trust_anchor_slots: ['authorization_receipt', 'delegation', 'transparency'],
    },
};
/**
 * Content hash of a pack: sha256 over its JCS-canonical form with the hash
 * field(s) removed, prefixed `sha256:` — the same construction the rest of EP
 * uses (RFC-8785/JCS + SHA-256). This makes a pack a PINNABLE object: a relying
 * party that adopts a pack pins this hash, and any later drift in the pack's
 * bytes changes the hash and is caught. It does NOT change pack SEMANTICS.
 * @param {object} pack
 * @returns {string} 'sha256:<hex>'
 */
export function computePolicyPackHash(pack) {
    if (!pack || typeof pack !== 'object')
        throw new Error('pack must be an object');
    const { policy_hash: _ph, profile_hash: _pf, ...rest } = pack;
    return `sha256:${sha256hex(canonicalize(rest))}`;
}
// Stamp each pack with its self-verifying content hash, then freeze so the pinned
// hash cannot drift. `policy_hash` and `profile_hash` are the same value under
// two names, so a relying party can pin a pack the same way it pins a profile.
for (const p of Object.values(packs)) {
    const h = computePolicyPackHash(p);
    p.policy_hash = h;
    p.profile_hash = h;
    Object.freeze(p);
}
export const POLICY_PACKS = Object.freeze(packs);
export const POLICY_PACK_IDS = Object.freeze(Object.keys(packs));
/** Fail-closed lookup: unknown pack id throws — never a silent default. */
export function getPolicyPack(id) {
    const p = POLICY_PACKS[id];
    if (!p)
        throw new Error(`unknown policy pack "${id}" (known: ${POLICY_PACK_IDS.join(', ')})`);
    return p;
}
/** True iff the pack's stamped policy_hash matches its recomputed content hash. */
export function verifyPolicyPackHash(pack) {
    try {
        return typeof pack?.policy_hash === 'string' && pack.policy_hash === computePolicyPackHash(pack);
    }
    catch {
        return false;
    }
}
