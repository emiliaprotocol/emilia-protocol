// SPDX-License-Identifier: Apache-2.0
// Generated from generate-quorum.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// Generator for EP-QUORUM-v1 multi-party (M-of-N / ordered) approval conformance
// vectors. Each member is a REAL WebAuthn ECDSA P-256 assertion (distinct key per
// human) bound to a shared action_hash — so the vectors exercise the real verifier,
// not hand-crafted signatures. Adversarial battery: one negative per quorum
// predicate (threshold, distinct-humans, order, action-binding, window, signature,
// role). Run: node generate-quorum.mjs
import crypto from 'node:crypto';
import { writeFileSync } from 'node:fs';
const canon = (v) => v === null || v === undefined ? JSON.stringify(v)
    : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
        : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
            : JSON.stringify(v);
// One canonical $40M program-funding release — the action the whole quorum authorizes.
const ACTION = crypto.createHash('sha256')
    .update(canon({ amount: 40_000_000, currency: 'USD', target: 'program/aegis-1' }), 'utf8')
    .digest('hex');
const chainHash = (ctx) => crypto.createHash('sha256').update(canon(ctx), 'utf8').digest('hex');
// Mint one real member assertion. Bend exactly one thing per negative vector.
// prevContextHash !== null  -> bind this signoff to its predecessor (ordered chain).
// sharedSigner provided      -> reuse a device key across slots (distinct-keys negative).
/**
 * @param {{ role: string, approver: string, issuedAt: string, actionHash?: string,
 *   wrongKey?: boolean, malformSig?: boolean, prevContextHash?: string|null,
 *   sharedSigner?: { publicKey: import('node:crypto').KeyObject, privateKey: import('node:crypto').KeyObject }|null,
 *   initiator?: string, crossOrigin?: boolean }} params
 */
function member({ role, approver, issuedAt, actionHash = ACTION, wrongKey = false, malformSig = false, prevContextHash = null, sharedSigner = null, initiator = 'ent_agent_7', crossOrigin = false, } = {}) {
    const signer = sharedSigner || crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const verifierKey = wrongKey ? crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey : signer.publicKey;
    const context = {
        ep_version: '1.0', context_type: 'ep.signoff.v1',
        action_hash: actionHash,
        policy: 'policy_aegis_quorum',
        nonce: 'sig_' + crypto.randomBytes(16).toString('hex'),
        approver, initiator,
        issued_at: issuedAt, expires_at: '2026-06-11T01:00:00.000Z',
    };
    if (prevContextHash !== null)
        context.prev_context_hash = prevContextHash;
    const challenge = crypto.createHash('sha256').update(canon(context), 'utf8').digest().toString('base64url');
    const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://www.emiliaprotocol.ai', crossOrigin }), 'utf8');
    const authData = Buffer.concat([
        crypto.createHash('sha256').update('emiliaprotocol.ai', 'utf8').digest(),
        Buffer.from([0x05]), // UP + UV
        Buffer.from([0, 0, 0, 9]),
    ]);
    const signed = Buffer.concat([authData, crypto.createHash('sha256').update(clientData).digest()]);
    let signature = crypto.sign('sha256', signed, signer.privateKey).toString('base64url');
    if (malformSig)
        signature = Buffer.from('not-a-valid-ecdsa-signature').toString('base64url');
    return {
        role,
        approver_public_key: verifierKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
        signoff: {
            '@type': 'ep.signoff',
            context,
            webauthn: { authenticator_data: authData.toString('base64url'), client_data_json: clientData.toString('base64url'), signature },
        },
    };
}
// The eligible roster: role -> named human. (Neutral chain-of-command roles.)
const PO = { role: 'program_officer', approver: 'ep:approver:po_rivera' };
const AO = { role: 'authorizing_official', approver: 'ep:approver:ao_chen' };
const IG = { role: 'inspector_general', approver: 'ep:approver:ig_okafor' };
const ROSTER = [PO, AO, IG];
const t = (s) => `2026-06-11T00:0${s}:00.000Z`; // 0..5 minutes
const orderedPolicy = { mode: 'ordered', required: 3, approvers: ROSTER, distinct_humans: true, window_sec: 900 };
// STRONG ordered mode: order proven by a cryptographic chain (prev_context_hash),
// not by operator-asserted timestamps.
const orderedChainPolicy = { ...orderedPolicy, ordered_chain: true };
const thresholdPolicy = { mode: 'threshold', required: 2, approvers: ROSTER, distinct_humans: true, window_sec: 900 };
const orderedTwoOfThreePolicy = { ...orderedPolicy, required: 2, ordered_chain: true };
const V = [];
const add = (id, description, failure_class, valid, quorum) => V.push({ id, description, failure_class, expect: { valid }, quorum });
// Build an ordered member list where each signoff cryptographically commits, in
// its own signed context, to the hash of its predecessor's context — so order is
// proven by the signatures, not by timestamps. The first member carries no
// predecessor.
function chained(specs) {
    const out = [];
    let prev = null;
    for (const s of specs) {
        const m = member({ ...s, prevContextHash: prev });
        out.push(m);
        prev = chainHash(m.signoff.context);
    }
    return out;
}
// ACCEPT — a genuine ordered 3-party quorum over the exact action.
add('accept_ordered_3of3', 'Ordered quorum (strong chain): Program Officer -> Authorizing Official -> Inspector General, distinct humans, each signoff cryptographically chained to its predecessor, all bound to the action', 'accept', true, {
    '@type': 'ep.quorum', action_hash: ACTION, policy: orderedChainPolicy,
    members: chained([
        { ...PO, issuedAt: t(1) },
        { ...AO, issuedAt: t(2) },
        { ...IG, issuedAt: t(3) },
    ]),
});
// ACCEPT — ordered prefix 2-of-3. `required` is quorum size k in both
// threshold and ordered modes; ordered mode constrains which first k slots may
// satisfy it and proves their order with the predecessor chain.
add('accept_ordered_2of3', 'Ordered prefix quorum: the first 2 of 3 roster slots approve in order with a signed predecessor chain', 'accept', true, {
    '@type': 'ep.quorum', action_hash: ACTION, policy: orderedTwoOfThreePolicy,
    members: chained([
        { ...PO, issuedAt: t(1) },
        { ...AO, issuedAt: t(2) },
    ]),
});
// ACCEPT — threshold 2-of-3 (any two distinct eligible approvers).
add('accept_threshold_2of3', 'Threshold quorum: 2 of 3 eligible approvers sign the exact action', 'accept', true, {
    '@type': 'ep.quorum', action_hash: ACTION, policy: thresholdPolicy,
    members: [member({ ...PO, issuedAt: t(1) }), member({ ...IG, issuedAt: t(2) })],
});
add('reject_unknown_policy_mode', 'An unknown policy mode must not be silently interpreted as threshold', 'structural', false, {
    '@type': 'ep.quorum', action_hash: ACTION, policy: { ...thresholdPolicy, mode: 'advisory' },
    members: [member({ ...PO, issuedAt: t(1) }), member({ ...IG, issuedAt: t(2) })],
});
// REJECT — a signature made in a cross-origin ceremony is not admitted merely
// because its visible origin string appears in the allowlist.
add('reject_cross_origin_ceremony', 'One quorum member signed in a cross-origin WebAuthn ceremony', 'audience', false, {
    '@type': 'ep.quorum', action_hash: ACTION, policy: thresholdPolicy,
    members: [member({ ...PO, issuedAt: t(1), crossOrigin: true }), member({ ...IG, issuedAt: t(2) })],
});
// REJECT — under threshold (required 3, only 2 present).
add('reject_under_threshold', 'Only 2 of a required 3 approvers signed', 'threshold', false, {
    '@type': 'ep.quorum', action_hash: ACTION, policy: orderedPolicy,
    members: chained([{ ...PO, issuedAt: t(1) }, { ...AO, issuedAt: t(2) }]),
});
// REJECT — same human fills two slots (separation of duties).
add('reject_duplicate_human', 'The Program Officer also signs the Inspector General slot — one human, two slots', 'distinct-humans', false, {
    '@type': 'ep.quorum', action_hash: ACTION, policy: orderedPolicy,
    members: chained([
        { ...PO, issuedAt: t(1) },
        { ...AO, issuedAt: t(2) },
        { role: 'inspector_general', approver: PO.approver, issuedAt: t(3) },
    ]),
});
// REJECT — out of order (ordered mode; AO signs before PO in time).
add('reject_out_of_order', 'Ordered quorum signed out of sequence (times not strictly increasing in role order)', 'order', false, {
    '@type': 'ep.quorum', action_hash: ACTION, policy: orderedPolicy,
    members: chained([
        { ...PO, issuedAt: t(3) },
        { ...AO, issuedAt: t(2) },
        { ...IG, issuedAt: t(4) },
    ]),
});
// REJECT — one member signed a DIFFERENT action.
add('reject_action_mismatch', 'One approver signed a different action_hash than the quorum authorizes', 'action-binding', false, {
    '@type': 'ep.quorum', action_hash: ACTION, policy: orderedPolicy,
    members: chained([
        { ...PO, issuedAt: t(1) },
        { ...AO, issuedAt: t(2) },
        { ...IG, issuedAt: t(3), actionHash: 'f'.repeat(64) },
    ]),
});
// REJECT — window exceeded (signatures span > window_sec).
add('reject_expired_window', 'Signatures span longer than the policy window_sec', 'window', false, {
    '@type': 'ep.quorum', action_hash: ACTION,
    policy: { ...orderedPolicy, window_sec: 60 },
    members: chained([
        { ...PO, issuedAt: t(1) },
        { ...AO, issuedAt: t(2) },
        { ...IG, issuedAt: t(5) }, // 4 min span > 60s
    ]),
});
// REJECT — one bad signature (wrong key).
add('reject_one_bad_signature', 'One member assertion verifies against the wrong key', 'cryptographic', false, {
    '@type': 'ep.quorum', action_hash: ACTION, policy: orderedPolicy,
    members: chained([
        { ...PO, issuedAt: t(1) },
        { ...AO, issuedAt: t(2), wrongKey: true },
        { ...IG, issuedAt: t(3) },
    ]),
});
// REJECT — ineligible role/approver (not on the roster).
add('reject_wrong_role', 'A signer whose (role, approver) is not an eligible quorum slot', 'role', false, {
    '@type': 'ep.quorum', action_hash: ACTION, policy: thresholdPolicy,
    members: [
        member({ ...PO, issuedAt: t(1) }),
        member({ role: 'intern', approver: 'ep:approver:not_on_roster', issuedAt: t(2) }),
    ],
});
// REJECT — broken ordering chain. Every signature is valid, the order and times
// are correct, but the final signoff commits (inside its signed context) to the
// WRONG predecessor hash — so the cryptographic order chain does not link.
const bc0 = member({ ...PO, issuedAt: t(1) });
const bc1 = member({ ...AO, issuedAt: t(2), prevContextHash: chainHash(bc0.signoff.context) });
const bc2 = member({ ...IG, issuedAt: t(3), prevContextHash: '0'.repeat(64) }); // not the hash of bc1
add('reject_broken_chain', 'Strong-chain ordered quorum where the final signoff commits to the wrong predecessor hash — chain_linked fails though every signature is valid', 'chain', false, {
    '@type': 'ep.quorum', action_hash: ACTION, policy: orderedChainPolicy,
    members: [bc0, bc1, bc2],
});
// REJECT — two distinct approver identities backed by the SAME device key.
// distinct_humans passes by name, but one key cannot fill two slots.
const dupKey = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
add('reject_duplicate_key', 'Two distinct approver identities sign with the same device key — distinct_keys fails', 'distinct-keys', false, {
    '@type': 'ep.quorum', action_hash: ACTION, policy: thresholdPolicy,
    members: [
        member({ ...PO, issuedAt: t(1), sharedSigner: dupKey }),
        member({ ...IG, issuedAt: t(2), sharedSigner: dupKey }),
    ],
});
// REJECT — the action's INITIATOR is also a counted approver (separation of
// duties). The PO's own identity is reused as the initiator in every signed
// context, so a member who INITIATED the action also approves it. Every other
// predicate passes (valid signatures, distinct humans, distinct keys, eligible
// roles, threshold met, window); the ONLY failing check is initiator_excluded.
// The eligible roster INCLUDES the PO so roles_admitted is not the failing check.
const initiatorId = PO.approver;
add('reject_initiator_is_approver', 'The action initiator is also a counted approver — one party both initiates and approves (SoD violation)', 'initiator-excluded', false, {
    '@type': 'ep.quorum', action_hash: ACTION,
    policy: { mode: 'threshold', required: 2, approvers: ROSTER, distinct_humans: true, window_sec: 900 },
    members: [
        member({ ...PO, issuedAt: t(1), initiator: initiatorId }),
        member({ ...AO, issuedAt: t(2), initiator: initiatorId }),
    ],
});
// REJECT — distinct_humans DISABLED, yet a single device key fills two seats.
// distinct_humans:false switches OFF the by-name separation, but key-uniqueness
// is a cryptographic floor that holds UNCONDITIONALLY: one key in two counted
// seats is one signer, never a quorum. The initiator (ent_agent_7, the default)
// differs from both approvers so initiator_excluded passes; the ONLY failing
// check is distinct_keys.
const sharedNoDistinct = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
add('reject_distinct_humans_false_shared_key', 'distinct_humans:false with one device key across two seats — distinct_keys is unconditional and must still reject', 'distinct-keys', false, {
    '@type': 'ep.quorum', action_hash: ACTION,
    policy: { mode: 'threshold', required: 2, approvers: ROSTER, distinct_humans: false, window_sec: 900 },
    members: [
        member({ ...PO, issuedAt: t(1), sharedSigner: sharedNoDistinct }),
        member({ ...IG, issuedAt: t(2), sharedSigner: sharedNoDistinct }),
    ],
});
const suite = {
    suite: 'EP-QUORUM-v1',
    profile: 'Multi-party (M-of-N / ordered) human approval over EP-SIGNOFF-v1 members',
    vectors_version: '1.0.0',
    description: 'Adversarial conformance vectors for EP multi-party quorum approval. Each member is a real Class-A WebAuthn assertion; the quorum predicate (all-signatures-valid, action-binding, distinct-humans, distinct-keys, roles-admitted, threshold, order, chain-linked, window) is fail-closed. Ordered quorums chain each signoff to its predecessor (prev_context_hash) so order is proven cryptographically, not by timestamps. A conformant verifier MUST return expect.valid for every vector.',
    count: V.length,
    vectors: V,
};
writeFileSync(new URL('./quorum.v1.json', import.meta.url), JSON.stringify(suite, null, 2) + '\n');
console.log(`wrote quorum.v1.json — ${V.length} vectors`);
