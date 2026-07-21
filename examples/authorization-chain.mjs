#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from authorization-chain.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * EP-AEC-v1 demo — composing heterogeneous agent-authorization receipts into ONE
 * offline ALLOW/DENY. A real EP distinct-human quorum (the human leg no other
 * effort supplies) + a policy-permit leg (stands in for draft-lee-orprg-permit-
 * receipts / a DRP delegation; verified here by a pluggable verifier). The chain
 * checks BOTH bind the same canonical action, then evaluates a fail-closed
 * requirement. Fully offline. Run: node examples/authorization-chain.mjs
 */
import crypto from 'node:crypto';
import { canonicalize } from '../packages/verify/index.js';
import { verifyAuthorizationChain } from '../packages/verify/evidence-chain.js';
const canon = canonicalize;
const sha256hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
// ── The high-risk action every leg must authorize ───────────────────────────
const ACTION = {
    ep_version: '1.0',
    action_type: 'disbursement.release',
    target: { system: 'erp.ap', resource: 'po/CAP-2026-0042' },
    parameters: { amount: '1850000.00', currency: 'USD', payee: 'Meridian Imaging Systems' },
    initiator: 'ep:agent:procurement-bot',
    policy_id: 'org:policy:capital-dual-control@v2',
    requested_at: '2026-02-03T17:41:09Z',
};
const ACTION_HASH = sha256hex(canon(ACTION));
// ── Mint a real ES256/WebAuthn device approval bound to the action ───────────
const POLICY_ID = ACTION.policy_id;
function approveOnDevice({ role, approver, issuedAt }) {
    const signer = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const context = {
        ep_version: '1.0', context_type: 'ep.signoff.v1', action_hash: ACTION_HASH, policy: POLICY_ID,
        nonce: 'sig_' + crypto.randomBytes(16).toString('hex'), approver, initiator: ACTION.initiator,
        issued_at: issuedAt, expires_at: '2026-02-06T18:00:00.000Z',
    };
    const challenge = crypto.createHash('sha256').update(canon(context), 'utf8').digest().toString('base64url');
    const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://www.emiliaprotocol.ai' }), 'utf8');
    const authData = Buffer.concat([crypto.createHash('sha256').update('emiliaprotocol.ai', 'utf8').digest(), Buffer.from([0x05]), Buffer.from([0, 0, 0, 9])]);
    const signed = Buffer.concat([authData, crypto.createHash('sha256').update(clientData).digest()]);
    const signature = crypto.sign('sha256', signed, signer.privateKey).toString('base64url');
    return {
        role, approver_public_key: signer.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
        signoff: { '@type': 'ep.signoff', context, webauthn: { authenticator_data: authData.toString('base64url'), client_data_json: clientData.toString('base64url'), signature } },
    };
}
const quorum = {
    '@type': 'ep.quorum', action_hash: ACTION_HASH,
    policy: { mode: 'threshold', required: 2, distinct_humans: true, window_sec: 172800,
        approvers: [{ role: 'department_director', approver: 'ep:approver:dir_alvarez' }, { role: 'cfo', approver: 'ep:approver:cfo_whitfield' }] },
    members: [approveOnDevice({ role: 'department_director', approver: 'ep:approver:dir_alvarez', issuedAt: '2026-02-03T17:55:00.000Z' }),
        approveOnDevice({ role: 'cfo', approver: 'ep:approver:cfo_whitfield', issuedAt: '2026-02-04T10:12:00.000Z' })],
};
// ── A policy-permit leg (stands in for Permit Receipts / a DRP delegation) ───
// Illustrative: a signed object asserting policy ALLOWed this exact action.
const permitKey = crypto.generateKeyPairSync('ed25519');
function mintPermit(actionDigestStr) {
    const body = { '@type': 'policy.permit', action_digest: actionDigestStr, decision: 'ALLOW', policy_epoch: 'epoch-2026-02', issued_at: '2026-02-04T10:12:30Z' };
    const sig = crypto.sign(null, Buffer.from(canon(body), 'utf8'), permitKey.privateKey).toString('base64url');
    return { ...body, signature: sig, issuer_public_key: permitKey.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}
// Pluggable verifier for the permit leg (this is how DRP/Permit/ACTA plug in).
const permitVerifier = (ev) => {
    let ok = false;
    try {
        const { signature, issuer_public_key, ...body } = ev;
        const key = crypto.createPublicKey({ key: Buffer.from(issuer_public_key, 'base64url'), format: 'der', type: 'spki' });
        ok = crypto.verify(null, Buffer.from(canon(body), 'utf8'), key, Buffer.from(signature, 'base64url')) && body.decision === 'ALLOW';
    }
    catch {
        ok = false;
    }
    return { valid: ok, action_digest: ev.action_digest };
};
// ── Build the chain ──────────────────────────────────────────────────────────
const makeChain = (permitDigest) => ({
    '@version': 'EP-AEC-v1', action: ACTION, action_digest: 'sha256:' + ACTION_HASH,
    requirement: 'ep-quorum AND policy-permit',
    components: [
        { type: 'ep-quorum', label: 'two-person human authorization', evidence: quorum },
        { type: 'policy-permit', label: 'machine policy permit', evidence: mintPermit(permitDigest) },
    ],
});
// The relying party pins the entire acceptance profile: exact quorum policy,
// WebAuthn audience, signed context policy, and key -> approver -> role mapping.
const approvers = Object.fromEntries(quorum.members.map((m) => [m.approver_public_key, {
        public_key: m.approver_public_key,
        approver_id: m.signoff.context.approver,
        roles: [m.role],
        status: 'active',
        valid_from: '2026-01-01T00:00:00.000Z',
        valid_to: '2027-01-01T00:00:00.000Z',
        revoked_at: null,
    }]));
const opts = {
    verifiers: { 'policy-permit': permitVerifier },
    requirement: 'ep-quorum AND policy-permit',
    expectedActionDigest: ACTION_HASH,
    verificationTime: '2026-02-04T10:13:00.000Z',
    policiesByType: {
        'ep-quorum': {
            policy: quorum.policy,
            rp_id: 'emiliaprotocol.ai',
            context_policy: POLICY_ID,
            max_age_sec: 172800,
            registry_checked_at: '2026-02-04T10:12:30.000Z',
            max_registry_age_sec: 300,
            approvers,
        },
    },
};
const C = { g: '\x1b[32m', r: '\x1b[31m', d: '\x1b[2m', b: '\x1b[1m', x: '\x1b[0m' };
const show = (title, res) => {
    console.log(`\n${C.b}${title}${C.x}`);
    for (const c of res.components)
        console.log(`  ${c.valid && c.bound ? C.g + '✓' : C.r + '✗'}${C.x} ${c.label} ${C.d}(${c.type})${c.reason ? ' — ' + c.reason : ''}${C.x}`);
    console.log(`  ${res.allow ? C.g + 'ALLOW' : C.r + 'DENY'}${C.x} ${C.d}— action ${res.action_digest?.slice(0, 24)}…${C.x}`);
    if (!res.allow)
        res.reasons.forEach((x) => console.log(`    ${C.d}· ${x}${C.x}`));
};
console.log(`${C.b}EP-AEC — Authorization Evidence Chain${C.x} ${C.d}(offline composition of heterogeneous receipts)${C.x}`);
// 1) Both legs bind the same action → ALLOW.
show('1. Genuine chain (human quorum + policy permit, same action)', verifyAuthorizationChain(makeChain('sha256:' + ACTION_HASH), opts));
// 2) Permit leg binds a DIFFERENT action (e.g., reused from another PO) → DENY.
show('2. Permit leg bound to a different action (cross-binding attack)', verifyAuthorizationChain(makeChain('sha256:' + sha256hex('a different action')), opts));
// 3) Human leg required but absent → DENY (the human leg is load-bearing).
const noHuman = makeChain('sha256:' + ACTION_HASH);
noHuman.components = noHuman.components.filter((c) => c.type !== 'ep-quorum');
show('3. Human authorization missing (requirement unmet)', verifyAuthorizationChain(noHuman, opts));
console.log('');
