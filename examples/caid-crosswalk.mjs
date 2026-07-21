#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from caid-crosswalk.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * CAID crosswalk — running code for the thin Canonical Action Identifier +
 * evidence-composition layer split out of the EP ceremony stack. ONE underlying
 * commerce action; THREE heterogeneous authorization legs, each digesting the
 * purchase in its OWN native form:
 *   Leg A — EP: sha256 over the RFC 8785 (JCS) canonical action. That digest
 *           IS the CAID.
 *   Leg B — an AP2-shaped cart mandate: an SD-JWT-style signed object carrying
 *           its own checkout digest over its own cart schema. AP2-shaped,
 *           illustrating the join; NOT a conformant AP2 implementation.
 *   Leg C — a SCITT-style signed statement whose subject is a digest of the
 *           same action (illustrative statement shape, not COSE_Sign1).
 * No leg ingests another leg's evidence into its trust boundary. Each leg's
 * ISSUER signs a digest-binding record — "my native digest D_leg binds
 * underlying action digest D_caid" — and the relying party composes the legs
 * offline through verifyAuthorizationChain with pluggable per-leg verifiers,
 * its own pinned requirement (all three legs), and expectedActionDigest = the
 * CAID. The shared action digest is the ONLY join point. Fully offline.
 * Run: node examples/caid-crosswalk.mjs
 */
import crypto from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { canonicalize } from '../packages/verify/index.js';
import { AEC_VERSION, actionDigest, verifyAuthorizationChain } from '../packages/verify/evidence-chain.js';
const canon = canonicalize;
const sha256hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const b64uJson = (o) => Buffer.from(JSON.stringify(o), 'utf8').toString('base64url');
const hexOf = (d) => (typeof d === 'string' && /^sha256:[0-9a-f]{64}$/.test(d) ? d.slice(7) : null);
// ── The ONE underlying commerce action all three legs authorize ──────────────
export const ACTION = {
    ep_version: '1.0',
    action_type: 'commerce.checkout',
    merchant: 'merchant:aurora-outfitters',
    item: 'sku:AO-TRAIL-JACKET-M',
    amount: '184.00',
    currency: 'USD',
    requested_at: '2026-07-12T09:30:00Z',
};
/** The Canonical Action Identifier: sha256 hex over the JCS canonical action. */
export const CAID = actionDigest(ACTION);
// A second, genuinely authorized purchase — raw material for the splice attack.
export const OTHER_ACTION = { ...ACTION, item: 'sku:AO-WOOL-BEANIE', amount: '24.00', requested_at: '2026-07-11T18:02:00Z' };
// ── Leg issuers (each leg signs with its OWN key; the RP pins each SPKI) ─────
const epIssuer = crypto.generateKeyPairSync('ed25519');
const ap2Merchant = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const scittIssuer = crypto.generateKeyPairSync('ed25519');
const spki = (kp) => kp.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
const pubKey = (b64u) => crypto.createPublicKey({ key: Buffer.from(b64u, 'base64url'), format: 'der', type: 'spki' });
const edSign = (kp) => (bytes) => crypto.sign(null, bytes, kp.privateKey).toString('base64url');
const es256Sign = (kp) => (bytes) => crypto.sign('sha256', bytes, { key: kp.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
const edVerify = (spkiB64u) => (bytes, sig) => {
    try {
        return crypto.verify(null, bytes, pubKey(spkiB64u), Buffer.from(sig, 'base64url'));
    }
    catch {
        return false;
    }
};
const es256Verify = (spkiB64u) => (bytes, sig) => {
    try {
        return crypto.verify('sha256', bytes, { key: pubKey(spkiB64u), dsaEncoding: 'ieee-p1363' }, Buffer.from(sig, 'base64url'));
    }
    catch {
        return false;
    }
};
// Relying-party trust anchors, one per leg role (no flat global key bag).
const PINNED = { ep: spki(epIssuer), ap2: spki(ap2Merchant), scitt: spki(scittIssuer) };
// ── The join: a signed digest-binding record per leg ─────────────────────────
// "This leg's native digest D_leg binds underlying action digest D_caid",
// signed by the LEG'S OWN issuer over both digests. Nobody re-verifies another
// leg's evidence; the CAID is the only shared coordinate.
export function mintBinding({ leg, legDigestHex, caidHex, issuedAt, sign }) {
    const body = { '@type': 'EP-CAID-BINDING-v1', leg, leg_digest: 'sha256:' + legDigestHex, caid: 'sha256:' + caidHex, issued_at: issuedAt };
    return { ...body, signature: sign(Buffer.from(canon(body), 'utf8')) };
}
function checkBinding(binding, leg, legDigestHex, verify) {
    if (binding?.['@type'] !== 'EP-CAID-BINDING-v1' || binding.leg !== leg)
        return null;
    const legD = hexOf(binding.leg_digest);
    const caid = hexOf(binding.caid);
    if (!legD || !caid || legD !== legDigestHex)
        return null;
    const { signature, ...body } = binding;
    return typeof signature === 'string' && verify(Buffer.from(canon(body), 'utf8'), signature) ? caid : null;
}
// ── Leg A: EP — the JCS action digest is native; D_leg == D_caid ─────────────
export function mintEpLeg(action) {
    const d = actionDigest(action);
    // Clone: the chain document also carries the action at top level, and the
    // verifier's JSON safety profile rejects repeated object references.
    return { action: structuredClone(action), binding: mintBinding({ leg: 'ep-action', legDigestHex: d, caidHex: d, issuedAt: action.requested_at, sign: edSign(epIssuer) }) };
}
// ── Leg B: AP2-SHAPED cart mandate ───────────────────────────────────────────
// AP2-shaped, illustrating the join; NOT a conformant AP2 implementation. The
// point illustrated: the mandate digests the purchase in AP2's OWN cart schema
// and canonical form (JCS stands in for the real stack's), so its checkout
// digest is a DIFFERENT digest of the SAME purchase — exactly the crosswalk
// the binding record performs.
export function mintAp2Leg(purchase) {
    const cart = {
        contents: {
            id: 'cart_' + sha256hex(canon(purchase)).slice(0, 16),
            merchant_name: purchase.merchant,
            payment_request: { details: {
                    display_items: [{ label: purchase.item, amount: { currency: purchase.currency, value: purchase.amount } }],
                    total: { amount: { currency: purchase.currency, value: purchase.amount } },
                } },
        },
        timestamp: purchase.requested_at,
    };
    const checkoutDigestHex = sha256hex(canon(cart)); // the mandate's OWN checkout digest
    const header = { alg: 'ES256', typ: 'sd-jwt' };
    const payload = { iss: 'https://merchant.example', iat: Math.floor(Date.parse(purchase.requested_at) / 1000), cart_hash: 'sha256:' + checkoutDigestHex };
    const signingInput = b64uJson(header) + '.' + b64uJson(payload);
    return {
        cart,
        cart_mandate: signingInput + '.' + es256Sign(ap2Merchant)(Buffer.from(signingInput, 'utf8')),
        binding: mintBinding({ leg: 'ap2-cart-mandate', legDigestHex: checkoutDigestHex, caidHex: actionDigest(purchase), issuedAt: purchase.requested_at, sign: es256Sign(ap2Merchant) }),
    };
}
// ── Leg C: SCITT-style signed statement ──────────────────────────────────────
// Illustrative statement shape (JSON, not COSE_Sign1): protected headers with
// issuer + subject, a payload, and a signature over the canonical pair. The
// SUBJECT is a digest of the same action; the leg's NATIVE digest is the digest
// of the signed statement itself (what a transparency service would register).
export function mintScittLeg(purchase) {
    const caidHex = actionDigest(purchase);
    const payload = { action_digest: 'sha256:' + caidHex, registered_by: 'agent:checkout-runner' };
    const protectedHeaders = { alg: 'EdDSA', issuer: 'did:web:ledger.example', subject: 'sha256:' + caidHex, content_type: 'application/json' };
    const signature = edSign(scittIssuer)(Buffer.from(canon({ payload, protected: protectedHeaders }), 'utf8'));
    const statement = { protected: protectedHeaders, payload, signature };
    return { statement, binding: mintBinding({ leg: 'scitt-statement', legDigestHex: sha256hex(canon(statement)), caidHex, issuedAt: purchase.requested_at, sign: edSign(scittIssuer) }) };
}
// ── Pluggable per-leg verifiers (how a leg plugs into EP-AEC) ────────────────
// Each verifies its leg's native evidence under its own rules, then the binding
// record's signature, and attests binding.caid. The CHAIN — not the leg —
// enforces that every attested caid equals the relying party's expected digest.
const NO = { valid: false, action_digest: null };
export const crosswalkVerifiers = {
    'ep-action': (ev) => {
        try {
            const d = actionDigest(ev.action);
            const caid = checkBinding(ev.binding, 'ep-action', d, edVerify(PINNED.ep));
            return caid === d ? { valid: true, action_digest: 'sha256:' + caid } : NO; // EP's native digest IS the CAID
        }
        catch {
            return NO;
        }
    },
    'ap2-cart-mandate': (ev) => {
        try {
            const parts = typeof ev.cart_mandate === 'string' ? ev.cart_mandate.split('.') : [];
            if (parts.length !== 3)
                return NO;
            const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
            const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
            if (header.alg !== 'ES256' || !es256Verify(PINNED.ap2)(Buffer.from(parts[0] + '.' + parts[1], 'utf8'), parts[2]))
                return NO;
            const checkoutDigestHex = sha256hex(canon(ev.cart));
            if (payload.cart_hash !== 'sha256:' + checkoutDigestHex)
                return NO; // mandate must carry the presented cart's own digest
            const caid = checkBinding(ev.binding, 'ap2-cart-mandate', checkoutDigestHex, es256Verify(PINNED.ap2));
            return caid ? { valid: true, action_digest: 'sha256:' + caid } : NO;
        }
        catch {
            return NO;
        }
    },
    'scitt-statement': (ev) => {
        try {
            const { signature, ...unsigned } = ev.statement; // { protected, payload }
            if (ev.statement.protected?.alg !== 'EdDSA'
                || !edVerify(PINNED.scitt)(Buffer.from(canon(unsigned), 'utf8'), signature))
                return NO;
            const caid = checkBinding(ev.binding, 'scitt-statement', sha256hex(canon(ev.statement)), edVerify(PINNED.scitt));
            if (!caid || ev.statement.protected.subject !== 'sha256:' + caid)
                return NO; // subject and binding must name the same action
            return { valid: true, action_digest: 'sha256:' + caid };
        }
        catch {
            return NO;
        }
    },
};
// ── Compose ──────────────────────────────────────────────────────────────────
export const REQUIREMENT = 'ep-action AND ap2-cart-mandate AND scitt-statement';
/**
 * @param {object} legs
 * @param {any} [legs.epLeg]
 * @param {any} [legs.ap2Leg]
 * @param {any} [legs.scittLeg]
 * @param {any} [action]
 */
export function buildCrosswalkChain({ epLeg, ap2Leg, scittLeg }, action = ACTION) {
    const components = [];
    if (epLeg)
        components.push({ type: 'ep-action', label: 'EP canonical action digest', evidence: epLeg });
    if (ap2Leg)
        components.push({ type: 'ap2-cart-mandate', label: 'AP2-shaped cart mandate', evidence: ap2Leg });
    if (scittLeg)
        components.push({ type: 'scitt-statement', label: 'SCITT-style signed statement', evidence: scittLeg });
    return { '@version': AEC_VERSION, action, action_digest: 'sha256:' + actionDigest(action), requirement: REQUIREMENT, components };
}
/** Relying-party call: pins its OWN requirement and its OWN expected CAID. */
export function verifyCrosswalk(chain, expectedCaidHex = CAID) {
    return verifyAuthorizationChain(chain, { verifiers: crosswalkVerifiers, requirement: REQUIREMENT, expectedActionDigest: expectedCaidHex });
}
// ── Scenarios ────────────────────────────────────────────────────────────────
export function genuineChain() {
    return buildCrosswalkChain({ epLeg: mintEpLeg(ACTION), ap2Leg: mintAp2Leg(ACTION), scittLeg: mintScittLeg(ACTION) });
}
/** (a) Cross-binding splice: a genuinely signed AP2 leg from a DIFFERENT
 *  purchase is spliced under this action's chain. Every signature verifies;
 *  only the CAID equality catches it. */
export function splicedChain() {
    return buildCrosswalkChain({ epLeg: mintEpLeg(ACTION), ap2Leg: mintAp2Leg(OTHER_ACTION), scittLeg: mintScittLeg(ACTION) });
}
/** (b) A binding record whose signature does not verify (one flipped char). */
export function forgedBindingChain() {
    const chain = genuineChain();
    const binding = /** @type {{ evidence: { binding: { signature: string } } }} */ (chain.components.find((c) => c.type === 'scitt-statement')).evidence.binding;
    binding.signature = (binding.signature[0] === 'A' ? 'B' : 'A') + binding.signature.slice(1);
    return chain;
}
/** (c) Missing leg: the SCITT statement never arrives; requirement unmet. */
export function missingLegChain() {
    return buildCrosswalkChain({ epLeg: mintEpLeg(ACTION), ap2Leg: mintAp2Leg(ACTION) });
}
// ── Demo ─────────────────────────────────────────────────────────────────────
const C = { g: '\x1b[32m', r: '\x1b[31m', d: '\x1b[2m', b: '\x1b[1m', x: '\x1b[0m' };
function show(title, res, expectAllow) {
    console.log(`\n${C.b}${title}${C.x}`);
    for (const c of res.components)
        console.log(`  ${c.valid && c.bound ? C.g + '✓' : C.r + '✗'}${C.x} ${c.label} ${C.d}(${c.type})${c.reason ? ' — ' + c.reason : ''}${C.x}`);
    const asExpected = res.allow === expectAllow;
    console.log(`  ${res.allow ? C.g + 'ALLOW' : C.r + 'DENY'}${C.x} ${C.d}— action ${res.action_digest?.slice(0, 24)}…${C.x}${asExpected ? '' : ` ${C.r}(UNEXPECTED)${C.x}`}`);
    if (!res.allow)
        res.reasons.forEach((x) => console.log(`    ${C.d}· ${x}${C.x}`));
    if (!asExpected)
        process.exitCode = 1;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    console.log(`${C.b}CAID crosswalk${C.x} ${C.d}(one action, three native digests, one join point)${C.x}`);
    const legA = mintEpLeg(ACTION), legB = mintAp2Leg(ACTION), legC = mintScittLeg(ACTION);
    console.log(`  ${C.d}CAID (JCS action digest)         ${C.x} ${CAID.slice(0, 32)}…`);
    console.log(`  ${C.d}Leg A native digest (EP)         ${C.x} ${hexOf(legA.binding.leg_digest).slice(0, 32)}… ${C.d}== CAID${C.x}`);
    console.log(`  ${C.d}Leg B native digest (AP2-shaped) ${C.x} ${hexOf(legB.binding.leg_digest).slice(0, 32)}… ${C.d}(its own cart form)${C.x}`);
    console.log(`  ${C.d}Leg C native digest (SCITT-style)${C.x} ${hexOf(legC.binding.leg_digest).slice(0, 32)}… ${C.d}(statement digest)${C.x}`);
    show('1. Genuine crosswalk (all three legs bind the same CAID)', verifyCrosswalk(genuineChain()), true);
    show('2. Cross-binding splice (AP2 leg minted for a different purchase)', verifyCrosswalk(splicedChain()), false);
    show('3. Forged binding record (binding signature does not verify)', verifyCrosswalk(forgedBindingChain()), false);
    show('4. Missing leg (no SCITT statement; requirement unmet)', verifyCrosswalk(missingLegChain()), false);
    console.log('');
}
