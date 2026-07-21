#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from observed-absence-vector.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// EP observed-absence statement — the ONLY way absence becomes evidence.
// A verifier attests that it performed a DEFINED search against DEFINED
// sources at a stated time and found no qualifying authorization. It attests
// the search and its emptiness — never a universal negative. Deterministic
// vector backing draft-schrock-scitt-authorization-evidence (Section 6).
// Run: node examples/scitt/observed-absence-vector.mjs
import crypto from 'node:crypto';
import { canonicalize } from '../../packages/verify/index.js';
const canon = (o) => Buffer.from(canonicalize(o), 'utf8');
const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const seed = crypto.createHash('sha256').update('ep:observed-absence-vector:v1').digest();
const key = crypto.createPrivateKey({ key: Buffer.concat([PKCS8, seed]), format: 'der', type: 'pkcs8' });
const pub = crypto.createPublicKey(key).export({ type: 'spki', format: 'der' }).toString('base64url');
export const statement = {
    typ: 'ep-observed-absence',
    action_digest: 'sha256:' + 'a'.repeat(64),
    search: {
        sources: ['https://ts.example/entries', 'local-receipt-store@2026-07-02'],
        query: 'authorization_receipt OR quorum_receipt bound to action_digest',
        as_of: '2026-07-02T12:00:00Z',
    },
    found: false,
    observer: 'verifier:relying-party.example',
};
export const signed = {
    payload: statement,
    sig: crypto.sign(null, canon(statement), key).toString('base64url'),
    observer_key: pub,
};
export function verifyObservedAbsence(doc, pinnedObserverKeys = []) {
    const checks = { structure: false, signature: false, observer_pinned: false };
    const p = doc?.payload;
    if (!p || p.typ !== 'ep-observed-absence' || p.found !== false
        || !p.search?.sources?.length || !p.search?.as_of || !p.action_digest) {
        return { verified: false, accepted: false, checks };
    }
    checks.structure = true;
    try {
        const k = crypto.createPublicKey({ key: Buffer.from(doc.observer_key, 'base64url'), type: 'spki', format: 'der' });
        checks.signature = crypto.verify(null, canon(p), k, Buffer.from(doc.sig, 'base64url'));
    }
    catch {
        checks.signature = false;
    }
    checks.observer_pinned = pinnedObserverKeys.includes(doc.observer_key);
    const verified = checks.structure && checks.signature;
    return { verified, accepted: verified && checks.observer_pinned, checks };
}
const pos = verifyObservedAbsence(signed, [pub]);
if (!pos.accepted)
    throw new Error('positive case failed');
const tampered = JSON.parse(JSON.stringify(signed));
tampered.payload.search.as_of = '2026-07-03T12:00:00Z';
if (verifyObservedAbsence(tampered, [pub]).verified)
    throw new Error('tamper not caught');
const asserted = { payload: { ...statement, search: undefined }, sig: signed.sig, observer_key: pub };
if (verifyObservedAbsence(asserted, [pub]).verified)
    throw new Error('absence-without-search accepted');
console.error('OBSERVED-ABSENCE VECTOR OK — search attested, tamper refused, bare assertion refused');
