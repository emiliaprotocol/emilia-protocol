// SPDX-License-Identifier: Apache-2.0
// Generated from verify-live.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// Live cross-operator verification against EP Federation Operator 2.
//
// Operator 2 is a SEPARATELY-DEPLOYED EP operator — a Supabase Edge Function on
// a different project / region / infrastructure, with its own Ed25519 key —
// publishing its PIP-006 federation surfaces. This script is the relying party:
// it fetches a receipt Operator 2 signed, resolves Operator 2's published keys
// and revocation surface from Operator 2's OWN live origin, and verifies. It
// also confirms a tampered receipt is rejected even though the keys are live.
//
//   node conformance/operator2/verify-live.mjs
//
// This upgrades PIP-006 acceptance gate #1 from a self-hosted *synthetic*
// harness to two separately-deployed *live* operators cross-verifying. It is
// NOT the independent-third-party operator the gate ultimately wants (Operator 2
// is the same owner) — that remains the final external step. The artifact here
// is exactly what such a third party would stand up: see conformance/operator2/.
import { verifyFederatedReceipt } from '../../packages/verify/federation.js';
const BASE = process.argv[2] || 'https://kgknhhdqsykxcwzdfeim.supabase.co/functions/v1/operator2';
// Out-of-band trust anchor: the relying party pins Operator 2's known operator
// id AND binds its key SOURCE (PIP-006 — trust must be pinned by the verifier,
// never taken from the receipt-carried signer, and pinning the id alone does not
// authenticate WHERE the key comes from). The bound key_discovery origin must
// match the receipt's key_discovery, or verifyFederatedReceipt refuses to fetch
// a receipt-supplied URL and returns accepted:false (fail closed).
const OPERATOR2_ID = 'ep_operator_2_supabase_edge';
const TRUSTED_ISSUERS = { [OPERATOR2_ID]: { key_discovery: `${BASE}/.well-known/ep-keys.json` } };
let fail = 0;
const check = (name, ok) => { if (!ok)
    fail++; console.log(`  ${ok ? '✓' : '✗'} ${name}`); };
console.log(`\nEP Federation — live cross-operator verification vs Operator 2\n${BASE}\n`);
let receipt;
try {
    receipt = await (await fetch(`${BASE}/receipt`, { signal: AbortSignal.timeout(15000) })).json();
}
catch (e) {
    console.log(`✗ could not reach Operator 2 (${e.message})`);
    process.exit(1);
}
check('fetched a receipt Operator 2 issued', receipt?.signature?.signer);
// Verify it — the online path fetches Operator 2's ep-keys.json (from the
// receipt's key_discovery) and its verify-of-record (from the discovery doc's
// verify_url_template), all on Operator 2's own origin.
const r = await verifyFederatedReceipt(receipt, { fetchImpl: fetch, timeoutMs: 15000, trustedIssuers: TRUSTED_ISSUERS });
check('receipt verifies against Operator 2\'s published keys', r.verified === true);
check('signer is Operator 2', r.signer === receipt?.signature?.signer);
check('Operator 2\'s revocation surface was consulted', r.revocation_confirmed === true);
check('verdict = accepted (verified + not revoked)', r.accepted === true);
// Negative control: tamper the amount. A live-key fetch must NOT save a forgery.
const tampered = JSON.parse(JSON.stringify(receipt));
tampered.payload.action.amount = 999_999_999;
const t = await verifyFederatedReceipt(tampered, { fetchImpl: fetch, timeoutMs: 15000, trustedIssuers: TRUSTED_ISSUERS });
check('a tampered receipt is rejected (no trust laundering)', t.accepted === false);
console.log('');
if (fail) {
    console.log(`✗ FAIL — ${fail} check(s) failed\n`);
    process.exit(1);
}
console.log('✓ PASS — two separately-deployed operators cross-verify live (Operator 2 → relying party)\n');
