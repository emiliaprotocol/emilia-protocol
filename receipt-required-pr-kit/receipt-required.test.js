// SPDX-License-Identifier: Apache-2.0
// Generated from receipt-required.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// RR-1 conformance plus the default-closed and binding properties, proved on
// every push so the claim can't go stale. Run: `npm test` (node --test).
//
//   1. missing receipt  -> 428 Receipt Required
//   2. valid receipt    -> the action runs (200)
//   3. replayed receipt -> refused (one-time consumption)
//   4. forged receipt   -> refused (signature / action-binding fails)
//
// and, because absence of a rule is not a safe default:
//
//   5. a tool the manifest does not name -> refused, never run
//   6. any argument the receipt did not cover -> refused
//   7. NODE_ENV=production ignores the inline-key demo escape
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { approvalActionHash, receiptRequiredConformance, validateActionRiskManifest } from '@emilia-protocol/require-receipt';
import { dispatch, receiptRequestFor } from './example-dangerous-action.js';
// The demo proof minter lives in its own demo-only module and is NOT exported
// by the guarded action module. A template that hands callers a Class-A proof
// minter hands them the signoff the gate exists to demand.
import { createDemoClassAAssuranceProof } from './demo-approver.js';
const HERE = dirname(fileURLToPath(import.meta.url));
const MANIFEST = JSON.parse(readFileSync(resolve(HERE, 'agent-actions.json'), 'utf8'));
const PACKAGE_METADATA = JSON.parse(readFileSync(resolve(HERE, 'package.json'), 'utf8'));
test('kit pins the current receipt gate release line', () => {
    assert.equal(PACKAGE_METADATA.dependencies['@emilia-protocol/require-receipt'], '^0.8.1');
});
test('the shipped manifest satisfies the author-time floors', () => {
    const result = validateActionRiskManifest(MANIFEST);
    assert.deepEqual(result.errors, []);
    assert.equal(result.ok, true);
});
// These conformance checks are self-contained: each receipt is minted with a
// fresh key, so we run the gate in explicit NON-PRODUCTION inline mode. In
// production you pin EMILIA_TRUSTED_KEYS instead (see the fail-closed test below,
// which proves the secure default refuses a destructive action with no trusted
// key configured).
process.env.EMILIA_ALLOW_INLINE_KEY = '1';
// Byte-identical to @emilia-protocol/verify's EP-RECEIPT-v1 canonicalization.
const canonicalize = (v) => (v === null || v === undefined ? JSON.stringify(v)
    : Array.isArray(v) ? `[${v.map(canonicalize).join(',')}]`
        : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`
            : JSON.stringify(v));
/**
 * What a receipt for this exact call must say. The dispatcher binds the WHOLE
 * argument object, so the approval names the tool, every argument, and the
 * material fields the manifest pins.
 */
function approvalFor(tool, args) {
    const request = receiptRequestFor(tool, args);
    assert.ok(request, `expected a manifest entry for ${tool}`);
    return request;
}
// Mint a FRESH valid EP-RECEIPT-v1 bound to `request`, signed by a named human's
// device key. (In production this is a real Face ID / passkey signoff; here it's
// node:crypto so the test is self-contained and needs no EMILIA backend.)
function issueReceiptFor(request, { withAssurance = true, claimExtras = {} } = {}) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const pub = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const payload = {
        receipt_id: 'rcpt_' + crypto.randomBytes(6).toString('hex'),
        subject: 'agent:autonomous',
        created_at: new Date().toISOString(),
        claim: {
            action_type: request.action_type,
            outcome: 'allow_with_signoff',
            approver: 'jane.doe@yourco.example',
            canonical_action: request.canonical_action,
            action_hash: approvalActionHash(request.canonical_action),
            ...claimExtras,
        },
    };
    if (withAssurance)
        payload.assurance_proof = createDemoClassAAssuranceProof(payload);
    const value = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey).toString('base64url');
    return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value }, public_key: pub };
}
test('RR-1: missing -> 428, valid -> runs, replay -> refused, forged -> refused', async () => {
    const request = approvalFor('delete_all_records', { table: 'customers' });
    const result = await receiptRequiredConformance({
        dispatch,
        tool: 'delete_all_records',
        args: { table: 'customers' },
        // The receipt is bound to the WHOLE call, not just the action type and not
        // just one convenient field: <action_type>:sha256:<hash of tool + args>.
        action: request.action_type,
        issueReceipt: () => issueReceiptFor(request),
        manifest: MANIFEST,
    });
    assert.equal(result.checks.manifest_valid, true, 'the shipped manifest should validate');
    assert.equal(result.checks.challenge_on_missing, true, 'missing receipt should return 428');
    assert.equal(result.checks.runs_on_valid, true, 'valid receipt should run the action');
    assert.equal(result.checks.replay_refused, true, 'replayed receipt should be refused');
    assert.equal(result.checks.forged_refused, true, 'forged receipt should be refused');
    assert.equal(result.level, 'RR-1', `expected RR-1, got ${result.level} (${JSON.stringify(result.detail)})`);
});
test('cross-target binding: a receipt for one table cannot wipe another', async () => {
    // Mint a receipt that authorizes wiping the "customers" table only.
    const customers = approvalFor('delete_all_records', { table: 'customers' });
    // Sanity: it works on its own target.
    const onTarget = await dispatch('delete_all_records', { table: 'customers' }, issueReceiptFor(customers));
    assert.equal(onTarget.status, 200, 'receipt should run against its bound table');
    // Same action type, DIFFERENT table -> must be refused (action_mismatch), and
    // the rejection must be sanitized to just a reason code.
    const offTarget = await dispatch('delete_all_records', { table: 'orders' }, issueReceiptFor(customers));
    assert.notEqual(offTarget.status, 200, 'a customers receipt must not wipe orders');
    assert.equal(offTarget.body.rejected.reason, 'action_mismatch', 'cross-target refusal should be action_mismatch');
    assert.deepEqual(Object.keys(offTarget.body.rejected), ['reason'], 'rejection must be sanitized to { reason } only');
});
test('one-time consumption: a completed action cannot reuse its receipt', async () => {
    const inventory = approvalFor('delete_all_records', { table: 'inventory' });
    const receipt = issueReceiptFor(inventory);
    // First call succeeds and consumes the receipt.
    const first = await dispatch('delete_all_records', { table: 'inventory' }, receipt);
    assert.equal(first.status, 200);
    // Replaying the now-consumed receipt is refused.
    const replay = await dispatch('delete_all_records', { table: 'inventory' }, receipt);
    assert.notEqual(replay.status, 200, 'consumed receipt should be refused on replay');
    assert.equal(replay.body.rejected.reason, 'replay_refused');
});
test('DEFAULT CLOSED: a tool the manifest does not name is refused, never run', async () => {
    for (const [tool, args] of [
        ['delete_all_records_v2', { table: 'customers', cascade: true }],
        ['drop_database', { db: 'prod' }],
    ]) {
        const res = await dispatch(tool, args, null);
        assert.equal(res.status, 403, `${tool} must not pass through unguarded`);
        assert.equal(res.body.rejected.reason, 'action_not_in_manifest');
        assert.notEqual(res.body.ran, true, `${tool} must not have executed`);
    }
});
test('DEFAULT CLOSED: manifest selectors are case-sensitive and the mismatch is explicit', async () => {
    const res = await dispatch('DELETE_ALL_RECORDS', { table: 'customers' }, null);
    assert.equal(res.status, 403, 'a case-mismatched tool name must not bypass the gate');
    assert.equal(res.body.rejected.reason, 'action_not_in_manifest');
    assert.match(res.body.detail, /case-sensitive/);
    assert.match(res.body.detail, /mcp\.delete_all_records/);
    assert.notEqual(res.body.ran, true);
});
test('an explicit receipt_required: false entry still passes through', async () => {
    const res = await dispatch('list_tables', { schema: 'public' }, null);
    assert.equal(res.status, 200, 'an author-declared reversible tool should run');
    assert.equal(res.body.ran, true);
});
test('full-argument binding: an argument the approval did not cover is refused', async () => {
    // The approval covers { table: 'customers' }. The call also carries a WHERE
    // clause, a cascade, a region, and a hard delete.
    const approval = approvalFor('delete_all_records', { table: 'customers' });
    const res = await dispatch('delete_all_records', {
        table: 'customers', where: '1=1', cascade: true, region: 'prod-eu', hard_delete: true,
    }, issueReceiptFor(approval));
    assert.notEqual(res.status, 200, 'unapproved arguments must not ride along');
    assert.equal(res.body.rejected.reason, 'action_mismatch');
    assert.notEqual(res.body.ran, true);
});
test('a call missing the pinned material field cannot degrade to the bare action', async () => {
    // No `table` at all. The manifest pins execution_binding.required_fields:
    // ['table'], so there is no signed canonical action that can satisfy this.
    const approval = receiptRequestFor('delete_all_records', { everything: true });
    const res = await dispatch('delete_all_records', { everything: true }, issueReceiptFor(approval));
    assert.notEqual(res.status, 200, 'a call with no bound target must not run');
    assert.equal(res.body.rejected.reason, 'signed_action_required_field_missing');
    assert.notEqual(res.body.ran, true);
});
test('the executed payload is the snapshot the receipt was bound to, not the caller object', async () => {
    const args = { table: 'toctou' };
    const approval = approvalFor('delete_all_records', args);
    const pending = dispatch('delete_all_records', args, issueReceiptFor(approval));
    // Mutate the caller-owned object while the gate is awaiting verification.
    args.table = 'attacker-choice';
    args.hard_delete = true;
    const res = await pending;
    assert.equal(res.status, 200);
    assert.equal(res.body.table, 'toctou', 'execution must use the bound snapshot');
    assert.equal(res.body.hard_delete, undefined, 'a field added after binding must not execute');
});
test('secure default: enforcement on with NO trusted key fails closed (does not run)', async () => {
    // Simulate production posture: no inline opt-in, no pinned issuer keys.
    const prevInline = process.env.EMILIA_ALLOW_INLINE_KEY;
    const prevKeys = process.env.EMILIA_TRUSTED_KEYS;
    delete process.env.EMILIA_ALLOW_INLINE_KEY;
    delete process.env.EMILIA_TRUSTED_KEYS;
    try {
        // Even a well-formed receipt must NOT run the destructive action when no
        // issuer key is trusted — accepting a self-signed receipt here would be the
        // exact unsafe default we refuse to ship.
        const approval = approvalFor('delete_all_records', { table: 'customers' });
        const res = await dispatch('delete_all_records', { table: 'customers' }, issueReceiptFor(approval));
        assert.notEqual(res.status, 200, 'destructive action must not run without a trusted key');
        assert.equal(res.body.rejected.reason, 'receipt_enforcement_misconfigured');
        assert.notEqual(res.body.ran, true, 'the action must not have executed');
    }
    finally {
        if (prevInline === undefined)
            delete process.env.EMILIA_ALLOW_INLINE_KEY;
        else
            process.env.EMILIA_ALLOW_INLINE_KEY = prevInline;
        if (prevKeys === undefined)
            delete process.env.EMILIA_TRUSTED_KEYS;
        else
            process.env.EMILIA_TRUSTED_KEYS = prevKeys;
    }
});
test('NODE_ENV=production ignores the inline-key demo escape', async () => {
    const prevEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    process.env.EMILIA_ALLOW_INLINE_KEY = '1';
    try {
        const approval = approvalFor('delete_all_records', { table: 'customers' });
        const res = await dispatch('delete_all_records', { table: 'customers' }, issueReceiptFor(approval));
        assert.notEqual(res.status, 200, 'a production image must not honour the demo escape');
        assert.equal(res.body.rejected.reason, 'receipt_enforcement_misconfigured');
        assert.notEqual(res.body.ran, true);
    }
    finally {
        if (prevEnv === undefined)
            delete process.env.NODE_ENV;
        else
            process.env.NODE_ENV = prevEnv;
        process.env.EMILIA_ALLOW_INLINE_KEY = '1';
    }
});
test('presenter labels cannot elevate a software receipt to Class-A', async () => {
    const approval = approvalFor('delete_all_records', { table: 'label-test' });
    const receipt = issueReceiptFor(approval, {
        withAssurance: false,
        claimExtras: {
            assurance_class: 'class_a',
            human_present: true,
            quorum: { threshold: 2, signers: ['alice', 'bob'] },
        },
    });
    const res = await dispatch('delete_all_records', { table: 'label-test' }, receipt);
    assert.notEqual(res.status, 200, 'receipt-supplied assurance labels must not run the action');
    assert.equal(res.body.rejected.reason, 'assurance_proof_required');
});
test('production posture fails closed when the approver trust inputs are absent', async () => {
    const approval = approvalFor('delete_all_records', { table: 'assurance-config' });
    const receipt = issueReceiptFor(approval);
    const previous = {
        inline: process.env.EMILIA_ALLOW_INLINE_KEY,
        keys: process.env.EMILIA_TRUSTED_KEYS,
        approvers: process.env.EMILIA_APPROVER_KEYS_JSON,
        rpId: process.env.EMILIA_RP_ID,
        origins: process.env.EMILIA_ALLOWED_ORIGINS,
    };
    delete process.env.EMILIA_ALLOW_INLINE_KEY;
    process.env.EMILIA_TRUSTED_KEYS = receipt.public_key;
    delete process.env.EMILIA_APPROVER_KEYS_JSON;
    delete process.env.EMILIA_RP_ID;
    delete process.env.EMILIA_ALLOWED_ORIGINS;
    try {
        const res = await dispatch('delete_all_records', { table: 'assurance-config' }, receipt);
        assert.notEqual(res.status, 200, 'missing approver trust inputs must refuse');
        assert.equal(res.body.rejected.reason, 'receipt_assurance_misconfigured');
    }
    finally {
        const restore = (name, value) => {
            if (value === undefined)
                delete process.env[name];
            else
                process.env[name] = value;
        };
        restore('EMILIA_ALLOW_INLINE_KEY', previous.inline);
        restore('EMILIA_TRUSTED_KEYS', previous.keys);
        restore('EMILIA_APPROVER_KEYS_JSON', previous.approvers);
        restore('EMILIA_RP_ID', previous.rpId);
        restore('EMILIA_ALLOWED_ORIGINS', previous.origins);
    }
});
