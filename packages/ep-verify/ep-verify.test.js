// Generated from ep-verify.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * ep-verify CLI tests — run with `node --test`.
 * @license Apache-2.0
 *
 * Mints EP-RECEIPT-v1 documents with the same canon/makeKey/mint helper
 * pattern as packages/gate/gate.test.js, then drives the CLI end to end:
 * verify pass, tampered fail, wrong-key fail, malformed fail, and the
 * fail-closed no-keys refusal.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const CLI = join(dirname(fileURLToPath(import.meta.url)), 'cli.mjs');
// ── helpers (packages/gate/gate.test.js pattern) ─────────────────────────────
function canon(v) {
    if (v === null || v === undefined)
        return JSON.stringify(v);
    if (Array.isArray(v))
        return `[${v.map(canon).join(',')}]`;
    if (typeof v === 'object')
        return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`;
    return JSON.stringify(v);
}
function makeKey() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}
function mint(privateKey, payload) {
    const value = crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey).toString('base64url');
    return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value } };
}
let n = 0;
function receipt(privateKey, { action = 'payment.release', outcome = 'allow' } = {}) {
    const payload = {
        receipt_id: `rcpt_${++n}`, subject: 'agent:test', issuer: 'ep:org:test',
        created_at: new Date().toISOString(), claim: { action_type: action, outcome },
    };
    return mint(privateKey, payload);
}
// ── CLI driver ────────────────────────────────────────────────────────────────
function tempDir() {
    return mkdtempSync(join(tmpdir(), 'ep-verify-'));
}
function writeJson(dir, name, doc) {
    const p = join(dir, name);
    writeFileSync(p, JSON.stringify(doc, null, 2));
    return p;
}
function runCli(args) {
    const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
    const lines = r.stdout.trim().split('\n');
    let detail = null;
    try {
        detail = JSON.parse(lines[lines.length - 1]);
    }
    catch { /* non-JSON output */ }
    return { code: r.status, verdict: lines[0], detail, stdout: r.stdout, stderr: r.stderr };
}
// ── tests ─────────────────────────────────────────────────────────────────────
test('valid receipt + pinned issuer key -> VERIFIED, exit 0', () => {
    const { privateKey, pub } = makeKey();
    const dir = tempDir();
    const r = receipt(privateKey);
    const receiptPath = writeJson(dir, 'receipt.json', r);
    const keysPath = writeJson(dir, 'keys.json', { keys: [pub] });
    const out = runCli([receiptPath, '--keys', keysPath]);
    assert.equal(out.code, 0, out.stdout + out.stderr);
    assert.equal(out.verdict, 'VERIFIED');
    assert.equal(out.detail.result, 'VERIFIED');
    assert.equal(out.detail.reason, 'signature_verified_against_pinned_key');
    assert.equal(out.detail.receipt_id, r.payload.receipt_id);
    assert.equal(out.detail.checks.signature, true);
    assert.equal(out.detail.checks.version, true);
});
test('tampered receipt (signed field mutated) -> REFUSED signature_invalid, exit 1', () => {
    const { privateKey, pub } = makeKey();
    const dir = tempDir();
    const r = receipt(privateKey);
    r.payload.claim.amount_usd = 999999; // mutate a signed field after minting
    const receiptPath = writeJson(dir, 'tampered.json', r);
    const keysPath = writeJson(dir, 'keys.json', [pub]);
    const out = runCli([receiptPath, '--keys', keysPath]);
    assert.equal(out.code, 1);
    assert.equal(out.verdict, 'REFUSED');
    assert.equal(out.detail.reason, 'signature_invalid');
    assert.equal(out.detail.checks.signature, false);
});
test('wrong pinned key (untrusted issuer) -> REFUSED, exit 1', () => {
    const { privateKey } = makeKey();
    const other = makeKey(); // a different key is pinned
    const dir = tempDir();
    const receiptPath = writeJson(dir, 'receipt.json', receipt(privateKey));
    const keysPath = writeJson(dir, 'keys.json', { keys: [other.pub] });
    const out = runCli([receiptPath, '--keys', keysPath]);
    assert.equal(out.code, 1);
    assert.equal(out.verdict, 'REFUSED');
    assert.equal(out.detail.reason, 'signature_invalid');
});
test('malformed receipt file (invalid JSON) -> REFUSED malformed_json, exit 1', () => {
    const { pub } = makeKey();
    const dir = tempDir();
    const receiptPath = join(dir, 'broken.json');
    writeFileSync(receiptPath, '{ this is not json');
    const keysPath = writeJson(dir, 'keys.json', [pub]);
    const out = runCli([receiptPath, '--keys', keysPath]);
    assert.equal(out.code, 1);
    assert.equal(out.verdict, 'REFUSED');
    assert.equal(out.detail.reason, 'malformed_json');
});
test('duplicate receipt member -> REFUSED before JSON key collapse', () => {
    const { pub } = makeKey();
    const dir = tempDir();
    const receiptPath = join(dir, 'duplicate.json');
    writeFileSync(receiptPath, '{"@version":"EP-RECEIPT-v1","@version":"attacker"}');
    const keysPath = writeJson(dir, 'keys.json', [pub]);
    const out = runCli([receiptPath, '--keys', keysPath]);
    assert.equal(out.code, 1);
    assert.equal(out.detail.reason, 'malformed_json');
    assert.match(out.detail.error, /duplicate object member/);
});
test('duplicate key-directory member -> REFUSED before trust-pin collapse', () => {
    const { privateKey, pub } = makeKey();
    const dir = tempDir();
    const receiptPath = writeJson(dir, 'receipt.json', receipt(privateKey));
    const keysPath = join(dir, 'duplicate-keys.json');
    writeFileSync(keysPath, `{"keys":["${pub}"],"keys":[]}`);
    const out = runCli([receiptPath, '--keys', keysPath]);
    assert.equal(out.code, 1);
    assert.equal(out.detail.reason, 'malformed_keys');
});
test('valid JSON that is not an EP receipt -> REFUSED unsupported_version, exit 1', () => {
    const { pub } = makeKey();
    const dir = tempDir();
    const receiptPath = writeJson(dir, 'notareceipt.json', { hello: 'world' });
    const keysPath = writeJson(dir, 'keys.json', [pub]);
    const out = runCli([receiptPath, '--keys', keysPath]);
    assert.equal(out.code, 1);
    assert.equal(out.verdict, 'REFUSED');
    assert.equal(out.detail.reason, 'unsupported_version');
});
test('no --keys -> REFUSED no_pinned_keys (never trusts an inline key), exit 1', () => {
    const { privateKey } = makeKey();
    const dir = tempDir();
    const receiptPath = writeJson(dir, 'receipt.json', receipt(privateKey));
    const out = runCli([receiptPath]);
    assert.equal(out.code, 1);
    assert.equal(out.verdict, 'REFUSED');
    assert.equal(out.detail.reason, 'no_pinned_keys');
});
test('missing receipt file -> REFUSED unreadable_receipt, exit 1 (fail closed)', () => {
    const dir = tempDir();
    const out = runCli([join(dir, 'nope.json')]);
    assert.equal(out.code, 1);
    assert.equal(out.verdict, 'REFUSED');
    assert.equal(out.detail.reason, 'unreadable_receipt');
});
