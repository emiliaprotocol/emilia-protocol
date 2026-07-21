// SPDX-License-Identifier: Apache-2.0
// Generated from initiator-attestation.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// All hostile / invisible codepoints in this file are constructed via
// String.fromCodePoint(...) so the SOURCE stays pure ASCII (no literal bidi or
// control bytes to smuggle past review). The runtime values are identical.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { canonicalize } from './index.js';
import { INITIATOR_ATTESTATION_VERSION, INITIATOR_ATTESTATION_FIELD, INITIATOR_STATEMENT_MAX, validateInitiatorAttestation, neutralizeStatement, normalizeDigest, bindInto, } from './initiator-attestation.js';
const cp = (n) => String.fromCodePoint(n);
const RLO = cp(0x202e); // right-to-left override (bidi)
const NUL = cp(0x0000); // C0 control
const BEL = cp(0x0007); // C0 control
const NEL = cp(0x0085); // C1 control
const ZWSP = cp(0x200b); // zero-width space
const BOM = cp(0xfeff); // BOM / ZWNBSP
const CYR_A = cp(0x0430); // Cyrillic "а" homoglyph of Latin "a"
const DIGEST = `sha256:${crypto.createHash('sha256').update('tool-context').digest('hex')}`;
const validAtt = () => ({
    model_id: 'anthropic/claude-opus',
    model_version: '2026-01-05',
    tool_chain_digest: DIGEST,
});
// ── validation: happy path ────────────────────────────────────────────────────
test('valid attestation normalizes (prefixed lowercase digest, stamped version)', () => {
    const r = validateInitiatorAttestation(validAtt());
    assert.equal(r.ok, true);
    assert.deepEqual(r.errors, []);
    assert.equal(r.normalized['@version'], INITIATOR_ATTESTATION_VERSION);
    assert.equal(r.normalized.model_id, 'anthropic/claude-opus');
    assert.equal(r.normalized.model_version, '2026-01-05');
    assert.equal(r.normalized.tool_chain_digest, DIGEST.toLowerCase());
    assert.equal('statement' in r.normalized, false);
});
test('bare (unprefixed) 64-hex digest normalizes to a sha256: form', () => {
    const bare = crypto.createHash('sha256').update('ctx').digest('hex');
    const r = validateInitiatorAttestation({ ...validAtt(), tool_chain_digest: bare.toUpperCase() });
    assert.equal(r.ok, true);
    assert.equal(r.normalized.tool_chain_digest, `sha256:${bare}`);
});
// ── validation: fail-closed rejections ────────────────────────────────────────
test('missing model_id is rejected (fail closed, normalized null)', () => {
    const att = validAtt();
    delete att.model_id;
    const r = validateInitiatorAttestation(att);
    assert.equal(r.ok, false);
    assert.equal(r.normalized, null);
    assert.match(r.errors.join(' '), /model_id is required/);
});
test('empty model_version is rejected', () => {
    const r = validateInitiatorAttestation({ ...validAtt(), model_version: '' });
    assert.equal(r.ok, false);
    assert.match(r.errors.join(' '), /model_version is required/);
});
test('malformed tool_chain_digest is rejected', () => {
    for (const bad of ['sha256:xyz', 'deadbeef', 'sha256:' + 'a'.repeat(63), 123, null]) {
        const r = validateInitiatorAttestation({ ...validAtt(), tool_chain_digest: bad });
        assert.equal(r.ok, false, `expected reject for ${String(bad)}`);
        assert.equal(r.normalized, null);
    }
});
test('missing tool_chain_digest is rejected', () => {
    const att = validAtt();
    delete att.tool_chain_digest;
    const r = validateInitiatorAttestation(att);
    assert.equal(r.ok, false);
    assert.match(r.errors.join(' '), /tool_chain_digest is required/);
});
test('unknown member is rejected (closed member set)', () => {
    const r = validateInitiatorAttestation({ ...validAtt(), evil: 'x' });
    assert.equal(r.ok, false);
    assert.match(r.errors.join(' '), /unknown member "evil"/);
});
test('wrong @version is rejected', () => {
    const r = validateInitiatorAttestation({ ...validAtt(), '@version': 'EP-OTHER-v9' });
    assert.equal(r.ok, false);
    assert.match(r.errors.join(' '), /@version must be/);
});
test('non-object attestation is rejected (fail closed)', () => {
    for (const bad of [null, undefined, 42, 'str', ['a']]) {
        const r = validateInitiatorAttestation(bad);
        assert.equal(r.ok, false);
        assert.equal(r.normalized, null);
    }
});
test('statement of wrong type is rejected', () => {
    const r = validateInitiatorAttestation({ ...validAtt(), statement: { not: 'a string' } });
    assert.equal(r.ok, false);
    assert.match(r.errors.join(' '), /statement, when present, must be a string/);
});
test('statement over the cap is rejected', () => {
    const r = validateInitiatorAttestation({ ...validAtt(), statement: 'a'.repeat(INITIATOR_STATEMENT_MAX + 1) });
    assert.equal(r.ok, false);
    assert.match(r.errors.join(' '), /exceeds the .* cap/);
});
// ── hostile-text neutralization ───────────────────────────────────────────────
test('a bidi override + control chars are neutralized (dangerous codepoints gone/escaped)', () => {
    // RLO (U+202E) reorders the visible line; NUL (U+0000) and BEL (U+0007) are C0
    // controls; U+0085 (NEL) is a C1 control. All must be escaped, none may survive.
    const hostile = `send ${RLO}${NUL}000,1$${BEL} pay${NEL} now`;
    const r = validateInitiatorAttestation({ ...validAtt(), statement: hostile });
    assert.equal(r.ok, true);
    const safe = r.normalized.statement;
    // The raw dangerous codepoints are no longer present.
    for (const codepoint of [0x202e, 0x0000, 0x0007, 0x0085]) {
        assert.equal(safe.includes(cp(codepoint)), false, `codepoint U+${codepoint.toString(16)} survived`);
    }
    // They were escaped (visible markers), not silently dropped.
    assert.match(safe, /<U\+202E>/);
    assert.match(safe, /<U\+0000>/);
    assert.match(safe, /<U\+0007>/);
    assert.match(safe, /<U\+0085>/);
    const rep = r.statement_report;
    assert.equal(rep.changed, true);
    assert.deepEqual([...rep.escaped_codepoints].sort((a, b) => a - b), [0x0000, 0x0007, 0x0085, 0x202e]);
});
test('neutralizeStatement preserves ordinary whitespace (tab/newline/cr) and plain text', () => {
    const r = neutralizeStatement('line1\n\tline2\r ok');
    assert.equal(r.safe, 'line1\n\tline2\r ok');
    assert.equal(r.changed, false);
    assert.equal(r.homoglyph_risk, false);
});
test('neutralizeStatement escapes zero-width and BOM codepoints', () => {
    const r = neutralizeStatement(`a${ZWSP}b${BOM}c`);
    assert.equal(r.safe.includes(ZWSP), false);
    assert.equal(r.safe.includes(BOM), false);
    assert.match(r.safe, /<U\+200B>/);
    assert.match(r.safe, /<U\+FEFF>/);
    assert.equal(r.changed, true);
});
test('neutralizeStatement flags homoglyph / mixed-script risk', () => {
    // Cyrillic "а" (U+0430) impersonating Latin "a" alongside ASCII letters.
    const r = neutralizeStatement(`p${CYR_A}y now`);
    assert.equal(r.homoglyph_risk, true);
});
test('neutralizeStatement treats a non-string as the empty statement (fail closed)', () => {
    for (const bad of [null, undefined, 42, { a: 1 }, ['x']]) {
        const r = neutralizeStatement(bad);
        assert.equal(r.safe, '');
        assert.equal(r.changed, false);
    }
});
test('neutralizeStatement caps by codepoints and flags truncation', () => {
    const r = neutralizeStatement('x'.repeat(INITIATOR_STATEMENT_MAX + 50));
    assert.equal(Array.from(r.safe).length, INITIATOR_STATEMENT_MAX);
    assert.equal(r.truncated, true);
});
test('normalizeDigest returns empty on malformed input', () => {
    assert.equal(normalizeDigest('sha256:zz'), '');
    assert.equal(normalizeDigest(undefined), '');
    const good = 'a'.repeat(64);
    assert.equal(normalizeDigest(`SHA256:${good.toUpperCase()}`), good);
});
// ── bindInto: composition with the frozen action hash ─────────────────────────
test('bindInto places the neutralized attestation under the reserved member and changes the digest', () => {
    const action = { action_type: 'wire.transfer', amount: 100, initiator: 'ep:entity:agent-7' };
    const baseline = `sha256:${crypto.createHash('sha256').update(canonicalize(action)).digest('hex')}`;
    const { action: bound, attestation, digest_preview } = bindInto(action, {
        ...validAtt(),
        statement: `ok ${RLO}spoof`,
    });
    // The attestation is under the reserved member and uses the neutralized statement.
    assert.equal(bound[INITIATOR_ATTESTATION_FIELD]['@version'], INITIATOR_ATTESTATION_VERSION);
    assert.equal(bound[INITIATOR_ATTESTATION_FIELD].statement.includes(RLO), false);
    assert.match(bound[INITIATOR_ATTESTATION_FIELD].statement, /<U\+202E>/);
    assert.equal(attestation.model_id, 'anthropic/claude-opus');
    // The bound digest covers the attestation, so it differs from the baseline, and
    // matches the same "sha256:"+sha256(canonicalize) definition actionHash() uses.
    assert.notEqual(digest_preview, baseline);
    assert.equal(digest_preview, `sha256:${crypto.createHash('sha256').update(canonicalize(bound)).digest('hex')}`);
});
test('bindInto throws on an invalid attestation (fail closed)', () => {
    const action = { action_type: 'wire.transfer' };
    assert.throws(() => bindInto(action, { model_id: 'x' }), /invalid initiator attestation/);
});
test('bindInto refuses to overwrite a different existing reserved member', () => {
    const action = { action_type: 'x', [INITIATOR_ATTESTATION_FIELD]: { model_id: 'other' } };
    assert.throws(() => bindInto(action, validAtt()), /refusing to overwrite/);
});
test('bindInto is idempotent when the existing member already equals the normalized form', () => {
    const action = { action_type: 'x' };
    const once = bindInto(action, validAtt());
    const twice = bindInto(once.action, validAtt());
    assert.equal(twice.digest_preview, once.digest_preview);
});
test('bindInto requires a plain action object', () => {
    assert.throws(() => bindInto(null, validAtt()), /requires the canonical Action Object/);
    assert.throws(() => bindInto(['a'], validAtt()), /requires the canonical Action Object/);
});
