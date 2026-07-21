// SPDX-License-Identifier: Apache-2.0
// Generated from markdown-cell-escaping.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * @emilia-protocol/gate — Markdown table-cell escaping across every report
 * renderer. Run with `node --test reports/markdown-cell-escaping.test.js`
 * from packages/gate.
 *
 * The renderers escape `|` so a log-derived string cannot break a table row.
 * Escaping the pipe ALONE is not enough: a value containing `a\|b` becomes
 * `a\\|b`, where Markdown reads `\\` as a literal backslash and the pipe stays
 * live as a cell delimiter. A log-derived action or refusal reason could then
 * split its own cell and shift every column after it — an evidence table that
 * reads differently from the record behind it. Backslash must be escaped first.
 *
 * These reports are the regulator-, underwriter-, and auditor-facing views of
 * the evidence log, so a row that renders differently from the record behind it
 * is an integrity defect, not a cosmetic one.
 *
 * Each test drives the hostile value down the path that actually reaches a
 * table cell in that report — action/principal for art14, refusal REASON for
 * the underwriter count tables, action for the auditor sample listing.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createEvidenceLog } from '../evidence.js';
import { buildArt14EvidencePack, renderMarkdown as renderArt14 } from './art14.js';
import { buildUnderwriterAttestation, renderMarkdown as renderUnderwriter } from './underwriter.js';
import { buildAuditWorkpaper, renderMarkdown as renderWorkpaper } from './auditor-workpaper.js';
// The adversarial shape: a backslash immediately before a pipe.
const HOSTILE_ACTION = 'payment.release\\|forged.column';
const HOSTILE_REASON = 'receipt_required\\|forged.column';
/**
 * Split a rendered Markdown row on the delimiters a parser would treat as LIVE
 * — a `|` preceded by an even number of backslashes. This is what decides
 * whether a cell was broken.
 */
function liveCells(row) {
    const cells = [];
    let current = '';
    let backslashes = 0;
    for (const ch of row) {
        if (ch === '|' && backslashes % 2 === 0) {
            cells.push(current);
            current = '';
            backslashes = 0;
            continue;
        }
        backslashes = ch === '\\' ? backslashes + 1 : 0;
        current += ch;
    }
    cells.push(current);
    return cells;
}
const isTableLine = (line) => line.trimStart().startsWith('|');
const isSeparator = (line) => /^\s*\|[\s:|-]+\|\s*$/.test(line);
/**
 * Every contiguous run of table lines is one table: the first line fixes the
 * column count and every later row must match it. A cell broken by a live pipe
 * shows up here as a row one column wider than its header.
 *
 * Returns the number of rows checked so a test can assert it actually saw the
 * table it meant to exercise, rather than passing on an empty document.
 */
function assertTablesIntact(markdown, label) {
    const lines = markdown.split('\n');
    let headerWidth = null;
    let checked = 0;
    for (const [i, line] of lines.entries()) {
        if (!isTableLine(line)) {
            headerWidth = null;
            continue;
        }
        if (isSeparator(line))
            continue;
        const width = liveCells(line).length;
        if (headerWidth === null) {
            headerWidth = width;
            continue;
        }
        assert.equal(width, headerWidth, `${label}: line ${i + 1} renders ${width} cells against a ${headerWidth}-cell header, `
            + `so a value broke out of its cell:\n  ${line}`);
        checked += 1;
    }
    return checked;
}
/** The hostile value must survive escaped — dropping it would be its own defect. */
function assertRenderedEscaped(markdown, raw, label) {
    const escaped = raw.replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
    assert.ok(markdown.includes(escaped), `${label}: hostile value must render escaped, not mangled or dropped`);
}
test('art14 pack: a backslash-pipe action cannot split its table cell', async () => {
    const log = createEvidenceLog();
    await log.record({
        kind: 'decision', at: '2026-01-15T00:00:00.000Z',
        action: HOSTILE_ACTION, allow: true, status: 200, reason: 'allow',
        required_tier: 'class_a', have_tier: 'class_a',
        receipt_id: 'rcpt_1', subject: HOSTILE_ACTION,
    });
    await log.record({
        kind: 'decision', at: '2026-01-16T00:00:00.000Z',
        action: HOSTILE_ACTION, allow: false, status: 428, reason: HOSTILE_REASON,
        required_tier: 'class_a', have_tier: 'software',
        receipt_id: null, subject: HOSTILE_ACTION,
    });
    const pack = buildArt14EvidencePack(log.all(), {
        organization: 'ACME Corp', system: 'payments-agent-gate',
        periodStart: '2026-01-01T00:00:00.000Z',
        periodEnd: '2026-02-01T00:00:00.000Z',
        now: Date.parse('2026-02-02T00:00:00.000Z'),
    });
    const markdown = renderArt14(pack);
    assert.ok(assertTablesIntact(markdown, 'art14') > 0, 'art14: expected table rows to check');
    assertRenderedEscaped(markdown, HOSTILE_ACTION, 'art14');
});
test('underwriter attestation: a backslash-pipe refusal reason cannot split its cell', () => {
    // The underwriter count tables render refusal REASON keys, so that is the
    // log-derived value that reaches a cell here.
    const entries = [1, 2].map((n) => ({
        seq: n, prev_hash: `h${n - 1}`, hash: `h${n}`,
        kind: 'decision', at: '2026-01-15T00:00:00.000Z',
        action: HOSTILE_ACTION, allow: false, status: 428, reason: HOSTILE_REASON,
        required_tier: 'class_a', receipt_id: null, subject: null,
    }));
    const pack = buildUnderwriterAttestation(entries, {
        insured: 'Acme Robotics, Inc.', policyRef: 'POL-2026-001',
        periodStart: '2026-01-01T00:00:00.000Z',
        periodEnd: '2026-01-31T23:59:59.000Z',
        now: Date.parse('2026-02-01T00:00:00.000Z'),
    });
    const markdown = renderUnderwriter(pack);
    assert.ok(assertTablesIntact(markdown, 'underwriter') > 0, 'underwriter: expected table rows');
    assertRenderedEscaped(markdown, HOSTILE_REASON, 'underwriter');
});
test('auditor workpaper: a backslash-pipe action cannot split its sample-row cell', async () => {
    const log = createEvidenceLog();
    for (const at of ['2026-01-10T00:00:00.000Z', '2026-01-15T12:00:00.000Z']) {
        await log.record({
            kind: 'decision', at, action: HOSTILE_ACTION, allow: true, status: 200,
            reason: 'allow', selector: { protocol: 'mcp', tool: 'release_payment' },
            required_tier: 'class_a', have_tier: 'class_a', signer: 'ep:key:issuer#1',
            consumption_mode: 'consume', receipt_id: `rcpt_${at}`, subject: 'ep:user:alice',
        });
    }
    const pack = buildAuditWorkpaper(log.all(), {
        client: 'Example Corp', engagement: 'FY26 ITGC — cycle 1', controlRef: 'EP-GATE-01',
        periodStart: '2026-01-01T00:00:00.000Z',
        periodEnd: '2026-02-01T00:00:00.000Z',
        sampleSize: 2, sampleSeed: 'seed-alpha',
        now: () => Date.parse('2026-02-02T00:00:00.000Z'),
    });
    const markdown = renderWorkpaper(pack);
    assert.ok(assertTablesIntact(markdown, 'auditor-workpaper') > 0, 'auditor: expected table rows');
    assertRenderedEscaped(markdown, HOSTILE_ACTION, 'auditor-workpaper');
});
test('liveCells models Markdown escaping, so the assertions above can fail', () => {
    // Counts include the empty cells either side of the leading/trailing pipe.
    //
    // Pre-fix output `| a\\|b | second |`: the pipe was escaped but the backslash
    // was not, so `\\` closes the escape, the pipe is a live delimiter, and the
    // first cell splits in two -> 5 cells for a 2-column row.
    assert.equal(liveCells('| a\\\\|b | second |').length, 5);
    // Fixed output `| a\\\|b | second |`: backslash escaped first, so the pipe
    // stays inert and the row keeps its 2 columns -> 4 cells.
    assert.equal(liveCells('| a\\\\\\|b | second |').length, 4);
    // assertTablesIntact must reject a row that is wider than its header.
    assert.throws(() => assertTablesIntact('| A | B |\n|---|---|\n| a\\\\|b | c |', 'self-test'), /broke out of its cell/);
});
