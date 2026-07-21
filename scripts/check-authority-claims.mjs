// SPDX-License-Identifier: Apache-2.0
// Generated from check-authority-claims.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// Authority-claim guard.
//
//   node scripts/check-authority-claims.mjs
//
// EMILIA's public surfaces must never claim it ENFORCES scoped human authority
// unless the machinery that makes the claim true is present AND intact:
//   1. the admissibility registry carries the scoped-authority claim, and
//   2. the authority conformance suite exists with real refusal cases, and
//   3. the authority tests exist.
//
// This is the authority-specific twin of scripts/check-admissibility-registry.mjs:
// it scans public documentation for authority-enforcement language and fails the
// build if any such claim is made while the backing is missing or broken. It is
// the mechanized form of "no public claim without code, negative test, and a
// pinned-acceptance rule behind it" — applied to the one claim most tempting to
// overstate: that authority is enforced.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REGISTRY = path.join(ROOT, 'admissibility', 'registry.json');
const VECTOR = path.join(ROOT, 'conformance', 'vectors', 'authority.v1.json');
const TEST = path.join(ROOT, 'tests', 'authority-registry.test.ts');
const CLAIM_ID = 'scoped-human-authority-valid-at-authorization';
// Phrases that assert authority is actually ENFORCED / scoped. Matched
// case-insensitively as whole phrases. Deliberately narrow: these are the
// specific overclaims the registry entry backs, not any mention of "authority".
const CLAIM_PHRASES = [
    'authority enforced',
    'authority is enforced',
    'enforces authority',
    'enforces scoped authority',
    'scoped authority',
    'scoped human authority',
    'within limit',
    'within their limit',
    'within authority',
    'authorized approver',
    'had authority to approve',
    'authority to approve this exact action',
];
// Public surfaces to scan. Documentation and the repo-root README are the
// customer-facing claim surfaces; the spec files intentionally use the phrases
// and are backed, which is exactly what this guard confirms is allowed.
const SCAN_DIRS = ['docs', 'content'];
const SCAN_FILES = ['README.md'];
const SCAN_EXT = new Set(['.md', '.mdx', '.html', '.txt']);
// The authority spec/doc files legitimately define the claim; the guard's job is
// to confirm backing exists, and it does. We do NOT exempt them — a present,
// intact backing is what makes their language allowed.
function walk(dir, out) {
    let entries;
    try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
    }
    catch {
        return;
    }
    for (const e of entries) {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) {
            // Skip private/gitignored strategy trees — they are not public surfaces.
            if (e.name === 'strategy-private' || e.name === 'ip' || e.name === 'node_modules')
                continue;
            walk(p, out);
        }
        else if (SCAN_EXT.has(path.extname(e.name))) {
            out.push(p);
        }
    }
}
function backingStatus() {
    const problems = [];
    // 1. Registry claim present.
    let claimPresent = false;
    try {
        const reg = JSON.parse(fs.readFileSync(REGISTRY, 'utf8'));
        claimPresent = Array.isArray(reg.claims) && reg.claims.some((c) => c.claim_id === CLAIM_ID);
    }
    catch (e) {
        problems.push(`admissibility registry unreadable: ${e.message}`);
    }
    if (!claimPresent)
        problems.push(`admissibility registry is missing the '${CLAIM_ID}' claim`);
    // 2. Conformance suite exists with real refusal cases.
    let refusals = 0;
    try {
        const suite = JSON.parse(fs.readFileSync(VECTOR, 'utf8'));
        refusals = (Array.isArray(suite.vectors) ? suite.vectors : []).filter((v) => v?.expect?.valid === false).length;
    }
    catch (e) {
        problems.push(`authority conformance suite unreadable: ${e.message}`);
    }
    if (refusals === 0)
        problems.push('conformance/vectors/authority.v1.json has no refusal case (expect.valid === false)');
    // 3. Tests exist.
    if (!fs.existsSync(TEST))
        problems.push('tests/authority-registry.test.ts is missing');
    return { ok: problems.length === 0, problems, refusals };
}
function scanClaims() {
    const files = [...SCAN_FILES.map((f) => path.join(ROOT, f))];
    for (const d of SCAN_DIRS)
        walk(path.join(ROOT, d), files);
    const hits = [];
    for (const f of files) {
        let text;
        try {
            text = fs.readFileSync(f, 'utf8');
        }
        catch {
            continue;
        }
        const lower = text.toLowerCase();
        for (const phrase of CLAIM_PHRASES) {
            if (lower.includes(phrase)) {
                hits.push({ file: path.relative(ROOT, f), phrase });
            }
        }
    }
    return hits;
}
const backing = backingStatus();
const hits = scanClaims();
if (hits.length > 0 && !backing.ok) {
    console.error('AUTHORITY-CLAIM GUARD: FAIL');
    console.error('Public surfaces assert enforced/scoped authority, but the backing is missing or broken:');
    for (const p of backing.problems)
        console.error(`  - ${p}`);
    console.error('Offending claim occurrences:');
    for (const h of hits.slice(0, 25))
        console.error(`  - ${h.file}: "${h.phrase}"`);
    process.exit(1);
}
if (!backing.ok) {
    // No public claim yet, but the backing is broken — still a defect to fix
    // before any such claim can be made. Fail so the machinery is never silently
    // removed.
    console.error('AUTHORITY-CLAIM GUARD: FAIL (backing broken)');
    for (const p of backing.problems)
        console.error(`  - ${p}`);
    process.exit(1);
}
console.log(`AUTHORITY-CLAIM GUARD: OK (backing intact: registry claim + ${backing.refusals} refusal vectors + tests; ${hits.length} backed claim occurrence(s) in public docs)`);
