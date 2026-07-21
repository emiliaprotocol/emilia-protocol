// SPDX-License-Identifier: Apache-2.0
// Generated from check-admissibility-registry.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// Admissibility Invariant Registry checker.
//
//   node scripts/check-admissibility-registry.mjs
//
// Enforces, for every registered claim, that all five invariants are present and
// RESOLVE against the real tree:
//   1. pinned_authority        non-empty string
//   2. verifier_behavior       {file, symbol}; file exists AND contains the symbol
//   3. negative_vector         a conformance suite (in conformance/vectors/) that
//                              actually contains at least one refusal case
//                              (expect.valid === false), OR a test file that exists
//   4. parity                  subset of conformance_langs; partial parity REQUIRES
//                              a non-empty parity_exception
//   5. acceptance_semantics    non-empty string that states verified-vs-accepted
//
// Exit 0 only if every claim passes. Any gap is a build failure. This is the
// mechanized form of "no public claim without code, negative test, parity, and a
// pinned-acceptance rule behind it."
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const VECTORS = path.join(ROOT, 'conformance', 'vectors');
const REGISTRY = path.join(ROOT, 'admissibility', 'registry.json');
const errors = [];
const fail = (claimId, msg) => errors.push(`[${claimId}] ${msg}`);
function nonEmptyString(v) {
    return typeof v === 'string' && v.trim().length > 0;
}
function suiteHasRefusalCase(suiteFile) {
    const p = path.join(VECTORS, suiteFile);
    if (!fs.existsSync(p))
        return { ok: false, reason: `suite not found: conformance/vectors/${suiteFile}` };
    let json;
    try {
        json = JSON.parse(fs.readFileSync(p, 'utf8'));
    }
    catch (e) {
        return { ok: false, reason: `suite unreadable (${e.message})` };
    }
    const vectors = Array.isArray(json?.vectors) ? json.vectors : [];
    const refusals = vectors.filter((v) => v?.expect?.valid === false).length;
    if (refusals === 0) {
        return { ok: false, reason: `suite ${suiteFile} has no refusal case (no vector with expect.valid === false)` };
    }
    return { ok: true, refusals };
}
let registry;
try {
    registry = JSON.parse(fs.readFileSync(REGISTRY, 'utf8'));
}
catch (e) {
    console.error(`FATAL: cannot read ${REGISTRY}: ${e.message}`);
    process.exit(2);
}
const DOCTRINE = ['signed_is_not_trusted', 'verified_is_not_accepted', 'accepted_requires_pinned_policy'];
if (!Array.isArray(registry.doctrine) || DOCTRINE.some((d, i) => registry.doctrine[i] !== d)) {
    fail('registry', `doctrine must be exactly ${JSON.stringify(DOCTRINE)}`);
}
const langs = Array.isArray(registry.conformance_langs) ? registry.conformance_langs : [];
if (langs.length === 0)
    fail('registry', 'conformance_langs must be non-empty');
const claims = Array.isArray(registry.claims) ? registry.claims : [];
if (claims.length === 0)
    fail('registry', 'no claims registered');
const seen = new Set();
for (const c of claims) {
    const id = c?.claim_id || '(missing claim_id)';
    if (seen.has(id))
        fail(id, 'duplicate claim_id');
    seen.add(id);
    if (!nonEmptyString(c.claim))
        fail(id, 'missing claim text');
    // 1. pinned authority
    if (!nonEmptyString(c.pinned_authority))
        fail(id, 'invariant 1: pinned_authority missing');
    // 2. verifier behavior resolves to real code
    const vb = c.verifier_behavior || {};
    if (!nonEmptyString(vb.file) || !nonEmptyString(vb.symbol)) {
        fail(id, 'invariant 2: verifier_behavior needs {file, symbol}');
    }
    else {
        const vp = path.join(ROOT, vb.file);
        if (!fs.existsSync(vp)) {
            fail(id, `invariant 2: verifier file not found: ${vb.file}`);
        }
        else if (!fs.readFileSync(vp, 'utf8').includes(vb.symbol)) {
            fail(id, `invariant 2: symbol '${vb.symbol}' not found in ${vb.file}`);
        }
    }
    // 3. negative vector proves refusal
    const nv = c.negative_vector || {};
    if (nv.suite) {
        const r = suiteHasRefusalCase(nv.suite);
        if (!r.ok)
            fail(id, `invariant 3: ${r.reason}`);
    }
    else if (nv.test) {
        if (!fs.existsSync(path.join(ROOT, nv.test)))
            fail(id, `invariant 3: negative test not found: ${nv.test}`);
    }
    else {
        fail(id, 'invariant 3: negative_vector needs a {suite} or {test}');
    }
    // 4. parity
    const parity = Array.isArray(c.parity) ? c.parity : [];
    if (parity.length === 0) {
        fail(id, 'invariant 4: parity must list at least one language');
    }
    else {
        const stray = parity.filter((l) => !langs.includes(l));
        if (stray.length)
            fail(id, `invariant 4: parity lists unknown language(s): ${stray.join(', ')}`);
        if (parity.length < langs.length && !nonEmptyString(c.parity_exception)) {
            fail(id, `invariant 4: partial parity (${parity.join(',')}) requires a parity_exception`);
        }
    }
    // 5. acceptance semantics
    if (!nonEmptyString(c.acceptance_semantics))
        fail(id, 'invariant 5: acceptance_semantics missing');
}
if (errors.length) {
    console.error(`ADMISSIBILITY REGISTRY: FAIL (${errors.length} problem${errors.length === 1 ? '' : 's'})`);
    for (const e of errors)
        console.error(`  - ${e}`);
    process.exit(1);
}
console.log(`ADMISSIBILITY REGISTRY: OK (${claims.length} claim${claims.length === 1 ? '' : 's'}, all five invariants resolved against the tree)`);
process.exit(0);
