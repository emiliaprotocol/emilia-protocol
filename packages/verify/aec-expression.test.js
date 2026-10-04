// SPDX-License-Identifier: Apache-2.0
// Generated from aec-expression.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// AEC -08 requirement-expression contract (evaluator EP-AEC-EVALUATOR-08-v1)
// over the frozen corpus conformance/vectors/aec-expression.v1.json.
//
// Syntax validity, refusal class, Boolean value, result, canonical parse and
// parse identity are asserted separately for every vector, through the
// diagnostic helper, the structured evaluator and the legacy string API.
//
// The mutation tests at the end build evaluators that report the SAME parse
// identity as the reference and still return a wrong verdict. The corpus must
// reject each of them: a matching parse identity is an interpretation
// diagnostic, never proof of a matching answer.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as aec from './dist/evidence-chain.js';
import { canonicalizeStrictJson } from './dist/strict-json.js';
const here = dirname(fileURLToPath(import.meta.url));
const corpusPath = resolve(here, '../../conformance/vectors/aec-expression.v1.json');
const corpusBytes = readFileSync(corpusPath);
const corpus = JSON.parse(corpusBytes.toString('utf8'));
const vectors = corpus.vectors;
const internals = aec.__aecSecurityInternals;
const NOW = '2026-10-03T12:00:00Z';
const action = { action_type: 'payment.release', amount: 100, destination: 'merchant:one' };
const ACTION = `sha256:${crypto.createHash('sha256').update(canonicalizeStrictJson(action)).digest('hex')}`;
const RESERVED = new Set(['ep-receipt', 'ep-quorum', 'ep-authorization-bundle', 'ep-platform-attestation']);
const ASSERTIONS = ['syntax', 'invalid_class', 'value', 'result', 'canonical_parse', 'parse_identity'];
test('corpus is frozen: SHA256SUMS matches, bytes are ASCII, ids unique', () => {
    const sums = readFileSync(resolve(here, '../../conformance/vectors/aec-expression.v1.SHA256SUMS'), 'utf8');
    const digest = crypto.createHash('sha256').update(corpusBytes).digest('hex');
    assert.equal(sums, `${digest}  aec-expression.v1.json\n`);
    assert.ok(/^[\x0a\x20-\x7e]*$/.test(corpusBytes.toString('latin1')), 'corpus bytes must be ASCII');
    assert.equal(corpus.suite, 'EP-AEC-EXPRESSION-v1');
    assert.equal(corpus.evaluator_revision, aec.AEC_EVALUATOR_REVISION);
    assert.equal(new Set(vectors.map(v => v.id)).size, vectors.length);
    assert.ok(vectors.length >= 100);
});
test('every review-table row is present with its stated syntax and value', () => {
    const table = vectors.filter(v => v.group === 'review-table');
    assert.equal(table.length, 17);
    const byExpression = (e, eligible) => table.find(v => v.aec_expression.expression === e
        && JSON.stringify(v.aec_expression.eligible_types) === JSON.stringify(eligible)).expect;
    assert.equal(byExpression('aORb', ['a']).value, false);
    assert.equal(byExpression('aORb', ['aORb']).value, true);
    assert.equal(byExpression('AND', ['AND']).syntax, 'INVALID');
    assert.equal(byExpression('a OR b AND c', ['a']).canonical_parse, '((a OR b) AND c)');
});
test('diagnostic helper: each assertion holds separately on every vector', () => {
    const failures = [];
    for (const vector of vectors) {
        const got = aec.evaluateAecRequirementExpression(vector.aec_expression.expression, vector.aec_expression.eligible_types);
        for (const key of ASSERTIONS) {
            if (got[key] !== vector.expect[key])
                failures.push(`${vector.id}.${key}`);
        }
        assert.deepEqual(Object.keys(got).sort(), [...ASSERTIONS].sort());
    }
    assert.deepEqual(failures, []);
});
test('validity is distinguishable from truth: invalid and false-valid both UNSATISFIED, never confused', () => {
    const falseValid = vectors.filter(v => v.expect.syntax === 'VALID' && v.expect.value === false);
    const invalid = vectors.filter(v => v.expect.syntax === 'INVALID');
    assert.ok(falseValid.length >= 10 && invalid.length >= 30);
    for (const v of [...falseValid, ...invalid])
        assert.equal(v.expect.result, 'UNSATISFIED');
    // A parser that refused everything would pass every result assertion on these
    // rows, and must still fail the syntax assertion on every valid one.
    const rejectAll = () => ({ syntax: 'INVALID', invalid_class: 'syntax', value: null, result: 'UNSATISFIED', canonical_parse: null, parse_identity: null });
    const caught = vectors.filter(v => v.expect.syntax === 'VALID' && rejectAll().syntax !== v.expect.syntax);
    assert.equal(caught.length, vectors.filter(v => v.expect.syntax === 'VALID').length);
    assert.ok(invalid.some(v => v.expect.invalid_class === 'limit') && invalid.some(v => v.expect.invalid_class === 'syntax'));
});
test('refusal order: a token counts once complete, and a lone surrogate counts three octets', () => {
    const chain = (n) => Array.from({ length: n }, (_, i) => `r${i}`).join(' OR ');
    const refusal = (expression) => aec.compileAecRequirementExpression(expression).invalid_class;
    const full = `${chain(128)} OR`; // 256 complete tokens
    // A lone & or | where the 257th token would start is an invalid character.
    for (const tail of [' &', ' |', '&', ' &x', ' !'])
        assert.equal(refusal(full + tail), 'syntax', JSON.stringify(tail));
    // Completing a 257th token is a limit refusal, whatever follows it.
    for (const tail of [' &&', ' ||', ' x', ' x!', ' (', ' )'])
        assert.equal(refusal(full + tail), 'limit', JSON.stringify(tail));
    // Length is measured on the decoded string value; a lone surrogate counts
    // three octets and is an invalid character.
    assert.equal(refusal(`${'a'.repeat(4094)}\ud800`), 'limit');
    assert.equal(refusal(`${'a'.repeat(4093)}\ud800`), 'syntax');
    assert.equal(refusal('\udfff'), 'syntax');
});
// ---------------------------------------------------------------------------
// Structured evaluator (createAuthorizationChainEvaluator)
// ---------------------------------------------------------------------------
const identifiersOf = (expression) => [...new Set(expression.match(/[A-Za-z0-9_.:-]+/g) ?? [])]
    .filter(id => id !== 'AND' && id !== 'OR');
const typeOk = (t) => t.length <= 128 && !RESERVED.has(t);
const stubProfile = { id: 'stub', revision: '1', native_format_revision: 'stub-v1' };
const passing = (_evidence, context) => ({ verified: true, accepted: true, format_revision: 'stub-v1', action_digest: context.expected_action_digest });
const failing = () => ({ verified: false, accepted: false, reason: 'signature_invalid' });
function structuredCase(vector) {
    const eligible = vector.aec_expression.eligible_types;
    // Every identifier the expression names but the vector does not make eligible
    // is presented as a component whose native verification FAILED.
    const failed = identifiersOf(vector.aec_expression.expression).filter(id => !eligible.includes(id));
    if (![...eligible, ...failed].every(typeOk) || eligible.length + failed.length > 64)
        return null;
    const nativeVerifiers = {};
    for (const t of eligible)
        nativeVerifiers[t] = { profile: stubProfile, trustSnapshot: {}, verify: passing };
    for (const t of failed)
        nativeVerifiers[t] = { profile: stubProfile, trustSnapshot: {}, verify: failing };
    const components = [...eligible, ...failed].map(type => ({ type, evidence: { t: type } }));
    return { nativeVerifiers, chain: { '@version': 'EP-AEC-v1', action, components }, failed };
}
const requirement = (expression) => ({ '@version': 'EP-AEC-REQUIREMENT-v1', requirement_id: 'expr@1', expression });
test('structured API: malformed expressions refuse construction; valid ones evaluate on the compiled tree', async () => {
    let constructed = 0;
    let refused = 0;
    for (const vector of vectors) {
        const { expression } = vector.aec_expression;
        if (vector.expect.syntax === 'INVALID') {
            // A constructor refusal produces no evaluator and so no replay record.
            assert.throws(() => aec.createAuthorizationChainEvaluator({ requirement: requirement(expression), nativeVerifiers: {} }), (e) => e instanceof TypeError && e.message === 'aec_requirement_invalid', vector.id);
            refused++;
            continue;
        }
        const harness = structuredCase(vector);
        if (!harness)
            continue;
        const evaluator = aec.createAuthorizationChainEvaluator({ requirement: requirement(expression), nativeVerifiers: harness.nativeVerifiers });
        assert.equal(evaluator.requirement_expression.parse_identity, vector.expect.parse_identity, vector.id);
        assert.equal(evaluator.requirement_expression.canonical_parse, vector.expect.canonical_parse, vector.id);
        const result = await evaluator.evaluate(harness.chain, { expectedAction: action, verificationTime: NOW });
        assert.equal(result.satisfied, vector.expect.value, vector.id);
        assert.equal(result.authorization_decision, false);
        assert.equal(result.reasons.includes('expression_unsatisfied'), vector.expect.value === false, vector.id);
        for (const t of harness.failed) {
            const fact = result.replay.facts.find((f) => f.type === t);
            assert.equal(fact.native_verification, 'FAILED');
            assert.equal(fact.eligible, false);
        }
        // The replay record keeps the v1 member set: no parse metadata on the wire.
        assert.deepEqual(Object.keys(result.replay).sort(), ['@version', 'aec_digest', 'algorithm_revision', 'evaluator_profile_digest',
            'expected_action_digest', 'expected_caid', 'facts', 'reasons', 'requirement_profile_digest', 'satisfied', 'verification_time']);
        assert.equal(result.replay.algorithm_revision, 'EP-AEC-EVALUATOR-08-v1');
        constructed++;
    }
    assert.equal(refused, vectors.filter(v => v.expect.syntax === 'INVALID').length);
    assert.ok(constructed >= 40, `structured harness covered ${constructed} valid vectors`);
});
test('structured API: the requirement keeps its closed v1 member set and its exact stored bytes', () => {
    const exact = requirement(' \ta OR\tb \n');
    const tidy = requirement('a OR b');
    const one = aec.createAuthorizationChainEvaluator({ requirement: exact, nativeVerifiers: {} });
    const two = aec.createAuthorizationChainEvaluator({ requirement: tidy, nativeVerifiers: {} });
    // Same tree, same parse identity ...
    assert.equal(one.requirement_expression.parse_identity, two.requirement_expression.parse_identity);
    // ... but the requirement profile digest commits to the expression as stored.
    const digest = (v) => `sha256:${crypto.createHash('sha256').update(canonicalizeStrictJson(v)).digest('hex')}`;
    assert.equal(one.requirement_profile_digest, digest(exact));
    assert.equal(two.requirement_profile_digest, digest(tidy));
    assert.notEqual(one.requirement_profile_digest, two.requirement_profile_digest);
    // A parse identity is not a requirement field: v1 readers refuse unknown keys.
    for (const key of ['parse_identity', 'canonical_parse', 'expression_fingerprint']) {
        assert.throws(() => aec.createAuthorizationChainEvaluator({ requirement: { ...tidy, [key]: one.requirement_expression.parse_identity }, nativeVerifiers: {} }), /aec_requirement_invalid/);
    }
});
test('structured API: a requirement that is not strict I-JSON is refused at construction by the strict JSON check', () => {
    // No evaluator, so no replay record; the refusal is the strict JSON error,
    // not aec_requirement_invalid, because the object itself is not I-JSON.
    assert.throws(() => aec.createAuthorizationChainEvaluator({ requirement: requirement('a OR \ud800'), nativeVerifiers: {} }), (e) => e instanceof TypeError && /unpaired Unicode surrogate/.test(e.message));
});
test('structured API: AND and OR stay valid native component types; only the expression reserves them', async () => {
    const evaluator = aec.createAuthorizationChainEvaluator({
        requirement: requirement('ok'),
        nativeVerifiers: { AND: { profile: stubProfile, trustSnapshot: {}, verify: passing }, ok: { profile: stubProfile, trustSnapshot: {}, verify: passing } },
    });
    const result = await evaluator.evaluate({ '@version': 'EP-AEC-v1', action, components: [{ type: 'AND', evidence: { t: 1 } }, { type: 'ok', evidence: { t: 2 } }] }, { expectedAction: action, verificationTime: NOW });
    assert.equal(result.satisfied, true);
    assert.equal(result.replay.facts.find((f) => f.type === 'AND').eligible, true);
    assert.throws(() => aec.createAuthorizationChainEvaluator({ requirement: requirement('AND'), nativeVerifiers: {} }), /aec_requirement_invalid/);
});
test('replay migration: same revision compares the complete record; other revisions are UNSUPPORTED_REVISION, never relabeled', async () => {
    const evaluator = aec.createAuthorizationChainEvaluator({
        requirement: requirement('a OR b'),
        nativeVerifiers: { a: { profile: stubProfile, trustSnapshot: {}, verify: passing } },
    });
    const chain = { '@version': 'EP-AEC-v1', action, components: [{ type: 'a', evidence: { t: 1 } }] };
    const inputs = () => ({ expectedAction: action, verificationTime: NOW });
    const first = await evaluator.evaluate(chain, inputs());
    assert.equal(first.satisfied, true);
    const recorded = JSON.parse(JSON.stringify(first.replay));
    const same = await evaluator.replay(chain, recorded, inputs());
    assert.equal(same.comparison, 'MATCH');
    assert.equal(same.matches, true);
    assert.equal(same.recorded_revision, 'EP-AEC-EVALUATOR-08-v1');
    const tampered = { ...recorded, reasons: ['edited'] };
    const mismatch = await evaluator.replay(chain, tampered, inputs());
    assert.equal(mismatch.comparison, 'MISMATCH');
    assert.equal(mismatch.matches, false);
    // A stored -07 record: same members, -07 revision, its own digests.
    const stored07 = { ...recorded, algorithm_revision: 'EP-AEC-EVALUATOR-07-v1', evaluator_profile_digest: `sha256:${'0'.repeat(64)}` };
    const before = JSON.stringify(stored07);
    const old = await evaluator.replay(chain, stored07, inputs());
    assert.equal(old.comparison, 'UNSUPPORTED_REVISION');
    assert.equal(old.matches, false);
    assert.equal(old.recorded_revision, 'EP-AEC-EVALUATOR-07-v1');
    assert.equal(JSON.stringify(stored07), before, 'the stored record is not rewritten');
    // Re-evaluation under -08 is a new, separately identified record.
    assert.equal(old.result.replay.algorithm_revision, 'EP-AEC-EVALUATOR-08-v1');
    assert.notEqual(old.result.replay_digest, old.claimed_replay_digest);
    // Relabeling the -07 record as -08 does not make it match either.
    const relabeled = await evaluator.replay(chain, { ...stored07, algorithm_revision: 'EP-AEC-EVALUATOR-08-v1' }, inputs());
    assert.equal(relabeled.comparison, 'MISMATCH');
    assert.ok(aec.AEC_SUPERSEDED_EVALUATOR_REVISIONS.includes('EP-AEC-EVALUATOR-07-v1'));
    const future = await evaluator.replay(chain, { ...recorded, algorithm_revision: 'EP-AEC-EVALUATOR-99-v1' }, inputs());
    assert.equal(future.comparison, 'UNSUPPORTED_REVISION');
    for (const garbage of [null, 'record', { '@version': 'EP-AEC-REPLAY-v1' }, { ...recorded, '@version': 'other' }]) {
        const refused = await evaluator.replay(chain, garbage, inputs());
        assert.equal(refused.comparison, 'RECORD_INVALID');
        assert.equal(refused.matches, false);
    }
});
// ---------------------------------------------------------------------------
// Legacy string API (verifyAuthorizationChain)
// ---------------------------------------------------------------------------
test('legacy API: satisfied iff the expression is valid and true, over every vector', () => {
    const stub = (evidence) => ({ valid: true, action_digest: evidence.action_digest });
    for (const vector of vectors) {
        const { expression, eligible_types } = vector.aec_expression;
        // The legacy API caps a chain at 64 components and types at 128 characters.
        if (!eligible_types.every(typeOk) || eligible_types.length > 64)
            continue;
        const verifiers = Object.fromEntries(eligible_types.map(t => [t, stub]));
        const chain = { '@version': 'EP-AEC-v1', action, components: eligible_types.length
                ? eligible_types.map(type => ({ type, evidence: { action_digest: ACTION } }))
                : [{ type: 'unrelated', evidence: { action_digest: ACTION } }] };
        const result = aec.verifyAuthorizationChain(chain, { requirement: expression, verifiers, expectedActionDigest: ACTION });
        assert.equal(result.satisfied, vector.expect.value === true, vector.id);
        if (vector.expect.syntax === 'INVALID' && /[^ \t\r\n]/.test(expression)) {
            assert.ok(result.reasons.some((r) => /malformed or exceeds parser limits|exceeds size limit/.test(r)), vector.id);
        }
        if (vector.expect.syntax === 'VALID' && vector.expect.value === false) {
            assert.ok(result.reasons.some((r) => r.startsWith('requirement not satisfied')), vector.id);
        }
    }
});
test('legacy API: a pinned requirement is never trimmed of non-ASCII whitespace', () => {
    const stub = (evidence) => ({ valid: true, action_digest: evidence.action_digest });
    const chain = { '@version': 'EP-AEC-v1', action, components: [{ type: 'a', evidence: { action_digest: ACTION } }] };
    const run = (requirementText) => aec.verifyAuthorizationChain(chain, { requirement: requirementText, verifiers: { a: stub }, expectedActionDigest: ACTION });
    assert.equal(run(' \ta\r\n').satisfied, true);
    for (const padded of [' a', 'a ', ' a', '﻿a', 'a\u000b', '\u000ca']) {
        const result = run(padded);
        assert.equal(result.satisfied, false, JSON.stringify(padded));
        assert.equal(result.requirement_source, 'relying_party');
    }
    // 4095 octets of identifier plus one 2-octet character exceeds the 4096-octet cap.
    assert.ok(run(`${'a'.repeat(4095)} `).reasons.includes('requirement expression exceeds size limit'));
});
function corpusVerdict(impl) {
    const failures = [];
    const sameIdentityWrongValue = [];
    for (const vector of vectors) {
        if (vector.expect.syntax !== 'VALID')
            continue;
        const got = impl(vector.aec_expression.expression, vector.aec_expression.eligible_types);
        const identityMatches = got.parse_identity === vector.expect.parse_identity;
        if (!identityMatches || got.value !== vector.expect.value)
            failures.push(vector.id);
        if (identityMatches && got.value !== vector.expect.value)
            sameIdentityWrongValue.push(vector.id);
    }
    return { failures, sameIdentityWrongValue };
}
const reference = (e, eligible) => aec.evaluateAecRequirementExpression(e, eligible);
function treeOf(expression) {
    const parsed = internals.parseAecExpression(expression);
    assert.equal(parsed.ok, true);
    return parsed.tree;
}
const identityOf = (expression) => aec.compileAecRequirementExpression(expression).parse_identity;
// Mutant 1: fingerprints the correct tree, then evaluates the TEXT with
// conventional precedence (AND binds tighter than OR).
const precedenceMutant = (expression, eligible) => {
    const set = new Set(eligible);
    const tokens = internals.lexAecExpression(expression).tokens.map((t) => t.kind === 'operator' ? t.operator : t.text);
    let i = 0;
    const primary = () => {
        const t = tokens[i++];
        if (t === '(') {
            const v = or();
            i++;
            return v;
        }
        return set.has(t);
    };
    const and = () => { let v = primary(); while (tokens[i] === 'AND') {
        i++;
        const r = primary();
        v = v && r;
    } return v; };
    const or = () => { let v = and(); while (tokens[i] === 'OR') {
        i++;
        const r = and();
        v = v || r;
    } return v; };
    return { parse_identity: identityOf(expression), value: or() };
};
// Mutant 2: evaluates the shared tree with AND and OR swapped.
const operatorMutant = (expression, eligible) => {
    const set = new Set(eligible);
    const run = (n) => n.kind === 'identifier' ? set.has(n.name)
        : n.operator === 'AND' ? run(n.left) || run(n.right) : run(n.left) && run(n.right);
    return { parse_identity: identityOf(expression), value: run(treeOf(expression)) };
};
// Mutant 3: evaluates the shared tree with case-folded role matching.
const caseFoldMutant = (expression, eligible) => {
    const folded = new Set(eligible.map(t => t.toLowerCase()));
    const run = (n) => n.kind === 'identifier' ? folded.has(n.name.toLowerCase())
        : n.operator === 'AND' ? run(n.left) && run(n.right) : run(n.left) || run(n.right);
    return { parse_identity: identityOf(expression), value: run(treeOf(expression)) };
};
test('mutation: the reference passes the corpus', () => {
    assert.deepEqual(corpusVerdict(reference).failures, []);
});
for (const [name, mutant, witness] of [
    ['operator precedence evaluated from text', precedenceMutant, 'table-13-left-to-right'],
    ['operator evaluation swapped on the tree', operatorMutant, 'table-03-a-OR-b'],
    ['role matching case-folded', caseFoldMutant, 'table-10-And-case-sensitive'],
]) {
    test(`mutation: ${name} keeps the parse identity and is rejected`, () => {
        const verdict = corpusVerdict(mutant);
        assert.ok(verdict.failures.length > 0, 'the corpus must reject the mutant');
        assert.ok(verdict.sameIdentityWrongValue.includes(witness), `${witness} must be a same-identity, wrong-verdict case`);
        // Every failure is a verdict failure: the mutant's parse identity always matched.
        assert.deepEqual(verdict.failures, verdict.sameIdentityWrongValue);
    });
}
test('mutation: the review counterexample, a OR b AND c with only a eligible', () => {
    const ref = reference('a OR b AND c', ['a']);
    const bad = precedenceMutant('a OR b AND c', ['a']);
    assert.equal(ref.parse_identity, bad.parse_identity);
    assert.equal(ref.value, false);
    assert.equal(bad.value, true);
});
test('mutation: crediting a FAILED fact keeps the parse identity and is rejected', async () => {
    const sameIdentityWrongValue = [];
    let covered = 0;
    for (const vector of vectors) {
        if (vector.expect.syntax !== 'VALID')
            continue;
        const harness = structuredCase(vector);
        if (!harness)
            continue;
        covered++;
        const evaluator = aec.createAuthorizationChainEvaluator({ requirement: requirement(vector.aec_expression.expression), nativeVerifiers: harness.nativeVerifiers });
        const result = await evaluator.evaluate(harness.chain, { expectedAction: action, verificationTime: NOW });
        const compiled = aec.compileAecRequirementExpression(vector.aec_expression.expression);
        // Reference eligibility, from the evaluator's own seam.
        const referenceTypes = internals.eligibleFactTypes(result.replay.facts);
        assert.deepEqual([...referenceTypes].sort(), [...vector.aec_expression.eligible_types].sort(), vector.id);
        assert.equal(compiled.evaluate(referenceTypes).value, result.satisfied, vector.id);
        // Mutant eligibility also credits facts whose native verification FAILED.
        const mutantTypes = new Set(result.replay.facts
            .filter((f) => f.eligible === true || f.native_verification === 'FAILED').map((f) => f.type));
        const mutantValue = compiled.evaluate(mutantTypes).value;
        assert.equal(compiled.parse_identity, evaluator.requirement_expression.parse_identity);
        if (compiled.parse_identity === vector.expect.parse_identity && mutantValue !== vector.expect.value)
            sameIdentityWrongValue.push(vector.id);
    }
    assert.ok(covered >= 40, `structured harness covered ${covered} valid vectors`);
    assert.ok(sameIdentityWrongValue.includes('table-13-left-to-right'), 'b and c FAILED, credited, flip the verdict');
    assert.ok(sameIdentityWrongValue.length >= 8, `only ${sameIdentityWrongValue.length} vectors caught the eligibility mutant`);
});
