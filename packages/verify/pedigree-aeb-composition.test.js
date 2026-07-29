// SPDX-License-Identifier: Apache-2.0
// Generated from pedigree-aeb-composition.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
const vector = JSON.parse(readFileSync(new URL('../../conformance/vectors/pedigree-aeb-composition.v1.json', import.meta.url), 'utf8'));
function evaluate(input) {
    if (input.native_verification !== 'VERIFIED') {
        return {
            native: input.native_verification,
            mapping: 'INDETERMINATE',
            role: 'delegated_agent_authority',
            role_satisfaction: 'UNSATISFIED',
            authorization: 'NOT_EVALUATED',
        };
    }
    if (input.phase === 'PRE_ACTION' && input.artifact_kind === 'PEDIGREE_COMPLETION_BLOCK') {
        return {
            native: 'VERIFIED',
            mapping: 'INDETERMINATE',
            role: 'post_effect_outcome_evidence',
            role_satisfaction: 'UNSATISFIED',
            authorization: 'NOT_EVALUATED',
        };
    }
    const exact = input.mapped_caid !== null && input.mapped_caid === input.observed_caid;
    if (!exact) {
        return {
            native: 'VERIFIED',
            mapping: 'NOT_EQUIVALENT',
            role: 'delegated_agent_authority',
            role_satisfaction: 'UNSATISFIED',
            authorization: 'NOT_EVALUATED',
        };
    }
    if (input.mandate_decision !== 'PERMIT' || input.ceiling_decision !== 'PERMIT') {
        return {
            native: 'VERIFIED',
            mapping: 'EQUIVALENT_UNDER_PROFILE',
            role: 'delegated_agent_authority',
            role_satisfaction: 'UNSATISFIED',
            authorization: 'NOT_EVALUATED',
        };
    }
    return {
        native: 'VERIFIED',
        mapping: 'EQUIVALENT_UNDER_PROFILE',
        role: 'delegated_agent_authority',
        role_satisfaction: 'SATISFIED',
        authorization: 'NOT_EVALUATED',
    };
}
test('PEDIGREE composition vector has one positive and five hostile cases', () => {
    assert.equal(vector['@version'], 'EP-PEDIGREE-AEB-COMPOSITION-CONFORMANCE-v1');
    assert.equal(vector.status, 'candidate_mapping_pending_source_author_review');
    assert.equal(vector.cases.length, 6);
    assert.equal(vector.cases.filter((item) => item.id.startsWith('positive_')).length, 1);
    assert.equal(vector.cases.filter((item) => item.id.startsWith('negative_')).length, 5);
    for (const item of vector.cases)
        assert.deepEqual(evaluate(item.input), item.expect, item.id);
});
test('no vector collapses verified, satisfied, or completion evidence into authorization', () => {
    for (const item of vector.cases) {
        if (item.expect.mapping === 'EQUIVALENT_UNDER_PROFILE') {
            assert.notEqual(item.expect.authorization, 'AUTHORIZED', item.id);
        }
        if (item.input.artifact_kind === 'PEDIGREE_COMPLETION_BLOCK') {
            assert.equal(item.expect.role, 'post_effect_outcome_evidence', item.id);
            assert.notEqual(item.expect.role_satisfaction, 'SATISFIED', item.id);
        }
    }
});
