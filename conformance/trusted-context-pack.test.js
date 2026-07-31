// SPDX-License-Identifier: Apache-2.0
// Generated from trusted-context-pack.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createApertoMemoryContextProvider } from '../packages/gate/apertomemory-context.js';
import { createTrustedContextEvaluator } from '../packages/gate/trusted-context.js';
const VECTOR = fileURLToPath(new URL('./vectors/trusted-context.v1.json', import.meta.url));
const GENERATOR = fileURLToPath(new URL('./vectors/generate-trusted-context.mjs', import.meta.url));
const vector = JSON.parse(readFileSync(VECTOR, 'utf8'));
function evaluatorFor(testCase) {
    const environment = structuredClone(vector.environment);
    if (testCase.mutation === 'adapter_status_stale') {
        environment.projection_adapter_status_checked_at = '2026-07-29T16:00:00.000Z';
    }
    if (testCase.mutation === 'adapter_revoked') {
        environment.projection_adapter_pin.status = 'revoked';
        environment.projection_adapter_pin.revoked_at = '2026-07-29T17:00:45.000Z';
    }
    if (testCase.mutation === 'forbid_authentication_exclusion') {
        environment.policy.allowed_exclusion_reasons = ['policy_filtered'];
    }
    const projectionPin = environment.projection_adapter_pin;
    const bindingPin = environment.binding_signer_pin;
    const provider = createApertoMemoryContextProvider({
        adapterKeys: {
            [projectionPin.key_id]: {
                public_key_spki_b64u: projectionPin.public_key_spki_b64u,
                status: projectionPin.status,
                valid_from: projectionPin.valid_from,
                valid_to: projectionPin.valid_to,
                revoked_at: projectionPin.revoked_at,
            },
        },
        statusCheckedAt: environment.projection_adapter_status_checked_at,
    });
    return createTrustedContextEvaluator({
        providers: [provider],
        policy: environment.policy,
        bindingKeys: { [bindingPin.key_id]: bindingPin },
        bindingStatusCheckedAt: environment.binding_signer_status_checked_at,
        expectedBindingNonce: environment.expected_binding_nonce,
        verificationTime: environment.verification_time,
    });
}
function inputFor(testCase) {
    const value = structuredClone(vector.fixture);
    if (testCase.mutation === 'action_diff_digest')
        value.action.diff_digest = `sha256:${'e'.repeat(64)}`;
    if (testCase.mutation === 'projection_byte_length')
        value.evidence.projection_record.projection.byte_length += 1;
    if (testCase.mutation === 'binding_signature') {
        const signature = value.evidence.context_binding.proof.signature_b64u;
        value.evidence.context_binding.proof.signature_b64u = `${signature[0] === 'A' ? 'B' : 'A'}${signature.slice(1)}`;
    }
    if (testCase.mutation === 'action_binding_digest') {
        value.action.trusted_context.context_binding_digest = `sha256:${'f'.repeat(64)}`;
    }
    if (testCase.mutation === 'binding_nonce') {
        value.evidence.context_binding.nonce = 'ctx_vector_nonce_for_another_admission';
    }
    return value;
}
test('Trusted Context Pack vector is deterministic', () => {
    execFileSync(process.execPath, [GENERATOR, '--check'], { stdio: 'pipe' });
});
test('Trusted Context Pack accepts the positive and refuses every hostile vector', () => {
    assert.equal(vector['@version'], 'EP-TRUSTED-CONTEXT-CONFORMANCE-v1');
    assert.equal(vector.cases.length, 9);
    for (const testCase of vector.cases) {
        const result = evaluatorFor(testCase)(inputFor(testCase));
        assert.equal(result.state, testCase.expect.state, `${testCase.id}: ${JSON.stringify(result)}`);
        assert.equal(result.reason, testCase.expect.reason, testCase.id);
        assert.equal(result.authorizes, false, `${testCase.id} must never authorize`);
    }
});
