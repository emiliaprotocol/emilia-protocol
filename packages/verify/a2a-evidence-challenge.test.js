// SPDX-License-Identifier: Apache-2.0
// Generated from a2a-evidence-challenge.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { A2A_AE_CHALLENGE_EXTENSION_URI, A2A_AP2_NATIVE_PRESENTATION_METHOD, createA2AAuthorizationChallengeTask, verifyA2AAuthorizationChallengeTask, } from './a2a-evidence-challenge.js';
import { digestAeb } from './aeb-adapter-contract.js';
const ACTION = Object.freeze({ action_type: 'payment.release.1', payment_instruction_id: 'pi-a2a-1' });
const NOW = '2026-08-09T17:00:00.000Z';
function challenge(overrides = {}) {
    return {
        '@version': 'AE-CHALLENGE-v1',
        challenge_id: 'challenge-a2a-1',
        nonce: 'challenge-nonce-a2a-0001',
        action_digest: digestAeb(ACTION),
        action_profile: 'https://emiliaprotocol.ai/profiles/artifact-digest-v1',
        reliance_purpose: 'authorize one payment release',
        policy_id: 'policy:a2a-ap2:test',
        policy_digest: digestAeb({ policy: 'a2a-ap2-test' }),
        required_evidence: [{
                requirement_id: 'ap2-native-authorization',
                type: 'ap2-native-authorization',
                max_age_sec: 300,
                status: 'current',
                profiles: ['ap2-agent-authorization-v0.2'],
            }],
        present_as: [A2A_AP2_NATIVE_PRESENTATION_METHOD],
        obtain_hints: [],
        expires_at: '2026-08-09T17:05:00.000Z',
        audience: 'executor.example',
        ...overrides,
    };
}
describe('AE-CHALLENGE in the A2A authorization interruption', () => {
    it('places the transport-neutral challenge in an AUTH_REQUIRED TaskStatus message', () => {
        const task = createA2AAuthorizationChallengeTask({
            task_id: 'task-a2a-1',
            context_id: 'context-a2a-1',
            message_id: 'message-a2a-challenge-1',
            timestamp: '2026-08-09T16:59:30.000Z',
            challenge: challenge(),
        });
        assert.equal(task.status.state, 'TASK_STATE_AUTH_REQUIRED');
        assert.deepEqual(task.status.message.extensions, [A2A_AE_CHALLENGE_EXTENSION_URI]);
        assert.equal(task.status.message.parts[0].text, 'Authorization evidence required.');
        assert.deepEqual(task.status.message.metadata[A2A_AE_CHALLENGE_EXTENSION_URI], challenge());
        const checked = verifyA2AAuthorizationChallengeTask(task, ACTION, NOW);
        assert.equal(checked.valid, true, JSON.stringify(checked.reasons));
        assert.equal(checked.authorization_granted, false);
        assert.equal(checked.admission_transferred, false);
    });
    it('rejects INPUT_REQUIRED substitution, action swap, and an expired challenge', () => {
        const task = createA2AAuthorizationChallengeTask({
            task_id: 'task-a2a-1',
            context_id: 'context-a2a-1',
            message_id: 'message-a2a-challenge-1',
            timestamp: '2026-08-09T16:59:30.000Z',
            challenge: challenge(),
        });
        const substituted = structuredClone(task);
        substituted.status.state = 'TASK_STATE_INPUT_REQUIRED';
        assert.ok(verifyA2AAuthorizationChallengeTask(substituted, ACTION, NOW).reasons.includes('task_not_auth_required'));
        const swapped = verifyA2AAuthorizationChallengeTask(task, { ...ACTION, payment_instruction_id: 'pi-a2a-2' }, NOW);
        assert.ok(swapped.reasons.includes('challenge_action_mismatch'));
        const expired = createA2AAuthorizationChallengeTask({
            task_id: 'task-a2a-1',
            context_id: 'context-a2a-1',
            message_id: 'message-a2a-challenge-1',
            timestamp: '2026-08-09T16:50:00.000Z',
            challenge: challenge({ expires_at: '2026-08-09T16:59:59.000Z' }),
        });
        assert.ok(verifyA2AAuthorizationChallengeTask(expired, ACTION, NOW).reasons.includes('challenge_expired'));
    });
});
