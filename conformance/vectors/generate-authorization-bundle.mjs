#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from generate-authorization-bundle.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import crypto from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { digestAeb } from '../../packages/verify/aeb-adapter-contract.js';
const NOW = '2026-08-09T18:00:00Z';
const AUDIENCE = 'https://payments.example.com';
const ACTION = {
    action_type: 'payment.release.1',
    initiator: 'ep:entity:agent-recon-7',
    parameters: { amount_minor: 12550, currency: 'USD', payee: 'merchant:7' },
};
const AUTHORIZATION_DETAILS = [{
        type: 'payment_initiation',
        amount_minor: 12550,
        currency: 'USD',
        payee: 'merchant:7',
    }];
const BINDING = {
    profile: 'EP-OAUTH-RAR-AUTHORIZATION-BINDING-v1',
    authorization_server: 'https://as.example.com',
    transaction_id: '97053963-771d-49cc-a4e3-20aad399c312',
    actor: 'spiffe://example.com/agent/recon-7',
    delegated_subject: 'user:alice',
    authorization_details_digest: digestAeb(AUTHORIZATION_DETAILS),
    action_mapping_profile: 'https://profiles.example.com/payment-release-v1',
};
const NATIVE_BINDING = {
    profile: 'EXAMPLE-NATIVE-MANDATE-BINDING-v1',
    mandate_id: 'mandate:release-7',
    actor: 'agent:recon-7',
    action_digest: digestAeb(ACTION),
};
const POLICY_HASH = digestAeb({ policy: 'payments', version: 4 });
const TEST_KEYS = [
    {
        id: 'ep:key:controller#1',
        approver: 'ep:approver:controller',
        private_key: 'MC4CAQAwBQYDK2VwBCIEIC5CT7cnPBXmtD4GF3ZOkF0y1CaLPGozqzL9foq17-iW',
        public_key: 'MCowBQYDK2VwAyEA8-JGCUJSYAflpoZeFhT3mweYL5RbPMO4xcwShb5M0X0',
    },
    {
        id: 'ep:key:treasurer#1',
        approver: 'ep:approver:treasurer',
        private_key: 'MC4CAQAwBQYDK2VwBCIEIIfOl4Dl0C5zVMoUFPU5YJCjbHfhr4rGmeFDMNQcEMXP',
        public_key: 'MCowBQYDK2VwAyEATxdXWH3M--29JIlek938V6z8JblWNTQErUIa-J-4DpI',
    },
    {
        id: 'ep:key:risk-officer#1',
        approver: 'ep:approver:risk-officer',
        private_key: 'MC4CAQAwBQYDK2VwBCIEIHcFDwdSpTxBTR2O73P0ad72-9RXfLkDC936JchWH18A',
        public_key: 'MCowBQYDK2VwAyEAt9zVJ5WG2hLmkT6Lm5xw9ZoPwsm_WzQwPhrVuZftsqA',
    },
];
const BASE_KEYS = TEST_KEYS.slice(0, 2);
function clone(value) {
    return structuredClone(value);
}
function signContext(context, key) {
    const contextHash = digestAeb(context);
    const privateKey = crypto.createPrivateKey({
        key: Buffer.from(key.private_key, 'base64url'),
        type: 'pkcs8',
        format: 'der',
    });
    return {
        context_hash: contextHash,
        signature: crypto.sign(null, Buffer.from(contextHash.slice('sha256:'.length), 'hex'), privateKey).toString('base64url'),
        key_class: 'B',
        approver_key_id: key.id,
        signed_at: context.issued_at,
    };
}
function fixture(input = {}) {
    const action = clone(input.action ?? ACTION);
    const actionHash = digestAeb(action);
    const authorizationInstance = input.authorizationInstance
        ?? `b64u:${Buffer.alloc(16, 0x41).toString('base64url')}`;
    const binding = input.binding === undefined ? clone(BINDING) : input.binding;
    const keys = input.keys ?? BASE_KEYS;
    const requiredApprovals = input.requiredApprovals ?? 2;
    const contexts = input.contexts ?? keys.map((key, index) => ({
        ep_version: '1.0',
        context_type: 'ep.signoff.v1',
        action_hash: actionHash,
        policy_id: 'ep:policy:payments@v4',
        policy_hash: POLICY_HASH,
        initiator: action.initiator,
        authorization_instance: authorizationInstance,
        audience: AUDIENCE,
        approver: key.approver,
        approver_index: index + 1,
        required_approvals: requiredApprovals,
        nonce: `b64u:${Buffer.alloc(16, index + 1).toString('base64url')}`,
        issued_at: '2026-08-09T17:55:00Z',
        expires_at: '2026-08-09T18:05:00Z',
        ...(binding === null ? {} : { authorization_binding: clone(binding) }),
    }));
    const signoffCount = input.signoffCount ?? contexts.length;
    const signoffs = contexts.slice(0, signoffCount)
        .map((context, index) => signContext(context, keys[index]));
    return {
        bundle: {
            bundle_version: 'EP-AUTHORIZATION-BUNDLE-v1',
            bundle_id: 'ep:authorization-bundle:case-0001',
            action,
            action_hash: actionHash,
            contexts,
            signoffs,
            approver_key_proofs: [],
            presentation_evidence: [],
        },
        approver_keys: Object.fromEntries(keys.map((key) => [key.id, {
                approver_id: key.approver,
                public_key: key.public_key,
                key_class: 'B',
                valid_from: '2026-01-01T00:00:00Z',
                valid_to: '2027-01-01T00:00:00Z',
                compromised_at: null,
            }])),
    };
}
function baseCase(id, expect, replacement = {}) {
    const built = fixture();
    return {
        id,
        bundle: built.bundle,
        approver_keys: built.approver_keys,
        expected_approvers: BASE_KEYS.map((key) => key.approver),
        accepted_key_classes: ['B'],
        current_policy: {
            policy_hash: POLICY_HASH,
            decision: 'PERMIT',
            checked_at: '2026-08-09T17:59:00Z',
            expires_at: '2026-08-09T18:01:00Z',
        },
        expected_action: clone(ACTION),
        expected_authorization_instance: built.bundle.contexts[0].authorization_instance,
        expected_authorization_binding: clone(BINDING),
        require_authorization_binding: true,
        audience: AUDIENCE,
        now: NOW,
        require_current_status: false,
        expect,
        ...replacement,
    };
}
const cases = [];
cases.push(baseCase('valid-two-person-oauth-bound-bundle', { verdict: 'SATISFIED', reasons: [] }));
{
    const built = fixture({ keys: TEST_KEYS, requiredApprovals: 2, signoffCount: 2 });
    cases.push(baseCase('valid-two-of-three-oauth-bound-bundle', {
        verdict: 'SATISFIED', reasons: [],
    }, {
        bundle: built.bundle,
        approver_keys: built.approver_keys,
        expected_approvers: TEST_KEYS.map((key) => key.approver),
    }));
}
{
    const first = fixture({
        authorizationInstance: `b64u:${Buffer.alloc(16, 0x41).toString('base64url')}`,
    });
    const second = fixture({
        authorizationInstance: `b64u:${Buffer.alloc(16, 0x42).toString('base64url')}`,
    });
    first.bundle.contexts[1] = clone(second.bundle.contexts[1]);
    first.bundle.signoffs[1] = clone(second.bundle.signoffs[1]);
    cases.push(baseCase('cross-ceremony-signoff-splicing', {
        verdict: 'REFUSE', reasons: ['authorization_instance_mismatch'],
    }, {
        bundle: first.bundle,
        approver_keys: first.approver_keys,
    }));
}
cases.push(baseCase('presenter-selected-authorization-instance', {
    verdict: 'REFUSE', reasons: ['authorization_instance_mismatch'],
}, {
    expected_authorization_instance: `b64u:${Buffer.alloc(16, 0x42).toString('base64url')}`,
}));
{
    const built = fixture({ binding: clone(NATIVE_BINDING) });
    cases.push(baseCase('valid-non-oauth-native-binding', {
        verdict: 'SATISFIED', reasons: [],
    }, {
        bundle: built.bundle,
        approver_keys: built.approver_keys,
        expected_authorization_binding: clone(NATIVE_BINDING),
    }));
}
cases.push(baseCase('approve-a-execute-b', {
    verdict: 'REFUSE', reasons: ['action_mismatch'],
}, {
    expected_action: { ...clone(ACTION), parameters: { ...ACTION.parameters, amount_minor: 50000 } },
}));
cases.push(baseCase('wrong-resource-server-audience', {
    verdict: 'REFUSE', reasons: ['context_audience_mismatch'],
}, { audience: 'https://attacker.example.com' }));
cases.push(baseCase('wrong-agent-actor', {
    verdict: 'REFUSE', reasons: ['authorization_binding_mismatch'],
}, { expected_authorization_binding: { ...clone(BINDING), actor: 'spiffe://example.com/agent/other' } }));
cases.push(baseCase('wrong-delegated-subject', {
    verdict: 'REFUSE', reasons: ['authorization_binding_mismatch'],
}, { expected_authorization_binding: { ...clone(BINDING), delegated_subject: 'user:bob' } }));
{
    const built = fixture({ binding: null });
    cases.push(baseCase('generic-confirmation-without-native-transaction-binding', {
        verdict: 'REFUSE', reasons: ['authorization_binding_required'],
    }, { bundle: built.bundle, approver_keys: built.approver_keys, expected_authorization_binding: undefined }));
}
{
    const built = fixture();
    delete built.bundle.contexts[1].authorization_binding;
    built.bundle.signoffs[1] = signContext(built.bundle.contexts[1], TEST_KEYS[1]);
    cases.push(baseCase('one-context-omits-native-binding', {
        verdict: 'REFUSE', reasons: ['contexts_do_not_share_one_policy_audience_and_binding'],
    }, { bundle: built.bundle, approver_keys: built.approver_keys }));
}
{
    const built = fixture({ binding: { native_id: 'missing-profile' } });
    cases.push(baseCase('profileless-native-binding-is-malformed', {
        verdict: 'REFUSE', reasons: ['authorization_binding_malformed'],
    }, { bundle: built.bundle, approver_keys: built.approver_keys }));
}
cases.push(baseCase('native-authorization-binding-unavailable', {
    verdict: 'INDETERMINATE', reasons: ['native_authorization_binding_unavailable'],
}, { expected_authorization_binding: undefined }));
cases.push(baseCase('expired-approval-window', {
    verdict: 'REFUSE', reasons: ['context_outside_validity_window'],
}, { now: '2026-08-09T18:06:00Z' }));
cases.push(baseCase('required-status-stale', {
    verdict: 'INDETERMINATE', reasons: ['current_status_unavailable_or_stale'],
}, {
    require_current_status: true,
    current_status: {
        checked_at: '2026-08-09T17:40:00Z',
        expires_at: '2026-08-09T17:50:00Z',
        revoked_key_ids: [],
    },
}));
cases.push(baseCase('required-status-provider-timeout', {
    verdict: 'INDETERMINATE', reasons: ['current_status_unavailable_or_stale'],
}, {
    require_current_status: true,
    current_status: {
        checked_at: NOW,
        expires_at: '2026-08-09T18:01:00Z',
        unavailable: true,
        revoked_key_ids: [],
    },
}));
cases.push(baseCase('approver-key-revoked', {
    verdict: 'REFUSE', reasons: ['approver_key_revoked'],
}, {
    require_current_status: true,
    current_status: {
        checked_at: '2026-08-09T17:59:00Z',
        expires_at: '2026-08-09T18:01:00Z',
        revoked_key_ids: [TEST_KEYS[0].id],
    },
}));
{
    const built = fixture();
    built.bundle.signoffs = built.bundle.signoffs.slice(0, 1);
    cases.push(baseCase('incomplete-quorum', {
        verdict: 'REFUSE', reasons: [
            'separation_of_duties_or_quorum_failed',
            'signoff_context_coverage_failed',
        ],
    }, { bundle: built.bundle, approver_keys: built.approver_keys }));
}
{
    const built = fixture();
    built.bundle.contexts = [clone(built.bundle.contexts[0]), clone(built.bundle.contexts[0])];
    built.bundle.signoffs = [clone(built.bundle.signoffs[0]), clone(built.bundle.signoffs[0])];
    cases.push(baseCase('duplicate-human-does-not-satisfy-quorum', {
        verdict: 'REFUSE', reasons: ['separation_of_duties_or_quorum_failed'],
    }, { bundle: built.bundle, approver_keys: built.approver_keys }));
}
{
    const action = { ...clone(ACTION), initiator: TEST_KEYS[0].approver };
    const built = fixture({ action });
    cases.push(baseCase('initiator-self-approval', {
        verdict: 'REFUSE', reasons: ['separation_of_duties_or_quorum_failed'],
    }, { bundle: built.bundle, approver_keys: built.approver_keys, expected_action: action }));
}
{
    const built = fixture();
    built.bundle.contexts[1].policy_hash = digestAeb({ policy: 'payments', version: 5 });
    built.bundle.signoffs[1] = signContext(built.bundle.contexts[1], TEST_KEYS[1]);
    cases.push(baseCase('mismatched-policy-between-contexts', {
        verdict: 'REFUSE', reasons: ['contexts_do_not_share_one_policy_audience_and_binding'],
    }, { bundle: built.bundle, approver_keys: built.approver_keys }));
}
{
    const built = fixture();
    built.bundle.signoffs[0].signature = Buffer.alloc(64).toString('base64url');
    cases.push(baseCase('invalid-approver-signature', {
        verdict: 'REFUSE', reasons: ['signoff_signature_invalid'],
    }, { bundle: built.bundle, approver_keys: built.approver_keys }));
}
cases.push(baseCase('unpinned-or-different-action-mapping-profile', {
    verdict: 'REFUSE', reasons: ['authorization_binding_mismatch'],
}, {
    expected_authorization_binding: {
        ...clone(BINDING),
        action_mapping_profile: 'https://profiles.example.com/lossy-payment-v0',
    },
}));
cases.push(baseCase('dynamic-plan-expands-beyond-approved-action', {
    verdict: 'REFUSE', reasons: ['action_mismatch'],
}, {
    expected_action: {
        ...clone(ACTION),
        parameters: { ...ACTION.parameters, recurring: true },
    },
}));
{
    const built = fixture();
    built.bundle.unregistered_member = true;
    cases.push(baseCase('closed-bundle-rejects-unknown-member', {
        verdict: 'REFUSE', reasons: ['bundle_malformed'],
    }, { bundle: built.bundle, approver_keys: built.approver_keys }));
}
cases.push(baseCase('current-policy-provider-unavailable', {
    verdict: 'INDETERMINATE', reasons: ['current_policy_unavailable_or_stale'],
}, {
    current_policy: {
        policy_hash: POLICY_HASH,
        decision: 'PERMIT',
        checked_at: '2026-08-09T17:59:00Z',
        expires_at: '2026-08-09T18:01:00Z',
        unavailable: true,
    },
}));
cases.push(baseCase('presenter-selected-approver-set-does-not-match-policy', {
    verdict: 'REFUSE', reasons: ['approver_selection_mismatch'],
}, { expected_approvers: [TEST_KEYS[0].approver] }));
const output = {
    '@version': 'EP-AUTHORIZATION-BUNDLE-CASES-v1',
    status: 'implementation-profile-cases',
    claim_boundary: 'These vectors test pre-execution evidence satisfaction. SATISFIED is not an authorization decision, grant, reservation, consumption record, or execution proof.',
    generated_by: 'conformance/vectors/generate-authorization-bundle.mts',
    cases,
};
await writeFile(new URL('./authorization-bundle.v1.json', import.meta.url), `${JSON.stringify(output, null, 2)}\n`);
console.log(`Generated ${cases.length} Authorization Bundle hostile cases.`);
