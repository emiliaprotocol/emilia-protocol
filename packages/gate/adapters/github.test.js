// SPDX-License-Identifier: Apache-2.0
// Generated from github.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { createGate, createEg1Harness } from '../index.js';
import { createGithubManifest, createGithubAllowanceConnector, githubWorkflowInputsDigest, guardGithubAllowanceMutation, guardGithubMutation, GITHUB_OPS, } from './github.js';
import { allowanceDigest, issueGateAllowance } from '../allowance.js';
import { createMemoryCapabilityStore } from '../capability-receipt.js';
const GITHUB_CONNECTOR_ID = 'github:installation:101';
const githubConnector = (octokit) => createGithubAllowanceConnector({ octokit });
const currentAllowanceStatus = () => ({
    ok: true,
    status_epoch: 1,
    status_head_digest: `sha256:${'a'.repeat(64)}`,
});
function initializeAllowanceStatus(store, issued) {
    const status = currentAllowanceStatus();
    const result = store.advanceAllowanceStatus({
        allowance_profile_id: `${issued.allowance.tenant_id}/${issued.allowance.allowance_id}`,
        allowance_digest: allowanceDigest(issued.allowance),
        revision: issued.allowance.revision,
        status_epoch: status.status_epoch,
        status_head_digest: status.status_head_digest,
        expected_status_epoch: null,
        expected_status_head_digest: null,
        status: 'active',
    });
    assert.equal(result.ok, true);
}
function fakeOctokit(installationId = 101) {
    const calls = [];
    return {
        calls,
        request: async (route) => {
            assert.equal(route, 'GET /installation');
            return { data: { id: installationId } };
        },
        repos: {
            delete: async (p) => { calls.push(['delete', p]); return { status: 204 }; },
            addCollaborator: async (p) => { calls.push(['addCollaborator', p]); return { status: 201 }; },
            deleteBranchProtection: async (p) => { calls.push(['deleteBranchProtection', p]); return { status: 204 }; },
        },
        actions: {
            createWorkflowDispatch: async (p) => {
                calls.push(['workflowDispatch', p]);
                return { status: 204 };
            },
        },
    };
}
function setup(action) {
    const harness = createEg1Harness({ action });
    const gate = createGate({ manifest: createGithubManifest(), trustedKeys: [harness.publicKey], approverKeys: harness.approverKeys, quorumPolicy: harness.quorumPolicy, rpId: harness.rpId, allowedOrigins: harness.allowedOrigins, allowEphemeralStore: true });
    return { harness, gate, octokit: fakeOctokit() };
}
test('exposes the three destructive GitHub ops', () => {
    assert.deepEqual([...GITHUB_OPS].sort(), ['branch_protection.remove', 'permission.change', 'repo.delete']);
});
test('repo.delete WITHOUT a receipt never reaches GitHub', async () => {
    const { gate, octokit } = setup({ action_type: 'github.repo.delete', owner: 'acme', repo: 'prod' });
    await assert.rejects(() => guardGithubMutation(gate, octokit, { op: 'repo.delete', params: { owner: 'acme', repo: 'prod' } }), (e) => e.code === 'EMILIA_RECEIPT_REQUIRED' && e.status === 428);
    assert.equal(octokit.calls.length, 0, 'the GitHub API must not be called on refusal');
});
test('repo.delete WITH a valid Class-A receipt executes and returns a reliance packet', async () => {
    const { gate, harness, octokit } = setup({ action_type: 'github.repo.delete', owner: 'acme', repo: 'prod' });
    const receipt = harness.mint({ outcome: 'allow_with_signoff' });
    const { result, reliance, execution } = await guardGithubMutation(gate, octokit, {
        op: 'repo.delete', params: { owner: 'acme', repo: 'prod' }, receipt,
    });
    assert.equal(result.status, 204);
    assert.deepEqual(octokit.calls[0], ['delete', { owner: 'acme', repo: 'prod' }]);
    assert.equal(String(reliance.verdict).toLowerCase(), 'rely');
    assert.ok(execution.authorizes_decision);
});
test('repo.delete refuses when the call targets a DIFFERENT repo than was authorized (drift)', async () => {
    const { gate, harness, octokit } = setup({ action_type: 'github.repo.delete', owner: 'acme', repo: 'prod' });
    const receipt = harness.mint({ outcome: 'allow_with_signoff' }); // authorizes acme/prod
    await assert.rejects(() => guardGithubMutation(gate, octokit, { op: 'repo.delete', params: { owner: 'acme', repo: 'staging' }, receipt }), (e) => e.code === 'EMILIA_RECEIPT_REQUIRED' && /binding/.test(e.gate.reason));
    assert.equal(octokit.calls.length, 0);
});
test('repo.delete refuses a replayed receipt', async () => {
    const { gate, harness, octokit } = setup({ action_type: 'github.repo.delete', owner: 'acme', repo: 'prod' });
    const receipt = harness.mint({ outcome: 'allow_with_signoff' });
    await guardGithubMutation(gate, octokit, { op: 'repo.delete', params: { owner: 'acme', repo: 'prod' }, receipt });
    await assert.rejects(() => guardGithubMutation(gate, octokit, { op: 'repo.delete', params: { owner: 'acme', repo: 'prod' }, receipt }), (e) => /replay/.test(e.gate.reason));
    assert.equal(octokit.calls.length, 1, 'the replay must not reach GitHub a second time');
});
test('permission.change requires quorum: a Class-A receipt is refused', async () => {
    const action = { action_type: 'github.permission.change', owner: 'acme', repo: 'prod', username: 'mallory', permission: 'admin' };
    const { gate, harness, octokit } = setup(action);
    const classA = harness.mint({ outcome: 'allow_with_signoff' });
    await assert.rejects(() => guardGithubMutation(gate, octokit, { op: 'permission.change', params: { owner: 'acme', repo: 'prod', username: 'mallory', permission: 'admin' }, receipt: classA }), (e) => /assurance/.test(e.gate.reason));
    // With a quorum receipt it executes.
    const quorum = harness.mint({ outcome: 'allow_with_signoff', quorum: { signers: ['ep:a', 'ep:b'], threshold: 2 } });
    const { result } = await guardGithubMutation(gate, octokit, {
        op: 'permission.change', params: { owner: 'acme', repo: 'prod', username: 'mallory', permission: 'admin' }, receipt: quorum,
    });
    assert.equal(result.status, 201);
});
function issueWorkflowAllowance({ repository = 'acme/prod', connectorId = GITHUB_CONNECTOR_ID, allowedValues = {
    workflow: ['deploy-production.yml'],
    ref: ['refs/tags/v1.2.3'],
    inputs_digest: [githubWorkflowInputsDigest({
            artifact: 'sha256:abc123',
            region: 'us-east-1',
        })],
}, materialFields = [
    'action_type',
    'repository',
    'workflow',
    'ref',
    'inputs_digest',
    'workflow_inputs',
    'amount',
    'currency',
    'operation_id',
], } = {}) {
    const keys = generateKeyPairSync('ed25519');
    const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const issued = issueGateAllowance({
        authorizationReceipt: {
            '@version': 'EP-RECEIPT-v1',
            payload: {
                receipt_id: 'receipt:github-workflow-allowance:01',
                claim: { action_type: 'gate.allowance.issue', capability_only: true },
            },
        },
        allowance: {
            allowance_id: 'allowance:github-workflow:adapter',
            tenant_id: 'tenant:example',
            subject_id: 'agent:release:01',
            audience: 'gate:github:production',
            connector_id: connectorId,
            action_type: 'github.workflow.dispatch.production',
            revision: 1,
            supersedes_allowance_digest: null,
            presentation_digest: `sha256:${'1'.repeat(64)}`,
            issued_at: '2026-07-30T17:59:00.000Z',
            valid_from: '2026-07-30T18:00:00.000Z',
            expires_at: '2026-07-31T18:00:00.000Z',
            constraints: {
                currency: 'DISPATCH',
                aggregate_amount: 3,
                max_amount_per_action: 1,
                material_fields: materialFields,
                operation_id_field: 'operation_id',
                amount_field: 'amount',
                currency_field: 'currency',
                target_field: 'repository',
                allowed_targets: [repository],
                allowed_values: allowedValues,
            },
        },
        signer: {
            issuer_id: 'customer:security',
            key_id: 'key:allowance',
            private_key: keys.privateKey,
        },
        capabilityIssuerPrivateKey: keys.privateKey,
    });
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(issued.capabilityReceipt), true);
    initializeAllowanceStatus(store, issued);
    return {
        issued,
        store,
        trustedAllowanceKeys: {
            'key:allowance': {
                issuer_id: 'customer:security',
                public_key: publicKey,
            },
        },
        trustedCapabilityIssuerKeys: [publicKey],
    };
}
function workflowAllowanceArgs(issued, store, trustedAllowanceKeys, trustedCapabilityIssuerKeys) {
    return {
        allowance: issued.allowance,
        capabilityReceipt: issued.capabilityReceipt,
        secret: issued.secret,
        store,
        verifyAuthorizationReceipt: () => true,
        verifyAllowanceStatus: () => currentAllowanceStatus(),
        trustedAllowanceKeys,
        trustedCapabilityIssuerKeys,
        expected: {
            allowance_id: 'allowance:github-workflow:adapter',
            tenant_id: 'tenant:example',
            subject_id: 'agent:release:01',
            audience: 'gate:github:production',
            authorizer_id: 'customer:security',
        },
        now: Date.parse('2026-07-30T18:00:00.000Z'),
    };
}
test('typed GitHub production workflow allowance executes an exact in-envelope dispatch', async () => {
    const allowance = issueWorkflowAllowance();
    const octokit = fakeOctokit();
    const connector = await githubConnector(octokit);
    const inputs = { artifact: 'sha256:abc123', region: 'us-east-1' };
    const result = await guardGithubAllowanceMutation({
        connector,
        params: {
            owner: 'acme',
            repo: 'prod',
            workflow: 'deploy-production.yml',
            ref: 'refs/tags/v1.2.3',
            inputs,
        },
        operationId: 'github:dispatch:01',
        ...workflowAllowanceArgs(allowance.issued, allowance.store, allowance.trustedAllowanceKeys, allowance.trustedCapabilityIssuerKeys),
    });
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.equal(result.result.status, 204);
    assert.deepEqual(octokit.calls, [[
            'workflowDispatch',
            {
                owner: 'acme',
                repo: 'prod',
                workflow_id: 'deploy-production.yml',
                ref: 'refs/tags/v1.2.3',
                inputs,
            },
        ]]);
    assert.match(githubWorkflowInputsDigest(inputs), /^sha256:[0-9a-f]{64}$/);
});
test('typed GitHub workflow allowance refuses a different repository and never calls GitHub', async () => {
    const allowance = issueWorkflowAllowance();
    const octokit = fakeOctokit();
    const connector = await githubConnector(octokit);
    const result = await guardGithubAllowanceMutation({
        connector,
        params: {
            owner: 'acme',
            repo: 'staging',
            workflow: 'deploy-production.yml',
            ref: 'refs/tags/v1.2.3',
            inputs: { artifact: 'sha256:abc123' },
        },
        operationId: 'github:dispatch:target-drift',
        ...workflowAllowanceArgs(allowance.issued, allowance.store, allowance.trustedAllowanceKeys, allowance.trustedCapabilityIssuerKeys),
    });
    assert.deepEqual(result, { ok: false, reason: 'allowance_target_not_allowed' });
    assert.equal(octokit.calls.length, 0);
});
test('typed GitHub workflow allowance refuses workflow, ref, or inputs substitution', async () => {
    const allowance = issueWorkflowAllowance();
    const octokit = fakeOctokit();
    const connector = await githubConnector(octokit);
    const result = await guardGithubAllowanceMutation({
        connector,
        params: {
            owner: 'acme',
            repo: 'prod',
            workflow: 'deploy-production.yml',
            ref: 'refs/heads/unreviewed',
            inputs: { artifact: 'sha256:attacker', region: 'us-east-1' },
        },
        operationId: 'github:dispatch:field-drift',
        ...workflowAllowanceArgs(allowance.issued, allowance.store, allowance.trustedAllowanceKeys, allowance.trustedCapabilityIssuerKeys),
    });
    assert.deepEqual(result, { ok: false, reason: 'allowance_field_value_not_allowed' });
    assert.equal(octokit.calls.length, 0);
});
test('typed GitHub workflow allowance refuses a non-matching material-field shape', async () => {
    const allowance = issueWorkflowAllowance({
        materialFields: [
            'action_type',
            'repository',
            'workflow',
            'ref',
            'amount',
            'currency',
            'operation_id',
        ],
        allowedValues: {
            workflow: ['deploy-production.yml'],
            ref: ['refs/tags/v1.2.3'],
        },
    });
    const octokit = fakeOctokit();
    const connector = await githubConnector(octokit);
    const result = await guardGithubAllowanceMutation({
        connector,
        params: {
            owner: 'acme',
            repo: 'prod',
            workflow: 'deploy-production.yml',
            ref: 'refs/tags/v1.2.3',
            inputs: { artifact: 'sha256:abc123' },
        },
        operationId: 'github:dispatch:shape-drift',
        ...workflowAllowanceArgs(allowance.issued, allowance.store, allowance.trustedAllowanceKeys, allowance.trustedCapabilityIssuerKeys),
    });
    assert.deepEqual(result, { ok: false, reason: 'allowance_action_shape_invalid' });
    assert.equal(octokit.calls.length, 0);
});
test('typed GitHub dispatch executes the immutable verified action when caller params mutate during verification', async () => {
    const allowance = issueWorkflowAllowance();
    const octokit = fakeOctokit();
    const connector = await githubConnector(octokit);
    const params = {
        owner: 'acme',
        repo: 'prod',
        workflow: 'deploy-production.yml',
        ref: 'refs/tags/v1.2.3',
        inputs: { artifact: 'sha256:abc123', region: 'us-east-1' },
    };
    const args = workflowAllowanceArgs(allowance.issued, allowance.store, allowance.trustedAllowanceKeys, allowance.trustedCapabilityIssuerKeys);
    const result = await guardGithubAllowanceMutation({
        connector,
        params,
        operationId: 'github:dispatch:mutation',
        ...args,
        verifyAuthorizationReceipt: async () => {
            params.repo = 'attacker';
            params.ref = 'refs/heads/unreviewed';
            params.inputs.artifact = 'sha256:attacker';
            return true;
        },
    });
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.deepEqual(octokit.calls, [[
            'workflowDispatch',
            {
                owner: 'acme',
                repo: 'prod',
                workflow_id: 'deploy-production.yml',
                ref: 'refs/tags/v1.2.3',
                inputs: { artifact: 'sha256:abc123', region: 'us-east-1' },
            },
        ]]);
});
test('typed GitHub dispatch refuses cross-protocol and cross-installation connector substitution', async () => {
    for (const [signedConnectorId, installationId] of [
        ['stripe:acct_authorized', GITHUB_CONNECTOR_ID],
        [GITHUB_CONNECTOR_ID, 202],
    ]) {
        const allowance = issueWorkflowAllowance({ connectorId: signedConnectorId });
        const octokit = fakeOctokit(typeof installationId === 'number' ? installationId : 101);
        const connector = await githubConnector(octokit);
        const result = await guardGithubAllowanceMutation({
            connector,
            params: {
                owner: 'acme',
                repo: 'prod',
                workflow: 'deploy-production.yml',
                ref: 'refs/tags/v1.2.3',
                inputs: { artifact: 'sha256:abc123', region: 'us-east-1' },
            },
            operationId: `github:connector:${installationId}`,
            ...workflowAllowanceArgs(allowance.issued, allowance.store, allowance.trustedAllowanceKeys, allowance.trustedCapabilityIssuerKeys),
        });
        assert.deepEqual(result, { ok: false, reason: 'connector_mismatch' });
        assert.equal(octokit.calls.length, 0);
    }
});
