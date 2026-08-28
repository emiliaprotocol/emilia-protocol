// SPDX-License-Identifier: Apache-2.0
// Generated from aeb-ccs-v14-adapter.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { digestAeb, mappingProfileDigest, } from './dist/aeb-adapter-contract.js';
import { CCS_V14_AEB_CONFIG_VERSION, CCS_V14_AEB_TRUST_ROOT_VERSION, CCS_V14_CAID_MAPPER_ID, CCS_V14_CAID_MAPPING_VERSION, CCS_V14_VECTOR_COMMIT, CCS_V14_VECTOR_MANIFEST_SHA256, createCcsV14AebActionDefinition, createCcsV14AebAdapter, } from './dist/aeb-ccs-v14-adapter.js';
import { canonicalizeFiniteJson } from './dist/strict-json.js';
const NOW = '2025-06-15T16:00:30.000Z';
const NOW_SECONDS = Date.parse(NOW) / 1000;
const ACTION_TYPE = 'github.issue-update.1';
const ARGS = {
    repository: 'emiliaprotocol/emilia-protocol',
    issue_number: 538,
    title: 'Record missing-evidence disposition',
    body: 'Evidence unavailable; no execution authority inferred.',
    state: 'open',
};
const PRIVATE_KEY = crypto.createPrivateKey({
    key: Buffer.concat([
        Buffer.from('302e020100300506032b657004220420', 'hex'),
        crypto.createHash('sha256')
            .update('ccs-conformance-vectors/v1/independent-checker')
            .digest(),
    ]),
    format: 'der',
    type: 'pkcs8',
});
const PUBLIC_RAW = crypto.createPublicKey(PRIVATE_KEY)
    .export({ type: 'spki', format: 'der' }).subarray(-32);
function hash(value) {
    return crypto.createHash('sha256')
        .update(canonicalizeFiniteJson(value), 'utf8').digest('hex');
}
function sign(unsigned) {
    return {
        ...unsigned,
        signature: crypto.sign(null, Buffer.from(canonicalizeFiniteJson(unsigned), 'utf8'), PRIVATE_KEY).toString('base64'),
    };
}
function mint(args = ARGS) {
    const response = { issue_url: 'https://github.com/emiliaprotocol/emilia-protocol/issues/538', updated: true };
    const unsigned = {
        trace_id: 'ccs-v14-emilia-github-trace',
        receipt_version: '1.4',
        verdict: 'allow',
        timestamp: NOW_SECONDS - 20,
        tool: 'github_issue_update',
        tool_call_id: 'call-ccs-v14-emilia-001',
        params_hash: hash({ tool: 'github_issue_update', arguments: args }),
        args_digest: hash(args),
        rule_summary: 'github-issue-update-conformance',
        rule_version: '1.4.0-conformance',
        request_hash: hash({ tool: 'github_issue_update', arguments: args }),
        response_hash: hash(response),
        runtime_context_hash: hash({ environment: 'test', relying_party: 'emilia-github-gate' }),
        config_hash: hash({ policy: 'ccs-v14-emilia-github-v1' }),
        verifier_source_class: 'EMILIAIndependentComposition',
        deployment_mode: 'test-in-process',
        issuer: 'ccs-conformance/v1.4.0',
        audience: 'rp:emilia-github-gate',
        nonce: 'ccs-v14-emilia-nonce-001',
        sequence: 0,
        issued_at: NOW_SECONDS - 20,
        expires_at: NOW_SECONDS + 60,
        max_clock_skew: 30,
        action: 'github_issue_update.execute',
        signing_algorithm: 'Ed25519',
        public_key_fingerprint: crypto.createHash('sha256').update(PUBLIC_RAW).digest('hex').slice(0, 16),
        public_key: PUBLIC_RAW.toString('base64'),
        verified_at: NOW_SECONDS - 20,
        latency_us: 842,
    };
    return { receipt: sign(unsigned), tool_args: args, response_body: response };
}
function profile() {
    const value = {
        version: CCS_V14_CAID_MAPPING_VERSION,
        definition: createCcsV14AebActionDefinition(ACTION_TYPE),
        registry_entry_ref: 'mapping:ccs-v14-github-action',
        mapper_id: CCS_V14_CAID_MAPPER_ID,
        resolver: {
            id: CCS_V14_CAID_MAPPER_ID,
            version: '1',
            implementation_digest: digestAeb({ implementation: CCS_V14_CAID_MAPPER_ID, version: '1' }),
        },
        semantic_equivalence: {
            assertion: 'EQUIVALENT_UNDER_PROFILE',
            loss_policy: 'NO_MATERIAL_FIELD_LOSS',
            omitted_material_fields: [],
            omitted_nonmaterial_fields: [
                'trace_id', 'receipt_version', 'verdict', 'timestamp', 'tool_call_id',
                'params_hash', 'rule_summary', 'rule_version', 'request_hash',
                'response_hash', 'runtime_context_hash', 'config_hash',
                'verifier_source_class', 'deployment_mode', 'issuer', 'audience',
                'nonce', 'sequence', 'issued_at', 'expires_at', 'max_clock_skew',
                'action', 'signature', 'signing_algorithm', 'public_key_fingerprint',
                'public_key', 'verified_at', 'latency_us',
            ],
        },
        profile_digest: digestAeb(null),
    };
    value.profile_digest = mappingProfileDigest('ccs-v14-github-action', value);
    return value;
}
function fixture() {
    const config = {
        '@version': CCS_V14_AEB_CONFIG_VERSION,
        evidence_role: 'machine-policy-decision',
        subject: { id: 'system:correctover-ccs-v14', kind: 'system' },
        issuer: 'ccs-conformance/v1.4.0',
        audience: 'rp:emilia-github-gate',
        action_type: ACTION_TYPE,
        allowed_actions: ['github_issue_update.execute'],
        allowed_tools: ['github_issue_update'],
        required_rule_version: '1.4.0-conformance',
        max_receipt_age_seconds: 300,
        max_status_age_seconds: 300,
        max_clock_skew_seconds: 30,
        deployment_scope: 'pinned-ed25519-issuer',
    };
    const root = {
        '@version': CCS_V14_AEB_TRUST_ROOT_VERSION,
        issuer: config.issuer,
        key_id: 'ccs-v14-independent-checker',
        algorithm: 'Ed25519',
        public_key_raw_base64: PUBLIC_RAW.toString('base64'),
        public_key_fingerprint_sha256_16: crypto.createHash('sha256').update(PUBLIC_RAW).digest('hex').slice(0, 16),
    };
    const adapter = createCcsV14AebAdapter({ config, trust_roots: [root] });
    const artifact = mint();
    const expected_action = {
        action_type: ACTION_TYPE,
        parameters: { tool: artifact.receipt.tool, arguments: ARGS },
    };
    const input = {
        artifact,
        artifact_ref: 'artifact:ccs-v14-github-allow',
        status: {
            checked_at: NOW,
            expires_at: '2025-06-15T16:02:00.000Z',
            revocation_checked: true,
            revoked: false,
            consumed: false,
        },
        trust_roots: [root],
        adapter_config: config,
        expected_action,
        now: NOW,
    };
    return { config, root, adapter, artifact, expected_action, input, profile: profile() };
}
test('pins the public v1.4 vector repository and manifest', () => {
    assert.equal(CCS_V14_VECTOR_COMMIT, 'a3503b2bc48922f92a28c372003885a0831da02b');
    assert.equal(CCS_V14_VECTOR_MANIFEST_SHA256, '3e77eae3045eb2bc824c52b8d022b75029beaf56623841ce7c035a99e65a2ddd');
});
test('verifies and exactly maps one signed CCS v1.4 GitHub issue update', () => {
    const f = fixture();
    const native = f.adapter.verifyNative(f.input);
    assert.equal(native.native_verification, 'VERIFIED');
    assert.equal(native.acceptance, 'ACCEPTED');
    const mapped = f.adapter.mapAction({ ...f.input, profile: f.profile, native });
    assert.equal(mapped.mapping, 'MATCH');
    assert.match(mapped.caid ?? '', /^caid:1:github\.issue-update\.1:jcs-sha256:/);
    assert.equal(mapped.action_digest, digestAeb(f.expected_action));
});
test('tamper, stale status, wrong audience, and action substitution fail closed', () => {
    const f = fixture();
    const tampered = structuredClone(f.artifact);
    tampered.receipt.response_hash = 'f'.repeat(64);
    assert.equal(f.adapter.verifyNative({ ...f.input, artifact: tampered }).native_verification, 'FAILED');
    const stale = f.adapter.verifyNative({
        ...f.input,
        status: { ...f.input.status, checked_at: '2025-06-15T15:00:00.000Z' },
    });
    assert.equal(stale.acceptance, 'REJECTED');
    const wrongAudienceConfig = { ...f.config, audience: 'rp:other-github-gate' };
    const wrongAudience = createCcsV14AebAdapter({ config: wrongAudienceConfig, trust_roots: [f.root] });
    assert.equal(wrongAudience.verifyNative({
        ...f.input,
        adapter_config: wrongAudienceConfig,
    }).acceptance, 'REJECTED');
    const native = f.adapter.verifyNative(f.input);
    const substituted = f.adapter.mapAction({
        ...f.input,
        expected_action: {
            ...f.expected_action,
            parameters: { tool: 'github_issue_update', arguments: { ...ARGS, issue_number: 539 } },
        },
        profile: f.profile,
        native,
    });
    assert.equal(substituted.mapping, 'MISMATCH');
});
