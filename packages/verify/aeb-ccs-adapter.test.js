// SPDX-License-Identifier: Apache-2.0
// Generated from aeb-ccs-adapter.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto, {} from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
// The CAID reference implementation intentionally has no TypeScript surface.
// @ts-expect-error -- independently cross-checked in this test.
import { computeCaid } from './vendor/caid.mjs';
import { AEB_ADAPTER_VERSION, AEB_REGISTRY_VERSION, AEB_REQUIREMENT_VERSION, InMemoryAebConsumptionStore, adapterPinDigest, authorizeAebExecution, digestAeb, evaluateAebEvidence, mappingProfileDigest, reconcileAebExecution, registryEntryDigest, unifiedRegistryDigest, verifyAebEvaluation, } from './aeb-adapter-contract.js';
import { CCS_AEB_ADAPTER_ID, CCS_AEB_ADAPTER_VERSION, CCS_AEB_CONFIG_VERSION, CCS_AEB_TRUST_ROOT_VERSION, CCS_CAID_MAPPER_ID, CCS_CAID_MAPPING_VERSION, CCS_PYPI_ARTIFACT_VERSION, CCS_PYPI_DISTRIBUTION_VERSION, CCS_PYPI_RUNTIME_VERSION, createCcsAebActionDefinition, createCcsNativeActionDefinition, createCcsPyPiHmacAebAdapter, } from './aeb-ccs-adapter.js';
const NOW = '2026-08-10T19:00:00Z';
const NOW_SECONDS = Date.parse(NOW) / 1000;
const ACTION_TYPE = 'agent.tool-invocation.1';
const ISSUER = 'https://ccs.example/verifier';
const AUDIENCE = 'https://gate.example/admit';
const SECRET = Buffer.from('ccs-aeb-public-test-secret-32-bytes!!', 'utf8');
const PACKAGE_FIXTURE = JSON.parse(readFileSync(new URL('../../interop/ccs-aeb/fixtures/ccs-verifier-pypi-1.1.0.json', import.meta.url), 'utf8'));
function spki(key) {
    return key.export({ type: 'spki', format: 'der' }).toString('base64url');
}
function canonicalPythonSubset(value) {
    function normalize(item) {
        if (Array.isArray(item))
            return item.map(normalize);
        if (item !== null && typeof item === 'object') {
            return Object.fromEntries(Object.keys(item).sort().map((key) => [key, normalize(item[key])]));
        }
        return item;
    }
    return JSON.stringify(normalize(value));
}
function paramsHash(params) {
    return crypto.createHash('sha256').update(canonicalPythonSubset(params), 'utf8').digest('hex').slice(0, 16);
}
function statusDigest(status) {
    return digestAeb({
        checked_at: status.checked_at,
        expires_at: status.expires_at,
        revocation_checked: status.revocation_checked,
        revoked: status.revoked,
        consumed: status.consumed,
        unavailable: status.unavailable === true,
    });
}
function ruleSummary(artifact) {
    return artifact.result.rule_results.map((result) => `${result.rule_name}=${result.verdict}`).join('|');
}
function signArtifact(artifact, secret = SECRET) {
    artifact.result.params_hash = paramsHash(artifact.command.params);
    artifact.result.receipt = crypto.createHmac('sha256', secret).update([
        artifact.result.trace_id,
        artifact.result.verdict,
        String(artifact.result.verified_at),
        artifact.result.tool,
        artifact.result.params_hash,
        ruleSummary(artifact),
    ].join(':'), 'utf8').digest('hex').slice(0, 32);
    return artifact;
}
function mintArtifact(overrides = {}) {
    const artifact = structuredClone(PACKAGE_FIXTURE);
    const traceId = overrides.trace_id ?? artifact.command.trace_id;
    const verdict = overrides.verdict ?? artifact.result.verdict;
    const tool = overrides.tool ?? artifact.command.tool;
    const params = overrides.params ?? artifact.command.params;
    artifact.command.trace_id = traceId;
    artifact.command.tool = tool;
    artifact.command.params = params;
    artifact.result.trace_id = traceId;
    artifact.result.verdict = verdict;
    artifact.result.block_reason = verdict === 'allow' ? '' : `${verdict} by policy`;
    artifact.result.rule_results = verdict === 'deny'
        ? [{ ...artifact.result.rule_results[0], verdict }]
        : artifact.result.rule_results.map((rule) => ({ ...rule, verdict }));
    artifact.result.verified_at = overrides.verified_at ?? artifact.result.verified_at;
    artifact.result.tool = tool;
    return signArtifact(artifact);
}
function profile() {
    const pin = {
        version: CCS_CAID_MAPPING_VERSION,
        definition: createCcsAebActionDefinition(ACTION_TYPE),
        registry_entry_ref: 'mapping:ccs-tool-invocation',
        mapper_id: CCS_CAID_MAPPER_ID,
        resolver: {
            id: CCS_CAID_MAPPER_ID,
            version: '1',
            implementation_digest: digestAeb({ implementation: CCS_CAID_MAPPER_ID, version: '1' }),
        },
        semantic_equivalence: {
            assertion: 'EQUIVALENT_UNDER_PROFILE',
            loss_policy: 'NO_MATERIAL_FIELD_LOSS',
            omitted_material_fields: [],
            omitted_nonmaterial_fields: [
                'command.agent_id', 'command.timestamp', 'command.trace_id',
                'result.block_reason', 'result.rule_results.reason', 'result.rule_results.latency_us',
                'result.error_code',
            ],
        },
        profile_digest: digestAeb(null),
    };
    pin.profile_digest = mappingProfileDigest('ccs-tool-invocation', pin);
    return pin;
}
function nativeActionProfile(actionType) {
    const pin = {
        version: CCS_CAID_MAPPING_VERSION,
        definition: createCcsNativeActionDefinition(actionType),
        registry_entry_ref: 'mapping:ccs-native-action',
        mapper_id: CCS_CAID_MAPPER_ID,
        resolver: {
            id: CCS_CAID_MAPPER_ID,
            version: '1',
            implementation_digest: digestAeb({ implementation: CCS_CAID_MAPPER_ID, version: '1' }),
        },
        semantic_equivalence: {
            assertion: 'EQUIVALENT_UNDER_PROFILE',
            loss_policy: 'NO_MATERIAL_FIELD_LOSS',
            omitted_material_fields: [],
            omitted_nonmaterial_fields: [
                'command.agent_id', 'command.timestamp', 'command.trace_id',
                'result.block_reason', 'result.rule_results.reason', 'result.rule_results.latency_us',
                'result.error_code',
            ],
        },
        profile_digest: digestAeb(null),
    };
    pin.profile_digest = mappingProfileDigest('ccs-native-action', pin);
    return pin;
}
function fixture() {
    const config = {
        '@version': CCS_AEB_CONFIG_VERSION,
        evidence_role: 'machine-policy-decision',
        subject: { id: 'system:ccs-local-verifier', kind: 'system' },
        issuer: ISSUER,
        audience: AUDIENCE,
        action_type: ACTION_TYPE,
        allowed_tools: ['release_payment'],
        required_rules: ['ssrf_protection', 'rce_protection'],
        max_receipt_age_seconds: 60,
        params_hash_bits: 64,
        deployment_scope: 'single-relying-party-local-hmac',
    };
    const root = {
        '@version': CCS_AEB_TRUST_ROOT_VERSION,
        issuer: ISSUER,
        audience: AUDIENCE,
        key_id: 'ccs-local-hmac-test-1',
        algorithm: 'HMAC-SHA256-TRUNC128',
        secret_base64url: SECRET.toString('base64url'),
    };
    const artifact = mintArtifact();
    const action = {
        action_type: ACTION_TYPE,
        parameters: { tool: artifact.command.tool, arguments: artifact.command.params },
    };
    const adapter = createCcsPyPiHmacAebAdapter({ config, trust_roots: [root] });
    const input = {
        artifact,
        artifact_ref: 'ccs:result:0011223344556677',
        status: {
            checked_at: NOW,
            expires_at: '2026-08-10T19:01:00Z',
            revocation_checked: true,
            revoked: false,
            consumed: false,
        },
        trust_roots: [root],
        adapter_config: config,
        expected_action: action,
        now: NOW,
    };
    return { config, root, artifact, action, adapter, input };
}
test('source lock names the PyPI label and the runtime bytes separately', () => {
    assert.equal(CCS_PYPI_DISTRIBUTION_VERSION, '1.1.0');
    assert.equal(CCS_PYPI_RUNTIME_VERSION, '0.4.1');
    assert.equal(PACKAGE_FIXTURE.result.params_hash, '11841931cced17ab');
    assert.equal(PACKAGE_FIXTURE.result.receipt, '5712658439a2dc61ddda501aa82ff4af');
});
test('current CCS HMAC result becomes accepted machine-policy evidence for one exact action', () => {
    const f = fixture();
    const native = f.adapter.verifyNative(f.input);
    assert.equal(native.native_verification, 'VERIFIED');
    assert.equal(native.acceptance, 'ACCEPTED');
    assert.equal(native.evidence_role, 'machine-policy-decision');
    const mapping = f.adapter.mapAction({ ...f.input, profile: profile(), native });
    assert.equal(mapping.mapping, 'MATCH');
    assert.equal(mapping.action_digest, digestAeb(f.action));
    const computed = computeCaid(f.action, {
        suite: 'jcs-sha256', definitions: profile().definition.definitions,
    });
    assert.equal(mapping.caid, computed.caid);
});
test('CCS maps its exact command into the shared native-action projection used by another evidence leg', () => {
    const f = fixture();
    const actionType = 'payment.transfer.1';
    const artifact = mintArtifact({
        tool: 'release_payment',
        params: { amount: '100.00', payee: 'acct_9' },
    });
    const config = { ...f.config, action_type: actionType };
    const expected_action = {
        action_type: actionType,
        native_action: {
            type: artifact.command.tool,
            parameters: artifact.command.params,
        },
    };
    const adapter = createCcsPyPiHmacAebAdapter({ config, trust_roots: [f.root] });
    const input = {
        ...f.input,
        artifact,
        adapter_config: config,
        expected_action,
    };
    const native = adapter.verifyNative(input);
    assert.equal(native.native_verification, 'VERIFIED');
    assert.equal(native.acceptance, 'ACCEPTED');
    const mapping = adapter.mapAction({
        ...input,
        profile: nativeActionProfile(actionType),
        native,
    });
    assert.equal(mapping.mapping, 'MATCH');
    assert.equal(mapping.action_digest, digestAeb(expected_action));
    assert.match(mapping.caid ?? '', /^caid:1:payment\.transfer\.1:jcs-sha256:/);
});
test('approve A execute B and changed command bytes fail independently', () => {
    const f = fixture();
    const native = f.adapter.verifyNative(f.input);
    const expected_action = structuredClone(f.action);
    expected_action.parameters.arguments.amount_minor = 999999;
    const mapped = f.adapter.mapAction({ ...f.input, expected_action, profile: profile(), native });
    assert.equal(mapped.mapping, 'MISMATCH');
    const tampered = structuredClone(f.artifact);
    tampered.command.params.amount_minor = 999999;
    const verified = f.adapter.verifyNative({ ...f.input, artifact: tampered });
    assert.equal(verified.acceptance, 'REJECTED');
    assert.ok(verified.reasons.includes('ccs:params_hash_mismatch'));
});
test('receipt tampering, tool substitution, rule removal, and presenter pin replacement fail closed', () => {
    const f = fixture();
    const receiptTamper = structuredClone(f.artifact);
    receiptTamper.result.receipt = `f${receiptTamper.result.receipt.slice(1)}`;
    assert.equal(f.adapter.verifyNative({ ...f.input, artifact: receiptTamper }).native_verification, 'FAILED');
    const toolSwap = structuredClone(f.artifact);
    toolSwap.command.tool = 'delete_repository';
    toolSwap.result.tool = 'delete_repository';
    signArtifact(toolSwap);
    const unpinnedTool = f.adapter.verifyNative({ ...f.input, artifact: toolSwap });
    assert.equal(unpinnedTool.native_verification, 'VERIFIED');
    assert.ok(unpinnedTool.reasons.includes('ccs:tool_not_pinned'));
    const ruleRemoval = structuredClone(f.artifact);
    ruleRemoval.result.rule_results.pop();
    signArtifact(ruleRemoval);
    const incompleteAllow = f.adapter.verifyNative({ ...f.input, artifact: ruleRemoval });
    assert.equal(incompleteAllow.native_verification, 'VERIFIED');
    assert.ok(incompleteAllow.reasons.includes('ccs:required_rules_mismatch'));
    const replacedRoot = { ...f.root, secret_base64url: crypto.randomBytes(32).toString('base64url') };
    assert.ok(f.adapter.verifyNative({ ...f.input, trust_roots: [replacedRoot] }).reasons.includes('ccs:constructor_pin_mismatch'));
});
test('deny, escalate, stale evidence, and unavailable status never reach accepted evidence', () => {
    for (const [verdict, acceptance] of [['deny', 'REJECTED'], ['escalate', 'INDETERMINATE']]) {
        const f = fixture();
        const artifact = mintArtifact({ verdict });
        const native = f.adapter.verifyNative({ ...f.input, artifact });
        assert.equal(native.native_verification, 'VERIFIED');
        assert.equal(native.acceptance, acceptance);
    }
    const stale = fixture();
    const oldArtifact = mintArtifact({ verified_at: NOW_SECONDS - 61 });
    assert.equal(stale.adapter.verifyNative({ ...stale.input, artifact: oldArtifact }).acceptance, 'INDETERMINATE');
    assert.equal(stale.adapter.verifyNative({
        ...stale.input,
        status: { ...stale.input.status, unavailable: true },
    }).acceptance, 'INDETERMINATE');
});
test('unknown post-effect fields are rejected instead of becoming execution evidence', () => {
    const f = fixture();
    const artifact = structuredClone(f.artifact);
    artifact.result.outcome_status = 'confirmed';
    const native = f.adapter.verifyNative({ ...f.input, artifact });
    assert.equal(native.native_verification, 'FAILED');
    assert.equal(native.acceptance, 'REJECTED');
    assert.ok(native.reasons.includes('ccs:artifact_malformed'));
});
function registryEntry(id, kind, definition) {
    const entry = { kind, version: '1', status: 'active', definition };
    entry.definition_digest = registryEntryDigest(id, entry);
    return entry;
}
test('a fresh CCS receipt cannot replay the same execution authority after an indeterminate attempt', () => {
    const f = fixture();
    const mapping = profile();
    const authorityAdapterId = 'native:test-execution-authority';
    const authorityConfig = { version: 'test-authority-v1', role: 'execution-authority' };
    const authorityRoot = { version: 'test-authority-root-v1', issuer: 'test-only' };
    const authorityArtifact = { authority_id: 'authority-payment-0001', action: f.action };
    const authorityAdapter = {
        id: authorityAdapterId,
        version: '1',
        verifyNative(input) {
            const artifact = input.artifact;
            const accepted = artifact?.authority_id === authorityArtifact.authority_id
                && digestAeb(artifact?.action) === digestAeb(input.expected_action);
            return {
                native_verification: accepted ? 'VERIFIED' : 'FAILED',
                acceptance: accepted ? 'ACCEPTED' : 'REJECTED',
                evidence_digest: digestAeb(input.artifact),
                status_digest: statusDigest(input.status),
                evidence_role: 'execution-authority',
                subject: { id: 'organization:owner', kind: 'organization' },
                replay_unit: digestAeb({ authority_id: artifact?.authority_id }),
                reasons: accepted ? [] : ['test_authority_invalid'],
            };
        },
        mapAction(input) {
            if (input.native.acceptance !== 'ACCEPTED') {
                return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['native_acceptance_required'] };
            }
            const artifact = input.artifact;
            if (digestAeb(artifact.action) !== digestAeb(input.expected_action)) {
                return { mapping: 'MISMATCH', caid: null, action_digest: digestAeb(artifact.action), reasons: ['action_mismatch'] };
            }
            const computed = computeCaid(artifact.action, {
                suite: 'jcs-sha256', definitions: mapping.definition.definitions,
            });
            return { mapping: 'MATCH', caid: computed.caid, action_digest: digestAeb(artifact.action), reasons: [] };
        },
    };
    const ccsPin = {
        version: CCS_AEB_ADAPTER_VERSION,
        trust_roots: [f.root],
        config: f.config,
        config_digest: digestAeb(null),
        max_status_age_sec: 120,
    };
    ccsPin.config_digest = adapterPinDigest(CCS_AEB_ADAPTER_ID, ccsPin);
    const authorityPin = {
        version: '1',
        trust_roots: [authorityRoot],
        config: authorityConfig,
        config_digest: digestAeb(null),
        max_status_age_sec: 120,
    };
    authorityPin.config_digest = adapterPinDigest(authorityAdapterId, authorityPin);
    const entries = {
        'mapping:ccs-tool-invocation': registryEntry('mapping:ccs-tool-invocation', 'mapping-profile', { profile_digest: mapping.profile_digest }),
        'role:machine-policy-decision': registryEntry('role:machine-policy-decision', 'evidence-role', { role: 'machine-policy-decision', subject_kinds: ['system'] }),
        'role:execution-authority': registryEntry('role:execution-authority', 'evidence-role', { role: 'execution-authority', subject_kinds: ['organization'] }),
    };
    const registry = {
        '@version': AEB_REGISTRY_VERSION,
        registry_id: 'registry:ccs-aeb-test',
        epoch: 1,
        entries,
        registry_digest: digestAeb(null),
    };
    registry.registry_digest = unifiedRegistryDigest(registry);
    const evaluator = crypto.generateKeyPairSync('ed25519');
    const config = {
        '@version': AEB_ADAPTER_VERSION,
        relying_party_id: 'rp:ccs-aeb-example',
        evaluator_keys: { 'evaluator:ccs-aeb': { public_key: spki(evaluator.publicKey) } },
        registry,
        accepted_mappers: [CCS_CAID_MAPPER_ID],
        adapters: { [CCS_AEB_ADAPTER_ID]: ccsPin, [authorityAdapterId]: authorityPin },
        profiles: { 'ccs-tool-invocation': mapping },
        requirements: {
            'requirement:policy-plus-authority': {
                '@version': AEB_REQUIREMENT_VERSION,
                all_of: ['machine-policy-decision', 'execution-authority'],
                terms: [{ type: 'one-time-consumption' }],
            },
        },
    };
    const computed = computeCaid(f.action, {
        suite: 'jcs-sha256', definitions: mapping.definition.definitions,
    });
    const status = f.input.status;
    const makeEvaluation = (artifact, operationId) => evaluateAebEvidence({
        config,
        adapters: { [CCS_AEB_ADAPTER_ID]: f.adapter, [authorityAdapterId]: authorityAdapter },
        operation_id: operationId,
        consumption_nonce: `consume-${operationId}`,
        initiator_id: 'workload:agent-overnight-1',
        executor_id: 'workload:gate',
        requirement_ref: 'requirement:policy-plus-authority',
        caid: computed.caid,
        expected_action: f.action,
        evaluated_at: NOW,
        signer: { key_id: 'evaluator:ccs-aeb', private_key: evaluator.privateKey },
        legs: [
            {
                adapter_id: CCS_AEB_ADAPTER_ID,
                profile_id: 'ccs-tool-invocation',
                artifact_ref: `ccs:${artifact.result.trace_id}`,
                artifact,
                status,
            },
            {
                adapter_id: authorityAdapterId,
                profile_id: 'ccs-tool-invocation',
                artifact_ref: 'authority:payment-0001',
                artifact: authorityArtifact,
                status,
            },
        ],
    });
    const first = makeEvaluation(f.artifact, 'operation-1');
    assert.equal(first.valid, true, JSON.stringify(first, null, 2));
    const firstVerification = verifyAebEvaluation(first.record, {
        config,
        adapters: { [CCS_AEB_ADAPTER_ID]: f.adapter, [authorityAdapterId]: authorityAdapter },
        artifacts: {
            [`ccs:${f.artifact.result.trace_id}`]: f.artifact,
            'authority:payment-0001': authorityArtifact,
        },
        mode: 'execution',
        now: NOW,
        expected_action: f.action,
        current_statuses: {
            [`ccs:${f.artifact.result.trace_id}`]: status,
            'authority:payment-0001': status,
        },
    });
    assert.equal(firstVerification.execution_authorizing, true, JSON.stringify(firstVerification, null, 2));
    const store = new InMemoryAebConsumptionStore();
    const admitted = authorizeAebExecution(first.record, {
        verification: firstVerification,
        local_authorization: true,
        store,
    });
    assert.equal(admitted.state, 'AUTHORIZED');
    assert.ok(admitted.reservation_key);
    assert.equal(reconcileAebExecution(store, admitted.reservation_key, 'INDETERMINATE').state, 'RECONCILIATION_REQUIRED');
    const secondArtifact = mintArtifact({ trace_id: '8899aabbccddeeff', verified_at: NOW_SECONDS });
    const second = makeEvaluation(secondArtifact, 'operation-2');
    assert.equal(second.valid, true, JSON.stringify(second, null, 2));
    const secondVerification = verifyAebEvaluation(second.record, {
        config,
        adapters: { [CCS_AEB_ADAPTER_ID]: f.adapter, [authorityAdapterId]: authorityAdapter },
        artifacts: {
            [`ccs:${secondArtifact.result.trace_id}`]: secondArtifact,
            'authority:payment-0001': authorityArtifact,
        },
        mode: 'execution',
        now: NOW,
        expected_action: f.action,
        current_statuses: {
            [`ccs:${secondArtifact.result.trace_id}`]: status,
            'authority:payment-0001': status,
        },
    });
    const replay = authorizeAebExecution(second.record, {
        verification: secondVerification,
        local_authorization: true,
        store,
    });
    assert.equal(replay.state, 'REFUSED');
    assert.equal(replay.reason, 'consumption_conflict');
});
