// SPDX-License-Identifier: Apache-2.0
// Generated from run.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/** Source-locked CCS 1.1.20 L1 receipt to AEB exact-action mapping runner. */
import crypto from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { digestAeb, mappingProfileDigest, } from '../../../packages/verify/aeb-adapter-contract.js';
import { CCS_L1_AEB_ADAPTER_ID, CCS_L1_AEB_ADAPTER_VERSION, CCS_L1_AEB_CONFIG_VERSION, CCS_L1_AEB_TRUST_ROOT_VERSION, CCS_L1_CAID_MAPPER_ID, CCS_L1_CAID_MAPPING_VERSION, CCS_L1_PYPI_DISTRIBUTION_VERSION, CCS_L1_PYPI_SDIST_SHA256, CCS_L1_PYPI_SOURCE_LOCK, CCS_L1_PYPI_WHEEL_SHA256, CCS_L1_REFERENCE_VECTOR_SHA256, CCS_L1_UPSTREAM_COMMIT_SHA, CCS_L1_UPSTREAM_REPOSITORY, CCS_L1_UPSTREAM_TAG, CCS_L1_UPSTREAM_TAG_GPG_SIGNED, CCS_L1_UPSTREAM_TAG_KIND, CCS_L1_UPSTREAM_TAG_OBJECT_SHA, createCcsL1AebActionDefinition, createCcsPyPiL1AebAdapter, } from '../../../packages/verify/aeb-ccs-adapter.js';
const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../../..');
const REPORT_PATH = resolve(HERE, 'report.reference.json');
const UPSTREAM_FIXTURE_PATH = resolve(ROOT, 'interop/ccs-aeb/fixtures/ccs-verifier-pypi-1.1.20-upstream-reference-signed-001.json');
const ACTION_TYPE = 'agent.tool-invocation.1';
const NOW = '2030-01-01T00:02:00Z';
function canonical(value) {
    if (Array.isArray(value))
        return `[${value.map(canonical).join(',')}]`;
    if (value !== null && typeof value === 'object') {
        return `{${Object.keys(value).sort().map((key) => (`${JSON.stringify(key)}:${canonical(value[key])}`)).join(',')}}`;
    }
    return JSON.stringify(value);
}
function sha256(value) {
    return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}
function fileSha256(path) {
    return crypto.createHash('sha256').update(readFileSync(path)).digest('hex');
}
function check(id, layer, description, passed, observed) {
    return { id, layer, description, passed, observed };
}
function profile() {
    const pin = {
        version: CCS_L1_CAID_MAPPING_VERSION,
        definition: createCcsL1AebActionDefinition(ACTION_TYPE),
        registry_entry_ref: 'mapping:ccs-l1-tool-action',
        mapper_id: CCS_L1_CAID_MAPPER_ID,
        resolver: {
            id: CCS_L1_CAID_MAPPER_ID,
            version: '1',
            implementation_digest: digestAeb({ implementation: CCS_L1_CAID_MAPPER_ID, version: '1' }),
        },
        semantic_equivalence: {
            assertion: 'EQUIVALENT_UNDER_PROFILE',
            loss_policy: 'NO_MATERIAL_FIELD_LOSS',
            omitted_material_fields: [],
            omitted_nonmaterial_fields: [
                'trace_id', 'timestamp', 'tool_call_id', 'params_hash', 'rule_summary',
                'request_hash', 'response_hash', 'runtime_context_hash', 'config_hash',
                'verifier_source_class', 'deployment_mode', 'nonce', 'sequence',
                'issued_at', 'expires_at', 'max_clock_skew', 'verified_at', 'latency_us',
            ],
        },
        profile_digest: digestAeb(null),
    };
    pin.profile_digest = mappingProfileDigest('ccs-l1-tool-action', pin);
    return pin;
}
function buildFixture() {
    const vector = JSON.parse(readFileSync(UPSTREAM_FIXTURE_PATH, 'utf8'));
    const config = {
        '@version': CCS_L1_AEB_CONFIG_VERSION,
        evidence_role: 'machine-policy-decision',
        subject: { id: 'system:ccs-reference-verifier', kind: 'system' },
        issuer: 'ccs-verifier/reference',
        audience: 'public',
        action_type: ACTION_TYPE,
        allowed_actions: ['shell.execute'],
        allowed_tools: ['shell'],
        required_rule_version: '1.1.20',
        max_receipt_age_seconds: 300,
        max_clock_skew_seconds: 5,
        deployment_scope: 'pinned-ed25519-issuer',
    };
    const root = {
        '@version': CCS_L1_AEB_TRUST_ROOT_VERSION,
        issuer: config.issuer,
        key_id: 'ccs-reference-ed25519-1',
        algorithm: 'Ed25519',
        public_key_raw_base64: vector.public_key_raw_b64,
        public_key_fingerprint_sha256_16: vector.public_key_fingerprint_sha256_16,
    };
    const action = {
        action_type: ACTION_TYPE,
        parameters: {
            action: 'shell.execute',
            tool: 'shell',
            arguments: { command: 'echo reference' },
        },
    };
    const status = {
        checked_at: NOW,
        expires_at: '2030-01-01T00:04:00Z',
        revocation_checked: true,
        revoked: false,
        consumed: false,
    };
    const adapter = createCcsPyPiL1AebAdapter({ config, trust_roots: [root] });
    const input = {
        artifact: structuredClone(vector.receipt),
        artifact_ref: 'ccs:l1:reference-signed-001',
        status,
        trust_roots: [root],
        adapter_config: config,
        expected_action: action,
        now: NOW,
    };
    return {
        vector,
        config,
        root,
        action,
        adapter,
        input,
        profile: profile(),
    };
}
export function runSuite() {
    const f = buildFixture();
    const native = f.adapter.verifyNative(f.input);
    const mapping = f.adapter.mapAction({ ...f.input, profile: f.profile, native });
    const signatureTamper = structuredClone(f.input.artifact);
    signatureTamper.signature = `${signatureTamper.signature[0] === 'A' ? 'B' : 'A'}${signatureTamper.signature.slice(1)}`;
    const invalidSignature = f.adapter.verifyNative({ ...f.input, artifact: signatureTamper });
    const expired = f.adapter.verifyNative({ ...f.input, now: '2030-01-01T00:05:01Z' });
    const unavailable = f.adapter.verifyNative({
        ...f.input,
        status: { ...f.input.status, unavailable: true },
    });
    const substitutedAction = {
        ...f.action,
        parameters: { ...f.action.parameters, arguments: { command: 'echo substituted' } },
    };
    const substitutedMapping = f.adapter.mapAction({
        ...f.input,
        expected_action: substitutedAction,
        profile: f.profile,
        native,
    });
    const wrongKey = Buffer.alloc(32, 7);
    const wrongRoot = {
        ...f.root,
        public_key_raw_base64: wrongKey.toString('base64'),
        public_key_fingerprint_sha256_16: crypto.createHash('sha256').update(wrongKey).digest('hex').slice(0, 16),
    };
    const wrongRootAdapter = createCcsPyPiL1AebAdapter({ config: f.config, trust_roots: [wrongRoot] });
    const untrusted = wrongRootAdapter.verifyNative({
        ...f.input,
        trust_roots: [wrongRoot],
    });
    const checks = [
        check('CCS-1.1.20-SOURCE-PIN', 'CCS', 'The exact upstream vector, annotated tag object, commit, and PyPI 1.1.20 artifacts are pinned without treating the unsigned tag as publisher authentication.', f.vector.package_version === CCS_L1_PYPI_DISTRIBUTION_VERSION
            && f.vector.receipt.rule_version === CCS_L1_PYPI_DISTRIBUTION_VERSION
            && f.vector.issuer === f.vector.receipt.issuer
            && f.vector.public_key_raw_b64 === f.vector.receipt.public_key
            && f.vector.public_key_fingerprint_sha256_16 === f.vector.receipt.public_key_fingerprint
            && f.vector.spec_version === f.vector.receipt.receipt_version
            && CCS_L1_UPSTREAM_TAG_KIND === 'annotated-unsigned'
            && CCS_L1_UPSTREAM_TAG_GPG_SIGNED === false
            && fileSha256(UPSTREAM_FIXTURE_PATH) === CCS_L1_REFERENCE_VECTOR_SHA256, {
            distribution: f.vector.package_version,
            source_lock: CCS_L1_PYPI_SOURCE_LOCK,
            upstream_repository: CCS_L1_UPSTREAM_REPOSITORY,
            upstream_tag: CCS_L1_UPSTREAM_TAG,
            upstream_tag_object_sha: CCS_L1_UPSTREAM_TAG_OBJECT_SHA,
            upstream_tag_kind: CCS_L1_UPSTREAM_TAG_KIND,
            upstream_tag_gpg_signed: CCS_L1_UPSTREAM_TAG_GPG_SIGNED,
            upstream_commit_sha: CCS_L1_UPSTREAM_COMMIT_SHA,
            upstream_reference_vector_sha256: fileSha256(UPSTREAM_FIXTURE_PATH),
        }),
        check('CCS-1.1.20-ED25519-ACCEPT', 'CCS', 'The reference L1 signature verifies and its issuer key is accepted only under the relying-party pin.', native.native_verification === 'VERIFIED' && native.acceptance === 'ACCEPTED', { verification: native.native_verification, acceptance: native.acceptance }),
        check('CCS-1.1.20-SIGNATURE-TAMPER', 'CCS', 'A signature mutation is refused before semantic mapping.', invalidSignature.native_verification === 'FAILED', invalidSignature),
        check('CCS-1.1.20-UNTRUSTED-ISSUER', 'CCS', 'A self-consistent receipt not matching the relying-party key pin is rejected.', untrusted.native_verification === 'VERIFIED' && untrusted.acceptance === 'REJECTED', untrusted),
        check('CCS-1.1.20-EXPIRY', 'CCS', 'A correctly signed receipt past expires_at is rejected.', expired.native_verification === 'VERIFIED' && expired.acceptance === 'REJECTED', expired),
        check('AEB-EXACT-ACTION-MAP', 'AEB', 'The signed CCS action, tool, and full args_digest map to one executor-constructed CAID.', mapping.mapping === 'MATCH', mapping),
        check('AEB-ACTION-SUBSTITUTION', 'AEB', 'Changing the executor action arguments produces MISMATCH.', substitutedMapping.mapping === 'MISMATCH', substitutedMapping),
        check('AEB-STATUS-UNAVAILABLE', 'AEB', 'Unavailable authenticated status remains INDETERMINATE.', unavailable.native_verification === 'VERIFIED' && unavailable.acceptance === 'INDETERMINATE', unavailable),
    ];
    const report = {
        '@version': 'CCS-L1-AEB-COMPOSITION-REPORT-v1',
        profile: 'ccs-l1-aeb-v1',
        pins: {
            ccs_distribution: CCS_L1_PYPI_DISTRIBUTION_VERSION,
            ccs_sdist_sha256: CCS_L1_PYPI_SDIST_SHA256,
            ccs_wheel_sha256: CCS_L1_PYPI_WHEEL_SHA256,
            ccs_reference_vector_sha256: CCS_L1_REFERENCE_VECTOR_SHA256,
            ccs_source_lock: CCS_L1_PYPI_SOURCE_LOCK,
            ccs_upstream_repository: CCS_L1_UPSTREAM_REPOSITORY,
            ccs_upstream_tag: CCS_L1_UPSTREAM_TAG,
            ccs_upstream_tag_object_sha: CCS_L1_UPSTREAM_TAG_OBJECT_SHA,
            ccs_upstream_tag_kind: CCS_L1_UPSTREAM_TAG_KIND,
            ccs_upstream_tag_gpg_signed: CCS_L1_UPSTREAM_TAG_GPG_SIGNED,
            ccs_upstream_commit_sha: CCS_L1_UPSTREAM_COMMIT_SHA,
            adapter_id: CCS_L1_AEB_ADAPTER_ID,
            adapter_version: CCS_L1_AEB_ADAPTER_VERSION,
            mapping_profile_digest: f.profile.profile_digest,
        },
        checks,
        passed: checks.every((entry) => entry.passed),
        known_limits: [
            'The reference signing seed and key are public test material and are not a production trust anchor.',
            'The pinned v1.1.20 tag is annotated but not GPG-signed. The tag object and target commit are exact byte pins, not cryptographic publisher authentication.',
            'CCS supplies machine-policy-decision evidence, not human authorization, provider admission, or effect proof.',
            'AEB reconstructs the exact action from the executor and checks the signed action, tool, and args_digest; it does not trust an action string as a CAID.',
            'A passing report reproduces the EMILIA reference adapter and is not independent implementation, deployment, certification, IETF adoption, or endorsement.',
        ],
        implementation_status_markdown: `The runner reproduced ${checks.filter((entry) => entry.passed).length}/${checks.length} source-locked CCS 1.1.20 to AEB checks. It verified the pinned Ed25519 L1 receipt and mapped its signed action, tool, and full argument digest to one executor-constructed CAID. This is a reproduction of the EMILIA reference adapter, not an independent implementation or IETF endorsement.`,
    };
    report.report_digest = sha256(canonical(report));
    return report;
}
function main() {
    const report = runSuite();
    const rendered = `${JSON.stringify(report, null, 2)}\n`;
    if (process.argv.includes('--write'))
        writeFileSync(REPORT_PATH, rendered);
    if (process.argv.includes('--check')) {
        const expected = readFileSync(REPORT_PATH, 'utf8');
        if (expected !== rendered) {
            console.error('CCS L1 to AEB reference report is stale');
            process.exitCode = 1;
        }
    }
    console.log(rendered.trimEnd());
    if (report.passed !== true)
        process.exitCode = 1;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
    main();
