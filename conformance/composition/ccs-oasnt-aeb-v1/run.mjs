// SPDX-License-Identifier: Apache-2.0
// Generated from run.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * Runnable CCS + OASNT -> AEB two-leg composition profile.
 *
 * This is an EMILIA reference composition. Running it externally reproduces
 * these pinned checks but does not become an independent implementation.
 */
import crypto, { KeyObject } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { computeCaid } from '../../../packages/verify/vendor/caid.mjs';
import { AEB_ADAPTER_VERSION, AEB_REGISTRY_VERSION, AEB_REQUIREMENT_VERSION, InMemoryAebConsumptionStore, adapterPinDigest, authorizeAebExecution, digestAeb, evaluateAebEvidence, mappingProfileDigest, reconcileAebExecution, registryEntryDigest, unifiedRegistryDigest, verifyAebEvaluation, } from '../../../packages/verify/aeb-adapter-contract.js';
import { CCS_AEB_ADAPTER_ID, CCS_AEB_ADAPTER_VERSION, CCS_AEB_CONFIG_VERSION, CCS_AEB_TRUST_ROOT_VERSION, CCS_CAID_MAPPER_ID, CCS_CAID_MAPPING_VERSION, CCS_PYPI_DISTRIBUTION_VERSION, CCS_PYPI_RUNTIME_VERSION, createCcsNativeActionDefinition, createCcsPyPiHmacAebAdapter, } from '../../../packages/verify/aeb-ccs-adapter.js';
import { OASNT_AEB_ADAPTER_ID, OASNT_AEB_ADAPTER_VERSION, OASNT_AEB_CONFIG_VERSION, OASNT_CAID_MAPPER_ID, OASNT_CAID_MAPPING_VERSION, OASNT_DRAFT_REVISION, OASNT_TRUST_ROOT_VERSION, computeOasntActionDigest, computeOasntDisplayDigest, createOasntActionDefinition, createOasntAebAdapter, } from '../../../packages/verify/aeb-oasnt-adapter.js';
const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../../..');
const LOCK_PATH = resolve(ROOT, 'conformance/composition/aeb-adapter-v1.lock.json');
const REFERENCE_REPORT_PATH = resolve(HERE, 'report.reference.json');
const NOW = new Date(1_800_000_000 * 1000).toISOString();
const ACTION_TYPE = 'payment.transfer.1';
const OASNT_ACTION_TYPE = 'payment.transfer';
const CCS_SECRET = Buffer.from('ccs-aeb-public-test-secret-32-bytes!!', 'utf8');
const PUBLISHED_OASNT_TOKEN = [
    'eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hc250K2p3dCJ9',
    'eyJzdWIiOiJhZ2VudC0xIiwiYWRnIjoiWWxIcDNNNEpJV0ZQUFpJVkF3QW1ZT0JPTWZVeWIyYmpFNnZlM0FEMmlhUSIsImRzcCI6InVTRWdPRzlVQzFJV0d4ekJhbEp2NWNJYmZ4RThreG1vS0YyNXlyUmwxZnMiLCJycWYiOiIxR0w3Q0lnMUprS0dhR2ZIZ2RGNV85M3JWeDRGcWZqb1kwbFlaNnhialEwIiwiaW50IjoiY2xlYW4iLCJqdGkiOiIwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZiIsImlhdCI6MTgwMDAwMDAwMCwiZXhwIjoxODAwMDAwMDYwLCJjbmYiOnsiamt0IjoieGNEYmMyLU1zUklFTlF5bkFZR3RKMFZjMHhQVEJkZmpfMWlBZUk5TU1GbyJ9fQ',
    '1rS6k1Yz9ZsYWpk51vTv0GDJX4VJ9vp3Qb9v4ZNG1VjQQwvVvUpUjNao7ZA0hxmBqEOHPLv8NY5C_Jqjl-SJzA',
].join('.');
function sortJson(value) {
    if (Array.isArray(value))
        return value.map(sortJson);
    if (value !== null && typeof value === 'object') {
        return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortJson(value[key])]));
    }
    return value;
}
function canonical(value) {
    return JSON.stringify(sortJson(value));
}
function sha256(value) {
    return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}
function fileSha256(path) {
    return crypto.createHash('sha256').update(readFileSync(resolve(ROOT, path))).digest('hex');
}
function exactText(value, field) {
    if (typeof value !== 'string' || value.length === 0 || value.length > 256
        || /[\u0000-\u001f\u007f]/.test(value))
        throw new TypeError(`${field} is invalid`);
    return value;
}
function exactInstant(value) {
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value)
        || !Number.isFinite(Date.parse(value)))
        throw new TypeError('executed_at is invalid');
    return value;
}
function spki(key) {
    return key.export({ type: 'spki', format: 'der' }).toString('base64url');
}
function canonicalPythonSubset(value) {
    if (Array.isArray(value))
        return `[${value.map(canonicalPythonSubset).join(',')}]`;
    if (value !== null && typeof value === 'object') {
        return `{${Object.keys(value).sort().map((key) => (`${JSON.stringify(key)}:${canonicalPythonSubset(value[key])}`)).join(',')}}`;
    }
    return JSON.stringify(value);
}
function paramsHash(params) {
    return crypto.createHash('sha256').update(canonicalPythonSubset(params), 'utf8').digest('hex').slice(0, 16);
}
function ruleSummary(artifact) {
    return artifact.result.rule_results.map((entry) => `${entry.rule_name}=${entry.verdict}`).join('|');
}
function signCcsArtifact(artifact) {
    artifact.result.params_hash = paramsHash(artifact.command.params);
    artifact.result.receipt = crypto.createHmac('sha256', CCS_SECRET).update([
        artifact.result.trace_id,
        artifact.result.verdict,
        String(artifact.result.verified_at),
        artifact.result.tool,
        artifact.result.params_hash,
        ruleSummary(artifact),
    ].join(':'), 'utf8').digest('hex').slice(0, 32);
    return artifact;
}
function ccsArtifact(traceId = '0011223344556677') {
    const fixture = JSON.parse(readFileSync(resolve(ROOT, 'interop/ccs-aeb/fixtures/ccs-verifier-pypi-1.1.0.json'), 'utf8'));
    fixture.command.trace_id = traceId;
    fixture.command.tool = OASNT_ACTION_TYPE;
    fixture.command.params = { amount: '100.00', payee: 'acct_9' };
    fixture.result.trace_id = traceId;
    fixture.result.verdict = 'allow';
    fixture.result.block_reason = '';
    fixture.result.rule_results = fixture.result.rule_results.map((entry) => ({ ...entry, verdict: 'allow' }));
    fixture.result.verified_at = 1_800_000_000;
    fixture.result.tool = OASNT_ACTION_TYPE;
    return signCcsArtifact(fixture);
}
const ACTION = Object.freeze({
    action_type: ACTION_TYPE,
    native_action: {
        type: OASNT_ACTION_TYPE,
        parameters: { amount: '100.00', payee: 'acct_9' },
    },
});
const PUBLISHED_OASNT_ROOT = Object.freeze({
    '@version': OASNT_TRUST_ROOT_VERSION,
    use: 'enrolled-oasnt-signing-key',
    native_subject: 'agent-1',
    public_jwk: {
        kty: 'EC',
        crv: 'P-256',
        x: 'P7Vp3OZi4XYii2VHo4T08zkjKrKhCt-gY-oAATkXaao',
        y: 'QNEaWqPG2EI5-2AdT8oX-S4odj8TH9wj_JW2I2ILBoc',
    },
    jwk_thumbprint: 'xcDbc2-MsRIENQynAYGtJ0Vc0xPTBdfj_1iAeI9MMFo',
    enrollment: {
        hardware_attested: true,
        evidence_digest: `sha256:${'a'.repeat(64)}`,
    },
});
function oasntThumbprint(jwk) {
    return crypto.createHash('sha256').update(canonical({
        crv: jwk.crv,
        kty: jwk.kty,
        x: jwk.x,
        y: jwk.y,
    })).digest('base64url');
}
function mintOasntCompositionFixture() {
    const keys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = keys.publicKey.export({ format: 'jwk' });
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
        throw new Error('unexpected OASNT test JWK');
    }
    const thumbprint = oasntThumbprint({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y });
    const claims = {
        sub: 'agent-composition',
        adg: computeOasntActionDigest(OASNT_ACTION_TYPE, ACTION.native_action.parameters),
        dsp: computeOasntDisplayDigest(OASNT_ACTION_TYPE, ACTION.native_action.parameters),
        int: 'clean',
        jti: 'ccs-oasnt-composition-0001',
        iat: 1_800_000_000,
        exp: 1_800_000_060,
        cnf: { jkt: thumbprint },
    };
    const header = { alg: 'ES256', typ: 'oasnt+jwt' };
    const signingInput = `${Buffer.from(JSON.stringify(header)).toString('base64url')}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}`;
    const signature = crypto.sign('sha256', Buffer.from(signingInput, 'ascii'), {
        key: keys.privateKey,
        dsaEncoding: 'ieee-p1363',
    }).toString('base64url');
    const root = {
        '@version': OASNT_TRUST_ROOT_VERSION,
        use: 'enrolled-oasnt-signing-key',
        native_subject: claims.sub,
        public_jwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y },
        jwk_thumbprint: thumbprint,
        enrollment: {
            hardware_attested: true,
            evidence_digest: `sha256:${'b'.repeat(64)}`,
        },
    };
    return { token: `${signingInput}.${signature}`, root };
}
const STATUS = Object.freeze({
    checked_at: NOW,
    expires_at: new Date(Date.parse(NOW) + 60_000).toISOString(),
    revocation_checked: true,
    revoked: false,
    consumed: false,
});
function profile(id, mapperId, version, definition, omitted) {
    const pin = {
        version,
        definition,
        registry_entry_ref: `mapping:${id}`,
        mapper_id: mapperId,
        resolver: {
            id: mapperId,
            version: '1',
            implementation_digest: digestAeb({ implementation: mapperId, version: '1' }),
        },
        semantic_equivalence: {
            assertion: 'EQUIVALENT_UNDER_PROFILE',
            loss_policy: 'NO_MATERIAL_FIELD_LOSS',
            omitted_material_fields: [],
            omitted_nonmaterial_fields: omitted,
        },
        profile_digest: digestAeb(null),
    };
    pin.profile_digest = mappingProfileDigest(id, pin);
    return pin;
}
function registryEntry(id, kind, definition) {
    const entry = { kind, version: '1', status: 'active', definition };
    entry.definition_digest = registryEntryDigest(id, entry);
    return entry;
}
function check(id, protocol, description, passed, observed) {
    return { id, protocol, description, passed, observed };
}
export function assertContractLock() {
    const lock = JSON.parse(readFileSync(LOCK_PATH, 'utf8'));
    const packageJson = JSON.parse(readFileSync(resolve(ROOT, 'packages/verify/package.json'), 'utf8'));
    const files = lock.files.map((entry) => {
        const actual = fileSha256(entry.path);
        return { path: entry.path, expected: entry.sha256, actual, matched: actual === entry.sha256 };
    });
    return {
        valid: lock.contract_version === AEB_ADAPTER_VERSION
            && packageJson.version === lock.verify_package_version
            && files.every((entry) => entry.matched),
        contract_version: lock.contract_version,
        lock_digest: sha256(readFileSync(LOCK_PATH)),
        files,
    };
}
function buildComposition() {
    const ccsConfig = {
        '@version': CCS_AEB_CONFIG_VERSION,
        evidence_role: 'machine-policy-decision',
        subject: { id: 'system:ccs-local-verifier', kind: 'system' },
        issuer: 'https://ccs.example/verifier',
        audience: 'https://gate.example/admit',
        action_type: ACTION_TYPE,
        allowed_tools: [OASNT_ACTION_TYPE],
        required_rules: ['ssrf_protection', 'rce_protection'],
        max_receipt_age_seconds: 120,
        params_hash_bits: 64,
        deployment_scope: 'single-relying-party-local-hmac',
    };
    const ccsRoot = {
        '@version': CCS_AEB_TRUST_ROOT_VERSION,
        issuer: ccsConfig.issuer,
        audience: ccsConfig.audience,
        key_id: 'ccs-local-hmac-test-1',
        algorithm: 'HMAC-SHA256-TRUNC128',
        secret_base64url: CCS_SECRET.toString('base64url'),
    };
    const oasntConfig = {
        '@version': OASNT_AEB_CONFIG_VERSION,
        evidence_role: 'human-authorization',
        subject: { id: 'human:agent-composition', kind: 'human', native_id: 'agent-composition' },
        action_type: ACTION_TYPE,
        require_request_binding: false,
        clock_skew_seconds: 5,
        max_token_lifetime_seconds: 120,
        max_status_age_seconds: 120,
    };
    const publishedOasntConfig = {
        ...oasntConfig,
        subject: { id: 'human:agent-1', kind: 'human', native_id: 'agent-1' },
        require_request_binding: true,
    };
    const publishedOasntAction = {
        ...ACTION,
        request: {
            method: 'POST',
            path: '/v1/transfers',
            org_id: 'org_acme',
            scope: 'payments:write',
            body_sha256: '05be0ab936cd56cf971cc8b57f7132a690d4ed3bf63b37ac3cb81d6e289f847a',
        },
    };
    const compositionOasnt = mintOasntCompositionFixture();
    const ccs = ccsArtifact();
    const ccsAdapter = createCcsPyPiHmacAebAdapter({ config: ccsConfig, trust_roots: [ccsRoot] });
    const oasntAdapter = createOasntAebAdapter({ config: oasntConfig, trust_roots: [compositionOasnt.root] });
    const publishedOasntAdapter = createOasntAebAdapter({
        config: publishedOasntConfig,
        trust_roots: [PUBLISHED_OASNT_ROOT],
    });
    const ccsProfile = profile('ccs-native-action', CCS_CAID_MAPPER_ID, CCS_CAID_MAPPING_VERSION, createCcsNativeActionDefinition(ACTION_TYPE), [
        'command.agent_id', 'command.timestamp', 'command.trace_id',
        'result.block_reason', 'result.rule_results.reason', 'result.rule_results.latency_us',
        'result.error_code',
    ]);
    const oasntProfile = profile('oasnt-native-action', OASNT_CAID_MAPPER_ID, OASNT_CAID_MAPPING_VERSION, createOasntActionDefinition(ACTION_TYPE, false), ['token.int', 'token.cnf.jkt', 'token.jti', 'token.iat', 'token.exp', 'token.rqf']);
    const ccsInput = {
        artifact: ccs,
        artifact_ref: 'ccs:0011223344556677',
        status: STATUS,
        trust_roots: [ccsRoot],
        adapter_config: ccsConfig,
        expected_action: ACTION,
        now: NOW,
    };
    const oasntInput = {
        artifact: compositionOasnt.token,
        artifact_ref: 'oasnt:composition-action-only-v1',
        status: STATUS,
        trust_roots: [compositionOasnt.root],
        adapter_config: oasntConfig,
        expected_action: ACTION,
        now: NOW,
    };
    const publishedOasntNative = publishedOasntAdapter.verifyNative({
        artifact: PUBLISHED_OASNT_TOKEN,
        artifact_ref: 'oasnt:published-v5',
        status: STATUS,
        trust_roots: [PUBLISHED_OASNT_ROOT],
        adapter_config: publishedOasntConfig,
        expected_action: publishedOasntAction,
        now: NOW,
    });
    const ccsNative = ccsAdapter.verifyNative(ccsInput);
    const oasntNative = oasntAdapter.verifyNative(oasntInput);
    const ccsMapping = ccsAdapter.mapAction({ ...ccsInput, profile: ccsProfile, native: ccsNative });
    const oasntMapping = oasntAdapter.mapAction({ ...oasntInput, profile: oasntProfile, native: oasntNative });
    const ccsPin = {
        version: CCS_AEB_ADAPTER_VERSION,
        trust_roots: [ccsRoot],
        config: ccsConfig,
        config_digest: digestAeb(null),
        max_status_age_sec: 120,
    };
    ccsPin.config_digest = adapterPinDigest(CCS_AEB_ADAPTER_ID, ccsPin);
    const oasntPin = {
        version: OASNT_AEB_ADAPTER_VERSION,
        trust_roots: [compositionOasnt.root],
        config: oasntConfig,
        config_digest: digestAeb(null),
        max_status_age_sec: 120,
    };
    oasntPin.config_digest = adapterPinDigest(OASNT_AEB_ADAPTER_ID, oasntPin);
    const entries = {
        'mapping:ccs-native-action': registryEntry('mapping:ccs-native-action', 'mapping-profile', { profile_digest: ccsProfile.profile_digest }),
        'mapping:oasnt-native-action': registryEntry('mapping:oasnt-native-action', 'mapping-profile', { profile_digest: oasntProfile.profile_digest }),
        'role:machine-policy-decision': registryEntry('role:machine-policy-decision', 'evidence-role', { role: 'machine-policy-decision', subject_kinds: ['system'] }),
        'role:human-authorization': registryEntry('role:human-authorization', 'evidence-role', { role: 'human-authorization', subject_kinds: ['human'] }),
    };
    const registry = {
        '@version': AEB_REGISTRY_VERSION,
        registry_id: 'registry:ccs-oasnt-aeb-v1',
        epoch: 1,
        entries,
        registry_digest: digestAeb(null),
    };
    registry.registry_digest = unifiedRegistryDigest(registry);
    const evaluator = crypto.generateKeyPairSync('ed25519');
    const config = {
        '@version': AEB_ADAPTER_VERSION,
        relying_party_id: 'rp:ccs-oasnt-composition',
        evaluator_keys: { 'evaluator:reference': { public_key: spki(evaluator.publicKey) } },
        registry,
        accepted_mappers: [CCS_CAID_MAPPER_ID, OASNT_CAID_MAPPER_ID],
        adapters: { [CCS_AEB_ADAPTER_ID]: ccsPin, [OASNT_AEB_ADAPTER_ID]: oasntPin },
        profiles: { 'ccs-native-action': ccsProfile, 'oasnt-native-action': oasntProfile },
        requirements: {
            'requirement:policy-plus-human': {
                '@version': AEB_REQUIREMENT_VERSION,
                all_of: ['machine-policy-decision', 'human-authorization'],
                terms: [{ type: 'one-time-consumption' }],
            },
        },
    };
    const computed = computeCaid(ACTION, {
        suite: 'jcs-sha256',
        definitions: oasntProfile.definition.definitions,
    });
    if (!('caid' in computed) || typeof computed.caid !== 'string')
        throw new Error('shared CAID failed');
    const adapters = { [CCS_AEB_ADAPTER_ID]: ccsAdapter, [OASNT_AEB_ADAPTER_ID]: oasntAdapter };
    const artifacts = {
        [ccsInput.artifact_ref]: ccs,
        [oasntInput.artifact_ref]: compositionOasnt.token,
    };
    const statuses = { [ccsInput.artifact_ref]: STATUS, [oasntInput.artifact_ref]: STATUS };
    const makeEvaluation = (operationId) => evaluateAebEvidence({
        config,
        adapters,
        operation_id: operationId,
        consumption_nonce: `consume-${operationId}`,
        initiator_id: 'workload:agent-1',
        executor_id: 'workload:gate',
        requirement_ref: 'requirement:policy-plus-human',
        caid: computed.caid,
        expected_action: ACTION,
        evaluated_at: NOW,
        signer: { key_id: 'evaluator:reference', private_key: evaluator.privateKey },
        legs: [
            {
                adapter_id: CCS_AEB_ADAPTER_ID,
                profile_id: 'ccs-native-action',
                artifact_ref: ccsInput.artifact_ref,
                artifact: ccs,
                status: STATUS,
            },
            {
                adapter_id: OASNT_AEB_ADAPTER_ID,
                profile_id: 'oasnt-native-action',
                artifact_ref: oasntInput.artifact_ref,
                artifact: compositionOasnt.token,
                status: STATUS,
            },
        ],
    });
    const first = makeEvaluation('operation-1');
    const firstVerification = verifyAebEvaluation(first.record, {
        config,
        adapters,
        artifacts,
        mode: 'execution',
        now: NOW,
        expected_action: ACTION,
        current_statuses: statuses,
    });
    const changedAction = structuredClone(ACTION);
    changedAction.native_action.parameters.amount = '1000.00';
    const substitutionVerification = verifyAebEvaluation(first.record, {
        config,
        adapters,
        artifacts,
        mode: 'execution',
        now: NOW,
        expected_action: changedAction,
        current_statuses: statuses,
    });
    const store = new InMemoryAebConsumptionStore();
    const firstAdmission = authorizeAebExecution(first.record, {
        verification: firstVerification,
        local_authorization: true,
        store,
    });
    const firstOutcome = firstAdmission.reservation_key
        ? reconcileAebExecution(store, firstAdmission.reservation_key, 'INDETERMINATE')
        : { state: 'REFUSED' };
    const second = makeEvaluation('operation-2');
    const secondVerification = verifyAebEvaluation(second.record, {
        config,
        adapters,
        artifacts,
        mode: 'execution',
        now: NOW,
        expected_action: ACTION,
        current_statuses: statuses,
    });
    const replayAdmission = authorizeAebExecution(second.record, {
        verification: secondVerification,
        local_authorization: true,
        store,
    });
    const tamperedCcs = structuredClone(ccs);
    tamperedCcs.command.params.amount = '1000.00';
    const tamperedCcsNative = ccsAdapter.verifyNative({ ...ccsInput, artifact: tamperedCcs });
    const changedOasntNative = oasntAdapter.verifyNative({ ...oasntInput, expected_action: changedAction });
    return {
        ccsNative,
        oasntNative,
        publishedOasntNative,
        ccsMapping,
        oasntMapping,
        first,
        firstVerification,
        substitutionVerification,
        firstAdmission,
        firstOutcome,
        secondVerification,
        replayAdmission,
        tamperedCcsNative,
        changedOasntNative,
        computed,
    };
}
export function canonicalReportBytes(report) {
    return Buffer.from(canonical(report), 'utf8');
}
export function runSuite(input) {
    const runner = {
        name: exactText(input.runner_name, 'runner_name'),
        affiliation: exactText(input.runner_affiliation, 'runner_affiliation'),
        revision: exactText(input.runner_revision, 'runner_revision'),
        executed_at: exactInstant(input.executed_at),
        execution_owner: 'runner-asserted',
        implementation_owner: 'EMILIA Protocol',
        independent_implementation: false,
    };
    const lock = assertContractLock();
    const result = buildComposition();
    const sourceProtocolChecks = [
        check('CCS-PINNED-HMAC-ACCEPT', 'CCS', 'Pinned CCS 1.1.0 distribution/runtime 0.4.1 HMAC artifact verifies as machine-policy evidence.', result.ccsNative.native_verification === 'VERIFIED' && result.ccsNative.acceptance === 'ACCEPTED', { verification: result.ccsNative.native_verification, acceptance: result.ccsNative.acceptance }),
        check('CCS-MUTATED-PARAMS-REFUSE', 'CCS', 'Mutation after receipt creation is refused by the pinned CCS adapter.', result.tamperedCcsNative.acceptance === 'REJECTED', { acceptance: result.tamperedCcsNative.acceptance, reasons: result.tamperedCcsNative.reasons }),
        check('CCS-NATIVE-ACTION-MAP', 'CCS', 'CCS command material maps losslessly to the shared native-action projection.', result.ccsMapping.mapping === 'MATCH', { mapping: result.ccsMapping.mapping, caid: result.ccsMapping.caid }),
        check('OASNT-01-TOKEN-ACCEPT', 'OASNT', 'Published OASNT-01 compact token verifies under the pinned enrolled key.', result.publishedOasntNative.native_verification === 'VERIFIED'
            && result.publishedOasntNative.acceptance === 'ACCEPTED', {
            verification: result.publishedOasntNative.native_verification,
            acceptance: result.publishedOasntNative.acceptance,
        }),
        check('OASNT-COMPOSITION-TOKEN-ACCEPT', 'OASNT', 'Synthetic action-only OASNT-01 token verifies under its pinned enrolled key for this composition.', result.oasntNative.native_verification === 'VERIFIED' && result.oasntNative.acceptance === 'ACCEPTED', { verification: result.oasntNative.native_verification, acceptance: result.oasntNative.acceptance }),
        check('OASNT-ACTION-SUBSTITUTION-REFUSE', 'OASNT', 'Changing the expected action makes the published token fail closed.', result.changedOasntNative.acceptance === 'REJECTED', { acceptance: result.changedOasntNative.acceptance, reasons: result.changedOasntNative.reasons }),
        check('OASNT-NATIVE-ACTION-MAP', 'OASNT', 'OASNT maps the signed native action to the pinned AEB profile.', result.oasntMapping.mapping === 'MATCH', { mapping: result.oasntMapping.mapping, caid: result.oasntMapping.caid }),
    ];
    const aebCompositionChecks = [
        check('AEB-CONTRACT-LOCK', 'AEB', 'The compatibility lock matches AEB-ADAPTER-v1 contract bytes.', lock.valid, { lock_digest: lock.lock_digest, files: lock.files }),
        check('AEB-COMPOSE-SAME-ACTION', 'AEB', 'Both native legs independently map to one CAID and action digest.', result.ccsMapping.mapping === 'MATCH'
            && result.oasntMapping.mapping === 'MATCH'
            && result.ccsMapping.caid === result.oasntMapping.caid
            && result.ccsMapping.action_digest === result.oasntMapping.action_digest, {
            ccs_caid: result.ccsMapping.caid,
            oasnt_caid: result.oasntMapping.caid,
            ccs_action_digest: result.ccsMapping.action_digest,
            oasnt_action_digest: result.oasntMapping.action_digest,
        }),
        check('AEB-COMPOSE-ROLES-PRESERVED', 'AEB', 'Machine policy and human authorization remain separate required roles.', result.first.valid && result.first.record.legs.map((entry) => entry.evidence_role).sort().join(',')
            === 'human-authorization,machine-policy-decision', { roles: result.first.record.legs.map((entry) => entry.evidence_role).sort() }),
        check('AEB-COMPOSE-ADMISSION', 'AEB', 'A satisfied signed evaluation authorizes one reserved provider admission.', result.firstVerification.execution_authorizing && result.firstAdmission.state === 'AUTHORIZED', { verdict: result.first.record.verdict, admission: result.firstAdmission.state }),
        check('AEB-COMPOSE-APPROVE-A-EXECUTE-B', 'AEB', 'A signed evaluation for action A cannot authorize changed action B.', !result.substitutionVerification.execution_authorizing, { execution_authorizing: result.substitutionVerification.execution_authorizing, reasons: result.substitutionVerification.reasons }),
        check('AEB-COMPOSE-INDETERMINATE', 'AEB', 'A lost provider outcome remains reconciliation-required rather than guessed.', result.firstOutcome.state === 'RECONCILIATION_REQUIRED', { state: result.firstOutcome.state }),
        check('AEB-COMPOSE-REPLAY-AFTER-INDETERMINATE', 'AEB', 'A second operation cannot re-admit the same native authority after an indeterminate attempt.', result.secondVerification.execution_authorizing
            && result.replayAdmission.state === 'REFUSED'
            && result.replayAdmission.reason === 'consumption_conflict', { state: result.replayAdmission.state, reason: result.replayAdmission.reason }),
    ];
    const allChecks = [...sourceProtocolChecks, ...aebCompositionChecks];
    const reportBody = {
        '@version': 'CCS-OASNT-AEB-COMPOSITION-REPORT-v1',
        profile: 'ccs-oasnt-aeb-v1',
        runner,
        pins: {
            aeb_contract: AEB_ADAPTER_VERSION,
            aeb_contract_lock: lock.lock_digest,
            ccs_distribution: CCS_PYPI_DISTRIBUTION_VERSION,
            ccs_runtime: CCS_PYPI_RUNTIME_VERSION,
            oasnt_revision: OASNT_DRAFT_REVISION,
        },
        source_protocol_checks: sourceProtocolChecks,
        aeb_composition_checks: aebCompositionChecks,
        composition: {
            action_digest: result.oasntMapping.action_digest,
            caid: result.computed.caid,
            ccs_action_digest: result.ccsMapping.action_digest,
            ccs_caid: result.ccsMapping.caid,
            oasnt_action_digest: result.oasntMapping.action_digest,
            oasnt_caid: result.oasntMapping.caid,
            evidence_roles: result.first.record.legs.map((entry) => entry.evidence_role).sort(),
            evaluation_verdict: result.first.record.verdict,
            first_admission: result.firstAdmission.state,
            first_outcome: result.firstOutcome.state,
            replay_admission: result.replayAdmission.state,
        },
        passed: allChecks.every((entry) => entry.passed),
        known_limits: [
            'This run executes the EMILIA reference implementation and is not an independent implementation.',
            'The CCS checks are pinned to ccs-verifier distribution 1.1.0 whose installed runtime reports 0.4.1; they do not claim conformance to later CCS draft text.',
            'One OASNT native check is pinned to the published draft-thallapelly-oasnt-01 token vector; the two-leg composition uses a synthetic action-only token under the same verifier rules.',
            'A passing report is not IETF adoption, endorsement, certification, or proof of deployment.',
        ],
    };
    reportBody.implementation_status_markdown = `${runner.name} (${runner.affiliation}) reproduced the EMILIA reference composition at ${runner.revision} on ${runner.executed_at}: ${sourceProtocolChecks.filter((entry) => entry.passed).length}/${sourceProtocolChecks.length} pinned native-protocol checks and ${aebCompositionChecks.filter((entry) => entry.passed).length}/${aebCompositionChecks.length} AEB composition checks passed against ${AEB_ADAPTER_VERSION} (${lock.lock_digest}). This is a reproduction of the EMILIA reference runner, not an independent implementation or IETF endorsement.`;
    reportBody.report_digest = sha256(canonicalReportBytes(reportBody));
    return reportBody;
}
export function signReport(report, privateKey, keyId) {
    const bytes = canonicalReportBytes(report);
    const privateKeyObject = privateKey instanceof KeyObject
        ? privateKey
        : crypto.createPrivateKey(privateKey);
    const publicKey = crypto.createPublicKey(privateKeyObject.export({
        type: 'pkcs8',
        format: 'pem',
    }));
    return {
        report,
        signature: {
            alg: 'Ed25519',
            key_id: exactText(keyId, 'key_id'),
            public_key_spki_b64u: spki(publicKey),
            signed_report_b64u: bytes.toString('base64url'),
            value: crypto.sign(null, bytes, privateKeyObject).toString('base64url'),
        },
    };
}
export function verifyReportSignature(value) {
    try {
        if (value?.signature?.alg !== 'Ed25519')
            return false;
        const bytes = canonicalReportBytes(value.report);
        const claimed = Buffer.from(value.signature.signed_report_b64u, 'base64url');
        if (!bytes.equals(claimed))
            return false;
        const key = crypto.createPublicKey({
            key: Buffer.from(value.signature.public_key_spki_b64u, 'base64url'),
            format: 'der',
            type: 'spki',
        });
        return crypto.verify(null, bytes, key, Buffer.from(value.signature.value, 'base64url'));
    }
    catch {
        return false;
    }
}
function argument(name) {
    const at = process.argv.indexOf(name);
    return at === -1 ? undefined : process.argv[at + 1];
}
function main() {
    const emit = process.argv.includes('--emit');
    const report = runSuite({
        runner_name: argument('--runner-name') ?? 'EMILIA reference runner',
        runner_affiliation: argument('--runner-affiliation') ?? 'EMILIA Protocol',
        runner_revision: argument('--runner-revision') ?? 'repository-working-tree',
        executed_at: argument('--executed-at') ?? new Date().toISOString(),
    });
    const signingKeyPath = argument('--signing-key');
    const output = signingKeyPath
        ? signReport(report, readFileSync(resolve(signingKeyPath), 'utf8'), argument('--key-id') ?? 'runner:unspecified')
        : report;
    if (emit || argument('--output')) {
        const outputPath = resolve(argument('--output') ?? REFERENCE_REPORT_PATH);
        writeFileSync(outputPath, `${JSON.stringify(output, null, 2)}\n`, 'utf8');
        process.stdout.write(`${outputPath}\n`);
    }
    else {
        process.stdout.write(`${report.implementation_status_markdown}\n`);
    }
    if (!report.passed)
        process.exitCode = 1;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
    main();
