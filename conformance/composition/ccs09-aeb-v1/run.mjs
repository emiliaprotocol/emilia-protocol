// SPDX-License-Identifier: Apache-2.0
// Generated from run.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/** Bounded CCS-09 receipt compatibility checks using the unchanged historical adapter. */
import crypto from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { digestAeb, mappingProfileDigest, } from '../../../packages/verify/dist/aeb-adapter-contract.js';
import { CCS_V13_AEB_ADAPTER_ID, CCS_V13_AEB_ADAPTER_VERSION, CCS_V13_AEB_CONFIG_VERSION, CCS_V13_AEB_TRUST_ROOT_VERSION, CCS_V13_CAID_MAPPER_ID, CCS_V13_CAID_MAPPING_VERSION, CCS_V13_SOURCE_LOCK, createCcsV13AebActionDefinition, createCcsV13AebAdapter, } from '../../../packages/verify/dist/aeb-ccs-adapter.js';
import { canonicalizeFiniteJson } from '../../../packages/verify/dist/strict-json.js';
const HERE = dirname(fileURLToPath(import.meta.url));
const REPORT_PATH = resolve(HERE, 'report.reference.json');
const SAMPLE_PATH = resolve(HERE, 'sample-receipts.reference.json');
const ACTION_TYPE = 'agent.tool-invocation.1';
const NOW = '2030-09-01T00:00:20Z';
const NOW_SECONDS = Date.parse(NOW) / 1000;
const ISSUED_AT = NOW_SECONDS - 20;
const EXPIRES_AT = ISSUED_AT + 60;
const PRIVATE_KEY = crypto.createPrivateKey({
    key: Buffer.concat([
        Buffer.from('302e020100300506032b657004220420', 'hex'),
        crypto.createHash('sha256').update('emilia/ccs09-receipt-compatibility/public-test-key/v1').digest(),
    ]),
    format: 'der',
    type: 'pkcs8',
});
const PUBLIC_RAW = crypto.createPublicKey(PRIVATE_KEY)
    .export({ type: 'spki', format: 'der' }).subarray(-32);
const LEGACY_TEST_SECRET = crypto.createHash('sha256')
    .update('emilia/ccs09-receipt-compatibility/public-legacy-hmac-key/v1').digest();
function sha256Bytes(value) {
    return crypto.createHash('sha256').update(value).digest('hex');
}
function sha256Json(value) {
    return sha256Bytes(canonicalizeFiniteJson(value));
}
function prefixedJsonDigest(value) {
    return `sha256:${sha256Json(value)}`;
}
function canonicalRequest(command) {
    return {
        agent_id: command.agent_id,
        params: command.params,
        timestamp: command.timestamp,
        tool: command.tool,
        trace_id: command.trace_id,
    };
}
function legacyReceipt(unsigned) {
    const payload = [
        unsigned.trace_id, unsigned.verdict, unsigned.timestamp, unsigned.tool,
        unsigned.params_hash, unsigned.rule_summary, unsigned.request_hash,
        unsigned.response_hash, unsigned.runtime_context_hash, unsigned.action,
        unsigned.config_hash, unsigned.issuer, unsigned.audience, unsigned.nonce,
        unsigned.sequence, unsigned.issued_at, unsigned.expires_at,
    ].join(':');
    return crypto.createHmac('sha256', LEGACY_TEST_SECRET)
        .update(payload, 'utf8').digest('hex').slice(0, 32);
}
function signReceipt(fields) {
    return {
        ...fields,
        signature: crypto.sign(null, Buffer.from(canonicalizeFiniteJson(fields), 'utf8'), PRIVATE_KEY).toString('hex'),
    };
}
function mintReceipt(input) {
    const fullParamsHash = sha256Json(input.command.params);
    const base = {
        trace_id: input.command.trace_id,
        verdict: input.verdict,
        timestamp: ISSUED_AT,
        tool: input.command.tool,
        params_hash: fullParamsHash.slice(0, 16),
        rule_summary: input.verdict === 'allow'
            ? 'bounded_integer_inputs=allow'
            : input.verdict === 'deny' ? 'bounded_integer_inputs=deny' : 'review_required',
        verified_at: ISSUED_AT,
        block_reason: input.blockReason,
        request_hash: prefixedJsonDigest(canonicalRequest(input.command)),
        response_hash: input.response === null ? '' : prefixedJsonDigest(input.response),
        runtime_context_hash: prefixedJsonDigest(input.command.runtime_context),
        action: `ccs:tool-invoke:${input.command.tool}:${fullParamsHash}`,
        config_hash: prefixedJsonDigest({ policy_floor: 'bounded-integer-sum-v1' }),
        issuer: 'https://emilia-protocol.example/interop/ccs09-fixture',
        audience: 'https://gate.example/admit',
        nonce: input.nonce,
        sequence: input.sequence,
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_clock_skew: 5,
    };
    return signReceipt({ ...base, receipt: legacyReceipt(base) });
}
function profile() {
    const pin = {
        version: CCS_V13_CAID_MAPPING_VERSION,
        definition: createCcsV13AebActionDefinition(ACTION_TYPE),
        registry_entry_ref: 'mapping:ccs-v13-tool-action',
        mapper_id: CCS_V13_CAID_MAPPER_ID,
        resolver: {
            id: CCS_V13_CAID_MAPPER_ID,
            version: '1',
            implementation_digest: digestAeb({ implementation: CCS_V13_CAID_MAPPER_ID, version: '1' }),
        },
        semantic_equivalence: {
            assertion: 'EQUIVALENT_UNDER_PROFILE',
            loss_policy: 'NO_MATERIAL_FIELD_LOSS',
            omitted_material_fields: [],
            omitted_nonmaterial_fields: [
                'trace_id', 'verdict', 'timestamp', 'params_hash', 'rule_summary', 'receipt',
                'verified_at', 'block_reason', 'request_hash', 'response_hash',
                'runtime_context_hash', 'config_hash', 'issuer', 'audience', 'nonce',
                'sequence', 'issued_at', 'expires_at', 'max_clock_skew', 'signature',
            ],
        },
        profile_digest: digestAeb(null),
    };
    pin.profile_digest = mappingProfileDigest('ccs-v13-tool-action', pin);
    return pin;
}
function fixture(params = { left: 19, right: 23 }) {
    const command = {
        intake_version: '1.3',
        agent_id: 'agent:ccs09-public-fixture',
        tool: 'sum',
        params,
        timestamp: ISSUED_AT,
        trace_id: '0123456789abcdef',
        runtime_context: { environment: 'deterministic-fixture', tenant: 'public-interop' },
    };
    // Test response bytes are issuer assertions, not execution or effect evidence.
    const response = { result: 42 };
    const allowReceipt = mintReceipt({
        command,
        verdict: 'allow',
        blockReason: '',
        response,
        nonce: '00112233445566778899aabbccddeeff',
        sequence: 1,
    });
    const denyCommand = {
        ...command,
        params: { left: 1_000_001, right: 23 },
        trace_id: 'fedcba9876543210',
    };
    const denyReceipt = mintReceipt({
        command: denyCommand,
        verdict: 'deny',
        blockReason: 'bounded_integer_inputs',
        response: null,
        nonce: 'ffeeddccbbaa99887766554433221100',
        sequence: 2,
    });
    const config = {
        '@version': CCS_V13_AEB_CONFIG_VERSION,
        evidence_role: 'machine-policy-decision',
        subject: { id: 'system:ccs09-fixture-issuer', kind: 'system' },
        issuer: allowReceipt.issuer,
        audience: allowReceipt.audience,
        action_type: ACTION_TYPE,
        allowed_tools: ['sum'],
        max_receipt_age_seconds: 300,
        max_clock_skew_seconds: 5,
        deployment_scope: 'pinned-ed25519-issuer',
    };
    const root = {
        '@version': CCS_V13_AEB_TRUST_ROOT_VERSION,
        issuer: config.issuer,
        key_id: 'emilia-ccs09-public-test-key-1',
        algorithm: 'Ed25519',
        public_key_raw_base64: PUBLIC_RAW.toString('base64'),
        public_key_fingerprint_sha256_16: sha256Bytes(PUBLIC_RAW).slice(0, 16),
    };
    const action = {
        action_type: ACTION_TYPE,
        parameters: { tool: command.tool, arguments: command.params },
    };
    const status = {
        checked_at: NOW,
        expires_at: '2030-09-01T00:01:00Z',
        revocation_checked: true,
        revoked: false,
        consumed: false,
    };
    const adapter = createCcsV13AebAdapter({ config, trust_roots: [root] });
    const input = {
        artifact: allowReceipt,
        artifact_ref: 'ccs09:fixture:sum-001',
        status,
        trust_roots: [root],
        adapter_config: config,
        expected_action: action,
        now: NOW,
    };
    return { command, response, allowReceipt, denyReceipt, config, root, action, adapter, input, profile: profile() };
}
function check(id, layer, description, passed, observed) {
    return { id, layer, description, passed, observed };
}
const TARGET = Object.freeze({
    draft: 'draft-correctover-ccs-09',
    url: 'https://www.ietf.org/archive/id/draft-correctover-ccs-09.txt',
    sha256: '8fe3b74e378b793fbd9d218949278cd21def73ff329101316bd83f0d240c958a',
    bytes: 160739,
    receipt_shape: 'v1.3; 22 fields; detached Ed25519 over fields 1-21',
});
function resign(receipt, changes) {
    const fields = { ...receipt, ...changes };
    delete fields.signature;
    return signReceipt(fields);
}
function signatureValid(receipt) {
    const fields = { ...receipt };
    delete fields.signature;
    return crypto.verify(null, Buffer.from(canonicalizeFiniteJson(fields), 'utf8'), crypto.createPublicKey(PRIVATE_KEY), Buffer.from(String(receipt.signature), 'hex'));
}
function altered(value) {
    if (typeof value === 'number')
        return value + 1;
    if (typeof value === 'string')
        return value.length ? (value[0] === 'a' ? 'b' : 'a') + value.slice(1) : 'changed';
    throw new TypeError('unexpected receipt field type');
}
export function sampleReceiptSet() {
    const f = fixture();
    return {
        '@version': 'CCS09-RECEIPT-COMPATIBILITY-FIXTURES-v1',
        provenance: 'emilia-generated-deterministic-test-fixtures',
        target: TARGET,
        command: f.command,
        issuer_asserted_response: f.response,
        receipts: [
            { id: 'allow', receipt: f.allowReceipt },
            { id: 'deny', receipt: f.denyReceipt },
            { id: 'escalate', receipt: mintReceipt({
                    command: f.command, verdict: 'escalate', blockReason: 'review_required',
                    response: null, nonce: '00000000000000000000000000000003', sequence: 3,
                }) },
        ],
        relying_party_trust_root: f.root,
        limitations: [
            'The deterministic Ed25519 and legacy HMAC keys are public test material, never production keys.',
            'These fixtures were generated by EMILIA; they are not upstream CCS output or an external operator run.',
            'Response bytes are issuer assertions; there is no Gate, provider call, durable status store, or effect proof in this runner.',
            'The historical CCS-05 adapter ID and source lock are retained deliberately; the target revision is a separate compatibility claim.',
        ],
    };
}
export function runSuite() {
    const f = fixture();
    const native = f.adapter.verifyNative(f.input);
    const mapped = f.adapter.mapAction({ ...f.input, profile: f.profile, native });
    const verify = (artifact) => f.adapter.verifyNative({ ...f.input, artifact });
    const map = (artifact, expected_action = f.action, pin = f.profile) => f.adapter.mapAction({ ...f.input, artifact, expected_action, profile: pin, native: verify(artifact) });
    const noMappingInput = { ...f.input, expected_action: null };
    const noMappingNative = f.adapter.verifyNative(noMappingInput);
    const absentMapping = f.adapter.mapAction({
        ...f.input, native, profile: undefined,
    });
    const badProfile = { ...f.profile, profile_digest: digestAeb({ changed: true }) };
    const wrongAction = { ...f.action, parameters: { tool: 'sum', arguments: { left: 19, right: 24 } } };
    const fullDigestChanged = resign(f.allowReceipt, {
        action: f.allowReceipt.action.slice(0, -48) + '0'.repeat(48),
    });
    const signatureTamper = verify({ ...f.allowReceipt, response_hash: 'sha256:' + 'f'.repeat(64) });
    const wrongRaw = Buffer.alloc(32, 7);
    const wrongRoot = {
        ...f.root, public_key_raw_base64: wrongRaw.toString('base64'),
        public_key_fingerprint_sha256_16: sha256Bytes(wrongRaw).slice(0, 16),
    };
    const wrongKey = createCcsV13AebAdapter({ config: f.config, trust_roots: [wrongRoot] })
        .verifyNative({ ...f.input, trust_roots: [wrongRoot] });
    const audienceConfig = { ...f.config, audience: 'https://other.example/admit' };
    const audience = createCcsV13AebAdapter({ config: audienceConfig, trust_roots: [f.root] })
        .verifyNative({ ...f.input, adapter_config: audienceConfig });
    const expired = f.adapter.verifyNative({ ...f.input, now: '2030-09-01T00:02:00Z' });
    const future = f.adapter.verifyNative({ ...f.input, now: '2030-08-31T23:59:50Z' });
    const deny = verify(f.denyReceipt);
    const escalateReceipt = sampleReceiptSet().receipts[2].receipt;
    const escalate = verify(escalateReceipt);
    const statusResult = (changes) => f.adapter.verifyNative({ ...f.input, status: { ...f.input.status, ...changes } });
    const consumed = statusResult({ consumed: true });
    const unknown = statusResult({ unavailable: true });
    const revoked = statusResult({ revoked: true });
    const fieldMutations = Object.entries(f.allowReceipt).map(([field, value]) => {
        const artifact = { ...f.allowReceipt, [field]: altered(value) };
        return { field, signature_valid: signatureValid(artifact),
            native_verification: verify(artifact).native_verification };
    });
    const extraField = resign(f.allowReceipt, { unexpected: 'signed-but-outside-profile' });
    const deletedField = { ...f.allowReceipt };
    delete deletedField.rule_summary;
    delete deletedField.signature;
    const missingField = signReceipt(deletedField);
    const unicodeReceipt = resign(f.allowReceipt, { rule_summary: '承認 café 🌱 e\u0301' });
    const unicodeNative = verify(unicodeReceipt);
    // Hand-pinned UTF-8 bytes check key order, non-ASCII text, and preserved NFD.
    const unicodeCanonicalBytes = Buffer.from(canonicalizeFiniteJson({ z: 'e\u0301', a: 'café 🌱' }), 'utf8').toString('hex');
    const unicodeGoldenBytes = '7b2261223a22636166c3a920f09f8cb1222c227a223a2265cc81227d';
    const unicodeFixture = fixture({ label: 'café 🌱' });
    const unicodeArgsNative = unicodeFixture.adapter.verifyNative(unicodeFixture.input);
    const unicodeArgsMapping = unicodeFixture.adapter.mapAction({
        ...unicodeFixture.input, profile: unicodeFixture.profile, native: unicodeArgsNative,
    });
    const fractionFixture = fixture({ amount: 1.5 });
    const fractionNative = fractionFixture.adapter.verifyNative(fractionFixture.input);
    const fractionMapping = fractionFixture.adapter.mapAction({
        ...fractionFixture.input, profile: fractionFixture.profile, native: fractionNative,
    });
    const reordered = Object.fromEntries(Object.entries(f.allowReceipt).reverse());
    const checks = [
        check('CCS09-SHAPE', 'RECEIPT', 'The local fixture has the 22-field v1.3 shape, not the distinct PyPI receipt_version shape.', Object.keys(f.allowReceipt).length === 22 && !('receipt_version' in f.allowReceipt), Object.keys(f.allowReceipt)),
        check('CCS09-SIGNED-21-FIELDS', 'RECEIPT', 'Ed25519 authenticates all fields except the detached signature.', signatureValid(f.allowReceipt), { signed_fields: 21, signature_bytes: Buffer.from(f.allowReceipt.signature, 'hex').length }),
        check('CCS09-NATIVE-WITHOUT-MAPPING', 'RECEIPT', 'Native receipt acceptance does not require an AEB profile or expected action.', noMappingNative.native_verification === 'VERIFIED' && noMappingNative.acceptance === 'ACCEPTED', noMappingNative),
        check('CCS09-OPTIONAL-EXACT-MAP', 'OPTIONAL-MAPPING', 'An explicitly selected pinned profile maps the exact tool and arguments.', mapped.mapping === 'MATCH', mapped),
        check('CCS09-ABSENT-MAPPING', 'OPTIONAL-MAPPING', 'Without an opted-in mapping profile the receipt remains valid but no AEB MATCH is inferred.', absentMapping.mapping === 'INDETERMINATE' && noMappingNative.acceptance === 'ACCEPTED', absentMapping),
        check('CCS09-MAPPING-PIN-DRIFT', 'OPTIONAL-MAPPING', 'Changed mapping pins refuse correlation.', map(f.allowReceipt, f.action, badProfile).mapping === 'INDETERMINATE', map(f.allowReceipt, f.action, badProfile)),
        check('CCS09-ARGUMENT-SUBSTITUTION', 'OPTIONAL-MAPPING', 'Different executor-owned arguments do not match.', map(f.allowReceipt, wrongAction).mapping === 'MISMATCH', map(f.allowReceipt, wrongAction)),
        check('CCS09-FULL-ACTION-DIGEST', 'OPTIONAL-MAPPING', 'Changing the full signed digest while retaining its short prefix refuses the match.', verify(fullDigestChanged).native_verification === 'VERIFIED' && map(fullDigestChanged).mapping === 'MISMATCH', map(fullDigestChanged)),
        check('CCS09-SIGNATURE-TAMPER', 'RECEIPT', 'A response digest cannot be changed without invalidating the signature.', signatureTamper.native_verification === 'FAILED', signatureTamper),
        check('CCS09-UNTRUSTED-KEY', 'RECEIPT', 'A different relying-party key cannot validate this signature.', wrongKey.native_verification === 'FAILED', wrongKey),
        check('CCS09-AUDIENCE', 'RP-POLICY', 'A cryptographically valid receipt for another audience is rejected.', audience.native_verification === 'VERIFIED' && audience.acceptance === 'REJECTED', audience),
        check('CCS09-EXPIRY', 'RP-POLICY', 'A receipt outside its validity window is rejected.', expired.native_verification === 'VERIFIED' && expired.acceptance === 'REJECTED', expired),
        check('CCS09-NOT-YET-VALID', 'RP-POLICY', 'A future receipt is rejected before its allowed clock-skew window.', future.native_verification === 'VERIFIED' && future.acceptance === 'REJECTED', future),
        check('CCS09-DENY', 'RP-POLICY', 'A valid deny remains rejected and cannot yield a match.', deny.native_verification === 'VERIFIED' && deny.acceptance === 'REJECTED' && map(f.denyReceipt).mapping === 'INDETERMINATE', deny),
        check('CCS09-ESCALATE', 'RP-POLICY', 'A valid escalate remains indeterminate and cannot yield a match.', escalate.native_verification === 'VERIFIED' && escalate.acceptance === 'INDETERMINATE' && map(escalateReceipt).mapping === 'INDETERMINATE', escalate),
        check('CCS09-CONSUMED-STATUS', 'RP-POLICY', 'A supplied consumed status refuses receipt acceptance; no durable store is claimed.', consumed.acceptance === 'REJECTED' && consumed.reasons.includes('evidence_consumed'), consumed),
        check('CCS09-UNKNOWN-STATUS', 'RP-POLICY', 'Unavailable status cannot be promoted into acceptance.', unknown.acceptance === 'INDETERMINATE', unknown),
        check('CCS09-REVOKED-STATUS', 'RP-POLICY', 'A supplied revoked status refuses acceptance.', revoked.acceptance === 'REJECTED', revoked),
        check('CCS09-MACHINE-POLICY-ROLE', 'RP-POLICY', 'This pinned profile emits only system machine-policy evidence, never human approval or authorization.', native.evidence_role === 'machine-policy-decision' && native.subject.kind === 'system'
            && !('authorized' in native) && !('executed' in native), { evidence_role: native.evidence_role, subject: native.subject }),
        check('CCS09-EVERY-FIELD-TAMPER', 'RECEIPT', 'Mutating each of the 22 fields separately invalidates cryptography and native verification.', fieldMutations.every((entry) => !entry.signature_valid && entry.native_verification === 'FAILED'), fieldMutations),
        check('CCS09-CLOSED-KEYSET-EXTRA', 'RECEIPT', 'Even a correctly signed extra field is outside this closed compatibility profile.', signatureValid(extraField) && verify(extraField).native_verification === 'FAILED', verify(extraField)),
        check('CCS09-CLOSED-KEYSET-MISSING', 'RECEIPT', 'Even a correctly signed receipt missing a required field is refused.', signatureValid(missingField) && verify(missingField).native_verification === 'FAILED', verify(missingField)),
        check('CCS09-UNICODE-SIGNED-TEXT', 'RECEIPT', 'UTF-8 signed metadata round-trips through canonicalization and Ed25519.', unicodeCanonicalBytes === unicodeGoldenBytes && signatureValid(unicodeReceipt)
            && unicodeNative.native_verification === 'VERIFIED' && unicodeNative.acceptance === 'ACCEPTED', { native: unicodeNative, canonical_utf8_hex: unicodeCanonicalBytes, expected_utf8_hex: unicodeGoldenBytes }),
        check('CCS09-UNICODE-ARGUMENT-BOUNDARY', 'OPTIONAL-MAPPING', 'Valid signed Unicode arguments are outside the existing ASCII-only mapping subset.', unicodeArgsNative.acceptance === 'ACCEPTED' && unicodeArgsMapping.mapping === 'INDETERMINATE', { native: unicodeArgsNative, mapping: unicodeArgsMapping }),
        check('CCS09-FRACTIONAL-ARGUMENT-BOUNDARY', 'OPTIONAL-MAPPING', 'Valid signed fractional arguments are outside the existing safe-integer mapping subset.', fractionNative.acceptance === 'ACCEPTED' && fractionMapping.mapping === 'INDETERMINATE', { native: fractionNative, mapping: fractionMapping }),
        check('CCS09-OBJECT-ORDER', 'RECEIPT', 'Object insertion order does not change canonical signed bytes.', signatureValid(reordered) && verify(reordered).native_verification === 'VERIFIED', verify(reordered)),
    ];
    const report = {
        '@version': 'CCS09-RECEIPT-COMPATIBILITY-REPORT-v1',
        profile: 'ccs09-aeb-v1',
        target: TARGET,
        mapping_policy: 'OPTIONAL',
        claim_scope: {
            bounded_receipt_compatibility: true,
            full_ccs09_conformance: false,
            external_operator_run: false,
            upstream_package_execution: false,
            source_bytes_verified_by_this_runner: false,
            pre_effect_enforcement: false,
            durable_consumption: false,
            provider_effect_proof: false,
        },
        pins: {
            adapter_id: CCS_V13_AEB_ADAPTER_ID,
            adapter_version: CCS_V13_AEB_ADAPTER_VERSION,
            adapter_source_lock: CCS_V13_SOURCE_LOCK,
            mapping_profile_digest: f.profile.profile_digest,
            sample_set_digest: prefixedJsonDigest(sampleReceiptSet()),
        },
        checks,
        field_mutations: fieldMutations,
        passed: checks.every((entry) => entry.passed),
        known_limits: [
            'The target source coordinates are pins, not a source-byte verification result. Run verify-sources.mjs separately.',
            'This is self-run compatibility evidence over local fixtures, not full CCS-09 conformance or a newer external interoperability result.',
            'The historical CCS-05 adapter and its source lock are unchanged and are identified separately from the CCS-09 target.',
            'The opted-in mapping supports safe integers and printable ASCII argument keys and strings, not every JSON/JCS value.',
            'A verified CCS allow reports machine policy only. Mapping is optional and never grants execution authority.',
            'Status is supplied by the test fixture, not fetched from a production authority or persisted in a durable store.',
            'The legacy HMAC field is authenticated issuer data, not independently checked as a cross-domain trust anchor.',
            'No receipt lifecycle deployment, independent key distribution, provider execution, or effect verification is exercised.',
            'The private fixture key is public deterministic test material.',
        ],
    };
    return { ...report, report_digest: prefixedJsonDigest(report) };
}
function main() {
    const args = process.argv.slice(2);
    if (args.some((arg) => !['--write', '--check'].includes(arg))) {
        throw new Error('unsupported argument; use --write or --check');
    }
    const report = runSuite();
    const sample = sampleReceiptSet();
    const renderedReport = JSON.stringify(report, null, 2) + '\n';
    const renderedSample = JSON.stringify(sample, null, 2) + '\n';
    if (process.argv.includes('--write')) {
        writeFileSync(REPORT_PATH, renderedReport);
        writeFileSync(SAMPLE_PATH, renderedSample);
    }
    if (process.argv.includes('--check')) {
        if (readFileSync(REPORT_PATH, 'utf8') !== renderedReport)
            throw new Error('CCS-09 compatibility report is stale');
        if (readFileSync(SAMPLE_PATH, 'utf8') !== renderedSample)
            throw new Error('CCS-09 compatibility fixtures are stale');
    }
    process.stdout.write(renderedReport);
    if (!report.passed)
        process.exitCode = 1;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
    main();
