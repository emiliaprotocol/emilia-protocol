// SPDX-License-Identifier: Apache-2.0
// Generated from run.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * Synthetic TrueAlter worker -> EMILIA Gate -> FC10 executor composition.
 *
 * This runner validates the collaborator-supplied provenance and native-wire
 * fixture, computes an EMILIA CAID over the material action, and exercises one
 * in-memory admission domain. It is a deterministic conformance model, not a
 * live TrueAlter service, durable multi-process deployment, or physical OT test.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize, computeCaid } from '../../../packages/verify/vendor/caid.mjs';
export const PROFILE = 'EP-WORKER-GATE-OT-COMPOSITION-v0.1';
const REPORT_VERSION = 'WORKER-GATE-OT-REFERENCE-REPORT-v0.1';
const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = resolve(HERE, 'fixtures/truealter-fc10.synthetic.v2.json');
const ACTION_DEFINITION_PATH = resolve(HERE, 'caid-action-definition.v1.json');
const CAID_PIN_PATH = resolve(HERE, 'caid-pin.v1.json');
const REFERENCE_PATH = resolve(HERE, 'report.reference.json');
const EXPECTED_AUDIENCE = 'emilia-gate-synthetic';
const EXPECTED_ISSUER = '~ada';
const EXPECTED_TOOL = 'ot.modbus.write_multiple_registers';
const MAX_FIXTURE_TTL_SECONDS = 300;
const FIXTURE_NOW = 1_790_208_001;
const PROVIDER_ID = 'provider:modbus-synthetic';
const ACTION_DEFINITION_BYTES = readFileSync(ACTION_DEFINITION_PATH);
const ACTION_DEFINITION = Object.freeze(JSON.parse(ACTION_DEFINITION_BYTES.toString('utf8')));
const ACTION_TYPE = ACTION_DEFINITION.action_type;
const CAID_PIN = Object.freeze(JSON.parse(readFileSync(CAID_PIN_PATH, 'utf8')));
function sha256(value) {
    return crypto.createHash('sha256').update(value).digest('hex');
}
function canonical(value) {
    const result = canonicalize(value);
    if (!result.ok)
        throw new Error(`canonicalization refused: ${result.refusals.join(',')}`);
    return result.canonical;
}
function digest(value) {
    return sha256(Buffer.from(canonical(value), 'utf8'));
}
function same(left, right) {
    return canonical(left) === canonical(right);
}
function deepFreeze(value) {
    if (value && typeof value === 'object' && !Object.isFrozen(value)) {
        Object.freeze(value);
        for (const entry of Object.values(value))
            deepFreeze(entry);
    }
    return value;
}
function loadFixture() {
    const bytes = readFileSync(FIXTURE_PATH);
    return { bytes, value: JSON.parse(bytes.toString('utf8')) };
}
function materialAction(value) {
    return {
        action_type: ACTION_TYPE,
        function_code: value.function_code,
        unit_id: value.unit_id,
        start_address: value.start_address,
        quantity: value.quantity,
        values: structuredClone(value.values),
        site: value.site,
        device: value.device,
    };
}
function caidFor(value) {
    const result = computeCaid(materialAction(value), {
        suite: CAID_PIN.suite,
        definitions: [ACTION_DEFINITION],
    });
    if (!('caid' in result)
        || typeof result.caid !== 'string'
        || typeof result.digest !== 'string') {
        throw new Error(`CAID refused: ${JSON.stringify(result)}`);
    }
    return { caid: result.caid, digest: result.digest };
}
function decodeB64Json(value) {
    return JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
}
export function verifyFixtureProvenance(provenance, publicJwk, options = {}) {
    const now = options.now ?? FIXTURE_NOW;
    const audience = options.audience ?? EXPECTED_AUDIENCE;
    if (!provenance || typeof provenance.jws !== 'string')
        return { valid: false, reason: 'missing_jws' };
    const parts = provenance.jws.split('.');
    if (parts.length !== 3)
        return { valid: false, reason: 'malformed_jws' };
    let header;
    let payload;
    try {
        header = decodeB64Json(parts[0]);
        payload = decodeB64Json(parts[1]);
    }
    catch {
        return { valid: false, reason: 'malformed_jws_json' };
    }
    if (!same(header, provenance.header))
        return { valid: false, reason: 'header_projection_mismatch' };
    if (!same(payload, provenance.payload))
        return { valid: false, reason: 'payload_projection_mismatch' };
    if (!same(Object.keys(header).sort(), ['alg', 'kid']))
        return { valid: false, reason: 'unexpected_protected_header' };
    if (header.alg !== 'ES256' || header.kid !== publicJwk.kid)
        return { valid: false, reason: 'unaccepted_key' };
    if (payload.iss !== EXPECTED_ISSUER)
        return { valid: false, reason: 'issuer_mismatch' };
    if (payload.tool !== EXPECTED_TOOL)
        return { valid: false, reason: 'tool_mismatch' };
    if (payload.aud !== audience)
        return { valid: false, reason: 'audience_mismatch' };
    if (!Number.isInteger(payload.iat)
        || !Number.isInteger(payload.exp)
        || payload.iat > now
        || payload.exp <= now
        || payload.exp - payload.iat > MAX_FIXTURE_TTL_SECONDS) {
        return { valid: false, reason: 'outside_validity' };
    }
    if (typeof payload.nonce !== 'string'
        || !/^[A-Za-z0-9_-]+$/.test(payload.nonce)
        || Buffer.from(payload.nonce, 'base64url').length < 16) {
        return { valid: false, reason: 'invalid_nonce' };
    }
    if (typeof payload.jti !== 'string' || payload.jti.length === 0)
        return { valid: false, reason: 'missing_jti' };
    if (typeof payload.args_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(payload.args_sha256)) {
        return { valid: false, reason: 'invalid_action_digest' };
    }
    const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii');
    const signature = Buffer.from(parts[2], 'base64url');
    const key = crypto.createPublicKey({
        key: publicJwk,
        format: 'jwk',
    });
    const signatureValid = signature.length === 64 && crypto.verify('sha256', signingInput, { key, dsaEncoding: 'ieee-p1363' }, signature);
    if (!signatureValid)
        return { valid: false, reason: 'invalid_signature' };
    if (sha256(Buffer.from(provenance.jws, 'utf8')) !== provenance.jws_sha256) {
        return { valid: false, reason: 'jws_digest_mismatch' };
    }
    return { valid: true, header, payload };
}
export function decodeFc10Adu(hex, context = {}) {
    if (typeof hex !== 'string' || !/^[0-9a-f]+$/i.test(hex) || hex.length % 2 !== 0) {
        throw new Error('invalid_hex');
    }
    const bytes = Buffer.from(hex, 'hex');
    if (bytes.length < 13)
        throw new Error('truncated_adu');
    const protocolId = bytes.readUInt16BE(2);
    const declaredLength = bytes.readUInt16BE(4);
    const unitId = bytes[6];
    const functionCode = bytes[7];
    const startAddress = bytes.readUInt16BE(8);
    const quantity = bytes.readUInt16BE(10);
    const byteCount = bytes[12];
    if (declaredLength !== bytes.length - 6)
        throw new Error('mbap_length_mismatch');
    if (protocolId !== 0)
        throw new Error('protocol_id_nonzero');
    if (unitId < 1 || unitId > 247)
        throw new Error('unit_id_out_of_range');
    if (functionCode !== 0x10)
        throw new Error('not_fc10');
    if (quantity < 1 || quantity > 123)
        throw new Error('quantity_out_of_range');
    if (byteCount !== quantity * 2 || bytes.length !== 13 + byteCount)
        throw new Error('byte_count_mismatch');
    if (context.device_context_unit !== undefined && unitId !== context.device_context_unit) {
        throw new Error('unit_context_mismatch');
    }
    const values = [];
    for (let offset = 13; offset < bytes.length; offset += 2)
        values.push(bytes.readUInt16BE(offset));
    return {
        transaction_id: bytes.readUInt16BE(0),
        action: {
            function_code: functionCode,
            unit_id: unitId,
            start_address: startAddress,
            quantity,
            values,
            site: context.site,
            device: context.device,
        },
    };
}
class AdmissionDomain {
    id;
    authorityUses;
    jtiUses;
    records;
    constructor(id) {
        this.id = id;
        this.authorityUses = new Map();
        this.jtiUses = new Map();
        this.records = new Map();
    }
    reserve(binding) {
        if (this.jtiUses.has(binding.jti))
            return { ok: false, reason: 'provenance_replay' };
        if (this.authorityUses.has(binding.authority_id))
            return { ok: false, reason: 'authority_already_reserved' };
        const record = {
            ...structuredClone(binding),
            state: 'RESERVED',
            provider_entries: 0,
            provider_outcome: 'NOT_ENTERED',
            effect_relation: 'UNOBSERVED',
        };
        this.records.set(binding.operation_id, record);
        this.authorityUses.set(binding.authority_id, binding.operation_id);
        this.jtiUses.set(binding.jti, binding.operation_id);
        return { ok: true, record };
    }
    enter(operationId) {
        const record = this.records.get(operationId);
        if (!record || record.state !== 'RESERVED')
            return false;
        record.state = 'PROVIDER_ENTERED';
        record.provider_entries += 1;
        record.provider_outcome = 'PENDING';
        return true;
    }
    commit(operationId) {
        const record = this.records.get(operationId);
        if (!record || record.state !== 'PROVIDER_ENTERED')
            return false;
        record.state = 'COMMITTED';
        record.provider_outcome = 'COMMITTED';
        return true;
    }
    markIndeterminate(operationId) {
        const record = this.records.get(operationId);
        if (!record || record.state !== 'PROVIDER_ENTERED')
            return false;
        record.state = 'INDETERMINATE';
        record.provider_outcome = 'INDETERMINATE';
        return true;
    }
    reconcile(operationId, evidence) {
        const record = this.records.get(operationId);
        if (!record || record.state !== 'INDETERMINATE')
            return false;
        if (evidence.authenticated !== true
            || evidence.action_caid !== record.action_caid
            || evidence.provider_idempotency_key !== record.provider_idempotency_key)
            return false;
        record.state = evidence.provider_outcome;
        record.provider_outcome = evidence.provider_outcome;
        record.effect_relation = evidence.effect_relation;
        return true;
    }
    entries() {
        return [...this.records.values()].reduce((sum, record) => sum + record.provider_entries, 0);
    }
}
function providerKey(authorityId, actionCaid) {
    return `sha256:${sha256(Buffer.from(`EP-WORKER-GATE-OT\0${authorityId}\0${actionCaid}`, 'utf8'))}`;
}
function validateDelivery(fixture, delivery) {
    const provenance = verifyFixtureProvenance(delivery.provenance, fixture.keys.public_jwk);
    if (!provenance.valid)
        return { ok: false, reason: provenance.reason };
    const decoded = decodeFc10Adu(delivery.observed_fc10_adu_hex, {
        site: delivery.observed_action.site,
        device: delivery.observed_action.device,
    });
    if (!same(decoded.action, delivery.observed_action))
        return { ok: false, reason: 'wire_projection_mismatch' };
    if (digest(delivery.observed_action) !== delivery.observed_action_digest) {
        return { ok: false, reason: 'observed_digest_mismatch' };
    }
    return { ok: true, provenance, decoded, actionCaid: caidFor(decoded.action).caid };
}
async function executeDelivery({ fixture, domain, delivery, authority, operationId, loseResponse = false }) {
    let checked;
    try {
        checked = validateDelivery(fixture, delivery);
    }
    catch (error) {
        return { state: 'REFUSED', reason: error.message, provider_entries: domain.entries() };
    }
    if (!checked.ok)
        return { state: 'REFUSED', reason: checked.reason, provider_entries: domain.entries() };
    if (checked.provenance.payload.args_sha256 !== fixture.action.A_digest) {
        return { state: 'REFUSED', reason: 'provenance_action_digest_mismatch', provider_entries: domain.entries() };
    }
    if (!authority)
        return { state: 'REFUSED', reason: 'missing_authority', provider_entries: domain.entries() };
    if (checked.actionCaid !== authority.action_caid) {
        return { state: 'REFUSED', reason: 'exact_action_binding_mismatch', provider_entries: domain.entries() };
    }
    const reservation = domain.reserve({
        operation_id: operationId,
        authority_id: authority.authority_id,
        action_caid: checked.actionCaid,
        jti: checked.provenance.payload.jti,
        provider_id: PROVIDER_ID,
        provider_idempotency_key: providerKey(authority.authority_id, checked.actionCaid),
    });
    if (!reservation.ok)
        return { state: 'REFUSED', reason: reservation.reason, provider_entries: domain.entries() };
    assert.equal(domain.enter(operationId), true);
    await Promise.resolve();
    if (loseResponse) {
        assert.equal(domain.markIndeterminate(operationId), true);
        return { state: 'INDETERMINATE', retry_allowed: false, provider_entries: domain.entries(), record: reservation.record };
    }
    assert.equal(domain.commit(operationId), true);
    return {
        state: 'EXECUTED',
        provider_entries: domain.entries(),
        provider_outcome: reservation.record.provider_outcome,
        effect_relation: reservation.record.effect_relation,
    };
}
function caseResult(id, category, passed, expected, observed) {
    return { id, category, passed, expected, observed };
}
export async function buildReferenceReport() {
    const loaded = loadFixture();
    const fixture = loaded.value;
    const cases = [];
    const allDeliveries = Object.values(fixture.cases).flatMap((entry) => entry.deliveries);
    const provenanceChecks = allDeliveries.map((entry) => verifyFixtureProvenance(entry.provenance, fixture.keys.public_jwk));
    cases.push(caseResult('TRUEALTER-PROVENANCE-SIGNATURES', 'prerequisite', provenanceChecks.every((entry) => entry.valid), 'every supplied compact JWS verifies under the pinned synthetic P-256 key and proposed aud/exp/jti profile', { deliveries: provenanceChecks.length, valid: provenanceChecks.filter((entry) => entry.valid).length }));
    const actionCanonical = canonical(fixture.action.A);
    const actionDigest = digest(fixture.action.A);
    const baseCaid = caidFor(fixture.action.A);
    const definitionFileDigest = sha256(ACTION_DEFINITION_BYTES);
    const fixtureFileDigest = sha256(loaded.bytes);
    cases.push(caseResult('ACTION-DIGEST-AND-CAID', 'prerequisite', actionCanonical === fixture.action.A_canonical
        && actionDigest === fixture.action.A_digest
        && actionDigest === CAID_PIN.fixture_action_jcs_sha256
        && fixtureFileDigest === CAID_PIN.fixture_file_sha256
        && ACTION_TYPE === CAID_PIN.action_type
        && definitionFileDigest === CAID_PIN.definition_file_sha256
        && baseCaid.caid === CAID_PIN.expected_caid
        && baseCaid.digest === CAID_PIN.expected_caid_digest, 'the collaborator JCS digest reproduces exactly and the separately pinned local definition computes the expected typed CAID without treating either identifier as authority', {
        fixture_digest: actionDigest,
        fixture_file_sha256: fixtureFileDigest,
        action_type: ACTION_TYPE,
        definition_file_sha256: definitionFileDigest,
        caid: baseCaid.caid,
        caid_digest: baseCaid.digest,
        collaborator_confirmation: CAID_PIN.collaborator_confirmation,
    }));
    const authority = (label) => ({ authority_id: `authority:${label}`, action_caid: baseCaid.caid });
    const j0Domain = new AdmissionDomain('domain:j0');
    const j0 = await executeDelivery({
        fixture,
        domain: j0Domain,
        delivery: fixture.cases.J0_THROUGH.deliveries[0],
        authority: authority('j0'),
        operationId: 'operation:j0',
    });
    cases.push(caseResult('J0-THROUGH', 'positive', j0.state === 'EXECUTED' && j0.provider_entries === 1 && j0.provider_outcome === 'COMMITTED', 'one reservation, one provider entry, provider commitment recorded separately from physical effect', j0));
    const j1Domain = new AdmissionDomain('domain:j1');
    const j1 = await executeDelivery({
        fixture,
        domain: j1Domain,
        delivery: fixture.cases.J1_IDENTITY_ONLY.deliveries[0],
        authority: null,
        operationId: 'operation:j1',
    });
    cases.push(caseResult('J1-IDENTITY-ONLY', 'hostile', j1.state === 'REFUSED' && j1.reason === 'missing_authority' && j1.provider_entries === 0, 'valid provenance never substitutes for authority and is refused before provider entry', j1));
    const j2Domain = new AdmissionDomain('domain:j2');
    const j2Authority = authority('j2');
    const j2Results = await Promise.all(fixture.cases.J2_CONCURRENT_DUPLICATE.deliveries.map((delivery, index) => executeDelivery({
        fixture,
        domain: j2Domain,
        delivery,
        authority: j2Authority,
        operationId: `operation:j2:${index + 1}`,
    })));
    cases.push(caseResult('J2-CONCURRENT-DUPLICATE', 'hostile', j2Results.filter((entry) => entry.state === 'EXECUTED').length === 1
        && j2Results.filter((entry) => entry.state === 'REFUSED').length === 1
        && j2Domain.entries() === 1, 'one atomic reservation wins across two sessions and the MBAP transaction identifier does not create fresh authority', { states: j2Results.map((entry) => entry.state), reasons: j2Results.map((entry) => entry.reason ?? null), provider_entries: j2Domain.entries() }));
    const j3Domain = new AdmissionDomain('domain:j3');
    const j3Authority = authority('j3');
    const [j3First, j3Redelivery, j3FreshWorker] = [
        await executeDelivery({ fixture, domain: j3Domain, delivery: fixture.cases.J3_LOST_RESPONSE_RESTART.deliveries[0], authority: j3Authority, operationId: 'operation:j3', loseResponse: true }),
        await executeDelivery({ fixture, domain: j3Domain, delivery: fixture.cases.J3_LOST_RESPONSE_RESTART.deliveries[1], authority: j3Authority, operationId: 'operation:j3:redelivery' }),
        await executeDelivery({ fixture, domain: j3Domain, delivery: fixture.cases.J3_LOST_RESPONSE_RESTART.deliveries[2], authority: j3Authority, operationId: 'operation:j3:fresh-worker' }),
    ];
    const reconciled = j3Domain.reconcile('operation:j3', {
        authenticated: true,
        action_caid: baseCaid.caid,
        provider_idempotency_key: providerKey(j3Authority.authority_id, baseCaid.caid),
        provider_outcome: 'COMMITTED',
        effect_relation: 'NOT_MEASURED',
    });
    cases.push(caseResult('J3-LOST-RESPONSE-RESTART', 'boundary', j3First.state === 'INDETERMINATE'
        && j3Redelivery.state === 'REFUSED'
        && j3FreshWorker.state === 'REFUSED'
        && reconciled
        && j3Domain.entries() === 1, 'lost response remains indeterminate, restarted deliveries do not redispatch, and authenticated reconciliation terminalizes the original attempt', {
        first: j3First.state,
        redelivery: j3Redelivery.reason,
        fresh_worker: j3FreshWorker.reason,
        reconciled,
        provider_entries: j3Domain.entries(),
    }));
    const j4Domain = new AdmissionDomain('domain:j4');
    const j4Authority = authority('j4');
    const j4Results = [];
    for (const [index, delivery] of fixture.cases.J4_ACTION_MUTATION.deliveries.entries()) {
        j4Results.push(await executeDelivery({
            fixture,
            domain: j4Domain,
            delivery,
            authority: j4Authority,
            operationId: `operation:j4:${index + 1}`,
        }));
    }
    const mutable = structuredClone(fixture.action.A);
    const frozen = deepFreeze(structuredClone(mutable));
    const frozenBefore = canonical(frozen);
    await Promise.resolve();
    mutable.values[1] = 501;
    const frozenAfter = canonical(frozen);
    cases.push(caseResult('J4-ACTION-MUTATION', 'hostile', j4Results.every((entry) => entry.state === 'REFUSED' && entry.reason === 'exact_action_binding_mismatch')
        && j4Domain.entries() === 0
        && frozenBefore === frozenAfter, 'native value or target mutation is refused before provider entry and an awaited mutation cannot alter frozen action bytes', { reasons: j4Results.map((entry) => entry.reason), provider_entries: j4Domain.entries(), frozen_bytes_unchanged: frozenBefore === frozenAfter }));
    const firstConduitResults = {};
    for (const [name, input] of Object.entries(fixture.first_conduit_refusals)) {
        if (name === 'note')
            continue;
        try {
            if (typeof input === 'string')
                decodeFc10Adu(input);
            else
                decodeFc10Adu(input.adu_hex, { device_context_unit: input.device_context_unit });
            firstConduitResults[name] = 'accepted';
        }
        catch (error) {
            firstConduitResults[name] = error.message;
        }
    }
    cases.push(caseResult('FIRST-CONDUIT-REFUSALS', 'hostile', Object.values(firstConduitResults).every((entry) => entry !== 'accepted'), 'all five malformed or context-mismatched FC10 inputs refuse before evidence lookup or reservation', firstConduitResults));
    const base = {
        '@version': REPORT_VERSION,
        profile: PROFILE,
        fixture: {
            id: fixture.fixture,
            sha256: fixtureFileDigest,
            bytes: loaded.bytes.length,
            status: fixture.status,
        },
        cases,
        passed: cases.every((entry) => entry.passed),
        coverage: {
            executed: ['J0', 'J1', 'J2', 'J3', 'J4'],
            not_executed: ['J5_SAFETY_INDEPENDENCE'],
        },
        composition: {
            provenance: 'collaborator-supplied synthetic ES256 invocation JWS',
            exact_action: `interoperability-local typed CAID ${ACTION_TYPE} under a separately hashed definition plus first-conduit FC10 projection`,
            authority: 'separate synthetic EMILIA authority input',
            admission: 'single-process in-memory one-time authority and provider-attempt domain',
            provider: 'synthetic FC10 provider-entry state; no live device',
        },
        known_limits: [
            'The fixture and authority are synthetic; no production key, live TrueAlter service, PLC, RTU, or protocol stack was exercised.',
            'The admission domain is an in-memory single-process conformance model, not evidence of multi-process durable atomicity.',
            'The fixture aud, exp, and jti claims are synthetic inputs. Blake Morrison reports them as implemented in @truealter/sdk 0.5.15, but that package was not available from the public npm registry during this run and remains unverified here.',
            'The fixture action digest is a provisional bare JCS SHA-256. The runner computes the separately hashed, jointly confirmed interoperability-local typed CAID and never treats either identifier as authority.',
            'Provider commitment and observed physical effect remain separate; no physical effect is claimed.',
            'J5 safety independence remains unexecuted because it requires a protective-path simulator outside the Gate.',
        ],
    };
    return { ...base, results_digest: `sha256:${digest(base)}` };
}
export async function runProfile(runner = {
    name: 'EMILIA reference runner',
    affiliation: 'EMILIA Protocol',
    revision: 'worker-gate-ot-v0.1',
    executed_at: '2026-09-24T06:30:00.000Z',
}) {
    return { ...(await buildReferenceReport()), runner };
}
function argument(name) {
    const index = process.argv.indexOf(name);
    return index >= 0 ? process.argv[index + 1] : undefined;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    const report = await runProfile();
    const writePath = argument('--write');
    if (writePath)
        writeFileSync(resolve(writePath), `${JSON.stringify(report, null, 2)}\n`);
    if (process.argv.includes('--reference')) {
        writeFileSync(REFERENCE_PATH, `${JSON.stringify(await buildReferenceReport(), null, 2)}\n`);
    }
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    if (!report.passed)
        process.exitCode = 1;
}
