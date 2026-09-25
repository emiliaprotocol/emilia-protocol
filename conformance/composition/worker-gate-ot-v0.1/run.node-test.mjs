// SPDX-License-Identifier: Apache-2.0
// Generated from run.node-test.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildReferenceReport, decodeFc10Adu, PROFILE, runProfile, verifyFixtureProvenance, } from './run.mjs';
const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE = JSON.parse(readFileSync(resolve(HERE, 'fixtures/truealter-fc10.synthetic.v2.json'), 'utf8'));
const CAID_PIN = JSON.parse(readFileSync(resolve(HERE, 'caid-pin.v1.json'), 'utf8'));
test('the joined synthetic fixture passes J0 through J4 under one admission-domain model', async () => {
    const report = await runProfile();
    const reference = JSON.parse(readFileSync(resolve(HERE, 'report.reference.json'), 'utf8'));
    assert.equal(report.profile, PROFILE);
    assert.equal(report.passed, true, JSON.stringify(report, null, 2));
    assert.deepEqual(report.coverage.executed, ['J0', 'J1', 'J2', 'J3', 'J4']);
    assert.deepEqual(await buildReferenceReport(), reference);
    assert.equal(report.results_digest, reference.results_digest);
});
test('identity-only, duplicate, lost-response restart, and mutation paths fail closed', async () => {
    const report = await runProfile();
    const byId = Object.fromEntries(report.cases.map((entry) => [entry.id, entry]));
    for (const id of [
        'J1-IDENTITY-ONLY',
        'J2-CONCURRENT-DUPLICATE',
        'J3-LOST-RESPONSE-RESTART',
        'J4-ACTION-MUTATION',
        'FIRST-CONDUIT-REFUSALS',
    ])
        assert.equal(byId[id].passed, true, id);
    assert.equal(byId['J2-CONCURRENT-DUPLICATE'].observed.provider_entries, 1);
    assert.equal(byId['J3-LOST-RESPONSE-RESTART'].observed.provider_entries, 1);
    assert.equal(byId['J4-ACTION-MUTATION'].observed.provider_entries, 0);
});
test('the fixture JWS rejects a changed audience and a changed signature', () => {
    const provenance = FIXTURE.cases.J0_THROUGH.deliveries[0].provenance;
    assert.equal(verifyFixtureProvenance(provenance, FIXTURE.keys.public_jwk).valid, true);
    assert.equal(verifyFixtureProvenance(provenance, FIXTURE.keys.public_jwk, { audience: 'other-gate' }).reason, 'audience_mismatch');
    const tampered = structuredClone(provenance);
    const parts = tampered.jws.split('.');
    const changedSignature = Buffer.from(parts[2], 'base64url');
    changedSignature[0] ^= 0x01;
    parts[2] = changedSignature.toString('base64url');
    tampered.jws = parts.join('.');
    assert.equal(verifyFixtureProvenance(tampered, FIXTURE.keys.public_jwk).reason, 'invalid_signature');
});
test('MBAP transaction identifiers are correlation-only while invalid FC10 structure refuses', () => {
    const first = decodeFc10Adu(FIXTURE.cases.J2_CONCURRENT_DUPLICATE.deliveries[0].observed_fc10_adu_hex);
    const second = decodeFc10Adu(FIXTURE.cases.J2_CONCURRENT_DUPLICATE.deliveries[1].observed_fc10_adu_hex);
    assert.notEqual(first.transaction_id, second.transaction_id);
    assert.deepEqual(first.action, second.action);
    assert.throws(() => decodeFc10Adu(FIXTURE.first_conduit_refusals.protocol_id_nonzero), /protocol_id_nonzero/);
    assert.throws(() => decodeFc10Adu(FIXTURE.first_conduit_refusals.byte_count_not_twice_quantity), /byte_count_mismatch/);
});
test('the report keeps synthetic execution and safety boundaries explicit', async () => {
    const report = await runProfile();
    assert.deepEqual(report.coverage.not_executed, ['J5_SAFETY_INDEPENDENCE']);
    assert.match(report.known_limits.join(' '), /single-process/i);
    assert.match(report.known_limits.join(' '), /no physical effect is claimed/i);
    assert.match(report.known_limits.join(' '), /0\.5\.15.*unverified/i);
});
test('the jointly confirmed local CAID pin excludes redundant protocol binding', async () => {
    const report = await runProfile();
    const caidCase = report.cases.find((entry) => entry.id === 'ACTION-DIGEST-AND-CAID');
    assert.equal(caidCase.passed, true);
    assert.equal(caidCase.observed.action_type, 'ot.modbus.write-multiple-registers.1');
    assert.equal(caidCase.observed.fixture_file_sha256, CAID_PIN.fixture_file_sha256);
    assert.equal(caidCase.observed.definition_file_sha256, CAID_PIN.definition_file_sha256);
    assert.equal(caidCase.observed.caid, CAID_PIN.expected_caid);
    assert.equal(caidCase.observed.collaborator_confirmation, 'confirmed-by-truealter-2026-09-25');
    assert.equal(Object.hasOwn(FIXTURE.action.A, 'protocol'), false);
});
