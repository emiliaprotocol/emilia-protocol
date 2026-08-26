// SPDX-License-Identifier: Apache-2.0
// Generated from vectors.test.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { commandDigest, decodeDnp3ControlRelay, decodeModbusWriteMultipleRegisters, decodeModbusWriteRegister, decodeOpcuaCall, extractOpcuaAuthorization, } from './commands.mjs';
import { buildOtCommandBindingVectors } from './generate-vectors.mjs';
const vectorPath = fileURLToPath(new URL('./vectors.v1.json', import.meta.url));
const pinned = JSON.parse(readFileSync(vectorPath, 'utf8'));
test('the checked-in OT vectors are byte-synchronized with their generator', () => {
    assert.deepEqual(pinned, buildOtCommandBindingVectors());
});
test('every pinned native command decodes to the action whose digest is published', () => {
    const byId = Object.fromEntries(pinned.vectors.map((vector) => [vector.id, vector]));
    const modbus = byId['modbus-write-single-register-v1'];
    const dnp3 = byId['dnp3-direct-operate-crob-v1'];
    const opcua = byId['opcua-call-method-v1'];
    const modbusObserved = decodeModbusWriteRegister(modbus.native_command.hex, {
        site: modbus.action.site,
        device: modbus.action.device,
        unit_id: modbus.action.unit_id,
    });
    const dnp3Observed = decodeDnp3ControlRelay(dnp3.native_command.hex, {
        site: dnp3.action.site,
        device: dnp3.action.device,
        outstation_address: dnp3.action.outstation_address,
    });
    const opcuaObserved = decodeOpcuaCall(opcua.native_command.request, {
        site: opcua.action.site,
        device: opcua.action.device,
    });
    for (const [vector, observed] of [[modbus, modbusObserved], [dnp3, dnp3Observed], [opcua, opcuaObserved]]) {
        assert.deepEqual(observed, vector.action);
        assert.equal(commandDigest(observed), vector.action_digest);
    }
});
test('every one-field negative case has a different action digest', () => {
    for (const vector of pinned.vectors) {
        for (const negative of vector.negative_cases) {
            assert.notEqual(negative.action_digest, vector.action_digest, `${vector.id}:${negative.field}`);
        }
    }
});
test('Modbus correlation changes native bytes without changing the action', () => {
    const vector = pinned.vectors.find((candidate) => candidate.id === 'modbus-write-single-register-v1');
    assert.notEqual(vector.native_command.hex, vector.correlation_variant.native_command.hex);
    const link = { site: vector.action.site, device: vector.action.device, unit_id: vector.action.unit_id };
    assert.equal(commandDigest(decodeModbusWriteRegister(vector.native_command.hex, link)), vector.action_digest);
    assert.equal(commandDigest(decodeModbusWriteRegister(vector.correlation_variant.native_command.hex, link)), vector.action_digest);
});
test('the pinned Modbus FC 0x10 quantity-one command decodes under its native encoding profile', () => {
    const vector = pinned.vectors.find((candidate) => candidate.id === 'modbus-write-single-register-v1');
    const fc16 = vector.encoding_scope.fc16_quantity_one;
    const observed = decodeModbusWriteMultipleRegisters(fc16.native_command.hex, {
        site: fc16.action.site,
        device: fc16.action.device,
        unit_id: fc16.action.unit_id,
    });
    assert.deepEqual(observed, fc16.action);
    assert.equal(commandDigest(observed), fc16.action_digest);
    assert.notEqual(fc16.action_digest, vector.action_digest);
});
test('the pinned wide FC 0x10 vector binds register order without claiming scalar meaning', () => {
    const vector = pinned.vectors.find((candidate) => candidate.id === 'modbus-write-single-register-v1');
    const ordered = vector.encoding_scope.fc16_ordered_pair;
    assert.deepEqual(ordered.action.values, [0x1234, 0xabcd]);
    assert.equal(ordered.native_command.hex, '00090000000b031000100002041234abcd');
    assert.equal(ordered.scalar_semantics, 'not-inferred');
    assert.equal(ordered.device_word_order, 'site-profile-required');
    assert.notEqual(ordered.action_digest, ordered.reversed_values_action_digest);
    const observed = decodeModbusWriteMultipleRegisters(ordered.native_command.hex, {
        site: ordered.action.site,
        device: ordered.action.device,
        unit_id: ordered.action.unit_id,
    });
    assert.deepEqual(observed, ordered.action);
    assert.equal(commandDigest(observed), ordered.action_digest);
});
test('the profile pins its companion merge and DNP3 control-octet source', () => {
    assert.equal(pinned.source.companion_merge_commit, '0b74b025533bc563e99ee39c5dce8513ad7d789f');
    assert.equal(pinned.source.dnp3_control_octet_source.commit, '562071e42b2ce1408e0930414f14afa181f444af');
});
test('DNP3 application sequence changes native bytes without changing the action', () => {
    const vector = pinned.vectors.find((candidate) => candidate.id === 'dnp3-direct-operate-crob-v1');
    assert.notEqual(vector.native_command.hex, vector.correlation_variant.native_command.hex);
    const link = {
        site: vector.action.site,
        device: vector.action.device,
        outstation_address: vector.action.outstation_address,
    };
    assert.equal(commandDigest(decodeDnp3ControlRelay(vector.native_command.hex, link)), vector.action_digest);
    assert.equal(commandDigest(decodeDnp3ControlRelay(vector.correlation_variant.native_command.hex, link)), vector.action_digest);
});
test('the pinned profiles state their normalization and request-instance boundaries', () => {
    const modbus = pinned.vectors.find((candidate) => candidate.id === 'modbus-write-single-register-v1');
    const dnp3 = pinned.vectors.find((candidate) => candidate.id === 'dnp3-direct-operate-crob-v1');
    assert.equal(modbus.action.protocol_address, 0);
    assert.equal(Object.hasOwn(modbus.action, 'register'), false);
    assert.equal(modbus.encoding_scope.fc06_and_fc16_quantity_one_are_distinct, true);
    assert.equal(modbus.transport_profile.encoding_profile.scope, 'native-encoding');
    assert.equal(dnp3.action.application_function, 5);
    assert.equal(dnp3.action.control_octet, 3);
    assert.equal(dnp3.action.operation_count, 1);
    assert.equal(dnp3.action.on_time_ms, 0);
    assert.equal(dnp3.action.off_time_ms, 0);
    assert.equal(dnp3.profile_scope.select_operate_supported, false);
    assert.equal(dnp3.transport_profile.encoding_profile.scope, 'native-encoding');
    assert.deepEqual(dnp3.transport_profile.encoding_profile.object_header, {
        qualifier: 0x17,
        object_count: 1,
        index_octets: 1,
        index_min: 0,
        index_max: 0xff,
    });
    assert.deepEqual(dnp3.transport_profile.encoding_profile.application_control_flags, {
        FIR: 1,
        FIN: 1,
        CON: 0,
        UNS: 0,
    });
    assert.equal(dnp3.transport_profile.encoding_profile.request_status, 0);
    assert.equal(pinned.detached_evidence.request_instance_binding, 'authenticated-conduit-context-plus-attempt-reference');
    assert.equal(pinned.detached_evidence.digest_is_secret, false);
    assert.equal(pinned.freshness.clock, 'conduit-owned');
});
test('the pinned vectors make no cross-transport equivalence claim', () => {
    assert.equal(pinned.detached_evidence.cross_transport_equivalence, 'not-claimed');
    assert.equal(Object.hasOwn(pinned.detached_evidence, 'equivalence_boundary'), false);
});
test('the OPC-UA vector demonstrates carriage but never pretends its reference is authorization', () => {
    const vector = pinned.vectors.find((candidate) => candidate.id === 'opcua-call-method-v1');
    assert.deepEqual(extractOpcuaAuthorization(vector.native_command.request), vector.inline_authorization_reference);
    assert.match(vector.inline_authorization_reference.note, /not a valid authorization receipt/);
});
