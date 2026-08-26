// SPDX-License-Identifier: Apache-2.0
// Generated from generate-vectors.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/** Generate deterministic OT command-binding interoperability vectors. */
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { TRANSPORT_PROFILES, commandDigest, dnp3ControlRelayAction, encodeDnp3ControlRelay, encodeModbusWriteMultipleRegisters, encodeModbusWriteRegister, encodeOpcuaCall, modbusWriteMultipleRegistersAction, } from './commands.mjs';
import { EXACT_COMMANDS } from './scenario.mjs';
export const OT_COMMAND_BINDING_VECTOR_PROFILE = 'EP-OT-COMMAND-BINDING-VECTORS-v1';
const INLINE_REFERENCE = Object.freeze({
    '@type': 'EP-OT-AUTHORIZATION-REFERENCE-v0',
    artifact_digest: `sha256:${'0'.repeat(64)}`,
    note: 'Illustrative carriage reference only; not a valid authorization receipt.',
});
function mutation(action, field, value) {
    const changed = { ...structuredClone(action), [field]: value };
    return {
        field,
        value,
        expected: 'different-action-digest',
        action_digest: commandDigest(changed),
    };
}
export function buildOtCommandBindingVectors() {
    const modbus = EXACT_COMMANDS['modbus-tcp'];
    const dnp3 = EXACT_COMMANDS.dnp3;
    const opcua = EXACT_COMMANDS['opc-ua'];
    const modbusTx1 = encodeModbusWriteRegister(modbus, { transactionId: 1 });
    const modbusTx4242 = encodeModbusWriteRegister(modbus, { transactionId: 4242 });
    const modbusFc16QuantityOne = modbusWriteMultipleRegistersAction({
        site: modbus.site,
        device: modbus.device,
        unitId: modbus.unit_id,
        protocolAddress: modbus.protocol_address,
        values: [modbus.value],
    });
    const modbusFc16OrderedPair = modbusWriteMultipleRegistersAction({
        site: modbus.site,
        device: modbus.device,
        unitId: modbus.unit_id,
        protocolAddress: 0x0010,
        values: [0x1234, 0xabcd],
    });
    const modbusFc16ReversedPair = modbusWriteMultipleRegistersAction({
        site: modbus.site,
        device: modbus.device,
        unitId: modbus.unit_id,
        protocolAddress: 0x0010,
        values: [0xabcd, 0x1234],
    });
    const dnp3NoAck = dnp3ControlRelayAction({
        site: dnp3.site,
        device: dnp3.device,
        outstationAddress: dnp3.outstation_address,
        index: dnp3.index,
        applicationFunction: 6,
        controlOctet: dnp3.control_octet,
        operationCount: dnp3.operation_count,
        onTimeMs: dnp3.on_time_ms,
        offTimeMs: dnp3.off_time_ms,
    });
    const dnp3Sequence0 = encodeDnp3ControlRelay(dnp3, { sequence: 0 });
    const dnp3Sequence9 = encodeDnp3ControlRelay(dnp3, { sequence: 9 });
    const modbusFc16QuantityOneWire = encodeModbusWriteMultipleRegisters(modbusFc16QuantityOne, { transactionId: 1 });
    const modbusFc16OrderedPairWire = encodeModbusWriteMultipleRegisters(modbusFc16OrderedPair, { transactionId: 9 });
    const encodedOpcua = encodeOpcuaCall(opcua, { receipt: INLINE_REFERENCE });
    return {
        '@type': OT_COMMAND_BINDING_VECTOR_PROFILE,
        profile_status: 'experimental',
        source: {
            example: 'examples/ot-command-binding-v1',
            companion_merge_commit: '0b74b025533bc563e99ee39c5dce8513ad7d789f',
            dnp3_control_octet_source: {
                repository: 'https://github.com/stepfunc/dnp3',
                commit: '562071e42b2ce1408e0930414f14afa181f444af',
                files: [
                    'dnp3/src/app/control_types.rs',
                    'dnp3/src/app/control_enums.rs',
                ],
            },
            note: 'Synthetic protocol models; no live PLC, RTU, DCS, or certified stack.',
        },
        invariants: [
            'derive the observed action from decoded native bytes and enforcement-point-owned link context',
            'compare the observed action digest with the authorized action before forwarding',
            'consume one authorization at most once',
            'after dispatch without a proved outcome, report INDETERMINATE and do not retry blindly',
        ],
        detached_evidence: {
            lookup: 'attempt reference plus exact-action digest',
            request_instance_binding: 'authenticated-conduit-context-plus-attempt-reference',
            digest_is_secret: false,
            repeated_action_rule: 'two authorizations for the same action use distinct attempt references',
            failure_domain: 'attempt holder and authoritative consumption record are conduit-owned',
            cross_transport_equivalence: 'not-claimed',
            profile_locality: 'Each binding is evaluated only under its pinned transport encoding profile and request-instance mechanism.',
        },
        freshness: {
            clock: 'conduit-owned',
            rule: 'the conduit evaluates the authorization validity window immediately before admission',
            short_window_is_not_reconciliation: true,
        },
        vectors: [
            {
                id: 'modbus-write-single-register-v1',
                transport_profile: TRANSPORT_PROFILES['modbus-tcp'],
                action: modbus,
                action_digest: commandDigest(modbus),
                native_command: modbusTx1,
                display_metadata: {
                    register_label: '40001',
                    note: 'Convention-dependent operator display only; excluded from the action digest.',
                },
                correlation_variant: {
                    native_command: modbusTx4242,
                    expected_action_digest: commandDigest(modbus),
                    note: 'Changing only the MBAP transaction id does not change the physical act.',
                },
                field_census: {
                    material: ['unit_id', 'function_code', 'protocol_address', 'value'],
                    conduit_context: ['site', 'device'],
                    correlation_only: ['mbap.transaction_id'],
                    fixed_or_derived: ['mbap.protocol_id=0', 'mbap.length=6'],
                },
                encoding_scope: {
                    fc06_and_fc16_quantity_one_are_distinct: true,
                    fc16_quantity_one: {
                        action: modbusFc16QuantityOne,
                        action_digest: commandDigest(modbusFc16QuantityOne),
                        native_command: modbusFc16QuantityOneWire,
                    },
                    fc16_ordered_pair: {
                        action: modbusFc16OrderedPair,
                        action_digest: commandDigest(modbusFc16OrderedPair),
                        native_command: modbusFc16OrderedPairWire,
                        reversed_values_action_digest: commandDigest(modbusFc16ReversedPair),
                        scalar_semantics: 'not-inferred',
                        device_word_order: 'site-profile-required',
                        note: 'Bytes and digest bind register order exactly; device word order and scalar meaning remain site-profile facts.',
                    },
                    note: 'The profile binds native encoding and does not normalize FC 0x06 into FC 0x10 quantity one.',
                },
                negative_cases: [
                    mutation(modbus, 'protocol_address', 1),
                    mutation(modbus, 'value', 0),
                    mutation(modbus, 'unit_id', 4),
                ],
            },
            {
                id: 'dnp3-direct-operate-crob-v1',
                transport_profile: TRANSPORT_PROFILES.dnp3,
                action: dnp3,
                action_digest: commandDigest(dnp3),
                native_command: dnp3Sequence0,
                link_context: {
                    fields: ['site', 'device', 'outstation_address'],
                    note: 'The pinned bytes begin at the application header; the conduit establishes the link-layer outstation address.',
                },
                field_census: {
                    material: [
                        'application_function', 'group', 'variation', 'index', 'control_octet',
                        'operation_count', 'on_time_ms', 'off_time_ms',
                    ],
                    conduit_context: ['site', 'device', 'outstation_address'],
                    correlation_only: ['application_control.sequence'],
                    fixed_or_derived: [
                        'application_control.FIR=1', 'application_control.FIN=1',
                        'application_control.CON=0', 'application_control.UNS=0',
                        'qualifier=0x17', 'object_count=1', 'status=0',
                    ],
                },
                correlation_variant: {
                    native_command: dnp3Sequence9,
                    expected_action_digest: commandDigest(dnp3),
                    note: 'Changing only the DNP3 application sequence changes the fragment bytes, not the physical act.',
                },
                profile_scope: {
                    direct_operate_supported: true,
                    direct_operate_no_ack_supported: true,
                    select_operate_supported: false,
                    select_operate_requirement: 'A future profile must bind SELECT and OPERATE to one authorization and enforce the arm timer in one state machine.',
                },
                no_ack_variant: {
                    action: dnp3NoAck,
                    action_digest: commandDigest(dnp3NoAck),
                    native_command: encodeDnp3ControlRelay(dnp3NoAck),
                    terminal_outcome: 'INDETERMINATE',
                    reason: 'DIRECT_OPERATE_NR supplies no protocol acknowledgement.',
                },
                negative_cases: [
                    mutation(dnp3, 'index', 8),
                    mutation(dnp3, 'control_octet', 0x43),
                    mutation(dnp3, 'on_time_ms', 100),
                    mutation(dnp3, 'off_time_ms', 100),
                    mutation(dnp3, 'application_function', 6),
                    mutation(dnp3, 'outstation_address', 13),
                ],
            },
            {
                id: 'opcua-call-method-v1',
                transport_profile: TRANSPORT_PROFILES['opc-ua'],
                action: opcua,
                action_digest: commandDigest(opcua),
                native_command: encodedOpcua,
                inline_authorization_reference: INLINE_REFERENCE,
                negative_cases: [
                    mutation(opcua, 'object_id', 'ns=2;s=LiftStation.OtherPump'),
                    mutation(opcua, 'method_id', 'ns=2;s=DisableInterlock'),
                    mutation(opcua, 'argument_value', 0),
                ],
            },
        ],
    };
}
function render() {
    return `${JSON.stringify(buildOtCommandBindingVectors(), null, 2)}\n`;
}
const scriptPath = fileURLToPath(import.meta.url);
const vectorPath = resolve(scriptPath, '..', 'vectors.v1.json');
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
    const expected = render();
    if (process.argv.includes('--write')) {
        writeFileSync(vectorPath, expected, 'utf8');
        process.stdout.write(`OT COMMAND BINDING VECTORS: wrote ${vectorPath}\n`);
    }
    else if (process.argv.includes('--check')) {
        const actual = readFileSync(vectorPath, 'utf8');
        if (actual !== expected)
            throw new Error('OT command-binding vectors are stale; run with --write');
        process.stdout.write('OT COMMAND BINDING VECTORS: synchronized\n');
    }
    else {
        process.stdout.write(expected);
    }
}
