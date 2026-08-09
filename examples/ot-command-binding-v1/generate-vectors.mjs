// SPDX-License-Identifier: Apache-2.0
// Generated from generate-vectors.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/** Generate deterministic OT command-binding interoperability vectors. */
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { TRANSPORT_PROFILES, commandDigest, encodeDnp3ControlRelay, encodeModbusWriteRegister, encodeOpcuaCall, } from './commands.mjs';
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
    const encodedOpcua = encodeOpcuaCall(opcua, { receipt: INLINE_REFERENCE });
    return {
        '@type': OT_COMMAND_BINDING_VECTOR_PROFILE,
        profile_status: 'experimental',
        source: {
            example: 'examples/ot-command-binding-v1',
            note: 'Synthetic protocol models; no live PLC, RTU, DCS, or certified stack.',
        },
        invariants: [
            'derive the observed action from decoded native bytes and enforcement-point-owned link context',
            'compare the observed action digest with the authorized action before forwarding',
            'consume one authorization at most once',
            'after dispatch without a proved outcome, report INDETERMINATE and do not retry blindly',
        ],
        vectors: [
            {
                id: 'modbus-write-single-register-v1',
                transport_profile: TRANSPORT_PROFILES['modbus-tcp'],
                action: modbus,
                action_digest: commandDigest(modbus),
                native_command: modbusTx1,
                correlation_variant: {
                    native_command: modbusTx4242,
                    expected_action_digest: commandDigest(modbus),
                    note: 'Changing only the MBAP transaction id does not change the physical act.',
                },
                negative_cases: [
                    mutation(modbus, 'register', 40002),
                    mutation(modbus, 'value', 0),
                    mutation(modbus, 'unit_id', 4),
                ],
            },
            {
                id: 'dnp3-direct-operate-crob-v1',
                transport_profile: TRANSPORT_PROFILES.dnp3,
                action: dnp3,
                action_digest: commandDigest(dnp3),
                native_command: encodeDnp3ControlRelay(dnp3),
                negative_cases: [
                    mutation(dnp3, 'index', 8),
                    mutation(dnp3, 'control_code', 'LATCH_OFF'),
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
