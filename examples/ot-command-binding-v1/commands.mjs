// SPDX-License-Identifier: Apache-2.0
// Generated from commands.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * OT command binding — canonical actions, wire encoders, and wire decoders for
 * three industrial control transports with very different envelope capacity.
 *
 * The whole example turns on one asymmetry. OPC-UA request structures have an
 * extension slot, so an authorization can ride inline with the call. A Modbus
 * write is a unit id, a function code, a register address, and a value; the
 * frame length is fixed by the function code and there is no optional field.
 * A DNP3 control relay output block is a fixed-width object in a typed object
 * space. For those two the authorization CANNOT travel with the command, so it
 * is held out of band and keyed to a canonical digest of the exact command.
 *
 * The digest is therefore the join. It has to be recomputable from what
 * actually reached the wire, not from a requester-supplied description of it,
 * which is why every transport here has a decoder: the enforcement point sits
 * in front of the device, decodes the frame it is about to forward, and derives
 * the observed action from those bytes plus the link facts it owns because it
 * terminates the connection. That observed action -- never the requester's
 * description -- is what the gate binds.
 *
 * The encoders are minimal models written for this example. They are not a
 * certified protocol stack, and the byte-level claims below are claims about
 * the frames THIS FILE produces.
 */
import { hashCanonical } from '../../packages/gate/index.js';
export const OT_COMMAND_BINDING_VERSION = 'EP-OT-COMMAND-BINDING-v1';
/**
 * What each transport can and cannot carry, and the binding mode that follows
 * from it. `metadata_octets_available` is the count this example's encoder
 * leaves free for anything that is not a protocol-defined field.
 */
export const TRANSPORT_PROFILES = Object.freeze({
    'opc-ua': Object.freeze({
        transport: 'opc-ua',
        envelope_capacity: 'extensible',
        carries_authorization_inline: true,
        binding_mode: 'inline',
        extension_point: 'request-header extension object (modeled here as a JSON member)',
        metadata_octets_available: null,
        why: 'The request structure has an extension slot, so an authorization can ride with the call.',
    }),
    'modbus-tcp': Object.freeze({
        transport: 'modbus-tcp',
        envelope_capacity: 'none',
        carries_authorization_inline: false,
        binding_mode: 'out-of-band-digest',
        extension_point: null,
        metadata_octets_available: 0,
        why: 'A write is unit id, function code, register address, and value. Length is fixed by the function code; nothing else fits on the wire.',
    }),
    dnp3: Object.freeze({
        transport: 'dnp3',
        envelope_capacity: 'fixed-object-space',
        carries_authorization_inline: false,
        binding_mode: 'out-of-band-digest',
        extension_point: null,
        metadata_octets_available: 0,
        why: 'A control relay output block is a fixed-width object in a typed object space. No octet of the fragment is free for an envelope.',
    }),
});
// ---------------------------------------------------------------------------
// Canonical actions
// ---------------------------------------------------------------------------
/**
 * The canonical digest of an exact command. This is `hashCanonical` from
 * @emilia-protocol/gate -- the same function the gate uses to record
 * `observed_action_hash` -- so an out-of-band index keyed by this digest is
 * keyed by exactly what the gate authorizes.
 */
export function commandDigestHex(action) {
    return hashCanonical(action);
}
/** Display form of the same digest. */
export function commandDigest(action) {
    return `sha256:${commandDigestHex(action)}`;
}
function requireSafeInt(value, name, min, max) {
    if (!Number.isSafeInteger(value) || value < min || value > max) {
        throw new TypeError(`${name} must be an integer in [${min}, ${max}]`);
    }
    return value;
}
function requireString(value, name) {
    if (typeof value !== 'string' || value.length === 0) {
        throw new TypeError(`${name} must be a non-empty string`);
    }
    return value;
}
/**
 * A Modbus FC 0x06 write to one holding-register protocol address.
 *
 * The digest binds the zero-based address carried on the wire. A site's
 * operator-facing 4xxxxx label is convention-dependent display metadata and
 * must not be substituted for the protocol address in the signed action.
 */
export function modbusWriteRegisterAction({ site, device, unitId, protocolAddress, value, }) {
    return Object.freeze({
        action_type: 'ot.modbus.write_single_register',
        transport: 'modbus-tcp',
        site: requireString(site, 'site'),
        device: requireString(device, 'device'),
        unit_id: requireSafeInt(unitId, 'unitId', 0, 247),
        function_code: 0x06,
        protocol_address: requireSafeInt(protocolAddress, 'protocolAddress', 0, 0xffff),
        value: requireSafeInt(value, 'value', 0, 0xffff),
    });
}
/**
 * A Modbus FC 0x10 write-multiple-registers action.
 *
 * This is modeled so the profile can state its normalization choice: FC 0x06
 * and FC 0x10 with quantity one can produce the same register effect, but this
 * profile treats the native encodings as distinct authorities.
 */
export function modbusWriteMultipleRegistersAction({ site, device, unitId, protocolAddress, values, }) {
    if (!Array.isArray(values) || values.length < 1 || values.length > 123) {
        throw new TypeError('values must contain between 1 and 123 register values');
    }
    const normalizedValues = Object.freeze(values.map((value, index) => requireSafeInt(value, `values[${index}]`, 0, 0xffff)));
    return Object.freeze({
        action_type: 'ot.modbus.write_multiple_registers',
        transport: 'modbus-tcp',
        site: requireString(site, 'site'),
        device: requireString(device, 'device'),
        unit_id: requireSafeInt(unitId, 'unitId', 0, 247),
        function_code: 0x10,
        protocol_address: requireSafeInt(protocolAddress, 'protocolAddress', 0, 0xffff),
        quantity: normalizedValues.length,
        byte_count: normalizedValues.length * 2,
        values: normalizedValues,
    });
}
/** A DNP3 direct-operate CROB (group 12, variation 1). */
export function dnp3ControlRelayAction({ site, device, outstationAddress, index, applicationFunction, controlOctet, operationCount = 1, onTimeMs = 0, offTimeMs = 0, }) {
    if (applicationFunction !== DNP3_FC_DIRECT_OPERATE
        && applicationFunction !== DNP3_FC_DIRECT_OPERATE_NO_ACK) {
        throw new TypeError('this profile supports DNP3 DIRECT_OPERATE (5) and DIRECT_OPERATE_NR (6) only');
    }
    return Object.freeze({
        action_type: 'ot.dnp3.control_relay_output_block',
        transport: 'dnp3',
        site: requireString(site, 'site'),
        device: requireString(device, 'device'),
        outstation_address: requireSafeInt(outstationAddress, 'outstationAddress', 0, 65519),
        application_function: applicationFunction,
        group: 12,
        variation: 1,
        index: requireSafeInt(index, 'index', 0, 0xff),
        control_octet: requireSafeInt(controlOctet, 'controlOctet', 0, 0xff),
        operation_count: requireSafeInt(operationCount, 'operationCount', 1, 0xff),
        on_time_ms: requireSafeInt(onTimeMs, 'onTimeMs', 0, 0xffffffff),
        off_time_ms: requireSafeInt(offTimeMs, 'offTimeMs', 0, 0xffffffff),
    });
}
/** An OPC-UA method call on one object node. */
export function opcuaCallMethodAction({ site, device, objectId, methodId, argumentName, argumentValue, }) {
    return Object.freeze({
        action_type: 'ot.opcua.call_method',
        transport: 'opc-ua',
        site: requireString(site, 'site'),
        device: requireString(device, 'device'),
        object_id: requireString(objectId, 'objectId'),
        method_id: requireString(methodId, 'methodId'),
        argument_name: requireString(argumentName, 'argumentName'),
        argument_value: requireSafeInt(argumentValue, 'argumentValue', 0, 0xffff),
    });
}
/**
 * The fields the gate binds, per transport. Every field of the canonical action
 * is material: in OT there is no cosmetic field, because a register address off
 * by one is a different physical action.
 */
export const BOUND_FIELDS = Object.freeze({
    'modbus-tcp': Object.freeze([
        'action_type', 'transport', 'site', 'device', 'unit_id', 'function_code',
        'protocol_address', 'value',
    ]),
    dnp3: Object.freeze([
        'action_type', 'transport', 'site', 'device', 'outstation_address', 'group', 'variation',
        'application_function', 'index', 'control_octet', 'operation_count', 'on_time_ms',
        'off_time_ms',
    ]),
    'opc-ua': Object.freeze([
        'action_type', 'transport', 'site', 'device', 'object_id', 'method_id',
        'argument_name', 'argument_value',
    ]),
});
// ---------------------------------------------------------------------------
// Modbus TCP
// ---------------------------------------------------------------------------
const MODBUS_FC_WRITE_SINGLE_REGISTER = 0x06;
/** Transaction id (2) + protocol id (2) + length (2) + unit id (1). */
const MODBUS_MBAP_OCTETS = 7;
/** Function code (1) + register address (2) + register value (2). */
const MODBUS_FC06_PDU_OCTETS = 5;
const MODBUS_ADU_OCTETS = MODBUS_MBAP_OCTETS + MODBUS_FC06_PDU_OCTETS;
/**
 * Encode the Modbus TCP application data unit for a write-single-register.
 *
 * `transactionId` is a per-request correlation number. It is deliberately NOT
 * part of the canonical action: two frames that differ only in transaction id
 * are the same physical action and must digest identically.
 */
export function encodeModbusWriteRegister(action, { transactionId = 1 } = {}) {
    if (action?.transport !== 'modbus-tcp' || action?.function_code !== MODBUS_FC_WRITE_SINGLE_REGISTER) {
        throw new TypeError('encodeModbusWriteRegister requires a modbus-tcp write-single-register action');
    }
    const protocolAddress = requireSafeInt(action.protocol_address, 'protocolAddress', 0, 0xffff);
    requireSafeInt(transactionId, 'transactionId', 0, 0xffff);
    const frame = Buffer.alloc(MODBUS_ADU_OCTETS);
    frame.writeUInt16BE(transactionId, 0); // MBAP transaction id
    frame.writeUInt16BE(0, 2); // MBAP protocol id
    frame.writeUInt16BE(6, 4); // MBAP length: unit id + 5-octet PDU
    frame.writeUInt8(action.unit_id, 6); // MBAP unit id
    frame.writeUInt8(MODBUS_FC_WRITE_SINGLE_REGISTER, 7);
    frame.writeUInt16BE(protocolAddress, 8);
    frame.writeUInt16BE(action.value, 10);
    return Object.freeze({
        transport: 'modbus-tcp',
        hex: frame.toString('hex'),
        octets: frame.length,
        protocol_address: protocolAddress,
        // Derived, not asserted: the whole frame minus the MBAP header minus the
        // function code's own fixed PDU. Zero means there is nothing left on the
        // wire an authorization envelope could occupy.
        metadata_octets_available: frame.length - MODBUS_MBAP_OCTETS - MODBUS_FC06_PDU_OCTETS,
        carries_authorization: false,
    });
}
/**
 * Decode a Modbus TCP write-single-register frame back into the canonical
 * action, using the link facts the enforcement point owns.
 */
export function decodeModbusWriteRegister(hex, link) {
    const frame = Buffer.from(requireString(hex, 'hex'), 'hex');
    if (frame.length !== MODBUS_ADU_OCTETS)
        throw new TypeError('unexpected Modbus ADU length');
    if (frame.readUInt16BE(2) !== 0)
        throw new TypeError('unexpected Modbus protocol id');
    if (frame.readUInt16BE(4) !== 6)
        throw new TypeError('unexpected Modbus length field');
    if (frame.readUInt8(7) !== MODBUS_FC_WRITE_SINGLE_REGISTER) {
        throw new TypeError('unexpected Modbus function code');
    }
    const unitId = frame.readUInt8(6);
    if (link?.unit_id !== undefined && unitId !== link.unit_id) {
        throw new TypeError('Modbus unit id does not match conduit device context');
    }
    return modbusWriteRegisterAction({
        site: link?.site,
        device: link?.device,
        unitId,
        protocolAddress: frame.readUInt16BE(8),
        value: frame.readUInt16BE(10),
    });
}
// ---------------------------------------------------------------------------
// DNP3
// ---------------------------------------------------------------------------
/** Human-readable labels for common complete CROB control-field octets. */
export const DNP3_CONTROL_CODES = Object.freeze({
    NUL: 0x00,
    PULSE_ON: 0x01,
    PULSE_OFF: 0x02,
    LATCH_ON: 0x03,
    LATCH_OFF: 0x04,
});
const DNP3_FC_DIRECT_OPERATE = 0x05;
const DNP3_FC_DIRECT_OPERATE_NO_ACK = 0x06;
/** Application control (1) + function code (1). */
const DNP3_APPLICATION_HEADER_OCTETS = 2;
/** Group (1) + variation (1) + qualifier (1) + count (1) + index (1). */
const DNP3_OBJECT_HEADER_OCTETS = 5;
/** Control code (1) + count (1) + on-time (4) + off-time (4) + status (1). */
const DNP3_CROB_OCTETS = 11;
const DNP3_FRAGMENT_OCTETS = DNP3_APPLICATION_HEADER_OCTETS + DNP3_OBJECT_HEADER_OCTETS + DNP3_CROB_OCTETS;
/**
 * Encode the DNP3 application fragment for a direct-operate of one CROB.
 *
 * The outstation address is a data-link field, not part of this fragment; the
 * enforcement point supplies it from the link it terminates, the same way it
 * supplies site and device.
 */
export function encodeDnp3ControlRelay(action, { sequence = 0 } = {}) {
    if (action?.transport !== 'dnp3' || action?.group !== 12 || action?.variation !== 1) {
        throw new TypeError('encodeDnp3ControlRelay requires a dnp3 group 12 variation 1 action');
    }
    requireSafeInt(sequence, 'sequence', 0, 0x0f);
    const fragment = Buffer.alloc(DNP3_FRAGMENT_OCTETS);
    fragment.writeUInt8(0xc0 | sequence, 0); // FIR | FIN | sequence
    fragment.writeUInt8(action.application_function, 1);
    fragment.writeUInt8(action.group, 2);
    fragment.writeUInt8(action.variation, 3);
    fragment.writeUInt8(0x17, 4); // 1-octet count, 1-octet index prefix
    fragment.writeUInt8(1, 5); // one object follows
    fragment.writeUInt8(action.index, 6);
    fragment.writeUInt8(action.control_octet, 7); // complete CROB control field
    fragment.writeUInt8(action.operation_count, 8);
    fragment.writeUInt32LE(action.on_time_ms, 9);
    fragment.writeUInt32LE(action.off_time_ms, 13);
    fragment.writeUInt8(0, 17); // status
    return Object.freeze({
        transport: 'dnp3',
        hex: fragment.toString('hex'),
        octets: fragment.length,
        crob_octets: DNP3_CROB_OCTETS,
        // Derived: the fragment minus its application header, its object header,
        // and the fixed-width CROB the object header declares.
        metadata_octets_available: fragment.length
            - DNP3_APPLICATION_HEADER_OCTETS - DNP3_OBJECT_HEADER_OCTETS - DNP3_CROB_OCTETS,
        carries_authorization: false,
    });
}
/** Decode a DNP3 direct-operate CROB fragment back into the canonical action. */
export function decodeDnp3ControlRelay(hex, link) {
    const fragment = Buffer.from(requireString(hex, 'hex'), 'hex');
    if (fragment.length !== DNP3_FRAGMENT_OCTETS)
        throw new TypeError('unexpected DNP3 fragment length');
    const applicationFunction = fragment.readUInt8(1);
    if (applicationFunction !== DNP3_FC_DIRECT_OPERATE
        && applicationFunction !== DNP3_FC_DIRECT_OPERATE_NO_ACK) {
        throw new TypeError('unexpected DNP3 function code');
    }
    if (fragment.readUInt8(2) !== 12 || fragment.readUInt8(3) !== 1) {
        throw new TypeError('unexpected DNP3 object group or variation');
    }
    if (fragment.readUInt8(4) !== 0x17 || fragment.readUInt8(5) !== 1) {
        throw new TypeError('unexpected DNP3 qualifier or object count');
    }
    return dnp3ControlRelayAction({
        site: link?.site,
        device: link?.device,
        outstationAddress: link?.outstation_address,
        index: fragment.readUInt8(6),
        applicationFunction,
        controlOctet: fragment.readUInt8(7),
        operationCount: fragment.readUInt8(8),
        onTimeMs: fragment.readUInt32LE(9),
        offTimeMs: fragment.readUInt32LE(13),
    });
}
// ---------------------------------------------------------------------------
// OPC-UA
// ---------------------------------------------------------------------------
/**
 * Build an OPC-UA Call request that carries the authorization inline, in the
 * request header's extension slot.
 *
 * The receipt riding along is a transport convenience and nothing more: the
 * gate still binds it to the action decoded from the call parameters below, so
 * an envelope describing a different command is refused exactly as an
 * out-of-band lookup for a different digest would be.
 */
export function encodeOpcuaCall(action, { receipt = null, requestHandle = 1 } = {}) {
    if (action?.transport !== 'opc-ua')
        throw new TypeError('encodeOpcuaCall requires an opc-ua action');
    const request = {
        service: 'Call',
        request_header: {
            request_handle: requireSafeInt(requestHandle, 'requestHandle', 0, 0xffffffff),
            additional_header: receipt
                ? {
                    type_id: `urn:emilia-protocol:${OT_COMMAND_BINDING_VERSION}`,
                    body: { ep_receipt: receipt },
                }
                : null,
        },
        methods_to_call: [{
                object_id: action.object_id,
                method_id: action.method_id,
                input_arguments: [{ name: action.argument_name, value: action.argument_value }],
            }],
    };
    return Object.freeze({
        transport: 'opc-ua',
        request,
        octets: Buffer.byteLength(JSON.stringify(request), 'utf8'),
        authorization_octets: receipt ? Buffer.byteLength(JSON.stringify(receipt), 'utf8') : 0,
        metadata_octets_available: null,
        carries_authorization: Boolean(receipt),
    });
}
/** Decode an OPC-UA Call request back into the canonical action. */
export function decodeOpcuaCall(request, link) {
    if (request?.service !== 'Call')
        throw new TypeError('unexpected OPC-UA service');
    const call = Array.isArray(request?.methods_to_call) ? request.methods_to_call[0] : null;
    const argument = Array.isArray(call?.input_arguments) ? call.input_arguments[0] : null;
    if (!call || !argument)
        throw new TypeError('malformed OPC-UA Call request');
    return opcuaCallMethodAction({
        site: link?.site,
        device: link?.device,
        objectId: call.object_id,
        methodId: call.method_id,
        argumentName: argument.name,
        argumentValue: argument.value,
    });
}
/** Pull the inline authorization out of an OPC-UA Call request, if it has one. */
export function extractOpcuaAuthorization(request) {
    return request?.request_header?.additional_header?.body?.ep_receipt ?? null;
}
export default {
    OT_COMMAND_BINDING_VERSION,
    TRANSPORT_PROFILES,
    BOUND_FIELDS,
    DNP3_CONTROL_CODES,
    commandDigest,
    commandDigestHex,
    modbusWriteRegisterAction,
    modbusWriteMultipleRegistersAction,
    dnp3ControlRelayAction,
    opcuaCallMethodAction,
    encodeModbusWriteRegister,
    decodeModbusWriteRegister,
    encodeDnp3ControlRelay,
    decodeDnp3ControlRelay,
    encodeOpcuaCall,
    decodeOpcuaCall,
    extractOpcuaAuthorization,
};
