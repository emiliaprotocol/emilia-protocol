// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  TRANSPORT_PROFILES,
  commandDigest,
  commandDigestHex,
  decodeDnp3ControlRelay,
  decodeModbusWriteRegister,
  dnp3ControlRelayAction,
  encodeDnp3ControlRelay,
  encodeModbusWriteRegister,
  encodeOpcuaCall,
  extractOpcuaAuthorization,
  modbusWriteMultipleRegistersAction,
  modbusWriteRegisterAction,
} from './commands.mjs';
import * as commandCodecs from './commands.mjs';
import {
  EXACT_COMMANDS,
  createEnforcementPoint,
  createOutOfBandAuthorizationIndex,
  runOtCommandBindingLab,
} from './scenario.mjs';

const LAB = await runOtCommandBindingLab();
const [DERIVATION, AUTHORIZED, DRIFT, UNRESOLVED, SPENT] = LAB.scenes;

const sceneById = (id: string) => LAB.scenes.find((scene: any) => scene.id === id);

// ---------------------------------------------------------------------------
// Transport envelope capacity
// ---------------------------------------------------------------------------

test('only OPC-UA can carry an authorization on the wire', () => {
  assert.equal(TRANSPORT_PROFILES['opc-ua'].carries_authorization_inline, true);
  assert.equal(TRANSPORT_PROFILES['opc-ua'].binding_mode, 'inline');
  for (const transport of ['modbus-tcp', 'dnp3']) {
    assert.equal(TRANSPORT_PROFILES[transport].carries_authorization_inline, false);
    assert.equal(TRANSPORT_PROFILES[transport].binding_mode, 'out-of-band-digest');
    assert.equal(TRANSPORT_PROFILES[transport].metadata_octets_available, 0);
  }
});

test('the Modbus and DNP3 authorities are explicitly native-encoding-profile scoped', () => {
  assert.equal(TRANSPORT_PROFILES['modbus-tcp'].encoding_profile.scope, 'native-encoding');
  assert.equal(TRANSPORT_PROFILES.dnp3.encoding_profile.scope, 'native-encoding');
});

test('the Modbus frame is fully occupied by protocol fields', () => {
  const encoded = encodeModbusWriteRegister(EXACT_COMMANDS['modbus-tcp'], { transactionId: 1 });
  assert.equal(encoded.octets, 12);
  assert.equal(encoded.metadata_octets_available, 0);
  assert.equal(encoded.carries_authorization, false);
  // MBAP length field declares 6 following octets: unit id plus a 5-octet PDU.
  const frame = Buffer.from(encoded.hex, 'hex');
  assert.equal(frame.readUInt16BE(4), 6);
  assert.equal(frame.length, 7 + frame.readUInt16BE(4) - 1);
});

test('the DNP3 fragment is fully occupied by typed object fields', () => {
  const encoded = encodeDnp3ControlRelay(EXACT_COMMANDS.dnp3, { sequence: 0 });
  assert.equal(encoded.octets, 18);
  assert.equal(encoded.crob_octets, 11);
  assert.equal(encoded.metadata_octets_available, 0);
  assert.equal(encoded.carries_authorization, false);
});

test('the OPC-UA request carries the authorization in its extension slot', () => {
  const receipt = { '@version': 'EP-RECEIPT-v1', payload: { receipt_id: 'probe' } };
  const withEnvelope = encodeOpcuaCall(EXACT_COMMANDS['opc-ua'], { receipt });
  const withoutEnvelope = encodeOpcuaCall(EXACT_COMMANDS['opc-ua'], {});
  assert.equal(withEnvelope.carries_authorization, true);
  assert.equal(withoutEnvelope.carries_authorization, false);
  assert.ok(withEnvelope.authorization_octets > 0);
  assert.equal(withoutEnvelope.authorization_octets, 0);
  assert.deepEqual(extractOpcuaAuthorization(withEnvelope.request), receipt);
  assert.equal(extractOpcuaAuthorization(withoutEnvelope.request), null);
});

// ---------------------------------------------------------------------------
// Scene 1 — canonical action derivation
// ---------------------------------------------------------------------------

test('every command shape and one-field variant has its own digest', () => {
  assert.equal(DERIVATION.id, 'canonical-action-derivation');
  assert.equal(DERIVATION.transports.length, 3);
  assert.equal(DERIVATION.distinct_digest_count, DERIVATION.expected_digest_count);
  for (const entry of DERIVATION.transports) {
    assert.match(entry.digest, /^sha256:[0-9a-f]{64}$/);
    // The digest is derived from the frame read back off the wire, not from
    // the object the enforcement point was handed.
    assert.equal(entry.derived_from_wire, true);
    assert.equal(entry.drift.length, 3);
    for (const drift of entry.drift) {
      assert.equal(drift.digest_changed, true, `${entry.transport}/${drift.field} digest must change`);
      assert.equal(drift.binding_ok, false, `${entry.transport}/${drift.field} must fail the binding`);
      assert.deepEqual(drift.mismatched_fields, [drift.field]);
    }
  }
});

test('a Modbus write binds the zero-based wire address, not a 4xxxxx display label', () => {
  const base = modbusWriteRegisterAction({
    site: 'ep:site:demo-lift-station', device: 'ep:device:plc-3', unitId: 3, protocolAddress: 0, value: 1,
  });
  assert.equal(commandDigest(base), commandDigest(EXACT_COMMANDS['modbus-tcp']));
  assert.equal(base.protocol_address, 0);
  assert.equal(Object.hasOwn(base, 'register'), false);
  const digests = new Set([commandDigest(base)]);
  for (const variant of [
    { unitId: 3, protocolAddress: 1, value: 1 },
    { unitId: 3, protocolAddress: 0, value: 0 },
    { unitId: 4, protocolAddress: 0, value: 1 },
  ]) {
    const digest = commandDigest(modbusWriteRegisterAction({
      site: 'ep:site:demo-lift-station', device: 'ep:device:plc-3', ...variant,
    }));
    assert.equal(digests.has(digest), false);
    digests.add(digest);
  }
  assert.equal(digests.size, 4);
});

test('Modbus FC 0x06 and FC 0x10 quantity one remain encoding-scoped authorities', () => {
  const fc06 = EXACT_COMMANDS['modbus-tcp'];
  const fc10 = modbusWriteMultipleRegistersAction({
    site: fc06.site,
    device: fc06.device,
    unitId: fc06.unit_id,
    protocolAddress: fc06.protocol_address,
    values: [fc06.value],
  });
  assert.equal(fc10.quantity, 1);
  assert.equal(fc10.values[0], fc06.value);
  assert.notEqual(commandDigest(fc10), commandDigest(fc06));
});

test('Modbus FC 0x10 quantity one has a native wire encode/decode round trip', () => {
  const fc06 = EXACT_COMMANDS['modbus-tcp'];
  const fc10 = modbusWriteMultipleRegistersAction({
    site: fc06.site,
    device: fc06.device,
    unitId: fc06.unit_id,
    protocolAddress: fc06.protocol_address,
    values: [fc06.value],
  });
  assert.equal(typeof commandCodecs.encodeModbusWriteMultipleRegisters, 'function');
  assert.equal(typeof commandCodecs.decodeModbusWriteMultipleRegisters, 'function');
  const encoded = commandCodecs.encodeModbusWriteMultipleRegisters(fc10, { transactionId: 9 });
  assert.equal(encoded.octets, 15);
  assert.equal(encoded.metadata_octets_available, 0);
  assert.deepEqual(
    commandCodecs.decodeModbusWriteMultipleRegisters(encoded.hex, {
      site: fc10.site,
      device: fc10.device,
      unit_id: fc10.unit_id,
    }),
    fc10,
  );
});

test('Modbus FC 0x10 refuses malformed quantity and byte-count fields', () => {
  const valid = Buffer.from('000100000009031000000001020001', 'hex');
  const missingQuantity = Buffer.from(valid);
  missingQuantity.writeUInt16BE(0, 10);
  assert.throws(
    () => commandCodecs.decodeModbusWriteMultipleRegisters(missingQuantity.toString('hex'), {
      site: 'ep:site:demo-lift-station',
      device: 'ep:device:plc-3',
      unit_id: 3,
    }),
    /quantity/,
  );

  const wrongByteCount = Buffer.from(valid);
  wrongByteCount.writeUInt8(4, 12);
  assert.throws(
    () => commandCodecs.decodeModbusWriteMultipleRegisters(wrongByteCount.toString('hex'), {
      site: 'ep:site:demo-lift-station',
      device: 'ep:device:plc-3',
      unit_id: 3,
    }),
    /byte count/,
  );
});

test('Modbus decoders refuse a wire unit id without conduit-owned unit mapping', () => {
  const fc06 = EXACT_COMMANDS['modbus-tcp'];
  const fc10 = modbusWriteMultipleRegistersAction({
    site: fc06.site,
    device: fc06.device,
    unitId: fc06.unit_id,
    protocolAddress: fc06.protocol_address,
    values: [fc06.value],
  });
  for (const [encoded, decode] of [
    [encodeModbusWriteRegister(fc06), decodeModbusWriteRegister],
    [commandCodecs.encodeModbusWriteMultipleRegisters(fc10), commandCodecs.decodeModbusWriteMultipleRegisters],
  ] as const) {
    assert.throws(
      () => decode(encoded.hex, {
        site: 'ep:site:demo-lift-station',
        device: 'ep:device:plc-3',
      }),
      /unit id mapping is required/,
    );
  }
});

test('a Modbus unit-id mismatch with conduit device context is refused during decode', () => {
  const encoded = encodeModbusWriteRegister(EXACT_COMMANDS['modbus-tcp']);
  assert.throws(
    () => decodeModbusWriteRegister(encoded.hex, {
      site: 'ep:site:demo-lift-station',
      device: 'ep:device:plc-3',
      unit_id: 4,
    }),
    /unit id does not match conduit device context/,
  );
});

test('a DNP3 CROB digest binds the complete control octet, timing, count, and function', () => {
  const link = { site: 'ep:site:demo-lift-station', device: 'ep:device:rtu-12', outstationAddress: 12 };
  const base = dnp3ControlRelayAction({
    ...link,
    index: 7,
    applicationFunction: 5,
    controlOctet: 0x03,
    operationCount: 1,
    onTimeMs: 0,
    offTimeMs: 0,
  });
  assert.equal(commandDigest(base), commandDigest(EXACT_COMMANDS.dnp3));
  assert.notEqual(
    commandDigest(dnp3ControlRelayAction({ ...link, index: 8, applicationFunction: 5, controlOctet: 0x03, operationCount: 1, onTimeMs: 0, offTimeMs: 0 })),
    commandDigest(base),
  );
  assert.notEqual(
    commandDigest(dnp3ControlRelayAction({ ...link, index: 7, applicationFunction: 5, controlOctet: 0x43, operationCount: 1, onTimeMs: 0, offTimeMs: 0 })),
    commandDigest(base),
  );
  for (const variant of [
    { applicationFunction: 6, controlOctet: 0x03, operationCount: 1, onTimeMs: 0, offTimeMs: 0 },
    { applicationFunction: 5, controlOctet: 0x03, operationCount: 2, onTimeMs: 0, offTimeMs: 0 },
    { applicationFunction: 5, controlOctet: 0x03, operationCount: 1, onTimeMs: 100, offTimeMs: 0 },
    { applicationFunction: 5, controlOctet: 0x03, operationCount: 1, onTimeMs: 0, offTimeMs: 100 },
  ]) {
    assert.notEqual(
      commandDigest(dnp3ControlRelayAction({ ...link, index: 7, ...variant })),
      commandDigest(base),
    );
  }
});

for (const hostile of [
  { name: 'FIN cleared', offset: 0, value: 0x80, reason: /application control/ },
  { name: 'CON set', offset: 0, value: 0xe0, reason: /application control/ },
  { name: 'UNS set', offset: 0, value: 0xd0, reason: /application control/ },
  { name: 'request status nonzero', offset: 17, value: 1, reason: /request status/ },
]) {
  test(`DNP3 refuses a hostile request with ${hostile.name}`, () => {
    const fragment = Buffer.from(encodeDnp3ControlRelay(EXACT_COMMANDS.dnp3).hex, 'hex');
    fragment.writeUInt8(hostile.value, hostile.offset);
    assert.throws(
      () => decodeDnp3ControlRelay(fragment.toString('hex'), {
        site: EXACT_COMMANDS.dnp3.site,
        device: EXACT_COMMANDS.dnp3.device,
        outstation_address: EXACT_COMMANDS.dnp3.outstation_address,
      }),
      hostile.reason,
    );
  });
}

test('DNP3 v1 pins qualifier 0x17, count one, and one-octet index range', () => {
  assert.deepEqual(TRANSPORT_PROFILES.dnp3.encoding_profile.object_header, {
    qualifier: 0x17,
    object_count: 1,
    index_octets: 1,
    index_min: 0,
    index_max: 0xff,
  });
  assert.deepEqual(TRANSPORT_PROFILES.dnp3.encoding_profile.application_control_flags, {
    FIR: 1,
    FIN: 1,
    CON: 0,
    UNS: 0,
  });
  assert.equal(TRANSPORT_PROFILES.dnp3.encoding_profile.request_status, 0);
  const maxIndex = dnp3ControlRelayAction({
    site: EXACT_COMMANDS.dnp3.site,
    device: EXACT_COMMANDS.dnp3.device,
    outstationAddress: EXACT_COMMANDS.dnp3.outstation_address,
    index: 0xff,
    applicationFunction: 5,
    controlOctet: 0x03,
  });
  const encoded = encodeDnp3ControlRelay(maxIndex);
  assert.equal(Buffer.from(encoded.hex, 'hex').readUInt8(4), 0x17);
  assert.equal(Buffer.from(encoded.hex, 'hex').readUInt8(5), 1);
  assert.deepEqual(decodeDnp3ControlRelay(encoded.hex, {
    site: maxIndex.site,
    device: maxIndex.device,
    outstation_address: maxIndex.outstation_address,
  }), maxIndex);
  assert.throws(() => dnp3ControlRelayAction({
    site: maxIndex.site,
    device: maxIndex.device,
    outstationAddress: maxIndex.outstation_address,
    index: 0x100,
    applicationFunction: 5,
    controlOctet: 0x03,
  }), /index must be an integer in \[0, 255\]/);
});

test('detached evidence distinguishes two authorizations for the same exact action', () => {
  const index = createOutOfBandAuthorizationIndex({ defaultRequestContext: 'session-a' });
  const action = EXACT_COMMANDS['modbus-tcp'];
  const first = { payload: { receipt_id: 'attempt-1' } };
  const second = { payload: { receipt_id: 'attempt-2' } };
  const heldFirst = index.hold(action, first);
  const heldSecond = index.hold(action, second);
  assert.notEqual(heldFirst.attempt_ref, heldSecond.attempt_ref);
  assert.equal(index.size, 2);
  assert.equal(index.lookup(heldFirst.attempt_ref, commandDigestHex(action)), first);
  assert.equal(index.lookup(heldSecond.attempt_ref, commandDigestHex(action)), second);
  assert.equal(index.lookup(heldFirst.attempt_ref, commandDigestHex(action), 'session-b'), null);
});

test('the digest is canonical, so key order cannot move it', () => {
  const base = EXACT_COMMANDS['modbus-tcp'];
  const reordered: any = {};
  for (const key of Object.keys(base).reverse()) reordered[key] = base[key];
  assert.notDeepEqual(Object.keys(reordered), Object.keys(base));
  assert.equal(commandDigest(reordered), commandDigest(base));
});

test('the per-request correlation id is not part of the act', () => {
  const invariance = DERIVATION.correlation_invariance;
  assert.equal(invariance.frames_differ, true);
  assert.equal(invariance.digests_equal, true);
  assert.equal(invariance.digest_a, commandDigest(EXACT_COMMANDS['modbus-tcp']));
});

test('the wire round-trips through the decoder without moving the digest', () => {
  const link = { site: 'ep:site:demo-lift-station', device: 'ep:device:plc-3', unit_id: 3 };
  const modbus = encodeModbusWriteRegister(EXACT_COMMANDS['modbus-tcp'], { transactionId: 7 });
  assert.deepEqual(
    decodeModbusWriteRegister(modbus.hex, link),
    EXACT_COMMANDS['modbus-tcp'],
  );
  const dnp3Link = { site: 'ep:site:demo-lift-station', device: 'ep:device:rtu-12', outstation_address: 12 };
  const dnp3 = encodeDnp3ControlRelay(EXACT_COMMANDS.dnp3, { sequence: 3 });
  assert.deepEqual(decodeDnp3ControlRelay(dnp3.hex, dnp3Link), EXACT_COMMANDS.dnp3);
});

// ---------------------------------------------------------------------------
// Scene 2 — authorized
// ---------------------------------------------------------------------------

test('one authorization admits one exact command once on every transport', () => {
  assert.equal(AUTHORIZED.id, 'authorized');
  assert.equal(AUTHORIZED.transports.length, 3);
  for (const entry of AUTHORIZED.transports) {
    assert.equal(entry.allowed, true, `${entry.transport} must be allowed`);
    assert.equal(entry.reason, 'allow');
    assert.equal(entry.device_entered, true);
    assert.equal(entry.device_command_count, 1);
    // What the gate recorded as the action it authorized is the digest the
    // command was keyed by.
    assert.equal(entry.gate_authorized_the_digest, true);
    assert.match(entry.recorded_action_digest, /^sha256:[0-9a-f]{64}$/);
    assert.equal(entry.execution_binds_authorization, true);
    assert.equal(entry.reliance_verdict, 'rely');
    // The same artifact re-verifies in the standalone offline verifier with
    // nothing but the pinned issuer public key.
    assert.equal(entry.offline_verification.valid, true);
    assert.equal(entry.offline_verification.signature, true);
    assert.equal(entry.offline_verification.error, null);
    assert.equal(entry.evidence_chain_ok, true);
  }
});

test('the two detached transports bind a conduit attempt reference and the exact-action digest', () => {
  const outOfBand = AUTHORIZED.transports.filter((entry: any) => entry.binding_mode === 'out-of-band-digest');
  assert.equal(outOfBand.length, 2);
  for (const entry of outOfBand) {
    assert.equal(entry.authorization_carried_inline, false);
    assert.equal(entry.authorization_octets_on_wire, 0);
    // The out-of-band index key is exactly the digest the gate authorized.
    assert.equal(entry.out_of_band_key, entry.observed_digest);
    assert.equal(entry.out_of_band_key, entry.recorded_action_digest);
    assert.equal(typeof entry.out_of_band_attempt_ref, 'string');
    assert.ok(entry.out_of_band_attempt_ref.length > 0);
  }
  const inline = AUTHORIZED.transports.filter((entry: any) => entry.binding_mode === 'inline');
  assert.equal(inline.length, 1);
  assert.equal(inline[0].authorization_carried_inline, true);
  assert.ok(inline[0].authorization_octets_on_wire > 0);
  assert.equal(inline[0].out_of_band_key, null);
});

// ---------------------------------------------------------------------------
// Scene 3 — drift refused
// ---------------------------------------------------------------------------

test('a command that differs in one field is refused with an action-binding reason', () => {
  assert.equal(DRIFT.id, 'drift-refused');
  assert.equal(DRIFT.cases.length, 6);
  for (const item of DRIFT.cases) {
    assert.equal(item.allowed, false, `${item.transport}/${item.drifted_field} must be refused`);
    assert.equal(item.reason, 'execution_binding_failed');
    assert.deepEqual(item.mismatched_fields, [item.drifted_field]);
    assert.notEqual(item.presented_digest, item.authorized_digest);
    assert.equal(item.device_entered, false);
  }
});

test('a valve address off by one never reaches the device', () => {
  const registerDrift = DRIFT.cases.find(
    (item: any) => item.transport === 'modbus-tcp' && item.drifted_field === 'protocol_address',
  );
  assert.ok(registerDrift);
  assert.equal(registerDrift.allowed, false);
  assert.equal(registerDrift.reason, 'execution_binding_failed');
  assert.equal(registerDrift.device_entered, false);
  // Exactly one command reached the device across the drifted attempt and the
  // honest one that followed it.
  assert.equal(registerDrift.device_command_count, 1);
});

test('refusing drift does not burn the operator authorization', () => {
  for (const item of DRIFT.cases) {
    assert.equal(item.store_state_after_refusal, 'unseen');
    assert.equal(item.authorization_survived_refusal, true);
    assert.equal(item.exact_command_still_admitted, true);
  }
});

test('detached lookup requires an attempt reference whose held digest matches the command', () => {
  assert.equal(DRIFT.out_of_band_lookup.length, 2);
  for (const item of DRIFT.out_of_band_lookup) {
    assert.equal(item.index_size, 1);
    assert.equal(item.authorization_found, false);
    assert.equal(item.allowed, false);
    assert.equal(item.reason, 'receipt_required');
    assert.equal(item.device_entered, false);
  }
});

// ---------------------------------------------------------------------------
// Scene 4 — unresolved after dispatch
// ---------------------------------------------------------------------------

test('a command dispatched to a PLC that goes quiet is recorded as indeterminate', () => {
  assert.equal(UNRESOLVED.id, 'unresolved-after-dispatch');
  assert.equal(UNRESOLVED.dispatch.device_entered, true);
  assert.equal(UNRESOLVED.dispatch.allowed, false);
  assert.equal(UNRESOLVED.dispatch.terminal_outcome, 'indeterminate');
  assert.equal(UNRESOLVED.dispatch.reason, 'effect_attempted_outcome_unknown');
});

test('DNP3 DIRECT_OPERATE_NR is an ordinary indeterminate terminal result', () => {
  const noAck = UNRESOLVED.dnp3_direct_operate_no_ack;
  assert.equal(noAck.application_function, 6);
  assert.equal(noAck.device_entered, true);
  assert.equal(noAck.terminal_outcome, 'indeterminate');
  assert.equal(noAck.reason, 'effect_attempted_outcome_unknown');
  assert.equal(noAck.store_state, 'committed:v2');
});

test('the indeterminate outcome is in the evidence log, not just in a message', () => {
  assert.equal(UNRESOLVED.evidence.indeterminate_recorded, true);
  assert.equal(UNRESOLVED.evidence.recorded_outcome, 'indeterminate');
  assert.equal(UNRESOLVED.evidence.recorded_detail_code, 'effect_attempted_outcome_unknown');
  assert.match(UNRESOLVED.evidence.recorded_action_digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(UNRESOLVED.evidence.chain_ok, true);
});

test('the authorization does not return to the pool after an unresolved dispatch', () => {
  // Read out of the consumption store backend, not out of a printed string.
  assert.equal(UNRESOLVED.consumption_store.state, 'committed:v2');
  assert.equal(UNRESOLVED.consumption_store.committed, true);
  assert.equal(UNRESOLVED.consumption_store.returned_to_pool, false);
});

test('a blind retry after an unresolved dispatch is refused and the device is not re-entered', () => {
  assert.equal(UNRESOLVED.blind_retry.allowed, false);
  assert.equal(UNRESOLVED.blind_retry.reason, 'replay_refused');
  assert.equal(UNRESOLVED.blind_retry.device_entered, false);
  assert.equal(UNRESOLVED.blind_retry.device_command_count_unchanged, true);
  assert.equal(UNRESOLVED.device_command_count, 1);
});

test('the retry refusal is scoped to the spent authorization, not to the command', () => {
  const recovery = UNRESOLVED.recovery_is_reauthorization;
  assert.equal(recovery.distinct_from_spent_authorization, true);
  // A human re-authorizing after reconciling is the recovery path, and it is
  // admitted. Without this the refusal above would be indistinguishable from
  // a dead enforcement point.
  assert.equal(recovery.allowed, true);
  assert.equal(recovery.reason, 'allow');
  assert.equal(recovery.device_entered, true);
  assert.equal(recovery.device_command_count_after, 2);
});

// ---------------------------------------------------------------------------
// Scene 5 — spent once
// ---------------------------------------------------------------------------

test('a still-fresh authorization that was already consumed is refused as a replay', () => {
  const fresh = SPENT.fresh_but_spent;
  assert.equal(fresh.first_use_allowed, true);
  assert.ok(fresh.age_seconds_at_replay < fresh.max_age_sec);
  assert.equal(fresh.still_inside_freshness_window, true);
  // The freshness property, checked on its own by the receipt verifier at the
  // instant the gate refused: the receipt is fine, the authority is spent.
  assert.equal(fresh.freshness_verdict_ok, true);
  assert.equal(fresh.freshness_reason, null);
  assert.equal(fresh.replay_allowed, false);
  assert.equal(fresh.replay_reason, 'replay_refused');
  assert.equal(fresh.store_state, 'committed:v2');
  assert.equal(fresh.device_entered_on_replay, false);
  assert.equal(fresh.device_command_count_unchanged, true);
});

test('a never-consumed authorization outside its window is refused as expired', () => {
  const stale = SPENT.stale_but_unspent;
  assert.ok(stale.age_seconds_at_use > stale.max_age_sec);
  assert.equal(stale.never_consumed_before_use, true);
  assert.equal(stale.freshness_verdict_ok, false);
  assert.equal(stale.freshness_reason, 'receipt_expired');
  assert.equal(stale.allowed, false);
  assert.equal(stale.reason, 'receipt_rejected:receipt_expired');
  assert.equal(stale.device_entered, false);
});

test('freshness and single-use refuse under different names', () => {
  assert.equal(SPENT.reasons_are_distinct, true);
  assert.equal(SPENT.fresh_but_spent.replay_reason, 'replay_refused');
  assert.equal(SPENT.stale_but_unspent.reason, 'receipt_rejected:receipt_expired');
  assert.notEqual(SPENT.fresh_but_spent.replay_reason, SPENT.stale_but_unspent.reason);
});

// ---------------------------------------------------------------------------
// Hostile cases against the enforcement point itself
// ---------------------------------------------------------------------------

test('an authorization from an unpinned issuer is refused on every transport', async () => {
  for (const transport of Object.keys(EXACT_COMMANDS)) {
    const point = createEnforcementPoint(transport);
    const rogue = createEnforcementPoint(transport);
    const rogueAuthorization = rogue.authorize();
    point.index.hold(point.action, rogueAuthorization);
    const result = await point.gate.run(
      {
        selector: { ...point.selector },
        receipt: rogueAuthorization,
        observedAction: point.action,
      },
      async () => point.device.apply(point.action),
    );
    assert.equal(result.ok, false, `${transport} must refuse an unpinned issuer`);
    assert.equal(result.authorization.reason, 'receipt_rejected:untrusted_or_invalid_signature');
    assert.equal(point.device.commandCount, 0);
  }
});

test('a guarded command with no authorization at all is refused before the device', async () => {
  const point = createEnforcementPoint('modbus-tcp');
  const result = await point.gate.run(
    { selector: { ...point.selector }, receipt: null, observedAction: point.action },
    async () => point.device.apply(point.action),
  );
  assert.equal(result.ok, false);
  assert.equal(result.authorization.reason, 'receipt_required');
  assert.equal(point.device.commandCount, 0);
});

test('an inline OPC-UA envelope is not a trust shortcut around the action binding', () => {
  const opcua = sceneById('drift-refused').cases.filter((item: any) => item.transport === 'opc-ua');
  assert.equal(opcua.length, 2);
  for (const item of opcua) {
    // The authorization rode inline with the very call that was refused.
    assert.equal(item.allowed, false);
    assert.equal(item.reason, 'execution_binding_failed');
    assert.equal(item.device_entered, false);
  }
});

test('the lab reports one device command per enforcement point in the authorized scene', () => {
  const total = AUTHORIZED.transports.reduce(
    (sum: number, entry: any) => sum + entry.device_command_count,
    0,
  );
  assert.equal(total, 3);
});
