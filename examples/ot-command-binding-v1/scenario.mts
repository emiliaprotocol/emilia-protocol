// SPDX-License-Identifier: Apache-2.0
/**
 * OT Command Binding lab.
 *
 * One exact-action authorization, three industrial control transports, one
 * binding. The scenes below are driven by the real gate: every verdict is a
 * `gate.check` / `gate.run` result, a `verifyExecutionBinding` result, an
 * offline `verifyReceipt` result, or a read of the consumption store and the
 * evidence log. Nothing here asserts by printing.
 *
 * Scene map:
 *   1. canonical-action-derivation   exact-action digest, and drift changes it
 *   2. authorized                    one command admitted once, receipt verifies offline
 *   3. drift-refused                 one field different, refused by action binding
 *   4. unresolved-after-dispatch     the PLC goes quiet; the outcome is indeterminate
 *   5. spent-once                    freshness and single-use are different properties
 */
import {
  createGate,
  createEg1Harness,
  createEvidenceLog,
  createDurableConsumptionStore,
  createMemoryBackend,
  verifyExecutionBinding,
} from '../../packages/gate/index.js';
import { manifestFromPack } from '../../packages/gate/adapters/_kit.js';
import { verifyReceipt } from '../../packages/verify/index.js';
import { verifyEmiliaReceipt } from '../../packages/require-receipt/index.js';

import {
  BOUND_FIELDS,
  OT_COMMAND_BINDING_VERSION,
  TRANSPORT_PROFILES,
  commandDigest,
  commandDigestHex,
  decodeDnp3ControlRelay,
  decodeModbusWriteRegister,
  decodeOpcuaCall,
  dnp3ControlRelayAction,
  encodeDnp3ControlRelay,
  encodeModbusWriteRegister,
  encodeOpcuaCall,
  extractOpcuaAuthorization,
  modbusWriteRegisterAction,
  opcuaCallMethodAction,
} from './commands.mjs';

export const LAB_VERSION = 'EP-OT-COMMAND-BINDING-LAB-v1';

/** Fixed clock origin so digests and evidence are byte-identical between runs. */
const T0 = Date.parse('2026-08-07T09:00:00.000Z');
const MAX_AGE_SEC = 900;

const SITE = 'ep:site:demo-lift-station';

/** Link facts each enforcement point owns because it terminates the connection. */
const LINKS = Object.freeze({
  'modbus-tcp': Object.freeze({ site: SITE, device: 'ep:device:plc-3' }),
  dnp3: Object.freeze({ site: SITE, device: 'ep:device:rtu-12', outstation_address: 12 }),
  'opc-ua': Object.freeze({ site: SITE, device: 'ep:device:dcs-1' }),
});

/** The one exact command per transport this lab authorizes. */
export const EXACT_COMMANDS = Object.freeze({
  'modbus-tcp': modbusWriteRegisterAction({
    ...LINKS['modbus-tcp'], unitId: 3, register: 40001, value: 1,
  }),
  dnp3: dnp3ControlRelayAction({
    site: LINKS.dnp3.site,
    device: LINKS.dnp3.device,
    outstationAddress: LINKS.dnp3.outstation_address,
    index: 7,
    controlCode: 'LATCH_ON',
  }),
  'opc-ua': opcuaCallMethodAction({
    ...LINKS['opc-ua'],
    objectId: 'ns=2;s=LiftStation.PumpTrain',
    methodId: 'ns=2;s=SetInterlock',
    argumentName: 'Enabled',
    argumentValue: 1,
  }),
});

const SELECTORS = Object.freeze({
  'modbus-tcp': Object.freeze({ protocol: 'ot', tool: 'modbus_write_single_register' }),
  dnp3: Object.freeze({ protocol: 'ot', tool: 'dnp3_direct_operate_crob' }),
  'opc-ua': Object.freeze({ protocol: 'ot', tool: 'opcua_call_method' }),
});

const WHY = Object.freeze({
  'modbus-tcp': 'Writes a physical setpoint. Bind the exact unit, register, and value; Class-A human key.',
  dnp3: 'Operates a physical relay. Bind the exact outstation, point index, and control code; Class-A human key.',
  'opc-ua': 'Changes a process interlock. Bind the exact node, method, and argument; Class-A human key.',
});

function actionPackEntry(transport: string): any {
  const action = EXACT_COMMANDS[transport];
  return Object.freeze({
    id: `ot.${transport}.guarded`,
    label: `${transport} control command`,
    action_type: action.action_type,
    risk: 'critical',
    receipt_required: true,
    assurance_class: 'class_a',
    match: { ...SELECTORS[transport] },
    why: WHY[transport],
    execution_binding: { required_fields: [...BOUND_FIELDS[transport]] },
  });
}

/** Per-transport wire operations: how a command reaches the device, and how the
 * enforcement point reads back what it is about to forward. */
const TRANSPORT_OPS: Record<string, any> = Object.freeze({
  'modbus-tcp': {
    encode: (action: any, opts: any = {}) => encodeModbusWriteRegister(action, opts),
    wireOf: (encoded: any) => encoded.hex,
    decode: (wire: any, link: any) => decodeModbusWriteRegister(wire, link),
    inlineAuthorization: () => null,
  },
  dnp3: {
    encode: (action: any, opts: any = {}) => encodeDnp3ControlRelay(action, opts),
    wireOf: (encoded: any) => encoded.hex,
    decode: (wire: any, link: any) => decodeDnp3ControlRelay(wire, link),
    inlineAuthorization: () => null,
  },
  'opc-ua': {
    encode: (action: any, opts: any = {}) => encodeOpcuaCall(action, opts),
    wireOf: (encoded: any) => encoded.request,
    decode: (wire: any, link: any) => decodeOpcuaCall(wire, link),
    inlineAuthorization: (wire: any) => extractOpcuaAuthorization(wire),
  },
});

/**
 * The out-of-band authorization holder. Modbus and DNP3 cannot carry an
 * authorization on the wire, so the enforcement point keeps it here, keyed by
 * the canonical digest of the exact command. `hashCanonical` is the gate's own
 * function, so this index is keyed by exactly what the gate records as
 * `observed_action_hash`.
 */
export function createOutOfBandAuthorizationIndex(): any {
  const byDigest = new Map<string, any>();
  return {
    hold(action: any, receipt: any) {
      const digest = commandDigestHex(action);
      byDigest.set(digest, receipt);
      return digest;
    },
    lookup(digest: string) {
      return byDigest.get(digest) ?? null;
    },
    get size() { return byDigest.size; },
  };
}

/** A device that records what it was told to do and can be made to go quiet. */
function createDevice(): any {
  const commands: any[] = [];
  let quiet = false;
  return {
    get commands() { return commands.slice(); },
    get commandCount() { return commands.length; },
    goQuiet() { quiet = true; },
    speakAgain() { quiet = false; },
    async apply(action: any) {
      // The command reaches the device either way. When the link is quiet the
      // acknowledgement is what is lost, which is exactly why the outcome is
      // indeterminate rather than failed.
      commands.push(structuredClone(action));
      if (quiet) {
        const error: any = new Error('plc_response_timeout');
        error.code = 'PLC_RESPONSE_TIMEOUT';
        throw error;
      }
      return { acknowledged: true, at: action.action_type };
    },
  };
}

/**
 * One enforcement point in front of one device, on one transport: its own
 * manifest, its own pinned issuer and approver keys, its own consumption store,
 * its own evidence log.
 */
export function createEnforcementPoint(transport: string, { startMs = T0 }: any = {}): any {
  const clock = { ms: startMs };
  const now = () => clock.ms;
  const harness = createEg1Harness({
    action: EXACT_COMMANDS[transport] as any,
    idPrefix: `ot_${transport.replace(/-/g, '_')}`,
    now,
  });
  const backend = createMemoryBackend();
  const consumption = createDurableConsumptionStore(backend);
  const evidenceLog = createEvidenceLog({ strict: true });
  const gate = createGate({
    manifest: manifestFromPack([actionPackEntry(transport)]),
    trustedKeys: [harness.publicKey],
    approverKeys: harness.approverKeys,
    rpId: harness.rpId,
    allowedOrigins: harness.allowedOrigins,
    store: consumption,
    log: evidenceLog,
    maxAgeSec: MAX_AGE_SEC,
    now,
    // Local lab: the consumption backend is an in-process Map, so it is
    // ownership-fenced and permanent but not shared durable state. A deployed
    // enforcement point requires a durable backend and drops this flag.
    allowEphemeralStore: true,
  });
  const device = createDevice();
  const index = createOutOfBandAuthorizationIndex();

  return {
    transport,
    clock,
    harness,
    gate,
    backend,
    evidenceLog,
    device,
    index,
    profile: TRANSPORT_PROFILES[transport],
    selector: SELECTORS[transport],
    link: LINKS[transport],
    requirement: actionPackEntry(transport),
    action: EXACT_COMMANDS[transport],
    advanceSeconds(seconds: number) { clock.ms += seconds * 1000; },
    /** Mint an operator authorization for this enforcement point's exact command. */
    authorize() { return harness.mint({ outcome: 'allow_with_signoff' }); },
    /** Raw store state for a receipt id: undefined, a reservation, or committed. */
    async storeState(receiptId: string) { return backend.get(receiptId); },
  };
}

/**
 * Put an authorized command on the wire and let the enforcement point handle
 * it. The observed action is always decoded from the wire plus the link facts;
 * the caller's description of the command is never a trust source.
 */
async function dispatch(point: any, { action, receipt, encodeOptions = {} }: any): Promise<any> {
  const ops = TRANSPORT_OPS[point.transport];
  const inline = point.profile.carries_authorization_inline;
  const encoded = ops.encode(action, inline ? { ...encodeOptions, receipt } : encodeOptions);
  const wire = ops.wireOf(encoded);

  const observedAction = ops.decode(wire, point.link);
  const observedDigest = commandDigestHex(observedAction);
  const presented = inline
    ? ops.inlineAuthorization(wire)
    : point.index.lookup(observedDigest);

  const before = point.device.commandCount;
  let outcome: any;
  let terminal: any = null;
  try {
    outcome = await point.gate.run(
      { selector: { ...point.selector }, receipt: presented, observedAction },
      async () => point.device.apply(observedAction),
    );
  } catch (error: any) {
    if (error?.code !== 'EMILIA_GATE_TERMINAL_OUTCOME') throw error;
    terminal = error;
    outcome = null;
  }

  const authorization = terminal
    ? { allow: false, reason: terminal.emiliaGateOutcome.reason, evidence: terminal.emiliaGateOutcome.authorizationEvidence }
    : (outcome.authorization ?? null);

  return {
    transport: point.transport,
    encoded,
    observed_action: observedAction,
    observed_digest: `sha256:${observedDigest}`,
    authorization_carried_inline: inline && Boolean(presented),
    authorization_presented: Boolean(presented),
    ok: Boolean(outcome?.ok),
    reason: terminal ? terminal.emiliaGateOutcome.reason : (outcome?.authorization?.reason ?? null),
    status: terminal ? null : (outcome?.status ?? 200),
    terminal_outcome: terminal ? terminal.emiliaGateOutcome.outcome : null,
    terminal_execution: terminal ? terminal.emiliaGateOutcome.execution : null,
    receipt_id: authorization?.evidence?.receipt_id ?? null,
    recorded_action_digest: authorization?.evidence?.observed_action_hash
      ? `sha256:${authorization.evidence.observed_action_hash}`
      : null,
    execution_binding: authorization?.evidence?.execution_binding ?? null,
    device_entered: point.device.commandCount > before,
    execution: outcome?.execution ?? null,
    packet: outcome?.packet ?? null,
  };
}

// ---------------------------------------------------------------------------
// Scene 1 — canonical action derivation
// ---------------------------------------------------------------------------

/** One-field variants of each exact command. Each one is a different physical act. */
function driftVariants(transport: string): any[] {
  const base = EXACT_COMMANDS[transport];
  if (transport === 'modbus-tcp') {
    return [
      { field: 'register', note: 'the adjacent holding register', action: modbusWriteRegisterAction({ ...LINKS['modbus-tcp'], unitId: 3, register: 40002, value: 1 }) },
      { field: 'value', note: 'the opposite setpoint', action: modbusWriteRegisterAction({ ...LINKS['modbus-tcp'], unitId: 3, register: 40001, value: 0 }) },
      { field: 'unit_id', note: 'the neighbouring unit on the same link', action: modbusWriteRegisterAction({ ...LINKS['modbus-tcp'], unitId: 4, register: 40001, value: 1 }) },
    ];
  }
  if (transport === 'dnp3') {
    const link = LINKS.dnp3;
    return [
      { field: 'index', note: 'the adjacent point index', action: dnp3ControlRelayAction({ site: link.site, device: link.device, outstationAddress: link.outstation_address, index: 8, controlCode: 'LATCH_ON' }) },
      { field: 'control_code', note: 'the opposite control code', action: dnp3ControlRelayAction({ site: link.site, device: link.device, outstationAddress: link.outstation_address, index: 7, controlCode: 'LATCH_OFF' }) },
      { field: 'outstation_address', note: 'a different outstation', action: dnp3ControlRelayAction({ site: link.site, device: link.device, outstationAddress: 13, index: 7, controlCode: 'LATCH_ON' }) },
    ];
  }
  return [
    { field: 'argument_value', note: 'the interlock cleared instead of set', action: opcuaCallMethodAction({ ...LINKS['opc-ua'], objectId: base.object_id, methodId: base.method_id, argumentName: base.argument_name, argumentValue: 0 }) },
    { field: 'method_id', note: 'a different method on the same object', action: opcuaCallMethodAction({ ...LINKS['opc-ua'], objectId: base.object_id, methodId: 'ns=2;s=ClearInterlock', argumentName: base.argument_name, argumentValue: 1 }) },
    { field: 'object_id', note: 'the same method on a different node', action: opcuaCallMethodAction({ ...LINKS['opc-ua'], objectId: 'ns=2;s=LiftStation.StandbyTrain', methodId: base.method_id, argumentName: base.argument_name, argumentValue: 1 }) },
  ];
}

function sceneCanonicalDerivation(): any {
  const transports: any[] = [];
  const allDigests = new Set<string>();

  for (const transport of Object.keys(EXACT_COMMANDS)) {
    const point = createEnforcementPoint(transport);
    const base = EXACT_COMMANDS[transport];
    const authorization = point.authorize();
    const baseDigest = commandDigest(base);
    allDigests.add(baseDigest);

    const encoded = TRANSPORT_OPS[transport].encode(base, {});
    const wire = TRANSPORT_OPS[transport].wireOf(encoded);
    // The digest is derived from what the enforcement point reads back off the
    // wire, not from the object it was handed.
    const roundTripped = TRANSPORT_OPS[transport].decode(wire, point.link);

    const drift = driftVariants(transport).map((variant: any) => {
      const digest = commandDigest(variant.action);
      allDigests.add(digest);
      const binding = verifyExecutionBinding({
        requirement: point.requirement,
        receipt: authorization,
        observedAction: variant.action,
      });
      return {
        field: variant.field,
        note: variant.note,
        digest,
        digest_changed: digest !== baseDigest,
        binding_ok: binding.ok === true,
        mismatched_fields: [...(binding.mismatched_fields ?? [])],
      };
    });

    transports.push({
      transport,
      profile: point.profile,
      action: base,
      digest: baseDigest,
      wire_octets: encoded.octets,
      metadata_octets_available: encoded.metadata_octets_available,
      carries_authorization_inline: point.profile.carries_authorization_inline,
      derived_from_wire: commandDigest(roundTripped) === baseDigest,
      drift,
    });
  }

  // A Modbus transaction id is per-request correlation, not part of the act.
  const modbus = EXACT_COMMANDS['modbus-tcp'];
  const frameA = encodeModbusWriteRegister(modbus, { transactionId: 1 });
  const frameB = encodeModbusWriteRegister(modbus, { transactionId: 4242 });
  const decodedA = decodeModbusWriteRegister(frameA.hex, LINKS['modbus-tcp']);
  const decodedB = decodeModbusWriteRegister(frameB.hex, LINKS['modbus-tcp']);

  return {
    id: 'canonical-action-derivation',
    title: 'One canonical action per command shape, on every transport',
    property: 'exact-action digest; changing any material field changes the digest',
    transports,
    distinct_digest_count: allDigests.size,
    expected_digest_count: transports.length * 4,
    correlation_invariance: {
      note: 'Two Modbus frames that differ only in MBAP transaction id are the same physical act.',
      frame_a: frameA.hex,
      frame_b: frameB.hex,
      frames_differ: frameA.hex !== frameB.hex,
      digest_a: commandDigest(decodedA),
      digest_b: commandDigest(decodedB),
      digests_equal: commandDigest(decodedA) === commandDigest(decodedB),
    },
  };
}

// ---------------------------------------------------------------------------
// Scene 2 — authorized
// ---------------------------------------------------------------------------

async function sceneAuthorized(): Promise<any> {
  const transports: any[] = [];

  for (const transport of Object.keys(EXACT_COMMANDS)) {
    const point = createEnforcementPoint(transport);
    const authorization = point.authorize();
    const inline = point.profile.carries_authorization_inline;
    const heldDigest = inline ? null : point.index.hold(point.action, authorization);

    const result = await dispatch(point, { action: point.action, receipt: authorization });

    // The same artifact, re-verified by the standalone offline verifier package
    // with nothing but the pinned issuer public key. No gate, no store, no log.
    const offline = verifyReceipt(authorization, point.harness.publicKey);

    transports.push({
      transport,
      binding_mode: point.profile.binding_mode,
      authorization_carried_inline: result.authorization_carried_inline,
      out_of_band_key: heldDigest ? `sha256:${heldDigest}` : null,
      wire_octets: result.encoded.octets,
      authorization_octets_on_wire: result.encoded.authorization_octets ?? 0,
      allowed: result.ok,
      reason: result.reason,
      device_entered: result.device_entered,
      device_command_count: point.device.commandCount,
      observed_digest: result.observed_digest,
      recorded_action_digest: result.recorded_action_digest,
      // The digest the out-of-band index is keyed by IS the digest the gate
      // recorded. That equality is the whole out-of-band binding.
      gate_authorized_the_digest: result.recorded_action_digest === result.observed_digest,
      execution_binds_authorization:
        result.execution?.authorizes_decision === result.packet?.summary?.decision_hash,
      reliance_verdict: result.packet?.verdict ?? null,
      offline_verification: {
        valid: offline.valid === true,
        signature: offline.checks?.signature === true,
        error: offline.error ?? null,
      },
      evidence_chain_ok: point.evidenceLog.verify().ok === true,
    });
  }

  return {
    id: 'authorized',
    title: 'One operator authorization admits one exact command, once, on each transport',
    property: 'authorized execution; the receipt verifies offline',
    transports,
  };
}

// ---------------------------------------------------------------------------
// Scene 3 — drift refused
// ---------------------------------------------------------------------------

async function sceneDriftRefused(): Promise<any> {
  const cases: any[] = [];

  for (const transport of Object.keys(EXACT_COMMANDS)) {
    for (const variant of driftVariants(transport).slice(0, 2)) {
      const point = createEnforcementPoint(transport);
      const authorization = point.authorize();
      // The operator authorized the exact command; the index is keyed by that
      // command's digest, so a drifted command finds no authorization at all.
      point.index.hold(point.action, authorization);
      // Hand the drifted command the authorization anyway, so the refusal is
      // the action binding refusing and not a lookup miss.
      point.index.hold(variant.action, authorization);

      const drifted = await dispatch(point, { action: variant.action, receipt: authorization });
      const receiptId = authorization.payload.receipt_id;
      const storeAfterDrift = await point.storeState(receiptId);

      // The refusal did not burn the operator's approval: the exact command
      // still goes through afterwards.
      const honest = await dispatch(point, { action: point.action, receipt: authorization });

      cases.push({
        transport,
        drifted_field: variant.field,
        note: variant.note,
        authorized_digest: commandDigest(point.action),
        presented_digest: drifted.observed_digest,
        allowed: drifted.ok,
        reason: drifted.reason,
        mismatched_fields: [...(drifted.execution_binding?.mismatched_fields ?? [])],
        device_entered: drifted.device_entered,
        store_state_after_refusal: storeAfterDrift === undefined ? 'unseen' : String(storeAfterDrift),
        authorization_survived_refusal: storeAfterDrift === undefined,
        exact_command_still_admitted: honest.ok === true,
        device_command_count: point.device.commandCount,
      });
    }
  }

  // The cases above deliberately plant the authorization under the drifted
  // digest too, so the refusal is the action binding refusing rather than an
  // empty lookup. The out-of-band channel is itself digest-keyed, which this
  // shows the other way round: nothing planted, nothing found.
  const lookupMiss: any[] = [];
  for (const transport of ['modbus-tcp', 'dnp3']) {
    const point = createEnforcementPoint(transport);
    const authorization = point.authorize();
    point.index.hold(point.action, authorization);
    const variant = driftVariants(transport)[0];
    const attempt = await dispatch(point, { action: variant.action, receipt: null });
    lookupMiss.push({
      transport,
      drifted_field: variant.field,
      index_size: point.index.size,
      presented_digest: attempt.observed_digest,
      authorization_found: attempt.authorization_presented,
      allowed: attempt.ok,
      reason: attempt.reason,
      device_entered: attempt.device_entered,
    });
  }

  return {
    id: 'drift-refused',
    title: 'One field different is a different physical action, and is refused by name',
    property: 'action binding; a valve address off by one is not the authorized act',
    cases,
    out_of_band_lookup: lookupMiss,
  };
}

// ---------------------------------------------------------------------------
// Scene 4 — unresolved after dispatch
// ---------------------------------------------------------------------------

async function sceneUnresolvedAfterDispatch(): Promise<any> {
  const point = createEnforcementPoint('modbus-tcp');
  const authorization = point.authorize();
  const receiptId = authorization.payload.receipt_id;
  point.index.hold(point.action, authorization);

  // The command is accepted by the gate and reaches the PLC. The PLC then goes
  // quiet, so the acknowledgement never comes back. The effect may or may not
  // have landed, and nothing available to the enforcement point can tell.
  point.device.goQuiet();
  const dispatched = await dispatch(point, { action: point.action, receipt: authorization });

  const storeAfter = await point.storeState(receiptId);
  const executionRecords = point.evidenceLog.all().filter((record: any) => record.kind === 'execution');
  const indeterminateRecord = executionRecords.find((record: any) => record.outcome === 'indeterminate') ?? null;

  // A blind retry with the same authorization. The device must not be entered
  // a second time on an authorization whose outcome is unknown.
  const commandsBeforeRetry = point.device.commandCount;
  point.device.speakAgain();
  const retry = await dispatch(point, { action: point.action, receipt: authorization });
  const commandsAfterRetry = point.device.commandCount;
  const retryLeftDeviceUntouched = commandsAfterRetry === commandsBeforeRetry;

  // The refusal is scoped to the spent authorization, not to the command or
  // the device. Recovery is a human re-authorizing after reconciling what the
  // PLC actually did, which the gate admits as a new authorization.
  const reauthorization = point.authorize();
  point.index.hold(point.action, reauthorization);
  const reauthorized = await dispatch(point, { action: point.action, receipt: reauthorization });

  return {
    id: 'unresolved-after-dispatch',
    title: 'The command is dispatched and the PLC goes quiet',
    property: 'indeterminate outcome recorded; the authorization does not return to the pool',
    dispatch: {
      device_entered: dispatched.device_entered,
      terminal_outcome: dispatched.terminal_outcome,
      reason: dispatched.reason,
      allowed: dispatched.ok,
    },
    consumption_store: {
      receipt_id: receiptId,
      // Read straight out of the store backend, not out of a printed line.
      state: storeAfter === undefined ? 'unseen' : String(storeAfter),
      committed: storeAfter === 'committed:v2',
      returned_to_pool: storeAfter === undefined,
    },
    evidence: {
      execution_records: executionRecords.length,
      indeterminate_recorded: indeterminateRecord !== null,
      recorded_outcome: indeterminateRecord?.outcome ?? null,
      recorded_detail_code: indeterminateRecord?.detail?.code ?? null,
      recorded_action_digest: indeterminateRecord?.observed_action_hash
        ? `sha256:${indeterminateRecord.observed_action_hash}`
        : null,
      chain_ok: point.evidenceLog.verify().ok === true,
    },
    blind_retry: {
      allowed: retry.ok,
      reason: retry.reason,
      device_entered: retry.device_entered,
      device_command_count_unchanged: retryLeftDeviceUntouched,
    },
    recovery_is_reauthorization: {
      note: 'A retry is refused; a new human authorization for the same command is admitted.',
      receipt_id: reauthorization.payload.receipt_id,
      distinct_from_spent_authorization: reauthorization.payload.receipt_id !== receiptId,
      allowed: reauthorized.ok,
      reason: reauthorized.reason,
      device_entered: reauthorized.device_entered,
      device_command_count_after: point.device.commandCount,
    },
    device_command_count: commandsAfterRetry,
  };
}

// ---------------------------------------------------------------------------
// Scene 5 — spent once
// ---------------------------------------------------------------------------

async function sceneSpentOnce(): Promise<any> {
  // (a) Still fresh, already spent. The freshness window is irrelevant once the
  //     authorization has been consumed.
  const spentPoint = createEnforcementPoint('modbus-tcp');
  const spent = spentPoint.authorize();
  const spentId = spent.payload.receipt_id;
  spentPoint.index.hold(spentPoint.action, spent);

  const firstUse = await dispatch(spentPoint, { action: spentPoint.action, receipt: spent });
  spentPoint.advanceSeconds(60);
  const commandsBeforeReplay = spentPoint.device.commandCount;
  const replay = await dispatch(spentPoint, { action: spentPoint.action, receipt: spent });

  // Freshness checked on its own terms, by the receipt verifier, at the same
  // instant the gate refused the replay. The verifier knows nothing about
  // consumption, so its verdict isolates the freshness property.
  const freshnessAtReplay = verifyEmiliaReceipt(spent, {
    trustedKeys: [spentPoint.harness.publicKey],
    maxAgeSec: MAX_AGE_SEC,
    now: () => spentPoint.clock.ms,
  });
  const ageSecondsAtReplay = Math.round(
    (spentPoint.clock.ms - Date.parse(spent.payload.created_at)) / 1000,
  );

  // (b) Never spent, no longer fresh. Same gate, a different authorization that
  //     was never presented until after the window closed.
  const stalePoint = createEnforcementPoint('modbus-tcp');
  const stale = stalePoint.authorize();
  const staleId = stale.payload.receipt_id;
  stalePoint.index.hold(stalePoint.action, stale);
  stalePoint.advanceSeconds(MAX_AGE_SEC + 300);
  const storeBeforeStale = await stalePoint.storeState(staleId);
  const freshnessAtStaleUse = verifyEmiliaReceipt(stale, {
    trustedKeys: [stalePoint.harness.publicKey],
    maxAgeSec: MAX_AGE_SEC,
    now: () => stalePoint.clock.ms,
  });
  const staleUse = await dispatch(stalePoint, { action: stalePoint.action, receipt: stale });

  return {
    id: 'spent-once',
    title: 'Freshness and single-use are different properties with different refusals',
    property: 'one-time consumption is independent of the freshness window',
    fresh_but_spent: {
      max_age_sec: MAX_AGE_SEC,
      receipt_id: spentId,
      first_use_allowed: firstUse.ok,
      age_seconds_at_replay: ageSecondsAtReplay,
      still_inside_freshness_window: ageSecondsAtReplay < MAX_AGE_SEC,
      replay_allowed: replay.ok,
      replay_reason: replay.reason,
      store_state: String(await spentPoint.storeState(spentId)),
      device_entered_on_replay: replay.device_entered,
      device_command_count_unchanged: spentPoint.device.commandCount === commandsBeforeReplay,
      freshness_verdict_ok: freshnessAtReplay.ok === true,
      freshness_reason: freshnessAtReplay.reason ?? null,
    },
    stale_but_unspent: {
      max_age_sec: MAX_AGE_SEC,
      receipt_id: staleId,
      age_seconds_at_use: Math.round(
        (stalePoint.clock.ms - Date.parse(stale.payload.created_at)) / 1000,
      ),
      never_consumed_before_use: storeBeforeStale === undefined,
      allowed: staleUse.ok,
      reason: staleUse.reason,
      device_entered: staleUse.device_entered,
      freshness_verdict_ok: freshnessAtStaleUse.ok === true,
      freshness_reason: freshnessAtStaleUse.reason ?? null,
    },
    reasons_are_distinct: replay.reason !== staleUse.reason,
  };
}

// ---------------------------------------------------------------------------

/** Run the whole lab and return a machine-readable result. */
export async function runOtCommandBindingLab(): Promise<any> {
  const scenes = [
    sceneCanonicalDerivation(),
    await sceneAuthorized(),
    await sceneDriftRefused(),
    await sceneUnresolvedAfterDispatch(),
    await sceneSpentOnce(),
  ];

  return Object.freeze({
    '@version': LAB_VERSION,
    binding_version: OT_COMMAND_BINDING_VERSION,
    title: 'OT Command Binding lab',
    scenario:
      'One exact-action authorization bound to industrial control commands across three transports with different envelope capacity.',
    transports: TRANSPORT_PROFILES,
    scenes,
    invariant:
      'The authorization binds to the canonical digest of the exact command. Where the wire can carry it, it rides along; where it cannot, it is held out of band and keyed to that same digest.',
  });
}

export default { LAB_VERSION, EXACT_COMMANDS, runOtCommandBindingLab, createEnforcementPoint };
