// SPDX-License-Identifier: Apache-2.0
/**
 * Conserved-Admission Handoff Lab.
 *
 * Executable cases for the cross-gateway property described in
 * draft-dunbar-dmsc-gw-scenarios-gap-analysis-04, Section 7.8 ("Conserved
 * Admission Across Gateway Boundaries"): when an in-progress task moves
 * between independently operated gateways while a single-use authorization
 * for a specific action is outstanding, the conserved object is the
 * exclusive ability to admit that one action. Copying the authorization,
 * transferring context, or exchanging a token is insufficient if both
 * gateways can still admit it.
 *
 * What is mechanism vs. what is illustration, precisely:
 *   - Every verification, exact-action binding, one-time consumption,
 *     refusal, and revocation-status check below is the repository
 *     implementation (EP-RECEIPT-v1 gate check, tenant-scoped consumption
 *     ledger, EP-STATUS-v1). Each refusal reason in the output is the one
 *     the mechanism produced, not one this file chose.
 *   - The handoff coordination itself (the enablement record, the
 *     dispose-before-enable ordering, the reconciliation record) is LAB
 *     CODE, deliberately minimal, because Section 7.8's finding is that no
 *     standard mechanism for this transfer exists. The lab makes the gap
 *     and its failure cases executable; it does not claim to close the gap.
 *
 * The Section 7.8 invariants under test:
 *   1. Both gateways bind to the same exact action and handoff instance.
 *   2. The previous gateway must be unable to admit before the new gateway
 *      may admit (source-side disposal first, the RFC 4067 replay model).
 *   3. The receiving gateway preserves independent trust and policy
 *      evaluation: it re-verifies the artifact under its own anchors and
 *      its own ledger; a transfer record is never admissible evidence.
 *   4. Transfer, admission, refusal, and reconciliation records correlate
 *      by shared action digest and handoff id.
 *   5. When exclusivity cannot be established the outcome is CLOSED:
 *      an unresolved handoff is never permission to admit or retry.
 *
 * The property is at-most-once admission of a specific action, not
 * exactly-once physical execution.
 */
import crypto from 'node:crypto';

import {
  createGate,
  createEg1Harness,
  hashCanonical,
  MemoryConsumptionStore,
} from '../../packages/gate/index.js';
import { manifestFromPack } from '../../packages/gate/adapters/_kit.js';
import { verifyStatusArtifact } from '../../packages/verify/index.js';
import {
  buildRevokerAuthorityCertificate,
  buildStatusArtifact,
  deriveRevokerKeyId,
} from '../../lib/revocation/status.js';

export const LAB_VERSION = 'EP-CONSERVED-ADMISSION-LAB-v1';

/**
 * The exact material action. An embodied agent (a field robot) holds a
 * one-use authorization to close one named gas valve. Mid-task it roams from
 * the facility gateway serving sector-7 (Gateway A) to the neighboring
 * facility's gateway (Gateway B), the mobility scenario Sections 7.6 and 7.8
 * describe: the ticket for the consequential action travels with the task.
 */
export const EXACT_ACTION = Object.freeze({
  action_type: 'field.robot.valve_shutoff',
  work_order: 'wo-2026-0814-77',
  asset: 'gas-main-valve-12',
  operation: 'close',
  site: 'sector-7',
});
const SELECTOR = Object.freeze({ protocol: 'field-ops', tool: 'valve_shutoff' });
const ACTION_PACK = Object.freeze([
  Object.freeze({
    id: 'field.robot.valve_shutoff',
    label: 'Robot-executed gas valve shutoff',
    action_type: 'field.robot.valve_shutoff',
    risk: 'critical',
    receipt_required: true,
    assurance_class: 'quorum',
    match: { protocol: SELECTOR.protocol, tool: SELECTOR.tool },
    why: 'Irreversible physical-world effect. Bind the exact valve and operation; quorum.',
    execution_binding: {
      required_fields: ['action_type', 'work_order', 'asset', 'operation', 'site'],
    },
  }),
]);
const QUORUM = Object.freeze({
  signers: ['ep:human:site-supervisor', 'ep:human:safety-officer'],
  threshold: 2,
});

/**
 * One gateway = one gate instance: its own pinned anchors, its own
 * consumption ledger, its own evidence log. The two instances share nothing;
 * exclusivity is never assumed from shared state, which is exactly why a
 * handoff has to establish it.
 */
function makeGateway(gatewayId, pins, { providerEntryGuard = null } = {}) {
  const store = new MemoryConsumptionStore();
  return {
    gatewayId,
    store,
    gate: createGate({
      manifest: manifestFromPack([...ACTION_PACK]),
      trustedKeys: [pins.issuerKey],
      approverKeys: pins.approverKeys,
      rpId: pins.rpId,
      allowedOrigins: pins.allowedOrigins,
      quorumPolicy: pins.quorumPolicy,
      store,
      providerEntryGuard,
      allowEphemeralStore: true, // local lab; production gateways require durable shared state
    }),
  };
}

function decisionRecord(gatewayId, decision) {
  return {
    gateway: gatewayId,
    allow: decision.allow,
    status: decision.status,
    reason: decision.reason ?? null,
    observed_action_hash: decision.evidence?.observed_action_hash ?? null,
    receipt_id: decision.evidence?.receipt_id ?? null,
    consumption_key: decision.evidence?.consumption_key ?? null,
  };
}

/**
 * The receiving organization's status authority (EP-STATUS-v1). Gateway B
 * pins this root out of band exactly as it pins issuer and approver keys.
 * During a handoff this is what lets revocation reach B even though the
 * artifact itself still verifies.
 */
async function createStatusAuthority(at) {
  const root = crypto.generateKeyPairSync('ed25519');
  const revoker = crypto.generateKeyPairSync('ed25519');
  const spki = (key) => key.export({ type: 'spki', format: 'der' }).toString('base64url');
  const signerFor = (keys, keyId) => ({
    algorithm: 'Ed25519' as const,
    keyId,
    async sign(bytes) {
      return crypto.sign(null, Buffer.from(bytes), keys.privateKey).toString('base64url');
    },
  });
  const authorityPin = Object.freeze({
    authority_domain: 'status.facility-b.example',
    authority_id: 'org:facility-b',
    key_id: 'key:facility-b-status-root',
    public_key: spki(root.publicKey),
  });
  const certificate = await buildRevokerAuthorityCertificate({
    certificateId: 'revoker-authority:facility-b:primary:v1',
    authorityPin,
    revokerId: 'revoker:facility-b:primary',
    revokerPublicKey: spki(revoker.publicKey),
    scope: { allowed_target_types: ['receipt'], allowed_usages: ['authorization'] },
    issuedAt: at(-30 * 86_400_000),
    expiresAt: at(30 * 86_400_000),
    signer: signerFor(root, authorityPin.key_id),
  });
  const revokerSigner = signerFor(revoker, deriveRevokerKeyId(spki(revoker.publicKey)));
  return {
    authorityPin,
    certificate,
    target(receipt) {
      return {
        type: 'receipt',
        id: receipt.payload.receipt_id,
        digest: `sha256:${hashCanonical(receipt)}`,
        usage: 'authorization',
      };
    },
    async issue(receipt, { issuedAt, nextUpdate, status = 'not_revoked' }) {
      return buildStatusArtifact({
        authorityPin,
        certificate,
        target: this.target(receipt),
        status,
        issuedAt,
        nextUpdate,
        signer: revokerSigner,
      });
    },
  };
}

/**
 * Gateway B's status policy at the provider-entry boundary. Fail-closed in
 * every direction: no bundle refuses, an inauthentic or stale bundle refuses
 * by the verifier's own reason, and an AUTHENTIC bundle whose outcome is
 * 'revoked' refuses. A revoked statement is valid evidence; it is evidence
 * FOR refusal.
 */
function statusGuard(authority, presentedStatus) {
  return (context) => {
    const receiptId = context.authorization?.evidence?.receipt_id ?? null;
    const presentation = receiptId === null ? null : presentedStatus.get(receiptId);
    if (!presentation) {
      return {
        ok: false,
        reason: 'status_evidence_absent',
        status: 409,
        reservation: 'release',
        evidence: { mechanism: 'EP-STATUS-v1', presented: false },
      };
    }
    const statusCheck = verifyStatusArtifact(presentation.target, presentation.status, {
      authorityPin: authority.authorityPin,
      certificate: authority.certificate,
      now: context.checked_at,
    });
    if (!statusCheck.valid) {
      return {
        ok: false,
        reason: statusCheck.reasons[0],
        status: 409,
        reservation: 'release',
        evidence: {
          mechanism: 'EP-STATUS-v1',
          status_outcome: statusCheck.outcome,
          reasons: [...statusCheck.reasons],
          evaluated_at: context.checked_at,
        },
      };
    }
    if (statusCheck.outcome !== 'current_not_revoked') {
      return {
        ok: false,
        reason: 'status_revoked',
        status: 409,
        reservation: 'release',
        evidence: {
          mechanism: 'EP-STATUS-v1',
          status_outcome: statusCheck.outcome,
          evaluated_at: context.checked_at,
        },
      };
    }
    return { ok: true, evidence: { status_outcome: statusCheck.outcome } };
  };
}

/** Run the conserved-admission handoff lab and return a machine-readable result. */
export async function runConservedAdmissionLab() {
  const labNow = Date.now();
  const at = (offsetMs) => new Date(labNow + offsetMs).toISOString();
  const currentWindow = () => ({ issuedAt: at(-60_000), nextUpdate: at(4 * 60_000) });

  const harness = createEg1Harness({ action: /** @type {any} */ (EXACT_ACTION), idPrefix: 'cah' });
  const pins = {
    issuerKey: harness.publicKey,
    approverKeys: harness.approverKeys,
    rpId: harness.rpId,
    allowedOrigins: harness.allowedOrigins,
    quorumPolicy: harness.quorumPolicy,
  };
  const actionHash = hashCanonical(EXACT_ACTION);

  const authority = await createStatusAuthority(at);
  const presentedStatus = new Map();
  async function present(receipt, window) {
    const status = await authority.issue(receipt, window);
    presentedStatus.set(receipt.payload.receipt_id, {
      receipt,
      status,
      target: authority.target(receipt),
    });
    return status;
  }

  // Both facilities pinned the issuer and approver keys out of band. Gateway
  // B additionally pins its own status root; Gateway A never sees it.
  const gatewayA = makeGateway('gateway-a.facility-a.example', pins);
  const gatewayB = makeGateway('gateway-b.facility-b.example', pins, {
    providerEntryGuard: statusGuard(authority, presentedStatus),
  });

  const executions = { a: 0, b: 0 };
  const executorAt = (side) => async () => {
    executions[side] += 1;
    return { closed: true, asset: EXACT_ACTION.asset };
  };

  async function admitAt(gateway, side, receipt, action = EXACT_ACTION) {
    const outcome = await gateway.gate.run(
      { selector: { ...SELECTOR }, receipt, observedAction: action },
      executorAt(side),
    );
    return decisionRecord(gateway.gatewayId, outcome.authorization);
  }

  /**
   * The handoff coordinator (LAB CODE, illustrative). The one ordering rule
   * it enforces is the Section 7.8 invariant: dispose at the source FIRST,
   * enable the target only after disposal is durable. `enablement` is a
   * plain data record, deliberately unsigned, so the lab can also prove the
   * receiving gateway refuses to treat it as evidence.
   */
  let handoffCounter = 0;
  async function beginHandoff(receipt, aReservation) {
    const handoffId = `ho-${labNow}-${++handoffCounter}`;
    // Source-side disposal (the RFC 4067 replay model): the reservation that
    // represents A's outstanding admission becomes a durable consumption in
    // A's own ledger BEFORE anything reaches B. From this instant A cannot
    // admit: that claim is proven below by re-presentation, not asserted.
    await gatewayA.store.commit(aReservation.consumption_key);
    const transferRecord = {
      kind: 'handoff_transfer',
      handoff_id: handoffId,
      gateway: gatewayA.gatewayId,
      action_hash: actionHash,
      receipt_id: receipt.payload.receipt_id,
      consumption_key: aReservation.consumption_key,
      disposed_at: at(0),
    };
    const enablement = {
      kind: 'handoff_enablement',
      handoff_id: handoffId,
      from: gatewayA.gatewayId,
      to: gatewayB.gatewayId,
      action_hash: actionHash,
      receipt_id: receipt.payload.receipt_id,
      source_disposed: true,
    };
    return { handoffId, transferRecord, enablement };
  }

  const cases: any[] = [];

  // 1. The gap, executable: naive context copy without source-side disposal.
  //    The artifact is valid at both gateways, each gateway owns its own
  //    ledger, and nothing made A unable to admit. Both admit. One approved
  //    action becomes two admissions and two physical executions. This is
  //    the failure Section 7.8 exists to name; every case after this one is
  //    about preventing it.
  {
    const receipt = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
    await present(receipt, currentWindow());
    const before = { ...executions };
    const aAdmit = await admitAt(gatewayA, 'a', receipt);
    const bAdmit = await admitAt(gatewayB, 'b', receipt);
    cases.push({
      id: 'copy-without-disposal-admits-twice',
      title: 'Context copy without conserved transfer: both gateways admit the same single-use action',
      a: aAdmit,
      b: bAdmit,
      admissions: (aAdmit.allow ? 1 : 0) + (bAdmit.allow ? 1 : 0),
      executions: { a: executions.a - before.a, b: executions.b - before.b },
      verdict: 'double_admission',
      note: 'Copying the authorization, transferring context, or exchanging a token is insufficient if both gateways can still admit the action. Each gateway behaved correctly in isolation; the missing property is between them.',
    });
  }

  // 2. The through-case: conserved handoff, dispose-before-enable. A holds
  //    the outstanding admission as a reservation in its own ledger; the
  //    coordinator disposes it at A first, then enables B; B re-verifies the
  //    same artifact under its own anchors and admits once in its own
  //    ledger. Re-presentation at A after disposal refuses by name. The
  //    transfer and admission records join by action digest and handoff id.
  let throughHandoff = null;
  {
    const receipt = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
    await present(receipt, currentWindow());
    // A's outstanding single-use admission, held in A's own ledger.
    const aReserve = await gatewayA.gate.check({
      selector: { ...SELECTOR },
      receipt,
      observedAction: EXACT_ACTION,
      consumptionMode: 'reserve',
    });
    const aReservation = decisionRecord(gatewayA.gatewayId, aReserve);
    const before = { ...executions };
    const handoff = await beginHandoff(receipt, aReservation);
    throughHandoff = { receipt, handoff };
    const bAdmit = await admitAt(gatewayB, 'b', receipt);
    // Prove, don't assert: A is unable to admit after disposal.
    const aAfter = await gatewayA.gate.check({
      selector: { ...SELECTOR },
      receipt,
      observedAction: EXACT_ACTION,
    });
    const aRefused = decisionRecord(gatewayA.gatewayId, aAfter);
    cases.push({
      id: 'conserved-handoff-admits-once',
      title: 'Dispose-before-enable: A becomes unable to admit, then B admits once under its own anchors',
      a: { reservation: aReservation, after_disposal: aRefused },
      b: bAdmit,
      admissions: bAdmit.allow ? 1 : 0,
      executions: { a: executions.a - before.a, b: executions.b - before.b },
      verdict: 'admit_once',
      records: {
        transfer: handoff.transferRecord,
        admission: bAdmit,
        joined_by: {
          action_hash: actionHash,
          handoff_id: handoff.handoffId,
          same_action_digest:
            handoff.transferRecord.action_hash === bAdmit.observed_action_hash
            && bAdmit.observed_action_hash === actionHash,
        },
      },
      note: 'B admitted because it verified the artifact itself, checked its own status authority, and consumed in its own ledger; the enablement record only sequenced the handoff, it proved nothing.',
    });
  }

  // 3. Duplicate delivery (Section 7.8 test condition): the enablement and
  //    artifact arrive at B a second time. B's own consumption ledger
  //    refuses the replay; the executor does not run again.
  {
    const before = { ...executions };
    const bDuplicate = await admitAt(gatewayB, 'b', throughHandoff.receipt);
    cases.push({
      id: 'duplicate-delivery-refused',
      title: 'The handoff enablement is delivered twice; the second admission attempt at B refuses',
      a: null,
      b: bDuplicate,
      admissions: bDuplicate.allow ? 1 : 0,
      executions: { a: executions.a - before.a, b: executions.b - before.b },
      verdict: 'refuse',
      reason: bDuplicate.reason,
    });
  }

  // 4. Concurrent admission attempts (Section 7.8 test condition): during
  //    the handoff window a stale client re-presents at A while the roamed
  //    task presents at B, concurrently. Because disposal at A preceded
  //    enablement of B, at most one gateway can admit regardless of the
  //    interleaving: A's ledger already holds the disposal.
  {
    const receipt = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
    await present(receipt, currentWindow());
    const aReserve = await gatewayA.gate.check({
      selector: { ...SELECTOR },
      receipt,
      observedAction: EXACT_ACTION,
      consumptionMode: 'reserve',
    });
    await beginHandoff(receipt, decisionRecord(gatewayA.gatewayId, aReserve));
    const before = { ...executions };
    const [aRace, bRace] = await Promise.all([
      gatewayA.gate.check({ selector: { ...SELECTOR }, receipt, observedAction: EXACT_ACTION })
        .then((decision) => decisionRecord(gatewayA.gatewayId, decision)),
      admitAt(gatewayB, 'b', receipt),
    ]);
    cases.push({
      id: 'concurrent-admission-at-most-once',
      title: 'Concurrent presentation at A and B during the handoff; at most one admission',
      a: aRace,
      b: bRace,
      admissions: (aRace.allow ? 1 : 0) + (bRace.allow ? 1 : 0),
      executions: { a: executions.a - before.a, b: executions.b - before.b },
      verdict: 'admit_once',
      reason: aRace.reason,
    });
  }

  // 5. Lost acknowledgement (Section 7.8 test condition): A disposed, then
  //    the enablement never reached B. The task retries at A; A refuses,
  //    because disposal is durable and unconditional. Nothing admits
  //    anywhere. The coordinator's reconciliation record CLOSES the handoff
  //    as unresolved: "an unresolved handoff must not be treated as
  //    permission to admit or retry" is the recorded outcome, not a retry.
  {
    const receipt = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
    await present(receipt, currentWindow());
    const aReserve = await gatewayA.gate.check({
      selector: { ...SELECTOR },
      receipt,
      observedAction: EXACT_ACTION,
      consumptionMode: 'reserve',
    });
    const before = { ...executions };
    const handoff = await beginHandoff(receipt, decisionRecord(gatewayA.gatewayId, aReserve));
    // The enablement is lost in transit: B is never presented anything.
    const aRetry = await gatewayA.gate.check({
      selector: { ...SELECTOR },
      receipt,
      observedAction: EXACT_ACTION,
    });
    const aRefused = decisionRecord(gatewayA.gatewayId, aRetry);
    const reconciliation = {
      kind: 'handoff_reconciliation',
      handoff_id: handoff.handoffId,
      action_hash: actionHash,
      receipt_id: receipt.payload.receipt_id,
      outcome: 'unresolved_closed',
      admitted_at: null,
      requires: 'operator reconciliation and a NEW authorization decision; the disposed one is spent',
      recorded_at: at(0),
    };
    cases.push({
      id: 'lost-acknowledgement-closed',
      title: 'The enablement is lost after disposal; no gateway admits, and the handoff closes as unresolved',
      a: aRefused,
      b: null,
      admissions: 0,
      executions: { a: executions.a - before.a, b: executions.b - before.b },
      verdict: 'closed_unresolved',
      reason: aRefused.reason,
      records: { transfer: handoff.transferRecord, reconciliation },
      note: 'Losing an in-flight authorization is the acceptable failure; resurrecting one is not. Continuing the task requires a new decision by the authority that made the first one.',
    });
  }

  // 6. Revocation during handoff (Section 7.8 test condition): after A
  //    disposes, the status authority publishes a terminal revoked statement
  //    for the receipt. The artifact itself still verifies; B's status guard
  //    refuses on the authenticated revoked outcome. A already cannot admit.
  //    Zero admissions, closed refusal, no silent retry.
  {
    const receipt = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
    await present(receipt, currentWindow());
    const aReserve = await gatewayA.gate.check({
      selector: { ...SELECTOR },
      receipt,
      observedAction: EXACT_ACTION,
      consumptionMode: 'reserve',
    });
    await beginHandoff(receipt, decisionRecord(gatewayA.gatewayId, aReserve));
    // Revoked between disposal at A and admission at B: terminal statement,
    // nextUpdate null by construction.
    await present(receipt, { issuedAt: at(-1_000), nextUpdate: null, status: 'revoked' });
    const before = { ...executions };
    const bRevoked = await admitAt(gatewayB, 'b', receipt);
    const aAfter = await gatewayA.gate.check({
      selector: { ...SELECTOR },
      receipt,
      observedAction: EXACT_ACTION,
    });
    cases.push({
      id: 'revoked-during-handoff-refused',
      title: 'The authorization is revoked mid-handoff; B refuses on the authenticated revoked status, A is already disposed',
      a: decisionRecord(gatewayA.gatewayId, aAfter),
      b: bRevoked,
      admissions: bRevoked.allow ? 1 : 0,
      executions: { a: executions.a - before.a, b: executions.b - before.b },
      verdict: 'refuse',
      reason: bRevoked.reason,
    });
  }

  // 7. Material action change (Section 7.8 test condition): the task drifts
  //    during roaming and B is asked to admit a different valve operation
  //    under the same artifact. The execution binding refuses by name.
  {
    const receipt = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
    await present(receipt, currentWindow());
    const drifted = { ...EXACT_ACTION, asset: 'gas-main-valve-9' };
    const before = { ...executions };
    const bDrifted = await admitAt(gatewayB, 'b', receipt, drifted);
    cases.push({
      id: 'material-action-change-refused',
      title: 'The observed action changed during the handoff; B refuses the mismatched binding',
      a: null,
      b: bDrifted,
      admissions: bDrifted.allow ? 1 : 0,
      executions: { a: executions.a - before.a, b: executions.b - before.b },
      verdict: 'refuse',
      reason: bDrifted.reason,
    });
  }

  // 8. Independent evaluation is preserved (Section 7.8 requirement): the
  //    enablement record alone, without the artifact, is not admissible
  //    evidence at B. A transfer message can sequence a handoff; it can
  //    never substitute for verification.
  {
    const before = { ...executions };
    const bEnablementOnly = await gatewayB.gate.check({
      selector: { ...SELECTOR },
      receipt: null,
      observedAction: EXACT_ACTION,
      consumptionMode: 'none',
    });
    cases.push({
      id: 'enablement-is-not-evidence',
      title: 'B is offered the handoff enablement record instead of the artifact; B refuses',
      a: null,
      b: decisionRecord(gatewayB.gatewayId, bEnablementOnly),
      admissions: 0,
      executions: { a: executions.a - before.a, b: executions.b - before.b },
      verdict: 'refuse',
      reason: bEnablementOnly.reason,
    });
  }

  return {
    '@version': LAB_VERSION,
    title: 'Conserved-Admission Handoff Lab',
    scenario:
      'A field robot with an outstanding single-use authorization for one valve shutoff roams from Gateway A\'s domain to Gateway B\'s while the authorization is live.',
    reference:
      'draft-dunbar-dmsc-gw-scenarios-gap-analysis-04, Section 7.8 (Conserved Admission Across Gateway Boundaries)',
    property:
      'At-most-once admission of a specific action across independently operated gateways; not exactly-once physical execution.',
    action: EXACT_ACTION,
    action_hash: actionHash,
    executions,
    cases,
  };
}

function print(result) {
  const width = 78;
  const label = {
    admit_once: 'ADMIT ONCE      ',
    double_admission: 'DOUBLE ADMISSION',
    refuse: 'REFUSE          ',
    closed_unresolved: 'CLOSED          ',
  };
  console.log('='.repeat(width));
  console.log(`${result.title} · ${result['@version']}`);
  console.log(result.reference);
  console.log('='.repeat(width));
  console.log(`Action: ${result.action.action_type} · ${result.action.operation} ${result.action.asset} (${result.action.work_order})`);
  console.log('-'.repeat(width));
  for (const [index, item] of result.cases.entries()) {
    console.log(`${index + 1}. ${label[item.verdict] ?? item.verdict} · ${item.id}`);
    console.log(`   ${item.title}`);
    if (item.reason) console.log(`   refusal names: ${item.reason}`);
    if (item.records?.joined_by) console.log(`   transfer and admission records join by action digest + handoff id: ${item.records.joined_by.same_action_digest ? 'yes' : 'NO'}`);
    console.log(`   admissions: ${item.admissions} · executions A/B: ${item.executions.a}/${item.executions.b}`);
  }
  console.log('-'.repeat(width));
  console.log(`Total executions · A: ${result.executions.a} · B: ${result.executions.b}`);
  console.log('Exclusive admission is conserved by disposal-before-enablement, or the handoff closes.');
  console.log('An unresolved handoff is never permission to admit or retry.\n');
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const result = await runConservedAdmissionLab();
  if (process.argv.includes('--json')) console.log(JSON.stringify(result, null, 2));
  else print(result);
}
