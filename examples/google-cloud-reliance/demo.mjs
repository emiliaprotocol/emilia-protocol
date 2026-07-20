#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * External Reliance Lab for Google Cloud-shaped mutations.
 *
 * This is a local compatibility demonstration, not a Google product and not a
 * live call to Google Cloud. The injected client has the same system-of-record
 * boundary as a real SDK or MCP proxy: if EMILIA refuses, setIamPolicy is never
 * called. The simulated IAM and Model Armor decisions are deliberately ALLOW;
 * the point is to exercise the separate question an external relying party asks:
 * did this exact consequential action clear the evidence bar WE pinned?
 */
import {
  createGate,
  createEg1Harness,
} from '../../packages/gate/index.js';
import { gateMcpTool } from '../../packages/gate/mcp.js';
import { createGcpManifest } from '../../packages/gate/adapters/gcp.js';

export const LAB_VERSION = 'EP-GCP-EXTERNAL-RELIANCE-LAB-v1';

export const EXACT_ACTION = Object.freeze({
  action_type: 'gcp.iam.set_policy',
  resource: 'projects/acme-regulated-prod',
  member: 'serviceAccount:gemini-ops@acme-regulated-prod.iam.gserviceaccount.com',
  role: 'roles/owner',
});

export const LOCAL_CONTROL_RESULT = Object.freeze({
  note: 'illustrative local-control decisions; no Google service was called',
  iam: Object.freeze({ verdict: 'allow', principal_authenticated: true, permission_granted: true }),
  model_armor: Object.freeze({ verdict: 'allow', prompt_injection_detected: false }),
});

const QUORUM = Object.freeze({ signers: ['ep:human:change-owner', 'ep:human:security-reviewer'], threshold: 2 });

/** @param {{ action?: any, idPrefix?: string }} [o] */
function makeSubject({ action = EXACT_ACTION, idPrefix = 'gcp_rc1' } = {}) {
  const harness = createEg1Harness({ action, idPrefix });
  const gate = createGate({
    manifest: createGcpManifest(),
    trustedKeys: [harness.publicKey],
    approverKeys: harness.approverKeys,
    rpId: harness.rpId,
    allowedOrigins: harness.allowedOrigins,
    quorumPolicy: harness.quorumPolicy,
    allowEphemeralStore: true, // local compatibility lab; production Gate requires durable shared state
  });
  const calls = [];
  const client = {
    async setIamPolicy(params) {
      calls.push(structuredClone(params));
      return {
        applied: true,
        etag: 'illustrative-etag-after-write',
        resource: params.resource,
        member: params.member,
        role: params.role,
      };
    },
  };
  const tool = gateMcpTool(gate, {
    protocol: 'gcp',
    tool: 'set_iam_policy',
    observedAction: (args) => ({
      action_type: 'gcp.iam.set_policy',
      resource: args.resource,
      member: args.member,
      role: args.role,
    }),
  }, (args) => client.setIamPolicy(paramsFor(args)));
  return { harness, gate, client, calls, tool };
}

function refusal(id, title, error, callsBefore, callsAfter) {
  return {
    id,
    title,
    local_controls: 'allow',
    verdict: 'refuse',
    status: error?.status ?? null,
    reason: error?.gate?.reason || error?.message || 'unknown_refusal',
    executor_called: callsAfter > callsBefore,
  };
}

async function expectRefusal(id, title, subject, invoke) {
  const before = subject.calls.length;
  try {
    await invoke();
  } catch (error) {
    return refusal(id, title, error, before, subject.calls.length);
  }
  throw new Error(`${id}: expected refusal, but the mutation ran`);
}

/**
 * @param {{ '@version': string, payload: object, signature: { algorithm: string, value: string } } | null} [receipt]
 *   evidence minted by harness.mint() (see createEg1Harness in packages/gate/eg1-conformance.js), or null/omitted for "no evidence".
 */
async function callMcpTool(subject, action = EXACT_ACTION, receipt = null) {
  const result = await subject.tool({
    ...paramsFor(action),
    ...(receipt ? { _emilia_receipt: receipt } : {}),
  });
  if (result?.isError) {
    const error = /** @type {Error & { status?: unknown, gate?: unknown, challenge?: unknown }} */ (
      new Error(result._emilia?.reason || 'mcp_tool_refused')
    );
    error.status = result._emilia?.status;
    error.gate = { reason: result._emilia?.reason };
    error.challenge = result._emilia?.challenge;
    throw error;
  }
  return result;
}

function paramsFor(action = EXACT_ACTION) {
  return {
    resource: action.resource,
    member: action.member,
    role: action.role,
  };
}

/** Run the six-case compatibility lab and return a machine-readable result. */
export async function runGoogleCloudRelianceLab() {
  const main = makeSubject();
  const cases = [];

  cases.push(await expectRefusal(
    'local-controls-allow-but-evidence-missing',
    'IAM and content controls allow; customer evidence is absent',
    main,
    () => callMcpTool(main),
  ));

  cases.push(await expectRefusal(
    'single-approver-cannot-fill-two-person-rule',
    'one human cannot satisfy the customer-pinned quorum',
    main,
    () => callMcpTool(main, EXACT_ACTION, main.harness.mint({ outcome: 'allow_with_signoff' })),
  ));

  const weakerAction = { ...EXACT_ACTION, role: 'roles/viewer' };
  const drift = makeSubject({ action: weakerAction, idPrefix: 'gcp_drift' });
  cases.push(await expectRefusal(
    'receipt-for-viewer-cannot-grant-owner',
    'evidence for roles/viewer cannot authorize roles/owner',
    drift,
    () => callMcpTool(
      drift,
      EXACT_ACTION,
      drift.harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM }),
    ),
  ));

  cases.push(await expectRefusal(
    'tampered-receipt-refused',
    'a signed receipt altered after issuance is not evidence',
    main,
    () => callMcpTool(
      main,
      EXACT_ACTION,
      main.harness.mint({
        outcome: 'allow_with_signoff',
        quorum: QUORUM,
        tamper: { role: 'roles/editor' },
      }),
    ),
  ));

  const receipt = main.harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
  const beforeValid = main.calls.length;
  const accepted = await callMcpTool(main, EXACT_ACTION, receipt);
  cases.push({
    id: 'exact-quorum-evidence-runs-once',
    title: 'the exact action clears a genuine two-person ceremony',
    local_controls: 'allow',
    verdict: 'rely',
    status: 200,
    reason: null,
    executor_called: main.calls.length === beforeValid + 1,
    receipt_id: receipt.payload.receipt_id,
    reliance_verdict: accepted._emilia?.reliance?.verdict ?? null,
    execution_binds_authorization:
      accepted._emilia?.execution?.authorizes_decision
        === accepted._emilia?.reliance?.summary?.decision_hash,
  });

  cases.push(await expectRefusal(
    'accepted-receipt-replay-refused',
    'the same accepted evidence cannot drive a second mutation',
    main,
    () => callMcpTool(main, EXACT_ACTION, receipt),
  ));

  return {
    '@version': LAB_VERSION,
    title: 'External Reliance Lab for Google Cloud-shaped mutations',
    disclaimer: 'Independent open-source compatibility demonstration. Not affiliated with or endorsed by Google.',
    local_controls: LOCAL_CONTROL_RESULT,
    relying_party_requirement: {
      mcp_tool: 'set_iam_policy',
      action: EXACT_ACTION,
      assurance_class: 'quorum',
      exact_fields: ['action_type', 'resource', 'member', 'role'],
      one_time_consumption: true,
      verifier_trust: 'relying-party-pinned issuer and approver keys',
    },
    cases,
    executor_call_count: main.calls.length,
    invariant: 'local controls may allow, but only exact, sufficiently assured, unused evidence reaches the executor',
  };
}

function print(result) {
  const width = 76;
  console.log('\nEXTERNAL RELIANCE LAB · GOOGLE CLOUD-SHAPED MUTATION');
  console.log('='.repeat(width));
  console.log('Illustrative Google-side controls: IAM ALLOW · Model Armor ALLOW');
  console.log(`Customer-pinned action: ${result.relying_party_requirement.action.resource}`);
  console.log(`                        ${result.relying_party_requirement.action.member}`);
  console.log(`                        ${result.relying_party_requirement.action.role}`);
  console.log('-'.repeat(width));
  for (const [index, item] of result.cases.entries()) {
    const verdict = item.verdict === 'rely' ? 'RELY  ' : 'REFUSE';
    console.log(`${index + 1}. ${verdict} · ${item.id}`);
    console.log(`   ${item.title}`);
    if (item.reason) console.log(`   reason: ${item.reason}`);
    console.log(`   executor called: ${item.executor_called ? 'yes' : 'no'}`);
    if (item.reliance_verdict) {
      console.log(`   reliance packet: ${item.reliance_verdict}`);
      console.log(`   execution binds authorization: ${item.execution_binds_authorization ? 'yes' : 'no'}`);
    }
  }
  console.log('-'.repeat(width));
  console.log(`Real mutation count: ${result.executor_call_count} (expected exactly 1)`);
  console.log('IAM answers who may call. Content controls inspect the call.');
  console.log('EMILIA lets the customer verify why this exact consequence may execute.');
  console.log('Independent demonstration; no Google service was called.\n');
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const result = await runGoogleCloudRelianceLab();
  if (process.argv.includes('--json')) console.log(JSON.stringify(result, null, 2));
  else print(result);
}
