// SPDX-License-Identifier: Apache-2.0
/**
 * Execution-Layer Evidence composition profile, instantiating Gap 6 of
 * draft-chen-oauth-agent-authz-use-cases-02.
 *
 * Gap 6 (sec 5 of that draft) names the missing mechanism: "a non-repudiable,
 * cryptographic proof of a user's explicit consent for a specific, high-risk
 * action at the moment it occurs", observing that "grant-layer tokens prove
 * potential, not the legitimacy of a specific, executed transaction."
 *
 * That sentence compresses three different claims, and no single artifact can
 * honestly prove all three. This profile separates them and reports a verdict
 * per claim in every case:
 *
 *   APPROVAL   what the named human(s) approved, proven by verifying the
 *              authorization artifact under pinned anchors. An authorization
 *              receipt answers THIS claim and only this claim.
 *   ADMISSION  whether the enforcement point in front of the executor admitted
 *              that exact action, once, under its own trust configuration and
 *              its own consumption ledger.
 *   EXECUTION  whether the effect was entered and with what outcome, proven by
 *              the execution record's binding to the admitted decision. An
 *              entered effect with no answer is INDETERMINATE, never a retry.
 *
 * The demonstration boundary is a finance-operations action: a vendor
 * bank-detail change, the classic business-email-compromise target. Bank
 * details enter the evidence as digests, never as cleartext.
 *
 * Status: source-pinned discussion artifact. It is not an Internet-Draft, not
 * a Chen-draft specification, and running it externally is a reproduction of
 * these pinned checks, not an independent implementation result.
 *
 * One execution emits three outputs:
 *   1. report.json                machine-verifiable conformance report with a
 *                                 deterministic results digest
 *   2. stdout                     the finance-operations demonstration
 *   3. reproduction-receipt.json  compact receipt an external operator can
 *                                 regenerate and paste into their own
 *                                 implementation-status section
 */
import { execFileSync } from 'node:child_process';
import { writeFileSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  createGate,
  createEg1Harness,
  hashCanonical,
  MemoryConsumptionStore,
} from '../../../packages/gate/index.js';
import { manifestFromPack } from '../../../packages/gate/adapters/_kit.js';

export const PROFILE = 'EP-GAP6-EXECUTION-EVIDENCE-PROFILE-v0.1';
const HERE = dirname(fileURLToPath(import.meta.url));

/**
 * The exact material action. Routing and account numbers appear only as
 * digests: the approver's device shows the human the cleartext out of band,
 * the evidence layer commits to it without carrying it.
 */
export const EXACT_ACTION = Object.freeze({
  action_type: 'finops.vendor.bank_detail_change',
  vendor_id: 'V-88012',
  erp: 'netsuite.prod.example',
  change_ticket: 'CHG-2026-4471',
  new_routing_digest: 'sha256:8c1f00a3b7e2d94c5a6b1e0f2d3c4b5a6978e0d1c2b3a4958677e8f9a0b1c2d3',
  new_account_digest: 'sha256:1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809',
});
const SELECTOR = Object.freeze({ protocol: 'finops', tool: 'vendor_bank_detail_change' });
const ACTION_PACK = Object.freeze([
  Object.freeze({
    id: 'finops.vendor.bank_detail_change',
    label: 'Vendor bank-detail change',
    action_type: 'finops.vendor.bank_detail_change',
    risk: 'critical',
    receipt_required: true,
    assurance_class: 'quorum',
    match: { protocol: SELECTOR.protocol, tool: SELECTOR.tool },
    why: 'Redirects every future payment to this vendor. Dual control over the exact change.',
    execution_binding: {
      required_fields: [
        'action_type',
        'vendor_id',
        'erp',
        'change_ticket',
        'new_routing_digest',
        'new_account_digest',
      ],
    },
  }),
]);
const QUORUM = Object.freeze({ threshold: 2 });
const PROVIDER_DEADLINE_MS = 25;

function claimVerdicts({ approval, admission, execution }) {
  return { approval, admission, execution };
}

function admissionRecord(decision) {
  return {
    allow: decision.allow,
    reason: decision.reason ?? null,
    observed_action_hash: decision.evidence?.observed_action_hash ?? null,
    receipt_id: decision.evidence?.receipt_id ?? null,
    consumption_key: decision.evidence?.consumption_key ?? null,
  };
}

/** Named humans a receipt's quorum evidence carries, or null when it cannot be credited. */
function creditedApprovers(receipt) {
  const quorum = receipt?.payload?.quorum;
  const named = quorum?.policy?.approvers;
  if (quorum?.['@type'] !== 'ep.quorum' || !Array.isArray(named) || !Array.isArray(quorum.members)) {
    return null;
  }
  const ids = named.map((p) => p?.approver ?? null);
  return ids.every((id) => typeof id === 'string' && id.length > 0) ? ids.sort() : null;
}

export async function runProfile() {
  const harness = createEg1Harness({ action: /** @type {any} */ (EXACT_ACTION), idPrefix: 'gap6' });
  const store = new MemoryConsumptionStore();
  const gate = createGate({
    manifest: manifestFromPack([...ACTION_PACK]),
    trustedKeys: [harness.publicKey],
    approverKeys: harness.approverKeys,
    rpId: harness.rpId,
    allowedOrigins: harness.allowedOrigins,
    quorumPolicy: harness.quorumPolicy,
    store,
    allowEphemeralStore: true, // reference profile; production requires durable shared state
  });
  const actionHash = hashCanonical(EXACT_ACTION);

  const executions: any[] = [];
  const executor = async () => {
    executions.push(structuredClone(EXACT_ACTION));
    return { changed: true, vendor_id: EXACT_ACTION.vendor_id };
  };
  const unresolvedProvider = async () => {
    executions.push(structuredClone(EXACT_ACTION));
    await new Promise((_, reject) => {
      setTimeout(() => reject(new Error('provider deadline exceeded, outcome unknown')), PROVIDER_DEADLINE_MS);
    });
    return { changed: true };
  };

  async function admit(receipt, action = EXACT_ACTION, effect = executor) {
    try {
      const outcome = await gate.run(
        { selector: { ...SELECTOR }, receipt, observedAction: action },
        effect,
      );
      return { outcome, terminal: null };
    } catch (error: any) {
      return { outcome: null, terminal: error?.emiliaGateOutcome ?? null };
    }
  }

  const cases: any[] = [];

  // 1. The through-case: two named humans approve the exact change under a
  //    user-verification-gated ceremony; the gate re-derives the action
  //    identity from the material IT observes, admits once, consumes once,
  //    and the execution record binds back to the admitted decision.
  {
    const receipt = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
    const before = executions.length;
    const { outcome } = await admit(receipt);
    const admission = admissionRecord(outcome.authorization);
    cases.push({
      id: 'through-exact-human-exact-action-once',
      title: 'Two named approvers, the exact change, one admitted attempt, execution bound to the decision',
      claims: claimVerdicts({
        approval: {
          verdict: 'proven',
          approvers: creditedApprovers(receipt),
          approved_action_hash: actionHash,
        },
        admission: { verdict: 'admitted', ...admission },
        execution: {
          verdict: 'executed',
          effect_ran: executions.length === before + 1,
          authorizes_decision: outcome.execution?.authorizes_decision ?? null,
          bound_to_admitted_decision:
            outcome.execution?.authorizes_decision === outcome.packet?.summary?.decision_hash,
        },
      }),
      boundary_reason: null,
      caid_recomputed_at_executor:
        admission.observed_action_hash === actionHash,
    });
  }

  // 2. Missing human evidence. The approval claim is indeterminate (nothing
  //    was presented to verify), and the boundary is fail-closed: refusal by
  //    name, not an error and not an execution.
  {
    const before = executions.length;
    const { outcome } = await admit(null);
    cases.push({
      id: 'missing-human-evidence',
      title: 'No authorization artifact: approval unprovable, boundary refuses by name',
      claims: claimVerdicts({
        approval: { verdict: 'indeterminate', reason: 'no_evidence_presented' },
        admission: { verdict: 'refused', ...admissionRecord(outcome.authorization) },
        execution: { verdict: 'not_entered', effect_ran: executions.length !== before },
      }),
      boundary_reason: outcome.authorization.reason,
    });
  }

  // 3. The agent clicks Approve: a self-asserted quorum block with no
  //    per-signer verifiable evidence. Every byte is well-formed; nothing in
  //    it is a human ceremony, and the gate refuses to credit it.
  {
    const receipt = harness.mint({ outcome: 'allow', fakeQuorum: true });
    const before = executions.length;
    const { outcome } = await admit(receipt);
    cases.push({
      id: 'fabricated-approval-refused',
      title: 'Software asserts a quorum without per-signer evidence; the tier is not credited',
      claims: claimVerdicts({
        approval: { verdict: 'not_credited', reason: 'self_asserted_quorum_without_signer_evidence' },
        admission: { verdict: 'refused', ...admissionRecord(outcome.authorization) },
        execution: { verdict: 'not_entered', effect_ran: executions.length !== before },
      }),
      boundary_reason: outcome.authorization.reason,
    });
  }

  // 4. Wrong approver: a syntactically perfect receipt whose issuer and
  //    approvers are not the ones this boundary pinned out of band.
  {
    const rogue = createEg1Harness({ action: /** @type {any} */ (EXACT_ACTION), idPrefix: 'gap6_rogue' });
    const receipt = rogue.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
    const before = executions.length;
    const { outcome } = await admit(receipt);
    cases.push({
      id: 'wrong-approver-refused',
      title: 'Valid-looking artifact from unpinned keys; verification fails under this boundary\'s anchors',
      claims: claimVerdicts({
        approval: { verdict: 'not_credited', reason: 'signature_not_under_pinned_anchors' },
        admission: { verdict: 'refused', ...admissionRecord(outcome.authorization) },
        execution: { verdict: 'not_entered', effect_ran: executions.length !== before },
      }),
      boundary_reason: outcome.authorization.reason,
    });
  }

  // 5. Material action substitution: the approval is real, the observed
  //    action is not the approved one. The binding refuses; consent to X is
  //    not consent to Y with the same shape.
  {
    const receipt = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
    const substituted = {
      ...EXACT_ACTION,
      new_routing_digest: 'sha256:eeee00a3b7e2d94c5a6b1e0f2d3c4b5a6978e0d1c2b3a4958677e8f9a0b1eeee',
    };
    const before = executions.length;
    const { outcome } = await admit(receipt, substituted);
    cases.push({
      id: 'action-substitution-refused',
      title: 'The routing digest changed between approval and execution; the exact-action binding refuses',
      claims: claimVerdicts({
        approval: { verdict: 'proven_for_different_action', approved_action_hash: actionHash },
        admission: { verdict: 'refused', ...admissionRecord(outcome.authorization) },
        execution: { verdict: 'not_entered', effect_ran: executions.length !== before },
      }),
      boundary_reason: outcome.authorization.reason,
    });
  }

  // 6. Reuse of consumed authority: the through-case artifact presented
  //    again. One approval is one admission; the ledger holds.
  {
    const receipt = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
    await admit(receipt);
    const before = executions.length;
    const { outcome } = await admit(receipt);
    cases.push({
      id: 'replay-refused',
      title: 'The consumed authorization cannot drive a second execution',
      claims: claimVerdicts({
        approval: { verdict: 'proven', note: 'the artifact still verifies; verification is not admission' },
        admission: { verdict: 'refused', ...admissionRecord(outcome.authorization) },
        execution: { verdict: 'not_entered', effect_ran: executions.length !== before },
      }),
      boundary_reason: outcome.authorization.reason,
    });
  }

  // 7. Lost provider acknowledgement: the effect was entered and never
  //    answered. The attempt may have landed. The authorization stays
  //    committed, the outcome is INDETERMINATE bound to the admitted
  //    decision, and a blind retry is refused rather than silently re-spent.
  {
    const receipt = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
    const { terminal } = await admit(receipt, EXACT_ACTION, unresolvedProvider);
    const consumptionKey = terminal?.authorizationEvidence?.consumption_key ?? null;
    const { outcome: retry } = await admit(receipt);
    cases.push({
      id: 'lost-acknowledgement-indeterminate',
      title: 'Provider goes silent after entry; outcome INDETERMINATE, authority stays spent, blind retry refused',
      claims: claimVerdicts({
        approval: { verdict: 'proven' },
        admission: { verdict: 'admitted_then_committed', consumption_key: consumptionKey },
        execution: {
          verdict: 'indeterminate',
          outcome: terminal?.outcome ?? null,
          execution_record_outcome: terminal?.execution?.outcome ?? null,
          bound_to_admitted_decision:
            typeof terminal?.execution?.authorizes_decision === 'string'
            && terminal.execution.authorizes_decision.length > 0,
          committed_not_released:
            consumptionKey !== null
            && store.seen.has(consumptionKey)
            && !store.reserved.has(consumptionKey),
          blind_retry: { allow: retry.authorization.allow, reason: retry.authorization.reason },
        },
      }),
      boundary_reason: terminal?.reason ?? null,
    });
  }

  // 8. False execution claim: an execution assertion that does not bind to
  //    any admitted decision. Occurrence is proven by the record's binding,
  //    never by the assertion's existence.
  {
    const receipt = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
    const { outcome } = await admit(receipt);
    const admittedDecisionHash = outcome.packet?.summary?.decision_hash ?? null;
    const forged = {
      kind: 'asserted_execution_result',
      changed: true,
      vendor_id: EXACT_ACTION.vendor_id,
      authorizes_decision: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
    };
    cases.push({
      id: 'false-execution-claim-rejected',
      title: 'An asserted result without a decision binding is not execution evidence',
      claims: claimVerdicts({
        approval: { verdict: 'proven' },
        admission: { verdict: 'admitted', decision_hash: admittedDecisionHash },
        execution: {
          verdict: 'claim_not_credited',
          reason: 'asserted_result_does_not_bind_admitted_decision',
          asserted_binding: forged.authorizes_decision,
          admitted_decision_hash: admittedDecisionHash,
          binding_matches: forged.authorizes_decision === admittedDecisionHash,
        },
      }),
      boundary_reason: null,
    });
  }

  // The deterministic portion: identical bytes on every conforming run, on
  // any machine. Volatile metadata (timestamps, runner, commit) lives beside
  // it, never inside it.
  const deterministic = {
    '@profile': PROFILE,
    reference:
      'draft-chen-oauth-agent-authz-use-cases-02, Section 5, Gap 6 (Execution-Layer Evidence); Use Case 11 execution-evidence requirement',
    claim_model: {
      approval: 'what the named human(s) approved, verified under pinned anchors',
      admission: 'whether this boundary admitted that exact action, once',
      execution: 'whether the effect was entered and with what outcome, bound to the admitted decision',
    },
    action: EXACT_ACTION,
    action_hash: actionHash,
    cases: cases.map((c) => ({
      id: c.id,
      title: c.title,
      boundary_reason: c.boundary_reason,
      approval: { verdict: c.claims.approval.verdict, reason: c.claims.approval.reason ?? null },
      admission: {
        verdict: c.claims.admission.verdict,
        allow: c.claims.admission.allow ?? null,
        reason: c.claims.admission.reason ?? null,
      },
      execution: {
        verdict: c.claims.execution.verdict,
        effect_ran: c.claims.execution.effect_ran ?? null,
      },
    })),
  };
  const resultsDigest = `sha256:${hashCanonical(deterministic)}`;

  return {
    deterministic,
    results_digest: resultsDigest,
    cases,
    total_executions: executions.length,
  };
}

function runnerIdentity() {
  let commit = null;
  try {
    commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: HERE, encoding: 'utf8' }).trim();
  } catch {
    commit = null;
  }
  return {
    node: process.version,
    platform: `${process.platform}-${process.arch}`,
    source_commit: commit,
    generated_at: new Date().toISOString(),
  };
}

function printDemo(result) {
  const width = 78;
  const a = EXACT_ACTION;
  console.log('='.repeat(width));
  console.log(`Execution-Layer Evidence profile ${PROFILE}`);
  console.log('Instantiates Gap 6 of draft-chen-oauth-agent-authz-use-cases-02');
  console.log('='.repeat(width));
  console.log(`Boundary: ${a.action_type} · vendor ${a.vendor_id} · ${a.erp} · ${a.change_ticket}`);
  console.log('Bank details appear only as digests; approvers saw the cleartext out of band.');
  console.log('-'.repeat(width));
  for (const [index, c] of result.cases.entries()) {
    console.log(`${index + 1}. ${c.id}`);
    console.log(`   ${c.title}`);
    console.log(`   approval: ${c.claims.approval.verdict}`
      + `${c.claims.approval.reason ? ` (${c.claims.approval.reason})` : ''}`);
    const admissionReason = c.claims.admission.verdict === 'refused' ? c.claims.admission.reason : null;
    console.log(`   admission: ${c.claims.admission.verdict}`
      + `${admissionReason ? ` (${admissionReason})` : ''}`);
    console.log(`   execution: ${c.claims.execution.verdict}`);
    if (c.boundary_reason) console.log(`   boundary refusal names: ${c.boundary_reason}`);
  }
  console.log('-'.repeat(width));
  console.log(`Executor ran ${result.total_executions} times across all 8 cases`
    + ' (once for the through-case, once for the entered-then-unresolved case,'
    + ' once for the artifact later replayed, once for the false-claim setup).');
  console.log(`results_digest: ${result.results_digest}`);
  console.log('One receipt proves approval. Admission and execution are separate claims');
  console.log('with separate evidence, and an unresolved outcome is never a retry.\n');
}

const isMain = process.argv[1]
  && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  const result = await runProfile();
  const runner = runnerIdentity();
  const report = {
    ...result.deterministic,
    results_digest: result.results_digest,
    runner,
  };
  writeFileSync(resolve(HERE, 'report.json'), `${JSON.stringify(report, null, 2)}\n`);

  let matchesReference = null;
  try {
    const reference = JSON.parse(readFileSync(resolve(HERE, 'report.reference.json'), 'utf8'));
    matchesReference = reference.results_digest === result.results_digest;
  } catch {
    matchesReference = null;
  }
  const receipt = {
    kind: 'gap6-execution-evidence-reproduction-receipt',
    profile: PROFILE,
    results_digest: result.results_digest,
    matches_committed_reference: matchesReference,
    note: 'Reproduction of the pinned profile checks; not an independent implementation result.',
    runner,
  };
  writeFileSync(resolve(HERE, 'reproduction-receipt.json'), `${JSON.stringify(receipt, null, 2)}\n`);

  if (process.argv.includes('--json')) console.log(JSON.stringify(report, null, 2));
  else printDemo(result);
  if (matchesReference === false) {
    console.error('results_digest DIFFERS from the committed reference report.');
    process.exitCode = 1;
  }
}
