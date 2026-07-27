#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { pathToFileURL } from 'node:url';

const MAX_STDIN_BYTES = 65_536;

function aggregateNative(evidence) {
  if (evidence.some((item) => item.trust_root.state === 'WRONG' || item.native_verification === 'FAILED')) {
    return 'FAILED';
  }
  if (evidence.some((item) => item.trust_root.state === 'UNAVAILABLE'
    || item.native_verification === 'INDETERMINATE')) return 'INDETERMINATE';
  return 'VERIFIED';
}

function actionRelation(input, nativeVerification) {
  if (nativeVerification !== 'VERIFIED') return 'INDETERMINATE';
  if (input.native_evidence.some((item) => item.mapping.material_fields !== 'PRESERVED')) {
    return 'INDETERMINATE';
  }
  if (input.native_evidence.some((item) => item.mapping.caid !== input.exact_action.caid
    || item.mapping.normalized_action_digest !== input.exact_action.normalized_action_digest)) {
    return 'MISMATCH';
  }
  return 'EXACT_MATCH';
}

function aggregateAcceptance(evidence) {
  if (evidence.some((item) => item.rp_acceptance === 'REJECTED')) return 'REJECTED';
  if (evidence.some((item) => item.rp_acceptance === 'INDETERMINATE')) return 'INDETERMINATE';
  return 'ACCEPTED';
}

function aggregateStatus(evidence) {
  for (const state of ['REVOKED', 'STALE', 'UNAVAILABLE']) {
    if (evidence.some((item) => item.status === state)) return state;
  }
  return 'CURRENT';
}

export function evaluateRefereeCase(input) {
  const nativeVerification = aggregateNative(input.native_evidence);
  const rpAcceptance = aggregateAcceptance(input.native_evidence);
  const relation = actionRelation(input, nativeVerification);
  const status = aggregateStatus(input.native_evidence);
  const replay = input.native_evidence.some((item) => (
    input.custody.consumed_replay_identities.includes(item.native_replay_identity)
  )) ? 'REPLAY' : 'FRESH';
  const reasons = [];

  if (input.native_evidence.some((item) => item.trust_root.state === 'WRONG')) reasons.push('wrong_trust_root');
  if (nativeVerification === 'FAILED') reasons.push('native_verification_failed');
  if (nativeVerification === 'INDETERMINATE') reasons.push('native_verification_indeterminate');
  if (rpAcceptance === 'REJECTED') reasons.push('rp_acceptance_rejected');
  if (rpAcceptance === 'INDETERMINATE') reasons.push('rp_acceptance_indeterminate');
  if (relation === 'MISMATCH') reasons.push('action_mismatch');
  if (input.native_evidence.some((item) => item.mapping.material_fields !== 'PRESERVED')) {
    reasons.push('material_field_loss');
  }
  if (status === 'REVOKED') reasons.push('status_revoked');
  if (status === 'STALE') reasons.push('status_stale');
  if (status === 'UNAVAILABLE') reasons.push('status_unavailable');
  if (replay === 'REPLAY' && input.phase === 'ADMISSION') reasons.push('native_replay_detected');

  let admission = 'NOT_APPLICABLE';
  let custody = input.custody.state;
  let providerCommitment = input.provider.commitment;
  let observedEffect = input.provider.observed_effect;
  let retry = 'NOT_APPLICABLE';
  let reconciliation = 'NOT_APPLICABLE';

  if (input.phase === 'ADMISSION') {
    if (nativeVerification === 'FAILED' || rpAcceptance === 'REJECTED' || relation === 'MISMATCH'
      || status === 'REVOKED' || replay === 'REPLAY') {
      admission = 'REFUSE';
    } else if (nativeVerification === 'INDETERMINATE' || rpAcceptance === 'INDETERMINATE'
      || relation === 'INDETERMINATE'
      || status === 'STALE' || status === 'UNAVAILABLE') {
      admission = 'INDETERMINATE';
    } else {
      admission = 'ADMIT';
      custody = 'RESERVED';
    }
  } else if (input.phase === 'INVOCATION') {
    if (input.provider.failure === 'TIMEOUT' || input.provider.failure === 'CRASH') {
      custody = 'INDETERMINATE';
      providerCommitment = 'INDETERMINATE';
      observedEffect = 'INDETERMINATE';
      retry = 'REFUSE';
      reconciliation = 'REQUIRED';
      reasons.push(input.provider.failure === 'TIMEOUT' ? 'provider_timeout' : 'provider_crash');
    }
  } else {
    const claim = input.reconciliation;
    if (!claim?.authenticated) {
      reconciliation = 'REFUSED';
      retry = 'REFUSE';
      reasons.push('reconciliation_not_authenticated');
    } else if (claim.operation_id !== input.custody.operation_id) {
      reconciliation = 'REFUSED';
      retry = 'REFUSE';
      reasons.push('reconciliation_binding_mismatch');
    } else {
      reconciliation = 'APPLIED';
      custody = claim.provider_commitment === 'INDETERMINATE' ? 'INDETERMINATE' : 'TERMINAL';
      providerCommitment = claim.provider_commitment;
      observedEffect = claim.observed_effect;
      if (providerCommitment === 'INDETERMINATE') {
        reconciliation = 'REQUIRED';
        retry = 'REFUSE';
      } else if (providerCommitment === 'PROVEN_NOT_COMMITTED') {
        retry = 'REQUIRES_NEW_ADMISSION';
      }
      if (observedEffect === 'DIVERGED') reasons.push('effect_diverged');
    }
  }

  return {
    '@version': 'AEB-1-REFEREE-RUNNER-RESULT-v1',
    case_id: input.case_id,
    native_verification: nativeVerification,
    rp_acceptance: rpAcceptance,
    action_relation: relation,
    status,
    replay,
    admission,
    custody,
    provider_commitment: providerCommitment,
    observed_effect: observedEffect,
    retry,
    reconciliation,
    reason_codes: [...new Set(reasons)].sort(),
  };
}

async function main() {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of process.stdin) {
    bytes += chunk.length;
    if (bytes > MAX_STDIN_BYTES) throw new Error('stdin limit exceeded');
    chunks.push(chunk);
  }
  const raw = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
  const input = JSON.parse(raw);
  process.stdout.write(`${JSON.stringify(evaluateRefereeCase(input))}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`reference runner: ${error.message}\n`);
    process.exitCode = 2;
  });
}
