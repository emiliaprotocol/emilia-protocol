// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { mapAction } from '../caid/impl/js/mapping.mjs';
import { verifyAgentROA as verifyAgentRoaEvidence } from '../packages/verify/agentroa.js';
import {
  verifyOrprgJsonJcsPermit as verifyOrprgPermitReceipt,
} from '../packages/verify/orprg.js';
import { canonicalize, verifyQuorum } from '../packages/verify/index.js';

// Sibling verifier API contract used here:
//   verifyAgentRoaEvidence({ chain, aer }, {
//     keysByType, policiesByType, verificationTime, action
//   }) -> { valid, action_digest, reason }
//   verifyOrprgPermitReceipt(receipt, {
//     expectedAction, expectedPolicyDigest, expectedEpoch, verificationTime,
//     maxReceiptAgeSeconds, maxStatusAgeSeconds, issuerKeys, antiReplay
//   }) -> { valid, action_digest, detail.denial_reason_code }
// Both are strict native verifiers. Neither is a human-approval verifier.

const suite = JSON.parse(readFileSync(
  new URL('../conformance/vectors/agentroa-orprg-ep.v1.json', import.meta.url),
  'utf8',
));
const clone = (value) => structuredClone(value);

function replayStore() {
  const seen = new Set();
  return {
    durable: true,
    atomic: true,
    consume(key) {
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    },
  };
}

function quorumIsRelyingPartyPinned(ep) {
  if (!ep?.quorum || !ep?.profile) return false;
  if (canonicalize(ep.quorum.policy) !== canonicalize(ep.profile.policy)) return false;
  for (const member of ep.quorum.members) {
    const enrolled = ep.profile.approvers?.[member.approver_public_key];
    if (!enrolled
        || enrolled.status !== 'active'
        || enrolled.approver_id !== member.signoff?.context?.approver
        || !enrolled.roles?.includes(member.role)) return false;
  }
  return verifyQuorum(ep.quorum, {
    rpId: ep.profile.rp_id,
    allowedOrigins: ep.profile.allowed_origins,
  }).valid;
}

function mapped(source, mapping, nativeVerified, definitions) {
  return mapAction(source, {
    profile: mapping.profile,
    sourceDescriptor: mapping.source_descriptor,
    expectedProfileHash: mapping.expected_profile_hash,
    nativeVerified,
    definitions,
    suite: 'jcs-sha256',
  });
}

function evaluate(input) {
  const vector = clone(input);
  const antiReplay = replayStore();
  const agentAction = vector.agentroa.evidence.aer.action;
  const agent = verifyAgentRoaEvidence(vector.agentroa.evidence, {
    keysByType: vector.agentroa.keys_by_type,
    policiesByType: vector.agentroa.policies_by_type,
    verificationTime: vector.orprg.options.verificationTime,
    action: agentAction,
  });

  const orprgOptions = {
    ...vector.orprg.options,
    expectedAction: vector.orprg.action,
    issuerKeys: vector.orprg.issuer_keys,
    antiReplay,
  };
  const permits = [];
  for (let index = 0; index < vector.presentations; index++) {
    permits.push(verifyOrprgPermitReceipt(vector.orprg.receipt, orprgOptions));
  }

  const agentMap = mapped(
    agentAction,
    vector.mapping.agentroa,
    agent.valid,
    suite.definitions,
  );
  const orprgMap = mapped(
    vector.orprg.action,
    vector.mapping.orprg,
    permits[0].valid,
    suite.definitions,
  );
  const quorumValid = quorumIsRelyingPartyPinned(vector.ep);
  const expectedDigest = vector.expected_caid.digest.replace(/^sha256:/, '');
  const sameCaid = agentMap.ok
    && orprgMap.ok
    && agentMap.caid === vector.expected_caid.value
    && orprgMap.caid === vector.expected_caid.value;
  const epBound = quorumValid && vector.ep.quorum.action_hash === expectedDigest;
  const requirementPinned = vector.relying_party_requirement
    === suite.required_component_types.join(' AND ');

  const firstValid = agent.valid
    && permits[0].valid
    && sameCaid
    && epBound
    && requirementPinned;
  const valid = firstValid
    && permits.slice(1).every((permit) => permit.valid);

  let reason = null;
  if (!requirementPinned) reason = 'relying_party_requirement_missing';
  else if (!vector.ep?.quorum) reason = 'human_evidence_missing';
  else if (!agent.valid || permits[0].detail?.denial_reason_code === 'ISSUER_UNTRUSTED') {
    reason = 'untrusted_issuer';
  } else if (!agentMap.ok || !orprgMap.ok) reason = 'mapping_profile_refused';
  else if (!sameCaid || !epBound) reason = 'material_action_mismatch';
  else if (permits.slice(1).some((permit) =>
    permit.detail?.denial_reason_code === 'ANTI_REPLAY_FAILURE')) reason = 'replay_refused';

  return {
    valid,
    first_valid: firstValid,
    reason,
    agent,
    permits,
    agentMap,
    orprgMap,
    quorumValid,
  };
}

describe('AgentROA + ORPRG + EP bind one CAID', () => {
  it('contains the complete fail-closed contract battery', () => {
    expect(suite.count).toBe(7);
    expect(suite.vectors.map((vector) => vector.id)).toEqual([
      'accept_agentroa_orprg_ep_same_caid',
      'reject_action_substitution',
      'reject_wrong_mapping_profile',
      'reject_untrusted_issuer',
      'reject_approval_state_only_substitution',
      'reject_orprg_replay',
      'reject_missing_relying_party_requirement',
    ]);
  });

  for (const vector of suite.vectors) {
    it(`${vector.id}: ${vector.description}`, () => {
      const result = evaluate(vector);
      expect({
        valid: result.valid,
        first_valid: result.first_valid,
        reason: result.reason,
      }).toEqual(vector.expect);
    });
  }

  it('proves the approval-state negative is not a broken machine signature', () => {
    const vector = suite.vectors.find((entry) =>
      entry.id === 'reject_approval_state_only_substitution');
    const result = evaluate(vector);
    expect(result.agent.valid).toBe(true);
    expect(result.permits[0].valid).toBe(true);
    expect(vector.agentroa.evidence.chain[0].authorization.approval_state).toBe('granted');
    expect(result.quorumValid).toBe(false);
    expect(result.reason).toBe('human_evidence_missing');
  });

  it('proves the action-substitution negative consists of two genuine native artifacts', () => {
    const vector = suite.vectors.find((entry) =>
      entry.id === 'reject_action_substitution');
    const result = evaluate(vector);
    expect(result.agent.valid).toBe(true);
    expect(result.permits[0].valid).toBe(true);
    expect(result.agentMap.ok).toBe(true);
    expect(result.orprgMap.ok).toBe(true);
    expect(result.agentMap.caid).not.toBe(result.orprgMap.caid);
  });
});
