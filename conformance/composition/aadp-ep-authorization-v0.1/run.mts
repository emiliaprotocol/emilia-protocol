// SPDX-License-Identifier: Apache-2.0
/**
 * AADP -01 and EP Authorization Bundle composition profile.
 *
 * The AADP side is a bounded, draft-derived lifecycle model. It is not the
 * onedoor implementation. The EP side executes the repository verifier.
 */
import crypto from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  deriveAadpEpAuthorizationArtifact,
  matchAadpAuthorizationArtifact,
  verifyAadpEpAuthorizationArtifact,
} from '../../../packages/verify/aadp-authorization-artifact.js';
import { canonicalizeAeb, digestAeb } from '../../../packages/verify/aeb-adapter-contract.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SOURCE_LOCK = JSON.parse(readFileSync(new URL('./source-lock.json', import.meta.url), 'utf8'));
const VECTORS = JSON.parse(readFileSync(
  new URL('../../vectors/authorization-bundle.v1.json', import.meta.url),
  'utf8',
));
const FIXTURE = VECTORS.cases.find((entry: any) => entry.id === 'valid-non-oauth-native-binding');

export const PROFILE = 'AADP-EP-AUTHORIZATION-COMPOSITION-v0.1';
export const MAPPING_PROFILE =
  'https://emiliaprotocol.ai/profiles/aadp-ep-payment-release-v1';

const BASE_REQUEST = Object.freeze({
  request_id: 'aadp-request-001',
  tenant_id: 'tenant:example',
  action_type: FIXTURE.expected_action.action_type,
  params: Object.freeze({
    initiator: FIXTURE.expected_action.initiator,
    ...FIXTURE.expected_action.parameters,
  }),
  source: Object.freeze({ kind: 'agent', id: 'agent:recon-7' }),
});

function aadpAction(request: any): any {
  return { action_type: request.action_type, params: request.params };
}

export function mapAadpPaymentRelease(action: any): any {
  return {
    action_type: action.action_type,
    initiator: action.params.initiator,
    parameters: {
      amount_minor: action.params.amount_minor,
      currency: action.params.currency,
      payee: action.params.payee,
    },
  };
}

function bundleOptions(overrides: Record<string, unknown> = {}): any {
  return {
    now: FIXTURE.now,
    audience: FIXTURE.audience,
    approverKeys: FIXTURE.approver_keys,
    expectedApprovers: FIXTURE.expected_approvers,
    acceptedKeyClasses: FIXTURE.accepted_key_classes,
    currentPolicy: FIXTURE.current_policy,
    expectedAuthorizationInstance: FIXTURE.expected_authorization_instance,
    expectedAuthorizationBinding: FIXTURE.expected_authorization_binding,
    requireAuthorizationBinding: true,
    ...overrides,
  };
}

function profileInput({
  request = BASE_REQUEST,
  bundle = FIXTURE.bundle,
  mappingProfile = MAPPING_PROFILE,
  mapAction = mapAadpPaymentRelease,
  options = bundleOptions(),
}: Record<string, any> = {}): any {
  return {
    bundle,
    aadpAction: aadpAction(request),
    actionMappingProfile: mappingProfile,
    mapAction,
    bundleOptions: options,
  };
}

function sameCanonical(left: unknown, right: unknown): boolean {
  try {
    return canonicalizeAeb(left) === canonicalizeAeb(right);
  } catch {
    return false;
  }
}

class AadpDraftLifecycle {
  approvals = new Map<string, any>();
  permits = new Map<string, any>();
  reports = new Map<string, any>();
  nextApproval = 1;
  nextPermit = 1;

  propose(request: any, hook: unknown): any {
    const parsed = matchAadpAuthorizationArtifact(hook, hook);
    if (parsed.verdict !== 'MATCH') return { ok: false, decision: 'refused', reason: parsed.reason };
    const approvalId = `approval:${this.nextApproval++}`;
    this.approvals.set(approvalId, {
      state: 'pending',
      action: structuredClone(aadpAction(request)),
      hook: structuredClone(parsed.artifact),
    });
    return { ok: true, decision: 'proposed', approval_id: approvalId };
  }

  approve(approvalId: string): any {
    const approval = this.approvals.get(approvalId);
    if (!approval || approval.state !== 'pending') {
      return { ok: false, reason: 'approval_not_pending' };
    }
    approval.state = 'approved';
    return { ok: true };
  }

  decide({
    request,
    approvalRef,
    presentedHook,
    verifiedHook,
    localPolicy = 'PERMIT',
    killSwitch = false,
  }: Record<string, any>): any {
    if (verifiedHook.verdict !== 'VERIFIED') {
      return {
        ok: false,
        decision: verifiedHook.verdict === 'REFUSE' ? 'refused' : 'indeterminate',
        reason: verifiedHook.reasons[0] ?? 'authorization_artifact_unavailable',
      };
    }
    const hookMatch = matchAadpAuthorizationArtifact(presentedHook, verifiedHook.artifact);
    if (hookMatch.verdict !== 'MATCH') {
      return {
        ok: false,
        decision: hookMatch.verdict === 'MISMATCH' ? 'refused' : 'indeterminate',
        reason: hookMatch.reason,
      };
    }
    const approval = this.approvals.get(approvalRef);
    if (!approval || approval.state !== 'approved') {
      return { ok: false, decision: 'proposed', reason: 'approval_ref_not_usable' };
    }
    if (!sameCanonical(approval.action, aadpAction(request))) {
      return { ok: false, decision: 'proposed', reason: 'approval_action_mismatch' };
    }
    if (!sameCanonical(approval.hook, hookMatch.artifact)) {
      return { ok: false, decision: 'proposed', reason: 'approval_artifact_mismatch' };
    }

    // AADP -01 requires one atomic approval transition and re-evaluation after
    // approval. The hook never overrules the current PDP state.
    approval.state = 'executed';
    if (killSwitch || localPolicy !== 'PERMIT') {
      return {
        ok: false,
        decision: 'refused',
        reason: killSwitch ? 'kill_switch_active' : 'local_policy_refused',
      };
    }

    const permitId = `permit:${this.nextPermit++}`;
    const providerKey = `aadp-provider:${crypto.createHash('sha256')
      .update(`AADP-PROVIDER-IDEMPOTENCY-v1\u0000${permitId}`, 'utf8')
      .digest('hex')}`;
    this.permits.set(permitId, {
      state: 'issued',
      action: structuredClone(aadpAction(request)),
      provider_key: providerKey,
      artifact_digest: hookMatch.artifact?.artifact_digest,
    });
    return {
      ok: true,
      decision: 'permitted',
      permit_id: permitId,
      provider_idempotency_key: providerKey,
    };
  }

  report(permitId: string, outcome: string): any {
    const permit = this.permits.get(permitId);
    if (!permit || permit.state !== 'issued') {
      return { ok: false, reason: 'permit_not_reportable' };
    }
    if (!['success', 'failure', 'timeout', 'not_attempted'].includes(outcome)) {
      return { ok: false, reason: 'report_outcome_unknown' };
    }
    permit.state = 'reported';
    this.reports.set(permitId, { outcome });
    return { ok: true, outcome };
  }
}

function derive(overrides: Record<string, any> = {}): any {
  return deriveAadpEpAuthorizationArtifact(profileInput(overrides));
}

function preparedFlow(): any {
  const verified = derive();
  if (verified.verdict !== 'VERIFIED') throw new Error(JSON.stringify(verified));
  const flow = new AadpDraftLifecycle();
  const proposed = flow.propose(BASE_REQUEST, verified.artifact);
  if (!proposed.ok || !flow.approve(proposed.approval_id).ok) {
    throw new Error('failed to prepare AADP reference approval');
  }
  return { flow, verified, approvalId: proposed.approval_id };
}

function check(id: string, claim: string, actual: any, predicate: (value: any) => boolean): any {
  const passed = predicate(actual);
  return { id, claim, passed, actual };
}

export function runComposition(): any {
  const checks: any[] = [];

  const positive = preparedFlow();
  const permitted = positive.flow.decide({
    request: BASE_REQUEST,
    approvalRef: positive.approvalId,
    presentedHook: positive.verified.artifact,
    verifiedHook: positive.verified,
  });
  checks.push(check('AADP-EP-01', 'a natively verified exact EP artifact can support one AADP permit', {
    artifact_digest: positive.verified.artifact.artifact_digest,
    action_digest: positive.verified.artifact.action_digest,
    decision: permitted.decision,
  }, (value) => value.decision === 'permitted'
    && value.action_digest === FIXTURE.bundle.action_hash
    && /^sha256:[0-9a-f]{64}$/.test(value.artifact_digest)));

  const changedAction = {
    ...BASE_REQUEST,
    request_id: 'aadp-request-substituted',
    params: { ...BASE_REQUEST.params, amount_minor: 999_999 },
  };
  const substituted = derive({ request: changedAction });
  checks.push(check('AADP-EP-02', 'material AADP action substitution is refused by native EP verification', {
    verdict: substituted.verdict,
    reasons: substituted.reasons,
  }, (value) => value.verdict === 'REFUSE' && value.reasons.includes('action_mismatch')));

  const tamperedBundle = structuredClone(FIXTURE.bundle);
  tamperedBundle.contexts[0].audience = 'https://attacker.example';
  const tampered = derive({ bundle: tamperedBundle });
  checks.push(check('AADP-EP-03', 'tampered EP artifact bytes do not yield an AADP hook', {
    verdict: tampered.verdict,
    reasons: tampered.reasons,
  }, (value) => value.verdict === 'REFUSE'));

  const unpinned = derive({ options: bundleOptions({ approverKeys: {} }) });
  checks.push(check('AADP-EP-04', 'self-presented or unpinned approver keys are refused', {
    verdict: unpinned.verdict,
    reasons: unpinned.reasons,
  }, (value) => value.verdict === 'REFUSE' && value.reasons.includes('approver_keys_missing')));

  const wrongAudience = derive({ options: bundleOptions({ audience: 'https://other.example' }) });
  checks.push(check('AADP-EP-05', 'wrong AADP relying-party audience is refused', {
    verdict: wrongAudience.verdict,
    reasons: wrongAudience.reasons,
  }, (value) => value.verdict === 'REFUSE' && value.reasons.includes('context_audience_mismatch')));

  const noMapper = derive({ mapAction: () => { throw new Error('mapping registry unavailable'); } });
  checks.push(check('AADP-EP-06', 'unavailable action mapping is indeterminate', {
    verdict: noMapper.verdict,
    reasons: noMapper.reasons,
  }, (value) => value.verdict === 'INDETERMINATE'
    && value.reasons.includes('aadp_action_mapping_unavailable')));

  const policyUnavailable = derive({
    options: bundleOptions({
      currentPolicy: { ...FIXTURE.current_policy, unavailable: true },
    }),
  });
  checks.push(check('AADP-EP-07', 'unavailable current EP policy is indeterminate, not cached authority', {
    verdict: policyUnavailable.verdict,
    reasons: policyUnavailable.reasons,
  }, (value) => value.verdict === 'INDETERMINATE'
    && value.reasons.includes('current_policy_unavailable_or_stale')));

  const profileSubstitution = preparedFlow();
  const changedHook = {
    ...profileSubstitution.verified.artifact,
    action_mapping_profile: 'https://attacker.example/mapping-v1',
  };
  const profileResult = profileSubstitution.flow.decide({
    request: BASE_REQUEST,
    approvalRef: profileSubstitution.approvalId,
    presentedHook: changedHook,
    verifiedHook: profileSubstitution.verified,
  });
  checks.push(check('AADP-EP-08', 'presenter-selected mapping-profile substitution is refused', profileResult,
    (value) => value.decision === 'refused' && value.reason === 'authorization_artifact_mismatch'));

  const missingHook = verifyAadpEpAuthorizationArtifact(undefined, profileInput());
  checks.push(check('AADP-EP-09', 'missing required hook is refused', {
    verdict: missingHook.verdict,
    reasons: missingHook.reasons,
  }, (value) => value.verdict === 'REFUSE'
    && value.reasons.includes('authorization_artifact_malformed')));

  const frozen = preparedFlow();
  const frozenResult = frozen.flow.decide({
    request: BASE_REQUEST,
    approvalRef: frozen.approvalId,
    presentedHook: frozen.verified.artifact,
    verifiedHook: frozen.verified,
    killSwitch: true,
  });
  checks.push(check('AADP-EP-10', 'a valid EP artifact cannot overrule an AADP kill switch', frozenResult,
    (value) => value.decision === 'refused' && value.reason === 'kill_switch_active'));

  const replay = preparedFlow();
  const first = replay.flow.decide({
    request: BASE_REQUEST,
    approvalRef: replay.approvalId,
    presentedHook: replay.verified.artifact,
    verifiedHook: replay.verified,
  });
  const second = replay.flow.decide({
    request: { ...BASE_REQUEST, request_id: 'aadp-request-replay' },
    approvalRef: replay.approvalId,
    presentedHook: replay.verified.artifact,
    verifiedHook: replay.verified,
  });
  checks.push(check('AADP-EP-11', 'AADP approval remains single-use even when the artifact is still valid', {
    first: first.decision,
    second: second.decision,
    second_reason: second.reason,
    permits: replay.flow.permits.size,
  }, (value) => value.first === 'permitted' && value.second === 'proposed'
    && value.permits === 1));

  checks.push(check('AADP-EP-12', 'permit and provider keys remain separate from the artifact digest', {
    permit_id: first.permit_id,
    provider_idempotency_key: first.provider_idempotency_key,
    artifact_digest: replay.verified.artifact.artifact_digest,
  }, (value) => value.permit_id !== value.provider_idempotency_key
    && value.permit_id !== value.artifact_digest
    && value.provider_idempotency_key !== value.artifact_digest));

  const timeout = replay.flow.report(first.permit_id, 'timeout');
  const retry = replay.flow.decide({
    request: { ...BASE_REQUEST, request_id: 'aadp-request-after-timeout' },
    approvalRef: replay.approvalId,
    presentedHook: replay.verified.artifact,
    verifiedHook: replay.verified,
  });
  checks.push(check('AADP-EP-13', 'unknown provider outcome is reported and does not reopen approval', {
    report: timeout.outcome,
    retry: retry.decision,
    retry_reason: retry.reason,
    permits: replay.flow.permits.size,
  }, (value) => value.report === 'timeout' && value.retry === 'proposed'
    && value.permits === 1));

  const sourceA = derive();
  const sourceB = derive({ request: {
    ...BASE_REQUEST,
    source: { kind: 'human', id: 'self-asserted-different-source' },
  } });
  checks.push(check('AADP-EP-14', 'AADP source metadata is informational and cannot change the hook', {
    first: sourceA.artifact,
    second: sourceB.artifact,
  }, (value) => sameCanonical(value.first, value.second)));

  const passed = checks.filter((entry) => entry.passed).length;
  const report: any = {
    profile: PROFILE,
    source_basis: {
      aadp: {
        draft: SOURCE_LOCK.aadp.draft,
        implementation_kind: 'draft-derived-bounded-lifecycle-model',
      },
      ep: {
        artifact: 'EP-AUTHORIZATION-BUNDLE-v1',
        implementation_kind: 'repository-runtime',
      },
      onedoor: {
        revision: SOURCE_LOCK.onedoor.revision,
        executed: false,
        note: 'inspected for implementation alignment; not executed by this runner',
      },
    },
    claim_boundary: {
      authorization_artifact_is_authority: false,
      aadp_re_evaluation_required: true,
      aadp_approval_single_use: true,
      aadp_permit_is_provider_idempotency_key: false,
      exactly_once_physical_effect_claimed: false,
    },
    summary: { passed, total: checks.length },
    passed: passed === checks.length,
    checks,
  };
  report.report_digest = digestAeb(report);
  return report;
}

function main(): void {
  const report = runComposition();
  const referencePath = `${HERE}/report.reference.json`;
  if (process.argv.includes('--emit')) {
    writeFileSync(referencePath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  }
  if (process.argv.includes('--check')) {
    const reference = JSON.parse(readFileSync(referencePath, 'utf8'));
    if (!sameCanonical(report, reference)) {
      throw new Error('AADP x EP report differs from report.reference.json');
    }
  }
  if (!report.passed) throw new Error(JSON.stringify(report, null, 2));
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
