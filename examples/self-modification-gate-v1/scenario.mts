// SPDX-License-Identifier: Apache-2.0

import {
  createHash,
  generateKeyPairSync,
  sign,
  verify,
} from 'node:crypto';

import { computeCaid } from '../../caid/impl/js/caid.mjs';
import {
  AUTONOMY_CONTROL_PLANE_VERSION,
  CAPABILITY_ALLOWANCE_SCOPE_PROFILE,
  capabilityActionDigest,
  canonicalize,
  compileAutonomyControlPlaneProfile,
  createDefaultActionRiskManifest,
  createEg1Harness,
  createGate,
  createMemoryCapabilityStore,
  createMemoryTrustProgramStore,
  createRuntimeMonitor,
  createTrustProgramKernel,
  executeWithCapability,
  mintCapabilityReceipt,
} from '../../packages/gate/index.js';

const NOW = Date.parse('2026-08-12T19:00:00.000Z');
const PROFILE_ID = 'self-modification:promotion:v1';
const SELECTOR = Object.freeze({ protocol: 'agent-runtime', tool: 'promote_candidate' });
const PROTECTED_PATH_PREFIXES = Object.freeze([
  '.github/workflows/self-modification-gate',
  'evaluation/',
  'packages/gate/',
  'trust/',
]);

type JsonRecord = Record<string, any>;

const ACTION_DEFINITIONS = [
  {
    action_type: 'agent.self-improvement.objective.1',
    required_fields: [
      { name: 'objective_id', type: 'string' },
      { name: 'logical_agent_id', type: 'string' },
      { name: 'policy_digest', type: 'digest' },
    ],
    optional_fields: [],
  },
  ...['canary', 'promote'].map((phase) => ({
    action_type: `agent.update.${phase}.1`,
    required_fields: [
      { name: 'logical_agent_id', type: 'string' },
      { name: 'update_kind', type: 'enum', values_ref: 'inline: scaffold | model-weights | prompt | memory-policy | tool' },
      { name: 'base_artifact_digest', type: 'digest' },
      { name: 'candidate_artifact_digest', type: 'digest' },
      { name: 'change_digest', type: 'digest' },
      { name: 'evaluator_profile_digest', type: 'digest' },
      { name: 'promotion_target', type: 'string' },
      { name: 'policy_digest', type: 'digest' },
    ],
    optional_fields: [],
  })),
];

export function selfModificationDigest(value: unknown): string {
  const bytes = typeof value === 'string' || Buffer.isBuffer(value)
    ? value
    : canonicalize(value);
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function exactActionMaterial(action: JsonRecord): JsonRecord {
  return {
    action_type: action.action_type,
    logical_agent_id: action.logical_agent_id,
    update_kind: action.update_kind,
    base_artifact_digest: action.base_artifact_digest,
    candidate_artifact_digest: action.candidate_artifact_digest,
    change_digest: action.change_digest,
    evaluator_profile_digest: action.evaluator_profile_digest,
    promotion_target: action.promotion_target,
    policy_digest: action.policy_digest,
  };
}

function resolveActionCaid(action: JsonRecord): string | null {
  const material = exactActionMaterial(action);
  material.action_type = `${material.action_type}.1`;
  const result = computeCaid(material, {
    suite: 'jcs-sha256',
    definitions: ACTION_DEFINITIONS,
  });
  return result.caid ?? null;
}

function exactActionDigest(action: JsonRecord): string {
  return capabilityActionDigest(exactActionMaterial(action));
}

function changeDigestMatches(action: JsonRecord): boolean {
  return Array.isArray(action.changed_paths)
    && action.change_digest === selfModificationDigest({
      before_digest: action.base_artifact_digest,
      after_digest: action.candidate_artifact_digest,
      changed_paths: [...action.changed_paths].sort(),
    });
}

function objectiveCaid(logicalAgentId: string, policyDigest: string): string {
  const result = computeCaid({
    action_type: 'agent.self-improvement.objective.1',
    objective_id: 'improve-without-editing-the-gate',
    logical_agent_id: logicalAgentId,
    policy_digest: policyDigest,
  }, {
    suite: 'jcs-sha256',
    definitions: ACTION_DEFINITIONS,
  });
  if (!result.caid) throw new Error(`objective CAID refused: ${result.refusals?.join(',')}`);
  return result.caid;
}

function makePromotionAction({
  phase,
  operationId,
  changedPaths,
  baseDigest,
  candidateDigest,
  evaluatorProfileDigest,
  policyDigest,
}: {
  phase: 'canary' | 'promote';
  operationId: string;
  changedPaths: string[];
  baseDigest: string;
  candidateDigest: string;
  evaluatorProfileDigest: string;
  policyDigest: string;
}): Readonly<JsonRecord> {
  const sortedPaths = [...changedPaths].sort();
  const action: JsonRecord = {
    action_type: `agent.update.${phase}`,
    operation_id: operationId,
    logical_agent_id: 'agent:optimizer:1',
    update_kind: 'scaffold',
    base_artifact_digest: baseDigest,
    candidate_artifact_digest: candidateDigest,
    change_digest: selfModificationDigest({
      before_digest: baseDigest,
      after_digest: candidateDigest,
      changed_paths: sortedPaths,
    }),
    evaluator_profile_digest: evaluatorProfileDigest,
    promotion_target: phase === 'canary' ? 'runtime:optimizer:canary' : 'runtime:optimizer:production',
    policy_digest: policyDigest,
    changed_paths: sortedPaths,
    amount: 1,
    currency: 'SELF_EDIT',
  };
  action.caid = resolveActionCaid(action);
  action.action_digest = exactActionDigest(action);
  if (!action.caid) throw new Error('self-modification action CAID refused');
  return Object.freeze(action);
}

function controlPlaneOverlap(changedPaths: string[]): boolean {
  return changedPaths.some((path) => PROTECTED_PATH_PREFIXES.some(
    (prefix) => prefix.endsWith('/') ? path.startsWith(prefix) : path === prefix || path.startsWith(`${prefix}.`),
  ));
}

function publicKeyFingerprint(publicKey): string {
  return selfModificationDigest(publicKey.export({ type: 'spki', format: 'der' }));
}

function signedArtifact(
  challenge: JsonRecord,
  requirement: JsonRecord,
  role: { id: string; privateKey: any; publicKey: any },
  claims: JsonRecord,
  evidenceId: string,
): JsonRecord {
  const body = {
    '@version': 'SELF-MODIFICATION-EVIDENCE-v1',
    evidence_id: evidenceId,
    binding_digest: challenge.binding_digest,
    policy_digest: requirement.policy_digest,
    subjects: [role.id],
    key_fingerprints: [publicKeyFingerprint(role.publicKey)],
    issued_at: new Date(NOW - 1_000).toISOString(),
    expires_at: new Date(NOW + 60_000).toISOString(),
    revocation_checked_at: new Date(NOW - 500).toISOString(),
    claims,
  };
  return {
    ...body,
    key_id: role.id,
    signature: sign(null, Buffer.from(canonicalize(body)), role.privateKey).toString('base64url'),
  };
}

function verifySignedArtifact(
  artifact: JsonRecord,
  trustedRoles: Map<string, any>,
): { ok: boolean; body?: JsonRecord; reason?: string } {
  if (!artifact || typeof artifact !== 'object' || typeof artifact.key_id !== 'string'
      || typeof artifact.signature !== 'string') return { ok: false, reason: 'evidence_shape_invalid' };
  const publicKey = trustedRoles.get(artifact.key_id);
  if (!publicKey) return { ok: false, reason: 'evidence_key_untrusted' };
  const { key_id: _keyId, signature, ...body } = artifact;
  let valid = false;
  try {
    valid = verify(
      null,
      Buffer.from(canonicalize(body)),
      publicKey,
      Buffer.from(signature, 'base64url'),
    );
  } catch {
    valid = false;
  }
  return valid ? { ok: true, body } : { ok: false, reason: 'evidence_signature_invalid' };
}

function resultFromEvidence(body: JsonRecord) {
  return {
    valid: true,
    reason: null,
    binding_digest: body.binding_digest,
    policy_digest: body.policy_digest,
    subjects: body.subjects,
    key_fingerprints: body.key_fingerprints,
    issued_at: body.issued_at,
    expires_at: body.expires_at,
    revocation_checked_at: body.revocation_checked_at,
  };
}

export function createSelfModificationHarness({
  changedPaths = ['src/optimizer.ts'],
  provider = async (action: JsonRecord) => ({
    deployment_id: `deployment:${action.candidate_artifact_digest.slice(-12)}`,
    status: 'promoted',
  }),
}: {
  changedPaths?: string[];
  provider?: (action: JsonRecord) => Promise<any>;
} = {}) {
  const baseDigest = selfModificationDigest('optimizer-v1');
  const candidateDigest = selfModificationDigest('optimizer-v2');
  const evaluatorSuiteDigest = selfModificationDigest('self-modification-evaluator-suite-v1');
  const evaluatorEnvironmentDigest = selfModificationDigest('sandbox-image@sha256:fixed');
  const evaluatorPolicyDigest = selfModificationDigest({
    version: 'SELF-MODIFICATION-ADMISSIBILITY-v1',
    protected_path_prefixes: PROTECTED_PATH_PREFIXES,
    verdict_required: 'pass',
  });
  const rootPolicyDigest = selfModificationDigest({
    evaluator_policy_digest: evaluatorPolicyDigest,
    evaluator_suite_digest: evaluatorSuiteDigest,
    evaluator_environment_digest: evaluatorEnvironmentDigest,
  });
  const canaryAction = makePromotionAction({
    phase: 'canary',
    operationId: 'promotion:canary:1',
    changedPaths,
    baseDigest,
    candidateDigest,
    evaluatorProfileDigest: evaluatorSuiteDigest,
    policyDigest: evaluatorPolicyDigest,
  });
  const action = makePromotionAction({
    phase: 'promote',
    operationId: 'promotion:production:1',
    changedPaths,
    baseDigest,
    candidateDigest,
    evaluatorProfileDigest: evaluatorSuiteDigest,
    policyDigest: evaluatorPolicyDigest,
  });
  const change = {
    before_digest: baseDigest,
    after_digest: candidateDigest,
    changed_paths: [...changedPaths].sort(),
  };
  const fitness = {
    suite_digest: evaluatorSuiteDigest,
    environment_digest: evaluatorEnvironmentDigest,
    policy_digest: evaluatorPolicyDigest,
    max_age_sec: 300,
  };
  const profile = {
    '@version': AUTONOMY_CONTROL_PLANE_VERSION,
    control_plane_id: 'self-improving-optimizer',
    version: 1,
    valid_from: new Date(NOW - 60_000).toISOString(),
    expires_at: new Date(NOW + 3_600_000).toISOString(),
    root: {
      objective_id: 'objective:improve-without-editing-the-gate',
      root_caid: objectiveCaid('agent:optimizer:1', rootPolicyDigest),
      action_digest: selfModificationDigest({
        objective_id: 'objective:improve-without-editing-the-gate',
        policy_digest: rootPolicyDigest,
      }),
      actions: ['agent.update.canary', 'agent.update.promote'],
      audiences: ['runtime:optimizer'],
      budget: { cents: 100, calls: 2 },
      expires_at: new Date(NOW + 3_600_000).toISOString(),
      initiator_id: 'agent:optimizer:1',
      authorization: {
        evidence_type: 'ep-class-a-signoff',
        verifier_profile: 'ep-class-a:v1',
        policy_digest: rootPolicyDigest,
        max_age_sec: 900,
        require_initiator_exclusion: false,
      },
    },
    status: {
      verifier_profile: 'ep-status:v1',
      policy_digest: selfModificationDigest('self-modification-status-policy-v1'),
      max_age_sec: 60,
    },
    children: [
      {
        goal_id: 'goal:canary-candidate',
        parent_goal_id: 'root',
        phase: 'canary',
        caid: canaryAction.caid,
        action_digest: canaryAction.action_digest,
        action_type: 'agent.update.canary',
        audience: 'runtime:optimizer',
        budget: { cents: 50, calls: 1 },
        expires_at: new Date(NOW + 1_800_000).toISOString(),
        capability_template_digest: selfModificationDigest('self-edit-capability-template-v1'),
        proposer_id: 'agent:optimizer:1',
        evaluator_id: 'service:evaluator:1',
        executor_id: 'service:canary-deployer:1',
        change: structuredClone(change),
        fitness: structuredClone(fitness),
        canary: {
          exposure_percent: 10,
          max_exposure_percent: 10,
          policy_digest: selfModificationDigest('canary-policy-10-percent-v1'),
          max_age_sec: 300,
        },
        rollback: null,
      },
      {
        goal_id: 'goal:promote-candidate',
        parent_goal_id: 'root',
        phase: 'promote',
        caid: action.caid,
        action_digest: action.action_digest,
        action_type: 'agent.update.promote',
        audience: 'runtime:optimizer',
        budget: { cents: 50, calls: 1 },
        expires_at: new Date(NOW + 2_700_000).toISOString(),
        capability_template_digest: selfModificationDigest('self-edit-capability-template-v1'),
        proposer_id: 'agent:optimizer:1',
        evaluator_id: 'service:evaluator:1',
        executor_id: 'service:production-deployer:1',
        change: structuredClone(change),
        fitness: structuredClone(fitness),
        canary: {
          goal_id: 'goal:canary-candidate',
          exposure_percent: 100,
          max_exposure_percent: 100,
          policy_digest: selfModificationDigest('canary-promotion-policy-v1'),
          max_age_sec: 300,
        },
        rollback: null,
      },
    ],
  };
  const compiled = compileAutonomyControlPlaneProfile(profile);
  const promotionProgram = compiled.programs[1];

  const roleNames = [
    'human:owner',
    'service:authority-allocator:1',
    'service:binding-verifier:1',
    'service:evaluator:1',
    'service:status-verifier:1',
    'service:canary-verifier:1',
  ];
  const roles = new Map(roleNames.map((id) => [id, { id, ...generateKeyPairSync('ed25519') }]));
  const trustedRoles = new Map([...roles].map(([id, role]) => [id, role.publicKey]));

  const rootHarness = createEg1Harness({
    // Gate's ordinary receipt is deliberately for this exact promotion. The
    // broader objective and budgets live in the compiled Trust Program and
    // capability envelope; neither is allowed to masquerade as an approval
    // of an as-yet-unknown candidate.
    action,
    now: () => NOW,
    idPrefix: 'self-modification',
  });
  const baseReceipt = rootHarness.mint({
    outcome: 'allow_with_signoff',
    extra: { capability_only: true },
  });
  const capabilityIssuer = generateKeyPairSync('ed25519');
  const capabilityIssuerKey = capabilityIssuer.publicKey
    .export({ type: 'spki', format: 'der' }).toString('base64url');
  const capability = mintCapabilityReceipt(baseReceipt, {
    issuerPrivateKey: capabilityIssuer.privateKey,
    budget: { amount: 1, currency: 'SELF_EDIT' },
    expiry: NOW + 3_600_000,
    revocationMode: 'direct',
    capabilityId: `cap:self-modification:${candidateDigest.slice(-12)}`,
    secret: Buffer.alloc(32, 17),
    scope: {
      profile: CAPABILITY_ALLOWANCE_SCOPE_PROFILE,
      profile_id: PROFILE_ID,
      profile_digest: compiled.profile_digest,
      operation_id_field: 'operation_id',
    },
  });
  const capabilityStore = createMemoryCapabilityStore();
  if (!capabilityStore.registerCapability(capability.capabilityReceipt)) {
    throw new Error('self-modification capability registration failed');
  }
  const allowanceStatus = {
    allowance_profile_id: PROFILE_ID,
    allowance_digest: compiled.profile_digest,
    revision: 1,
    status_epoch: 1,
    status_head_digest: selfModificationDigest('self-modification-allowance-status-1'),
  };
  const advanced = capabilityStore.advanceAllowanceStatus({
    ...allowanceStatus,
    expected_status_epoch: null,
    expected_status_head_digest: null,
    status: 'active',
  });
  if (!advanced.ok) throw new Error(`allowance status initialization failed: ${advanced.reason}`);

  const gate = createGate({
    manifest: createDefaultActionRiskManifest({
      extraActions: [{
        id: 'agent.self-modification.promote',
        label: 'Promote self-modified agent candidate',
        action_type: 'agent.update.promote',
        risk: 'high',
        receipt_required: true,
        assurance_class: 'class_a',
        match: SELECTOR,
        why: 'Changes the executable agent artifact in a live target.',
      }],
    }),
    trustedKeys: [rootHarness.publicKey],
    approverKeys: rootHarness.approverKeys,
    quorumPolicy: rootHarness.quorumPolicy,
    rpId: rootHarness.rpId,
    allowedOrigins: rootHarness.allowedOrigins,
    capabilityStore,
    capabilityTrustedIssuerKeys: [capabilityIssuerKey],
    runtimeMonitor: createRuntimeMonitor({ now: () => NOW }),
    allowEphemeralStore: true,
    now: () => NOW,
  });

  let providerCallCount = 0;

  function makeVerifier(expectedAction: JsonRecord) {
    return async ({ artifact, requirement }: JsonRecord) => {
      const signed = verifySignedArtifact(artifact, trustedRoles);
      if (!signed.ok) return { valid: false, reason: signed.reason };
      const body = signed.body!;
      const claims = body.claims ?? {};
      if (requirement.verifier_profile === 'ep-execution-binding:v1') {
        if (claims.before_digest !== expectedAction.base_artifact_digest
            || claims.after_digest !== expectedAction.candidate_artifact_digest
            || canonicalize(claims.changed_paths) !== canonicalize(expectedAction.changed_paths)) {
          return { valid: false, reason: 'change_binding_mismatch' };
        }
      }
      if (requirement.verifier_profile === 'agent-fitness-bench:v1') {
        if (controlPlaneOverlap(expectedAction.changed_paths)) {
          return { valid: false, reason: 'control_plane_overlap' };
        }
        if (claims.candidate_artifact_digest !== expectedAction.candidate_artifact_digest) {
          return { valid: false, reason: 'fitness_candidate_mismatch' };
        }
        if (claims.suite_digest !== evaluatorSuiteDigest) {
          return { valid: false, reason: 'fitness_suite_mismatch' };
        }
        if (claims.environment_digest !== evaluatorEnvironmentDigest
            || claims.policy_digest !== evaluatorPolicyDigest
            || claims.verdict !== 'pass') {
          return { valid: false, reason: 'fitness_policy_mismatch' };
        }
      }
      if (requirement.verifier_profile === 'ep-canary-result:v1'
          && claims.candidate_artifact_digest !== expectedAction.candidate_artifact_digest) {
        return { valid: false, reason: 'canary_candidate_mismatch' };
      }
      return resultFromEvidence(body);
    };
  }

  async function run({
    action: presentedAction = action,
    operationId = presentedAction.operation_id,
    fitnessClaims = {},
  }: {
    action?: JsonRecord;
    operationId?: string;
    fitnessClaims?: JsonRecord;
  } = {}) {
    const trustReceiptKeys = generateKeyPairSync('ed25519');
    const verifier = makeVerifier(presentedAction);
    const verifiers = Object.fromEntries([
      'ep-class-a:v1',
      'ep-authority-allocation:v1',
      'ep-execution-binding:v1',
      'agent-fitness-bench:v1',
      'ep-status:v1',
      'ep-canary-result:v1',
    ].map((profileId) => [profileId, verifier]));
    const kernel = createTrustProgramKernel({
      program: promotionProgram,
      store: createMemoryTrustProgramStore(),
      verifiers,
      receiptPrivateKey: trustReceiptKeys.privateKey,
      receiptContext: {
        issuer: 'emilia-self-modification-example',
        tenant: 'example',
        environment: 'local-demo',
        audience: 'self-modification-verifier',
        key_id: 'self-modification-example-key',
      },
      actionBindingVerifier: ({ action: observed, expectedCaid, expectedActionDigest }: JsonRecord) => (
        observed?.caid === expectedCaid
        && resolveActionCaid(observed) === expectedCaid
        && exactActionDigest(observed) === expectedActionDigest
        && changeDigestMatches(observed)
        && observed?.action_digest === expectedActionDigest
      ),
      allowEphemeralState: true,
      now: () => NOW,
    });
    const instanceId = `self-modification:${operationId}`;
    const started = await kernel.start({ instanceId, action: presentedAction });
    if (!started.ok) return { ok: false, outcome: 'refused', reason: started.reason };

    const child = profile.children[1];
    const roleByProfile = {
      'ep-class-a:v1': 'human:owner',
      'ep-authority-allocation:v1': 'service:authority-allocator:1',
      'ep-execution-binding:v1': 'service:binding-verifier:1',
      'agent-fitness-bench:v1': 'service:evaluator:1',
      'ep-status:v1': 'service:status-verifier:1',
      'ep-canary-result:v1': 'service:canary-verifier:1',
    };
    for (const stage of promotionProgram.stages) {
      for (const requirement of stage.requirements) {
        const challenge = await kernel.challenge({
          instanceId,
          stageId: stage.stage_id,
          requirementId: requirement.requirement_id,
        });
        if (!challenge.ok) return { ok: false, outcome: 'refused', reason: challenge.reason };
        let claims: JsonRecord = { status: 'current' };
        if (requirement.verifier_profile === 'ep-execution-binding:v1') claims = child.change;
        if (requirement.verifier_profile === 'agent-fitness-bench:v1') claims = {
          candidate_artifact_digest: presentedAction.candidate_artifact_digest,
          suite_digest: evaluatorSuiteDigest,
          environment_digest: evaluatorEnvironmentDigest,
          policy_digest: evaluatorPolicyDigest,
          verdict: 'pass',
          ...fitnessClaims,
        };
        if (requirement.verifier_profile === 'ep-canary-result:v1') claims = {
          candidate_artifact_digest: presentedAction.candidate_artifact_digest,
          canary_goal_id: 'goal:canary-candidate',
          exposure_percent: 10,
          verdict: 'pass',
        };
        const roleId = roleByProfile[requirement.verifier_profile];
        const role = roles.get(roleId);
        if (!role) return { ok: false, outcome: 'refused', reason: 'evidence_role_unavailable' };
        const artifact = signedArtifact(
          challenge,
          requirement,
          role,
          claims,
          `evidence:${operationId}:${requirement.requirement_id}`,
        );
        const admitted = await kernel.admit({
          instanceId,
          stageId: stage.stage_id,
          requirementId: requirement.requirement_id,
          artifact,
        });
        if (!admitted.ok) return { ok: false, outcome: 'refused', reason: admitted.reason };
      }
    }

    const claim = await kernel.claimExecution({
      instanceId,
      operationId,
      claimToken: selfModificationDigest(`claim:${operationId}`).slice(7),
    });
    if (!claim.ok) return { ok: false, outcome: 'refused', reason: claim.reason };
    if (typeof claim.claim_token !== 'string') {
      return { ok: false, outcome: 'indeterminate', reason: 'execution_claim_token_missing' };
    }

    const capabilityResult = await executeWithCapability({
      capabilityReceipt: capability.capabilityReceipt,
      secret: capability.secret!,
      action: { amount: 1, currency: 'SELF_EDIT' },
      observedAction: presentedAction,
      operationId,
      store: capabilityStore,
      trustedIssuerKeys: [capabilityIssuerKey],
      gate,
      selector: SELECTOR,
      verifyActionProfile: (candidate, pinned) => {
        if (pinned.profile_id !== PROFILE_ID || pinned.profile_digest !== compiled.profile_digest) {
          return { ok: false, reason: 'self_modification_profile_mismatch' };
        }
        if (resolveActionCaid(candidate) !== child.caid
            || exactActionDigest(candidate) !== child.action_digest
            || !changeDigestMatches(candidate)
            || candidate.caid !== child.caid
            || candidate.action_digest !== child.action_digest) {
          return { ok: false, reason: 'self_modification_action_mismatch' };
        }
        return {
          ok: true,
          action_fence_digest: capabilityActionDigest(exactActionMaterial(candidate)),
        };
      },
      allowanceStatus,
      executeAction: async (immutableAction) => {
        providerCallCount += 1;
        return provider(immutableAction);
      },
      now: () => NOW,
    });

    const terminalOutcome = capabilityResult.ok
      ? 'executed'
      : capabilityResult.reason === 'effect_indeterminate' || capabilityResult.reason === 'capability_commit_indeterminate'
        ? 'indeterminate'
        : 'refused';
    const evidenceDigest = selfModificationDigest({
      operation_id: operationId,
      outcome: terminalOutcome,
      capability_reason: capabilityResult.reason ?? null,
      action_digest: capabilityResult.action_digest ?? null,
    });
    const finalized = await kernel.finalizeExecution({
      instanceId,
      claimToken: claim.claim_token,
      outcome: terminalOutcome,
      evidenceDigest,
      evidence: capabilityResult,
    });
    if (!finalized.ok) return { ok: false, outcome: 'indeterminate', reason: finalized.reason };
    return {
      ok: capabilityResult.ok,
      outcome: terminalOutcome,
      reason: capabilityResult.reason,
      caid: presentedAction.caid,
      action_digest: presentedAction.action_digest,
      capability: capabilityResult,
      trust_state: finalized.state,
    };
  }

  return Object.freeze({
    profile,
    compiled,
    action,
    canaryAction,
    run,
    providerCalls: () => providerCallCount,
    capabilityState: () => capabilityStore.getState(capability.capabilityReceipt.capability.id),
  });
}
