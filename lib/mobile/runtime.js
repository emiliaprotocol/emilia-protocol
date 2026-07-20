// SPDX-License-Identifier: Apache-2.0
import {
  createGovernmentMobileController,
  createMobileCeremonyService,
  createMobileEnrollmentService,
  createMobileHttpHandler,
  createMobileRelianceProfile,
} from '@/packages/mobile/index.js';
import { createDurableChallengeStore } from '@/packages/gate/challenge-store.js';
import { getGuardedClient } from '@/lib/write-guard.js';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit.js';
import { getMobileConfig } from './config.js';
import {
  authenticateMobileToken,
  commitMobileActionDecision,
  createMobileAuditLog,
  createMobileCounterStore,
  createMobileEnrollmentDirectory,
  createMobileStateBackend,
  registerMobileActionChallenge,
  resolveMobileAction,
} from './store.js';
import {
  createGooglePlayIntegrityDecoder,
  createPlatformEnrollmentVerifier,
  createProductionAttestationVerifier,
  verifyMobilePasskeyRegistration,
} from './attestation.js';

function refusal(verdict, reason) {
  return {
    valid: false,
    ok: false,
    verdict,
    decision: null,
    challenge: null,
    reason,
    checks: {},
  };
}

function rateLimitResponse(result) {
  const unavailable = typeof result?.error === 'string';
  return new Response(JSON.stringify({
    ok: false,
    valid: false,
    verdict: unavailable ? 'refuse_store_unavailable' : 'refuse_rate_limited',
    reason: unavailable
      ? 'mobile authorization rate limiter unavailable'
      : 'mobile authorization request rate exceeded',
  }), {
    status: unavailable ? 503 : 429,
    headers: {
      'cache-control': 'no-store',
      'content-type': 'application/json; charset=utf-8',
      pragma: 'no-cache',
      'referrer-policy': 'no-referrer',
      'retry-after': String(Math.max(1, Number(result?.reset) || 60)),
      'x-content-type-options': 'nosniff',
    },
  });
}

function noEnrollmentController() {
  return {
    async issue() { return refusal('refuse_profile_mismatch', 'enroll this device before requesting an action'); },
    async verify() { return refusal('refuse_profile_mismatch', 'no active enrollment matches this ceremony'); },
  };
}

function playDecoder(env, config) {
  if (!env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON) {
    return async () => { throw new Error('Google Play Integrity verification is not configured'); };
  }
  return createGooglePlayIntegrityDecoder(/** @type {any} */ ({
    serviceAccount: env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON,
    packageName: config.androidPackageName,
  }));
}

export function mobileSessionAuthorizes(session, input) {
  return Boolean(session
    && session.approver_id === input.approver_id
    && session.profile_id === input.profile_id
    && session.platform === input.platform
    && session.app_id === input.app_id
    && ((input.device_key_id === null && session.device_key_id === null)
      || (typeof input.device_key_id === 'string' && input.device_key_id === session.device_key_id)));
}

/**
 * @param {{ request?: Request, env?: NodeJS.ProcessEnv }} [options]
 */
export async function createMobileRuntime({ request, env = process.env } = {}) {
  const supabase = getGuardedClient();
  const session = await authenticateMobileToken(supabase, request?.headers?.get('authorization'));
  if (!session) return { session: null, handler: null };

  const config = getMobileConfig({ env });
  if ((session.platform === 'ios' && session.app_id !== config.iosBundleId)
      || (session.platform === 'android' && session.app_id !== config.androidPackageName)) {
    return { session: null, handler: null };
  }
  if (session.platform === 'android' && (!config.androidConfigured || !env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON)) {
    throw new Error('Android mobile verification is not fully configured');
  }
  const stateBackend = createMobileStateBackend(supabase);
  const challengeStore = createDurableChallengeStore(stateBackend);
  const directory = createMobileEnrollmentDirectory(supabase, session.entity_ref, session.session_id);
  const webAuthnCounterStore = createMobileCounterStore(supabase, 'mobile:webauthn');
  const attestationCounterStore = createMobileCounterStore(supabase, 'mobile:platform-attestation');
  const auditLog = createMobileAuditLog(supabase, session.entity_ref);
  const decodePlay = playDecoder(env, config);
  const verifyEnrollmentPlatform = createPlatformEnrollmentVerifier(/** @type {any} */ ({ config, playDecoder: decodePlay }));
  const attestationVerifier = createProductionAttestationVerifier(/** @type {any} */ ({
    config,
    directory,
    counterStore: attestationCounterStore,
    playDecoder: decodePlay,
  }));
  const enrollmentService = createMobileEnrollmentService({
    challengeStore,
    directory,
    verifyPasskeyRegistration: verifyMobilePasskeyRegistration,
    verifyPlatformEnrollment: verifyEnrollmentPlatform,
    authorizeEnrollment: (input) => mobileSessionAuthorizes(session, {
      ...input,
      profile_id: session.profile_id,
      device_key_id: null,
    }),
  });

  const enrollments = (await directory.active()).filter((item) => item.approver_id === session.approver_id);
  /** @type {{ issue: (request?: any, caller?: any) => Promise<any>, verify: (presentation?: any, caller?: any) => Promise<any> }} */
  let controller = noEnrollmentController();
  if (enrollments.length > 0) {
    const profile = createMobileRelianceProfile({
      profileId: config.profileId,
      rpId: config.rpId,
      allowedOrigins: [config.iosOrigin, ...config.androidOrigins],
      acceptedApps: {
        ios: [config.iosBundleId],
        android: [config.androidPackageName],
      },
      enrollments,
      maxChallengeAgeMs: config.maxChallengeAgeMs,
    });
    const service = createMobileCeremonyService({
      challengeStore,
      auditLog,
      counterStore: webAuthnCounterStore,
      attestationVerifier,
      commitDecision: ({ challenge, result, auditEntry }) => /** @type {any} */ (commitMobileActionDecision(supabase, {
        entityRef: session.entity_ref,
        sessionId: session.session_id,
        challengeId: challenge.challenge_id,
        actionHash: challenge.action_hash,
        decision: result.decision,
        verdict: result.verdict,
        decisionEvidence: result.decision_evidence,
        auditEntry,
      })),
    });
    controller = createGovernmentMobileController({
      service,
      profiles: new Map([[profile.profile_id, profile]]),
      authorize: (input) => mobileSessionAuthorizes(session, input),
      registerChallenge: (challenge) => registerMobileActionChallenge(supabase, {
        entityRef: session.entity_ref,
        sessionId: session.session_id,
        actionReference: challenge.action_reference,
        approverId: challenge.approver_id,
        challengeId: challenge.challenge_id,
        actionHash: challenge.action_hash,
        decision: challenge.decision,
        expiresAt: challenge.expires_at,
      }),
      resolveRequest: /** @type {any} */ (async ({ action_reference: actionReference, approver_id: approverId }) => {
        const row = await resolveMobileAction(supabase, {
          entityRef: session.entity_ref,
          approverId,
          actionReference,
        });
        if (!row) return null;
        const issuedAt = new Date().toISOString();
        const expiresAt = new Date(Math.min(
          Date.parse(row.expires_at),
          Date.now() + config.maxChallengeAgeMs,
        )).toISOString();
        const approvers = Array.isArray(row.policy?.approvers)
          ? row.policy.approvers.filter((value) => typeof value === 'string')
          : [];
        const requiredApprovals = Number.isSafeInteger(row.policy?.required_approvals)
          ? row.policy.required_approvals
          : 1;
        const approverIndex = approvers.length > 0
          ? approvers.indexOf(row.approver_id) + 1
          : 1;
        if (requiredApprovals < 1
            || (approvers.length === 0 && requiredApprovals !== 1)
            || (approvers.length > 0 && (approverIndex < 1
              || approverIndex > approvers.length
              || requiredApprovals > approvers.length))) {
          return null;
        }
        return {
          action: row.action,
          presentation: row.presentation,
          policy: row.policy,
          policy_id: row.policy_id,
          initiator_id: row.initiator_id,
          approver_id: row.approver_id,
          approver_index: approverIndex,
          required_approvals: requiredApprovals,
          issued_at: issuedAt,
          expires_at: expiresAt,
        };
      }),
    });
  }

  const handler = createMobileHttpHandler({
    controller,
    enrollmentService,
    authenticate: () => session,
    resolveEnrollmentIdentity: ({ approver_id: approverId }) => ({
      userName: `${approverId}@${session.entity_ref}`,
      displayName: approverId,
    }),
    enrollmentConfig: {
      rpId: config.rpId,
      origins: {
        ios: config.iosOrigin,
        android: config.androidOrigins[0] || config.iosOrigin,
      },
    },
    routePrefix: '/api/v1/mobile',
  });
  return { session, handler, config };
}

export async function handleMobileRuntimeRequest(request) {
  const networkLimit = await checkRateLimit(`ip:${getClientIP(request)}`, 'mobile_runtime_ip');
  if (!networkLimit.allowed) return rateLimitResponse(networkLimit);
  const runtime = await createMobileRuntime({ request });
  if (!runtime.handler) {
    return new Response(JSON.stringify({
      ok: false,
      valid: false,
      verdict: 'refuse_unauthorized',
      reason: 'a valid paired mobile session is required',
    }), {
      status: 401,
      headers: {
        'cache-control': 'no-store',
        'content-type': 'application/json; charset=utf-8',
        pragma: 'no-cache',
        'referrer-policy': 'no-referrer',
        'x-content-type-options': 'nosniff',
      },
    });
  }
  const sessionLimit = await checkRateLimit(`session:${runtime.session.session_id}`, 'mobile_write');
  if (!sessionLimit.allowed) return rateLimitResponse(sessionLimit);
  return runtime.handler(request);
}
