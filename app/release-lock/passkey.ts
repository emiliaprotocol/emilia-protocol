// SPDX-License-Identifier: Apache-2.0

import {
  getRegistrationOptions,
  getResolutionOptions,
  isReleaseLockDemoMode,
  submitResolution,
  verifyRegistration,
} from './api';

function pause(milliseconds: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

interface ResolutionContextExpected {
  ceremony: string;
  role: string;
  action_digest: string;
  prompt_set_digest?: string | null;
  answer_digest?: string | null;
}

function assertResolutionContext(context: any, expected: ResolutionContextExpected): void {
  if (!context
    || context.ceremony !== expected.ceremony
    || context.role !== expected.role
    || context.action_digest !== expected.action_digest
    || (context.prompt_set_digest || null) !== (expected.prompt_set_digest || null)
    || (context.answer_digest || null) !== (expected.answer_digest || null)) {
    throw new Error('Approval context does not match the exact action. Nothing was approved.');
  }
}

interface EnsureReleaseLockCredentialArgs {
  lockId: string;
  role: string;
  verifiedHandle: string;
  credentialAlreadyEnrolled?: boolean;
}

interface CredentialResult {
  credential_already_enrolled: boolean;
}

export async function ensureReleaseLockCredential({
  lockId,
  role,
  verifiedHandle,
  credentialAlreadyEnrolled = false,
}: EnsureReleaseLockCredentialArgs): Promise<CredentialResult> {
  if (credentialAlreadyEnrolled) return { credential_already_enrolled: true };
  const registration = await getRegistrationOptions(lockId, {
    role,
    verified_handle: verifiedHandle,
  });
  if (registration.credential_already_enrolled) return registration;
  let attestation: any;
  if (isReleaseLockDemoMode()) {
    await pause(320);
    attestation = {
      id: `demo-passkey-${role}-01`,
      type: 'public-key',
      demo: true,
    };
  } else {
    const { startRegistration } = await import('@simplewebauthn/browser');
    attestation = await startRegistration({ optionsJSON: registration.options });
  }
  await verifyRegistration(lockId, {
    role,
    verified_handle: verifiedHandle,
    registration_id: registration.registration_id,
    attestation,
  });
  return { credential_already_enrolled: true };
}

interface BeginReleaseLockActionCheckArgs {
  lockId: string;
  ceremony: string;
  role: string;
}

export async function beginReleaseLockActionCheck({ lockId, ceremony, role }: BeginReleaseLockActionCheckArgs) {
  return getResolutionOptions(lockId, { ceremony, role });
}

interface CompleteReleaseLockActionCheckArgs {
  lockId: string;
  ceremony: string;
  resolution: any;
  answers: any;
}

export async function completeReleaseLockActionCheck({
  lockId,
  ceremony,
  resolution,
  answers,
}: CompleteReleaseLockActionCheckArgs) {
  const { startAuthentication } = await import('@simplewebauthn/browser');
  const assertion = await startAuthentication({ optionsJSON: resolution.options });
  return submitResolution(lockId, {
    ceremony,
    resolution_id: resolution.resolution_id,
    answers,
    assertion,
  });
}

interface ApproveReleaseLockWithPasskeyArgs {
  lockId: string;
  ceremony: string;
  role: string;
  verifiedHandle: string;
  bindings: {
    action_digest: string;
    prompt_set_digest?: string;
    answer_digest?: string;
  };
}

export async function approveReleaseLockWithPasskey({
  lockId,
  ceremony,
  role,
  verifiedHandle,
  bindings,
}: ApproveReleaseLockWithPasskeyArgs) {
  const demo = isReleaseLockDemoMode();
  await ensureReleaseLockCredential({ lockId, role, verifiedHandle });

  const request = {
    ceremony,
    role,
    decision: 'approved',
    action_digest: bindings.action_digest,
    prompt_set_digest: bindings.prompt_set_digest || null,
    answer_digest: bindings.answer_digest || null,
  };
  const resolution = await getResolutionOptions(lockId, request);
  assertResolutionContext(resolution.context, request);

  let assertion: any;
  if (demo) {
    await pause(520);
    assertion = {
      id: `demo-passkey-${role}-01`,
      type: 'public-key',
      demo: true,
    };
  } else {
    const { startAuthentication } = await import('@simplewebauthn/browser');
    assertion = await startAuthentication({ optionsJSON: resolution.options });
  }

  return submitResolution(lockId, {
    ...request,
    resolution_id: resolution.resolution_id,
    assertion,
  });
}
