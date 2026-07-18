// SPDX-License-Identifier: Apache-2.0

import {
  getRegistrationOptions,
  getResolutionOptions,
  isReleaseLockDemoMode,
  submitResolution,
  verifyRegistration,
} from './api';

function pause(milliseconds) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

function assertResolutionContext(context, expected) {
  if (!context
    || context.ceremony !== expected.ceremony
    || context.role !== expected.role
    || context.action_digest !== expected.action_digest
    || (context.prompt_set_digest || null) !== (expected.prompt_set_digest || null)
    || (context.answer_digest || null) !== (expected.answer_digest || null)) {
    throw new Error('Approval context does not match the exact action. Nothing was approved.');
  }
}

export async function ensureReleaseLockCredential({
  lockId,
  role,
  verifiedHandle,
  credentialAlreadyEnrolled = false,
}) {
  if (credentialAlreadyEnrolled) return { credential_already_enrolled: true };
  const registration = await getRegistrationOptions(lockId, {
    role,
    verified_handle: verifiedHandle,
  });
  if (registration.credential_already_enrolled) return registration;
  let attestation;
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

export async function beginReleaseLockActionCheck({ lockId, ceremony, role }) {
  return getResolutionOptions(lockId, { ceremony, role });
}

export async function completeReleaseLockActionCheck({
  lockId,
  ceremony,
  resolution,
  answers,
}) {
  const { startAuthentication } = await import('@simplewebauthn/browser');
  const assertion = await startAuthentication({ optionsJSON: resolution.options });
  return submitResolution(lockId, {
    ceremony,
    resolution_id: resolution.resolution_id,
    answers,
    assertion,
  });
}

export async function approveReleaseLockWithPasskey({
  lockId,
  ceremony,
  role,
  verifiedHandle,
  bindings,
}) {
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

  let assertion;
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
