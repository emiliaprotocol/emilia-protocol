#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Review vector for draft-liu-agent-operation-authorization-02.
 *
 * The draft's signed token carries policy_id while the executable Rego policy
 * is resolved separately. This lab shows that a token can remain byte-for-byte
 * identical and signature-valid while the policy behind that identifier gains
 * broader semantics. The candidate repair binds the complete policy-resolution
 * descriptor by digest and refuses before evaluation when it changes.
 *
 * This is an interoperability review artifact, not a claim that the draft
 * requires mutable policy identifiers or that any implementation is vulnerable.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import { SignJWT, jwtVerify } from 'jose';
import { canonicalize } from '../../packages/issue/index.js';

const VECTOR_URL = new URL('./policy-alias-substitution.v1.json', import.meta.url);
const ISSUER = 'https://as.example';
const AUDIENCE = 'https://api.online-shop.example';
const SUBJECT = 'user_12345@myassistant.example';
const KEY_ID = 'as.example#operation-authorization-1';

type PolicyDescriptor = {
  policy_id: string;
  media_type: string;
  language_version: string;
  entrypoint: string;
  input_schema_digest: string;
  source: string;
};

type ReviewVector = {
  profile: string;
  source_draft: string;
  finding: string;
  token_claims: Record<string, any>;
  policy_at_confirmation: PolicyDescriptor;
  policy_at_execution: PolicyDescriptor;
  attempted_input: { transaction: { amount: number } };
};

type LabOptions = {
  resolveApprovedPolicyAtExecution?: boolean;
  attemptedAmount?: number;
};

function readVector(): ReviewVector {
  return JSON.parse(fs.readFileSync(VECTOR_URL, 'utf8')) as ReviewVector;
}

function sha256(value: string): string {
  return `sha256:${crypto.createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

/** Bind the full interpretation tuple, not only the Rego source bytes. */
export function policyResolutionDigest(policy: PolicyDescriptor): string {
  return sha256(canonicalize({
    media_type: policy.media_type,
    language_version: policy.language_version,
    entrypoint: policy.entrypoint,
    input_schema_digest: policy.input_schema_digest,
    source: policy.source,
  }));
}

function policyAllows(policy: PolicyDescriptor, amount: number): boolean {
  const match = /input\.transaction\.amount\s*<=\s*([0-9]+(?:\.[0-9]+)?)/u.exec(policy.source);
  if (!match) throw new Error('review vector contains an unsupported Rego expression');
  return amount <= Number(match[1]);
}

function confirmedDisplayLimit(claims: Record<string, any>): number {
  const content = claims.evidence?.user_confirmation_record?.displayed_content;
  const match = typeof content === 'string'
    ? /\bUSD\s+([0-9]+(?:\.[0-9]+)?)/u.exec(content)
    : null;
  if (!match) throw new Error('review vector does not state a parseable displayed USD limit');
  return Number(match[1]);
}

async function issueToken({ claims, privateKey, policyDigest }: {
  claims: Record<string, any>;
  privateKey: crypto.KeyObject;
  policyDigest?: string;
}): Promise<string> {
  const authorization = structuredClone(claims.agent_operation_authorization);
  if (policyDigest) {
    authorization.policy_binding = {
      digest: policyDigest,
      profile: 'AOP-POLICY-RESOLUTION-BINDING-v0',
    };
  }
  return new SignJWT({
    evidence: claims.evidence,
    agent_operation_authorization: authorization,
  })
    .setProtectedHeader({ alg: 'ES256', kid: KEY_ID, typ: 'at+jwt' })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setSubject(SUBJECT)
    .setJti('urn:uuid:1c89dcaa-93f5-43df-8188-e75559fce629')
    .setIssuedAt(1785780010)
    .setExpirationTime(1785783610)
    .sign(privateKey);
}

async function verifyToken(token: string, publicKey: crypto.KeyObject) {
  return jwtVerify(token, publicKey, {
    issuer: ISSUER,
    audience: AUDIENCE,
    algorithms: ['ES256'],
    typ: 'at+jwt',
    currentDate: new Date(1785780100 * 1000),
  });
}

export async function runAgentOperationAuthorizationPolicyBindingLab({
  resolveApprovedPolicyAtExecution = false,
  attemptedAmount,
}: LabOptions = {}) {
  const vector = readVector();
  const amount = attemptedAmount ?? vector.attempted_input.transaction.amount;
  const policyAtConfirmation = vector.policy_at_confirmation;
  const policyAtExecution = resolveApprovedPolicyAtExecution
    ? policyAtConfirmation
    : vector.policy_at_execution;
  const confirmationDigest = policyResolutionDigest(policyAtConfirmation);
  const executionDigest = policyResolutionDigest(policyAtExecution);
  const displayedLimit = confirmedDisplayLimit(vector.token_claims);

  const asKey = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const unboundToken = await issueToken({
    claims: vector.token_claims,
    privateKey: asKey.privateKey,
  });
  const tokenAtConfirmation = unboundToken;
  const tokenAtExecution = unboundToken;
  const unboundVerification = await verifyToken(tokenAtExecution, asKey.publicKey);
  const unboundAuthorization = unboundVerification.payload.agent_operation_authorization as
    | { policy_id?: unknown }
    | undefined;
  const unboundPolicyId = unboundAuthorization?.policy_id;
  const unboundAllows = policyAllows(policyAtExecution, amount);

  const boundToken = await issueToken({
    claims: vector.token_claims,
    privateKey: asKey.privateKey,
    policyDigest: confirmationDigest,
  });
  const boundVerification = await verifyToken(boundToken, asKey.publicKey);
  const boundAuthorization = boundVerification.payload.agent_operation_authorization as
    | { policy_binding?: { digest?: unknown } }
    | undefined;
  const boundDigest = boundAuthorization?.policy_binding?.digest;
  const policyBindingValid = boundDigest === executionDigest;

  return {
    '@version': vector.profile,
    source_draft: vector.source_draft,
    finding: vector.finding,
    same_signed_token: tokenAtConfirmation === tokenAtExecution,
    same_policy_id: unboundPolicyId === policyAtConfirmation.policy_id
      && policyAtConfirmation.policy_id === policyAtExecution.policy_id,
    policy_at_confirmation: {
      policy_id: policyAtConfirmation.policy_id,
      digest: confirmationDigest,
    },
    policy_at_execution: {
      policy_id: policyAtExecution.policy_id,
      digest: executionDigest,
    },
    unbound_resolution: {
      token_signature_valid: true,
      displayed_limit: displayedLimit,
      attempted_amount: amount,
      resolved_policy_allows: unboundAllows,
      substitution_detectable_from_token: false,
      portable_verdict: 'INDETERMINATE',
    },
    digest_bound_resolution: {
      token_signature_valid: true,
      policy_binding_valid: policyBindingValid,
      resolved_policy_allows: policyBindingValid && policyAllows(policyAtExecution, amount),
      reason: policyBindingValid ? null : 'policy_digest_mismatch',
    },
  };
}

function printLab(result: Awaited<ReturnType<typeof runAgentOperationAuthorizationPolicyBindingLab>>) {
  console.log(JSON.stringify(result, null, 2));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  printLab(await runAgentOperationAuthorizationPolicyBindingLab());
}
