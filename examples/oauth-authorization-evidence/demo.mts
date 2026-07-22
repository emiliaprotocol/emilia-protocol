#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * OAuth Authorization Evidence + EP receipt composition lab.
 *
 * draft-liu-oauth-authorization-evidence-01 defines the OAuth/RAR envelope and
 * an AS-signed record of the consent interaction. EP supplies the optional
 * user-side authorization artifact contemplated by Section 8.2. The artifacts
 * join through audit_trail.evidence_ref, which is protected by the signed
 * access token and resolves to a content-addressed EP receipt.
 *
 * Trust roots remain separate:
 *   - AS key: verifies the access token and detached evidence JWS.
 *   - Directory root: verifies the relying party's approver-key snapshot.
 *   - Receipt-log key: verifies the EP receipt checkpoint.
 *
 * No key named by the presented receipt is trusted as its own authority.
 */
import crypto from 'node:crypto';
import { CompactSign, SignJWT, compactVerify, jwtVerify } from 'jose';
import {
  actionHash,
  canonicalize,
  generateEd25519KeyPair,
  issueTrustReceipt,
  publicKeyToSpkiB64u,
  softwareSignerFromPrivateKey,
} from '../../packages/issue/index.js';
import { verifyTrustReceipt } from '../../packages/verify/index.js';

export const LAB_VERSION = 'EP-OAUTH-AUTHORIZATION-EVIDENCE-LAB-v1';
export const DRAFT_VERSION = 'draft-liu-oauth-authorization-evidence-01';

const AS_ISSUER = 'https://as.example';
const RESOURCE_AUDIENCE = 'https://api.merchant.example';
const AS_KEY_ID = 'as.example#evidence-1';
const DIRECTORY_KEY_ID = 'merchant.example#approver-directory-1';
const LOG_KEY_ID = 'ep:log:merchant-example#1';
const APPROVER_KEY_ID = 'ep:key:alice#2026-07';
const APPROVER_ID = 'ep:approver:alice';
const AGENT_ID = 'agent:shopping-assistant:42';
const MAX_CONFIRMATION_AGE_SEC = 300;

export const EXACT_ACTION = Object.freeze({
  ep_version: '1.0',
  action_type: 'commerce.purchase.execute',
  target: Object.freeze({
    system: 'api.merchant.example',
    resource: 'orders/order-8841',
  }),
  parameters: Object.freeze({
    merchant: 'merchant.example',
    sku: 'headphones-pro-2',
    quantity: 1,
    total: '2499.00',
    currency: 'USD',
    ship_to_country: 'US',
  }),
  initiator: AGENT_ID,
  policy_id: 'policy:shopping-agent:high-value-purchase@7',
  requested_at: '2026-07-16T18:00:00Z',
});

type LabVerificationInput = {
  accessToken?: string;
  expectedAction?: Record<string, any>;
  artifactStore?: Map<string, any>;
  approverDirectory?: any;
  trust?: any;
  now?: Date;
};

const sha256Hex = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const clone = (value) => structuredClone(value);

function receiptReference(receipt) {
  return `urn:ep:receipt:sha256:${sha256Hex(Buffer.from(canonicalize(receipt), 'utf8'))}`;
}

function evidenceSignatureInput(evidence) {
  return {
    id: evidence.id,
    user_confirmation: evidence.user_confirmation,
  };
}

async function createDetachedEvidenceJws(evidence, privateKey) {
  const payload = Buffer.from(canonicalize(evidenceSignatureInput(evidence)), 'utf8');
  const compact = await new CompactSign(payload)
    .setProtectedHeader({ alg: 'ES256', kid: AS_KEY_ID })
    .sign(privateKey);
  const [header, , signature] = compact.split('.');
  return `${header}..${signature}`;
}

async function verifyDetachedEvidenceJws(evidence, publicKey) {
  const parts = typeof evidence?.as_signature === 'string'
    ? evidence.as_signature.split('.')
    : [];
  if (parts.length !== 3 || parts[1] !== '') throw new Error('as_signature is not a detached compact JWS');
  const payload = Buffer.from(canonicalize(evidenceSignatureInput(evidence)), 'utf8');
  const attached = `${parts[0]}.${payload.toString('base64url')}.${parts[2]}`;
  const result = await compactVerify(attached, publicKey, { algorithms: ['ES256'] });
  if (result.protectedHeader.kid !== AS_KEY_ID) throw new Error('unexpected AS evidence key id');
  return true;
}

function createDirectorySnapshot({ entry, rootPrivateKey, now }) {
  const payload = {
    profile: 'example-signed-approver-directory-snapshot',
    directory_id: 'https://merchant.example/approvers',
    sequence: 18,
    valid_from: new Date(now.getTime() - 60_000).toISOString(),
    valid_until: new Date(now.getTime() + 3_600_000).toISOString(),
    entries: { [APPROVER_KEY_ID]: entry },
  };
  return {
    payload,
    signature: {
      alg: 'Ed25519',
      kid: DIRECTORY_KEY_ID,
      value: crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), rootPrivateKey).toString('base64url'),
    },
  };
}

function verifyDirectorySnapshot(snapshot, pinnedDirectoryRoots, now) {
  if (!snapshot || typeof snapshot !== 'object') throw new Error('missing approver directory snapshot');
  const { payload, signature } = snapshot;
  if (!payload || !signature || signature.alg !== 'Ed25519') throw new Error('malformed approver directory snapshot');
  const root = pinnedDirectoryRoots?.[signature.kid];
  if (typeof root !== 'string') throw new Error('directory root is not pinned');
  const publicKey = crypto.createPublicKey({
    key: Buffer.from(root, 'base64url'),
    format: 'der',
    type: 'spki',
  });
  const signatureOk = crypto.verify(
    null,
    Buffer.from(canonicalize(payload), 'utf8'),
    publicKey,
    Buffer.from(signature.value || '', 'base64url'),
  );
  if (!signatureOk) throw new Error('approver directory signature is invalid');
  const nowMs = now.getTime();
  const from = Date.parse(payload.valid_from);
  const until = Date.parse(payload.valid_until);
  if (!Number.isFinite(from) || !Number.isFinite(until) || nowMs < from || nowMs > until) {
    throw new Error('approver directory snapshot is outside its validity window');
  }
  if (!payload.entries || typeof payload.entries !== 'object' || Array.isArray(payload.entries)) {
    throw new Error('approver directory entries are malformed');
  }
  return clone(payload.entries);
}

async function issueAccessToken({ evidence, privateKey, now }) {
  const iat = Math.floor(now.getTime() / 1000);
  return new SignJWT({
    scope: 'purchase:execute',
    authorization_details: [{ type: 'authorization_evidence', evidence }],
  })
    .setProtectedHeader({ alg: 'ES256', kid: AS_KEY_ID, typ: 'at+jwt' })
    .setIssuer(AS_ISSUER)
    .setAudience(RESOURCE_AUDIENCE)
    .setSubject(AGENT_ID)
    .setJti(crypto.randomUUID())
    .setIssuedAt(iat)
    .setExpirationTime(iat + 300)
    .sign(privateKey);
}

function refusal(checks, reason) {
  return { accepted: false, checks, reason };
}

/**
 * Resource-server verification. Hostile input always yields a typed refusal;
 * it never escapes as an exception or silently skips a trust leg.
 */
export async function verifyOAuthAuthorizationEvidence({
  accessToken,
  expectedAction,
  artifactStore,
  approverDirectory,
  trust,
  now = new Date(),
}: LabVerificationInput = {}) {
  const checks = {
    access_token: false,
    as_evidence_signature: false,
    evidence_time: false,
    evidence_reference: false,
    approver_directory: false,
    ep_receipt: false,
    action_binding: false,
    subject_binding: false,
  };

  try {
    if (!(now instanceof Date) || !Number.isFinite(now.getTime())) return refusal(checks, 'invalid_verification_time');
    if (!expectedAction || typeof expectedAction !== 'object') return refusal(checks, 'missing_expected_action');
    if (typeof accessToken !== 'string' || !accessToken) return refusal(checks, 'missing_access_token');
    const token = await jwtVerify(accessToken, trust?.asPublicKey, {
      issuer: AS_ISSUER,
      audience: RESOURCE_AUDIENCE,
      algorithms: ['ES256'],
      currentDate: now,
      typ: 'at+jwt',
    });
    if (token.protectedHeader.kid !== AS_KEY_ID) return refusal(checks, 'unexpected_as_key');
    checks.access_token = true;

    const details = token.payload.authorization_details;
    const matches = Array.isArray(details)
      ? details.filter((item) => item?.type === 'authorization_evidence')
      : [];
    if (matches.length !== 1 || !matches[0].evidence) return refusal(checks, 'missing_or_ambiguous_authorization_evidence');
    const evidence = matches[0].evidence;

    await verifyDetachedEvidenceJws(evidence, trust.asPublicKey);
    checks.as_evidence_signature = true;

    const confirmationTime = evidence?.user_confirmation?.timestamp;
    const tokenIssuedAt = token.payload.iat;
    const nowSeconds = Math.floor(now.getTime() / 1000);
    if (typeof confirmationTime !== 'number' || !Number.isSafeInteger(confirmationTime)
        || typeof tokenIssuedAt !== 'number' || !Number.isSafeInteger(tokenIssuedAt)
        || confirmationTime > tokenIssuedAt
        || confirmationTime > nowSeconds
        || nowSeconds - confirmationTime > MAX_CONFIRMATION_AGE_SEC) {
      return refusal(checks, 'evidence_time_is_inconsistent_with_token');
    }
    checks.evidence_time = true;

    const reference = evidence?.audit_trail?.evidence_ref;
    if (typeof reference !== 'string' || !reference.startsWith('urn:ep:receipt:sha256:')) {
      return refusal(checks, 'missing_or_unsupported_evidence_reference');
    }
    const receipt = artifactStore instanceof Map ? artifactStore.get(reference) : undefined;
    if (!receipt || receiptReference(receipt) !== reference) return refusal(checks, 'evidence_reference_digest_mismatch');
    checks.evidence_reference = true;

    const approverKeys = verifyDirectorySnapshot(approverDirectory, trust.pinnedDirectoryRoots, now);
    checks.approver_directory = true;

    const receiptReport = verifyTrustReceipt(receipt, {
      approverKeys,
      logPublicKey: trust.logPublicKey,
    });
    if (!receiptReport.valid) return refusal(checks, `ep_receipt_refused:${receiptReport.errors[0] || 'invalid'}`);
    checks.ep_receipt = true;

    checks.action_binding = receipt.action_hash === actionHash(expectedAction);
    if (!checks.action_binding) return refusal(checks, 'authorized_action_does_not_match_requested_action');

    checks.subject_binding = token.payload.sub === expectedAction.initiator;
    if (!checks.subject_binding) return refusal(checks, 'token_subject_does_not_match_action_initiator');

    return { accepted: true, checks, reason: null, evidence_id: evidence.id, receipt_id: receipt.receipt_id };
  } catch (error) {
    return refusal(checks, `verification_error:${error instanceof Error ? error.message : 'unknown'}`);
  }
}

function tamperJwtPayload(jwt, mutate) {
  const parts = jwt.split('.');
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  mutate(payload);
  parts[1] = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  return parts.join('.');
}

async function issueReceipt({ action, approver, approverKeyId, log, issuedAt, signedAt, expiresAt }) {
  return issueTrustReceipt({
    receiptId: `ep:receipt:${crypto.randomUUID()}`,
    action,
    policyHash: 'sha256:2da7b1b2ae86d7fef324ddf9a8bcd3ed3f711ba95f832f42f597c23c654f15f2',
    approvers: [APPROVER_ID],
    requiredApprovals: 1,
    issuedAt,
    expiresAt,
    committedAt: signedAt,
    signers: [softwareSignerFromPrivateKey({
      privateKey: approver.privateKey,
      approverKeyId,
      signedAt,
      keyClass: 'B',
    })],
    log: { privateKey: log.privateKey, logKeyId: LOG_KEY_ID },
  });
}

/** Build and attack the full composition. */
export async function runOAuthAuthorizationEvidenceLab() {
  const now = new Date();
  const issuedAt = new Date(now.getTime() - 10_000).toISOString();
  const signedAt = new Date(now.getTime() - 8_000).toISOString();
  const expiresAt = new Date(now.getTime() + 300_000).toISOString();

  const asKey = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const approver = generateEd25519KeyPair();
  const rogueApprover = generateEd25519KeyPair();
  const log = generateEd25519KeyPair();
  const directoryRoot = generateEd25519KeyPair();

  const approverEntry = {
    approver_id: APPROVER_ID,
    public_key: publicKeyToSpkiB64u(approver.publicKey),
    key_class: 'B',
    valid_from: new Date(now.getTime() - 86_400_000).toISOString(),
    valid_to: new Date(now.getTime() + 86_400_000).toISOString(),
    roles: ['high_value_purchaser'],
  };
  const directory = createDirectorySnapshot({
    entry: approverEntry,
    rootPrivateKey: directoryRoot.privateKey,
    now,
  });
  const trust = {
    asPublicKey: asKey.publicKey,
    pinnedDirectoryRoots: {
      [DIRECTORY_KEY_ID]: publicKeyToSpkiB64u(directoryRoot.publicKey),
    },
    logPublicKey: publicKeyToSpkiB64u(log.publicKey),
  };

  const receipt = await issueReceipt({
    action: EXACT_ACTION,
    approver,
    approverKeyId: APPROVER_KEY_ID,
    log,
    issuedAt,
    signedAt,
    expiresAt,
  });
  const reference = receiptReference(receipt);
  const evidence: Record<string, any> = {
    id: `urn:uuid:${crypto.randomUUID()}`,
    user_confirmation: {
      displayed_content: 'Purchase 1 headphones-pro-2 from merchant.example for USD 2,499.00',
      user_action: 'biometric_confirmation',
      timestamp: Math.floor((now.getTime() - 9_000) / 1000),
    },
    audit_trail: {
      semantic_expansion_level: 'none',
      proposal_ref: 'urn:uuid:0f837236-19e6-45bb-88cb-478b58d44b80',
      evidence_ref: reference,
    },
  };
  evidence.as_signature = await createDetachedEvidenceJws(evidence, asKey.privateKey);
  const accessToken = await issueAccessToken({ evidence, privateKey: asKey.privateKey, now });
  const artifactStore = new Map([[reference, receipt]]);

  const verify = (overrides = {}) => verifyOAuthAuthorizationEvidence({
    accessToken,
    expectedAction: EXACT_ACTION,
    artifactStore,
    approverDirectory: directory,
    trust,
    now,
    ...overrides,
  });

  const cases: Array<{
    id: string;
    expected: 'accept' | 'refuse';
    result: Awaited<ReturnType<typeof verifyOAuthAuthorizationEvidence>>;
  }> = [];
  cases.push({
    id: 'accept-composed-evidence',
    expected: 'accept',
    result: await verify(),
  });

  cases.push({
    id: 'refuse-action-substitution',
    expected: 'refuse',
    result: await verify({ expectedAction: { ...EXACT_ACTION, parameters: { ...EXACT_ACTION.parameters, total: '24999.00' } } }),
  });

  const tamperedToken = tamperJwtPayload(accessToken, (payload) => {
    payload.authorization_details[0].evidence.audit_trail.evidence_ref = `urn:ep:receipt:sha256:${'0'.repeat(64)}`;
  });
  cases.push({
    id: 'refuse-token-level-reference-tamper',
    expected: 'refuse',
    result: await verify({ accessToken: tamperedToken }),
  });

  const badInnerEvidence = clone(evidence);
  {
    const [header, , encodedSignature] = badInnerEvidence.as_signature.split('.');
    const signatureBytes = Buffer.from(encodedSignature, 'base64url');
    signatureBytes[0] ^= 0x01;
    badInnerEvidence.as_signature = `${header}..${signatureBytes.toString('base64url')}`;
  }
  const tokenWithBadInnerSignature = await issueAccessToken({
    evidence: badInnerEvidence,
    privateKey: asKey.privateKey,
    now,
  });
  cases.push({
    id: 'refuse-invalid-detached-as-signature',
    expected: 'refuse',
    result: await verify({ accessToken: tokenWithBadInnerSignature }),
  });

  const staleEvidence = clone(evidence);
  staleEvidence.id = `urn:uuid:${crypto.randomUUID()}`;
  staleEvidence.user_confirmation.timestamp = Math.floor((now.getTime() - 600_000) / 1000);
  staleEvidence.as_signature = await createDetachedEvidenceJws(staleEvidence, asKey.privateKey);
  const tokenWithStaleEvidence = await issueAccessToken({
    evidence: staleEvidence,
    privateKey: asKey.privateKey,
    now,
  });
  cases.push({
    id: 'refuse-stale-user-confirmation',
    expected: 'refuse',
    result: await verify({ accessToken: tokenWithStaleEvidence }),
  });

  const mutatedReceipt = clone(receipt);
  mutatedReceipt.action.parameters.total = '24999.00';
  cases.push({
    id: 'refuse-content-address-mismatch',
    expected: 'refuse',
    result: await verify({ artifactStore: new Map([[reference, mutatedReceipt]]) }),
  });

  const rogueReceipt = await issueReceipt({
    action: EXACT_ACTION,
    approver: rogueApprover,
    approverKeyId: 'ep:key:attacker#1',
    log,
    issuedAt,
    signedAt,
    expiresAt,
  });
  const rogueReference = receiptReference(rogueReceipt);
  const rogueEvidence = clone(evidence);
  rogueEvidence.id = `urn:uuid:${crypto.randomUUID()}`;
  rogueEvidence.audit_trail.evidence_ref = rogueReference;
  rogueEvidence.as_signature = await createDetachedEvidenceJws(rogueEvidence, asKey.privateKey);
  const rogueToken = await issueAccessToken({ evidence: rogueEvidence, privateKey: asKey.privateKey, now });
  cases.push({
    id: 'refuse-receipt-key-not-in-pinned-directory',
    expected: 'refuse',
    result: await verify({
      accessToken: rogueToken,
      artifactStore: new Map([[rogueReference, rogueReceipt]]),
    }),
  });

  const modifiedDirectory = clone(directory);
  modifiedDirectory.payload.entries[APPROVER_KEY_ID].public_key = publicKeyToSpkiB64u(rogueApprover.publicKey);
  cases.push({
    id: 'refuse-directory-entry-substitution',
    expected: 'refuse',
    result: await verify({ approverDirectory: modifiedDirectory }),
  });

  return {
    '@version': LAB_VERSION,
    source_draft: DRAFT_VERSION,
    composition: 'OAuth/RAR carries the AS-witnessed interaction; evidence_ref joins a separately verifiable EP receipt by digest.',
    trust_roots: ['authorization server', 'organization approver directory', 'receipt transparency log'],
    cases,
  };
}

function printLab(result) {
  const green = (value) => `\x1b[32m${value}\x1b[0m`;
  const red = (value) => `\x1b[31m${value}\x1b[0m`;
  console.log('='.repeat(78));
  console.log(' OAuth Authorization Evidence + EP receipt composition');
  console.log(` ${result.source_draft}`);
  console.log('='.repeat(78));
  for (const testCase of result.cases) {
    const actual = testCase.result.accepted ? 'accept' : 'refuse';
    const ok = actual === testCase.expected;
    console.log(` ${ok ? green('PASS') : red('FAIL')}  ${testCase.id}`);
    console.log(`       expected=${testCase.expected} actual=${actual} reason=${testCase.result.reason || 'none'}`);
  }
  console.log('-'.repeat(78));
  console.log(' AS evidence proves what the AS recorded. The EP leg independently proves');
  console.log(' which directory-enrolled approver signed the exact action. Neither replaces');
  console.log(' the other, and the presented receipt never supplies its own trusted key.');
  console.log('='.repeat(78));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const result = await runOAuthAuthorizationEvidenceLab();
  printLab(result);
  const ok = result.cases.every((item) => item.result.accepted === (item.expected === 'accept'));
  process.exitCode = ok ? 0 : 1;
}
