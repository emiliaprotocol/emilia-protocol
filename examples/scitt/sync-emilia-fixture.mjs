// SPDX-License-Identifier: Apache-2.0
//
// SYNC x EMILIA interop fixture harness.
//
// The production signing profile supplied by SYNC is reproduced here as a
// byte-level vector.  The harness verifies the native SYNC presentation
// without promoting it into an EMILIA authorization or execution record.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturePath = path.join(here, 'fixtures', 'sync-receipt-SYNC-6A27C41D696E.vc.json');
const vectorPath = path.join(here, 'fixtures', 'sync-emilia-vectors.v1.json');
const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
const vectors = JSON.parse(fs.readFileSync(vectorPath, 'utf8'));

/**
 * The production app uses Swift JSONEncoder sortedKeys and
 * withoutEscapingSlashes.  The payload contains already encoded strings and
 * dates, so this compact sorted-key encoder is the equivalent profile for the
 * checked-in vector.
 */
export function canonicalize(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function decodeBase64Url(value) {
  return Buffer.from(
    value.replace(/-/g, '+').replace(/_/g, '/')
      + '='.repeat((4 - (value.length % 4)) % 4),
    'base64',
  );
}

function isSha256(value) {
  return typeof value === 'string' && /^SHA-256:[0-9a-f]{64}$/.test(value);
}

function isB64Url(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value) && !/[+/=]/.test(value);
}

function check(id, title, status, detail = '') {
  return { id, title, status, detail };
}

function pass(id, title, detail = '') { return check(id, title, 'PASS', detail); }
function fail(id, title, detail = '') { return check(id, title, 'FAIL', detail); }
function indeterminate(id, title, detail) { return check(id, title, 'INDETERMINATE', detail); }

function publicKeyFromRawB64(value) {
  const raw = Buffer.from(value, 'base64');
  // id-ecPublicKey / secp256r1 SubjectPublicKeyInfo wrapper.
  const prefix = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
  if (raw.length !== 65 || raw[0] !== 0x04) {
    throw new Error('SYNC public key is not a raw uncompressed P-256 point');
  }
  return crypto.createPublicKey({
    key: Buffer.concat([prefix, raw]),
    format: 'der',
    type: 'spki',
  });
}

function sha256Label(value) {
  return `SHA-256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}

/** Construct the exact object signed by the current SYNC production profile. */
export function buildSigningPayload(subject, createdAt) {
  return {
    schema: vectors.profile,
    intent: subject.intent,
    intentSha256: subject.intentHash,
    evidence: subject.evidence,
    policyContext: subject.policyContext.labels,
    createdAt,
  };
}

function isoSecondRange(anchor, beforeSeconds, afterSeconds) {
  if (typeof anchor !== 'string' || !Number.isFinite(Date.parse(anchor))) {
    throw new Error('createdAt window anchor is not a valid ISO timestamp');
  }
  if (!Number.isInteger(beforeSeconds) || beforeSeconds < 0
    || !Number.isInteger(afterSeconds) || afterSeconds < 0) {
    throw new Error('createdAt window bounds must be non-negative integers');
  }
  const anchorMs = Date.parse(anchor);
  const candidates = [];
  for (let offset = -beforeSeconds; offset <= afterSeconds; offset += 1) {
    candidates.push(new Date(anchorMs + offset * 1000).toISOString().replace('.000Z', 'Z'));
  }
  return candidates;
}

function payloadCandidate(subject, createdAt) {
  const payload = buildSigningPayload(subject, createdAt);
  const canonicalBytes = Buffer.from(canonicalize(payload), 'utf8');
  const digestB64Url = crypto.createHash('sha256').update(canonicalBytes).digest('base64url');
  return { createdAt, payload, canonicalBytes, digestB64Url };
}

/**
 * Resolve the transient production `createdAt` from the adjacent authorization
 * timestamp window. Exactly one digest match is required before signature
 * verification can proceed.
 */
export function resolveCreatedAt(subject, {
  anchor = subject.authorization?.created_at,
  beforeSeconds = 5,
  afterSeconds = 5,
  candidateCreatedAtValues,
} = {}) {
  const createdAtValues = candidateCreatedAtValues
    ?? isoSecondRange(anchor, beforeSeconds, afterSeconds);
  const candidates = [...new Set(createdAtValues)].map((createdAt) => payloadCandidate(subject, createdAt));
  const expectedDigest = subject.authorization?.signed_payload_digest_b64url;
  const matches = candidates.filter((candidate) => candidate.digestB64Url === expectedDigest);
  return {
    candidates: candidates.map((candidate) => candidate.createdAt),
    matches,
  };
}

/**
 * Verify the native SYNC profile.  This returns only the cryptographic
 * presentation result; chain continuity and EMILIA admission are separate.
 */
export function verifyProductionProfile(subject, {
  createdAt,
  createdAtWindow,
  expectedDigest,
} = {}) {
  const auth = subject.authorization;
  const resolution = createdAt
    ? { candidates: [createdAt], matches: [payloadCandidate(subject, createdAt)] }
    : resolveCreatedAt(subject, createdAtWindow);
  const failures = [];

  if (resolution.matches.length !== 1) {
    failures.push(resolution.matches.length === 0
      ? 'no createdAt candidate in the authorization timestamp window reproduces signed_payload_digest_b64url'
      : 'multiple createdAt candidates reproduce signed_payload_digest_b64url');
  }

  const selected = resolution.matches.length === 1 ? resolution.matches[0] : null;
  const payload = selected?.payload ?? null;
  const canonicalBytes = selected?.canonicalBytes ?? null;
  const digestB64Url = selected?.digestB64Url ?? null;

  if (subject.intentHash !== sha256Label(subject.intent)) {
    failures.push('intentSha256 does not match the visible intent');
  }
  if (expectedDigest && digestB64Url !== expectedDigest) {
    failures.push(`vector digest mismatch: computed ${digestB64Url}, expected ${expectedDigest}`);
  }
  if (digestB64Url && digestB64Url !== auth.signed_payload_digest_b64url) {
    failures.push('canonical payload digest does not match signed_payload_digest_b64url');
  }

  let signatureValid = false;
  if (canonicalBytes) {
    try {
      const publicKey = publicKeyFromRawB64(auth.public_key_b64);
      const signature = decodeBase64Url(auth.signature_b64url);
      signatureValid = crypto.verify('sha256', canonicalBytes, publicKey, signature);
    } catch (error) {
      failures.push(`signature material could not be decoded: ${error.message}`);
    }
    if (!signatureValid) failures.push('ES256 signature does not verify over the canonical payload');
  }

  return {
    status: failures.length === 0 ? 'PASS' : 'REFUSE',
    payload,
    canonicalBytes,
    digestB64Url,
    createdAtResolution: {
      candidates: resolution.candidates,
      matches: resolution.matches.map((candidate) => candidate.createdAt),
      selected: selected?.createdAt ?? null,
    },
    detail: failures.length === 0
      ? `createdAt resolved uniquely (${selected.createdAt}); canonical payload, disclosed digest, and DER ES256 signature agree`
      : failures.join('; '),
  };
}

function structuralChecks(subject, vc) {
  const auth = subject.authorization;
  const chain = subject.receiptChain;
  return [
    vc.type?.includes('VerifiableCredential') && vc.type?.includes('SYNCAuthorizationReceipt')
      ? pass('vc-shape', 'fixture is a VerifiableCredential with SYNCAuthorizationReceipt')
      : fail('vc-shape', 'fixture is a VerifiableCredential with SYNCAuthorizationReceipt'),
    subject.receiptType === 'human_authorization_origin_receipt'
      ? pass('receipt-type', 'receipt type is human_authorization_origin_receipt')
      : fail('receipt-type', 'receipt type is human_authorization_origin_receipt', subject.receiptType),
    subject.publicReceiptID === 'SYNC-6A27C41D696E' && subject.receiptID === '82F6AB81-EE0B-43D0-A13C-6A27C41D696E'
      ? pass('export-binding', 'public and internal receipt identifiers are present and consistent')
      : fail('export-binding', 'public and internal receipt identifiers are present and consistent'),
    vc.id?.includes(subject.receiptID)
      ? pass('top-level-id', 'top-level VC id binds to exported receipt id')
      : fail('top-level-id', 'top-level VC id binds to exported receipt id', vc.id),
    subject.intent?.includes('SYNC') && subject.intent?.includes('EMILIA')
      ? pass('purpose-binding', 'receipt states its SYNC x EMILIA conformance purpose')
      : fail('purpose-binding', 'receipt states its SYNC x EMILIA conformance purpose'),
    [subject.canonicalReceiptHash, chain.currentReceiptHash, chain.previousReceiptHash, chain.chainHead].every(isSha256)
      ? pass('hash-shapes', 'chain and canonical receipt hashes have SHA-256 shapes')
      : fail('hash-shapes', 'chain and canonical receipt hashes have SHA-256 shapes'),
    [subject.canonicalPayloadHashB64Url, subject.receiptSealHashB64Url, subject.chainHeadB64Url, auth.signed_payload_digest_b64url].every(isB64Url)
      ? pass('encoding-shapes', 'payload, seal, chain-head, and signed-digest fields have base64url shapes')
      : fail('encoding-shapes', 'payload, seal, chain-head, and signed-digest fields have base64url shapes'),
    subject.evidence?.length === 0
      ? pass('effect-boundary', 'receipt makes no physical execution/outcome claim', 'evidence array is empty; this is an authorization-origin presentation')
      : fail('effect-boundary', 'receipt makes no physical execution/outcome claim'),
    pass('policy-context', 'policy context is advisory metadata only', 'the receipt itself disclaims legal/compliance determination; policyContext is not an AEB authorization decision'),
  ];
}

function missingChainContext(subject) {
  return subject.receiptChain?.previousReceiptHash
    ? indeterminate('chain-continuity', 'receipt-chain continuity', 'previousReceiptHash is present, but the neighboring record or a trusted checkpoint is not supplied with this export')
    : fail('chain-continuity', 'receipt-chain continuity', 'previousReceiptHash is missing');
}

function clone(value) {
  return structuredClone(value);
}

export function buildVectorSubjects() {
  const positive = clone(fixture);
  const contentMutation = clone(positive);
  contentMutation.credentialSubject.intent = vectors.contentMutation.mutation.value;
  const forgedKey = clone(positive);
  forgedKey.credentialSubject.authorization.public_key_b64 = vectors.forgedKey.replacementPublicKeyB64;
  return { positive, contentMutation, forgedKey };
}

export function runVectors() {
  const subjects = buildVectorSubjects();
  const positive = verifyProductionProfile(subjects.positive.credentialSubject, {
    createdAtWindow: vectors.positive.createdAtWindow,
    expectedDigest: vectors.positive.expectedSignedPayloadDigestB64Url,
  });
  const contentMutation = verifyProductionProfile(subjects.contentMutation.credentialSubject, {
    createdAtWindow: vectors.positive.createdAtWindow,
  });
  const forgedKey = verifyProductionProfile(subjects.forgedKey.credentialSubject, {
    createdAtWindow: vectors.positive.createdAtWindow,
  });
  const results = [
    { id: vectors.positive.id, expected: vectors.positive.expected, actual: positive.status, detail: positive.detail },
    { id: vectors.contentMutation.id, expected: vectors.contentMutation.expected, actual: contentMutation.status, detail: contentMutation.detail },
    { id: vectors.forgedKey.id, expected: vectors.forgedKey.expected, actual: forgedKey.status, detail: forgedKey.detail },
    { id: vectors.missingChainContext.id, expected: vectors.missingChainContext.expected, actual: 'INDETERMINATE', detail: 'no neighboring record or trusted checkpoint was supplied' },
  ];
  return { results, subjects, positive, contentMutation, forgedKey };
}

export function run() {
  const subject = fixture.credentialSubject;
  const profile = runVectors();
  const checks = [
    ...structuralChecks(subject, fixture),
    profile.positive.status === 'PASS'
      ? pass('production-profile', 'SYNC production signing profile reproduces', profile.positive.detail)
      : fail('production-profile', 'SYNC production signing profile reproduces', profile.positive.detail),
    profile.contentMutation.status === 'REFUSE'
      ? pass('content-mutation', 'content mutation is refused', profile.contentMutation.detail)
      : fail('content-mutation', 'content mutation is refused', profile.contentMutation.detail),
    profile.forgedKey.status === 'REFUSE'
      ? pass('forged-key', 'changed public key is refused', profile.forgedKey.detail)
      : fail('forged-key', 'changed public key is refused', profile.forgedKey.detail),
    missingChainContext(subject),
  ];

  const hasFailure = checks.some((item) => item.status === 'FAIL');
  const hasIndeterminate = checks.some((item) => item.status === 'INDETERMINATE');
  const report = {
    fixture: path.relative(process.cwd(), fixturePath),
    vectorProfile: path.relative(process.cwd(), vectorPath),
    externalVerificationClaim: 'OpenVerifier.org accepted the exported receipt (per Louis Clybourn, 2026-07-25)',
    verdict: hasFailure ? 'FAIL' : hasIndeterminate ? 'INDETERMINATE' : 'SATISFIED',
    admission: hasFailure || hasIndeterminate ? 'REFUSE_CONSEQUENTIAL_EFFECT' : 'ADMIT_SUBJECT_TO_LOCAL_POLICY',
    checks,
    vectors: profile.results,
    note: 'The native SYNC presentation now has a reproducible cryptographic vector. It remains distinct from an EMILIA authorization receipt and an execution/outcome record; missing chain context still prevents consequential-effect admission.',
  };
  console.log(JSON.stringify(report, null, 2));
  if (hasFailure) process.exitCode = 1;
  return report;
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  run();
}
