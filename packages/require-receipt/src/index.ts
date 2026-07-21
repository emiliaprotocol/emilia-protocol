/**
 * @emilia-protocol/require-receipt — the demand side of the network.
 * @license Apache-2.0
 *
 * One line that lets ANY service refuse an irreversible agent action unless it
 * arrives with a verifiable EMILIA Trust Receipt at the relying party's
 * configured assurance tier. A software-tier receipt is not proof that a named
 * human was present; Class-A/quorum profiles add that requirement. This is NOT auth ("who are you")
 * and NOT permissions ("are you allowed here"). It is *portable accountability
 * evidence the service keeps for its own liability*.
 *
 * When the receipt is missing, the service answers with a machine-readable
 * Receipt Required challenge and tells the agent exactly what to bring — so a
 * well-behaved agent obtains one and retries on its own. Existing callers keep
 * the 402 shape; new "Receipt Required" rails can opt into HTTP 428.
 *
 * Verification is offline Ed25519 over canonical JSON — same shape as
 * @emilia-protocol/verify. Zero network. Pin the issuer keys you trust.
 */
import crypto from 'node:crypto';
import { strictJsonGate } from './strict-json.js';
export {
  EP_APPROVAL_FLOW,
  APPROVAL_REQUEST_ID_PATTERN,
  APPROVAL_POLL_TOKEN_PATTERN,
  APPROVAL_IDEMPOTENCY_KEY_PATTERN,
  APPROVAL_STATUSES,
  approvalActionHash,
  validateApprovalAuthorization,
  validateRequiredFields,
  validateCaidSelector,
  beginReceiptApproval,
  pollReceiptApproval,
} from './acquisition.js';
import {
  approvalActionHash,
  validateApprovalAuthorization,
  validateRequiredFields,
  validateCaidSelector,
} from './acquisition.js';

type AnyRecord = Record<string, any>;
type AssuranceTier = 'software' | 'class_a' | 'quorum';
type AssuranceOptions = AnyRecord;
type AssuranceResult = {
  ok: boolean;
  tier: AssuranceTier;
  reason: string;
  approvers?: string[];
  [key: string]: any;
};
type ChallengeOptions = AnyRecord;
type VerifyOptions = AnyRecord;
type Selector = AnyRecord;
type ReceiptGateOptions = AnyRecord;

export const LEGACY_RECEIPT_REQUIRED_STATUS = 402;
export const RECEIPT_REQUIRED_STATUS = 428;
export const RECEIPT_REQUIRED_HEADER = 'Receipt-Required';
export const RECEIPT_PROOF_HEADER = 'X-EMILIA-Receipt';
export const ACTION_RISK_MANIFEST_VERSION = 'EP-ACTION-RISK-MANIFEST-v0.1';
export const DEFAULT_ACTION_RISK_MANIFEST = '/.well-known/agent-actions.json';
export const ASSURANCE_TIERS = ['software', 'class_a', 'quorum'];
export const ASSURANCE_PROOF_VERSION = 'EP-ASSURANCE-PROOF-v1';
export const MAX_RECEIPT_CARRIER_BYTES = 8 * 1024 * 1024;
const ASSURANCE_RANK = { software: 0, class_a: 1, quorum: 2 };
const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const RECEIPT_UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });

/**
 * Decode an HTTP/MCP receipt carrier without inheriting Buffer's permissive
 * base64 behavior. The bytes must use one canonical alphabet, be valid UTF-8,
 * contain strict JSON (no duplicate member names), and decode to an object.
 */
export function parseReceiptCarrier(value: unknown, { maxBytes = MAX_RECEIPT_CARRIER_BYTES }: { maxBytes?: number } = {}): AnyRecord | null {
  if (typeof value !== 'string' || value.length === 0) return null;
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) return null;
  if (value.length > Math.ceil(maxBytes * 4 / 3) + 4) return null;
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(value) || value.length % 4 === 1) return null;
  const hasBase64url = /[-_]/.test(value);
  const hasBase64 = /[+/]/.test(value);
  if (hasBase64url && hasBase64) return null;
  const encoding = hasBase64url ? 'base64url' : 'base64';
  try {
    const bytes = Buffer.from(value, encoding);
    if (bytes.length === 0 || bytes.length > maxBytes) return null;
    const supplied = value.replace(/=+$/, '');
    const canonical = bytes.toString(encoding).replace(/=+$/, '');
    if (canonical !== supplied) return null;
    const text = RECEIPT_UTF8_DECODER.decode(bytes);
    if (!strictJsonGate(text).ok) return null;
    const parsed = JSON.parse(text);
    return isObject(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function canonicalize(v: any): string {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  if (typeof v === 'object') return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`;
  return JSON.stringify(v);
}

/**
 * EP canonicalization profile: JCS over an I-JSON value subset. Signed receipt
 * payloads must contain only strings, booleans, null, arrays, objects, and safe
 * integers. Non-finite numbers, floats, BigInt, undefined, functions, and
 * symbols are rejected before signature verification so implementations never
 * diverge on canonical bytes.
 */
export function isCanonicalizable(value: any): boolean {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isInteger(value) && Number.isSafeInteger(value);
  if (Array.isArray(value)) return value.every(isCanonicalizable);
  if (typeof value === 'object') return Object.values(value).every(isCanonicalizable);
  return false;
}

/**
 * Parse a base64url SPKI-DER public key into a KeyObject, cached by string so a
 * given key is parsed once (not once per verification). Beyond the perf win this
 * removes the per-key DER-parsing work from the verify loop, shrinking the timing
 * difference between "key matched early" and "key matched late". Trusted keys are
 * public, so this is defense-in-depth, not a secret-dependent path. Returns null
 * for an unparseable key (treated as "no match").
 */
const _keyCache = new Map();
function parseSpkiKey(b64: string): any {
  if (_keyCache.has(b64)) return _keyCache.get(b64);
  let key = null;
  try {
    key = crypto.createPublicKey({ key: Buffer.from(b64, 'base64url'), format: 'der', type: 'spki' });
  } catch {
    key = null;
  }
  _keyCache.set(b64, key);
  return key;
}

function asChallengeOptions(opts: number | ChallengeOptions): ChallengeOptions {
  if (!opts) return {};
  if (typeof opts === 'number') return { status: opts };
  return opts;
}

function quoteHeaderValue(value: any): string {
  return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function definedEntries(obj: AnyRecord): Array<[string, any]> {
  return Object.entries(obj).filter(([, value]) => value !== undefined && value !== null && value !== false);
}

function isObject(v: unknown): v is AnyRecord {
  return Boolean(v && typeof v === 'object' && !Array.isArray(v));
}

function normalizeAssuranceClass(value: unknown): AssuranceTier {
  return typeof value === 'string' && ASSURANCE_TIERS.includes(value) ? value as AssuranceTier : 'software';
}

function b64urlDecode(value: any): Buffer {
  return Buffer.from(String(value || ''), 'base64url');
}

function sha256Bytes(value: any): Buffer {
  return crypto.createHash('sha256').update(value).digest();
}

function sha256Hex(value: any): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function proofContext(doc: AnyRecord): AnyRecord {
  return {
    '@version': 'EP-ASSURANCE-CONTEXT-v1',
    receipt_id: doc?.payload?.receipt_id || null,
    claim_hash: `sha256:${sha256Hex(canonicalize(doc?.payload?.claim || {}))}`,
  };
}

function verifyEd25519Digest(signature: string, digest: Buffer, publicKeyB64u: string): boolean {
  try {
    const pub = crypto.createPublicKey({ key: b64urlDecode(publicKeyB64u), format: 'der', type: 'spki' });
    return crypto.verify(null, digest, pub, b64urlDecode(signature));
  } catch {
    return false;
  }
}

function spkiFingerprint(publicKeyB64u: string): string | null {
  try {
    const key = crypto.createPublicKey({ key: b64urlDecode(publicKeyB64u), format: 'der', type: 'spki' });
    const der = key.export({ type: 'spki', format: 'der' });
    return sha256Hex(der);
  } catch {
    return null;
  }
}

function verifyWebAuthnDigest(webauthn: AnyRecord, digest: Buffer, publicKeyB64u: string, opts: AssuranceOptions = {}) {
  try {
    if (!webauthn || typeof webauthn !== 'object') return false;
    const allowedOrigins = Array.isArray(opts.allowedOrigins)
      ? opts.allowedOrigins.filter((origin) => typeof origin === 'string' && origin.length > 0)
      : [];
    if (typeof opts.rpId !== 'string' || !opts.rpId || allowedOrigins.length === 0) return false;
    const authData = b64urlDecode(webauthn.authenticator_data);
    const clientDataBytes = b64urlDecode(webauthn.client_data_json);
    if (authData.length < 37) return false;
    const flags = authData[32];
    if ((flags & FLAG_UP) !== FLAG_UP || (flags & FLAG_UV) !== FLAG_UV) return false;
    const clientDataText = clientDataBytes.toString('utf8');
    if (!strictJsonGate(clientDataText).ok) return false;
    const clientData = JSON.parse(clientDataText);
    if (clientData.type !== 'webauthn.get') return false;
    if (clientData.challenge !== Buffer.from(digest).toString('base64url')) return false;
    if (!allowedOrigins.includes(clientData.origin) || clientData.crossOrigin === true) return false;
    const expectedRpIdHash = sha256Bytes(opts.rpId);
    if (!expectedRpIdHash.equals(authData.subarray(0, 32))) return false;
    const signedData = Buffer.concat([authData, sha256Bytes(clientDataBytes)]);
    const pub = crypto.createPublicKey({ key: b64urlDecode(publicKeyB64u), format: 'der', type: 'spki' });
    return crypto.verify('sha256', signedData, pub, b64urlDecode(webauthn.signature));
  } catch {
    return false;
  }
}

function normalizeApproverKeys(input: any): AnyRecord {
  if (!input || typeof input !== 'object') return {};
  return input;
}

function verifyEmbeddedClassASignoff(doc: AnyRecord, opts: AssuranceOptions = {}): AssuranceResult {
  const payload = doc?.payload;
  const signoff = payload?.signoff || payload?.claim?.signoff;
  const keyId = payload?.approver_key_id || payload?.claim?.approver_key_id;
  const keys = normalizeApproverKeys(opts.approverKeys || opts.approver_keys);
  const entry = typeof keyId === 'string' ? keys[keyId] : null;
  if (!isObject(signoff) || !isObject(entry) || entry.key_class !== 'A'
      || typeof entry.public_key !== 'string') {
    return { ok: false, tier: 'software', reason: 'assurance_proof_required' };
  }
  const approver = signoff.context?.approver;
  const sourceHash = payload?.claim?.source_receipt_action_hash;
  if (typeof approver !== 'string' || approver !== entry.approver_id
      || payload?.claim?.approver !== approver
      || typeof sourceHash !== 'string'
      || signoff.context?.action_hash !== sourceHash) {
    return { ok: false, tier: 'software', reason: 'assurance_context_mismatch' };
  }
  try {
    const digest = sha256Bytes(canonicalize(signoff.context));
    const valid = verifyWebAuthnDigest(signoff.webauthn, digest, entry.public_key, opts);
    return valid
      ? { ok: true, tier: 'class_a', reason: 'embedded_class_a_signoff_verified', approvers: [approver] }
      : { ok: false, tier: 'software', reason: 'assurance_proof_invalid' };
  } catch {
    return { ok: false, tier: 'software', reason: 'assurance_proof_invalid' };
  }
}

/**
 * Validate the quorum rule supplied by the relying party. The policy is a trust
 * input, not evidence: a receipt creator's own threshold or roster never
 * establishes the organization's actual two-person rule.
 */
export function validatePinnedQuorumPolicy(policy: AnyRecord): AnyRecord {
  if (!isObject(policy)) return { ok: false, reason: 'quorum_policy_required' };
  if (policy.mode !== 'threshold' && policy.mode !== 'ordered') {
    return { ok: false, reason: 'quorum_policy_invalid_mode' };
  }
  const approvers = Array.isArray(policy.approvers) ? policy.approvers : [];
  if (approvers.length < 2 || approvers.some((entry) => !isObject(entry)
      || typeof entry.approver !== 'string' || !entry.approver
      || typeof entry.role !== 'string' || !entry.role)) {
    return { ok: false, reason: 'quorum_policy_invalid_roster' };
  }
  const people = approvers.map((entry) => entry.approver);
  const slots = approvers.map((entry) => `${entry.role}\u0000${entry.approver}`);
  if (new Set(people).size !== people.length || new Set(slots).size !== slots.length) {
    return { ok: false, reason: 'quorum_policy_duplicate_roster_entry' };
  }
  if (policy.distinct_humans === false) {
    return { ok: false, reason: 'quorum_policy_distinct_humans_required' };
  }
  const required = policy.mode === 'ordered' ? approvers.length : policy.required;
  if (!Number.isInteger(required) || required < 2 || required > approvers.length) {
    return { ok: false, reason: 'quorum_policy_invalid_threshold' };
  }
  if (policy.window_sec !== undefined
      && (!Number.isSafeInteger(policy.window_sec) || policy.window_sec <= 0)) {
    return { ok: false, reason: 'quorum_policy_invalid_window' };
  }
  return { ok: true, reason: null, policy, required, approvers };
}

function verifyPinnedAssuranceProof(doc: AnyRecord, opts: AssuranceOptions = {}): AssuranceResult {
  const proof = doc?.payload?.assurance_proof || doc?.assurance_proof;
  if (!proof || typeof proof !== 'object') return { ok: false, tier: 'software', reason: 'assurance_proof_required' };
  if (proof['@version'] !== ASSURANCE_PROOF_VERSION) {
    return { ok: false, tier: 'software', reason: 'assurance_proof_bad_version' };
  }
  const approverKeys = normalizeApproverKeys(opts.approverKeys || opts.approver_keys);
  const signoffs = Array.isArray(proof.signoffs) ? proof.signoffs : [];
  if (!signoffs.length) return { ok: false, tier: 'software', reason: 'assurance_proof_missing_signoffs' };

  const context = proofContext(doc);
  const contextHash = `sha256:${sha256Hex(canonicalize(context))}`;
  if (proof.context_hash && proof.context_hash !== contextHash) {
    return { ok: false, tier: 'software', reason: 'assurance_context_mismatch' };
  }
  const digest = Buffer.from(contextHash.replace(/^sha256:/, ''), 'hex');
  const valid = [];
  for (const s of signoffs) {
    const keyId = s?.approver_key_id;
    const entry = keyId ? approverKeys[keyId] : null;
    if (!entry?.public_key) continue;
    // The pinned directory entry is authoritative. A presenter-controlled
    // key_class must never upgrade a software key into a human ceremony.
    const keyClass = entry.key_class === 'A' ? 'A' : 'B';
    const ok = keyClass === 'A'
      ? verifyWebAuthnDigest(s.webauthn, digest, entry.public_key, opts)
      : verifyEd25519Digest(s.signature, digest, entry.public_key);
    if (!ok) continue;
    const keyFingerprint = spkiFingerprint(entry.public_key);
    if (!keyFingerprint) continue;
    // Distinctness MUST key on the PINNED SIGNING KEY (approver_key_id), never the
    // attacker-controlled `approver` label. One key signing the same digest twice
    // under two names is ONE approver — it must not inflate the quorum count and
    // satisfy a two-person rule with a single key.
    valid.push({
      keyId: String(keyId),
      keyFingerprint,
      approver: typeof entry.approver_id === 'string' && entry.approver_id ? entry.approver_id : null,
      keyClass,
    });
  }
  if (!valid.length) return { ok: false, tier: 'software', reason: 'assurance_proof_invalid' };
  const classA = valid.filter((entry) => entry.keyClass === 'A');
  const claimedApprover = doc?.payload?.claim?.approver;
  if (claimedApprover !== undefined
      && (typeof claimedApprover !== 'string' || !claimedApprover
        || !classA.some((entry) => entry.approver === claimedApprover))) {
    return {
      ok: false,
      tier: 'software',
      reason: 'assurance_claimed_approver_mismatch',
      approvers: classA.map((entry) => entry.approver).filter(Boolean),
    };
  }
  const policyCheck = validatePinnedQuorumPolicy(opts.quorumPolicy || opts.quorum_policy);
  if (policyCheck.ok && policyCheck.policy.mode === 'threshold') {
    const eligible = new Set((policyCheck.approvers as AnyRecord[]).map((entry) => entry.approver));
    const admitted = valid.filter((entry) => entry.keyClass === 'A'
      && entry.approver && eligible.has(entry.approver));
    // A single SPKI registered under two key IDs is still one signing key.
    const distinctKeys = new Set(admitted.map((entry) => entry.keyFingerprint));
    const distinctHumans = new Set(admitted.map((entry) => entry.approver));
    if (distinctKeys.size >= policyCheck.required && distinctHumans.size >= policyCheck.required) {
      return {
        ok: true,
        tier: 'quorum',
        reason: 'assurance_proof_verified_against_pinned_policy',
        approvers: [...distinctHumans],
      };
    }
  }
  if (classA.length) {
    return {
      ok: true,
      tier: 'class_a',
      reason: 'assurance_proof_verified',
      approvers: [...new Set(classA.map((entry) => entry.approver).filter(Boolean))],
    };
  }
  return { ok: true, tier: 'software', reason: 'assurance_proof_verified', approvers: [] };
}

function normalizeVerifierResult(result: AnyRecord): AssuranceResult {
  if (result && typeof result === 'object') {
    return {
      // Elevated assurance is a positive security decision. Missing `ok` is
      // malformed, never implicit success.
      ok: result.ok === true,
      tier: normalizeAssuranceClass(result.tier || result.have || result.assuranceClass),
      reason: result.reason || 'custom_assurance_verifier',
    };
  }
  return { ok: false, tier: 'software', reason: 'custom_assurance_result_invalid' };
}

function invokeCustomAssurance(verifier: (doc: AnyRecord, context: AnyRecord) => AnyRecord, doc: AnyRecord, requiredTier: AssuranceTier): AssuranceResult {
  try {
    return normalizeVerifierResult(verifier(doc, { requiredTier }));
  } catch {
    return { ok: false, tier: 'software', reason: 'assurance_verification_failed' };
  }
}

export function receiptAssuranceTier(doc: AnyRecord, opts: AssuranceOptions = {}): AssuranceTier {
  const custom = typeof opts.verifyAssurance === 'function'
    ? invokeCustomAssurance(opts.verifyAssurance, doc, 'quorum')
    : null;
  if (custom?.ok) return custom.tier;
  const proof = verifyPinnedAssuranceProof(doc, opts);
  if (proof.ok) return proof.tier;
  return verifyEmbeddedClassASignoff(doc, opts).tier;
}

export function evaluateReceiptAssurance(doc: AnyRecord, required: string, opts: AssuranceOptions = {}): AnyRecord {
  const need = normalizeAssuranceClass(required);
  if (need === 'software') return { ok: true, have: 'software', need, reason: 'software_receipt' };
  const custom = typeof opts.verifyAssurance === 'function'
    ? invokeCustomAssurance(opts.verifyAssurance, doc, need)
    : null;
  if (need === 'quorum' && !custom) {
    const policy = validatePinnedQuorumPolicy(opts.quorumPolicy || opts.quorum_policy);
    if (!policy.ok) {
      const lower = verifyPinnedAssuranceProof(doc, { ...opts, quorumPolicy: null, quorum_policy: null });
      return { ok: false, have: normalizeAssuranceClass(lower.tier), need, reason: policy.reason };
    }
  }
  const pinned = custom || verifyPinnedAssuranceProof(doc, opts);
  const hasEmbeddedSignoff = isObject(doc?.payload?.signoff || doc?.payload?.claim?.signoff);
  const proof = pinned.ok || !hasEmbeddedSignoff
    ? pinned
    : verifyEmbeddedClassASignoff(doc, opts);
  const have = normalizeAssuranceClass(proof.tier);
  const rankOk = (ASSURANCE_RANK[have] ?? 0) >= (ASSURANCE_RANK[need] ?? 0);
  return {
    ok: proof.ok === true && rankOk,
    have,
    need,
    reason: proof.ok === true && !rankOk ? 'assurance_too_low' : (proof.reason || (proof.ok ? 'assurance_ok' : 'assurance_proof_required')),
    approvers: Array.isArray(proof.approvers) ? proof.approvers : [],
  };
}

function challengeHeaderParams(opts: ChallengeOptions = {}) {
  const authorization = opts.authorization === undefined
    ? null
    : validateApprovalAuthorization(opts.authorization);
  if (authorization && !authorization.ok) throw new Error(authorization.reason);
  const requiredFields = opts.requiredFields === undefined && opts.required_fields === undefined
    ? null
    : validateRequiredFields(opts.requiredFields ?? opts.required_fields);
  if (requiredFields && !requiredFields.ok) throw new Error(requiredFields.reason);
  const caidSelector = opts.caidSelector === undefined && opts.caid_selector === undefined
    ? null
    : validateCaidSelector(opts.caidSelector ?? opts.caid_selector);
  if (caidSelector && !caidSelector.ok) throw new Error(caidSelector.reason);
  return definedEntries({
    action: opts.action,
    action_hash: opts.actionHash,
    manifest: opts.manifestUrl || opts.manifest,
    proof: opts.proofHeader || RECEIPT_PROOF_HEADER,
    profile: opts.profile || 'EP-RECEIPT-v1',
    assurance: opts.assuranceClass,
    quorum: opts.quorum ? JSON.stringify(opts.quorum) : null,
    max_age: Number.isFinite(opts.maxAgeSec) ? String(opts.maxAgeSec) : null,
    authorization_endpoint: authorization?.ok ? authorization.value.authorization_endpoint : null,
    flow: authorization?.ok ? authorization.value.flow : null,
    required_fields: requiredFields?.ok ? JSON.stringify(requiredFields.value) : null,
    caid_selector: caidSelector?.ok ? JSON.stringify(caidSelector.value) : null,
  });
}

/** Build the compact Receipt-Required challenge header value for HTTP 428. */
export function receiptRequiredHeader(opts: ChallengeOptions = {}) {
  return challengeHeaderParams(opts)
    .map(([key, value]) => `${key}="${quoteHeaderValue(value)}"`)
    .join(', ');
}

/**
 * Verify an EP-RECEIPT-v1 document.
 * @param {object} doc the receipt document
 * @param {object} opts
 * @param {string[]} [opts.trustedKeys] base64url SPKI-DER public keys you trust as issuers
 * @param {boolean} [opts.allowInlineKey=false] also accept the receipt's own inline key (proves integrity, NOT trust)
 * @param {string|null} [opts.action] require the receipt to be bound to this action_type
 * @param {number} [opts.maxAgeSec=900] reject receipts older than this
 * @param {()=>number} [opts.now=Date.now] trusted clock used for freshness
 * @param {string[]} [opts.allowedOutcomes] acceptable claim.outcome values
 * @returns {{ok:boolean, reason?:string, detail?:string, outcome?:string, subject?:string, receipt_id?:string, signer?:string}}
 */
export function verifyEmiliaReceipt(doc: any, opts: VerifyOptions = {}) {
  const { trustedKeys = [], allowInlineKey = false, action = null, maxAgeSec = 900,
    now = Date.now, allowedOutcomes = ['allow', 'allow_with_signoff'],
    actionHash = null, requiredFields = null, required_fields = null,
    caidSelector = null, caid_selector = null, maxFutureSkewSec = 60 } = opts;

  if (!doc || doc['@version'] !== 'EP-RECEIPT-v1' || !doc.payload || !doc.signature?.value) {
    return { ok: false, reason: 'malformed_receipt' };
  }
  const payload = doc.payload;
  if (!isCanonicalizable(payload)) {
    return { ok: false, reason: 'payload_outside_ijson_profile' };
  }

  const candidates = [...trustedKeys];
  if (allowInlineKey && doc.public_key) candidates.push(doc.public_key);
  if (candidates.length === 0) return { ok: false, reason: 'no_trusted_keys_configured' };

  const data = Buffer.from(canonicalize(payload), 'utf8');
  let sig;
  try { sig = Buffer.from(doc.signature.value, 'base64url'); } catch { return { ok: false, reason: 'bad_signature_encoding' }; }

  let signer = null;
  for (const k of candidates) {
    const pub = parseSpkiKey(k); // cached parse — avoids per-call DER parsing + the timing variance it adds
    if (!pub) continue;
    try {
      if (crypto.verify(null, data, pub, sig)) { signer = k; break; }
    } catch { /* try next key */ }
  }
  if (!signer) return { ok: false, reason: 'untrusted_or_invalid_signature' };

  // Freshness fail-closed: when a max age is enforced, a receipt MUST carry a
  // parseable created_at. A missing or unparseable created_at is treated as
  // EXPIRED (not skipped) so an undated receipt can never slip past the age
  // gate — matching what /api/v1/guarded enforces on the demand side.
  const nowMs = typeof now === 'function' ? now() : Number.NaN;
  if (maxAgeSec) {
    const ageSec = (nowMs - Date.parse(payload.created_at)) / 1000;
    if (!Number.isFinite(ageSec) || ageSec > maxAgeSec) return { ok: false, reason: 'receipt_expired' };
    if (!Number.isFinite(maxFutureSkewSec) || maxFutureSkewSec < 0 || ageSec < -maxFutureSkewSec) {
      return { ok: false, reason: 'receipt_not_yet_valid' };
    }
  }
  // A signed terminal expiry is an absolute validity boundary. Disabling the
  // relative-age policy must never revive a receipt after that boundary.
  if (payload.expires_at !== undefined) {
    const expiresAt = Date.parse(payload.expires_at);
    if (!Number.isFinite(nowMs) || !Number.isFinite(expiresAt) || nowMs >= expiresAt) {
      return { ok: false, reason: 'receipt_expired' };
    }
  }
  if (action && payload.claim?.action_type !== action) {
    return { ok: false, reason: 'action_mismatch', detail: `receipt is for "${payload.claim?.action_type}", required "${action}"` };
  }
  const expectedFields = requiredFields ?? required_fields;
  const expectedCaidSelector = caidSelector ?? caid_selector;
  if (actionHash || expectedFields || expectedCaidSelector) {
    const signedAction = payload.claim?.canonical_action;
    if (!isObject(signedAction)) return { ok: false, reason: 'signed_action_required' };
    let computedActionHash;
    try {
      computedActionHash = approvalActionHash(signedAction);
    } catch {
      return { ok: false, reason: 'signed_action_invalid' };
    }
    const claimHash = typeof payload.claim?.action_hash === 'string'
      ? `sha256:${payload.claim.action_hash.replace(/^sha256:/, '').toLowerCase()}`
      : null;
    if (!claimHash || claimHash !== computedActionHash) {
      return { ok: false, reason: 'signed_action_hash_mismatch' };
    }
    if (actionHash && actionHash !== computedActionHash) {
      return { ok: false, reason: 'action_hash_mismatch' };
    }
    if (expectedFields) {
      const checkedFields = validateRequiredFields(expectedFields);
      if (!checkedFields.ok) return { ok: false, reason: checkedFields.reason };
      for (const field of checkedFields.value) {
        if (!Object.prototype.hasOwnProperty.call(signedAction, field)
            || signedAction[field] === undefined) {
          return { ok: false, reason: 'signed_action_required_field_missing', detail: field };
        }
      }
    }
    if (expectedCaidSelector) {
      const checkedSelector = validateCaidSelector(expectedCaidSelector);
      if (!checkedSelector.ok) return { ok: false, reason: checkedSelector.reason };
      const caid = signedAction[checkedSelector.value.field];
      if (typeof caid !== 'string'
          || !/^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:[a-z0-9]+(?:-[a-z0-9]+)*:[A-Za-z0-9_-]{43}$/.test(caid)) {
        return { ok: false, reason: 'signed_action_caid_invalid' };
      }
    }
  }
  const outcome = payload.claim?.outcome;
  if (allowedOutcomes && !allowedOutcomes.includes(outcome)) {
    return { ok: false, reason: 'outcome_not_accepted', detail: `outcome "${outcome}" not in [${allowedOutcomes.join(', ')}]` };
  }
  return { ok: true, outcome, subject: payload.subject, receipt_id: payload.receipt_id, signer: `${signer.slice(0, 16)}…` };
}

/**
 * Build the challenge body that tells an agent exactly what receipt to bring.
 *
 * Backward-compatible default: status 402, matching the original demand loop.
 * New Receipt Required rail: pass `{ status: 428 }` or `{ statusCode: 428 }`.
 */
export function receiptChallenge(action: string | null, reason: string, opts: number | ChallengeOptions = {}) {
  const o = asChallengeOptions(opts);
  const status = o.statusCode || o.status || LEGACY_RECEIPT_REQUIRED_STATUS;
  const proofHeader = o.proofHeader || RECEIPT_PROOF_HEADER;
  const authorization = o.authorization === undefined
    ? null
    : validateApprovalAuthorization(o.authorization);
  if (authorization && !authorization.ok) throw new Error(authorization.reason);
  const requiredFields = o.requiredFields === undefined && o.required_fields === undefined
    ? null
    : validateRequiredFields(o.requiredFields ?? o.required_fields);
  if (requiredFields && !requiredFields.ok) throw new Error(requiredFields.reason);
  const caidSelector = o.caidSelector === undefined && o.caid_selector === undefined
    ? null
    : validateCaidSelector(o.caidSelector ?? o.caid_selector);
  if (caidSelector && !caidSelector.ok) throw new Error(caidSelector.reason);
  return {
    type: 'https://emiliaprotocol.ai/errors/emilia_receipt_required',
    title: 'EMILIA Receipt Required',
    status,
    detail: reason || 'This action requires an accountable, verifiable authorization receipt.',
    required: {
      action: action || null,
      action_hash: o.actionHash || null,
      manifest: o.manifestUrl || o.manifest || null,
      status,
      challenge_header: RECEIPT_REQUIRED_HEADER,
      proof_header: proofHeader,
      header: `${proofHeader}: base64(<EP-RECEIPT-v1 JSON>)`,
      acceptable_issuers: o.acceptableIssuers || o.issuers || null,
      assurance_class: o.assuranceClass || null,
      quorum: o.quorum || null,
      max_age_sec: Number.isFinite(o.maxAgeSec) ? o.maxAgeSec : null,
      authorization: authorization?.ok ? { ...authorization.value } : null,
      required_fields: requiredFields?.ok ? [...requiredFields.value] : null,
      caid_selector: caidSelector?.ok ? { ...caidSelector.value } : null,
      how: authorization?.ok
        ? `POST the exact challenged action to the authorization endpoint using ${authorization.value.flow}, poll with the returned private token, then retry with the approved receipt.`
        : 'Obtain a receipt (run emilia-gate, the SDK, or POST /api/trust/gate), then resend with the header.',
      learn_more: 'https://www.emiliaprotocol.ai/agent-guard',
    },
  };
}

/** Validate a .well-known/agent-actions.json Action Risk Manifest. */
export function validateActionRiskManifest(manifest: AnyRecord) {
  const errors = [];
  if (!isObject(manifest)) {
    return { ok: false, errors: ['manifest must be an object'] };
  }
  if (manifest['@version'] !== ACTION_RISK_MANIFEST_VERSION) {
    errors.push(`@version must be ${ACTION_RISK_MANIFEST_VERSION}`);
  }
  if (!Array.isArray(manifest.actions)) {
    errors.push('actions must be an array');
  }

  const seen = new Set();
  for (const [i, action] of (manifest.actions || []).entries()) {
    const p = `actions[${i}]`;
    if (!isObject(action)) {
      errors.push(`${p} must be an object`);
      continue;
    }
    if (!action.id || typeof action.id !== 'string') errors.push(`${p}.id must be a string`);
    if (seen.has(action.id)) errors.push(`${p}.id must be unique`);
    seen.add(action.id);
    if (!isObject(action.match)) errors.push(`${p}.match must be an object`);
    if (typeof action.receipt_required !== 'boolean') errors.push(`${p}.receipt_required must be boolean`);
    if (action.receipt_required && !action.action_type) errors.push(`${p}.action_type is required when receipt_required is true`);
    if (action.receipt_required && !['medium', 'high', 'critical'].includes(action.risk)) {
      errors.push(`${p}.risk must be medium, high, or critical when receipt_required is true`);
    }
    if (action.receipt_required && !action.assurance_class) {
      // Omitting the tier on a guarded action would silently downgrade it to the
      // weakest 'software' tier at enforcement time, letting a critical action
      // accept a bare machine-signed receipt with no human signoff. Require it.
      errors.push(`${p}.assurance_class is required when receipt_required is true (software, class_a, or quorum)`);
    }
    if (action.assurance_class && !['software', 'class_a', 'quorum'].includes(action.assurance_class)) {
      errors.push(`${p}.assurance_class must be software, class_a, or quorum`);
    }
    if (action.receipt_required && action.risk === 'critical' && action.assurance_class === 'software') {
      // A critical (typically irreversible) action must be bound to a human key,
      // not a bare software/machine key. Require at least class_a (a WebAuthn
      // human signature) so the weakest tier cannot satisfy the highest-
      // consequence action. This is the author-time key-class floor; the gate
      // separately fails closed on any receipt weaker than the declared tier.
      errors.push(`${p}.assurance_class must be class_a or quorum when risk is critical (software is not sufficient for a critical action)`);
    }
  }

  return { ok: errors.length === 0, errors };
}

function selectorMatches(match: Selector = {}, selector: Selector = {}) {
  for (const key of ['protocol', 'tool', 'method', 'path']) {
    if (match[key] && selector[key] && match[key] !== selector[key]) return false;
  }
  if (match.tool && selector.tool) return match.tool === selector.tool;
  if (match.method && selector.method && match.path && selector.path) return match.method === selector.method && match.path === selector.path;
  return false;
}

/**
 * Find the first manifest entry matching an action selector.
 * Selectors may use { id }, { action_type } / { action }, or protocol fields
 * such as { protocol: 'mcp', tool: 'release_payment' }.
 */
export function findActionRequirement(manifest: AnyRecord, selector: Selector = {}) {
  const actions = Array.isArray(manifest?.actions) ? manifest.actions : [];
  return actions.find((entry) => (
    (selector.id && entry.id === selector.id) ||
    (selector.action_type && entry.action_type === selector.action_type) ||
    (selector.action && entry.action_type === selector.action) ||
    selectorMatches(entry.match, selector)
  )) || null;
}

/**
 * Express/Connect middleware: demand a valid EMILIA receipt for the route.
 * @param {object} opts verify options + { action?: string | (req)=>string, statusCode?: 402|428 }
 */
export function requireEmiliaReceipt(opts: ReceiptGateOptions = {}) {
  return function emiliaReceiptGate(req: AnyRecord, res: AnyRecord, next: () => unknown) {
    const action = typeof opts.action === 'function' ? opts.action(req) : opts.action;
    const status = opts.statusCode || opts.status || LEGACY_RECEIPT_REQUIRED_STATUS;
    const challengeOpts = { ...opts, action, status };
    let doc = null;
    const hdr = req.headers?.['x-emilia-receipt'];
    if (hdr) doc = parseReceiptCarrier(hdr);
    if (!doc && req.body && req.body.emilia_receipt) doc = req.body.emilia_receipt;

    if (!doc) {
      res.setHeader(RECEIPT_REQUIRED_HEADER, receiptRequiredHeader(challengeOpts));
      if (status === LEGACY_RECEIPT_REQUIRED_STATUS) {
        res.setHeader('WWW-Authenticate', `EMILIA realm="agent-actions"${action ? `, action="${action}"` : ''}`);
      }
      return res.status(status).json(receiptChallenge(action, 'No EMILIA receipt presented.', challengeOpts));
    }
    const v = verifyEmiliaReceipt(doc, { ...opts, action });
    if (!v.ok) {
      res.setHeader(RECEIPT_REQUIRED_HEADER, receiptRequiredHeader(challengeOpts));
      if (status === LEGACY_RECEIPT_REQUIRED_STATUS) {
        res.setHeader('WWW-Authenticate', `EMILIA realm="agent-actions"${action ? `, action="${action}"` : ''}`);
      }
      return res.status(status).json({ ...receiptChallenge(action, `Receipt rejected: ${v.reason}.`, challengeOpts), rejected: v });
    }
    if (opts.assuranceClass || opts.assurance_class) {
      const tier = evaluateReceiptAssurance(doc, opts.assuranceClass || opts.assurance_class, opts);
      if (!tier.ok) {
        res.setHeader(RECEIPT_REQUIRED_HEADER, receiptRequiredHeader(challengeOpts));
        if (status === LEGACY_RECEIPT_REQUIRED_STATUS) {
          res.setHeader('WWW-Authenticate', `EMILIA realm="agent-actions"${action ? `, action="${action}"` : ''}`);
        }
        return res.status(status).json({
          ...receiptChallenge(action, `Receipt rejected: ${tier.reason}.`, challengeOpts),
          rejected: { ok: false, reason: tier.reason, have_tier: tier.have, need_tier: tier.need },
        });
      }
    }
    req.emiliaReceipt = v;
    return next();
  };
}

/**
 * Receipt Required conformance harness. Exercises a guarded dispatcher against
 * the four normative behaviors and returns a structured report. The badge is
 * EARNED by passing this — never self-asserted. (Don't trust us; run the check.)
 *
 * Level RR-1 requires all of: a Receipt-Required challenge on a missing receipt,
 * the action running on a valid action-bound receipt, replay of the same receipt
 * refused (one-time consumption), and a forged receipt refused.
 *
 * @param {object} p
 * @param {(name:string, args:object, receipt:object|null)=>Promise<{status:number, body?:object}>} p.dispatch
 * @param {string} p.tool       receipt-required tool/route name to probe
 * @param {object} [p.args]     arguments passed to the tool
 * @param {string} p.action     canonical action_type the receipt must bind
 * @param {(action:string)=>(object|Promise<object>)} p.issueReceipt  mints a FRESH
 *   valid EP-RECEIPT-v1 bound to `action` (passed in) that this dispatcher accepts
 * @param {object} [p.manifest] optional Action Risk Manifest to validate
 * @returns {Promise<{level:string, passed:boolean, checks:object, detail:object}>}
 */
export async function receiptRequiredConformance({ dispatch, tool, args = {}, action, issueReceipt, manifest }: AnyRecord) {
  const checks: AnyRecord = {};
  const detail: AnyRecord = {};
  const RR = RECEIPT_REQUIRED_STATUS;

  if (manifest !== undefined) {
    const m = validateActionRiskManifest(manifest);
    checks.manifest_valid = m.ok;
    if (!m.ok) detail.manifest_errors = m.errors;
  }

  // 1. missing receipt -> a Receipt Required challenge (428, or legacy 402)
  const r1 = await dispatch(tool, args, null);
  checks.challenge_on_missing = (r1.status === RR || r1.status === LEGACY_RECEIPT_REQUIRED_STATUS) && !!r1.body?.required;
  detail.missing_status = r1.status;

  // 2. valid, action-bound receipt -> the action runs
  const good = await issueReceipt(action);
  const r2 = await dispatch(tool, args, good);
  checks.runs_on_valid = r2.status === 200;
  detail.valid_status = r2.status;

  // 3. the SAME receipt again -> refused (one-time consumption)
  const r3 = await dispatch(tool, args, good);
  checks.replay_refused = r3.status !== 200;
  detail.replay_status = r3.status;

  // 4. a forged receipt (a signed field altered) -> refused
  const forged = await issueReceipt(action);
  if (forged?.payload?.claim) forged.payload.claim.action_type = `${action}.tampered`;
  const r4 = await dispatch(tool, args, forged);
  checks.forged_refused = r4.status !== 200;
  detail.forged_status = r4.status;

  const passed = Object.values(checks).every(Boolean);
  return { level: passed ? 'RR-1' : 'none', passed, checks, detail };
}

const requireReceiptExports = {
  verifyEmiliaReceipt,
  requireEmiliaReceipt,
  receiptChallenge,
  receiptRequiredHeader,
  validateActionRiskManifest,
  findActionRequirement,
  receiptRequiredConformance,
};

export default requireReceiptExports;

// Canonical hardened gate: target binding + consume-after-success + sanitized
// rejections, in one reviewed place. Prefer this over hand-rolling a guard.
export { makeReceiptGate } from './gate.js';
export { strictJsonGate } from './strict-json.js';

// EP-RECEIPT-JWS-PROFILE-v1: serialize/verify an EP receipt as a standard
// compact JWS (RFC 7515, EdDSA per RFC 8037) so any JOSE verifier can consume
// it. Parallel envelope over the SAME JCS canonical payload — not a replacement
// for the native EP-RECEIPT-v1 signature.
export {
  serializeReceiptJws,
  verifyReceiptJws,
  deriveKid,
  JWS_PROFILE_VERSION,
  JWS_ALG,
  JWS_TYP,
} from './jws.js';
