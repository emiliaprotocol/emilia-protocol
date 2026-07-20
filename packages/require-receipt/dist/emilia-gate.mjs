// SPDX-License-Identifier: Apache-2.0
//
// emilia-gate.mjs — the EMILIA Receipt-Required gate, as a single drop-in file.
//
//   • Zero dependencies (Node built-in crypto only). Copy this file into your
//     repo — no npm package, no supply-chain or version surface to own.
//   • The gate blocks an irreversible action unless it arrives with a valid,
//     action-bound, non-replayed EMILIA authorization receipt at the configured
//     assurance tier, verified offline (Ed25519/WebAuthn over canonical bytes).
//   • Off by default: you decide which actions require a receipt.
//
//   Quick use:
//     import { makeReceiptGate } from './emilia-gate.mjs';
//     const gate = makeReceiptGate({ action: 'db.records.delete', trustedKeys: [ISSUER_SPKI_B64URL] });
//     const r = await gate.run(receipt, { target: 'customers' }, async () => doDelete());
//     if (!r.ok) return reply(r.status, r.body);   // 428 Receipt-Required challenge
//
//   PRODUCTION NOTES (the two things easy to get wrong):
//     1. Pass trustedKeys (issuer SPKI keys). Do NOT rely on allowInlineKey for
//        real actions — an inline key proves integrity, not WHO authorized.
//     2. The default consumed-store is in-memory (process-local). For restart-
//        durable / multi-instance one-time consumption, pass a shared store:
//        makeReceiptGate({ ..., store: { reserve, commit, release } }).
//        reserve MUST be an atomic insert-if-absent. Once execution begins, an
//        indeterminate result is committed, never released for automatic retry.
//
//   Conformance: this drop-in passes EMILIA RR-1 (challenge-on-missing, runs-on-
//   valid, replay-refused, forged-refused). Verify with @emilia-protocol/fire-drill.
//
//   GENERATED — do not edit by hand. Regenerate with:
//     npx @emilia-protocol/require-receipt   (or: node build-drop-in.mjs)
//   source: @emilia-protocol/require-receipt@0.6.1  ·  content-sha256:fa0eba0951ca8b89
//   docs: https://www.emiliaprotocol.ai/gate   spec: draft-schrock-ep-authorization-receipts

// SPDX-License-Identifier: Apache-2.0
// Duplicate-name and Unicode-scalar gate for signed nested JSON such as
// WebAuthn clientDataJSON. JSON.parse remains the syntax gate.

const MAX_JSON_DEPTH = 64;

function hasUnpairedUtf16Surrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function strictJsonGate(raw) {
  if (typeof raw !== 'string') return { ok: false, reason: 'JSON input must be text' };
  if (hasUnpairedUtf16Surrogate(raw)) {
    return { ok: false, reason: 'unpaired Unicode surrogate' };
  }
  try { JSON.parse(raw); } catch { return { ok: false, reason: 'invalid JSON syntax' }; }
  let index = 0;
  const stack = [];
  let reason = null;
  const escapes = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };

  function readString() {
    index += 1;
    let output = '';
    while (index < raw.length) {
      const character = raw[index];
      if (character === '"') { index += 1; return output; }
      if (character !== '\\') { output += character; index += 1; continue; }
      const escape = raw[index + 1];
      if (escape !== 'u') {
        output += escapes[escape] ?? '';
        index += 2;
        continue;
      }
      const first = Number.parseInt(raw.slice(index + 2, index + 6), 16);
      index += 6;
      if (first >= 0xd800 && first <= 0xdbff) {
        if (raw[index] === '\\' && raw[index + 1] === 'u') {
          const second = Number.parseInt(raw.slice(index + 2, index + 6), 16);
          if (second >= 0xdc00 && second <= 0xdfff) {
            output += String.fromCharCode(first, second);
            index += 6;
            continue;
          }
        }
        reason = 'unpaired high surrogate escape';
        return null;
      }
      if (first >= 0xdc00 && first <= 0xdfff) {
        reason = 'unpaired low surrogate escape';
        return null;
      }
      output += String.fromCharCode(first);
    }
    reason = 'unterminated string';
    return null;
  }

  while (index < raw.length) {
    const character = raw[index];
    if (character === '{') {
      stack.push({ object: true, keys: new Set(), expectsKey: true });
      if (stack.length > MAX_JSON_DEPTH) return { ok: false, reason: `nesting depth exceeds ${MAX_JSON_DEPTH}` };
      index += 1;
    } else if (character === '[') {
      stack.push({ object: false });
      if (stack.length > MAX_JSON_DEPTH) return { ok: false, reason: `nesting depth exceeds ${MAX_JSON_DEPTH}` };
      index += 1;
    } else if (character === '}' || character === ']') {
      stack.pop();
      index += 1;
    } else if (character === ',') {
      const top = stack.at(-1);
      if (top?.object) top.expectsKey = true;
      index += 1;
    } else if (character === '"') {
      const top = stack.at(-1);
      const isKey = Boolean(top?.object && top.expectsKey);
      const value = readString();
      if (reason) return { ok: false, reason };
      if (isKey) {
        // `isKey` is only true when `top?.object && top.expectsKey` held above,
        // which guarantees `top` is a defined object-frame here; narrow the
        // type for the compiler without altering the runtime reference.
        const frame = /** @type {{ object: true, keys: Set<string>, expectsKey: boolean }} */ (top);
        // `readString()` only ever returns null on a path that also sets
        // `reason`, and the `if (reason) return` above already exited in
        // that case, so `value` is guaranteed to be a string here.
        const key = /** @type {string} */ (value);
        if (frame.keys.has(key)) return { ok: false, reason: 'duplicate object member name' };
        frame.keys.add(key);
        frame.expectsKey = false;
      }
    } else {
      index += 1;
    }
  }
  return { ok: true };
}

// ── inlined from index.js ──────────────────────────────────────────────────

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
export function parseReceiptCarrier(value, { maxBytes = MAX_RECEIPT_CARRIER_BYTES } = {}) {
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

function canonicalize(v) {
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
export function isCanonicalizable(value) {
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
function parseSpkiKey(b64) {
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

function asChallengeOptions(opts) {
  if (!opts) return {};
  if (typeof opts === 'number') return { status: opts };
  return opts;
}

function quoteHeaderValue(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function definedEntries(obj) {
  return Object.entries(obj).filter(([, value]) => value !== undefined && value !== null && value !== false);
}

function isObject(v) {
  return v && typeof v === 'object' && !Array.isArray(v);
}

function normalizeAssuranceClass(value) {
  return ASSURANCE_TIERS.includes(value) ? value : 'software';
}

function b64urlDecode(value) {
  return Buffer.from(String(value || ''), 'base64url');
}

function sha256Bytes(value) {
  return crypto.createHash('sha256').update(value).digest();
}

function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function proofContext(doc) {
  return {
    '@version': 'EP-ASSURANCE-CONTEXT-v1',
    receipt_id: doc?.payload?.receipt_id || null,
    claim_hash: `sha256:${sha256Hex(canonicalize(doc?.payload?.claim || {}))}`,
  };
}

function verifyEd25519Digest(signature, digest, publicKeyB64u) {
  try {
    const pub = crypto.createPublicKey({ key: b64urlDecode(publicKeyB64u), format: 'der', type: 'spki' });
    return crypto.verify(null, digest, pub, b64urlDecode(signature));
  } catch {
    return false;
  }
}

function spkiFingerprint(publicKeyB64u) {
  try {
    const key = crypto.createPublicKey({ key: b64urlDecode(publicKeyB64u), format: 'der', type: 'spki' });
    const der = key.export({ type: 'spki', format: 'der' });
    return sha256Hex(der);
  } catch {
    return null;
  }
}

function verifyWebAuthnDigest(webauthn, digest, publicKeyB64u, opts = {}) {
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

function normalizeApproverKeys(input) {
  if (!input || typeof input !== 'object') return {};
  return input;
}

/**
 * Validate the quorum rule supplied by the relying party. The policy is a trust
 * input, not evidence: a receipt creator's own threshold or roster never
 * establishes the organization's actual two-person rule.
 */
export function validatePinnedQuorumPolicy(policy) {
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

function verifyPinnedAssuranceProof(doc, opts = {}) {
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
    const eligible = new Set(policyCheck.approvers.map((entry) => entry.approver));
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

function normalizeVerifierResult(result) {
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

function invokeCustomAssurance(verifier, doc, requiredTier) {
  try {
    return normalizeVerifierResult(verifier(doc, { requiredTier }));
  } catch {
    return { ok: false, tier: 'software', reason: 'assurance_verification_failed' };
  }
}

export function receiptAssuranceTier(doc, opts = {}) {
  const custom = typeof opts.verifyAssurance === 'function'
    ? invokeCustomAssurance(opts.verifyAssurance, doc, 'quorum')
    : null;
  if (custom?.ok) return custom.tier;
  return verifyPinnedAssuranceProof(doc, opts).tier;
}

export function evaluateReceiptAssurance(doc, required, opts = {}) {
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
  const proof = custom || verifyPinnedAssuranceProof(doc, opts);
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

function challengeHeaderParams(opts = {}) {
  return definedEntries({
    action: opts.action,
    action_hash: opts.actionHash,
    manifest: opts.manifestUrl || opts.manifest,
    proof: opts.proofHeader || RECEIPT_PROOF_HEADER,
    profile: opts.profile || 'EP-RECEIPT-v1',
    assurance: opts.assuranceClass,
    quorum: opts.quorum ? JSON.stringify(opts.quorum) : null,
    max_age: Number.isFinite(opts.maxAgeSec) ? String(opts.maxAgeSec) : null,
  });
}

/** Build the compact Receipt-Required challenge header value for HTTP 428. */
export function receiptRequiredHeader(opts = {}) {
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
export function verifyEmiliaReceipt(doc, opts = {}) {
  const { trustedKeys = [], allowInlineKey = false, action = null, maxAgeSec = 900,
    now = Date.now, allowedOutcomes = ['allow', 'allow_with_signoff'] } = opts;

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
  if (maxAgeSec) {
    const nowMs = typeof now === 'function' ? now() : Number.NaN;
    const ageSec = (nowMs - Date.parse(payload.created_at)) / 1000;
    if (!Number.isFinite(ageSec) || ageSec > maxAgeSec) return { ok: false, reason: 'receipt_expired' };
  }
  if (action && payload.claim?.action_type !== action) {
    return { ok: false, reason: 'action_mismatch', detail: `receipt is for "${payload.claim?.action_type}", required "${action}"` };
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
export function receiptChallenge(action, reason, opts = {}) {
  const o = asChallengeOptions(opts);
  const status = o.statusCode || o.status || LEGACY_RECEIPT_REQUIRED_STATUS;
  const proofHeader = o.proofHeader || RECEIPT_PROOF_HEADER;
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
      how: 'Obtain a receipt (run emilia-gate, the SDK, or POST /api/trust/gate), then resend with the header.',
      learn_more: 'https://www.emiliaprotocol.ai/agent-guard',
    },
  };
}

/** Validate a .well-known/agent-actions.json Action Risk Manifest. */
export function validateActionRiskManifest(manifest) {
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

function selectorMatches(match = {}, selector = {}) {
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
export function findActionRequirement(manifest, selector = {}) {
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
export function requireEmiliaReceipt(opts = {}) {
  return function emiliaReceiptGate(req, res, next) {
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
export async function receiptRequiredConformance({ dispatch, tool, args = {}, action, issueReceipt, manifest }) {
  const checks = {};
  const detail = {};
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

// ── inlined from gate.js ───────────────────────────────────────────────────

/**
 * @emilia-protocol/require-receipt — makeReceiptGate
 * @license Apache-2.0
 *
 * The canonical, hardened Receipt-Required gate. Encodes, in ONE reviewed place,
 * the three properties that are easy to get wrong when hand-rolling a guard:
 *
 *   1. TARGET BINDING — a receipt is bound to the exact resource, not just the
 *      action type, so a valid receipt for resource A cannot act on resource B.
 *   2. CONSUME-BEFORE-RETRY (+ replay safety) — a receipt is RESERVED before the
 *      side effect and permanently COMMITTED after any execution attempt. Once
 *      execution begins, an exception cannot distinguish "nothing happened"
 *      from "the effect happened but its response was lost", so automatic retry
 *      would risk duplicating an irreversible action.
 *   3. SANITIZED REJECTIONS — a refusal returns only a `{ reason }` code, never
 *      the verified receipt's signer/subject/library detail.
 *
 * Prefer `gate.run(receipt, { target }, fn)` — it orchestrates verify → reserve →
 * attempt → commit so a caller cannot get the ordering wrong. Use the lower-level
 * `check` / `commit` / `release` only when you can prove the effect has not begun.
 */

/** Default process-local atomic store. Fleets must pass an ownership-fenced
 * shared store implementing the same reserve/commit/release contract. */
function inMemoryStore() {
  const states = new Map();
  return {
    durable: false,
    ownershipFenced: true,
    async reserve(id) {
      if (states.has(id)) return false;
      states.set(id, 'reserved');
      return true;
    },
    async commit(id) {
      if (states.get(id) !== 'reserved') throw new Error('consumption reservation not owned');
      states.set(id, 'committed');
      return true;
    },
    async release(id) {
      if (states.get(id) !== 'reserved') throw new Error('consumption reservation not owned');
      states.delete(id);
      return true;
    },
  };
}

function normalizeTarget(target) {
  if (target === undefined || target === null) return null;
  if (Array.isArray(target)) return target.map(String).sort().join(',');
  return String(target);
}

const TIER_RANK = { software: 0, class_a: 1, quorum: 2 };

function normalizeGateAssuranceClass(value) {
  return Object.prototype.hasOwnProperty.call(TIER_RANK, value) ? value : 'software';
}


/**
 * Build a hardened Receipt-Required gate for one action type.
 *
 * @param {object} [opts]
 * @param {string|((target:any)=>string)} [opts.action]  base action_type, or a fn
 *   that derives the fully-bound action from the target. Required at runtime
 *   (throws when absent); optional in the type so a `{}` default is well-formed.
 * @param {string[]} [opts.trustedKeys]      issuer SPKI keys you trust (recommended).
 * @param {boolean} [opts.allowInlineKey=false] also accept the receipt's own key
 *   (proves integrity, NOT issuer trust) — demo only; leave off in production.
 * @param {number} [opts.maxAgeSec=900]
 * @param {string[]} [opts.allowedOutcomes]
 * @param {number} [opts.statusCode=428]
 * @param {string} [opts.manifestUrl]
 * @param {string} [opts.assuranceClass]
 * @param {object} [opts.quorum]
 * @param {object} [opts.quorumPolicy] relying-party-pinned organizational quorum rule
 * @param {Record<string, any>} [opts.approverKeys] pinned approver keys (assurance eval).
 * @param {Record<string, any>} [opts.approver_keys] snake_case alias of approverKeys.
 * @param {(receipt:any, requiredTier:string, ctx:any)=>any} [opts.verifyAssurance]
 *   optional override for assurance evaluation.
 * @param {string} [opts.rpId] expected WebAuthn RP ID for Class-A assurance checks.
 * @param {string[]} [opts.allowedOrigins] allowed WebAuthn origins for Class-A checks.
 * @param {{reserve:(id:string)=>Promise<boolean>|boolean,
 *   commit:(id:string)=>Promise<boolean>|boolean,
 *   release:(id:string)=>Promise<boolean>|boolean}} [opts.store]
 *   Atomic ownership-fenced consumption store; defaults to process-local memory.
 *   Fleet stores MUST make reserve() an atomic insert-if-absent and MUST leave an
 *   uncertain reservation closed until operator reconciliation.
 */
export function makeReceiptGate(opts = {}) {
  const {
    action,
    trustedKeys = [],
    allowInlineKey = false,
    maxAgeSec = 900,
    allowedOutcomes,
    statusCode = RECEIPT_REQUIRED_STATUS,
    manifestUrl,
    assuranceClass,
    quorum,
    quorumPolicy,
    approverKeys,
    approver_keys,
    verifyAssurance,
    rpId,
    allowedOrigins,
    store = inMemoryStore(),
  } = opts;

  if (!action) throw new Error('makeReceiptGate: `action` is required');
  for (const method of ['reserve', 'commit', 'release']) {
    if (typeof store?.[method] !== 'function') {
      throw new Error(`makeReceiptGate: store must implement atomic ${method}(); legacy {has, add} stores are not fleet-safe`);
    }
  }

  const boundActionFor = (target) => {
    const base = typeof action === 'function' ? action(target) : action;
    if (typeof action === 'function') return base; // fn already folds in the target
    const t = normalizeTarget(target);
    return t === null ? base : `${base}:${t}`;
  };

  const requiredTier = normalizeGateAssuranceClass(assuranceClass);
  const challengeOpts = () => ({ statusCode, manifestUrl, assuranceClass: requiredTier, quorum, maxAgeSec });

  /** @returns {{ok:false, status:number, body:any}} */
  function refuse(boundAction, reason) {
    return {
      ok: false,
      status: statusCode,
      body: { ...receiptChallenge(boundAction, `Receipt rejected: ${reason}.`, challengeOpts()), rejected: { reason } },
    };
  }

  /**
   * Verify + reserve a receipt WITHOUT consuming it. On ok, the caller MUST
   * later call commit(receiptId) after an execution attempt, or release(receiptId)
   * only when it can prove the external effect never began.
   * @returns {Promise<{ok:true, receiptId, outcome, signer, subject, boundAction}
   *          | {ok:false, status, body}>}
   */
  async function check(receipt, { target } = /** @type {{target?:any}} */ ({})) {
    const boundAction = boundActionFor(target);

    if (!receipt) {
      return {
        ok: false,
        status: statusCode,
        body: receiptChallenge(boundAction, 'This action requires an accountable, verifiable authorization receipt.', challengeOpts()),
      };
    }

    const v = verifyEmiliaReceipt(receipt, { trustedKeys, allowInlineKey, action: boundAction, maxAgeSec, allowedOutcomes });
    if (!v.ok) return refuse(boundAction, v.reason); // sanitized: reason code only

    // No receipt_id means no consumption identity: every no-id receipt collapses
    // to the same empty consume key, so the reservation below would neither
    // identify nor protect this receipt. Refuse before touching the store, as
    // app/api/v1/guarded and packages/gate already do (redteam HI-5).
    if (typeof v.receipt_id !== 'string' || v.receipt_id === '') {
      return refuse(boundAction, 'missing_receipt_id');
    }

    const assurance = evaluateReceiptAssurance(receipt, requiredTier, {
      approverKeys, approver_keys, verifyAssurance, rpId, allowedOrigins, quorumPolicy,
    });
    if (!assurance.ok || (TIER_RANK[assurance.have] ?? 0) < (TIER_RANK[requiredTier] ?? 0)) {
      return refuse(boundAction, assurance.reason || 'assurance_too_low');
    }

    let reserved;
    try {
      reserved = await store.reserve(v.receipt_id);
    } catch {
      return refuse(boundAction, 'consumption_store_unavailable');
    }
    if (reserved !== true) return refuse(boundAction, 'replay_refused');
    return { ok: true, receiptId: v.receipt_id, outcome: v.outcome, signer: v.signer, subject: v.subject, boundAction };
  }

  /** Finalize one-time consumption after an execution attempt begins. */
  async function commit(receiptId) {
    const committed = await store.commit(receiptId);
    if (committed !== true) throw new Error('consumption commit failed closed');
  }

  /** Release only when the caller can prove the external effect never began. */
  async function release(receiptId) {
    const released = await store.release(receiptId);
    if (released !== true) throw new Error('consumption release failed closed');
  }

  /**
   * The safe path: verify+reserve, run the side effect, then commit regardless
   * of its return value. An exception after invocation is an indeterminate
   * outcome and MUST consume the approval to prevent duplicate execution.
   * Receives the check result: fn({ receiptId, outcome, signer, ... }).
   * @returns {Promise<{ok:true, receiptId, outcome, signer, result}|{ok:false, status, body}>}
   */
  async function run(receipt, ctx, fn) {
    if (typeof ctx === 'function') { fn = ctx; ctx = {}; }
    if (typeof fn !== 'function') throw new Error('makeReceiptGate.run: fn is required');
    const c = await check(receipt, ctx || {});
    if (!c.ok) return /** @type {{ok:false, status:any, body:any}} */ (c);
    let attempted = false;
    let committed = false;
    try {
      attempted = true;
      const result = await fn(c);
      await commit(c.receiptId);
      committed = true;
      return { ok: true, receiptId: c.receiptId, outcome: c.outcome, signer: c.signer, result };
    } catch (err) {
      if (attempted && !committed) {
        try {
          await commit(c.receiptId); // effect may have occurred before the exception
        } catch (commitError) {
          if (err && typeof err === 'object') {
            err.consumption_error = String(commitError?.message ?? commitError);
          }
        }
      }
      throw err;
    }
  }

  return { check, commit, release, run, boundActionFor };
}
