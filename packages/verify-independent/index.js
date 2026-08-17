// SPDX-License-Identifier: Apache-2.0
//
// Clean-Room Independent Node.js Verifier Runner
// Developed from scratch using only native Node.js crypto.
//

import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';

// read suite file
const vectorsPath = process.argv[2];
if (!vectorsPath) {
  console.error("Usage: node run-independent.mjs <path-to-vectors-json>");
  process.exit(1);
}
const { vectors } = JSON.parse(fs.readFileSync(vectorsPath, 'utf8'));

const SUPPORTED_VERSIONS = ['EP-RECEIPT-v1'];
const MERKLE_V2_ALG = 'EP-MERKLE-v2';
const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const HASH_PREFIX = /^sha256:/i;
const HEX_ONLY = /^[0-9a-f]+$/;

function hexOf(h) {
  return String(h || '').replace(HASH_PREFIX, '').toLowerCase();
}

function isHex64(h) {
  return typeof h === 'string' && h.length === 64 && HEX_ONLY.test(h);
}

function sha256(input) {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

function sha256Bytes(input) {
  return crypto.createHash('sha256').update(input, 'utf8').digest();
}

function canonicalize(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(',')}]`;
  }
  if (typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + canonicalize(value[k]))
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function isCanonicalizable(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isInteger(value) && Number.isSafeInteger(value);
  if (Array.isArray(value)) return value.every(isCanonicalizable);
  if (typeof value === 'object') return Object.values(value).every(isCanonicalizable);
  return false;
}

function leafHashV2(canonicalPayload) {
  return crypto.createHash('sha256')
    .update(Buffer.concat([Buffer.from([0x00]), Buffer.from(canonicalPayload, 'utf8')]))
    .digest('hex');
}

function hashPairV2(left, right) {
  return crypto.createHash('sha256')
    .update(Buffer.concat([Buffer.from([0x01]), Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8')]))
    .digest('hex');
}

function hashPair(a, b) {
  const sorted = [a, b].sort();
  return crypto.createHash('sha256').update(sorted[0] + sorted[1]).digest('hex');
}

function verifyMerkleAnchor(leafHash, proof, expectedRoot, opts = {}) {
  if (typeof leafHash !== 'string' || !leafHash) return false;
  if (typeof expectedRoot !== 'string' || !expectedRoot) return false;
  if (!Array.isArray(proof)) return false;
  if (proof.length > 20) return false;

  const pair = opts.v2 === true ? hashPairV2 : hashPair;
  let current = leafHash;
  for (const step of proof) {
    if (!step || typeof step.hash !== 'string') return false;
    if (step.position !== 'left' && step.position !== 'right') return false;
    current = step.position === 'left' ? pair(step.hash, current) : pair(current, step.hash);
  }

  return current === expectedRoot;
}

export function verifyReceipt(doc, publicKeyBase64url, opts = {}) {
  const checks = { version: false, signature: false, anchor: null };

  if (!doc?.['@version'] || !SUPPORTED_VERSIONS.includes(doc['@version'])) {
    return { valid: false, checks, error: `Unsupported version: ${doc?.['@version']}` };
  }
  checks.version = true;

  if (!doc.payload || !doc.signature?.value || !doc.signature?.algorithm) {
    return { valid: false, checks, error: 'Missing payload or signature' };
  }
  if (!isCanonicalizable(doc.payload)) {
    return {
      valid: false,
      checks,
      error: 'Payload is outside the EP canonicalization profile',
    };
  }

  try {
    const payloadBytes = Buffer.from(canonicalize(doc.payload), 'utf8');
    const publicKeyDer = Buffer.from(publicKeyBase64url, 'base64url');
    const keyObject = crypto.createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' });
    const sigBytes = Buffer.from(doc.signature.value, 'base64url');
    checks.signature = crypto.verify(null, payloadBytes, keyObject, sigBytes);
  } catch (e) {
    return { valid: false, checks, error: `Signature verification failed: ${e.message}` };
  }

  if (doc.anchor?.merkle_proof && doc.anchor?.leaf_hash && doc.anchor?.merkle_root) {
    const isV2 = doc.anchor.alg === MERKLE_V2_ALG;
    if (isV2) {
      const expectedLeaf = leafHashV2(canonicalize(doc.payload));
      checks.anchor = doc.anchor.leaf_hash === expectedLeaf
        && verifyMerkleAnchor(doc.anchor.leaf_hash, doc.anchor.merkle_proof, doc.anchor.merkle_root, { v2: true });
    } else if (opts.allowLegacyMerkle === true) {
      checks.anchor = verifyMerkleAnchor(doc.anchor.leaf_hash, doc.anchor.merkle_proof, doc.anchor.merkle_root);
    } else {
      checks.anchor = false;
    }
  }

  const valid = checks.version && checks.signature && (checks.anchor === null || checks.anchor === true);
  return { valid, checks };
}

export function verifyWebAuthnSignoff(signoff, approverPublicKeySpkiB64u, opts = {}) {
  const checks = {
    challenge_binding: false,
    client_data_type: false,
    user_present: false,
    user_verified: false,
    rp_id_hash: null,
    signature: false,
  };

  try {
    if (!signoff?.context || !signoff?.webauthn) {
      return { valid: false, checks, error: 'Missing context or webauthn evidence' };
    }
    const { authenticator_data, client_data_json, signature } = signoff.webauthn;
    if (!authenticator_data || !client_data_json || !signature) {
      return { valid: false, checks, error: 'Missing webauthn fields' };
    }

    const clientDataBytes = Buffer.from(client_data_json, 'base64url');
    const clientData = JSON.parse(clientDataBytes.toString('utf8'));
    const expectedChallenge = crypto
      .createHash('sha256')
      .update(canonicalize(signoff.context), 'utf8')
      .digest()
      .toString('base64url');
    checks.challenge_binding = clientData.challenge === expectedChallenge;

    checks.client_data_type = clientData.type === 'webauthn.get';

    const authData = Buffer.from(authenticator_data, 'base64url');
    if (authData.length < 37) {
      return { valid: false, checks, error: 'authenticator_data too short' };
    }
    const flags = authData[32];
    checks.user_present = (flags & FLAG_UP) === FLAG_UP;
    checks.user_verified = (flags & FLAG_UV) === FLAG_UV;

    if (opts.rpId) {
      const expectedRpIdHash = crypto.createHash('sha256').update(opts.rpId, 'utf8').digest();
      checks.rp_id_hash = expectedRpIdHash.equals(authData.subarray(0, 32));
    }

    const signedData = Buffer.concat([
      authData,
      crypto.createHash('sha256').update(clientDataBytes).digest(),
    ]);
    const keyObject = crypto.createPublicKey({
      key: Buffer.from(approverPublicKeySpkiB64u, 'base64url'),
      format: 'der',
      type: 'spki',
    });
    checks.signature = crypto.verify(
      'sha256',
      signedData,
      keyObject,
      Buffer.from(signature, 'base64url'),
    );
  } catch (e) {
    return { valid: false, checks, error: `WebAuthn verification failed: ${e.message}` };
  }

  const valid = checks.challenge_binding
    && checks.client_data_type
    && checks.user_present
    && checks.user_verified
    && checks.signature
    && (checks.rp_id_hash === null || checks.rp_id_hash === true);
  return { valid, checks };
}

export function verifyQuorum(quorum, opts = {}) {
  const checks = {
    all_signatures_valid: false,
    action_binding: false,
    distinct_humans: false,
    distinct_keys: false,
    roles_admitted: false,
    threshold_met: false,
    order_satisfied: false,
    chain_linked: false,
    within_window: false,
    initiator_excluded: false,
  };
  const memberResults = [];

  try {
    const policy = quorum?.policy;
    const members = Array.isArray(quorum?.members) ? quorum.members : null;
    const actionHash = quorum?.action_hash;
    if (!policy || !members || members.length === 0 || typeof actionHash !== 'string' || !actionHash) {
      return { valid: false, checks, members: memberResults };
    }

    const mode = policy.mode === 'ordered' ? 'ordered' : 'threshold';
    const distinctHumans = policy.distinct_humans !== false;
    const windowSec = Number.isFinite(policy.window_sec) ? policy.window_sec : 900;
    const eligible = Array.isArray(policy.approvers) ? policy.approvers : [];
    const required = mode === 'ordered'
      ? eligible.length
      : (Number.isInteger(policy.required) && policy.required > 0 ? policy.required : NaN);
    if (!Number.isInteger(required) || required <= 0 || eligible.length === 0) {
      return { valid: false, checks, members: memberResults };
    }

    let allSigsValid = true;
    let allBound = true;
    const approverIds = [];
    const issuedAts = [];
    for (const m of members) {
      const r = verifyWebAuthnSignoff(m?.signoff, m?.approver_public_key, opts);
      const approver = m?.signoff?.context?.approver ?? null;
      const role = m?.role ?? null;
      memberResults.push({ approver, role, valid: !!r.valid });
      if (!r.valid) allSigsValid = false;
      if (m?.signoff?.context?.action_hash !== actionHash) allBound = false;
      approverIds.push(approver);
      const t = Date.parse(m?.signoff?.context?.issued_at ?? '');
      issuedAts.push(Number.isNaN(t) ? null : t);
    }
    checks.all_signatures_valid = allSigsValid;
    checks.action_binding = allBound;

    const counted = members
      .map((m, i) => ({ m, i, ok: memberResults[i].valid && m?.signoff?.context?.action_hash === actionHash }))
      .filter((x) => x.ok);

    const countedApprovers = counted.map((x) => x.m?.signoff?.context?.approver);
    checks.distinct_humans = distinctHumans
      ? new Set(countedApprovers).size === countedApprovers.length
      : true;

    const countedKeys = counted.map((x) => x.m?.approver_public_key);
    checks.distinct_keys = new Set(countedKeys).size === countedKeys.length;

    let initiator = null;
    let initiatorOk = true;
    for (const x of counted) {
      const init = x.m?.signoff?.context?.initiator;
      if (init) {
        if (initiator === null) {
          initiator = init;
        } else if (initiator !== init) {
          initiatorOk = false;
        }
      }
    }
    checks.initiator_excluded = initiatorOk && (initiator === null || !countedApprovers.includes(initiator));

    const eligibleSet = new Set(eligible.map((e) => `${e.role} ${e.approver}`));
    checks.roles_admitted = counted.length > 0 && counted.every((x) =>
      eligibleSet.has(`${x.m?.role} ${x.m?.signoff?.context?.approver}`));

    const distinctEligible = new Set(
      counted
        .filter((x) => eligibleSet.has(`${x.m?.role} ${x.m?.signoff?.context?.approver}`))
        .map((x) => x.m?.signoff?.context?.approver),
    );
    checks.threshold_met = distinctEligible.size >= required;

    if (mode === 'ordered') {
      const seqRolesOk = eligible.every((e, idx) => members[idx]?.role === e.role
        && members[idx]?.signoff?.context?.approver === e.approver);
      const times = issuedAts.slice(0, eligible.length);
      const timesOk = times.every((t, idx) => t !== null && (idx === 0 || t > times[idx - 1]));
      checks.order_satisfied = members.length >= eligible.length && seqRolesOk && timesOk;
    } else {
      checks.order_satisfied = true;
    }

    if (mode === 'ordered' && policy.ordered_chain === true) {
      const seq = members.slice(0, eligible.length);
      let linked = seq.length === eligible.length;
      for (let idx = 0; idx < seq.length; idx++) {
        const prev = seq[idx]?.signoff?.context?.prev_context_hash;
        if (idx === 0) {
          if (prev !== undefined && prev !== null) linked = false;
        } else if (prev !== crypto.createHash('sha256').update(canonicalize(seq[idx - 1]?.signoff?.context ?? {}), 'utf8').digest('hex')) {
          linked = false;
        }
      }
      checks.chain_linked = linked;
    } else {
      checks.chain_linked = true;
    }

    const ts = counted.map((x) => issuedAts[x.i]).filter((t) => t !== null);
    checks.within_window = ts.length === counted.length && counted.length > 0
      && (Math.max(...ts) - Math.min(...ts)) <= windowSec * 1000;
  } catch {
    return { valid: false, checks, members: memberResults };
  }

  const valid = checks.all_signatures_valid
    && checks.action_binding
    && checks.distinct_humans
    && checks.distinct_keys
    && checks.roles_admitted
    && checks.threshold_met
    && checks.order_satisfied
    && checks.chain_linked
    && checks.within_window
    && checks.initiator_excluded;
  return { valid, checks, members: memberResults };
}

const REVOCATION_VERSION = 'EP-REVOCATION-v1';
const TARGET_TYPES = ['receipt', 'commit', 'delegation'];

function instantMs(s) {
  if (typeof s !== 'string' || s.length === 0) return null;
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : t;
}

function revocationSignedPayload(stmt) {
  return Buffer.from(
    canonicalize({
      '@version': REVOCATION_VERSION,
      action_hash: stmt.action_hash ?? null,
      reason: stmt.reason ?? null,
      revoked_at: stmt.revoked_at ?? null,
      revoker_id: stmt.revoker_id ?? null,
      target_id: stmt.target_id ?? null,
      target_type: stmt.target_type ?? null,
    }),
    'utf8',
  );
}

function verifyEd25519(bytes, publicKeyB64u, signatureB64u) {
  try {
    if (!bytes || !publicKeyB64u || !signatureB64u) return false;
    const key = crypto.createPublicKey({
      key: Buffer.from(publicKeyB64u, 'base64url'),
      format: 'der',
      type: 'spki',
    });
    return crypto.verify(null, bytes, key, Buffer.from(signatureB64u, 'base64url'));
  } catch {
    return false;
  }
}

function isWellFormedSignature(sigB64u) {
  try { return Buffer.from(String(sigB64u ?? ''), 'base64url').length === 64; }
  catch { return false; }
}

export function verifyRevocation(target, statement, opts = {}) {
  const revokerKeys = opts.revokerKeys || {};
  const checks = {
    version: true,
    target_bound: true,
    revoker_key_pinned: true,
    revoked_at_present: true,
    revoker_signature_valid: true,
    signature_binds_statement: true,
    freshness: true,
  };
  const errors = [];
  const fail = (key, msg) => { checks[key] = false; errors.push(msg); };

  if (!statement || typeof statement !== 'object') {
    fail('signature_binds_statement', 'no revocation statement presented');
    fail('revoker_signature_valid', 'no revocation statement presented');
    return { valid: false, checks, errors };
  }

  if (statement['@version'] !== REVOCATION_VERSION) {
    fail('version', `unsupported version: ${statement['@version']}`);
  }

  if (!target || typeof target !== 'object') {
    fail('target_bound', 'no target handed to the verifier');
  } else {
    if (target.target_type && !TARGET_TYPES.includes(target.target_type)) {
      fail('target_bound', `unknown target_type "${target.target_type}"`);
    }
    if (statement.target_type !== target.target_type) {
      fail('target_bound',
        `statement target_type "${statement.target_type}" != handed "${target.target_type}"`);
    }
    if (statement.target_id !== target.target_id) {
      fail('target_bound',
        `statement target_id "${statement.target_id}" != handed "${target.target_id}"`);
    } else if (hexOf(statement.action_hash) !== hexOf(target.action_hash)) {
      fail('target_bound',
        `statement action_hash ${hexOf(statement.action_hash)} != handed ${hexOf(target.action_hash)}`);
    }
  }

  const proof = statement.proof || null;
  const revokerId = statement.revoker_id;
  const pinned = revokerKeys[revokerId]?.public_key;
  const presentedKey = proof?.public_key ?? null;
  if (!pinned) {
    fail('revoker_key_pinned', `no pinned key for revoker "${revokerId}"`);
  } else if (presentedKey && pinned !== presentedKey) {
    fail('revoker_key_pinned', `presented revoker key != pinned key for "${revokerId}"`);
  }

  const revokedAtMs = instantMs(statement.revoked_at);
  if (revokedAtMs === null) {
    fail('revoked_at_present', 'revoked_at is absent or not a well-formed RFC 3339 instant');
  }

  let recomputedBytes = null;
  try { recomputedBytes = revocationSignedPayload(statement); } catch { recomputedBytes = null; }
  const signatureB64u = proof?.signature_b64u ?? null;
  const sigBindsPinned = pinned && recomputedBytes && verifyEd25519(recomputedBytes, pinned, signatureB64u);
  if (!sigBindsPinned) {
    const verifyKey = pinned || presentedKey;
    const sigOverRecomputed = verifyKey && recomputedBytes && verifyEd25519(recomputedBytes, verifyKey, signatureB64u);
    if (!signatureB64u || !verifyKey) {
      fail('revoker_signature_valid', 'revocation proof signature or key missing');
    } else if (!sigOverRecomputed && isWellFormedSignature(signatureB64u)) {
      fail('signature_binds_statement',
        'revoker signature does not bind the presented statement bytes');
      fail('revoker_signature_valid',
        'revoker signature does not verify under the pinned revoker key over the recomputed bytes');
    } else if (!sigOverRecomputed) {
      fail('revoker_signature_valid', 'revoker signature does not verify under the pinned revoker key');
    }
  }

  if (typeof opts.maxAgeSeconds === 'number' && revokedAtMs !== null) {
    const nowMs = opts.now === undefined ? Date.now() : new Date(opts.now).getTime();
    if (!Number.isNaN(nowMs)) {
      const ageSeconds = (nowMs - revokedAtMs) / 1000;
      if (ageSeconds > opts.maxAgeSeconds) {
        fail('freshness',
          `revoked_at is ${Math.round(ageSeconds)}s old, beyond the ${opts.maxAgeSeconds}s window`);
      }
    }
  }

  const valid = Object.values(checks).every(Boolean);
  return { valid, checks, errors };
}

const TIME_ATTESTATION_VERSION = 'EP-TIME-ATTESTATION-v1';

function timeSignedPayload(att) {
  return Buffer.from(
    canonicalize({
      '@version': TIME_ATTESTATION_VERSION,
      hashed: att.hashed ?? null,
      time: att.time ?? null,
      ts_authority_id: att.ts_authority_id ?? null,
    }),
    'utf8',
  );
}

export function verifyTimeAttestation(att, opts = {}) {
  const tsaKeys = opts.tsaKeys || {};
  const checks = {
    version: true,
    tsa_key_pinned: true,
    time_present: true,
    signature_valid: true,
    hash_bound: true,
    within_bounds: true,
  };
  const errors = [];
  const fail = (k, m) => { checks[k] = false; errors.push(m); };

  if (!att || typeof att !== 'object') {
    fail('signature_valid', 'no time attestation presented');
    return { valid: false, checks, errors };
  }
  if (att['@version'] !== TIME_ATTESTATION_VERSION) fail('version', `unsupported version: ${att['@version']}`);

  const proof = att.proof || null;
  const pinned = tsaKeys[att.ts_authority_id]?.public_key;
  const presentedKey = proof?.public_key ?? null;
  if (!pinned) fail('tsa_key_pinned', `no pinned key for ts_authority "${att.ts_authority_id}"`);
  else if (presentedKey && pinned !== presentedKey) fail('tsa_key_pinned', `presented TSA key != pinned key for "${att.ts_authority_id}"`);

  const ms = instantMs(att.time);
  if (ms === null) fail('time_present', 'time is absent or not a well-formed RFC 3339 instant');

  const sigOk = pinned && verifyEd25519(timeSignedPayload(att), pinned, proof?.signature_b64u);
  if (!sigOk) fail('signature_valid', 'TSA signature does not verify under the pinned key');

  if (typeof opts.expectedHash === 'string') {
    if (hexOf(att.hashed) !== hexOf(opts.expectedHash)) {
      fail('hash_bound', `attestation hashed ${hexOf(att.hashed)} != expected ${hexOf(opts.expectedHash)}`);
    }
  }

  if (ms !== null) {
    const nb = opts.notBefore === undefined ? null : new Date(opts.notBefore).getTime();
    const na = opts.notAfter === undefined ? null : new Date(opts.notAfter).getTime();
    if (nb !== null && !Number.isNaN(nb) && ms < nb) fail('within_bounds', 'attested time is before notBefore');
    if (na !== null && !Number.isNaN(na) && ms > na) fail('within_bounds', 'attested time is after notAfter');
  }

  const valid = Object.values(checks).every(Boolean);
  return { valid, checks, errors };
}

const STRICT_CHECK_NAMES = [
  'pinned_keys',
  'rp_id',
  'user_presence',
  'user_verification',
  'key_windows',
  'policy_hash',
  'no_unsigned',
];

function createStrictReport(enabled) {
  return {
    enabled,
    valid: !enabled,
    checks: enabled ? Object.fromEntries(STRICT_CHECK_NAMES.map((name) => [name, false])) : {},
    errors: [],
  };
}

function parseableTimestamp(value) {
  return typeof value === 'string' && !Number.isNaN(parseInstant(value));
}

function coerceRequiredApprovals(value) {
  if (value === undefined || value === null) return 1;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) return null;
  return value;
}

function markStrict(report, name, ok, message) {
  report.checks[name] = Boolean(ok);
  if (!ok && message) report.errors.push(message);
}

function evaluateTrustReceiptStrict(report, receipt, contexts, signoffs, contextByHash, approverKeys, logPublicKey, opts) {
  const classASignoffs = [];

  let pinnedKeysOk = Boolean(logPublicKey);
  if (!logPublicKey) {
    report.errors.push('strict pinned_keys requires a trusted logPublicKey');
  }
  for (const s of signoffs) {
    if (!s?.approver_key_id) {
      pinnedKeysOk = false;
      report.errors.push('strict pinned_keys requires every signoff to name approver_key_id');
      continue;
    }
    const keyEntry = approverKeys[s.approver_key_id];
    if (!keyEntry?.public_key) {
      pinnedKeysOk = false;
      report.errors.push(`strict pinned_keys has no pinned public key for ${s.approver_key_id}`);
    }
    const keyClass = keyEntry?.key_class || s.key_class || 'B';
    if (keyClass === 'A') classASignoffs.push({ signoff: s, keyEntry });
  }
  markStrict(report, 'pinned_keys', pinnedKeysOk);

  let rpOk = true;
  if (classASignoffs.length > 0 && !opts.rpId) {
    rpOk = false;
    report.errors.push('strict rp_id requires opts.rpId for Class-A WebAuthn signoffs');
  }
  for (const { signoff } of classASignoffs) {
    const parsed = parseClassAAssertion(signoff.webauthn);
    if (!parsed) {
      rpOk = false;
      report.errors.push('strict rp_id could not parse Class-A WebAuthn authenticator data');
      continue;
    }
    if (opts.rpId) {
      const expectedRpHash = sha256Bytes(opts.rpId);
      if (!parsed.authData.subarray(0, 32).equals(expectedRpHash)) {
        rpOk = false;
        report.errors.push('strict rp_id WebAuthn rpIdHash does not match opts.rpId');
      }
    }
  }
  markStrict(report, 'rp_id', rpOk);

  let upOk = true;
  let uvOk = true;
  for (const { signoff } of classASignoffs) {
    const parsed = parseClassAAssertion(signoff.webauthn);
    const flags = parsed?.authData?.[32] || 0;
    if (!parsed || (flags & FLAG_UP) !== FLAG_UP) {
      upOk = false;
      report.errors.push('strict user_presence requires Class-A WebAuthn UP');
    }
    if (!parsed || (flags & FLAG_UV) !== FLAG_UV) {
      uvOk = false;
      report.errors.push('strict user_verification requires Class-A WebAuthn UV');
    }
  }
  markStrict(report, 'user_presence', upOk);
  markStrict(report, 'user_verification', uvOk);

  let keyWindowsOk = true;
  for (const s of signoffs) {
    const digestHex = hexOf(s?.context_hash);
    const ctx = contextByHash.get(digestHex);
    const keyEntry = approverKeys[s?.approver_key_id];
    if (!ctx || !keyEntry?.public_key) {
      keyWindowsOk = false;
      report.errors.push('strict key_windows cannot bind a signoff to both context and pinned key');
      continue;
    }
    if (!parseableTimestamp(keyEntry.valid_from) || !parseableTimestamp(keyEntry.valid_to)) {
      keyWindowsOk = false;
      report.errors.push(`strict key_windows requires valid_from and valid_to for ${s.approver_key_id}`);
      continue;
    }
    if (!withinWindow(ctx.issued_at, keyEntry.valid_from, keyEntry.valid_to)) {
      keyWindowsOk = false;
      report.errors.push(`strict key_windows rejects ${s.approver_key_id} at context issued_at`);
    }
  }
  markStrict(report, 'key_windows', keyWindowsOk);

  let policyHashOk = true;
  const expectedPolicyHash = opts.expectedPolicyHash ? hexOf(opts.expectedPolicyHash) : null;
  if (!expectedPolicyHash) {
    policyHashOk = false;
    report.errors.push('strict policy_hash requires opts.expectedPolicyHash');
  }
  for (const ctx of contexts) {
    if (!ctx?.policy_hash) {
      policyHashOk = false;
      report.errors.push('strict policy_hash requires every context to carry policy_hash');
      continue;
    }
    if (expectedPolicyHash && hexOf(ctx.policy_hash) !== expectedPolicyHash) {
      policyHashOk = false;
      report.errors.push('strict policy_hash context policy_hash does not match opts.expectedPolicyHash');
    }
  }
  markStrict(report, 'policy_hash', policyHashOk);

  let noUnsignedOk = true;
  const requireField = (value, message) => {
    if (value === undefined || value === null || value === '') {
      noUnsignedOk = false;
      report.errors.push(message);
    }
  };
  requireField(receipt.action_hash, 'strict no_unsigned requires action_hash');
  requireField(receipt.consumption?.committed_at, 'strict no_unsigned requires consumption.committed_at');
  requireField(receipt.log_proof?.checkpoint?.log_signature, 'strict no_unsigned requires checkpoint.log_signature');
  if (!Array.isArray(receipt.log_proof?.inclusion_path)) {
    noUnsignedOk = false;
    report.errors.push('strict no_unsigned requires log_proof.inclusion_path');
  }
  for (const ctx of contexts) {
    requireField(ctx?.action_hash, 'strict no_unsigned requires every context to carry action_hash');
    requireField(ctx?.policy_hash, 'strict no_unsigned requires every context to carry policy_hash');
    requireField(ctx?.approver, 'strict no_unsigned requires every context to name approver');
    requireField(ctx?.issued_at, 'strict no_unsigned requires every context to carry issued_at');
    requireField(ctx?.expires_at, 'strict no_unsigned requires every context to carry expires_at');
  }
  for (const s of signoffs) {
    requireField(s?.context_hash, 'strict no_unsigned requires every signoff to carry context_hash');
    requireField(s?.approver_key_id, 'strict no_unsigned requires every signoff to carry approver_key_id');
    requireField(s?.key_class, 'strict no_unsigned requires every signoff to carry key_class');
    requireField(s?.signed_at, 'strict no_unsigned requires every signoff to carry signed_at');
    const keyClass = approverKeys[s?.approver_key_id]?.key_class || s?.key_class || 'B';
    if (keyClass === 'A') {
      requireField(s?.webauthn?.authenticator_data, 'strict no_unsigned requires Class-A authenticator_data');
      requireField(s?.webauthn?.client_data_json, 'strict no_unsigned requires Class-A client_data_json');
      requireField(s?.webauthn?.signature, 'strict no_unsigned requires Class-A WebAuthn signature');
    } else {
      requireField(s?.signature, 'strict no_unsigned requires Ed25519 signoff signature');
    }
  }
  markStrict(report, 'no_unsigned', noUnsignedOk);

  report.valid = STRICT_CHECK_NAMES.every((name) => report.checks[name] === true);
}

const ATTESTATION_TRIGGERS = new Set([
  'irreversibility', 'magnitude', 'uncertainty', 'novelty', 'authority_gap', 'policy_rule',
]);
const ATTESTATION_MEMBERS = new Set(['escalation_trigger', 'policy_basis', 'statement']);
const ATTESTATION_STATEMENT_MAX = 280;

function buildAttestationReport(contexts) {
  const withAtt = contexts.filter((c) => c && c.initiator_attestation !== undefined);
  if (withAtt.length === 0) {
    return { present: false, consistent: true, issues: [] };
  }

  const issues = [];
  let consistent = true;

  if (withAtt.length !== contexts.length) {
    consistent = false;
    issues.push('initiator_attestation is present in some contexts but not all');
  }
  const canonForms = new Set(withAtt.map((c) => canonicalize(c.initiator_attestation)));
  if (canonForms.size > 1) {
    consistent = false;
    issues.push('initiator_attestation differs across contexts');
  }

  for (const ctx of withAtt) {
    const att = ctx.initiator_attestation;
    const who = ctx.approver || 'unknown approver';
    if (!att || typeof att !== 'object' || Array.isArray(att)) {
      issues.push(`initiator_attestation for ${who} is not an object`);
      continue;
    }
    for (const key of Object.keys(att)) {
      if (!ATTESTATION_MEMBERS.has(key)) {
        issues.push(`initiator_attestation for ${who} has an unknown member "${key}"`);
      }
    }
    if (!ATTESTATION_TRIGGERS.has(att.escalation_trigger)) {
      issues.push(`initiator_attestation for ${who} has an invalid escalation_trigger "${att.escalation_trigger}"`);
    }
    if (att.escalation_trigger === 'policy_rule' && !att.policy_basis) {
      issues.push(`initiator_attestation for ${who} uses escalation_trigger "policy_rule" without policy_basis`);
    }
    if (typeof att.statement === 'string' && att.statement.length > ATTESTATION_STATEMENT_MAX) {
      issues.push(`initiator_attestation statement for ${who} exceeds the ${ATTESTATION_STATEMENT_MAX}-character cap`);
    }
  }

  return { present: true, consistent, issues };
}

function trustReceiptCanonicalProfileError(receipt) {
  const leafContent = { ...receipt };
  delete leafContent.log_proof;
  delete leafContent.approver_key_proofs;
  if (!isCanonicalizable(leafContent)) return 'Trust Receipt body';

  const checkpoint = receipt?.log_proof?.checkpoint;
  if (checkpoint && typeof checkpoint === 'object') {
    const signedCheckpoint = { ...checkpoint };
    delete signedCheckpoint.log_signature;
    if (!isCanonicalizable(signedCheckpoint)) return 'Trust Receipt checkpoint';
  }
  return null;
}

const RFC3339_OFFSET = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
function parseInstant(value) {
  if (typeof value !== 'string' || !RFC3339_OFFSET.test(value)) return NaN;
  return Date.parse(value);
}

function withinWindow(t, from, to) {
  const ts = parseInstant(t);
  if (Number.isNaN(ts)) return false;
  if (from) { const f = parseInstant(from); if (Number.isNaN(f) || ts < f) return false; }
  if (to) { const g = parseInstant(to); if (Number.isNaN(g) || ts > g) return false; }
  return true;
}

export function verifyTrustReceipt(receipt, opts = {}) {
  const checks = {
    action_hash: false,
    context_commitments: false,
    signoff_signatures: false,
    sod: false,
    inclusion: false,
    checkpoint_signature: false,
    windows: false,
  };
  const errors = [];
  const attestationContexts = Array.isArray(receipt?.contexts) ? receipt.contexts : [];
  const attestation = buildAttestationReport(attestationContexts);
  const strict = createStrictReport(opts.strict === true);
  const fail = (msg) => { errors.push(msg); return { valid: false, checks, errors, attestation, strict }; };

  if (!receipt || typeof receipt !== 'object') return fail('Missing receipt');
  const { approverKeys = {}, logPublicKey } = opts;
  const contexts = Array.isArray(receipt.contexts) ? receipt.contexts : [];
  const signoffs = Array.isArray(receipt.signoffs) ? receipt.signoffs : [];
  if (!receipt.action || !receipt.action_hash) return fail('Missing action or action_hash');
  if (contexts.length === 0 || signoffs.length === 0) return fail('Missing contexts or signoffs');
  const profileError = trustReceiptCanonicalProfileError(receipt);
  if (profileError) {
    return fail(`${profileError} is outside the EP canonicalization profile`);
  }

  const { signoffs: _s, log_proof: _lp, approver_key_proofs: _akp, ...canonicalScope } = receipt;
  if (!isCanonicalizable(canonicalScope)) {
    return fail('Receipt contains a value outside the EP canonicalization profile');
  }

  const actionHashHex = sha256(canonicalize(receipt.action));
  checks.action_hash = actionHashHex === hexOf(receipt.action_hash);
  if (!checks.action_hash) errors.push('action_hash does not match the canonical Action Object');

  const contextByHash = new Map();
  let commitmentsOk = true;
  const policyHashes = new Set();
  for (const ctx of contexts) {
    const digestHex = sha256(canonicalize(ctx));
    contextByHash.set(digestHex, ctx);
    if (hexOf(ctx.action_hash) !== actionHashHex) {
      commitmentsOk = false;
      errors.push(`context for ${ctx.approver || 'unknown approver'} does not commit to the action hash`);
    }
    if (!ctx.policy_hash) {
      commitmentsOk = false;
      errors.push('context is missing policy_hash');
    } else {
      policyHashes.add(hexOf(ctx.policy_hash));
    }
    if (!ctx.approver) {
      commitmentsOk = false;
      errors.push('context is missing approver');
    }
  }
  if (policyHashes.size > 1) {
    commitmentsOk = false;
    errors.push('contexts commit to different policy hashes');
  }
  checks.context_commitments = commitmentsOk;

  const validApprovals = [];
  let signaturesOk = signoffs.length > 0;
  for (const s of signoffs) {
    const digestHex = hexOf(s.context_hash);
    const ctx = contextByHash.get(digestHex);
    if (!ctx) {
      signaturesOk = false;
      errors.push('signoff references a context hash not present in this receipt');
      continue;
    }
    const keyEntry = approverKeys[s.approver_key_id];
    if (!keyEntry?.public_key) {
      signaturesOk = false;
      errors.push(`no pinned key entry for ${s.approver_key_id}`);
      continue;
    }
    if (!withinWindow(ctx.issued_at, keyEntry.valid_from, keyEntry.valid_to)) {
      signaturesOk = false;
      errors.push(`approver key ${s.approver_key_id} was not valid at issued_at`);
      continue;
    }
    const digestBytes = Buffer.from(digestHex, 'hex');
    const keyClass = keyEntry.key_class || s.key_class || 'B';
    const sigOk = keyClass === 'A'
      ? Boolean(s.webauthn) && verifyClassAOverDigest(s.webauthn, digestBytes, keyEntry.public_key)
      : verifyEd25519OverDigest(s.signature, digestBytes, keyEntry.public_key);
    if (!sigOk) {
      signaturesOk = false;
      errors.push(`signoff by ${ctx.approver} does not verify`);
      continue;
    }
    validApprovals.push({ approver: ctx.approver, signedAt: s.signed_at, ctx });
  }
  checks.signoff_signatures = signaturesOk;

  const initiator = receipt.action.initiator;
  const approvers = validApprovals.map((a) => a.approver);
  const coerced = contexts.map((c) => coerceRequiredApprovals(c.required_approvals));
  let sodOk = true;
  if (coerced.some((n) => n === null)) {
    sodOk = false;
    errors.push('required_approvals must be an integer >= 1');
  }
  const requiredApprovals = Math.max(1, ...coerced.map((n) => n ?? 1));
  if (initiator && approvers.includes(initiator)) {
    sodOk = false;
    errors.push('initiator appears in an approver slot');
  }
  if (new Set(approvers).size !== approvers.length) {
    sodOk = false;
    errors.push('approvers are not pairwise distinct');
  }
  if (validApprovals.length < requiredApprovals) {
    sodOk = false;
    errors.push(`approval count ${validApprovals.length} < required_approvals ${requiredApprovals}`);
  }
  checks.sod = sodOk;

  const lp = receipt.log_proof;
  if (lp?.checkpoint && Array.isArray(lp.inclusion_path)) {
    const leafContent = { ...receipt };
    delete leafContent.log_proof;
    delete leafContent.approver_key_proofs;
    const canonicalLeaf = canonicalize(leafContent);
    const merkleAlg = lp.alg || lp.checkpoint?.merkle_alg || null;
    let emptyPathRefusal = null;
    if (lp.inclusion_path.length === 0) {
      if (lp.checkpoint.tree_size !== 1) {
        emptyPathRefusal = 'empty inclusion_path requires checkpoint tree_size 1';
      } else if (lp.leaf_index !== undefined && lp.leaf_index !== 0) {
        emptyPathRefusal = 'empty inclusion_path requires leaf_index 0';
      }
    }
    if (emptyPathRefusal) {
      checks.inclusion = false;
      errors.push(emptyPathRefusal);
    } else if (merkleAlg === MERKLE_V2_ALG) {
      const leafHash = leafHashV2(canonicalLeaf);
      const presentedLeaf = lp.leaf_hash ? hexOf(lp.leaf_hash) : leafHash;
      checks.inclusion = presentedLeaf === leafHash
        && verifyMerkleAnchor(leafHash, lp.inclusion_path, hexOf(lp.checkpoint.root_hash), { v2: true });
      if (presentedLeaf !== leafHash) errors.push('Trust Receipt log_proof leaf_hash does not bind this receipt');
    } else if (opts.allowLegacyMerkle === true || opts.allowLegacyTrustReceiptMerkle === true) {
      const leafHash = sha256(canonicalLeaf);
      checks.inclusion = verifyMerkleAnchor(leafHash, lp.inclusion_path, hexOf(lp.checkpoint.root_hash));
    } else {
      checks.inclusion = false;
      errors.push('log_proof is not EP-MERKLE-v2');
    }

    if (logPublicKey && lp.checkpoint.log_signature) {
      const signedCheckpoint = { ...lp.checkpoint };
      delete signedCheckpoint.log_signature;
      checks.checkpoint_signature = verifyEd25519OverDigest(
        String(lp.checkpoint.log_signature).replace(/^b64u:/, ''),
        sha256Bytes(canonicalize(signedCheckpoint)),
        logPublicKey,
      );
    } else {
      errors.push('missing log public key or checkpoint signature');
    }
  } else {
    errors.push('missing log_proof');
  }

  if (opts.priorCheckpoint !== undefined) {
    checks.consistency = false;
    const prior = opts.priorCheckpoint;
    const priorSize = prior?.tree_size;
    const priorRoot = hexOf(prior?.root_hash);
    const headSize = lp?.checkpoint?.tree_size;
    const headRoot = hexOf(lp?.checkpoint?.root_hash);
    if (!prior || typeof prior !== 'object' || !Number.isInteger(priorSize) || priorSize < 1 || !priorRoot) {
      errors.push('priorCheckpoint requires integer tree_size >= 1 and root_hash');
    } else if (!Number.isInteger(headSize) || !headRoot) {
      errors.push('priorCheckpoint is pinned but the receipt checkpoint is missing tree_size or root_hash');
    } else if (!Array.isArray(prior.consistency_proof)) {
      errors.push('priorCheckpoint is pinned but consistency_proof is missing');
    } else if (verifyCheckpointConsistency(priorRoot, priorSize, headRoot, headSize, prior.consistency_proof)) {
      checks.consistency = true;
    } else {
      errors.push('consistency_proof does not prove an append-only extension');
    }
  }

  const optionalResults = {};

  if (opts.witnessQuorum !== undefined) {
    checks.witness_quorum = false;
    const wq = opts.witnessQuorum;
    const checkpoint = lp?.checkpoint;
    if (!checkpoint || typeof checkpoint !== 'object') {
      optionalResults.witness_quorum = {
        ok: false, met: 0, required: 0, witness_ids: [],
        reasons: ['receipt has no checkpoint'],
      };
      errors.push('witnessQuorum is set but the receipt checkpoint is missing');
    } else if (!wq || typeof wq !== 'object') {
      optionalResults.witness_quorum = {
        ok: false, met: 0, required: 0, witness_ids: [],
        reasons: ['witnessQuorum must be an object'],
      };
      errors.push('witnessQuorum must be an object');
    } else {
      const res = requireWitnessQuorum(checkpoint, wq.cosignatures, wq.pinnedWitnessKeys, wq.k);
      optionalResults.witness_quorum = res;
      checks.witness_quorum = res.ok === true;
    }
  }

  if (opts.timestampProof !== undefined) {
    checks.timestamp_proof = false;
    const tp = opts.timestampProof;
    if (!tp || typeof tp !== 'object') {
      optionalResults.timestamp_proof = {
        verified: false, tsa_key_id: null, gen_time: null,
        reason: 'timestampProof must be an object',
      };
    } else {
      const res = verifyTimestampProof(tp.token, tp.expectedDigest, tp.pinnedTsaKeys);
      optionalResults.timestamp_proof = res;
      checks.timestamp_proof = res.verified === true;
    }
  }

  if (opts.currency !== undefined) {
    checks.currency = false;
    const c = (opts.currency && typeof opts.currency === 'object') ? opts.currency : {};
    const res = evaluateCurrency({
      receipt,
      authentic_as_of_commit: c.authentic_as_of_commit === true,
      now: c.now,
      maxStalenessSeconds: c.maxStalenessSeconds,
      freshHead: c.freshHead,
      freshHeadRequired: c.freshHeadRequired,
    });
    optionalResults.currency = res;
    checks.currency = res.currency_at_T.status === 'fresh';
  }

  if (opts.consumptionProof !== undefined) {
    checks.consumption = false;
    const res = verifyConsumptionProof(opts.consumptionProof);
    optionalResults.consumption = res;
    checks.consumption = res.valid === true;
  }

  if (opts.requireInitiatorAttestation === true) {
    checks.initiator_attestation = false;
    const att = (receipt.action && typeof receipt.action === 'object')
      ? receipt.action.initiator_software
      : undefined;
    if (att === undefined) {
      optionalResults.initiator_attestation = {
        ok: false, normalized: null,
        errors: ['requireInitiatorAttestation is set but action.initiator_software is absent'],
        statement_report: null,
      };
    } else {
      const res = validateInitiatorAttestation(att);
      optionalResults.initiator_attestation = res;
      checks.initiator_attestation = res.ok === true;
    }
  }

  let windowsOk = validApprovals.length > 0;
  for (const a of validApprovals) {
    if (!withinWindow(a.signedAt, a.ctx.issued_at, a.ctx.expires_at)) {
      windowsOk = false;
    }
  }
  const committedAt = receipt.consumption?.committed_at;
  if (!committedAt) {
    windowsOk = false;
  } else {
    for (const ctx of contexts) {
      if (!withinWindow(committedAt, ctx.issued_at, ctx.expires_at)) {
        windowsOk = false;
        break;
      }
    }
  }
  checks.windows = windowsOk;

  if (strict.enabled) {
    evaluateTrustReceiptStrict(strict, receipt, contexts, signoffs, contextByHash, approverKeys, logPublicKey, opts);
  }
  const valid = Object.values(checks).every(Boolean) && strict.valid;
  return { valid, checks, errors, attestation, strict, ...optionalResults };
}

function isPowerOfTwo(n) {
  return n > 0 && (n & (n - 1)) === 0;
}

function largestPowerOfTwoLessThan(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function verifyCheckpointConsistency(oldRoot, oldSize, newRoot, newSize, proof) {
  if (!Number.isInteger(oldSize) || !Number.isInteger(newSize)) return false;
  if (oldSize < 0 || newSize < 0 || oldSize > newSize) return false;
  if (!Array.isArray(proof)) return false;
  if (proof.length > 64) return false;
  const oldR = hexOf(oldRoot);
  const newR = hexOf(newRoot);
  if (!oldR || !newR) return false;

  if (oldSize === newSize) {
    return proof.length === 0 && oldR === newR;
  }
  if (oldSize === 0) return false;
  if (proof.length === 0) return false;

  const path = proof.map(hexOf);
  if (path.some((h) => !h)) return false;

  let node = path;
  let seed;
  if (isPowerOfTwo(oldSize)) {
    seed = oldR;
  } else {
    seed = node[0];
    node = node.slice(1);
  }

  let fn = oldSize - 1;
  let sn = newSize - 1;
  while (fn % 2 === 1) {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }

  let fr = seed;
  let sr = seed;

  for (const c of node) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = hashChildrenV2(c, fr);
      sr = hashChildrenV2(c, sr);
      while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      sr = hashChildrenV2(sr, c);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }

  return sn === 0 && fr === oldR && sr === newR;
}

function hashChildrenV2(left, right) {
  return crypto
    .createHash('sha256')
    .update(Buffer.concat([Buffer.from([0x01]), Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8')]))
    .digest('hex');
}

const DEFAULT_HUMAN_KEY_CLASSES = ['A'];
const WELL_FORMED_ACTION_TYPE = /^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$/;
function isWellFormedActionType(s) {
  return typeof s === 'string' && WELL_FORMED_ACTION_TYPE.test(s);
}

function hasHumanSignoff(receipt, humanClasses) {
  const set = new Set(humanClasses);
  const signoffs = Array.isArray(receipt?.signoffs) ? receipt.signoffs : [];
  return signoffs.some((s) => set.has(s?.key_class));
}

function receiptApprovers(receipt) {
  const ids = new Set();
  for (const ctx of receipt?.contexts || []) if (ctx?.approver) ids.add(ctx.approver);
  for (const s of receipt?.signoffs || []) if (s?.approver_key_id) ids.add(s.approver_key_id);
  return ids;
}

const executedActionType = (doc) => doc?.action_approval?.receipt?.action?.action_type ?? null;

function latestContextExpiry(receipt) {
  let max = null;
  for (const ctx of receipt?.contexts || []) {
    const t = Date.parse(ctx?.expires_at);
    if (!Number.isNaN(t) && (max === null || t > max)) max = t;
  }
  return max;
}

function committedAtMs(receipt) {
  const t = Date.parse(receipt?.consumption?.committed_at);
  return Number.isNaN(t) ? null : t;
}

function scopePermits(scope, actionType) {
  if (!Array.isArray(scope) || !isWellFormedActionType(actionType)) return false;
  for (const grant of scope) {
    if (grant === '*' || grant === actionType) return true;
    if (typeof grant === 'string' && grant.endsWith('.*')) {
      const prefix = grant.slice(0, -2);
      if (actionType === prefix || actionType.startsWith(prefix + '.')) return true;
    }
  }
  return false;
}

function scopeContainmentViolations(parent, child) {
  const violations = [];
  for (const token of child.scope || []) {
    const probe = typeof token === 'string' && token.endsWith('.*') ? token.slice(0, -2) : token;
    if (!scopePermits(parent.scope, probe)) {
      violations.push(`child scope "${token}" exceeds parent scope [${(parent.scope || []).join(', ')}]`);
    }
  }
  const parentCap = parent.max_value_usd;
  let childCap = child.max_value_usd;
  if (childCap === null || childCap === undefined) childCap = parentCap;
  if (parentCap !== null && parentCap !== undefined) {
    if (childCap === null || childCap === undefined || Number(childCap) > Number(parentCap)) {
      violations.push(`child max_value_usd ${childCap} exceeds parent cap ${parentCap}`);
    }
  }
  const pExp = Date.parse(parent.expires_at);
  const cExp = Date.parse(child.expires_at);
  if (!Number.isNaN(pExp) && !Number.isNaN(cExp) && cExp > pExp) {
    violations.push(`child expires_at ${child.expires_at} is after parent expires_at ${parent.expires_at}`);
  }
  return violations;
}

function verifyDetachedSignature(att) {
  try {
    if (!att?.signed_payload_b64u || !att?.signature_b64u || !att?.public_key) return false;
    if (att.algorithm && att.algorithm !== 'Ed25519') return false;
    const key = crypto.createPublicKey({ key: Buffer.from(att.public_key, 'base64url'), format: 'der', type: 'spki' });
    return crypto.verify(null, Buffer.from(att.signed_payload_b64u, 'base64url'), key, Buffer.from(att.signature_b64u, 'base64url'));
  } catch {
    return false;
  }
}

const DELEGATION_PROOF_FIELDS = ['delegation_id', 'delegator', 'delegatee', 'scope', 'max_value_usd', 'expires_at', 'constraints'];

function delegationProofBytes(link) {
  const subset = {};
  for (const f of DELEGATION_PROOF_FIELDS) subset[f] = link[f] ?? null;
  return Buffer.from(canonicalize(subset), 'utf8');
}

function rootAuthorizedScope(rootReceipt) {
  const at = rootReceipt?.action?.action_type;
  return typeof at === 'string' && at.length > 0 ? [at] : [];
}

function constraintsMonotonic(parentC, childC) {
  const p = parentC || {};
  const c = childC || {};
  for (const k of Object.keys(p)) {
    if (!(k in c)) return false;
    const pv = p[k];
    const cv = c[k];
    if (typeof pv === 'number' && typeof cv === 'number') {
      if (cv > pv) return false;
    } else if (Array.isArray(pv) && Array.isArray(cv)) {
      const pset = new Set(pv.map((x) => canonicalize(x)));
      if (!cv.every((x) => pset.has(canonicalize(x)))) return false;
    } else if (canonicalize(pv) !== canonicalize(cv)) {
      return false;
    }
  }
  return true;
}

const PROVENANCE_VERSION = 'EP-PROVENANCE-CHAIN-v1';

export function verifyProvenanceOffline(doc, opts = {}) {
  const humanKeyClasses = opts.humanKeyClasses || DEFAULT_HUMAN_KEY_CLASSES;
  const allowUnsignedDelegations = opts.allowUnsignedDelegations === true;
  const now = typeof opts.now === 'number' ? opts.now : Date.now();
  const requireActionApprovalAlways = opts.requireActionApprovalAlways === true;

  const checks = {
    version: false, root_receipt_valid: false, root_human_signoff: false,
    per_action_required: true, action_receipt_valid: true, action_human_signoff: true,
    execution_binding: true, chain_anchored: true, chain_links_bound: true,
    delegations_signed: true, proof_key_bound: true, delegations_not_expired: true,
    scope_containment: true, constraints_monotonic: true, leaf_permits_action: true, temporal_containment: true,
  };
  const errors = [];
  const links = [];
  const fail = (key, msg) => { checks[key] = false; errors.push(msg); };

  if (doc?.['@version'] !== PROVENANCE_VERSION) {
    errors.push(`unsupported version: ${doc?.['@version']}`);
    return { valid: false, checks, errors, links, agent_identity: null, liability: null };
  }
  checks.version = true;

  const root = doc.root_signoff;
  if (!root?.receipt || !root?.verification) {
    fail('root_receipt_valid', 'missing root_signoff.receipt or root_signoff.verification');
  } else {
    const r0 = verifyTrustReceipt(root.receipt, {
      approverKeys: root.verification.approver_keys,
      logPublicKey: root.verification.log_public_key,
    });
    checks.root_receipt_valid = r0.valid;
    checks.root_human_signoff = hasHumanSignoff(root.receipt, humanKeyClasses);
  }

  const exec = doc.execution || {};
  const reversibilityAsserted = typeof opts.reversibilityAsserted === 'function' ? opts.reversibilityAsserted(exec) === true : false;
  const needApproval = requireActionApprovalAlways || !reversibilityAsserted;
  const approval = doc.action_approval;
  if (needApproval && !approval?.receipt) {
    fail('per_action_required', 'execution is irreversible but no action_approval is present');
  }
  if (approval?.receipt) {
    const ra = verifyTrustReceipt(approval.receipt, {
      approverKeys: approval.verification?.approver_keys,
      logPublicKey: approval.verification?.log_public_key,
    });
    checks.action_receipt_valid = ra.valid;
    if (exec.irreversible === true) {
      checks.action_human_signoff = hasHumanSignoff(approval.receipt, humanKeyClasses);
    }
    checks.execution_binding = hexOf(exec.action_hash) === hexOf(approval.receipt.action_hash);
  }

  const chain = Array.isArray(doc.delegation_chain) ? [...doc.delegation_chain] : [];
  chain.sort((a, b) => (a.sequence ?? 0) - (b.sequence ?? 0));
  const delegationKeys = opts.delegationKeys || {};
  const rootApprovers = doc.root_signoff?.receipt ? receiptApprovers(doc.root_signoff.receipt) : new Set();
  const rootExpiry = latestContextExpiry(doc.root_signoff?.receipt);
  const rootScope = doc.root_signoff?.receipt ? rootAuthorizedScope(doc.root_signoff.receipt) : [];
  let parent = {
    scope: rootScope, max_value_usd: null,
    expires_at: rootExpiry !== null ? new Date(rootExpiry).toISOString() : undefined,
    id: '(root human signoff)',
  };

  if (chain.length > 0) {
    const head = chain[0];
    checks.chain_anchored = rootApprovers.has(head.parent_ref) || rootApprovers.has(head.delegator);
  }

  let prevDelegatee = null;
  for (const link of chain) {
    const linkReport = { sequence: link.sequence, delegation_id: link.delegation_id, ok: true, issues: [] };
    if (prevDelegatee !== null) {
      if (link.parent_ref !== prevDelegatee || link.delegator !== prevDelegatee) {
        checks.chain_links_bound = false; linkReport.ok = false; linkReport.issues.push('inter_hop_link_broken');
      }
    }
    const expM = Date.parse(link.expires_at);
    if (Number.isNaN(expM) || expM < now) {
      checks.delegations_not_expired = false; linkReport.ok = false; linkReport.issues.push('expired');
    }
    if (link.proof) {
      const sigOk = verifyDetachedSignature(link.proof);
      const boundBytes = delegationProofBytes(link);
      const presentedBytes = (() => { try { return Buffer.from(link.proof.signed_payload_b64u || '', 'base64url'); } catch { return Buffer.alloc(0); } })();
      const bytesMatch = sigOk && presentedBytes.equals(boundBytes);
      if (!sigOk || !bytesMatch) {
        checks.delegations_signed = false; linkReport.ok = false;
        linkReport.issues.push(sigOk ? 'proof_not_over_own_fields' : 'signature_invalid');
      }
      const boundKey = delegationKeys[link.delegator]?.public_key;
      if (!boundKey) {
        checks.proof_key_bound = false; linkReport.ok = false; linkReport.issues.push('no_pinned_delegator_key');
      } else if (boundKey !== link.proof.public_key) {
        checks.proof_key_bound = false; linkReport.ok = false; linkReport.issues.push('proof_key_not_bound_to_delegator');
      }
    } else if (!allowUnsignedDelegations) {
      checks.delegations_signed = false; linkReport.ok = false; linkReport.issues.push('unsigned');
    }
    const violations = scopeContainmentViolations(parent, link);
    if (violations.length > 0) {
      checks.scope_containment = false; linkReport.ok = false; linkReport.issues.push(...violations);
    }
    if (!constraintsMonotonic(parent.constraints, link.constraints)) {
      checks.constraints_monotonic = false; linkReport.ok = false; linkReport.issues.push('constraints_relaxed');
    }
    links.push(linkReport);
    let effectiveCap;
    if (link.max_value_usd === null || link.max_value_usd === undefined) effectiveCap = parent.max_value_usd;
    else if (parent.max_value_usd === null || parent.max_value_usd === undefined) effectiveCap = link.max_value_usd;
    else effectiveCap = Math.min(Number(link.max_value_usd), Number(parent.max_value_usd));
    parent = { ...link, max_value_usd: effectiveCap };
    prevDelegatee = link.delegatee;
  }

  const actionType = executedActionType(doc);
  if (!actionType) {
    checks.leaf_permits_action = false;
  } else if (!scopePermits(parent.scope, actionType)) {
    checks.leaf_permits_action = false;
  }

  {
    const commit = approval?.receipt ? committedAtMs(approval.receipt) : null;
    const leafExp = Date.parse(parent.expires_at);
    if (commit !== null && !Number.isNaN(leafExp) && commit > leafExp) {
      checks.temporal_containment = false;
    }
  }

  let agentIdentity = null;
  if (doc.agent_identity) {
    agentIdentity = {
      agent_id: doc.agent_identity.agent_id ?? null,
      claimed_by: doc.agent_identity.claimed_by ?? null,
      claim_only: true,
      attestation_signature_valid: doc.agent_identity.attestation ? verifyDetachedSignature(doc.agent_identity.attestation) : null,
    };
  }
  let liability = null;
  if (doc.liability) {
    liability = {
      owner: doc.liability.owner ?? null,
      owner_name: doc.liability.owner_name ?? null,
      evidence_only: true,
      attestation_signature_valid: doc.liability.attestation ? verifyDetachedSignature(doc.liability.attestation) : null,
    };
  }

  const valid = Object.values(checks).every(Boolean);
  return { valid, checks, errors, links, agent_identity: agentIdentity, liability };
}

const EVIDENCE_RECORD_VERSION = 'EP-EVIDENCE-RECORD-v1';
const SUPPORTED_HASH = new Set(['sha256', 'sha384', 'sha512']);

function algOf(hashed) {
  const s = String(hashed ?? '');
  const i = s.indexOf(':');
  if (i < 0) return { alg: 'sha256', hex: s.toLowerCase() };
  return { alg: s.slice(0, i).toLowerCase(), hex: s.slice(i + 1).toLowerCase() };
}

function hashHexWith(alg, bytes) {
  return crypto.createHash(alg).update(bytes).digest('hex');
}

export function verifyEvidenceRecord(record, opts = {}) {
  const tsaKeys = opts.tsaKeys || {};
  const checks = {
    version: false,
    protected_bound: true,
    chain_nonempty: false,
    all_timestamps_valid: true,
    chain_linked: true,
    monotonic_time: true,
  };
  const errors = [];
  const fail = (k, m) => { checks[k] = false; errors.push(m); };

  try {
    if (record?.['@version'] !== EVIDENCE_RECORD_VERSION) {
      errors.push(`unsupported version: ${record?.['@version']}`);
      return { valid: false, checks, errors };
    }
    checks.version = true;

    const ats = Array.isArray(record.archive_timestamps) ? record.archive_timestamps : [];
    checks.chain_nonempty = ats.length > 0;
    if (!checks.chain_nonempty) {
      errors.push('no archive timestamps');
      return { valid: false, checks, errors };
    }

    if (typeof opts.protectedHash === 'string') {
      if (algOf(record.protected_hash).hex !== algOf(opts.protectedHash).hex) {
        fail('protected_bound', 'record protected_hash does not match the supplied artifact hash');
      }
    }

    let prevTime = null;
    let firstTime = null;
    for (let i = 0; i < ats.length; i++) {
      const ta = ats[i]?.time_attestation;
      const r = verifyTimeAttestation(ta, { tsaKeys });
      if (!r.valid) fail('all_timestamps_valid', `archive timestamp ${i} TSA attestation does not verify`);

      const cur = algOf(ta?.hashed);
      if (i === 0) {
        if (cur.hex !== algOf(record.protected_hash).hex) {
          fail('chain_linked', 'first archive timestamp does not cover protected_hash');
        }
      } else if (!SUPPORTED_HASH.has(cur.alg)) {
        fail('chain_linked', `renewal ${i} uses an unsupported hash algorithm "${cur.alg}"`);
      } else {
        const expected = hashHexWith(cur.alg, Buffer.from(canonicalize(ats[i - 1].time_attestation), 'utf8'));
        if (cur.hex !== expected) fail('chain_linked', `renewal ${i} does not cover the previous attestation`);
      }

      const t = Date.parse(ta?.time ?? '');
      if (Number.isNaN(t)) {
        fail('monotonic_time', `archive timestamp ${i} has no parseable time`);
      } else {
        if (prevTime !== null && !(t > prevTime)) fail('monotonic_time', `renewal ${i} time is not after the previous`);
        if (firstTime === null) firstTime = ta?.time;
        prevTime = t;
      }
    }

    const valid = Object.values(checks).every(Boolean);
    const last = ats[ats.length - 1]?.time_attestation?.time;
    return { valid, checks, errors, protected_since: firstTime, last_renewed: last };
  } catch {
    return { valid: false, checks, errors };
  }
}

const MAX_DEPTH = 64;

function strictParseGate(raw) {
  let i = 0;
  const n = raw.length;
  const stack = [];
  let reason = null;
  const ESCAPES = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
  const readString = () => {
    i++;
    let out = '';
    while (i < n) {
      const c = raw[i];
      if (c === '"') { i++; return out; }
      if (c === '\\') {
        const e = raw[i + 1];
        if (e === 'u') {
          const cu = parseInt(raw.slice(i + 2, i + 6), 16);
          i += 6;
          if (cu >= 0xd800 && cu <= 0xdbff) {
            if (raw[i] === '\\' && raw[i + 1] === 'u') {
              const cu2 = parseInt(raw.slice(i + 2, i + 6), 16);
              if (cu2 >= 0xdc00 && cu2 <= 0xdfff) {
                i += 6;
                out += String.fromCharCode(cu, cu2);
                continue;
              }
            }
            reason = 'unpaired high surrogate escape';
            return null;
          }
          if (cu >= 0xdc00 && cu <= 0xdfff) {
            reason = 'unpaired low surrogate escape';
            return null;
          }
          out += String.fromCharCode(cu);
        } else {
          out += ESCAPES[e] ?? '';
          i += 2;
        }
      } else {
        out += c;
        i++;
      }
    }
    reason = 'unterminated string';
    return null;
  };
  while (i < n) {
    const c = raw[i];
    if (c === '{') {
      stack.push({ obj: true, keys: new Set(), expectKey: true });
      if (stack.length > MAX_DEPTH) return { ok: false, reason: `nesting depth exceeds ${MAX_DEPTH}` };
      i++;
    } else if (c === '[') {
      stack.push({ obj: false });
      if (stack.length > MAX_DEPTH) return { ok: false, reason: `nesting depth exceeds ${MAX_DEPTH}` };
      i++;
    } else if (c === '}' || c === ']') {
      stack.pop();
      i++;
    } else if (c === ',') {
      const top = stack[stack.length - 1];
      if (top?.obj) top.expectKey = true;
      i++;
    } else if (c === '"') {
      const top = stack[stack.length - 1];
      const isKey = Boolean(top?.obj && top.expectKey);
      const s = readString();
      if (reason) return { ok: false, reason };
      if (isKey) {
        if (top.keys.has(s)) return { ok: false, reason: 'duplicate object member name' };
        top.keys.add(s);
        top.expectKey = false;
      }
    } else {
      i++;
    }
  }
  return { ok: true };
}




// --- WebAuthn and Ed25519 helper functions manually patched ---

function parseClassAAssertion(webauthn) {
  try {
    const clientDataBytes = Buffer.from(webauthn.client_data_json, 'base64url');
    const clientData = JSON.parse(clientDataBytes.toString('utf8'));
    const authData = Buffer.from(webauthn.authenticator_data, 'base64url');
    if (authData.length < 37) return null;
    return { authData, clientData, clientDataBytes };
  } catch {
    return null;
  }
}

function verifyClassAOverDigest(webauthn, digestBytes, publicKeySpkiB64u) {
  try {
    const parsed = parseClassAAssertion(webauthn);
    if (!parsed) return false;
    const { authData, clientData, clientDataBytes } = parsed;
    if (clientData.type !== 'webauthn.get') return false;
    if (clientData.challenge !== Buffer.from(digestBytes).toString('base64url')) return false;

    if ((authData[32] & FLAG_UP) !== FLAG_UP) return false; // human presence required
    if ((authData[32] & FLAG_UV) !== FLAG_UV) return false; // biometric/PIN verification required

    const signedData = Buffer.concat([authData, crypto.createHash('sha256').update(clientDataBytes).digest()]);
    const keyObject = crypto.createPublicKey({
      key: Buffer.from(publicKeySpkiB64u, 'base64url'), format: 'der', type: 'spki',
    });
    return crypto.verify('sha256', signedData, keyObject, Buffer.from(webauthn.signature, 'base64url'));
  } catch {
    return false;
  }
}

function verifyEd25519OverDigest(signatureB64u, digestBytes, publicKeySpkiB64u) {
  try {
    const keyObject = crypto.createPublicKey({
      key: Buffer.from(publicKeySpkiB64u, 'base64url'), format: 'der', type: 'spki',
    });
    return crypto.verify(null, digestBytes, keyObject, Buffer.from(signatureB64u, 'base64url'));
  } catch {
    return false;
  }
}


export function runCanonicalization(c) {
  if (typeof c?.input_json !== 'string') return false;
  let value;
  try { value = JSON.parse(c.input_json); } catch { return false; }
  if (!strictParseGate(c.input_json).ok) return false;
  if (!isCanonicalizable(value)) return false;
  return crypto.createHash('sha256').update(canonicalize(value), 'utf8').digest('hex') === c.expected_digest;
}

// ── EP-CURRENCY-v1: two-valued currency evaluation ──────────────────────────
// Offline verification cannot prove current validity. This function computes
// whether a receipt is authentic-as-of-commit (passed through) and whether it
// is fresh/stale/unknown at time T based on a supplied freshHead.

const CURRENCY_REASON = Object.freeze({
  offline_only_no_fresh_head: 'offline_only_no_fresh_head',
  fresh_head_malformed: 'fresh_head_malformed',
  now_invalid: 'now_invalid',
  fresh_head_stale: 'fresh_head_stale',
  fresh_head_required_but_absent: 'fresh_head_required_but_absent',
  revoked_by_fresh_head: 'revoked_by_fresh_head',
  max_staleness_invalid: 'max_staleness_invalid',
  fresh_head_within_window: 'fresh_head_within_window',
});

function _currencyHexOf(h) {
  const s = String(h ?? '').replace(/^sha256:/, '').toLowerCase();
  return /^[0-9a-f]{64}$/.test(s) ? s : '';
}

function _headRevokesReceipt(head, receipt) {
  if (head && head.revoked === true) return true;
  const list = head && head.revoked_target_hashes;
  if (Array.isArray(list) && list.length > 0) {
    const targets = new Set(list.map(_currencyHexOf).filter(Boolean));
    if (targets.size === 0) return false;
    const rHash = _currencyHexOf(receipt?.action_hash);
    const eHash = _currencyHexOf(head?.target_hash);
    if (rHash && targets.has(rHash)) return true;
    if (eHash && targets.has(eHash)) return true;
  }
  return false;
}

export function evaluateCurrency(args = {}) {
  const {
    receipt,
    authentic_as_of_commit,
    now,
    maxStalenessSeconds,
    freshHead,
    freshHeadRequired,
  } = (args && typeof args === 'object') ? args : {};

  const authentic = authentic_as_of_commit === true;

  const nowMs = now === undefined
    ? Date.now()
    : instantMs(String(now instanceof Date ? now.toISOString() : now));
  const evaluated_at = Number.isFinite(nowMs) ? new Date(nowMs).toISOString() : null;

  const result = (status, reason) => ({
    authentic_as_of_commit: authentic,
    currency_at_T: { status, evaluated_at, reason },
  });

  if (freshHead === undefined || freshHead === null) {
    if (freshHeadRequired === true) {
      return result('stale', CURRENCY_REASON.fresh_head_required_but_absent);
    }
    return result('unknown', CURRENCY_REASON.offline_only_no_fresh_head);
  }

  if (!Number.isFinite(nowMs)) {
    return result('unknown', CURRENCY_REASON.now_invalid);
  }

  if (typeof freshHead !== 'object') {
    return result('unknown', CURRENCY_REASON.fresh_head_malformed);
  }
  const headMs = instantMs(freshHead.observed_at) ?? instantMs(freshHead.issued_at);
  if (headMs === null) {
    return result('unknown', CURRENCY_REASON.fresh_head_malformed);
  }

  if (typeof maxStalenessSeconds !== 'number'
      || !Number.isFinite(maxStalenessSeconds)
      || maxStalenessSeconds < 0) {
    return result('stale', CURRENCY_REASON.max_staleness_invalid);
  }

  if (_headRevokesReceipt(freshHead, receipt)) {
    return result('stale', CURRENCY_REASON.revoked_by_fresh_head);
  }

  const ageSeconds = (nowMs - headMs) / 1000;
  if (ageSeconds > maxStalenessSeconds) {
    return result('stale', CURRENCY_REASON.fresh_head_stale);
  }

  return result('fresh', CURRENCY_REASON.fresh_head_within_window);
}

// ── EP-INITIATOR-ATTESTATION-v1: structural validation ──────────────────────
// Fail-closed validation of a self-asserted initiator attestation. Enforces a
// closed member set, required fields, well-formed digest, and character cap.

const _IA_VERSION = 'EP-INITIATOR-ATTESTATION-v1';
const _IA_ALLOWED = new Set(['@version', 'model_id', 'model_version', 'tool_chain_digest', 'statement']);
const _IA_REQUIRED_STRINGS = ['model_id', 'model_version'];
const _IA_STATEMENT_MAX = 280;

function _normalizeDigest(h) {
  const s = String(h ?? '').replace(/^sha256:/i, '').toLowerCase();
  return /^[0-9a-f]{64}$/.test(s) ? s : '';
}

const _BIDI_CPS = new Set([
  0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
  0x2066, 0x2067, 0x2068, 0x2069,
  0x200e, 0x200f, 0x061c,
]);
const _INVIS_CPS = new Set([0x200b, 0x200c, 0x200d, 0x2060, 0xfeff]);

function _neutralizeStatement(statement) {
  const raw = typeof statement === 'string' ? statement : '';
  const cps = Array.from(raw);
  const truncated = cps.length > _IA_STATEMENT_MAX;
  const bounded = truncated ? cps.slice(0, _IA_STATEMENT_MAX) : cps;

  const escaped = [];
  let changed = false;
  let hasAscii = false, hasNonAscii = false, hasConfusable = false;

  const out = bounded.map((ch) => {
    const cp = ch.codePointAt(0);
    if (/[A-Za-z]/.test(ch)) hasAscii = true;
    if (cp > 0x7f && /\p{L}/u.test(ch)) hasNonAscii = true;
    if (/[\u0400-\u04ff]/.test(ch) || /[\u0370-\u03ff]/.test(ch)) hasConfusable = true;

    const isBidi = _BIDI_CPS.has(cp);
    const isInvis = _INVIS_CPS.has(cp);
    const isCtrl = (cp <= 0x1f && cp !== 0x09 && cp !== 0x0a && cp !== 0x0d)
      || (cp >= 0x7f && cp <= 0x9f);

    if (isBidi || isInvis || isCtrl) {
      changed = true;
      escaped.push(cp);
      return `<U+${cp.toString(16).toUpperCase().padStart(4, '0')}>`;
    }
    return ch;
  });

  return {
    safe: out.join(''),
    changed,
    homoglyph_risk: hasConfusable || (hasNonAscii && hasAscii),
    escaped_codepoints: escaped,
    truncated,
  };
}

export function validateInitiatorAttestation(att) {
  const errors = [];
  const fail = () => ({ ok: false, normalized: null, errors, statement_report: null });

  if (!att || typeof att !== 'object' || Array.isArray(att)) {
    errors.push('initiator attestation must be a non-array object');
    return fail();
  }

  for (const key of Object.keys(att)) {
    if (!_IA_ALLOWED.has(key)) {
      errors.push(`unknown member "${key}" (allowed: ${[..._IA_ALLOWED].join(', ')})`);
    }
  }

  if (att['@version'] !== undefined && att['@version'] !== _IA_VERSION) {
    errors.push(`@version must be ${_IA_VERSION} when present`);
  }

  for (const key of _IA_REQUIRED_STRINGS) {
    if (typeof att[key] !== 'string' || att[key].length === 0) {
      errors.push(`${key} is required and must be a non-empty string`);
    }
  }

  const digestHex = _normalizeDigest(att.tool_chain_digest);
  if (att.tool_chain_digest === undefined || att.tool_chain_digest === null) {
    errors.push('tool_chain_digest is required');
  } else if (digestHex === '') {
    errors.push('tool_chain_digest must be a well-formed SHA-256 (optionally "sha256:"-prefixed 64-hex)');
  }

  if (att.statement !== undefined) {
    if (typeof att.statement !== 'string') {
      errors.push('statement, when present, must be a string');
    } else if (Array.from(att.statement).length > _IA_STATEMENT_MAX) {
      errors.push(`statement exceeds the ${_IA_STATEMENT_MAX}-character cap`);
    }
  }

  if (errors.length) return fail();

  let statementReport = null;
  if (att.statement !== undefined) {
    statementReport = _neutralizeStatement(att.statement);
  }

  const normalized = {
    '@version': _IA_VERSION,
    model_id: att.model_id,
    model_version: att.model_version,
    tool_chain_digest: `sha256:${digestHex}`,
  };
  if (statementReport) normalized.statement = statementReport.safe;

  return { ok: true, normalized, errors, statement_report: statementReport };
}

// ── EP-SMT-CONSUME-v1: sparse Merkle consumption proof verification ─────────
// Proves a nonce transitioned absent → present exactly once between two
// append-only heads. Uses the same EP-MERKLE-v2 branch hash (0x01 prefix) plus
// distinct 0x02 (present leaf) and 0x03 (default/absent leaf) domain tags.

const _SMT_DEPTH = 32;

function _smtBranch(left, right) {
  return crypto.createHash('sha256')
    .update(Buffer.concat([Buffer.from([0x01]), Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8')]))
    .digest('hex');
}

function _smtPresentLeaf(keyHex, valueHex) {
  return crypto.createHash('sha256')
    .update(Buffer.concat([Buffer.from([0x02]), Buffer.from(keyHex, 'utf8'), Buffer.from(valueHex, 'utf8')]))
    .digest('hex');
}

function _smtDefaultLeaf() {
  return crypto.createHash('sha256').update(Buffer.from([0x03])).digest('hex');
}

function _smtNonceKey(nonce) {
  return crypto.createHash('sha256').update(Buffer.from(String(nonce), 'utf8')).digest('hex');
}

function _smtPathBit(keyHex, i) {
  const byteIdx = i >> 3;
  const byte = parseInt(keyHex.substr(byteIdx * 2, 2), 16);
  return (byte >> (7 - (i & 7))) & 1;
}

function _smtFoldToRoot(leafHex, siblings, keyHex, depth) {
  if (!isHex64(leafHex)) return null;
  if (!Array.isArray(siblings) || siblings.length !== depth) return null;
  let node = leafHex;
  for (let level = depth - 1; level >= 0; level--) {
    const sib = hexOf(siblings[level]);
    if (!isHex64(sib)) return null;
    const bit = _smtPathBit(keyHex, level);
    node = bit === 0 ? _smtBranch(node, sib) : _smtBranch(sib, node);
  }
  return node;
}

function _smtCheckSub(sub, keyHex, label) {
  if (!sub || typeof sub !== 'object') return { ok: false, reason: `${label}_missing` };
  const root = hexOf(sub.root);
  if (!isHex64(root)) return { ok: false, reason: `${label}_root_malformed` };
  if (!Array.isArray(sub.siblings) || sub.siblings.length !== _SMT_DEPTH) {
    return { ok: false, reason: `${label}_siblings_wrong_length` };
  }
  let leaf;
  if (sub.present === true) {
    const val = hexOf(sub.value);
    if (!isHex64(val)) return { ok: false, reason: `${label}_present_value_malformed` };
    leaf = _smtPresentLeaf(keyHex, val);
  } else if (sub.present === false) {
    leaf = _smtDefaultLeaf();
  } else {
    return { ok: false, reason: `${label}_present_flag_missing` };
  }
  const reconstructed = _smtFoldToRoot(leaf, sub.siblings, keyHex, _SMT_DEPTH);
  if (reconstructed === null) return { ok: false, reason: `${label}_sibling_malformed` };
  if (reconstructed !== root) return { ok: false, reason: `${label}_does_not_reconstruct_root` };
  return { ok: true };
}

export function verifyConsumptionProof(bundle) {
  const checks = { non_inclusion: false, inclusion: false, consistency: false };
  const fail = (reason) => ({ valid: false, checks, reason });

  if (!bundle || typeof bundle !== 'object') return fail('bundle_missing');
  if (typeof bundle.nonce !== 'string' || bundle.nonce.length === 0) return fail('nonce_missing');

  const keyHex = _smtNonceKey(bundle.nonce);

  // Non-inclusion at h1: nonce must be absent
  const ni = bundle.non_inclusion_proof;
  if (!ni || typeof ni !== 'object') return fail('non_inclusion_proof_missing');
  if (ni.present !== false) return fail('non_inclusion_proof_must_assert_absent');
  const niRes = _smtCheckSub(ni, keyHex, 'non_inclusion');
  if (!niRes.ok) return fail(niRes.reason);
  checks.non_inclusion = true;

  // Inclusion at h2: nonce must be present
  const inc = bundle.inclusion_proof;
  if (!inc || typeof inc !== 'object') return fail('inclusion_proof_missing');
  if (inc.present !== true) return fail('inclusion_proof_must_assert_present');
  const incRes = _smtCheckSub(inc, keyHex, 'inclusion');
  if (!incRes.ok) return fail(incRes.reason);
  checks.inclusion = true;

  // The two SMT roots must differ (a transition must have occurred)
  if (hexOf(ni.root) === hexOf(inc.root)) return fail('smt_root_unchanged_no_transition');

  // Append-only consistency between h1 and h2 dense-log checkpoints
  const cps = bundle.checkpoints;
  if (!cps || typeof cps !== 'object' || !cps.h1 || !cps.h2) return fail('checkpoints_missing');
  const h1Size = cps.h1.tree_size;
  const h2Size = cps.h2.tree_size;
  const h1Root = hexOf(cps.h1.root_hash);
  const h2Root = hexOf(cps.h2.root_hash);
  if (!Number.isInteger(h1Size) || h1Size < 1 || !isHex64(h1Root)) return fail('checkpoint_h1_malformed');
  if (!Number.isInteger(h2Size) || h2Size < 1 || !isHex64(h2Root)) return fail('checkpoint_h2_malformed');
  if (!(h1Size < h2Size)) return fail('checkpoint_h1_not_before_h2');
  if (!Array.isArray(bundle.consistency_proof)) return fail('consistency_proof_missing');
  if (!verifyCheckpointConsistency(h1Root, h1Size, h2Root, h2Size, bundle.consistency_proof)) {
    return fail('consistency_proof_not_append_only');
  }
  checks.consistency = true;

  return { valid: true, checks, reason: null };
}

// ── EP-WITNESS-v1: witness cosignature quorum verification ──────────────────
// Verifies k-of-n distinct pinned witnesses have cosigned the same checkpoint.
// Domain-separated: witnesses sign SHA-256(DOMAIN_TAG || canonicalize(checkpoint
// without log_signature)), distinct from the log's own signature.

const _WITNESS_DOMAIN_TAG = 'EP-WITNESS-COSIGN-v1\0';

function _witnessDigest(checkpoint) {
  if (!checkpoint || typeof checkpoint !== 'object' || Array.isArray(checkpoint)) return null;
  const signed = { ...checkpoint };
  delete signed.log_signature;
  const preimage = Buffer.concat([
    Buffer.from(_WITNESS_DOMAIN_TAG, 'utf8'),
    Buffer.from(canonicalize(signed), 'utf8'),
  ]);
  return crypto.createHash('sha256').update(preimage).digest();
}

function _verifyOneCosig(checkpoint, cosig, pinned) {
  const refuse = (reason) => ({ verified: false, witness_id: null, reason });

  if (!checkpoint || typeof checkpoint !== 'object' || Array.isArray(checkpoint))
    return refuse('checkpoint is missing or not an object');
  if (!cosig || typeof cosig !== 'object' || Array.isArray(cosig))
    return refuse('cosignature is missing or not an object');
  if (!pinned || typeof pinned !== 'object')
    return refuse('pinnedWitnessKey is missing');

  const pinnedId = pinned.witness_id;
  const pinnedPub = pinned.public_key;
  if (typeof pinnedId !== 'string' || !pinnedId) return refuse('pinnedWitnessKey.witness_id is missing');
  if (typeof pinnedPub !== 'string' || !pinnedPub) return refuse('pinnedWitnessKey.public_key is missing');

  const coId = cosig.witness_id;
  if (typeof coId !== 'string' || !coId) return refuse('cosignature.witness_id is missing');
  if (coId !== pinnedId) return refuse('cosignature witness_id is not the pinned witness (unpinned witness refused)');

  if (cosig.alg !== undefined && cosig.alg !== 'EP-WITNESS-v1')
    return refuse('cosignature alg must be EP-WITNESS-v1 when present');

  if (typeof cosig.signature !== 'string' || !cosig.signature)
    return refuse('cosignature.signature is missing');

  // Echoed fields must match if present
  if (cosig.tree_size !== undefined && cosig.tree_size !== checkpoint.tree_size)
    return refuse('cosignature tree_size does not match the checkpoint (cosignature for a different head)');
  if (cosig.root_hash !== undefined && hexOf(cosig.root_hash) !== hexOf(checkpoint.root_hash))
    return refuse('cosignature root_hash does not match the checkpoint (cosignature for a different head)');
  if (cosig.log_key_id !== undefined && cosig.log_key_id !== checkpoint.log_key_id)
    return refuse('cosignature log_key_id does not match the checkpoint (cosignature for a different log)');

  const digest = _witnessDigest(checkpoint);
  if (digest === null) return refuse('checkpoint could not be canonicalized');

  try {
    const keyObj = crypto.createPublicKey({
      key: Buffer.from(pinnedPub, 'base64url'),
      format: 'der',
      type: 'spki',
    });
    const ok = crypto.verify(null, digest, keyObj, Buffer.from(cosig.signature, 'base64url'));
    if (!ok) return refuse('cosignature does not verify over the checkpoint committed bytes');
    return { verified: true, witness_id: coId };
  } catch (e) {
    return refuse(`cosignature verification failed: ${e.message}`);
  }
}

export function requireWitnessQuorum(checkpoint, cosignatures, pinnedWitnessKeys, k) {
  const reasons = [];
  const empty = { ok: false, met: 0, required: 0, witness_ids: [], reasons };

  if (!Number.isInteger(k) || k < 1) {
    reasons.push('k must be an integer >= 1');
    return { ...empty, required: typeof k === 'number' ? k : 0 };
  }
  empty.required = k;

  if (!checkpoint || typeof checkpoint !== 'object' || Array.isArray(checkpoint)) {
    reasons.push('checkpoint is missing or not an object');
    return { ok: false, met: 0, required: k, witness_ids: [], reasons };
  }
  if (!Array.isArray(cosignatures)) {
    reasons.push('cosignatures must be an array');
    return { ok: false, met: 0, required: k, witness_ids: [], reasons };
  }
  if (!Array.isArray(pinnedWitnessKeys)) {
    reasons.push('pinnedWitnessKeys must be an array');
    return { ok: false, met: 0, required: k, witness_ids: [], reasons };
  }

  // Build pinned directory; drop duplicates as ambiguous
  const pinnedById = new Map();
  const seenPinned = new Set();
  const dupPinned = new Set();
  for (const w of pinnedWitnessKeys) {
    const id = w && typeof w === 'object' ? w.witness_id : undefined;
    if (typeof id !== 'string' || !id) {
      reasons.push('a pinned witness entry is missing witness_id (dropped)');
      continue;
    }
    if (seenPinned.has(id)) { dupPinned.add(id); continue; }
    seenPinned.add(id);
    pinnedById.set(id, w);
  }
  for (const id of dupPinned) {
    pinnedById.delete(id);
    reasons.push(`pinned witness_id "${id}" appears more than once (dropped as ambiguous)`);
  }

  // Count distinct verified witnesses
  const met = new Set();
  for (const cosig of cosignatures) {
    const id = cosig && typeof cosig === 'object' ? cosig.witness_id : undefined;
    if (typeof id !== 'string' || !id) {
      reasons.push('a cosignature is missing witness_id (ignored)');
      continue;
    }
    if (met.has(id)) {
      reasons.push(`duplicate cosignature from witness "${id}" (counted once)`);
      continue;
    }
    const pinned = pinnedById.get(id);
    if (!pinned) {
      reasons.push(`cosignature from unpinned witness "${id}" (ignored)`);
      continue;
    }
    const res = _verifyOneCosig(checkpoint, cosig, pinned);
    if (res.verified) {
      met.add(res.witness_id);
    } else {
      reasons.push(`cosignature from "${id}" did not verify: ${res.reason}`);
    }
  }

  const witness_ids = [...met].sort();
  return { ok: met.size >= k, met: met.size, required: k, witness_ids, reasons };
}

// ── RFC 3161 timestamp-proof verification ───────────────────────────────────
// Minimal DER/CMS parser for RFC 3161 TimeStampToken, verified against pinned
// TSA keys. Supports RSA (PKCS1 v1.5) and ECDSA over SHA-2 digests.

const _OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const _OID_CT_TSTINFO = '1.2.840.113549.1.9.16.1.4';
const _OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';
const _OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const _OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const _OID_SHA384 = '2.16.840.1.101.3.4.2.2';
const _OID_SHA512 = '2.16.840.1.101.3.4.2.3';
const _OID_RSA_ENC = '1.2.840.113549.1.1.1';
const _OID_ECDSA_256 = '1.2.840.10045.4.3.2';
const _OID_ECDSA_384 = '1.2.840.10045.4.3.3';
const _OID_ECDSA_512 = '1.2.840.10045.4.3.4';

const _DIGEST_OID_MAP = {
  [_OID_SHA256]: 'sha256',
  [_OID_SHA384]: 'sha384',
  [_OID_SHA512]: 'sha512',
};

class _DerErr extends Error {}

function _readTLV(buf, offset) {
  if (offset + 2 > buf.length) throw new _DerErr('truncated');
  const first = buf[offset];
  const cls = (first & 0xc0) >> 6;
  const constructed = (first & 0x20) !== 0;
  let tag = first & 0x1f;
  let p = offset + 1;
  if (tag === 0x1f) {
    tag = 0;
    let b;
    do {
      if (p >= buf.length) throw new _DerErr('truncated high tag');
      b = buf[p++];
      tag = (tag << 7) | (b & 0x7f);
    } while (b & 0x80);
  }
  if (p >= buf.length) throw new _DerErr('truncated length');
  let len = buf[p++];
  if (len & 0x80) {
    const numBytes = len & 0x7f;
    if (numBytes === 0 || numBytes > 4) throw new _DerErr('bad length form');
    if (p + numBytes > buf.length) throw new _DerErr('truncated length');
    len = 0;
    for (let i = 0; i < numBytes; i++) len = (len << 8) | buf[p++];
  }
  const contentStart = p;
  const contentEnd = p + len;
  if (contentEnd > buf.length) throw new _DerErr('content exceeds buffer');
  return { cls, constructed, tag, headerLen: contentStart - offset, contentStart, contentEnd, buf };
}

function* _derChildren(node) {
  let p = node.contentStart;
  while (p < node.contentEnd) {
    const child = _readTLV(node.buf, p);
    yield child;
    p = child.contentEnd;
  }
}

function _derContent(node) { return node.buf.subarray(node.contentStart, node.contentEnd); }
function _derRaw(node) { return node.buf.subarray(node.contentStart - node.headerLen, node.contentEnd); }

function _decodeOID(node) {
  if (node.tag !== 0x06 || node.cls !== 0) throw new _DerErr('expected OID');
  const b = _derContent(node);
  if (b.length === 0) throw new _DerErr('empty OID');
  const parts = [Math.floor(b[0] / 40), b[0] % 40];
  let val = 0;
  for (let i = 1; i < b.length; i++) {
    val = (val << 7) | (b[i] & 0x7f);
    if (!(b[i] & 0x80)) { parts.push(val); val = 0; }
  }
  return parts.join('.');
}

function _decodeGenTime(node) {
  const s = _derContent(node).toString('latin1');
  let m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$/.exec(s);
  if (node.tag === 0x18 && m) {
    const frac = m[7] || '';
    const iso = `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${frac}Z`;
    const ms = Date.parse(iso);
    return Number.isNaN(ms) ? null : { iso, ms };
  }
  m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
  if (node.tag === 0x17 && m) {
    const yy = parseInt(m[1], 10);
    const year = yy < 50 ? 2000 + yy : 1900 + yy;
    const iso = `${year}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z`;
    const ms = Date.parse(iso);
    return Number.isNaN(ms) ? null : { iso, ms };
  }
  return null;
}

function _tsHexOf(h) {
  if (Buffer.isBuffer(h)) return h.toString('hex').toLowerCase();
  const s = String(h ?? '').replace(/^sha256:/i, '').replace(/^sha384:/i, '').replace(/^sha512:/i, '').toLowerCase();
  return /^[0-9a-f]+$/.test(s) && s.length % 2 === 0 && s.length >= 40 ? s : '';
}

function _loadTsaKey(pinned) {
  try {
    if (!pinned) return null;
    if (typeof pinned === 'string' && pinned.includes('-----BEGIN')) {
      const key = crypto.createPublicKey(pinned);
      return { key, spkiDer: key.export({ type: 'spki', format: 'der' }) };
    }
    const der = Buffer.from(String(pinned).replace(/\s+/g, ''), 'base64');
    if (der.length === 0) return null;
    const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    return { key, spkiDer: key.export({ type: 'spki', format: 'der' }) };
  } catch { return null; }
}

function _resolveSigAlg(oid, digestName, keyType) {
  if (oid === _OID_RSA_ENC || keyType === 'rsa') return digestName ? { hash: digestName } : null;
  if (oid === _OID_ECDSA_256) return { hash: 'sha256', dsaEncoding: 'der' };
  if (oid === _OID_ECDSA_384) return { hash: 'sha384', dsaEncoding: 'der' };
  if (oid === _OID_ECDSA_512) return { hash: 'sha512', dsaEncoding: 'der' };
  return null;
}

function _parseTstInfo(der) {
  try {
    const seq = _readTLV(der, 0);
    if (seq.tag !== 0x10) return { error: 'unparseable_token' };
    const kids = [..._derChildren(seq)];
    if (kids.length < 5) return { error: 'unparseable_token' };
    const mi = kids[2];
    if (mi.tag !== 0x10) return { error: 'unparseable_token' };
    const miKids = [..._derChildren(mi)];
    if (miKids.length < 2) return { error: 'unparseable_token' };
    const hashAlgOid = _decodeOID([..._derChildren(miKids[0])][0]);
    if (miKids[1].tag !== 0x04) return { error: 'unparseable_token' };
    const messageImprintHex = _derContent(miKids[1]).toString('hex').toLowerCase();
    let genTime = null;
    for (let i = 3; i < kids.length; i++) {
      if (kids[i].tag === 0x18 || kids[i].tag === 0x17) {
        const t = _decodeGenTime(kids[i]);
        if (t) genTime = t.iso;
        break;
      }
    }
    return { messageImprintHex, imprintAlgOid: hashAlgOid, genTime };
  } catch { return { error: 'unparseable_token' }; }
}

function _parseSignerInfo(node) {
  try {
    if (node.tag !== 0x10) return { error: 'unparseable_token' };
    const kids = [..._derChildren(node)];
    let idx = 0;
    const version = kids[idx++];
    if (!version || version.tag !== 0x02) return { error: 'unparseable_token' };
    idx++; // sid
    const digestAlg = kids[idx++];
    if (!digestAlg || digestAlg.tag !== 0x10) return { error: 'unparseable_token' };
    const digestAlgOid = _decodeOID([..._derChildren(digestAlg)][0]);

    let signedAttrs = null;
    if (kids[idx] && kids[idx].cls === 2 && kids[idx].tag === 0 && kids[idx].constructed) {
      signedAttrs = kids[idx++];
    }
    const sigAlg = kids[idx++];
    if (!sigAlg || sigAlg.tag !== 0x10) return { error: 'unparseable_token' };
    const sigAlgOid = _decodeOID([..._derChildren(sigAlg)][0]);
    const sigOctet = kids[idx++];
    if (!sigOctet || sigOctet.tag !== 0x04) return { error: 'unparseable_token' };

    return {
      digestAlgOid,
      digestName: _DIGEST_OID_MAP[digestAlgOid] || null,
      signedAttrs,
      sigAlgOid,
      signature: _derContent(sigOctet),
    };
  } catch { return { error: 'unparseable_token' }; }
}

function _parseAttrs(setNode) {
  const out = {};
  for (const attr of _derChildren(setNode)) {
    if (attr.tag !== 0x10) continue;
    const kids = [..._derChildren(attr)];
    if (kids.length < 2) continue;
    const oid = _decodeOID(kids[0]);
    out[oid] = [..._derChildren(kids[1])];
  }
  return out;
}

function _derSetHeader(len) {
  if (len < 0x80) return Buffer.from([0x31, len]);
  const bytes = [];
  let n = len;
  while (n > 0) { bytes.unshift(n & 0xff); n >>= 8; }
  return Buffer.from([0x31, 0x80 | bytes.length, ...bytes]);
}

function _parseTimestampToken(der) {
  const ci = _readTLV(der, 0);
  if (ci.tag !== 0x10 || !ci.constructed) return { error: 'unparseable_token' };
  const ciKids = [..._derChildren(ci)];
  if (ciKids.length < 2) return { error: 'unparseable_token' };
  if (_decodeOID(ciKids[0]) !== _OID_SIGNED_DATA) return { error: 'not_signed_data' };
  const explicit0 = ciKids[1];
  if (explicit0.cls !== 2 || explicit0.tag !== 0 || !explicit0.constructed) return { error: 'unparseable_token' };
  const signedData = [..._derChildren(explicit0)][0];
  if (!signedData || signedData.tag !== 0x10) return { error: 'unparseable_token' };

  const sdKids = [..._derChildren(signedData)];
  if (sdKids.length < 4) return { error: 'unparseable_token' };
  const encap = sdKids[2];
  let signerInfos = null;
  for (let i = sdKids.length - 1; i >= 3; i--) {
    if (sdKids[i].tag === 0x11 && sdKids[i].cls === 0) { signerInfos = sdKids[i]; break; }
  }
  if (!encap || encap.tag !== 0x10) return { error: 'unparseable_token' };
  if (!signerInfos) return { error: 'unparseable_token' };

  const encapKids = [..._derChildren(encap)];
  if (encapKids.length < 2) return { error: 'unparseable_token' };
  if (_decodeOID(encapKids[0]) !== _OID_CT_TSTINFO) return { error: 'not_a_timestamp_token' };
  const eContentExplicit = encapKids[1];
  if (eContentExplicit.cls !== 2 || eContentExplicit.tag !== 0) return { error: 'unparseable_token' };
  const octet = [..._derChildren(eContentExplicit)][0];
  if (!octet || octet.tag !== 0x04) return { error: 'unparseable_token' };
  const eContentRaw = _derContent(octet);

  const tstInfo = _parseTstInfo(eContentRaw);
  if (tstInfo.error) return { error: tstInfo.error };

  const siList = [..._derChildren(signerInfos)];
  if (siList.length !== 1) return { error: 'unsupported_signerinfo_count' };
  const signerInfo = _parseSignerInfo(siList[0]);
  if (signerInfo.error) return { error: signerInfo.error };

  return { tstInfo, signerInfo, eContentRaw };
}

function _verifySigner(signerInfo, eContentRaw, loadedKeys) {
  const { digestName, signedAttrs, sigAlgOid, signature } = signerInfo;
  if (!digestName) return { ok: false, reason: 'unsupported_digest_algorithm' };

  let signedBytes;
  if (signedAttrs) {
    const attrs = _parseAttrs(signedAttrs);
    const ctNodes = attrs[_OID_CONTENT_TYPE];
    if (!ctNodes || ctNodes.length !== 1) return { ok: false, reason: 'missing_content_type_attr' };
    let ctOid;
    try { ctOid = _decodeOID(ctNodes[0]); } catch { return { ok: false, reason: 'unparseable_token' }; }
    if (ctOid !== _OID_CT_TSTINFO) return { ok: false, reason: 'content_type_attr_mismatch' };

    const mdNodes = attrs[_OID_MESSAGE_DIGEST];
    if (!mdNodes || mdNodes.length !== 1 || mdNodes[0].tag !== 0x04)
      return { ok: false, reason: 'missing_message_digest_attr' };
    const attrDigest = _derContent(mdNodes[0]);
    const eContentDigest = crypto.createHash(digestName).update(eContentRaw).digest();
    if (!attrDigest.equals(eContentDigest))
      return { ok: false, reason: 'message_digest_attr_mismatch' };

    // Re-encode attributes as explicit SET (0x31) per RFC 5652 §5.4
    const attrsBody = _derRaw(signedAttrs).subarray(signedAttrs.headerLen);
    signedBytes = Buffer.concat([_derSetHeader(attrsBody.length), attrsBody]);
  } else {
    signedBytes = eContentRaw;
  }

  for (const { key, spkiDer } of loadedKeys) {
    const keyType = key.asymmetricKeyType;
    const alg = _resolveSigAlg(sigAlgOid, digestName, keyType);
    if (!alg) continue;
    if (sigAlgOid === _OID_RSA_ENC && keyType !== 'rsa') continue;
    if ((sigAlgOid === _OID_ECDSA_256 || sigAlgOid === _OID_ECDSA_384 || sigAlgOid === _OID_ECDSA_512) && keyType !== 'ec') continue;
    try {
      const opts = { key };
      if (alg.dsaEncoding) opts.dsaEncoding = alg.dsaEncoding;
      const ok = crypto.verify(alg.hash, signedBytes, opts, signature);
      if (ok) return { ok: true, tsaKeyId: 'sha256:' + crypto.createHash('sha256').update(spkiDer).digest('hex') };
    } catch { /* try next */ }
  }
  return { ok: false, reason: 'bad_signature' };
}

export function verifyTimestampProof(timestampProof, expectedDigest, pinnedTsaKeys) {
  const refuse = (reason) => ({ verified: false, tsa_key_id: null, gen_time: null, reason });

  if (timestampProof === undefined || timestampProof === null
    || (typeof timestampProof !== 'string' && !Buffer.isBuffer(timestampProof))
    || (typeof timestampProof === 'string' && timestampProof.trim() === '')) {
    return refuse('missing_token');
  }
  const wantDigest = _tsHexOf(expectedDigest);
  if (!wantDigest) return refuse('missing_or_malformed_expected_digest');

  // Build pinned key set
  const pinnedList = [];
  if (Array.isArray(pinnedTsaKeys)) pinnedList.push(...pinnedTsaKeys);
  else if (pinnedTsaKeys && typeof pinnedTsaKeys === 'object') pinnedList.push(...Object.values(pinnedTsaKeys));
  else if (pinnedTsaKeys) pinnedList.push(pinnedTsaKeys);
  const loadedKeys = pinnedList.map(_loadTsaKey).filter(Boolean);
  if (loadedKeys.length === 0) return refuse('unpinned_tsa');

  let der;
  try {
    der = Buffer.isBuffer(timestampProof)
      ? timestampProof
      : Buffer.from(timestampProof.replace(/\s+/g, ''), 'base64');
    if (der.length === 0) return refuse('unparseable_token');
  } catch { return refuse('unparseable_token'); }

  let parsed;
  try { parsed = _parseTimestampToken(der); } catch { return refuse('unparseable_token'); }
  if (parsed.error) return refuse(parsed.error);

  const { tstInfo, signerInfo, eContentRaw } = parsed;

  if (tstInfo.messageImprintHex !== wantDigest) return refuse('digest_mismatch');
  if (!tstInfo.genTime) return refuse('unparseable_token');

  const sigResult = _verifySigner(signerInfo, eContentRaw, loadedKeys);
  if (!sigResult.ok) return refuse(sigResult.reason);

  return { verified: true, tsa_key_id: sigResult.tsaKeyId, gen_time: tstInfo.genTime };
}

