/**
 * @emilia-protocol/require-receipt — the demand side of the network.
 * @license Apache-2.0
 *
 * One line that lets ANY service refuse an irreversible agent action unless it
 * arrives with a verifiable EMILIA Trust Receipt — proof that a named human
 * accountably authorized this exact action. This is NOT auth ("who are you")
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

function canonicalize(v) {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  if (typeof v === 'object') return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`;
  return JSON.stringify(v);
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
 * @param {string[]} [opts.allowedOutcomes] acceptable claim.outcome values
 * @returns {{ok:boolean, reason?:string, outcome?:string, subject?:string, receipt_id?:string, signer?:string}}
 */
export function verifyEmiliaReceipt(doc, opts = {}) {
  const { trustedKeys = [], allowInlineKey = false, action = null, maxAgeSec = 900,
    allowedOutcomes = ['allow', 'allow_with_signoff'] } = opts;

  if (!doc || doc['@version'] !== 'EP-RECEIPT-v1' || !doc.payload || !doc.signature?.value) {
    return { ok: false, reason: 'malformed_receipt' };
  }
  const payload = doc.payload;

  const candidates = [...trustedKeys];
  if (allowInlineKey && doc.public_key) candidates.push(doc.public_key);
  if (candidates.length === 0) return { ok: false, reason: 'no_trusted_keys_configured' };

  const data = Buffer.from(canonicalize(payload), 'utf8');
  let sig;
  try { sig = Buffer.from(doc.signature.value, 'base64url'); } catch { return { ok: false, reason: 'bad_signature_encoding' }; }

  let signer = null;
  for (const k of candidates) {
    try {
      const pub = crypto.createPublicKey({ key: Buffer.from(k, 'base64url'), format: 'der', type: 'spki' });
      if (crypto.verify(null, data, pub, sig)) { signer = k; break; }
    } catch { /* try next key */ }
  }
  if (!signer) return { ok: false, reason: 'untrusted_or_invalid_signature' };

  if (maxAgeSec && payload.created_at) {
    const ageSec = (Date.now() - Date.parse(payload.created_at)) / 1000;
    if (Number.isFinite(ageSec) && ageSec > maxAgeSec) return { ok: false, reason: 'receipt_expired' };
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
    if (action.assurance_class && !['software', 'class_a', 'quorum'].includes(action.assurance_class)) {
      errors.push(`${p}.assurance_class must be software, class_a, or quorum`);
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
    if (hdr) { try { doc = JSON.parse(Buffer.from(hdr, 'base64').toString('utf8')); } catch { /* fallthrough */ } }
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
 * @param {()=>(object|Promise<object>)} p.issueReceipt  mints a FRESH valid
 *   EP-RECEIPT-v1 bound to `action` that this dispatcher accepts
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
