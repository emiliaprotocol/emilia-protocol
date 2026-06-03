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
 * When the receipt is missing, the service answers `402` and tells the agent
 * exactly what to bring — so a well-behaved agent obtains one and retries on its
 * own (like a browser handling 401). The receipt becomes the passport.
 *
 * Verification is offline Ed25519 over canonical JSON — same shape as
 * @emilia-protocol/verify. Zero network. Pin the issuer keys you trust.
 */
import crypto from 'node:crypto';

function canonicalize(v) {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  if (typeof v === 'object') return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`;
  return JSON.stringify(v);
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

/** Build the 402 challenge body that tells an agent exactly what to bring. */
export function receiptChallenge(action, reason) {
  return {
    type: 'https://emiliaprotocol.ai/errors/emilia_receipt_required',
    title: 'EMILIA Receipt Required',
    status: 402,
    detail: reason || 'This action requires an accountable, verifiable authorization receipt.',
    required: {
      action: action || null,
      header: 'X-EMILIA-Receipt: base64(<EP-RECEIPT-v1 JSON>)',
      how: 'Obtain a receipt (run emilia-gate, the SDK, or POST /api/trust/gate), then resend with the header.',
      learn_more: 'https://www.emiliaprotocol.ai/agent-guard',
    },
  };
}

/**
 * Express/Connect middleware: demand a valid EMILIA receipt for the route.
 * @param {object} opts verify options + { action?: string | (req)=>string }
 */
export function requireEmiliaReceipt(opts = {}) {
  return function emiliaReceiptGate(req, res, next) {
    const action = typeof opts.action === 'function' ? opts.action(req) : opts.action;
    let doc = null;
    const hdr = req.headers?.['x-emilia-receipt'];
    if (hdr) { try { doc = JSON.parse(Buffer.from(hdr, 'base64').toString('utf8')); } catch { /* fallthrough */ } }
    if (!doc && req.body && req.body.emilia_receipt) doc = req.body.emilia_receipt;

    if (!doc) {
      res.setHeader('WWW-Authenticate', `EMILIA realm="agent-actions"${action ? `, action="${action}"` : ''}`);
      return res.status(402).json(receiptChallenge(action, 'No EMILIA receipt presented.'));
    }
    const v = verifyEmiliaReceipt(doc, { ...opts, action });
    if (!v.ok) {
      res.setHeader('WWW-Authenticate', `EMILIA realm="agent-actions"${action ? `, action="${action}"` : ''}`);
      return res.status(402).json({ ...receiptChallenge(action, `Receipt rejected: ${v.reason}.`), rejected: v });
    }
    req.emiliaReceipt = v;
    return next();
  };
}

export default { verifyEmiliaReceipt, requireEmiliaReceipt, receiptChallenge };
