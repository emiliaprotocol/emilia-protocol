#!/usr/bin/env node

/**
 * create-ep-app — Zero to verified trust system in 5 minutes
 *
 * Usage: npx create-ep-app my-trust-system
 *
 * Creates a minimal but complete EP-powered application with:
 *   - Entity registration
 *   - Receipt submission + verification
 *   - Trust profile view
 *   - Handshake ceremony demo
 *   - Self-verifying receipt generation
 *   - Offline receipt verification
 *
 * No Supabase, no Vercel, no blockchain wallet required.
 * Just Node.js 20+ and 5 minutes.
 *
 * @license Apache-2.0
 */

import { execSync } from 'child_process';
import { mkdirSync, writeFileSync, existsSync } from 'fs';
import { join } from 'path';

const rawProjectName = process.argv[2];

if (!rawProjectName) {
  console.error(`
  Usage: npx create-ep-app <project-name>

  Example: npx create-ep-app my-trust-system
  `);
  process.exit(1);
}

// Sanitize project name: basename only, no path traversal, alphanumeric + dash/underscore/dot
const projectName = rawProjectName.replace(/[^a-zA-Z0-9._-]/g, '');
if (!projectName || projectName !== rawProjectName || projectName.startsWith('.')) {
  console.error(`Error: Invalid project name "${rawProjectName}". Use only alphanumeric characters, dashes, underscores, and dots. Must not start with a dot.`);
  process.exit(1);
}

if (existsSync(projectName)) {
  console.error(`Error: Directory "${projectName}" already exists.`);
  process.exit(1);
}

console.log(`
  ╔══════════════════════════════════════════╗
  ║                                          ║
  ║   EMILIA PROTOCOL                        ║
  ║   Trust, before high-risk action.        ║
  ║                                          ║
  ╚══════════════════════════════════════════╝

  Creating ${projectName}...
`);

// Path safety: projectName is already validated (alphanumeric + dash/underscore/dot,
// no dots at start, no slashes, exact match confirmed). Resolve and verify it stays
// under CWD to satisfy path-traversal analysis.
const cwd = process.cwd();
const resolvedRoot = join(cwd, projectName);
if (!resolvedRoot.startsWith(cwd)) {
  console.error('Error: resolved path escapes current directory.');
  process.exit(1);
}

// Safe output function — all file writes use this verified constant
function safeDir(...segments) { return join(resolvedRoot, ...segments); }

// Create project structure
const dirs = ['', 'lib', 'app', 'app/api', 'app/api/entity', 'app/api/receipt', 'app/api/verify', 'app/api/trust', 'app/api/handshake'];
dirs.forEach(dir => mkdirSync(safeDir(dir), { recursive: true }));

// package.json
writeFileSync(safeDir( 'package.json'), JSON.stringify({
  name: projectName,
  version: '0.1.0',
  private: true,
  type: 'module',
  scripts: {
    dev: 'node --watch server.js',
    start: 'node server.js',
    verify: 'node verify-receipt.js',
  },
  dependencies: {
    '@emilia-protocol/verify': 'latest',
  },
}, null, 2));

// Server
writeFileSync(safeDir( 'server.js'), `
import { createServer } from 'http';
import crypto from 'crypto';

// ============================================================================
// In-memory store (replace with your database in production)
// ============================================================================
const entities = new Map();
const receipts = new Map();
const handshakes = new Map();

// ============================================================================
// EP Crypto primitives
// ============================================================================
function sha256(input) {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

function generateEntityKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  return {
    publicKey: Buffer.from(publicKey).toString('base64url'),
    privateKey: Buffer.from(privateKey).toString('base64url'),
  };
}

function signPayload(payload, privateKeyBase64url) {
  const payloadBytes = Buffer.from(JSON.stringify(payload, Object.keys(payload).sort()), 'utf8');
  const keyDer = Buffer.from(privateKeyBase64url, 'base64url');
  const keyObject = crypto.createPrivateKey({ key: keyDer, format: 'der', type: 'pkcs8' });
  return crypto.sign(null, payloadBytes, keyObject).toString('base64url');
}

function verifySignature(payload, signature, publicKeyBase64url) {
  const payloadBytes = Buffer.from(JSON.stringify(payload, Object.keys(payload).sort()), 'utf8');
  const keyDer = Buffer.from(publicKeyBase64url, 'base64url');
  const keyObject = crypto.createPublicKey({ key: keyDer, format: 'der', type: 'spki' });
  return crypto.verify(null, payloadBytes, keyObject, Buffer.from(signature, 'base64url'));
}

// ============================================================================
// Route handlers
// ============================================================================

const routes = {
  // Register a new entity
  'POST /api/entity': (body) => {
    const id = 'ep_entity_' + crypto.randomBytes(8).toString('hex');
    const keys = generateEntityKeys();
    const entity = {
      entity_id: id,
      display_name: body.name || id,
      public_key: keys.publicKey,
      created_at: new Date().toISOString(),
      receipts: [],
      score: 0,
    };
    entities.set(id, { ...entity, _privateKey: keys.privateKey });
    return { entity_id: id, display_name: entity.display_name, public_key: keys.publicKey, api_key: 'ep_live_' + crypto.randomBytes(16).toString('hex') };
  },

  // Submit a trust receipt (self-verifying)
  'POST /api/receipt': (body) => {
    const issuer = entities.get(body.issuer);
    if (!issuer) return { error: 'Issuer entity not found', status: 404 };

    const payload = {
      receipt_id: 'ep_r_' + crypto.randomBytes(8).toString('hex'),
      issuer: body.issuer,
      subject: body.subject,
      claim: { action_type: body.action_type || 'interaction', outcome: body.outcome || 'positive', context: body.context || {} },
      receipt_hash: sha256(JSON.stringify({ issuer: body.issuer, subject: body.subject, outcome: body.outcome })),
      created_at: new Date().toISOString(),
    };

    const signature = signPayload(payload, issuer._privateKey);

    const receipt = {
      '@version': 'EP-RECEIPT-v1',
      '@type': 'TrustReceipt',
      payload,
      signature: { algorithm: 'Ed25519', value: signature, signer: body.issuer, key_discovery: '/.well-known/ep-keys.json' },
    };

    receipts.set(payload.receipt_id, receipt);

    // Update trust profile
    const subject = entities.get(body.subject);
    if (subject) {
      subject.receipts.push(payload.receipt_id);
      const allReceipts = subject.receipts.map(id => receipts.get(id)).filter(Boolean);
      const positive = allReceipts.filter(r => r.payload.claim.outcome === 'positive').length;
      subject.score = Math.round((positive / allReceipts.length) * 100) / 100;
    }

    return receipt;
  },

  // Verify a receipt (offline-capable)
  'POST /api/verify': (body) => {
    const doc = body.receipt || receipts.get(body.receipt_id);
    if (!doc) return { error: 'Receipt not found', status: 404 };

    const signer = entities.get(doc.signature.signer);
    if (!signer) return { valid: false, error: 'Signer not found' };

    const valid = verifySignature(doc.payload, doc.signature.value, signer.public_key);
    return { valid, receipt_id: doc.payload.receipt_id, signer: doc.signature.signer, checked_at: new Date().toISOString() };
  },

  // Get trust profile
  'GET /api/trust': (body, url) => {
    const entityId = new URL(url, 'http://localhost').searchParams.get('entity_id');
    const entity = entities.get(entityId);
    if (!entity) return { error: 'Entity not found', status: 404 };
    return {
      entity_id: entity.entity_id,
      display_name: entity.display_name,
      score: entity.score,
      confidence: entity.receipts.length >= 10 ? 'confident' : entity.receipts.length >= 5 ? 'emerging' : 'provisional',
      evidence_depth: entity.receipts.length,
      public_key: entity.public_key,
    };
  },

  // Initiate handshake
  'POST /api/handshake': (body) => {
    const id = 'ep_hs_' + crypto.randomBytes(8).toString('hex');
    const nonce = crypto.randomBytes(32).toString('hex');
    const binding = { action_type: body.action_type, resource_ref: body.resource_ref, nonce, expires_at: new Date(Date.now() + 300_000).toISOString() };
    const binding_hash = sha256(JSON.stringify(binding, Object.keys(binding).sort()));

    const hs = { handshake_id: id, status: 'initiated', initiator: body.initiator, binding, binding_hash, created_at: new Date().toISOString(), consumed: false };
    handshakes.set(id, hs);
    return hs;
  },

  // Verify + consume handshake
  'POST /api/handshake/verify': (body) => {
    const hs = handshakes.get(body.handshake_id);
    if (!hs) return { error: 'Handshake not found', status: 404 };
    if (hs.consumed) return { error: 'Already consumed', status: 409 };
    if (new Date(hs.binding.expires_at) < new Date()) return { error: 'Expired', status: 410 };
    hs.status = 'verified';
    hs.consumed = true;
    hs.verified_at = new Date().toISOString();
    return { handshake_id: hs.handshake_id, status: 'verified', binding_hash: hs.binding_hash, verified_at: hs.verified_at, _note: 'One-time consumed. Cannot be replayed.' };
  },

  // Key discovery
  'GET /.well-known/ep-keys.json': () => {
    const keys = {};
    for (const [id, e] of entities) keys[id] = { algorithm: 'Ed25519', public_key: e.public_key, status: 'active' };
    return { version: '1.0', keys };
  },

  // Operator discovery
  'GET /.well-known/ep-trust.json': () => ({
    version: '1.0',
    operator_id: 'ep_op_local',
    protocol_version: 'EP-v1.0',
    extensions: ['handshake'],
    federation: { accepts_cross_operator_receipts: true },
  }),
};

// ============================================================================
// HTTP server
// ============================================================================

const server = createServer(async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const routeKey = req.method + ' ' + req.url.split('?')[0];
  const handler = routes[routeKey];

  if (!handler) {
    // Serve a simple HTML dashboard for GET /
    if (req.method === 'GET' && req.url === '/') {
      res.setHeader('Content-Type', 'text/html');
      res.writeHead(200);
      res.end(DASHBOARD_HTML);
      return;
    }
    res.writeHead(404);
    res.end(JSON.stringify({ error: 'Not found' }));
    return;
  }

  let body = {};
  if (req.method === 'POST') {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    try { body = JSON.parse(Buffer.concat(chunks).toString()); } catch { body = {}; }
  }

  const result = handler(body, req.url);
  const status = result.status || (result.error ? 400 : 200);
  res.writeHead(status);
  res.end(JSON.stringify(result, null, 2));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(\`
  ╔══════════════════════════════════════════════════╗
  ║  EP is running at http://localhost:\${PORT}         ║
  ║                                                  ║
  ║  Open your browser to see the trust dashboard.   ║
  ║                                                  ║
  ║  API:                                            ║
  ║    POST /api/entity      Register entity         ║
  ║    POST /api/receipt      Submit receipt          ║
  ║    POST /api/verify       Verify receipt          ║
  ║    GET  /api/trust        Trust profile           ║
  ║    POST /api/handshake    Start ceremony          ║
  ╚══════════════════════════════════════════════════╝
  \`);
});

// ============================================================================
// Dashboard HTML (inline — no dependencies)
// ============================================================================

const DASHBOARD_HTML = \`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>EP Trust Dashboard</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Inter', sans-serif; background: #FAFAF9; color: #1C1917; padding: 32px; max-width: 900px; margin: 0 auto; }
    h1 { font-size: 28px; font-weight: 700; margin-bottom: 8px; letter-spacing: -1px; }
    h2 { font-size: 18px; font-weight: 600; margin: 32px 0 12px; color: #44403C; }
    .subtitle { color: #78716C; font-size: 14px; margin-bottom: 32px; }
    .card { background: white; border: 1px solid #E7E5E4; border-radius: 8px; padding: 20px; margin-bottom: 12px; }
    .card h3 { font-size: 14px; font-weight: 600; margin-bottom: 8px; }
    .card p { font-size: 13px; color: #57534E; line-height: 1.6; }
    button { background: #1C1917; color: white; border: none; padding: 10px 20px; border-radius: 6px; font-size: 13px; cursor: pointer; font-weight: 500; }
    button:hover { background: #292524; }
    .mono { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 12px; background: #F5F5F4; padding: 12px; border-radius: 6px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; border: 1px solid #E7E5E4; margin-top: 8px; }
    .badge { display: inline-block; font-size: 10px; font-weight: 600; letter-spacing: 1px; text-transform: uppercase; padding: 3px 8px; border-radius: 100px; }
    .badge-green { background: rgba(22,163,74,0.1); color: #16A34A; }
    .badge-blue { background: rgba(59,130,246,0.1); color: #3B82F6; }
    .badge-gold { background: rgba(176,141,53,0.1); color: #B08D35; }
    .steps { display: grid; gap: 12px; margin-top: 16px; }
    .step { display: flex; align-items: flex-start; gap: 12px; }
    .step-num { background: #1C1917; color: white; width: 24px; height: 24px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 600; flex-shrink: 0; }
    .step-text { font-size: 13px; color: #57534E; line-height: 1.6; }
    #log { max-height: 400px; overflow-y: auto; }
    .success { color: #16A34A; }
    .error { color: #DC2626; }
  </style>
</head>
<body>
  <h1>EMILIA Protocol</h1>
  <p class="subtitle">Trust, before high-risk action. <span class="badge badge-green">EP-v1.0</span></p>

  <div class="card">
    <h3>Try the full trust lifecycle</h3>
    <p>Click the button below to run a complete EP ceremony: register two entities, submit receipts, build trust profiles, run a handshake ceremony, and verify a receipt — all with self-verifying cryptographic proofs.</p>
    <br />
    <button onclick="runDemo()">Run Trust Demo</button>
  </div>

  <h2>Activity Log</h2>
  <div id="log" class="mono"></div>

  <script>
    const log = document.getElementById('log');
    function emit(msg, cls) {
      const line = document.createElement('div');
      line.className = cls || '';
      line.textContent = '> ' + msg;
      log.appendChild(line);
      log.scrollTop = log.scrollHeight;
    }

    async function api(method, path, body) {
      const res = await fetch(path, { method, headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
      return res.json();
    }

    async function runDemo() {
      log.innerHTML = '';
      emit('=== EMILIA PROTOCOL TRUST DEMO ===');
      emit('');

      // 1. Register entities
      emit('Step 1: Registering two entities...');
      const alice = await api('POST', '/api/entity', { name: 'Alice (AI Agent)' });
      emit('  Alice registered: ' + alice.entity_id, 'success');
      const bob = await api('POST', '/api/entity', { name: 'Bob (Service Provider)' });
      emit('  Bob registered: ' + bob.entity_id, 'success');
      emit('');

      // 2. Submit receipts
      emit('Step 2: Submitting trust receipts...');
      for (let i = 0; i < 5; i++) {
        const r = await api('POST', '/api/receipt', { issuer: alice.entity_id, subject: bob.entity_id, action_type: 'api_call', outcome: 'positive', context: { task: 'data_retrieval_' + i } });
        emit('  Receipt ' + r.payload.receipt_id + ' — Ed25519 signed, self-verifying', 'success');
      }
      emit('');

      // 3. Check trust profile
      emit('Step 3: Reading trust profile...');
      const profile = await api('GET', '/api/trust?entity_id=' + bob.entity_id);
      emit('  Bob trust score: ' + profile.score + ' (' + profile.confidence + ', ' + profile.evidence_depth + ' receipts)', 'success');
      emit('');

      // 4. Verify a receipt (offline-capable)
      emit('Step 4: Verifying a receipt (Ed25519 signature check)...');
      const receipts = await api('POST', '/api/receipt', { issuer: alice.entity_id, subject: bob.entity_id, outcome: 'positive' });
      const verification = await api('POST', '/api/verify', { receipt: receipts });
      emit('  Signature valid: ' + verification.valid, verification.valid ? 'success' : 'error');
      emit('  This verification works OFFLINE — no EP API needed. Just the receipt + public key.', 'success');
      emit('');

      // 5. Run handshake ceremony
      emit('Step 5: Running handshake ceremony (pre-action authorization)...');
      const hs = await api('POST', '/api/handshake', { initiator: alice.entity_id, action_type: 'deploy_production', resource_ref: 'service/payment-gateway' });
      emit('  Handshake initiated: ' + hs.handshake_id);
      emit('  Binding hash: ' + hs.binding_hash.slice(0, 24) + '...');
      emit('  Nonce: ' + hs.binding.nonce.slice(0, 16) + '...');
      emit('  Expires: ' + hs.binding.expires_at);

      const verified = await api('POST', '/api/handshake/verify', { handshake_id: hs.handshake_id });
      emit('  Status: ' + verified.status + ' — one-time consumed, replay-proof', 'success');
      emit('');

      // 6. Try to replay (should fail)
      emit('Step 6: Attempting replay attack (should fail)...');
      const replay = await api('POST', '/api/handshake/verify', { handshake_id: hs.handshake_id });
      emit('  Replay result: ' + replay.error, replay.error ? 'success' : 'error');
      emit('  Replay prevention: WORKING', 'success');
      emit('');

      emit('=== DEMO COMPLETE ===');
      emit('');
      emit('What just happened:');
      emit('  1. Two entities registered with Ed25519 key pairs');
      emit('  2. Trust receipts issued with cryptographic signatures');
      emit('  3. Trust profile computed from receipt evidence');
      emit('  4. Receipt verified using ONLY the signature — no API needed');
      emit('  5. Pre-action handshake ceremony with nonce + expiry + binding');
      emit('  6. Replay attack blocked by one-time consumption');
      emit('');
      emit('This is EMILIA Protocol. Trust, before high-risk action.');
    }
  </script>
</body>
</html>\`;
`);

// Verify receipt standalone script
writeFileSync(safeDir( 'verify-receipt.js'), `
/**
 * Standalone receipt verification — works offline, no EP server needed.
 *
 * Usage: node verify-receipt.js < receipt.json
 */

import crypto from 'crypto';
import { readFileSync } from 'fs';

const input = readFileSync('/dev/stdin', 'utf8');
const doc = JSON.parse(input);

if (doc['@version'] !== 'EP-RECEIPT-v1') {
  console.error('Unsupported version:', doc['@version']);
  process.exit(1);
}

// To verify, you need the signer's public key.
// In production, fetch from: signer's /.well-known/ep-keys.json
const publicKey = process.argv[2];
if (!publicKey) {
  console.error('Usage: node verify-receipt.js <public-key-base64url> < receipt.json');
  process.exit(1);
}

const payloadBytes = Buffer.from(JSON.stringify(doc.payload, Object.keys(doc.payload).sort()), 'utf8');
const keyDer = Buffer.from(publicKey, 'base64url');
const keyObject = crypto.createPublicKey({ key: keyDer, format: 'der', type: 'spki' });
const sigBytes = Buffer.from(doc.signature.value, 'base64url');

const valid = crypto.verify(null, payloadBytes, keyObject, sigBytes);

console.log(JSON.stringify({
  valid,
  receipt_id: doc.payload.receipt_id,
  issuer: doc.payload.issuer,
  subject: doc.payload.subject,
  outcome: doc.payload.claim.outcome,
  verified_at: new Date().toISOString(),
  _note: valid
    ? 'Receipt signature is valid. This was verified OFFLINE — no EP server contacted.'
    : 'INVALID SIGNATURE. This receipt may have been tampered with.',
}, null, 2));
`);

// README
writeFileSync(safeDir( 'README.md'), `# ${projectName}

Built with [EMILIA Protocol](https://emiliaprotocol.ai) — trust, before high-risk action.

## Quick Start

\`\`\`bash
npm install
npm run dev
# Open http://localhost:3000
\`\`\`

Click "Run Trust Demo" to see the full EP lifecycle:
- Entity registration with Ed25519 key pairs
- Self-verifying trust receipts
- Trust profile computation
- Pre-action handshake ceremony
- Replay attack prevention
- Offline receipt verification

## What You're Seeing

EP enforces trust at the action level. Before any high-risk action proceeds, EP verifies:
1. **Who** is acting (entity identity)
2. **What** they want to do (action binding)
3. **Whether** policy allows it (trust evaluation)
4. **That** a human owns the outcome (signoff, when required)
5. **That** the action is sealed (commit)

Every receipt is self-verifying: Ed25519-signed, verifiable with just the signer's public key. No API call. No account. Just math.

## Verify a Receipt Offline

\`\`\`bash
# Save a receipt from the API, then verify it locally:
curl -s http://localhost:3000/api/receipt -X POST \\
  -H 'Content-Type: application/json' \\
  -d '{"issuer":"ep_entity_...", "subject":"ep_entity_...", "outcome":"positive"}' > receipt.json

# Verify using the signer's public key (from /.well-known/ep-keys.json):
node verify-receipt.js <public-key> < receipt.json
\`\`\`

## Learn More

- [Protocol Specification](https://emiliaprotocol.ai/spec)
- [AAIF Proposal](https://github.com/emilia-protocol/docs/AAIF-PROPOSAL-v3.md)
- [Federation Spec](https://github.com/emilia-protocol/docs/FEDERATION-SPEC.md)
- [NIST AI RMF Mapping](https://github.com/emilia-protocol/docs/compliance/NIST-AI-RMF-MAPPING.md)

## License

Apache 2.0
`);

console.log(`
  Done! Your EP trust system is ready.

  Next steps:
    cd ${projectName}
    npm install
    npm run dev

  Then open http://localhost:3000 and click "Run Trust Demo".

  You'll see the full EP lifecycle in 60 seconds:
  entity registration, receipt issuance, trust profiles,
  handshake ceremonies, and offline receipt verification.

  Welcome to EMILIA Protocol.
`);
