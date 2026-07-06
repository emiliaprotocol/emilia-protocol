#!/usr/bin/env node
/**
 * EP Witness — cosigner service (EP-WITNESS-v1).
 *
 * A minimal, zero-dependency HTTP service that an INDEPENDENT operator runs to
 * cosign a transparency-log checkpoint. It re-signs the SAME committed checkpoint
 * bytes the log signed, under a distinct domain tag (see WITNESS_DOMAIN_TAG in
 * @emilia-protocol/verify witness.js), so that when several independent witnesses
 * cosign whatever head they observed, a split view (equivocation) becomes
 * detectable to strangers who later compare cosignatures.
 *
 * WHAT A COSIGNATURE FROM THIS SERVICE ATTESTS
 *   "I, witness <witness_id>, observed a checkpoint claiming this tree_size and
 *    root_hash under this log_key_id, and I sign exactly these committed bytes."
 * It does NOT vouch for the log's honesty or append-only property, and it does
 * NOT establish current validity (it is authentic-as-of-observation only).
 *
 * The signing digest and domain tag are IMPORTED from the verify package, so a
 * cosignature this server emits is byte-identical to what verifyWitnessCosignature
 * checks. No canonicalization or crypto is re-implemented here.
 *
 * Endpoints:
 *   POST /cosign        body: a checkpoint {tree_size, root_hash, log_key_id, ...}
 *                       200 -> a witness cosignature; 400 on malformed input.
 *   GET  /witness-key   200 -> { alg, witness_id, public_key }
 *   GET  /healthz       200 -> { ok: true }
 *
 * Key loading (never hardcoded):
 *   WITNESS_PRIVATE_KEY        PEM literal of the PKCS8 Ed25519 private key, OR
 *   WITNESS_PRIVATE_KEY_FILE   path to that PEM file (default ./keys/witness-private.pem)
 *   WITNESS_PUBLIC_FILE        path to witness-public.json (default ./keys/witness-public.json)
 *   PORT                       listen port (default 8787)
 *
 * @license Apache-2.0
 */

import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  witnessSigningDigest,
  WITNESS_VERSION,
} from '../packages/verify/witness.js';
import { deriveWitnessId } from './generate-key.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_KEYDIR = path.join(HERE, 'keys');

const MAX_BODY_BYTES = 64 * 1024; // a checkpoint is tiny; refuse anything larger.

// Structural validity for a checkpoint we are willing to cosign. Fail-closed:
// a witness signs ONLY a well-formed checkpoint. tree_size must be a
// non-negative integer; root_hash and log_key_id must be non-empty strings.
function checkpointStructureError(cp) {
  if (!cp || typeof cp !== 'object' || Array.isArray(cp)) return 'checkpoint must be a JSON object';
  if (!Number.isInteger(cp.tree_size) || cp.tree_size < 0) return 'checkpoint.tree_size must be a non-negative integer';
  if (typeof cp.root_hash !== 'string' || cp.root_hash.trim() === '') return 'checkpoint.root_hash must be a non-empty string';
  if (typeof cp.log_key_id !== 'string' || cp.log_key_id.trim() === '') return 'checkpoint.log_key_id must be a non-empty string';
  return null;
}

function loadIdentity() {
  const keydir = process.env.WITNESS_KEYDIR || DEFAULT_KEYDIR;

  // Private key: literal env wins over a file path; refuse if neither is present.
  let privatePem = process.env.WITNESS_PRIVATE_KEY;
  if (!privatePem) {
    const privFile = process.env.WITNESS_PRIVATE_KEY_FILE || path.join(keydir, 'witness-private.pem');
    if (!fs.existsSync(privFile)) {
      throw new Error(
        `No witness private key. Set WITNESS_PRIVATE_KEY (PEM) or WITNESS_PRIVATE_KEY_FILE, ` +
        `or run: node generate-key.mjs  (looked for ${privFile})`,
      );
    }
    privatePem = fs.readFileSync(privFile, 'utf8');
  }
  const privateKey = crypto.createPrivateKey(privatePem);
  if (privateKey.asymmetricKeyType !== 'ed25519') {
    throw new Error(`witness private key must be Ed25519 (got ${privateKey.asymmetricKeyType})`);
  }

  // Derive the public key + id from the private key so they can never drift.
  const publicKey = crypto.createPublicKey(privateKey);
  const public_key = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const witness_id = deriveWitnessId(public_key);

  // If a public record exists, cross-check it and refuse a mismatch (fail-closed).
  const pubFile = process.env.WITNESS_PUBLIC_FILE || path.join(keydir, 'witness-public.json');
  if (fs.existsSync(pubFile)) {
    try {
      const rec = JSON.parse(fs.readFileSync(pubFile, 'utf8'));
      if (rec.public_key && rec.public_key !== public_key) {
        throw new Error('WITNESS_PUBLIC_FILE public_key does not match the loaded private key');
      }
      if (rec.witness_id && rec.witness_id !== witness_id) {
        throw new Error('WITNESS_PUBLIC_FILE witness_id does not match the loaded private key');
      }
    } catch (e) {
      if (e instanceof SyntaxError) throw new Error(`WITNESS_PUBLIC_FILE is not valid JSON: ${e.message}`);
      throw e;
    }
  }

  return { privateKey, public_key, witness_id };
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
  });
  res.end(body);
}

function cosignCheckpoint(checkpoint, identity) {
  const digest = witnessSigningDigest(checkpoint);
  if (digest === null) return null; // canonicalization failed -> refuse
  const signature = crypto.sign(null, digest, identity.privateKey).toString('base64url');
  // Echo the head so a relying party can refuse a cosignature reused for a
  // different checkpoint (verifyWitnessCosignature enforces the echo).
  return {
    alg: WITNESS_VERSION,
    witness_id: identity.witness_id,
    tree_size: checkpoint.tree_size,
    root_hash: checkpoint.root_hash,
    log_key_id: checkpoint.log_key_id,
    cosigned_at: new Date().toISOString(),
    signature,
  };
}

export function createServer(identity) {
  return http.createServer((req, res) => {
    const url = new URL(req.url, 'http://witness.local');

    if (req.method === 'GET' && url.pathname === '/healthz') {
      return sendJson(res, 200, { ok: true });
    }

    if (req.method === 'GET' && url.pathname === '/witness-key') {
      return sendJson(res, 200, {
        alg: WITNESS_VERSION,
        witness_id: identity.witness_id,
        public_key: identity.public_key,
      });
    }

    if (req.method === 'POST' && url.pathname === '/cosign') {
      const chunks = [];
      let total = 0;
      let aborted = false;
      req.on('data', (c) => {
        if (aborted) return;
        total += c.length;
        if (total > MAX_BODY_BYTES) {
          aborted = true;
          sendJson(res, 413, { error: 'checkpoint body too large' });
          req.destroy();
          return;
        }
        chunks.push(c);
      });
      req.on('end', () => {
        if (aborted) return;
        let parsed;
        try {
          parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        } catch (e) {
          return sendJson(res, 400, { error: `invalid JSON: ${e.message}` });
        }
        // Accept either a bare checkpoint or { checkpoint: {...} }.
        const checkpoint = parsed && typeof parsed === 'object' && parsed.checkpoint !== undefined
          ? parsed.checkpoint
          : parsed;
        const structErr = checkpointStructureError(checkpoint);
        if (structErr) {
          return sendJson(res, 400, { error: structErr });
        }
        const cosignature = cosignCheckpoint(checkpoint, identity);
        if (!cosignature) {
          return sendJson(res, 400, { error: 'checkpoint could not be canonicalized (out of profile)' });
        }
        return sendJson(res, 200, { cosignature });
      });
      req.on('error', () => {
        if (!aborted) sendJson(res, 400, { error: 'request stream error' });
      });
      return;
    }

    return sendJson(res, 404, { error: 'not found' });
  });
}

function main() {
  let identity;
  try {
    identity = loadIdentity();
  } catch (e) {
    console.error(`witness: ${e.message}`);
    process.exit(1);
  }
  const port = Number(process.env.PORT) || 8787;
  const server = createServer(identity);
  server.listen(port, () => {
    console.log(`EP witness ${identity.witness_id} listening on :${port}`);
    console.log(`  GET  /witness-key   -> public key to pin`);
    console.log(`  POST /cosign        -> cosign a checkpoint`);
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
