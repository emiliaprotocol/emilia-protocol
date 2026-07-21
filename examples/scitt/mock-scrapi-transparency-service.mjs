// SPDX-License-Identifier: Apache-2.0
// Generated from mock-scrapi-transparency-service.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// Zero-dependency mock SCRAPI-like Transparency Service for EP-SCITT demos.
//
// This is intentionally named "mock": it is a reproducible CI twin for the
// register -> receipt -> verify-inclusion path. It is not a SCITT WG
// conformance claim and does not implement COSE Receipt verification.
import crypto from 'node:crypto';
import http from 'node:http';
import { canonicalize } from './ep-receipt-scitt-conformance.mjs';
const MOCK_RECEIPT_PROFILE = 'EP-SCITT-MOCK-TRANSPARENCY-RECEIPT-v1';
const MOCK_RECEIPT_CONTENT_TYPE = 'application/vnd.emilia.mock-scitt-receipt+json';
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const fromB64u = (s) => Buffer.from(s, 'base64url');
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest();
const hex = (buf) => Buffer.from(buf).toString('hex');
const statementLeafHash = (statementBytes) => sha256(Buffer.concat([Buffer.from([0x00]), statementBytes]));
const parentHash = (left, right) => sha256(Buffer.concat([Buffer.from([0x01]), left, right]));
function buildMerkleLevels(leaves) {
    if (!leaves.length)
        return [[sha256(Buffer.alloc(0))]];
    const levels = [leaves.map((leaf) => Buffer.from(leaf))];
    while (levels.at(-1).length > 1) {
        const prev = levels.at(-1);
        const next = [];
        for (let i = 0; i < prev.length; i += 2) {
            next.push(i + 1 < prev.length ? parentHash(prev[i], prev[i + 1]) : prev[i]);
        }
        levels.push(next);
    }
    return levels;
}
function inclusionPath(levels, index) {
    const path = [];
    let cursor = index;
    for (let level = 0; level < levels.length - 1; level++) {
        const nodes = levels[level];
        const isRight = cursor % 2 === 1;
        const siblingIndex = isRight ? cursor - 1 : cursor + 1;
        if (siblingIndex < nodes.length) {
            path.push({
                position: isRight ? 'left' : 'right',
                hash: hex(nodes[siblingIndex]),
            });
        }
        cursor = Math.floor(cursor / 2);
    }
    return path;
}
function verifyPath({ leafHash, rootHash, path }) {
    let cursor = Buffer.from(leafHash);
    for (const step of path) {
        const sibling = Buffer.from(step.hash, 'hex');
        cursor = step.position === 'left'
            ? parentHash(sibling, cursor)
            : parentHash(cursor, sibling);
    }
    return hex(cursor) === rootHash;
}
function signJsonPayload(payload, privateKey) {
    const payloadBytes = Buffer.from(canonicalize(payload), 'utf8');
    return crypto.sign(null, payloadBytes, privateKey);
}
function verifyJsonPayload(payload, signature, publicKey) {
    const payloadBytes = Buffer.from(canonicalize(payload), 'utf8');
    return crypto.verify(null, payloadBytes, publicKey, signature);
}
function buildMockTransparencyReceipt({ entries, entryIndex, serviceKeys, issuedAt = new Date().toISOString() }) {
    const leaves = entries.map((entry) => statementLeafHash(entry.statement));
    const levels = buildMerkleLevels(leaves);
    const root = levels.at(-1)[0];
    const entry = entries[entryIndex];
    const payload = {
        profile: MOCK_RECEIPT_PROFILE,
        note: 'Reproducible mock receipt for CI; not a SCITT WG receipt format.',
        statement_sha256: hex(sha256(entry.statement)),
        leaf_hash: hex(leaves[entryIndex]),
        tree_size: entries.length,
        leaf_index: entryIndex,
        root_hash: hex(root),
        inclusion_path: inclusionPath(levels, entryIndex),
        issued_at: issuedAt,
    };
    const signature = signJsonPayload(payload, serviceKeys.privateKey);
    const spki = serviceKeys.publicKey.export({ type: 'spki', format: 'der' });
    return {
        payload,
        signature: {
            algorithm: 'Ed25519',
            value: b64u(signature),
        },
        public_key: b64u(spki),
    };
}
function verifyMockTransparencyReceipt(receipt, statementBytes, trustedPublicKey = null) {
    const publicKey = trustedPublicKey || crypto.createPublicKey({
        key: fromB64u(receipt.public_key),
        type: 'spki',
        format: 'der',
    });
    const expectedStatementHash = hex(sha256(statementBytes));
    const expectedLeafHash = hex(statementLeafHash(statementBytes));
    const signature = fromB64u(receipt.signature?.value || '');
    const leafHash = Buffer.from(receipt.payload.leaf_hash || '', 'hex');
    return [
        {
            id: 'mock_receipt_profile',
            title: 'mock transparency receipt profile is explicit',
            pass: receipt.payload.profile === MOCK_RECEIPT_PROFILE,
        },
        {
            id: 'mock_receipt_signature',
            title: 'mock receipt payload signature verifies',
            pass: verifyJsonPayload(receipt.payload, signature, publicKey),
        },
        {
            id: 'statement_hash_binding',
            title: 'receipt binds the registered COSE_Sign1 bytes',
            pass: receipt.payload.statement_sha256 === expectedStatementHash,
        },
        {
            id: 'leaf_hash_binding',
            title: 'receipt leaf hash recomputes from statement bytes',
            pass: receipt.payload.leaf_hash === expectedLeafHash,
        },
        {
            id: 'inclusion_path',
            title: 'inclusion path recomputes the root hash',
            pass: verifyPath({
                leafHash,
                rootHash: receipt.payload.root_hash,
                path: receipt.payload.inclusion_path || [],
            }),
        },
    ];
}
function createMockScrapiRegistry() {
    const entries = [];
    const serviceKeys = crypto.generateKeyPairSync('ed25519');
    return {
        publicKey: serviceKeys.publicKey,
        register(statement) {
            const entryIndex = entries.push({ statement: Buffer.from(statement) }) - 1;
            const receipt = buildMockTransparencyReceipt({ entries, entryIndex, serviceKeys });
            const body = Buffer.from(JSON.stringify(receipt), 'utf8');
            return {
                ok: true,
                status: 201,
                location: `/entries/${entryIndex + 1}/receipt`,
                contentType: MOCK_RECEIPT_CONTENT_TYPE,
                body,
                receipt,
            };
        },
    };
}
async function readBody(req) {
    const chunks = [];
    for await (const chunk of req)
        chunks.push(Buffer.from(chunk));
    return Buffer.concat(chunks);
}
async function createMockScrapiTransparencyService({ port = 0 } = {}) {
    const entries = [];
    const serviceKeys = crypto.generateKeyPairSync('ed25519');
    const server = http.createServer(async (req, res) => {
        const url = new URL(req.url ?? '/', 'http://127.0.0.1');
        if (req.method === 'POST' && url.pathname === '/entries') {
            const statement = await readBody(req);
            if (!/^application\/cose\b/i.test(req.headers['content-type'] || '')) {
                res.writeHead(415, { 'content-type': 'application/json' });
                res.end(JSON.stringify({ error: 'content_type_must_be_application_cose' }));
                return;
            }
            const entryIndex = entries.push({ statement }) - 1;
            const receipt = buildMockTransparencyReceipt({ entries, entryIndex, serviceKeys });
            res.writeHead(201, {
                'content-type': MOCK_RECEIPT_CONTENT_TYPE,
                location: `/entries/${entryIndex + 1}/receipt`,
            });
            res.end(JSON.stringify(receipt));
            return;
        }
        if (req.method === 'GET' && url.pathname === '/health') {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ ok: true, service: 'mock-scrapi-transparency-service' }));
            return;
        }
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'not_found' }));
    });
    await new Promise((resolve) => server.listen(port, '127.0.0.1', () => resolve()));
    const address = server.address();
    if (!address)
        throw new Error('server.address() returned null');
    return {
        url: `http://127.0.0.1:${address.port}`,
        publicKey: serviceKeys.publicKey,
        close: () => new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve()))),
    };
}
async function main() {
    const service = await createMockScrapiTransparencyService({ port: Number(process.env.PORT || 0) });
    console.log(`mock-scrapi-transparency-service listening at ${service.url}`);
}
if (import.meta.url === `file://${process.argv[1]}`) {
    main().catch((err) => {
        console.error(err);
        process.exit(1);
    });
}
export { MOCK_RECEIPT_CONTENT_TYPE, MOCK_RECEIPT_PROFILE, buildMockTransparencyReceipt, createMockScrapiRegistry, createMockScrapiTransparencyService, verifyMockTransparencyReceipt, };
