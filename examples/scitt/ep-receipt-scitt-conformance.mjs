// SPDX-License-Identifier: Apache-2.0
// Generated from ep-receipt-scitt-conformance.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// EP-RECEIPT-SCITT-PROFILE-v1 local conformance harness.
//
// This proves the local profile invariants for carrying an EMILIA authorization
// receipt as a SCITT Signed Statement:
//   - native EP signature verifies over the RFC 8785/JCS payload bytes;
//   - COSE_Sign1 is well-formed for the profile shape;
//   - protected header carries alg=EdDSA, cty=application/ep-receipt+json, kid;
//   - COSE Sig_structure verifies under the same Ed25519 key;
//   - COSE payload bytes are byte-identical to the EP canonical payload;
//   - SCRAPI request shape is POST /entries + application/cose.
//
// Optional live mode:
//   SCITT_URL=https://<transparency-service> node examples/scitt/ep-receipt-scitt-conformance.mjs
//
// Without a live Transparency Service and returned Receipt verification, this is
// not a SCITT WG conformance claim. It is the local EP-SCITT profile proof plus
// an optional SCRAPI registration smoke test.
import crypto from 'node:crypto';
const CTY = 'application/ep-receipt+json';
const SCRAPI_PATH = '/entries';
// --- RFC 8785 (JCS) canonicalization over the EP I-JSON value subset ---------
function canonicalize(v) {
    return v === null || v === undefined ? JSON.stringify(v)
        : Array.isArray(v) ? `[${v.map(canonicalize).join(',')}]`
            : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`
                : JSON.stringify(v);
}
// --- Minimal deterministic CBOR encoder (only types this profile needs) ------
const U = (n) => Buffer.from([n]);
function head(major, len) {
    const m = major << 5;
    if (len < 24)
        return U(m | len);
    if (len < 256)
        return Buffer.from([m | 24, len]);
    if (len < 65536)
        return Buffer.from([m | 25, len >> 8, len & 0xff]);
    throw new Error('length out of range for this minimal encoder');
}
const cbBstr = (buf) => Buffer.concat([head(2, buf.length), buf]);
const cbTstr = (s) => {
    const b = Buffer.from(s, 'utf8');
    return Buffer.concat([head(3, b.length), b]);
};
const cbUint = (n) => head(0, n);
const cbNint = (n) => head(1, -1 - n);
const cbArr = (items) => Buffer.concat([head(4, items.length), ...items]);
function cbMap(pairs) {
    return Buffer.concat([head(5, pairs.length), ...pairs.flat()]);
}
const tagCoseSign1 = (buf) => Buffer.concat([Buffer.from([0xd2]), buf]); // tag(18)
// --- Minimal CBOR decoder for conformance assertions -------------------------
function readLen(buf, offset, ai) {
    if (ai < 24)
        return [ai, offset];
    if (ai === 24)
        return [buf[offset], offset + 1];
    if (ai === 25)
        return [buf.readUInt16BE(offset), offset + 2];
    throw new Error(`unsupported CBOR additional info ${ai}`);
}
function decodeCbor(buf, offset = 0) {
    const first = buf[offset++];
    const major = first >> 5;
    const ai = first & 0x1f;
    if (major === 0 || major === 1) {
        const [n, next] = readLen(buf, offset, ai);
        return { value: major === 0 ? n : -1 - n, offset: next };
    }
    if (major === 2 || major === 3) {
        const [len, start] = readLen(buf, offset, ai);
        const raw = buf.subarray(start, start + len);
        return { value: major === 2 ? Buffer.from(raw) : raw.toString('utf8'), offset: start + len };
    }
    if (major === 4) {
        const [len, next] = readLen(buf, offset, ai);
        const out = [];
        let cursor = next;
        for (let i = 0; i < len; i++) {
            const decoded = decodeCbor(buf, cursor);
            out.push(decoded.value);
            cursor = decoded.offset;
        }
        return { value: out, offset: cursor };
    }
    if (major === 5) {
        const [len, next] = readLen(buf, offset, ai);
        const out = new Map();
        let cursor = next;
        for (let i = 0; i < len; i++) {
            const key = decodeCbor(buf, cursor);
            const val = decodeCbor(buf, key.offset);
            out.set(key.value, val.value);
            cursor = val.offset;
        }
        return { value: out, offset: cursor };
    }
    if (major === 6) {
        const [tag, next] = readLen(buf, offset, ai);
        const inner = decodeCbor(buf, next);
        return { value: { tag, value: inner.value }, offset: inner.offset };
    }
    throw new Error(`unsupported CBOR major type ${major}`);
}
function buildArtifacts() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const spki = publicKey.export({ type: 'spki', format: 'der' });
    const kid = crypto.createHash('sha256').update(spki).digest().subarray(0, 16);
    const action = { action_type: 'db.records.delete_all', target: 'customers' };
    const payload = {
        receipt_id: 'rcpt_' + crypto.randomBytes(6).toString('hex'),
        subject: 'agent:autonomous',
        created_at: new Date().toISOString(),
        claim: {
            action_type: action.action_type,
            target: action.target,
            outcome: 'allow_with_signoff',
            approver: 'jane.doe@yourco.example',
        },
    };
    const payloadBytes = Buffer.from(canonicalize(payload), 'utf8');
    const nativeSig = crypto.sign(null, payloadBytes, privateKey);
    const protectedMap = cbMap([
        [cbUint(1), cbNint(-8)], // alg = EdDSA (-8)
        [cbUint(3), cbTstr(CTY)], // content type
        [cbUint(4), cbBstr(kid)], // kid
    ]);
    const protectedBstr = cbBstr(protectedMap);
    const sigStructure = cbArr([
        cbTstr('Signature1'),
        protectedBstr,
        cbBstr(Buffer.alloc(0)),
        cbBstr(payloadBytes),
    ]);
    const coseSig = crypto.sign(null, sigStructure, privateKey);
    const coseSign1 = tagCoseSign1(cbArr([
        protectedBstr,
        cbMap([]),
        cbBstr(payloadBytes),
        cbBstr(coseSig),
    ]));
    return {
        publicKey,
        privateKey,
        spki,
        kid,
        payload,
        payloadBytes,
        nativeSig,
        protectedMap,
        protectedBstr,
        sigStructure,
        coseSig,
        coseSign1,
        scrapi: {
            method: 'POST',
            path: SCRAPI_PATH,
            headers: { 'content-type': 'application/cose' },
            body: coseSign1,
        },
    };
}
function inspectCoseSign1(coseSign1) {
    const decoded = decodeCbor(coseSign1);
    if (decoded.offset !== coseSign1.length)
        throw new Error('trailing CBOR bytes');
    if (!decoded.value || decoded.value.tag !== 18)
        throw new Error('not COSE_Sign1 tag(18)');
    const arr = decoded.value.value;
    if (!Array.isArray(arr) || arr.length !== 4)
        throw new Error('COSE_Sign1 must contain 4 entries');
    const [protectedBstr, unprotected, payloadBytes, signature] = arr;
    if (!Buffer.isBuffer(protectedBstr))
        throw new Error('protected header is not a bstr');
    if (!(unprotected instanceof Map) || unprotected.size !== 0)
        throw new Error('unexpected unprotected header');
    if (!Buffer.isBuffer(payloadBytes))
        throw new Error('payload is not a bstr');
    if (!Buffer.isBuffer(signature))
        throw new Error('signature is not a bstr');
    const protectedDecoded = decodeCbor(protectedBstr);
    if (!(protectedDecoded.value instanceof Map) || protectedDecoded.offset !== protectedBstr.length) {
        throw new Error('protected header is not a complete map');
    }
    return {
        protected: protectedDecoded.value,
        payloadBytes,
        signature,
    };
}
function check(id, title, pass, detail = '') {
    return { id, title, pass: Boolean(pass), detail };
}
function verifyProfileArtifacts(artifacts) {
    const parsed = inspectCoseSign1(artifacts.coseSign1);
    const rebuiltSigStructure = cbArr([
        cbTstr('Signature1'),
        artifacts.protectedBstr,
        cbBstr(Buffer.alloc(0)),
        cbBstr(parsed.payloadBytes),
    ]);
    return [
        check('native_ep_signature', 'native EP Ed25519 signature verifies over JCS payload', crypto.verify(null, artifacts.payloadBytes, artifacts.publicKey, artifacts.nativeSig)),
        check('cose_sign1_tag', 'statement is tagged COSE_Sign1', artifacts.coseSign1[0] === 0xd2, 'tag(18)'),
        check('protected_alg', 'protected alg is EdDSA (-8)', parsed.protected.get(1) === -8, String(parsed.protected.get(1))),
        check('protected_cty', `protected content type is ${CTY}`, parsed.protected.get(3) === CTY, parsed.protected.get(3)),
        check('protected_kid', 'protected kid matches issuer key id', Buffer.compare(parsed.protected.get(4), artifacts.kid) === 0, artifacts.kid.toString('hex')),
        check('payload_byte_identity', 'COSE payload is byte-identical to EP canonical payload', Buffer.compare(parsed.payloadBytes, artifacts.payloadBytes) === 0),
        check('sig_structure_signature', 'COSE Sig_structure Ed25519 signature verifies', crypto.verify(null, rebuiltSigStructure, artifacts.publicKey, parsed.signature)),
        check('scrapi_request_shape', 'SCRAPI request is POST /entries with application/cose', artifacts.scrapi.method === 'POST'
            && artifacts.scrapi.path === SCRAPI_PATH
            && artifacts.scrapi.headers['content-type'] === 'application/cose'
            && Buffer.compare(artifacts.scrapi.body, artifacts.coseSign1) === 0),
    ];
}
async function registerWithTransparencyService(artifacts, baseUrl) {
    const url = new URL(SCRAPI_PATH, baseUrl);
    const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/cose', accept: 'application/cose, */*' },
        body: artifacts.coseSign1,
    });
    const body = Buffer.from(await res.arrayBuffer());
    return {
        status: res.status,
        ok: res.ok,
        contentType: res.headers.get('content-type') || '',
        bodyLength: body.length,
        bodySha256: crypto.createHash('sha256').update(body).digest('hex'),
    };
}
function printReport({ checks, artifacts, live }) {
    console.log('EP-RECEIPT-SCITT-PROFILE-v1 local conformance');
    for (const c of checks) {
        console.log(`${c.pass ? 'PASS' : 'FAIL'} ${c.id} — ${c.title}${c.detail ? ` (${c.detail})` : ''}`);
    }
    console.log('\nSCRAPI registration request:');
    console.log(`  ${artifacts.scrapi.method} ${artifacts.scrapi.path}`);
    console.log(`  Content-Type: ${artifacts.scrapi.headers['content-type']}`);
    console.log(`  Body: COSE_Sign1 ${artifacts.coseSign1.length} bytes, sha256=${crypto.createHash('sha256').update(artifacts.coseSign1).digest('hex')}`);
    if (live) {
        console.log('\nLive Transparency Service registration:');
        console.log(`  status=${live.status} ok=${live.ok} content-type=${live.contentType || '(none)'}`);
        console.log(`  receipt-bytes=${live.bodyLength} receipt-sha256=${live.bodySha256}`);
        console.log('  note: returned SCITT Receipt verification is intentionally not claimed by this local harness.');
    }
    else {
        console.log('\nSKIP live_scrapi_registration — set SCITT_URL to POST the Signed Statement to a Transparency Service.');
    }
    const passed = checks.every((c) => c.pass);
    console.log(`\n${passed ? 'LOCAL PROFILE PASS' : 'LOCAL PROFILE FAIL'} — local EP/COSE/SCRAPI shape only; not a SCITT WG conformance claim.`);
    return passed;
}
async function main() {
    const artifacts = buildArtifacts();
    const checks = verifyProfileArtifacts(artifacts);
    let live = null;
    const liveUrl = process.env.SCITT_URL || process.env.SCITT_TS_URL;
    if (liveUrl) {
        live = await registerWithTransparencyService(artifacts, liveUrl);
    }
    const passed = printReport({ checks, artifacts, live });
    if (!passed)
        process.exit(1);
}
if (import.meta.url === `file://${process.argv[1]}`) {
    main().catch((err) => {
        console.error(err);
        process.exit(1);
    });
}
export { buildArtifacts, canonicalize, inspectCoseSign1, registerWithTransparencyService, verifyProfileArtifacts, };
