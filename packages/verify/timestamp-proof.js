// SPDX-License-Identifier: Apache-2.0
/**
 * EP timestamp-proof — an INDEPENDENT RFC 3161 proof of WHEN, so a receipt's
 * commit time does not reduce to trusting the operator's own clock.
 *
 * time-attestation.js (EP-TIME-ATTESTATION-v1) is EP's native, Ed25519, JCS
 * trusted-time anchor. This module is its INTEROP sibling: it verifies a
 * standards-track RFC 3161 TimeStampToken (a CMS/PKCS#7 SignedData carrying a
 * TSTInfo) minted by an EXTERNAL Time-Stamping Authority. The design contract is
 * identical to everything else in this package: ASYMMETRIC, key-PINNED, and
 * FAIL-CLOSED. An unpinned or unknown TSA REFUSES. A token whose messageImprint
 * is not the digest the caller expected REFUSES. A token whose signature does
 * not verify under the pinned key REFUSES. An unparseable token REFUSES. Nothing
 * defaults to "trusted".
 *
 * WHAT THIS PROVES (and only this): a TSA that the caller chose to pin asserted,
 * with its signature, that `expectedDigest` (whatever the caller bound: a
 * checkpoint root, an action digest, a receipt leaf) existed at `gen_time`. In
 * other words the bytes PREDATE gen_time. It does NOT prove the action was
 * correct, authorized, or even sensible; it does not prove the TSA's clock was
 * accurate; it does not prove no EARLIER timestamp exists; and, exactly like
 * every offline check in this package, it is authentic-as-of-token only — it
 * says nothing about CURRENT validity or revocation of the TSA's certificate
 * (that needs a fresh online status check). It bounds an instant. It does not
 * divine truth.
 *
 * PARSING BOUNDARY (honest): this is a PURPOSE-BUILT minimal DER/CMS reader in
 * pure node:crypto, so the package stays zero-dependency. It supports the RFC
 * 3161 token shape a compliant TSA emits: a single SignerInfo, RSA
 * (RSASSA-PKCS1-v1_5) or ECDSA over a SHA-2 digest, with OR without CMS signed
 * attributes. It does NOT implement: full X.509 path building or trust-anchor
 * chaining (the caller PINS the exact TSA key, so no chain is walked), RSASSA-PSS,
 * or multi-signer tokens. Any token outside the supported shape REFUSES with a
 * distinct reason rather than being force-fit or waved through. When the RFC 5652
 * signed-attributes form is present, the signature is verified over the DER
 * re-encoding of the SignedAttributes (SET, 0x31 tag) per RFC 5652 §5.4, and the
 * `messageDigest` signed attribute is checked to equal SHA-256/384/512 of the
 * eContent (the TSTInfo) — a token that signs attributes whose messageDigest does
 * not bind the TSTInfo REFUSES.
 */
import crypto from 'node:crypto';

export const TIMESTAMP_PROOF_ALG = 'RFC3161';

// ── OIDs we recognize (dotted string form) ───────────────────────────────────
const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';        // pkcs7-signedData
const OID_CT_TSTINFO = '1.2.840.113549.1.9.16.1.4';    // id-ct-TSTInfo (eContentType)
const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';       // id-contentType signed attr
const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';     // id-messageDigest signed attr
const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const OID_SHA384 = '2.16.840.1.101.3.4.2.2';
const OID_SHA512 = '2.16.840.1.101.3.4.2.3';
const OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1';     // rsaEncryption (PKCS1 v1.5)
const OID_ECDSA_WITH_SHA256 = '1.2.840.10045.4.3.2';
const OID_ECDSA_WITH_SHA384 = '1.2.840.10045.4.3.3';
const OID_ECDSA_WITH_SHA512 = '1.2.840.10045.4.3.4';

// SHA-2 only, deliberately: SHA-1 (1.3.14.3.2.26) is collision-broken and a
// TSA still issuing SHA-1 tokens is itself a trust signal to refuse. A SHA-1
// digest OID therefore refuses with unsupported_digest_algorithm.
const DIGEST_OID_TO_NAME = {
  [OID_SHA256]: 'sha256',
  [OID_SHA384]: 'sha384',
  [OID_SHA512]: 'sha512',
};

// ── Minimal DER reader. Returns typed TLV nodes; throws on malformed length. ──
// A node = { cls, constructed, tag, headerLen, contentStart, contentEnd, buf }.
// Every accessor validates bounds so a truncated/over-long field throws (caught
// by the top-level verifier and turned into a fail-closed refusal).
class DerError extends Error {}

function readTLV(buf, offset) {
  if (offset + 2 > buf.length) throw new DerError('truncated TLV header');
  const first = buf[offset];
  const cls = (first & 0xc0) >> 6;        // 0 universal, 2 context
  const constructed = (first & 0x20) !== 0;
  let tag = first & 0x1f;
  let p = offset + 1;
  if (tag === 0x1f) {
    // high-tag-number form — supported enough to skip, but EP tokens don't use it
    tag = 0;
    let b;
    do {
      if (p >= buf.length) throw new DerError('truncated high tag');
      b = buf[p++];
      tag = (tag << 7) | (b & 0x7f);
    } while (b & 0x80);
  }
  if (p >= buf.length) throw new DerError('truncated length');
  let len = buf[p++];
  if (len & 0x80) {
    const numBytes = len & 0x7f;
    if (numBytes === 0) throw new DerError('indefinite length not allowed in DER');
    if (numBytes > 4) throw new DerError('length too large');
    if (p + numBytes > buf.length) throw new DerError('truncated long length');
    len = 0;
    for (let i = 0; i < numBytes; i++) len = (len << 8) | buf[p++];
  }
  const contentStart = p;
  const contentEnd = p + len;
  if (contentEnd > buf.length) throw new DerError('content exceeds buffer');
  return { cls, constructed, tag, headerLen: contentStart - offset, contentStart, contentEnd, buf };
}

// Iterate the children TLVs of a constructed node.
function* children(node) {
  let p = node.contentStart;
  while (p < node.contentEnd) {
    const child = readTLV(node.buf, p);
    yield child;
    p = child.contentEnd;
  }
}

function content(node) {
  return node.buf.subarray(node.contentStart, node.contentEnd);
}

// Full DER bytes of a node (header + content) — used to re-hash eContent and to
// re-encode SignedAttributes for signature verification.
function raw(node) {
  return node.buf.subarray(node.contentStart - node.headerLen, node.contentEnd);
}

// Decode an OBJECT IDENTIFIER node's content to dotted-decimal string.
function decodeOID(node) {
  if (node.tag !== 0x06 || node.cls !== 0) throw new DerError('expected OID');
  const b = content(node);
  if (b.length === 0) throw new DerError('empty OID');
  const first = b[0];
  const parts = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (let i = 1; i < b.length; i++) {
    value = (value << 7) | (b[i] & 0x7f);
    if (!(b[i] & 0x80)) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join('.');
}

// GeneralizedTime / UTCTime -> RFC 3339 UTC instant (epoch ms too). RFC 3161
// genTime is GeneralizedTime in Z (RFC 3161 §2.4.2); we also accept UTCTime for
// robustness. Returns { iso, ms } or null on any non-conforming form (fail-closed
// — an unparseable time never satisfies a bound).
function decodeGeneralizedTime(node) {
  const s = content(node).toString('latin1');
  // GeneralizedTime: YYYYMMDDHHMMSS[.fff]Z   (tag 0x18)
  let m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$/.exec(s);
  if (node.tag === 0x18 && m) {
    const frac = m[7] ? m[7] : '';
    const iso = `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${frac}Z`;
    const ms = Date.parse(iso);
    return Number.isNaN(ms) ? null : { iso, ms };
  }
  // UTCTime: YYMMDDHHMMSSZ (tag 0x17). Pivot per RFC 5280: 00-49 => 20xx, 50-99 => 19xx.
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

// Normalize any digest input ("sha256:<hex>" | "<hex>" | Buffer) to lowercase
// hex, or '' when malformed so comparisons fail closed (mirrors the hexOf guard
// in time-attestation.js / index.js).
function hexOf(h) {
  if (Buffer.isBuffer(h)) return h.toString('hex').toLowerCase();
  const s = String(h ?? '').replace(/^sha256:/i, '').replace(/^sha384:/i, '').replace(/^sha512:/i, '').toLowerCase();
  return /^[0-9a-f]+$/.test(s) && s.length % 2 === 0 && s.length >= 40 ? s : '';
}

// A stable identifier for the pinned key that verified the token, so the caller
// can record WHICH TSA key stamped the proof. Fingerprint of the SPKI DER.
function keyIdOfSpki(spkiDer) {
  return 'sha256:' + crypto.createHash('sha256').update(spkiDer).digest('hex');
}

// Build the public KeyObject for the pinned TSA key. Accepts base64/base64url
// SPKI DER, or a PEM string. Returns null (fail-closed) if it cannot be loaded.
function loadPinnedKey(pinned) {
  try {
    if (!pinned) return null;
    if (typeof pinned === 'string' && pinned.includes('-----BEGIN')) {
      return { key: crypto.createPublicKey(pinned), spkiDer: crypto.createPublicKey(pinned).export({ type: 'spki', format: 'der' }) };
    }
    // Treat as base64/base64url SPKI DER.
    const der = Buffer.from(String(pinned).replace(/\s+/g, ''), 'base64');
    if (der.length === 0) return null;
    const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    return { key, spkiDer: key.export({ type: 'spki', format: 'der' }) };
  } catch {
    return null;
  }
}

// Map a signatureAlgorithm OID (+ the digestAlgorithm the signer used) to the
// node:crypto verify parameters. Returns { hash, format } or null (unsupported).
function resolveSignatureAlg(sigAlgOid, digestName, keyType) {
  if (sigAlgOid === OID_RSA_ENCRYPTION || keyType === 'rsa') {
    // RSASSA-PKCS1-v1_5 over the signer's digest. RSASSA-PSS is deliberately
    // unsupported here (would carry an id-RSASSA-PSS OID + params we do not read).
    return digestName ? { hash: digestName } : null;
  }
  if (sigAlgOid === OID_ECDSA_WITH_SHA256) return { hash: 'sha256', dsaEncoding: 'der' };
  if (sigAlgOid === OID_ECDSA_WITH_SHA384) return { hash: 'sha384', dsaEncoding: 'der' };
  if (sigAlgOid === OID_ECDSA_WITH_SHA512) return { hash: 'sha512', dsaEncoding: 'der' };
  return null;
}

/**
 * Parse + verify an RFC 3161 TimeStampToken against a PINNED TSA key.
 *
 * @param {string|Buffer} timestampProof  DER TimeStampToken, base64/base64url (or a Buffer).
 * @param {string|Buffer} expectedDigest  the digest the token MUST timestamp
 *   (the receipt's checkpoint root or action digest — CALLER decides which).
 *   Accepts "sha256:<hex>", bare hex, or a Buffer of raw digest bytes.
 * @param {string|string[]|object} pinnedTsaKeys  the caller-supplied trust set.
 *   Each entry is an SPKI DER public key (base64/base64url) or a PEM string. May
 *   be a single key, an array of keys, or an object map { id: key }. The token
 *   REFUSES unless its signature verifies under one of these pinned keys.
 * @returns {{verified:boolean, tsa_key_id:(string|null), gen_time:(string|null), reason?:string}}
 *   FAIL-CLOSED. `verified:false` always carries a distinct `reason`. On success
 *   `tsa_key_id` is the SHA-256 fingerprint of the pinned SPKI that verified it,
 *   and `gen_time` is the TSA-asserted RFC 3339 UTC instant. The honest meaning:
 *   this TSA asserted `expectedDigest` existed at `gen_time` (the bytes predate
 *   gen_time). It does NOT prove the action was correct.
 */
export function verifyTimestampProof(timestampProof, expectedDigest, pinnedTsaKeys) {
  const refuse = (reason) => ({ verified: false, tsa_key_id: null, gen_time: null, reason });

  // ── Input gates (fail-closed on anything missing/blank) ──────────────────
  if (timestampProof === undefined || timestampProof === null
    || (typeof timestampProof !== 'string' && !Buffer.isBuffer(timestampProof))
    || (typeof timestampProof === 'string' && timestampProof.trim() === '')) {
    return refuse('missing_token');
  }
  const wantDigest = hexOf(expectedDigest);
  if (!wantDigest) return refuse('missing_or_malformed_expected_digest');

  // Assemble the pinned key set. An empty/absent set is an UNPINNED TSA -> refuse.
  const pinnedList = [];
  if (Array.isArray(pinnedTsaKeys)) pinnedList.push(...pinnedTsaKeys);
  else if (pinnedTsaKeys && typeof pinnedTsaKeys === 'object') pinnedList.push(...Object.values(pinnedTsaKeys));
  else if (pinnedTsaKeys) pinnedList.push(pinnedTsaKeys);
  const loadedKeys = pinnedList.map(loadPinnedKey).filter(Boolean);
  if (loadedKeys.length === 0) return refuse('unpinned_tsa');

  // ── Decode DER ────────────────────────────────────────────────────────────
  let der;
  try {
    der = Buffer.isBuffer(timestampProof)
      ? timestampProof
      : Buffer.from(timestampProof.replace(/\s+/g, ''), 'base64');
    if (der.length === 0) return refuse('unparseable_token');
  } catch {
    return refuse('unparseable_token');
  }

  let parsed;
  try {
    // Any structural malformation (bad TLV length, wrong shape) throws a
    // DerError and is caught here as a fail-closed unparseable_token refusal.
    parsed = parseTimeStampToken(der);
  } catch {
    return refuse('unparseable_token');
  }
  if (parsed.error) return refuse(parsed.error);

  const { tstInfo, signerInfo, eContentRaw } = parsed;

  // ── messageImprint must equal the digest the caller expected ─────────────
  // (bind BEFORE trusting the signature result: a wrong-digest token is refused
  //  with its own reason regardless of who signed it.)
  const imprintHex = tstInfo.messageImprintHex;
  if (imprintHex !== wantDigest) return refuse('digest_mismatch');

  // ── genTime ──────────────────────────────────────────────────────────────
  if (!tstInfo.genTime) return refuse('unparseable_token');

  // ── Verify the TSA signature under a PINNED key ──────────────────────────
  const sigResult = verifySignerInfo(signerInfo, eContentRaw, loadedKeys);
  if (!sigResult.ok) return refuse(sigResult.reason);

  return {
    verified: true,
    tsa_key_id: sigResult.tsaKeyId,
    gen_time: tstInfo.genTime,
  };
}

// ── TimeStampToken (CMS SignedData) structural parse ─────────────────────────
// ContentInfo ::= SEQUENCE { contentType OID(signedData), content [0] SignedData }
// SignedData  ::= SEQUENCE { version, digestAlgorithms SET, encapContentInfo,
//                            certificates [0] IMPLICIT OPTIONAL, crls [1] OPTIONAL,
//                            signerInfos SET }
// Returns { tstInfo, signerInfo, eContentRaw } or { error }.
function parseTimeStampToken(der) {
  const contentInfo = readTLV(der, 0);
  if (contentInfo.tag !== 0x10 || !contentInfo.constructed) return { error: 'unparseable_token' };
  const ciKids = [...children(contentInfo)];
  if (ciKids.length < 2) return { error: 'unparseable_token' };
  if (decodeOID(ciKids[0]) !== OID_SIGNED_DATA) return { error: 'not_signed_data' };
  // content [0] EXPLICIT
  const explicit0 = ciKids[1];
  if (explicit0.cls !== 2 || explicit0.tag !== 0 || !explicit0.constructed) return { error: 'unparseable_token' };
  const signedData = [...children(explicit0)][0];
  if (!signedData || signedData.tag !== 0x10) return { error: 'unparseable_token' };

  const sdKids = [...children(signedData)];
  // sdKids: [0]=version INTEGER, [1]=digestAlgorithms SET, [2]=encapContentInfo,
  //         then optional certificates [0] / crls [1] IMPLICIT, then signerInfos
  //         SET. Bind by position (encapContentInfo is the 3rd element) and take
  //         signerInfos as the final universal SET (tag 0x11) — never a heuristic
  //         scan that could mistake the certificates set for signerInfos.
  if (sdKids.length < 4) return { error: 'unparseable_token' };
  const encap = sdKids[2];
  let signerInfos = null;
  for (let i = sdKids.length - 1; i >= 3; i--) {
    if (sdKids[i].tag === 0x11 && sdKids[i].cls === 0) { signerInfos = sdKids[i]; break; }
  }
  if (!encap || encap.tag !== 0x10) return { error: 'unparseable_token' };
  if (!signerInfos) return { error: 'unparseable_token' };

  // encapContentInfo ::= SEQUENCE { eContentType OID, eContent [0] EXPLICIT OCTET STRING }
  const encapKids = [...children(encap)];
  if (encapKids.length < 2) return { error: 'unparseable_token' };
  if (decodeOID(encapKids[0]) !== OID_CT_TSTINFO) return { error: 'not_a_timestamp_token' };
  const eContentExplicit = encapKids[1];
  if (eContentExplicit.cls !== 2 || eContentExplicit.tag !== 0) return { error: 'unparseable_token' };
  const octet = [...children(eContentExplicit)][0];
  if (!octet || octet.tag !== 0x04) return { error: 'unparseable_token' };
  const eContentRaw = content(octet); // the DER-encoded TSTInfo bytes (what messageDigest hashes)

  const tstInfo = parseTstInfo(eContentRaw);
  if (tstInfo.error) return { error: tstInfo.error };

  // Exactly one SignerInfo supported (multi-signer refuses).
  const siList = [...children(signerInfos)];
  if (siList.length !== 1) return { error: 'unsupported_signerinfo_count' };
  const signerInfo = parseSignerInfo(siList[0]);
  if (signerInfo.error) return { error: signerInfo.error };

  return { tstInfo, signerInfo, eContentRaw };
}

// TSTInfo ::= SEQUENCE { version INTEGER, policy OID, messageImprint,
//   serialNumber INTEGER, genTime GeneralizedTime, accuracy OPTIONAL, ... }
// messageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
function parseTstInfo(der) {
  try {
    const seq = readTLV(der, 0);
    if (seq.tag !== 0x10) return { error: 'unparseable_token' };
    const kids = [...children(seq)];
    // kids[0]=version, kids[1]=policy OID, kids[2]=messageImprint SEQUENCE, kids[3]=serial, kids[4]=genTime
    if (kids.length < 5) return { error: 'unparseable_token' };
    const mi = kids[2];
    if (mi.tag !== 0x10) return { error: 'unparseable_token' };
    const miKids = [...children(mi)];
    if (miKids.length < 2) return { error: 'unparseable_token' };
    const hashAlgSeq = miKids[0];
    const hashAlgOid = decodeOID([...children(hashAlgSeq)][0]);
    const hashedMessage = miKids[1];
    if (hashedMessage.tag !== 0x04) return { error: 'unparseable_token' };
    const messageImprintHex = content(hashedMessage).toString('hex').toLowerCase();

    // genTime is the first GeneralizedTime/UTCTime after serialNumber.
    let genTime = null;
    for (let i = 3; i < kids.length; i++) {
      if (kids[i].tag === 0x18 || kids[i].tag === 0x17) {
        const t = decodeGeneralizedTime(kids[i]);
        if (t) genTime = t.iso;
        break;
      }
    }
    return { messageImprintHex, imprintAlgOid: hashAlgOid, genTime };
  } catch {
    return { error: 'unparseable_token' };
  }
}

// SignerInfo ::= SEQUENCE { version, sid, digestAlgorithm, signedAttrs [0] IMPLICIT OPTIONAL,
//   signatureAlgorithm, signature OCTET STRING, unsignedAttrs [1] OPTIONAL }
function parseSignerInfo(node) {
  try {
    if (node.tag !== 0x10) return { error: 'unparseable_token' };
    const kids = [...children(node)];
    // kids[0]=version INTEGER, kids[1]=sid, kids[2]=digestAlgorithm SEQ, then
    // optional [0] signedAttrs, then signatureAlgorithm SEQ, then signature OCTET STRING.
    let idx = 0;
    const version = kids[idx++];
    if (!version || version.tag !== 0x02) return { error: 'unparseable_token' };
    const sid = kids[idx++]; // IssuerAndSerialNumber (SEQ) or [0] SubjectKeyIdentifier
    if (!sid) return { error: 'unparseable_token' };
    const digestAlg = kids[idx++];
    if (!digestAlg || digestAlg.tag !== 0x10) return { error: 'unparseable_token' };
    const digestAlgOid = decodeOID([...children(digestAlg)][0]);

    let signedAttrs = null;
    if (kids[idx] && kids[idx].cls === 2 && kids[idx].tag === 0 && kids[idx].constructed) {
      signedAttrs = kids[idx++]; // [0] IMPLICIT SET OF Attribute
    }
    const sigAlg = kids[idx++];
    if (!sigAlg || sigAlg.tag !== 0x10) return { error: 'unparseable_token' };
    const sigAlgOid = decodeOID([...children(sigAlg)][0]);
    const sigOctet = kids[idx++];
    if (!sigOctet || sigOctet.tag !== 0x04) return { error: 'unparseable_token' };
    const signature = content(sigOctet);

    return {
      digestAlgOid,
      digestName: DIGEST_OID_TO_NAME[digestAlgOid] || null,
      signedAttrs,
      sigAlgOid,
      signature,
    };
  } catch {
    return { error: 'unparseable_token' };
  }
}

// Parse a SET OF Attribute; return a map { oid: [valueNodes...] }.
function parseAttributes(setNode) {
  const out = {};
  for (const attr of children(setNode)) {
    if (attr.tag !== 0x10) continue;
    const kids = [...children(attr)];
    if (kids.length < 2) continue;
    const oid = decodeOID(kids[0]);
    const valuesSet = kids[1]; // SET OF AttributeValue
    out[oid] = [...children(valuesSet)];
  }
  return out;
}

// Verify the SignerInfo signature against each pinned key until one verifies.
// Two RFC 5652 shapes:
//  (a) signedAttrs present: signature is over DER re-encoding of signedAttrs as an
//      explicit SET (0x31), AND the messageDigest attr MUST equal H(eContent), AND
//      the contentType attr MUST be id-ct-TSTInfo. (RFC 5652 §5.4)
//  (b) no signedAttrs: signature is directly over eContent (the TSTInfo bytes).
function verifySignerInfo(signerInfo, eContentRaw, loadedKeys) {
  const { digestName, signedAttrs, sigAlgOid, signature } = signerInfo;
  if (!digestName) return { ok: false, reason: 'unsupported_digest_algorithm' };

  let signedBytes;
  if (signedAttrs) {
    const attrs = parseAttributes(signedAttrs);
    // contentType signed attr MUST be id-ct-TSTInfo.
    const ctNodes = attrs[OID_CONTENT_TYPE];
    if (!ctNodes || ctNodes.length !== 1) return { ok: false, reason: 'missing_content_type_attr' };
    let ctOid;
    try { ctOid = decodeOID(ctNodes[0]); } catch { return { ok: false, reason: 'unparseable_token' }; }
    if (ctOid !== OID_CT_TSTINFO) return { ok: false, reason: 'content_type_attr_mismatch' };

    // messageDigest signed attr MUST equal H(eContent).
    const mdNodes = attrs[OID_MESSAGE_DIGEST];
    if (!mdNodes || mdNodes.length !== 1 || mdNodes[0].tag !== 0x04) {
      return { ok: false, reason: 'missing_message_digest_attr' };
    }
    const attrDigest = content(mdNodes[0]);
    const eContentDigest = crypto.createHash(digestName).update(eContentRaw).digest();
    if (!attrDigest.equals(eContentDigest)) return { ok: false, reason: 'message_digest_attr_mismatch' };

    // Signature input: DER re-encoding of the attributes as SET (0x31), NOT the
    // [0] IMPLICIT tag they appear with in the SignerInfo (RFC 5652 §5.4).
    const attrsBody = raw(signedAttrs).subarray(signedAttrs.headerLen); // content bytes of [0]
    signedBytes = Buffer.concat([derSetHeader(attrsBody.length), attrsBody]);
  } else {
    signedBytes = eContentRaw;
  }

  for (const { key, spkiDer } of loadedKeys) {
    const keyType = key.asymmetricKeyType; // 'rsa' | 'ec' | ...
    const alg = resolveSignatureAlg(sigAlgOid, digestName, keyType);
    if (!alg) continue;
    // Guard: signatureAlgorithm must be consistent with the pinned key type.
    if ((sigAlgOid === OID_RSA_ENCRYPTION && keyType !== 'rsa')) continue;
    if ((sigAlgOid === OID_ECDSA_WITH_SHA256 || sigAlgOid === OID_ECDSA_WITH_SHA384 || sigAlgOid === OID_ECDSA_WITH_SHA512) && keyType !== 'ec') continue;
    try {
      const verifyOpts = { key };
      if (alg.dsaEncoding) verifyOpts.dsaEncoding = alg.dsaEncoding;
      const ok = crypto.verify(alg.hash, signedBytes, verifyOpts, signature);
      if (ok) return { ok: true, tsaKeyId: keyIdOfSpki(spkiDer) };
    } catch {
      // try next pinned key
    }
  }
  return { ok: false, reason: 'bad_signature' };
}

// Encode a DER SET (0x31) header for a body of the given length.
function derSetHeader(len) {
  if (len < 0x80) return Buffer.from([0x31, len]);
  const bytes = [];
  let n = len;
  while (n > 0) { bytes.unshift(n & 0xff); n >>= 8; }
  return Buffer.from([0x31, 0x80 | bytes.length, ...bytes]);
}
