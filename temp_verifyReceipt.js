function verifyReceipt(doc, publicKeyBase64url, opts = {}) {
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


