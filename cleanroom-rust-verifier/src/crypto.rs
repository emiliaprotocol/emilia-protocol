// SPDX-License-Identifier: Apache-2.0
//
// Cryptographic primitives for the EMILIA Protocol verifier.
// Ed25519 verification, ECDSA P-256 verification, SHA-256 hashing.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{DerSignature, VerifyingKey as P256VerifyingKey};
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256, Sha384, Sha512};
use spki::SubjectPublicKeyInfoRef;

/// Decode a base64url-encoded SPKI public key and extract the raw 32-byte Ed25519 key.
pub fn parse_ed25519_spki_key(b64url: &str) -> Result<Ed25519VerifyingKey, String> {
    // Try base64url (no padding) first, then standard base64
    let der_bytes = URL_SAFE_NO_PAD
        .decode(b64url)
        .or_else(|_| STANDARD.decode(b64url))
        .map_err(|e| format!("base64 decode error: {}", e))?;

    // Parse SPKI
    let spki = SubjectPublicKeyInfoRef::try_from(der_bytes.as_slice())
        .map_err(|e| format!("SPKI parse error: {}", e))?;

    let raw_key = spki.subject_public_key.raw_bytes();
    if raw_key.len() != 32 {
        return Err(format!("Ed25519 key must be 32 bytes, got {}", raw_key.len()));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(raw_key);
    Ed25519VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| format!("Ed25519 key error: {}", e))
}

/// Verify an Ed25519 signature over given data.
pub fn verify_ed25519(
    public_key_b64url: &str,
    message: &[u8],
    signature_b64url: &str,
) -> Result<bool, String> {
    let verifying_key = parse_ed25519_spki_key(public_key_b64url)?;

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64url)
        .or_else(|_| STANDARD.decode(signature_b64url))
        .map_err(|e| format!("signature base64 decode error: {}", e))?;

    if sig_bytes.len() != 64 {
        return Ok(false);
    }

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Ed25519Signature::from_bytes(&sig_arr);

    use ed25519_dalek::Verifier;
    Ok(verifying_key.verify(message, &signature).is_ok())
}

/// Parse a base64url-encoded SPKI P-256 public key.
pub fn parse_p256_spki_key(b64url: &str) -> Result<P256VerifyingKey, String> {
    let der_bytes = URL_SAFE_NO_PAD
        .decode(b64url)
        .or_else(|_| STANDARD.decode(b64url))
        .map_err(|e| format!("base64 decode error: {}", e))?;

    let spki = SubjectPublicKeyInfoRef::try_from(der_bytes.as_slice())
        .map_err(|e| format!("SPKI parse error: {}", e))?;

    let raw_key = spki.subject_public_key.raw_bytes();
    P256VerifyingKey::from_sec1_bytes(raw_key)
        .map_err(|e| format!("P-256 key error: {}", e))
}

/// Verify an ECDSA P-256 signature (DER-encoded) over given data.
pub fn verify_p256(
    public_key_b64url: &str,
    message: &[u8],
    signature_b64url: &str,
) -> Result<bool, String> {
    let verifying_key = parse_p256_spki_key(public_key_b64url)?;

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64url)
        .or_else(|_| STANDARD.decode(signature_b64url))
        .map_err(|e| format!("signature base64 decode error: {}", e))?;

    let signature = DerSignature::try_from(sig_bytes.as_slice());
    match signature {
        Ok(sig) => Ok(verifying_key.verify(&message, &sig).is_ok()),
        Err(_) => Ok(false),
    }
}

/// Compute SHA-256 of input bytes, return hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Compute SHA-256 of input bytes, return raw 32-byte array.
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Compute SHA-384 of input bytes, return hex string.
pub fn sha384_hex(data: &[u8]) -> String {
    let mut hasher = Sha384::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Parse a base64-encoded SPKI RSA public key.
pub fn parse_rsa_spki_key(b64: &str) -> Result<RsaPublicKey, String> {
    let raw = b64.split_whitespace().collect::<String>();
    let der_bytes = STANDARD
        .decode(&raw)
        .or_else(|_| URL_SAFE_NO_PAD.decode(&raw))
        .map_err(|e| format!("base64 decode error: {}", e))?;
    RsaPublicKey::from_public_key_der(&der_bytes).map_err(|e| format!("RSA key error: {}", e))
}

/// Verify an RSA PKCS#1 v1.5 signature over a SHA-2 digest of `message`.
pub fn verify_rsa_pkcs1v15_sha256(key: &RsaPublicKey, message: &[u8], signature: &[u8]) -> bool {
    let digest = Sha256::digest(message);
    key.verify(Pkcs1v15Sign::new::<Sha256>(), digest.as_ref(), signature)
        .is_ok()
}

pub fn verify_rsa_pkcs1v15(key: &RsaPublicKey, digest_name: &str, message: &[u8], signature: &[u8]) -> bool {
    match digest_name {
        "sha384" => {
            let digest = Sha384::digest(message);
            key.verify(Pkcs1v15Sign::new::<Sha384>(), digest.as_ref(), signature)
                .is_ok()
        }
        "sha512" => {
            let digest = Sha512::digest(message);
            key.verify(Pkcs1v15Sign::new::<Sha512>(), digest.as_ref(), signature)
                .is_ok()
        }
        _ => verify_rsa_pkcs1v15_sha256(key, message, signature),
    }
}
