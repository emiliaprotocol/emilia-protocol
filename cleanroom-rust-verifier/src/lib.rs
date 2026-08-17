use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub mod error;
pub mod canonical;
pub mod jcs;
pub mod crypto;
pub mod merkle;
pub mod suites;
pub mod external_statement;

pub use error::Error;
pub use canonical::{canonicalize, is_canonicalizable, strict_parse_gate};

// Re-export key shared verification helpers used across suites
pub use suites::trust_receipt::verify_trust_receipt;
pub use suites::time_attestation::{verify_time_attestation, parse_instant_ms};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifyOpts {
    pub strict: Option<bool>,
    pub rp_id: Option<String>,
    pub expected_policy_hash: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CurrencyResult {
    pub authentic_as_of_commit: bool,
    pub currency_at_t: CurrencyAtT,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CurrencyAtT {
    pub status: String,
    pub evaluated_at: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Cosignature {
    pub witness_id: String,
    pub signature: String,
}

pub fn verify_receipt(document: &str, public_key_b64: &str) -> Result<bool, Error> {
    strict_parse_gate(document)?;
    
    let val: serde_json::Value = serde_json::from_str(document)
        .map_err(|e| Error::InvalidFormat(e.to_string()))?;
        
    let obj = val.as_object()
        .ok_or_else(|| Error::InvalidFormat("receipt must be a JSON object".to_string()))?;
        
    let version = obj.get("@version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::InvalidFormat("missing @version".to_string()))?;
        
    if version != "EP-RECEIPT-v1" {
        return Ok(false);
    }
    
    let payload = obj.get("payload")
        .ok_or_else(|| Error::InvalidFormat("missing payload".to_string()))?;
        
    let signature_obj = obj.get("signature")
        .and_then(|s| s.as_object())
        .ok_or_else(|| Error::InvalidFormat("missing or invalid signature object".to_string()))?;
        
    let signature_val = signature_obj.get("value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::InvalidFormat("missing signature value".to_string()))?;
        
    let signature_alg = signature_obj.get("algorithm")
        .and_then(|a| a.as_str())
        .ok_or_else(|| Error::InvalidFormat("missing signature algorithm".to_string()))?;
        
    if signature_alg != "Ed25519" {
        return Ok(false);
    }
    
    if !is_canonicalizable(payload) {
        return Ok(false);
    }
    
    let payload_str = canonicalize(payload)?;
    
    let pub_key_bytes = decode_base64url(public_key_b64)?;
    if pub_key_bytes.len() != 44 {
        return Ok(false);
    }
    let expected_header = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    if &pub_key_bytes[0..12] != expected_header {
        return Ok(false);
    }
    let raw_pub_key = &pub_key_bytes[12..];
    
    let sig_bytes = decode_base64url(signature_val)?;
    
    use ed25519_dalek::{VerifyingKey, Signature, Verifier};
    
    let raw_pub_key_arr: &[u8; 32] = match raw_pub_key.try_into() {
        Ok(arr) => arr,
        Err(_) => return Ok(false),
    };
    
    let verifying_key = match VerifyingKey::from_bytes(raw_pub_key_arr) {
        Ok(vk) => vk,
        Err(_) => return Ok(false),
    };
    
    let signature = match Signature::from_slice(&sig_bytes) {
        Ok(sig) => sig,
        Err(_) => return Ok(false),
    };
    
    let verified = verifying_key.verify(payload_str.as_bytes(), &signature).is_ok();
    
    Ok(verified)
}

fn decode_base64url(s: &str) -> Result<Vec<u8>, Error> {
    use base64::{Engine as _, engine::general_purpose::{URL_SAFE_NO_PAD, URL_SAFE}};
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(&cleaned) {
        Ok(bytes)
    } else if let Ok(bytes) = URL_SAFE.decode(&cleaned) {
        Ok(bytes)
    } else {
        Err(Error::InvalidFormat("Failed to decode base64url".to_string()))
    }
}

pub fn verify_webauthn_signoff(signoff_json: &str, approver_pk_b64: &str, rp_id: Option<&str>) -> Result<bool, Error> {
    let rp_id = match rp_id {
        Some(id) => id,
        None => return Ok(false),
    };

    let signoff: Value = serde_json::from_str(signoff_json)
        .map_err(|e| Error::InvalidFormat(e.to_string()))?;

    let context = signoff.get("context").ok_or_else(|| Error::InvalidFormat("missing context".to_string()))?;
    let webauthn = signoff.get("webauthn").ok_or_else(|| Error::InvalidFormat("missing webauthn".to_string()))?;

    if !is_canonicalizable(context) {
        return Ok(false);
    }

    let canonical = jcs::canonicalize(context);
    let context_hash = Sha256::digest(&canonical);
    let expected_challenge = URL_SAFE_NO_PAD.encode(context_hash);

    let cdj_b64 = match webauthn.get("client_data_json").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return Ok(false),
    };
    let cdj_bytes = match URL_SAFE_NO_PAD.decode(cdj_b64) {
        Ok(b) => b,
        Err(_) => return Ok(false),
    };
    let cdj: Value = match serde_json::from_slice(&cdj_bytes) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };

    if cdj.get("type").and_then(|v| v.as_str()) != Some("webauthn.get") {
        return Ok(false);
    }
    if cdj.get("challenge").and_then(|v| v.as_str()) != Some(expected_challenge.as_str()) {
        return Ok(false);
    }
    if cdj.get("origin").and_then(|v| v.as_str()).is_none() {
        return Ok(false);
    }

    let auth_data_b64 = match webauthn.get("authenticator_data").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return Ok(false),
    };
    let auth_data = match URL_SAFE_NO_PAD.decode(auth_data_b64) {
        Ok(b) => b,
        Err(_) => return Ok(false),
    };
    if auth_data.len() < 37 {
        return Ok(false);
    }

    let rp_id_hash = Sha256::digest(rp_id.as_bytes());
    if auth_data[..32] != rp_id_hash[..] {
        return Ok(false);
    }

    let flags = auth_data[32];
    if flags & 0x01 == 0 || flags & 0x04 == 0 {
        return Ok(false);
    }

    let cdj_hash = Sha256::digest(&cdj_bytes);
    let mut signed_data = auth_data;
    signed_data.extend_from_slice(&cdj_hash);

    let sig_b64 = match webauthn.get("signature").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return Ok(false),
    };

    match crypto::verify_p256(approver_pk_b64, &signed_data, sig_b64) {
        Ok(true) => Ok(true),
        _ => Ok(false),
    }
}

pub fn verify_quorum(_quorum_json: &str, _rp_id: &str) -> Result<bool, Error> {
    Ok(false)
}

pub fn verify_revocation(_target_json: &str, _revocation_json: &str, _revoker_keys: &[String], _max_age_secs: Option<u64>, _now: u64) -> Result<bool, Error> {
    Ok(false)
}

pub fn verify_provenance_offline(_provenance_chain_json: &str, _delegation_keys: &[String], _now_ms: u64) -> Result<bool, Error> {
    Ok(false)
}

pub fn verify_evidence_record(_evidence_record_json: &str, _tsa_keys: &[String], _protected_hash: &str) -> Result<bool, Error> {
    Ok(false)
}

pub fn evaluate_currency(_args_json: &str) -> Result<CurrencyResult, Error> {
    Ok(CurrencyResult {
        authentic_as_of_commit: false,
        currency_at_t: CurrencyAtT {
            status: "unknown".to_string(),
            evaluated_at: None,
            reason: "stub".to_string(),
        }
    })
}

pub fn validate_initiator_attestation(_attestation_json: &str) -> Result<bool, Error> {
    Ok(false)
}

pub fn verify_consumption_proof(_proof_json: &str) -> Result<bool, Error> {
    Ok(false)
}

pub fn require_witness_quorum(_checkpoint_json: &str, _cosignatures: &[Cosignature], _pinned: &[String], _k: usize) -> Result<bool, Error> {
    Ok(false)
}

pub fn verify_timestamp_proof(_proof_json: &str, _expected_digest: Option<&str>, _pinned_tsa_keys: Option<&[String]>) -> Result<bool, Error> {
    Ok(false)
}
