// SPDX-License-Identifier: Apache-2.0
// EP-EVIDENCE-RECORD-v1 — crypto-agile evidence record renewal chain.

use crate::canonical::canonicalize;
use crate::suites::time_attestation;
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384, Sha512};

const EVIDENCE_RECORD_VERSION: &str = "EP-EVIDENCE-RECORD-v1";
const SUPPORTED_HASH: [&str; 3] = ["sha256", "sha384", "sha512"];

pub fn run(vectors: &Value) -> Vec<(String, bool)> {
    let vecs = vectors["vectors"].as_array().unwrap();
    let mut results = Vec::new();

    for v in vecs {
        let id = v["id"].as_str().unwrap().to_string();
        let valid = verify_evidence_record(
            v.get("evidence_record").unwrap_or(&Value::Null),
            v.get("tsa_keys"),
            v.get("protected_hash").and_then(|x| x.as_str()),
        );
        results.push((id, valid));
    }
    results
}

pub fn verify_evidence_record(
    record: &Value,
    tsa_keys: Option<&Value>,
    protected_hash: Option<&str>,
) -> bool {
    let record = match record.as_object() {
        Some(o) => o,
        None => return false,
    };

    if record.get("@version").and_then(|v| v.as_str()) != Some(EVIDENCE_RECORD_VERSION) {
        return false;
    }

    let ats = match record.get("archive_timestamps").and_then(|v| v.as_array()) {
        Some(a) if !a.is_empty() => a,
        _ => return false,
    };

    if let Some(ph) = protected_hash {
        if alg_hex(record.get("protected_hash").and_then(|v| v.as_str()).unwrap_or("")).1
            != alg_hex(ph).1
        {
            return false;
        }
    }

    let mut prev_time: Option<f64> = None;

    for (i, at) in ats.iter().enumerate() {
        let ta = at.get("time_attestation").unwrap_or(&Value::Null);
        if !time_attestation::verify_time_attestation(ta, tsa_keys, None, None, None) {
            return false;
        }

        let (alg, hex_) = alg_hex(ta.get("hashed").and_then(|v| v.as_str()).unwrap_or(""));
        if i == 0 {
            let protected_hex = alg_hex(record.get("protected_hash").and_then(|v| v.as_str()).unwrap_or("")).1;
            if hex_ != protected_hex {
                return false;
            }
        } else if !SUPPORTED_HASH.contains(&alg.as_str()) {
            return false;
        } else {
            let prev_ta = ats[i - 1].get("time_attestation").unwrap_or(&Value::Null);
            let canon = match canonicalize(prev_ta) {
                Ok(s) => s,
                Err(_) => return false,
            };
            let expected = hash_hex(&alg, canon.as_bytes());
            if hex_ != expected {
                return false;
            }
        }

        let time_ms = match ta
            .get("time")
            .and_then(|v| v.as_str())
            .and_then(time_attestation::parse_instant_ms)
        {
            Some(ms) => ms,
            None => return false,
        };
        if let Some(prev) = prev_time {
            if !(time_ms > prev) {
                return false;
            }
        }
        prev_time = Some(time_ms);
    }

    true
}

fn alg_hex(hashed: &str) -> (String, String) {
    if let Some((alg, hex)) = hashed.split_once(':') {
        (alg.to_ascii_lowercase(), hex.to_ascii_lowercase())
    } else {
        ("sha256".to_string(), hashed.to_ascii_lowercase())
    }
}

fn hash_hex(alg: &str, data: &[u8]) -> String {
    match alg {
        "sha384" => {
            let mut hasher = Sha384::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
        "sha512" => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
        _ => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
    }
}

