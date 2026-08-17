// SPDX-License-Identifier: Apache-2.0
// EP-WITNESS-v1 — k-of-n witness cosignature quorum.

use crate::canonical::canonicalize;
use crate::crypto;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

const WITNESS_VERSION: &str = "EP-WITNESS-v1";
const WITNESS_DOMAIN_TAG: &[u8] = b"EP-WITNESS-COSIGN-v1\0";

pub fn run(vectors: &Value) -> Vec<(String, bool)> {
    let vecs = vectors["vectors"].as_array().unwrap();
    let mut results = Vec::new();

    for v in vecs {
        let id = v["id"].as_str().unwrap().to_string();
        let wq = &v["witness_quorum"];
        let k = match coerce_k(wq.get("k")) {
            Some(k) => k,
            None => {
                results.push((id, false));
                continue;
            }
        };
        let empty: Vec<Value> = Vec::new();
        let cosigs = wq
            .get("cosignatures")
            .and_then(|v| v.as_array())
            .unwrap_or(&empty);
        let pinned = wq
            .get("pinned")
            .and_then(|v| v.as_array())
            .unwrap_or(&empty);
        let valid = require_witness_quorum(
            wq.get("checkpoint").unwrap_or(&Value::Null),
            cosigs,
            pinned,
            k,
        );
        results.push((id, valid));
    }
    results
}

fn coerce_k(value: Option<&Value>) -> Option<u64> {
    match value {
        None => None,
        Some(v) => {
            if let Some(n) = v.as_u64() {
                if n >= 1 {
                    Some(n)
                } else {
                    None
                }
            } else if let Some(i) = v.as_i64() {
                if i >= 1 {
                    Some(i as u64)
                } else {
                    None
                }
            } else {
                None
            }
        }
    }
}

fn require_witness_quorum(
    checkpoint: &Value,
    cosignatures: &[Value],
    pinned_witness_keys: &[Value],
    k: u64,
) -> bool {
    if k < 1 {
        return false;
    }
    let checkpoint = match checkpoint.as_object() {
        Some(o) => o,
        None => return false,
    };

    let mut pinned_by_id: HashMap<String, &Value> = HashMap::new();
    let mut seen_pinned = HashSet::new();
    for w in pinned_witness_keys {
        let wid = match w.get("witness_id").and_then(|v| v.as_str()) {
            Some(id) if !id.is_empty() => id,
            _ => continue,
        };
        if !seen_pinned.insert(wid.to_string()) {
            pinned_by_id.remove(wid);
            continue;
        }
        pinned_by_id.insert(wid.to_string(), w);
    }

    let mut met = HashSet::new();
    for cosig in cosignatures {
        let cid = match cosig.get("witness_id").and_then(|v| v.as_str()) {
            Some(id) if !id.is_empty() => id,
            _ => continue,
        };
        if met.contains(cid) {
            continue;
        }
        let pinned = match pinned_by_id.get(cid) {
            Some(p) => *p,
            None => continue,
        };
        if verify_witness_cosignature(checkpoint, cosig, pinned) {
            met.insert(cid.to_string());
        }
    }

    met.len() >= k as usize
}

fn verify_witness_cosignature(
    checkpoint: &serde_json::Map<String, Value>,
    cosignature: &Value,
    pinned_witness_key: &Value,
) -> bool {
    let cosig = match cosignature.as_object() {
        Some(o) => o,
        None => return false,
    };

    let pinned_id = match pinned_witness_key
        .get("witness_id")
        .and_then(|v| v.as_str())
    {
        Some(id) if !id.is_empty() => id,
        _ => return false,
    };
    let public_key = match pinned_witness_key
        .get("public_key")
        .and_then(|v| v.as_str())
    {
        Some(k) if !k.is_empty() => k,
        _ => return false,
    };

    let co_id = match cosig.get("witness_id").and_then(|v| v.as_str()) {
        Some(id) if !id.is_empty() => id,
        _ => return false,
    };
    if co_id != pinned_id {
        return false;
    }

    if let Some(alg) = cosig.get("alg").and_then(|v| v.as_str()) {
        if alg != WITNESS_VERSION {
            return false;
        }
    }

    let sig = match cosig.get("signature").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s,
        _ => return false,
    };

    if let Some(ts) = cosig.get("tree_size") {
        if checkpoint.get("tree_size") != Some(ts) {
            return false;
        }
    }
    if let Some(rh) = cosig.get("root_hash").and_then(|v| v.as_str()) {
        let cp_rh = checkpoint
            .get("root_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if hex_of(rh) != hex_of(cp_rh) {
            return false;
        }
    }
    if let Some(lid) = cosig.get("log_key_id").and_then(|v| v.as_str()) {
        let cp_lid = checkpoint
            .get("log_key_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if lid != cp_lid {
            return false;
        }
    }

    let digest = match witness_signing_digest(checkpoint) {
        Some(d) => d,
        None => return false,
    };

    crypto::verify_ed25519(public_key, &digest, sig).unwrap_or(false)
}

fn witness_signing_digest(checkpoint: &serde_json::Map<String, Value>) -> Option<Vec<u8>> {
    let mut signed = checkpoint.clone();
    signed.remove("log_signature");
    let canon = canonicalize(&Value::Object(signed)).ok()?;
    let mut preimage = Vec::with_capacity(WITNESS_DOMAIN_TAG.len() + canon.len());
    preimage.extend_from_slice(WITNESS_DOMAIN_TAG);
    preimage.extend_from_slice(canon.as_bytes());
    Some(Sha256::digest(&preimage).to_vec())
}

fn hex_of(h: &str) -> String {
    h.strip_prefix("sha256:")
        .unwrap_or(h)
        .to_ascii_lowercase()
}