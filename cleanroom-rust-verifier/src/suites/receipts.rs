// SPDX-License-Identifier: Apache-2.0
// EP-RECEIPT-v1 conformance suite (13 vectors).

use crate::crypto;
use crate::jcs;
use crate::merkle;
use serde_json::Value;

pub fn run(vectors: &Value) -> Vec<(String, bool)> {
    let vecs = vectors["vectors"].as_array().unwrap();
    let mut results = Vec::new();

    for v in vecs {
        let id = v["id"].as_str().unwrap().to_string();
        let public_key = v["public_key"].as_str().unwrap();
        let doc = &v["document"];
        let valid = verify_receipt(doc, public_key);
        results.push((id, valid));
    }
    results
}

fn verify_receipt(doc: &Value, public_key: &str) -> bool {
    // 1. Check version
    let version = match doc["@version"].as_str() {
        Some(v) => v,
        None => return false,
    };
    if version != "EP-RECEIPT-v1" {
        return false;
    }

    // 2. Check signature exists
    let sig_val = match doc["signature"]["value"].as_str() {
        Some(s) => s,
        None => return false,
    };

    // 3. Canonicalize payload and verify Ed25519 signature
    let payload = &doc["payload"];
    let canonical = jcs::canonicalize(payload);

    match crypto::verify_ed25519(public_key, &canonical, sig_val) {
        Ok(true) => {}
        _ => return false,
    }

    // 4. If anchor is present, verify it
    if let Some(anchor) = doc.get("anchor") {
        if !anchor.is_null() {
            return verify_anchor(anchor, payload);
        }
    }

    true
}

fn verify_anchor(anchor: &Value, payload: &Value) -> bool {
    // Check for v2 anchor (alg field present)
    let alg = anchor.get("alg").and_then(|a| a.as_str());

    let leaf_hash = match anchor["leaf_hash"].as_str() {
        Some(h) => h,
        None => return false,
    };
    let merkle_root = match anchor["merkle_root"].as_str() {
        Some(r) => r,
        None => return false,
    };
    let proof_arr = match anchor["merkle_proof"].as_array() {
        Some(a) => a,
        None => return false,
    };

    let proof: Vec<(&str, &str)> = proof_arr
        .iter()
        .map(|step| {
            (
                step["hash"].as_str().unwrap_or(""),
                step["position"].as_str().unwrap_or(""),
            )
        })
        .collect();

    if alg == Some("EP-MERKLE-v2") {
        // v2: verify payload binding
        match merkle::verify_merkle_v2_bound(payload, leaf_hash, &proof, merkle_root) {
            Ok(true) => true,
            _ => false,
        }
    } else {
        // Legacy v1: reject by default (per spec and conformance rules)
        false
    }
}
