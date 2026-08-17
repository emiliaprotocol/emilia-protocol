// SPDX-License-Identifier: Apache-2.0
// EP-SIGNOFF-v1 — Class A WebAuthn device signoff verification (9 vectors).

use crate::verify_webauthn_signoff;
use serde_json::Value;

pub fn run(vectors: &Value) -> Vec<(String, bool)> {
    let vecs = vectors["vectors"].as_array().unwrap();
    let mut results = Vec::new();

    for v in vecs {
        let id = v["id"].as_str().unwrap().to_string();
        let rp_id = v["rp_id"].as_str().unwrap();
        let approver_pk = v["approver_public_key"].as_str().unwrap();
        let signoff = &v["signoff"];
        let valid = if let Ok(so_str) = serde_json::to_string(signoff) {
            verify_webauthn_signoff(&so_str, approver_pk, Some(rp_id)).unwrap_or(false)
        } else {
            false
        };
        results.push((id, valid));
    }
    results
}