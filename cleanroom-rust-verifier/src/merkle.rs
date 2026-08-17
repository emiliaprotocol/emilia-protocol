// SPDX-License-Identifier: Apache-2.0
//
// Merkle inclusion proof verification.
//
// EP receipt anchors use hex-string hashes throughout:
// - v2 leaf binding: SHA-256(0x00 || JCS(payload)) → lowercase hex
// - v2 internal pair: SHA-256(0x01 || utf8(left_hex || right_hex)), positional
// - v1 internal pair: SHA-256(utf8(sorted(left_hex, right_hex).join()))

use crate::crypto::sha256_bytes;
use crate::jcs;
use serde_json::Value;

fn is_lower_hex(s: &str) -> bool {
    !s.is_empty() && s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// v2 payload-bound leaf: SHA-256(0x00 || canonical payload bytes) as hex.
pub fn leaf_hash_v2_bound(payload: &Value) -> Result<String, String> {
    let canonical = jcs::canonicalize(payload);
    leaf_hash_v2_from_canonical_string(std::str::from_utf8(&canonical).map_err(|e| e.to_string())?)
}

/// v2 trust-receipt leaf: SHA-256(0x00 || utf8(canonical string)) as hex.
pub fn leaf_hash_v2_from_canonical_string(canonical: &str) -> Result<String, String> {
    let mut input = Vec::with_capacity(1 + canonical.len());
    input.push(0x00);
    input.extend_from_slice(canonical.as_bytes());
    Ok(hex::encode(sha256_bytes(&input)))
}

fn hash_pair_v1_hex(left: &str, right: &str) -> String {
    let (lo, hi) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    let mut input = lo.as_bytes().to_vec();
    input.extend_from_slice(hi.as_bytes());
    hex::encode(sha256_bytes(&input))
}

fn hash_pair_v2_hex(left: &str, right: &str) -> String {
    let mut input = Vec::with_capacity(1 + left.len() + right.len());
    input.push(0x01);
    input.extend_from_slice(left.as_bytes());
    input.extend_from_slice(right.as_bytes());
    hex::encode(sha256_bytes(&input))
}

/// Walk a receipt-style merkle_proof (hex strings + left/right positions).
pub fn verify_merkle_proof_hex(
    leaf_hash: &str,
    proof: &[(&str, &str)],
    merkle_root: &str,
    v2: bool,
) -> Result<bool, String> {
    if !is_lower_hex(leaf_hash) || !is_lower_hex(merkle_root) {
        return Ok(false);
    }
    if proof.len() > 20 {
        return Ok(false);
    }

    let mut current = leaf_hash.to_string();
    for (sibling, position) in proof {
        if !is_lower_hex(sibling) {
            return Ok(false);
        }
        current = match (*position, v2) {
            ("left", true) => hash_pair_v2_hex(sibling, &current),
            ("right", true) => hash_pair_v2_hex(&current, sibling),
            ("left", false) => hash_pair_v1_hex(sibling, &current),
            ("right", false) => hash_pair_v1_hex(&current, sibling),
            _ => return Ok(false),
        };
    }

    Ok(current == merkle_root)
}

/// Verify a v2 Merkle anchor with domain-separated payload binding.
pub fn verify_merkle_v2_bound(
    payload: &Value,
    leaf_hash: &str,
    proof: &[(&str, &str)],
    merkle_root: &str,
) -> Result<bool, String> {
    let expected_leaf = leaf_hash_v2_bound(payload)?;
    if expected_leaf != leaf_hash {
        return Ok(false);
    }
    verify_merkle_proof_hex(leaf_hash, proof, merkle_root, true)
}

/// Verify a v2 Merkle inclusion path for trust receipts (raw bytes + sha256: prefix).
pub fn verify_merkle_v2_inclusion(
    leaf_hash_hex: &str,
    inclusion_path: &[String],
    merkle_root_hex: &str,
    tree_size: Option<u64>,
    leaf_index: Option<u64>,
) -> Result<bool, String> {
    let leaf_hex = leaf_hash_hex
        .strip_prefix("sha256:")
        .unwrap_or(leaf_hash_hex);
    let root_hex = merkle_root_hex
        .strip_prefix("sha256:")
        .unwrap_or(merkle_root_hex);

    if inclusion_path.is_empty() {
        if let Some(ts) = tree_size {
            if ts != 1 {
                return Ok(false);
            }
        }
        if let Some(li) = leaf_index {
            if li != 0 {
                return Ok(false);
            }
        }
        return Ok(leaf_hex == root_hex);
    }

    let mut current = hex::decode(leaf_hex).map_err(|e| format!("hex decode leaf: {}", e))?;
    let mut idx = leaf_index.unwrap_or(0);

    for step_hex in inclusion_path {
        let step_hex_clean = step_hex.strip_prefix("sha256:").unwrap_or(step_hex);
        let sibling = hex::decode(step_hex_clean).map_err(|e| format!("hex decode: {}", e))?;

        let combined = if idx % 2 == 0 {
            let mut data = current.clone();
            data.extend_from_slice(&sibling);
            data
        } else {
            let mut data = sibling.clone();
            data.extend_from_slice(&current);
            data
        };

        let mut domain_input = Vec::with_capacity(1 + combined.len());
        domain_input.push(0x01);
        domain_input.extend_from_slice(&combined);
        current = sha256_bytes(&domain_input).to_vec();
        idx /= 2;
    }

    Ok(hex::encode(&current) == root_hex)
}