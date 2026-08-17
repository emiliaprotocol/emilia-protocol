// SPDX-License-Identifier: Apache-2.0
// EP-SMT-CONSUME-v1 — sparse-Merkle nonce consumption transition proofs.

use crate::crypto::sha256_bytes;
use serde_json::Value;
use sha2::{Digest, Sha256};

const SMT_DEPTH: usize = 32;

pub fn run(vectors: &Value) -> Vec<(String, bool)> {
    let vecs = vectors["vectors"].as_array().unwrap();
    let mut results = Vec::new();

    for v in vecs {
        let id = v["id"].as_str().unwrap().to_string();
        let valid = verify_consumption_proof(&v["consumption_proof"]);
        results.push((id, valid));
    }
    results
}

fn verify_consumption_proof(bundle: &Value) -> bool {
    let bundle = match bundle.as_object() {
        Some(o) => o,
        None => return false,
    };

    let nonce = match bundle.get("nonce").and_then(|v| v.as_str()) {
        Some(n) if !n.is_empty() => n,
        _ => return false,
    };
    let key_hex = smt_nonce_key_hex(nonce);

    let ni = match bundle.get("non_inclusion_proof") {
        Some(v) => v,
        None => return false,
    };
    if ni.get("present").and_then(|v| v.as_bool()) != Some(false) {
        return false;
    }
    if !smt_check_sub(ni, &key_hex, false) {
        return false;
    }

    let inc = match bundle.get("inclusion_proof") {
        Some(v) => v,
        None => return false,
    };
    if inc.get("present").and_then(|v| v.as_bool()) != Some(true) {
        return false;
    }
    if !smt_check_sub_present(inc, &key_hex) {
        return false;
    }

    let ni_root = hex_of(ni.get("root").and_then(|v| v.as_str()).unwrap_or(""));
    let inc_root = hex_of(inc.get("root").and_then(|v| v.as_str()).unwrap_or(""));
    if ni_root == inc_root {
        return false;
    }

    let cps = match bundle.get("checkpoints").and_then(|v| v.as_object()) {
        Some(o) => o,
        None => return false,
    };
    let h1 = match cps.get("h1") {
        Some(v) => v,
        None => return false,
    };
    let h2 = match cps.get("h2") {
        Some(v) => v,
        None => return false,
    };

    let h1_size = match h1.get("tree_size").and_then(|v| v.as_u64()) {
        Some(n) if n >= 1 => n,
        _ => return false,
    };
    let h2_size = match h2.get("tree_size").and_then(|v| v.as_u64()) {
        Some(n) if n >= 1 => n,
        _ => return false,
    };
    let h1_root = hex_of(
        h1.get("root_hash")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    );
    let h2_root = hex_of(
        h2.get("root_hash")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    );
    if !is_hex64(&h1_root) || !is_hex64(&h2_root) {
        return false;
    }
    if h1_size >= h2_size {
        return false;
    }

    let proof = match bundle.get("consistency_proof").and_then(|v| v.as_array()) {
        Some(p) => p,
        None => return false,
    };

    verify_checkpoint_consistency(&h1_root, h1_size, &h2_root, h2_size, proof)
}

fn smt_check_sub(sub: &Value, key_hex: &str, present: bool) -> bool {
    let sub = match sub.as_object() {
        Some(o) => o,
        None => return false,
    };
    let root = hex_of(sub.get("root").and_then(|v| v.as_str()).unwrap_or(""));
    if !is_hex64(&root) {
        return false;
    }
    let siblings = match sub.get("siblings").and_then(|v| v.as_array()) {
        Some(s) if s.len() == SMT_DEPTH => s,
        _ => return false,
    };

    let leaf = if present {
        return false;
    } else {
        smt_default_leaf()
    };

    smt_fold_to_root(&leaf, siblings, key_hex) == Some(root)
}

fn smt_check_sub_present(sub: &Value, key_hex: &str) -> bool {
    let sub = match sub.as_object() {
        Some(o) => o,
        None => return false,
    };
    let root = hex_of(sub.get("root").and_then(|v| v.as_str()).unwrap_or(""));
    if !is_hex64(&root) {
        return false;
    }
    let siblings = match sub.get("siblings").and_then(|v| v.as_array()) {
        Some(s) if s.len() == SMT_DEPTH => s,
        _ => return false,
    };
    let value = hex_of(sub.get("value").and_then(|v| v.as_str()).unwrap_or(""));
    if !is_hex64(&value) {
        return false;
    }

    let leaf = smt_present_leaf(key_hex, &value);
    smt_fold_to_root(&leaf, siblings, key_hex) == Some(root)
}

fn smt_fold_to_root(leaf_hex: &str, siblings: &[Value], key_hex: &str) -> Option<String> {
    if !is_hex64(leaf_hex) {
        return None;
    }
    let mut node = leaf_hex.to_string();
    for level in (0..SMT_DEPTH).rev() {
        let sib = hex_of(
            siblings[level]
                .as_str()
                .unwrap_or(""),
        );
        if !is_hex64(&sib) {
            return None;
        }
        let bit = smt_path_bit(key_hex, level);
        node = if bit == 0 {
            hash_pair_v2_hex(&node, &sib)
        } else {
            hash_pair_v2_hex(&sib, &node)
        };
    }
    Some(node)
}

fn smt_present_leaf(key_hex: &str, value_hex: &str) -> String {
    let mut input = Vec::with_capacity(1 + key_hex.len() + value_hex.len());
    input.push(0x02);
    input.extend_from_slice(key_hex.as_bytes());
    input.extend_from_slice(value_hex.as_bytes());
    hex::encode(sha256_bytes(&input))
}

fn smt_default_leaf() -> String {
    hex::encode(sha256_bytes(&[0x03]))
}

fn smt_nonce_key_hex(nonce: &str) -> String {
    hex::encode(Sha256::digest(nonce.as_bytes()))
}

fn smt_path_bit(key_hex: &str, i: usize) -> u8 {
    let byte_index = i >> 3;
    let start = byte_index * 2;
    let byte = u8::from_str_radix(&key_hex[start..start + 2], 16).unwrap_or(0);
    (byte >> (7 - (i & 7))) & 1
}

fn hash_pair_v2_hex(left: &str, right: &str) -> String {
    let mut input = Vec::with_capacity(1 + left.len() + right.len());
    input.push(0x01);
    input.extend_from_slice(left.as_bytes());
    input.extend_from_slice(right.as_bytes());
    hex::encode(sha256_bytes(&input))
}

fn verify_checkpoint_consistency(
    old_root: &str,
    old_size: u64,
    new_root: &str,
    new_size: u64,
    proof: &[Value],
) -> bool {
    if old_size > new_size {
        return false;
    }
    if proof.len() > 64 {
        return false;
    }

    if old_size == new_size {
        return proof.is_empty() && old_root == new_root;
    }
    if old_size == 0 || proof.is_empty() {
        return false;
    }

    let mut path: Vec<String> = proof
        .iter()
        .map(|h| hex_of(h.as_str().unwrap_or("")))
        .collect();
    if path.iter().any(|h| !is_hex64(h)) {
        return false;
    }

    let (seed, node) = if is_power_of_two(old_size) {
        (old_root.to_string(), path)
    } else {
        if path.is_empty() {
            return false;
        }
        let seed = path.remove(0);
        (seed, path)
    };

    let mut fn_idx = old_size - 1;
    let mut sn_idx = new_size - 1;
    while fn_idx % 2 == 1 {
        fn_idx /= 2;
        sn_idx /= 2;
    }

    let mut fr = seed.clone();
    let mut sr = seed;

    for c in node {
        if sn_idx == 0 {
            return false;
        }
        if fn_idx % 2 == 1 || fn_idx == sn_idx {
            fr = hash_pair_v2_hex(&c, &fr);
            sr = hash_pair_v2_hex(&c, &sr);
            while fn_idx % 2 == 0 && fn_idx != 0 {
                fn_idx /= 2;
                sn_idx /= 2;
            }
        } else {
            sr = hash_pair_v2_hex(&sr, &c);
        }
        fn_idx /= 2;
        sn_idx /= 2;
    }

    sn_idx == 0 && fr == old_root && sr == new_root
}

fn is_power_of_two(n: u64) -> bool {
    n > 0 && (n & (n - 1)) == 0
}

fn hex_of(h: &str) -> String {
    h.strip_prefix("sha256:")
        .unwrap_or(h)
        .to_ascii_lowercase()
}

fn is_hex64(h: &str) -> bool {
    h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())
}