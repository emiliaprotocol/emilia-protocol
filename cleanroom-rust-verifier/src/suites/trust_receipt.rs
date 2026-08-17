// SPDX-License-Identifier: Apache-2.0
// EP-TRUST-RECEIPT-v1 — §6.2 trust receipt verification.

use crate::canonical::{canonicalize, is_canonicalizable};
use crate::crypto;
use crate::merkle;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};

const MERKLE_V2_ALG: &str = "EP-MERKLE-v2";

pub struct VerifyOpts {
    pub allow_legacy_merkle: bool,
}

pub fn run(vectors: &Value) -> Vec<(String, bool)> {
    let vecs = vectors["vectors"].as_array().unwrap();
    let mut results = Vec::new();

    for v in vecs {
        let id = v["id"].as_str().unwrap().to_string();
        let receipt = &v["trust_receipt"];
        let verification = &v["verification"];
        let opts = VerifyOpts {
            allow_legacy_merkle: v
                .get("verify_opts")
                .and_then(|o| o.get("allowLegacyMerkle"))
                .and_then(|b| b.as_bool())
                .unwrap_or(false),
        };
        let valid = verify_trust_receipt(receipt, verification, &opts);
        results.push((id, valid));
    }
    results
}

pub fn verify_trust_receipt(receipt: &Value, verification: &Value, opts: &VerifyOpts) -> bool {
    let approver_keys = match verification.get("approver_keys").and_then(|v| v.as_object()) {
        Some(k) => k,
        None => return false,
    };
    let log_public_key = match verification.get("log_public_key").and_then(|v| v.as_str()) {
        Some(k) => k,
        None => return false,
    };

    let contexts = match receipt.get("contexts").and_then(|v| v.as_array()) {
        Some(c) if !c.is_empty() => c,
        _ => return false,
    };
    let signoffs = match receipt.get("signoffs").and_then(|v| v.as_array()) {
        Some(s) if !s.is_empty() => s,
        _ => return false,
    };
    let action = match receipt.get("action") {
        Some(a) => a,
        None => return false,
    };
    let action_hash_field = match receipt.get("action_hash").and_then(|v| v.as_str()) {
        Some(h) => h,
        None => return false,
    };

    if trust_receipt_profile_error(receipt).is_some() {
        return false;
    }

    let canonical_scope = receipt_scope_without_log(receipt);
    if !is_canonicalizable(&canonical_scope) {
        return false;
    }

    let action_canon = match canonicalize(action) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let action_hash_hex = hex::encode(Sha256::digest(action_canon.as_bytes()));
    if hex_of(action_hash_field) != action_hash_hex {
        return false;
    }

    let mut context_by_hash = std::collections::HashMap::new();
    let mut policy_hashes = std::collections::HashSet::new();
    for ctx in contexts {
        if !is_canonicalizable(ctx) {
            return false;
        }
        let ctx_canon = match canonicalize(ctx) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let digest_hex = hex::encode(Sha256::digest(ctx_canon.as_bytes()));
        context_by_hash.insert(digest_hex.clone(), ctx);

        if hex_of(ctx.get("action_hash").and_then(|v| v.as_str()).unwrap_or("")) != action_hash_hex {
            return false;
        }
        let policy_hash = match ctx.get("policy_hash").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => return false,
        };
        policy_hashes.insert(hex_of(policy_hash));
        if ctx.get("approver").and_then(|v| v.as_str()).is_none() {
            return false;
        }
    }
    if policy_hashes.len() != 1 {
        return false;
    }

    let mut valid_approvals: Vec<(&Value, &Value, &str)> = Vec::new();
    for signoff in signoffs {
        let context_hash = match signoff.get("context_hash").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => return false,
        };
        let digest_hex = hex_of(context_hash);
        let ctx = match context_by_hash.get(&digest_hex) {
            Some(c) => *c,
            None => return false,
        };

        let key_id = match signoff.get("approver_key_id").and_then(|v| v.as_str()) {
            Some(id) => id,
            None => return false,
        };
        let key_entry = match approver_keys.get(key_id) {
            Some(e) => e,
            None => return false,
        };
        let public_key = match key_entry.get("public_key").and_then(|v| v.as_str()) {
            Some(k) => k,
            None => return false,
        };

        let issued_at = match ctx.get("issued_at").and_then(|v| v.as_str()) {
            Some(t) => t,
            None => return false,
        };
        let valid_from = key_entry.get("valid_from").and_then(|v| v.as_str());
        let valid_to = key_entry.get("valid_to").and_then(|v| v.as_str());
        if !within_window(issued_at, valid_from, valid_to) {
            return false;
        }

        let digest_bytes = match hex::decode(&digest_hex) {
            Ok(b) if b.len() == 32 => b,
            _ => return false,
        };

        let key_class = key_entry
            .get("key_class")
            .and_then(|v| v.as_str())
            .or_else(|| signoff.get("key_class").and_then(|v| v.as_str()))
            .unwrap_or("B");

        let sig_ok = if key_class == "A" {
            signoff.get("webauthn").map_or(false, |wa| {
                verify_class_a_over_digest(wa, &digest_bytes, public_key)
            })
        } else {
            let sig = signoff.get("signature").and_then(|v| v.as_str()).unwrap_or("");
            crypto::verify_ed25519(public_key, &digest_bytes, sig).unwrap_or(false)
        };
        if !sig_ok {
            return false;
        }

        let signed_at = match signoff.get("signed_at").and_then(|v| v.as_str()) {
            Some(t) => t,
            None => return false,
        };
        valid_approvals.push((ctx, signoff, signed_at));
    }

    let initiator = action.get("initiator").and_then(|v| v.as_str()).unwrap_or("");
    let mut approvers = Vec::new();
    for (ctx, _, _) in &valid_approvals {
        let approver = ctx.get("approver").and_then(|v| v.as_str()).unwrap_or("");
        if initiator == approver {
            return false;
        }
        approvers.push(approver);
    }
    let mut seen = std::collections::HashSet::new();
    for a in &approvers {
        if !seen.insert(*a) {
            return false;
        }
    }

    let mut required_values: Vec<u64> = Vec::new();
    for ctx in contexts {
        match coerce_required_approvals(ctx.get("required_approvals")) {
            Some(n) => required_values.push(n),
            None => return false,
        }
    }
    let required_approvals = required_values.iter().copied().max().unwrap_or(1).max(1);
    if valid_approvals.len() < required_approvals as usize {
        return false;
    }

    let log_proof = match receipt.get("log_proof") {
        Some(lp) => lp,
        None => return false,
    };
    let inclusion_path = match log_proof.get("inclusion_path").and_then(|v| v.as_array()) {
        Some(p) => p,
        None => return false,
    };
    let checkpoint = match log_proof.get("checkpoint") {
        Some(c) => c,
        None => return false,
    };

    let leaf_canon = match canonicalize(&receipt_scope_without_log(receipt)) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let merkle_alg = log_proof
        .get("alg")
        .and_then(|v| v.as_str())
        .or_else(|| checkpoint.get("merkle_alg").and_then(|v| v.as_str()));

    if inclusion_path.is_empty() {
        let tree_size = checkpoint.get("tree_size").and_then(|v| v.as_u64());
        if tree_size != Some(1) {
            return false;
        }
        if let Some(idx) = log_proof.get("leaf_index").and_then(|v| v.as_u64()) {
            if idx != 0 {
                return false;
            }
        }
    }

    let root_hex = match checkpoint.get("root_hash").and_then(|v| v.as_str()) {
        Some(h) => hex_of(h),
        None => return false,
    };

    let inclusion_ok = if merkle_alg == Some(MERKLE_V2_ALG) {
        let leaf_hash = merkle::leaf_hash_v2_from_canonical_string(&leaf_canon).unwrap_or_default();
        let presented = log_proof
            .get("leaf_hash")
            .and_then(|v| v.as_str())
            .map(hex_of)
            .unwrap_or_else(|| leaf_hash.clone());
        if presented != leaf_hash {
            false
        } else {
            verify_trust_merkle_anchor(&leaf_hash, inclusion_path, &root_hex, true)
        }
    } else if opts.allow_legacy_merkle {
        let leaf_hash = hex::encode(Sha256::digest(leaf_canon.as_bytes()));
        verify_trust_merkle_anchor(&leaf_hash, inclusion_path, &root_hex, false)
    } else {
        false
    };
    if !inclusion_ok {
        return false;
    }

    let log_sig = match checkpoint.get("log_signature").and_then(|v| v.as_str()) {
        Some(s) => s.strip_prefix("b64u:").unwrap_or(s),
        None => return false,
    };
    let mut signed_checkpoint = checkpoint.clone();
    if let Some(obj) = signed_checkpoint.as_object_mut() {
        obj.remove("log_signature");
    }
    let cp_canon = match canonicalize(&signed_checkpoint) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let cp_digest = Sha256::digest(cp_canon.as_bytes());
    if !crypto::verify_ed25519(log_public_key, &cp_digest, log_sig).unwrap_or(false) {
        return false;
    }

    let committed_at = match receipt.get("consumption").and_then(|c| c.get("committed_at")).and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return false,
    };
    for (ctx, _, signed_at) in &valid_approvals {
        let issued = ctx.get("issued_at").and_then(|v| v.as_str()).unwrap_or("");
        let expires = ctx.get("expires_at").and_then(|v| v.as_str()).unwrap_or("");
        if !within_window(signed_at, Some(issued), Some(expires)) {
            return false;
        }
        if !within_window(committed_at, Some(issued), Some(expires)) {
            return false;
        }
    }

    true
}

fn receipt_scope_without_log(receipt: &Value) -> Value {
    let mut obj = serde_json::Map::new();
    if let Some(map) = receipt.as_object() {
        for (k, v) in map {
            if k != "log_proof" && k != "approver_key_proofs" {
                obj.insert(k.clone(), v.clone());
            }
        }
    }
    Value::Object(obj)
}

fn trust_receipt_profile_error(receipt: &Value) -> Option<&'static str> {
    let scope = receipt_scope_without_log(receipt);
    if !is_canonicalizable(&scope) {
        return Some("Trust Receipt body");
    }
    if let Some(cp) = receipt.get("log_proof").and_then(|lp| lp.get("checkpoint")) {
        let mut signed = cp.clone();
        if let Some(obj) = signed.as_object_mut() {
            obj.remove("log_signature");
        }
        if !is_canonicalizable(&signed) {
            return Some("Trust Receipt checkpoint");
        }
    }
    None
}

fn hex_of(h: &str) -> String {
    h.strip_prefix("sha256:")
        .unwrap_or(h)
        .to_ascii_lowercase()
}

fn coerce_required_approvals(value: Option<&Value>) -> Option<u64> {
    match value {
        None => Some(1),
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

fn parse_instant(value: &str) -> Option<i64> {
    if !is_rfc3339_with_offset(value) {
        return None;
    }
    chrono_parse_ms(value)
}

fn is_rfc3339_with_offset(value: &str) -> bool {
    let s = value.trim();
    if !s.contains('T') {
        return false;
    }
    if s.ends_with('Z') || s.ends_with('z') {
        return true;
    }
    if let Some(idx) = s.rfind('+') {
        let tz = &s[idx..];
        return tz.len() >= 6 && tz.as_bytes().get(3) == Some(&b':');
    }
    if let Some(after_t) = s.split('T').nth(1) {
        if let Some(idx) = after_t.rfind('-') {
            let tz = &after_t[idx..];
            return tz.len() >= 6 && tz.as_bytes().get(3) == Some(&b':');
        }
    }
    false
}

fn chrono_parse_ms(value: &str) -> Option<i64> {
    parse_rfc3339_ms(value)
}

fn parse_rfc3339_ms(s: &str) -> Option<i64> {
    let s = s.trim();
    let (date, rest) = s.split_once('T')?;
    let (time_core, offset) = split_time_offset(rest)?;

    let mut ymd = date.split('-');
    let year: i32 = ymd.next()?.parse().ok()?;
    let month: u32 = ymd.next()?.parse().ok()?;
    let day: u32 = ymd.next()?.parse().ok()?;

    let mut hms_parts = time_core.split(':');
    let hour: u32 = hms_parts.next()?.parse().ok()?;
    let minute: u32 = hms_parts.next()?.parse().ok()?;
    let sec_str = hms_parts.next()?;
    let (second, ms) = if let Some((sec, frac)) = sec_str.split_once('.') {
        let sec: u32 = sec.parse().ok()?;
        let mut frac_str: String = frac.chars().take(3).collect();
        while frac_str.len() < 3 {
            frac_str.push('0');
        }
        let ms: u64 = frac_str.parse().ok()?;
        (sec, ms)
    } else {
        (sec_str.parse().ok()?, 0)
    };

    let sign: i64 = if offset.starts_with('-') { -1 } else { 1 };
    let off = offset.strip_prefix('+').or_else(|| offset.strip_prefix('-'))?;
    let mut offp = off.split(':');
    let oh: i64 = offp.next()?.parse().ok()?;
    let om: i64 = offp.next().unwrap_or("0").parse().ok()?;

    let days = days_from_civil(year, month, day) as i64;
    let local_ms =
        days * 86_400_000 + hour as i64 * 3_600_000 + minute as i64 * 60_000 + second as i64 * 1000 + ms as i64;
    let offset_ms = sign * (oh * 3_600_000 + om * 60_000);
    Some(local_ms - offset_ms)
}

fn split_time_offset(rest: &str) -> Option<(&str, &str)> {
    if let Some(idx) = rest.rfind('Z') {
        return Some((&rest[..idx], "+00:00"));
    }
    if let Some(idx) = rest.rfind('+') {
        return Some((&rest[..idx], &rest[idx..]));
    }
    if rest.len() > 6 {
        if let Some(idx) = rest.rfind('-') {
            if rest[idx..].contains(':') {
                return Some((&rest[..idx], &rest[idx..]));
            }
        }
    }
    None
}

fn days_from_civil(y: i32, m: u32, d: u32) -> i32 {
    let m = m as i32;
    let y = if m <= 2 { y - 1 } else { y };
    let m = if m <= 2 { m + 12 } else { m };
    let era = if y >= 0 { y / 400 } else { -1 - (-1 - y) / 400 };
    let yoe = y - era * 400;
    let doy = (153 * (m - 3) + 2) / 5 + d as i32 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn within_window(t: &str, from: Option<&str>, to: Option<&str>) -> bool {
    let ts = match parse_instant(t) {
        Some(v) => v,
        None => return false,
    };
    if let Some(f) = from {
        if let Some(fv) = parse_instant(f) {
            if ts < fv {
                return false;
            }
        } else {
            return false;
        }
    }
    if let Some(g) = to {
        if let Some(gv) = parse_instant(g) {
            if ts > gv {
                return false;
            }
        } else {
            return false;
        }
    }
    true
}

fn verify_trust_merkle_anchor(leaf_hex: &str, path: &[Value], root_hex: &str, v2: bool) -> bool {
    let steps: Vec<(String, String)> = path
        .iter()
        .filter_map(|step| {
            if let Some(h) = step.as_str() {
                Some((hex_of(h), "right".to_string()))
            } else {
                let hash = step.get("hash").and_then(|v| v.as_str())?;
                let pos = step.get("position").and_then(|v| v.as_str())?;
                Some((hex_of(hash), pos.to_string()))
            }
        })
        .collect();
    let step_refs: Vec<(&str, &str)> = steps
        .iter()
        .map(|(h, p)| (h.as_str(), p.as_str()))
        .collect();
    merkle::verify_merkle_proof_hex(leaf_hex, &step_refs, root_hex, v2).unwrap_or(false)
}

fn verify_class_a_over_digest(webauthn: &Value, digest_bytes: &[u8], public_key: &str) -> bool {
    let auth_b64 = match webauthn.get("authenticator_data").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return false,
    };
    let cdj_b64 = match webauthn.get("client_data_json").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return false,
    };
    let sig_b64 = match webauthn.get("signature").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return false,
    };

    let auth_data = match URL_SAFE_NO_PAD.decode(auth_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let cdj_bytes = match URL_SAFE_NO_PAD.decode(cdj_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let cdj: Value = match serde_json::from_slice(&cdj_bytes) {
        Ok(v) => v,
        Err(_) => return false,
    };

    if cdj.get("type").and_then(|v| v.as_str()) != Some("webauthn.get") {
        return false;
    }

    let expected_challenge = URL_SAFE_NO_PAD.encode(digest_bytes);
    if cdj.get("challenge").and_then(|v| v.as_str()) != Some(expected_challenge.as_str()) {
        return false;
    }

    if auth_data.len() < 37 {
        return false;
    }
    let flags = auth_data[32];
    if flags & 0x01 == 0 || flags & 0x04 == 0 {
        return false;
    }

    let cdj_hash = Sha256::digest(&cdj_bytes);
    let mut signed_data = auth_data;
    signed_data.extend_from_slice(&cdj_hash);

    crypto::verify_p256(public_key, &signed_data, sig_b64).unwrap_or(false)
}