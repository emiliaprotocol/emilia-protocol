// SPDX-License-Identifier: Apache-2.0
// EP-QUORUM-v1 — Multi-party quorum verification (13 vectors).

use crate::crypto;
use crate::jcs;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};
use serde_json::Value;
use std::collections::HashSet;

pub fn run(vectors: &Value) -> Vec<(String, bool)> {
    let vecs = vectors["vectors"].as_array().unwrap();
    let mut results = Vec::new();

    for v in vecs {
        let id = v["id"].as_str().unwrap().to_string();
        let valid = verify_quorum(&v["quorum"]);
        results.push((id, valid));
    }
    results
}

fn parse_rfc3339_ms(s: &str) -> Option<u64> {
    // Vectors use Z-terminated RFC3339 with optional fractional seconds.
    let s = s.trim();
    if !s.ends_with('Z') {
        return None;
    }
    let core = &s[..s.len() - 1];
    let (date_time, frac_ms) = if let Some((dt, frac)) = core.split_once('.') {
        let ms: u64 = frac.chars().take(3).collect::<String>().parse().ok()?;
        (dt, ms)
    } else {
        (core, 0)
    };
    let (date, time) = date_time.split_once('T')?;
    let mut date_parts = date.split('-');
    let year: i32 = date_parts.next()?.parse().ok()?;
    let month: u32 = date_parts.next()?.parse().ok()?;
    let day: u32 = date_parts.next()?.parse().ok()?;

    let mut time_parts = time.split(':');
    let hour: u32 = time_parts.next()?.parse().ok()?;
    let minute: u32 = time_parts.next()?.parse().ok()?;
    let second: u32 = time_parts.next()?.parse().ok()?;
    let days_from_civil = |y: i32, m: u32, d: u32| -> i32 {
        let m = m as i32;
        let y = if m <= 2 { y - 1 } else { y };
        let m = if m <= 2 { m + 12 } else { m };
        let era = if y >= 0 { y / 400 } else { -1 - (-1 - y) / 400 };
        let yoe = y - era * 400;
        let doy = (153 * (m - 3) + 2) / 5 + d as i32 - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146097 + doe - 719468
    };
    let day = days_from_civil(year, month, day) as i64;
    let secs = day * 86_400 + hour as i64 * 3600 + minute as i64 * 60 + second as i64;
    Some((secs as u64) * 1000 + frac_ms)
}

fn is_eligible_slot(policy: &Value, role: &str, approver: &str) -> bool {
    policy
        .get("approvers")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter().any(|slot| {
                slot.get("role").and_then(|v| v.as_str()) == Some(role)
                    && slot.get("approver").and_then(|v| v.as_str()) == Some(approver)
            })
        })
        .unwrap_or(false)
}

fn verify_quorum(quorum: &Value) -> bool {
    let action_hash = match quorum["action_hash"].as_str() {
        Some(h) => h,
        None => return false,
    };
    let policy = &quorum["policy"];
    let members = match quorum["members"].as_array() {
        Some(m) => m,
        None => return false,
    };

    let required = match policy["required"].as_u64() {
        Some(r) => r as usize,
        None => return false,
    };

    let mode = policy["mode"].as_str().unwrap_or("threshold");
    let is_ordered = mode == "ordered" || policy.get("ordered_chain").and_then(|v| v.as_bool()).unwrap_or(false);

    if members.len() < required {
        return false;
    }

    let mut seen_keys = HashSet::new();
    let mut seen_approvers = HashSet::new();
    let mut prev_context_hash: Option<String> = None;
    let mut issued_times: Vec<u64> = Vec::new();

    let rp_id = "emiliaprotocol.ai";

    for (i, member) in members.iter().enumerate() {
        let pk = match member["approver_public_key"].as_str() {
            Some(k) => k,
            None => return false,
        };
        let role = member["role"].as_str().unwrap_or("");
        let signoff = &member["signoff"];
        let context = &signoff["context"];
        let webauthn = &signoff["webauthn"];

        let approver = context["approver"].as_str().unwrap_or("");
        let initiator = context["initiator"].as_str().unwrap_or("");

        if approver == initiator {
            return false;
        }

        if !is_eligible_slot(policy, role, approver) {
            return false;
        }

        if !seen_approvers.insert(approver.to_string()) {
            return false;
        }

        if !seen_keys.insert(pk.to_string()) {
            return false;
        }

        if context["action_hash"].as_str() != Some(action_hash) {
            return false;
        }

        if let Some(issued_at) = context.get("issued_at").and_then(|v| v.as_str()) {
            if let Some(ms) = parse_rfc3339_ms(issued_at) {
                if let Some(prev) = issued_times.last() {
                    if is_ordered && ms <= *prev {
                        return false;
                    }
                }
                issued_times.push(ms);
            } else {
                return false;
            }
        } else {
            return false;
        }

        if is_ordered && i > 0 {
            if let Some(ref expected_prev) = prev_context_hash {
                match context["prev_context_hash"].as_str() {
                    Some(actual_prev) if actual_prev == expected_prev => {}
                    _ => return false,
                }
            }
        }

        let canonical = jcs::canonicalize(context);
        let context_hash_bytes = Sha256::digest(&canonical);
        let context_hash_hex = hex::encode(context_hash_bytes);
        prev_context_hash = Some(context_hash_hex.clone());

        let expected_challenge = URL_SAFE_NO_PAD.encode(context_hash_bytes);

        let cdj_b64 = match webauthn["client_data_json"].as_str() {
            Some(s) => s,
            None => return false,
        };
        let cdj_bytes = match URL_SAFE_NO_PAD.decode(cdj_b64) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let cdj: Value = match serde_json::from_slice(&cdj_bytes) {
            Ok(v) => v,
            Err(_) => return false,
        };

        if cdj["type"].as_str() != Some("webauthn.get") {
            return false;
        }
        if cdj["challenge"].as_str() != Some(&expected_challenge) {
            return false;
        }

        let auth_data_b64 = match webauthn["authenticator_data"].as_str() {
            Some(s) => s,
            None => return false,
        };
        let auth_data = match URL_SAFE_NO_PAD.decode(auth_data_b64) {
            Ok(b) => b,
            Err(_) => return false,
        };

        if auth_data.len() < 37 {
            return false;
        }

        let rp_id_hash = Sha256::digest(rp_id.as_bytes());
        if auth_data[..32] != rp_id_hash[..] {
            return false;
        }

        let flags = auth_data[32];
        if flags & 0x01 == 0 || flags & 0x04 == 0 {
            return false;
        }

        let cdj_hash = Sha256::digest(&cdj_bytes);
        let mut signed_data = auth_data.clone();
        signed_data.extend_from_slice(&cdj_hash);

        let sig_b64 = match webauthn["signature"].as_str() {
            Some(s) => s,
            None => return false,
        };

        match crypto::verify_p256(pk, &signed_data, sig_b64) {
            Ok(true) => {}
            _ => return false,
        }
    }

    if let Some(window_sec) = policy["window_sec"].as_u64() {
        if issued_times.len() >= 2 {
            let min = *issued_times.iter().min().unwrap();
            let max = *issued_times.iter().max().unwrap();
            if max.saturating_sub(min) > window_sec * 1000 {
                return false;
            }
        }
    }

    if let Some(policy_approvers) = policy["approvers"].as_array() {
        if is_ordered {
            for (i, member) in members.iter().enumerate() {
                if i < policy_approvers.len() {
                    let expected_role = policy_approvers[i]["role"].as_str().unwrap_or("");
                    let expected_approver = policy_approvers[i]["approver"].as_str().unwrap_or("");
                    let actual_role = member["role"].as_str().unwrap_or("");
                    let actual_approver = member["signoff"]["context"]["approver"].as_str().unwrap_or("");
                    if expected_role != actual_role || expected_approver != actual_approver {
                        return false;
                    }
                }
            }
        }
    }

    true
}