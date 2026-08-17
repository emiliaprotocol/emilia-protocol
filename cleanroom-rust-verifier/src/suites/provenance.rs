// SPDX-License-Identifier: Apache-2.0
// EP-PROVENANCE-CHAIN-v1 — offline delegated provenance verification.

use crate::canonical::canonicalize;
use crate::crypto;
use crate::suites::time_attestation;
use crate::suites::trust_receipt::VerifyOpts;
use crate::suites::trust_receipt;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};

const PROVENANCE_VERSION: &str = "EP-PROVENANCE-CHAIN-v1";
const DELEGATION_PROOF_FIELDS: [&str; 7] = [
    "delegation_id",
    "delegator",
    "delegatee",
    "scope",
    "max_value_usd",
    "expires_at",
    "constraints",
];

pub fn run(vectors: &Value) -> Vec<(String, bool)> {
    let vecs = vectors["vectors"].as_array().unwrap();
    let mut results = Vec::new();

    for v in vecs {
        let id = v["id"].as_str().unwrap().to_string();
        let now_ms = v
            .get("now_ms")
            .and_then(|x| x.as_f64())
            .or_else(|| v.get("now_ms").and_then(|x| x.as_u64().map(|n| n as f64)))
            .unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as f64)
                    .unwrap_or(0.0)
            });
        let valid = verify_provenance_offline(
            v.get("provenance_chain").unwrap_or(&Value::Null),
            v.get("delegation_keys"),
            now_ms,
        );
        results.push((id, valid));
    }
    results
}

pub fn verify_provenance_offline(doc: &Value, delegation_keys: Option<&Value>, now_ms: f64) -> bool {
    let doc = match doc.as_object() {
        Some(o) => o,
        None => return false,
    };

    if doc.get("@version").and_then(|v| v.as_str()) != Some(PROVENANCE_VERSION) {
        return false;
    }

    let root = match doc.get("root_signoff") {
        Some(r) if r.get("receipt").is_some() && r.get("verification").is_some() => r,
        _ => return false,
    };
    let opts = VerifyOpts {
        allow_legacy_merkle: false,
    };
    if !trust_receipt::verify_trust_receipt(
        root.get("receipt").unwrap(),
        root.get("verification").unwrap(),
        &opts,
    ) || !has_human_signoff(root.get("receipt").unwrap(), &["A"])
    {
        return false;
    }

    let exec = doc.get("execution").cloned().unwrap_or(Value::Null);
    let approval = doc.get("action_approval");
    let need_approval = true;
    if need_approval && approval.and_then(|a| a.get("receipt")).is_none() {
        return false;
    }

    if let Some(approval) = approval {
        if let Some(receipt) = approval.get("receipt") {
            let verification = approval.get("verification").unwrap_or(&Value::Null);
            let opts = VerifyOpts {
                allow_legacy_merkle: false,
            };
            if !trust_receipt::verify_trust_receipt(receipt, verification, &opts) {
                return false;
            }
            if exec.get("irreversible").and_then(|v| v.as_bool()) == Some(true) {
                if !has_human_signoff(receipt, &["A"]) {
                    return false;
                }
            }
            let exec_hash = hex_of(exec.get("action_hash").and_then(|v| v.as_str()).unwrap_or(""));
            let receipt_hash = hex_of(receipt.get("action_hash").and_then(|v| v.as_str()).unwrap_or(""));
            if exec_hash != receipt_hash {
                return false;
            }
        }
    }

    let mut chain: Vec<&Value> = doc
        .get("delegation_chain")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().collect())
        .unwrap_or_default();
    chain.sort_by_key(|link| link.get("sequence").and_then(|v| v.as_u64()).unwrap_or(0));

    let root_receipt = root.get("receipt").unwrap();
    let root_approvers = receipt_approvers(root_receipt);
    let root_expiry = latest_context_expiry(root_receipt);
    let root_at = root_receipt
        .get("action")
        .and_then(|a| a.get("action_type"))
        .and_then(|v| v.as_str());
    let root_scope: Vec<Value> = root_at.map(|s| json!(s)).into_iter().collect();

    let mut parent = json!({
        "scope": root_scope,
        "max_value_usd": Value::Null,
        "expires_at": root_expiry_iso(root_expiry),
        "constraints": json!({}),
    });

    if !chain.is_empty() {
        let head = chain[0];
        let parent_ref = head.get("parent_ref").and_then(|v| v.as_str()).unwrap_or("");
        let delegator = head.get("delegator").and_then(|v| v.as_str()).unwrap_or("");
        if !root_approvers.contains(parent_ref) && !root_approvers.contains(delegator) {
            return false;
        }
    }

    let mut prev_delegatee: Option<&str> = None;
    for link in chain {
        if let Some(prev) = prev_delegatee {
            let parent_ref = link.get("parent_ref").and_then(|v| v.as_str()).unwrap_or("");
            let delegator = link.get("delegator").and_then(|v| v.as_str()).unwrap_or("");
            if parent_ref != prev || delegator != prev {
                return false;
            }
        }

        let exp = link
            .get("expires_at")
            .and_then(|v| v.as_str())
            .and_then(time_attestation::parse_instant_ms);
        if exp.is_none() || exp.unwrap() < now_ms {
            return false;
        }

        if let Some(proof) = link.get("proof") {
            if !verify_detached_signature(proof) {
                return false;
            }
            let presented = decode_b64url_bytes(
                proof
                    .get("signed_payload_b64u")
                    .and_then(|v| v.as_str())
                    .unwrap_or(""),
            );
            let expected = delegation_proof_bytes(link);
            if presented.as_deref() != Some(expected.as_slice()) {
                return false;
            }
            let delegator = link.get("delegator").and_then(|v| v.as_str()).unwrap_or("");
            let bound_key = delegation_keys
                .and_then(|k| k.get(delegator))
                .and_then(|e| e.get("public_key"))
                .and_then(|v| v.as_str());
            let proof_key = proof.get("public_key").and_then(|v| v.as_str());
            if bound_key.is_none() || bound_key != proof_key {
                return false;
            }
        } else {
            return false;
        }

        if !scope_containment_violations(&parent, link).is_empty() {
            return false;
        }
        if !constraints_monotonic(
            parent.get("constraints").unwrap_or(&Value::Null),
            link.get("constraints").unwrap_or(&Value::Null),
        ) {
            return false;
        }

        let parent_cap = parent.get("max_value_usd");
        let link_cap = link.get("max_value_usd");
        let eff_cap = match (parent_cap, link_cap) {
            (None | Some(Value::Null), _) => link_cap.cloned(),
            (_, None | Some(Value::Null)) => parent_cap.cloned(),
            (Some(p), Some(c)) => {
                let pv = p.as_f64().or_else(|| p.as_u64().map(|n| n as f64));
                let cv = c.as_f64().or_else(|| c.as_u64().map(|n| n as f64));
                match (pv, cv) {
                    (Some(pf), Some(cf)) => Some(json!(pf.min(cf))),
                    _ => link_cap.cloned(),
                }
            }
        };
        parent = json!({
            "delegation_id": link.get("delegation_id"),
            "delegator": link.get("delegator"),
            "delegatee": link.get("delegatee"),
            "scope": link.get("scope"),
            "max_value_usd": eff_cap,
            "expires_at": link.get("expires_at"),
            "constraints": link.get("constraints"),
        });
        prev_delegatee = link.get("delegatee").and_then(|v| v.as_str());
    }

    let action_type = approval
        .and_then(|a| a.get("receipt"))
        .and_then(|r| r.get("action"))
        .and_then(|a| a.get("action_type"))
        .and_then(|v| v.as_str());
    let action_type = match action_type {
        Some(t) => t,
        None => return false,
    };
    if !scope_permits(parent.get("scope"), action_type) {
        return false;
    }

    let commit = approval
        .and_then(|a| a.get("receipt"))
        .and_then(|r| r.get("consumption"))
        .and_then(|c| c.get("committed_at"))
        .and_then(|v| v.as_str())
        .and_then(time_attestation::parse_instant_ms);
    let leaf_exp = parent
        .get("expires_at")
        .and_then(|v| v.as_str())
        .and_then(time_attestation::parse_instant_ms);
    if let (Some(c), Some(le)) = (commit, leaf_exp) {
        if c > le {
            return false;
        }
    }

    true
}

fn has_human_signoff(receipt: &Value, human_classes: &[&str]) -> bool {
    let class_set: std::collections::HashSet<&str> = human_classes.iter().copied().collect();
    receipt
        .get("signoffs")
        .and_then(|v| v.as_array())
        .map(|sos| {
            sos.iter().any(|so| {
                so.get("key_class")
                    .and_then(|v| v.as_str())
                    .map(|c| class_set.contains(c))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

fn receipt_approvers(receipt: &Value) -> std::collections::HashSet<String> {
    let mut ids = std::collections::HashSet::new();
    if let Some(ctxs) = receipt.get("contexts").and_then(|v| v.as_array()) {
        for ctx in ctxs {
            if let Some(a) = ctx.get("approver").and_then(|v| v.as_str()) {
                ids.insert(a.to_string());
            }
        }
    }
    if let Some(sos) = receipt.get("signoffs").and_then(|v| v.as_array()) {
        for so in sos {
            if let Some(id) = so.get("approver_key_id").and_then(|v| v.as_str()) {
                ids.insert(id.to_string());
            }
        }
    }
    ids
}

fn latest_context_expiry(receipt: &Value) -> Option<f64> {
    let mut mx: Option<f64> = None;
    if let Some(ctxs) = receipt.get("contexts").and_then(|v| v.as_array()) {
        for ctx in ctxs {
            if let Some(t) = ctx
                .get("expires_at")
                .and_then(|v| v.as_str())
                .and_then(time_attestation::parse_instant_ms)
            {
                if mx.map(|m| t > m).unwrap_or(true) {
                    mx = Some(t);
                }
            }
        }
    }
    mx
}

fn root_expiry_iso(root_expiry: Option<f64>) -> Value {
    root_expiry
        .map(|ms| {
            let secs = (ms / 1000.0).floor() as i64;
            let nanos = ((ms % 1000.0) * 1_000_000.0).round() as u32;
            let dt = chrono_from_unix_ms(secs, nanos);
            Value::String(dt)
        })
        .unwrap_or(Value::Null)
}

fn chrono_from_unix_ms(secs: i64, millis_frac: u32) -> String {
    // Format UTC ISO without external chrono dependency.
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;
    let (y, m, d) = civil_from_days(days);
    if millis_frac > 0 {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            y,
            m,
            d,
            hour,
            minute,
            second,
            millis_frac / 1_000_000
        )
    } else {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            y, m, d, hour, minute, second
        )
    }
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (mp + if mp < 10 { 3 } else { -9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn scope_permits(scope: Option<&Value>, action_type: &str) -> bool {
    let scope = match scope.and_then(|v| v.as_array()) {
        Some(s) => s,
        None => return false,
    };
    if action_type.is_empty() {
        return false;
    }
    for grant in scope {
        let grant = match grant.as_str() {
            Some(g) => g,
            None => continue,
        };
        if grant == "*" || grant == action_type {
            return true;
        }
        if grant.ends_with(".*") {
            let prefix = &grant[..grant.len() - 2];
            if action_type == prefix || action_type.starts_with(&format!("{}.", prefix)) {
                return true;
            }
        }
    }
    false
}

fn scope_containment_violations(parent: &Value, child: &Value) -> Vec<&'static str> {
    let mut viol = Vec::new();
    if let Some(scope) = child.get("scope").and_then(|v| v.as_array()) {
        for token in scope {
            let probe = match token.as_str() {
                Some(t) if t.ends_with(".*") => &t[..t.len() - 2],
                Some(t) => t,
                None => continue,
            };
            if !scope_permits(parent.get("scope"), probe) {
                viol.push("scope exceeds parent");
            }
        }
    }
    let parent_cap = parent.get("max_value_usd");
    let child_cap = child.get("max_value_usd");
    let child_eff = if child_cap.is_none() || child_cap == Some(&Value::Null) {
        parent_cap
    } else {
        child_cap
    };
    if let Some(pc) = parent_cap {
        if pc.is_null() {
            // no parent cap
        } else {
            let pf = pc.as_f64().or_else(|| pc.as_u64().map(|n| n as f64));
            let cf = child_eff
                .and_then(|c| c.as_f64().or_else(|| c.as_u64().map(|n| n as f64)));
            if let Some(pf) = pf {
                if cf.map(|c| c > pf).unwrap_or(true) {
                    viol.push("cap exceeds parent");
                }
            }
        }
    }
    let p_exp = parent
        .get("expires_at")
        .and_then(|v| v.as_str())
        .and_then(time_attestation::parse_instant_ms);
    let c_exp = child
        .get("expires_at")
        .and_then(|v| v.as_str())
        .and_then(time_attestation::parse_instant_ms);
    if let (Some(pe), Some(ce)) = (p_exp, c_exp) {
        if ce > pe {
            viol.push("expiry after parent");
        }
    }
    viol
}

fn constraints_monotonic(parent_c: &Value, child_c: &Value) -> bool {
    let parent_c = parent_c.as_object();
    let child_c = child_c.as_object();
    let parent_c = match parent_c {
        Some(o) => o,
        None => return true,
    };
    let child_c = match child_c {
        Some(o) => o,
        None => return parent_c.is_empty(),
    };
    for (k, pv) in parent_c {
        let cv = match child_c.get(k) {
            Some(v) => v,
            None => return false,
        };
        if let (Some(pn), Some(cn)) = (pv.as_f64(), cv.as_f64()) {
            if cn > pn {
                return false;
            }
        } else if pv.is_array() && cv.is_array() {
            let pset: std::collections::HashSet<String> = pv
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|x| canonicalize(x).ok())
                .collect();
            for x in cv.as_array().unwrap() {
                let cx = match canonicalize(x) {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                if !pset.contains(&cx) {
                    return false;
                }
            }
        } else {
            let pc = canonicalize(pv).ok();
            let cc = canonicalize(cv).ok();
            if pc != cc {
                return false;
            }
        }
    }
    true
}

fn verify_detached_signature(att: &Value) -> bool {
    let signed_payload = att.get("signed_payload_b64u").and_then(|v| v.as_str());
    let signature = att.get("signature_b64u").and_then(|v| v.as_str());
    let public_key = att.get("public_key").and_then(|v| v.as_str());
    if signed_payload.is_none() || signature.is_none() || public_key.is_none() {
        return false;
    }
    if let Some(alg) = att.get("algorithm").and_then(|v| v.as_str()) {
        if alg != "Ed25519" {
            return false;
        }
    }
    let payload = match decode_b64url_bytes(signed_payload.unwrap()) {
        Some(b) => b,
        None => return false,
    };
    crypto::verify_ed25519(public_key.unwrap(), &payload, signature.unwrap()).unwrap_or(false)
}

fn delegation_proof_bytes(link: &Value) -> Vec<u8> {
    let mut obj = serde_json::Map::new();
    for field in DELEGATION_PROOF_FIELDS {
        if let Some(v) = link.get(field) {
            obj.insert(field.to_string(), v.clone());
        }
    }
    canonicalize(&Value::Object(obj))
        .map(|s| s.into_bytes())
        .unwrap_or_default()
}

fn decode_b64url_bytes(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

fn hex_of(h: &str) -> String {
    h.strip_prefix("sha256:")
        .unwrap_or(h)
        .to_ascii_lowercase()
}