// SPDX-License-Identifier: Apache-2.0
// EP-REVOCATION-v1 — revocation statement verification.

use crate::canonical::canonicalize;
use crate::crypto;
use serde_json::{json, Value};

const REVOCATION_VERSION: &str = "EP-REVOCATION-v1";
const TARGET_TYPES: &[&str] = &["receipt", "commit", "delegation"];

pub fn run(vectors: &Value) -> Vec<(String, bool)> {
    let vecs = vectors["vectors"].as_array().unwrap();
    let mut results = Vec::new();

    for v in vecs {
        let id = v["id"].as_str().unwrap().to_string();
        let valid = verify_revocation(
            v.get("target").unwrap_or(&Value::Null),
            v.get("revocation").unwrap_or(&Value::Null),
            v.get("revoker_keys"),
            v.get("max_age_seconds").and_then(|x| x.as_u64()),
            v.get("now").and_then(|x| x.as_str()),
        );
        results.push((id, valid));
    }
    results
}

fn verify_revocation(
    target: &Value,
    statement: &Value,
    revoker_keys: Option<&Value>,
    max_age_seconds: Option<u64>,
    now: Option<&str>,
) -> bool {
    let statement = match statement.as_object() {
        Some(o) => o,
        None => return false,
    };

    if statement
        .get("@version")
        .and_then(|v| v.as_str())
        != Some(REVOCATION_VERSION)
    {
        return false;
    }

    let target = match target.as_object() {
        Some(o) => o,
        None => return false,
    };

    if let Some(tt) = target.get("target_type").and_then(|v| v.as_str()) {
        if !TARGET_TYPES.contains(&tt) {
            return false;
        }
    }
    if statement.get("target_type") != target.get("target_type") {
        return false;
    }
    if statement.get("target_id") != target.get("target_id") {
        return false;
    }
    let stmt_hash = hex_of(
        statement
            .get("action_hash")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    );
    let tgt_hash = hex_of(
        target
            .get("action_hash")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    );
    if stmt_hash != tgt_hash {
        return false;
    }

    let revoker_id = match statement.get("revoker_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return false,
    };

    let pinned = revoker_keys
        .and_then(|k| k.get(revoker_id))
        .and_then(|e| e.get("public_key"))
        .and_then(|v| v.as_str());

    let proof = statement.get("proof").and_then(|v| v.as_object());
    let presented = proof
        .and_then(|p| p.get("public_key"))
        .and_then(|v| v.as_str());

    let pinned = match pinned {
        Some(k) => k,
        None => return false,
    };
    if let Some(p) = presented {
        if p != pinned {
            return false;
        }
    }

    let revoked_ms = match statement
        .get("revoked_at")
        .and_then(|v| v.as_str())
        .and_then(parse_instant_ms)
    {
        Some(ms) => ms,
        None => return false,
    };

    let payload = match revocation_signed_payload(statement) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let sig = proof
        .and_then(|p| p.get("signature_b64u"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !crypto::verify_ed25519(pinned, payload.as_bytes(), sig).unwrap_or(false) {
        return false;
    }

    if let Some(max_age) = max_age_seconds {
        let now_ms = now
            .and_then(parse_instant_ms)
            .unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as f64)
                    .unwrap_or(0.0)
            });
        if (now_ms - revoked_ms) / 1000.0 > max_age as f64 {
            return false;
        }
    }

    true
}

fn revocation_signed_payload(stmt: &serde_json::Map<String, Value>) -> Result<String, ()> {
    let obj = json!({
        "@version": REVOCATION_VERSION,
        "action_hash": stmt.get("action_hash"),
        "reason": stmt.get("reason"),
        "revoked_at": stmt.get("revoked_at"),
        "revoker_id": stmt.get("revoker_id"),
        "target_id": stmt.get("target_id"),
        "target_type": stmt.get("target_type"),
    });
    canonicalize(&obj).map_err(|_| ())
}

fn hex_of(h: &str) -> String {
    h.strip_prefix("sha256:")
        .unwrap_or(h)
        .to_ascii_lowercase()
}

fn parse_instant_ms(s: &str) -> Option<f64> {
    if !is_rfc3339_offset(s) {
        return None;
    }
    parse_rfc3339_ms(s)
}

fn is_rfc3339_offset(value: &str) -> bool {
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

fn parse_rfc3339_ms(s: &str) -> Option<f64> {
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
        days as f64 * 86_400_000.0 + hour as f64 * 3_600_000.0 + minute as f64 * 60_000.0
            + second as f64 * 1000.0 + ms as f64;
    let offset_ms = sign as f64 * (oh as f64 * 3_600_000.0 + om as f64 * 60_000.0);
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