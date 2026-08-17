// SPDX-License-Identifier: Apache-2.0
// EP-CURRENCY-v1 — receipt currency-at-T evaluation.

use serde_json::Value;

pub fn run(vectors: &Value) -> Vec<(String, bool)> {
    let vecs = vectors["vectors"].as_array().unwrap();
    let mut results = Vec::new();

    for v in vecs {
        let id = v["id"].as_str().unwrap().to_string();
        let args = &v["currency"]["args"];
        let expect_status = v["currency"]["expect_status"]
            .as_str()
            .unwrap_or("");
        let status = evaluate_currency_status(args);
        results.push((id, status == expect_status));
    }
    results
}

fn evaluate_currency_status(args: &Value) -> &'static str {
    let args = match args.as_object() {
        Some(o) => o,
        None => return "unknown",
    };

    let receipt = args.get("receipt");
    let now_ms = match args.get("now") {
        Some(v) if v.is_string() => parse_rfc3339_ms(v.as_str().unwrap_or("")),
        Some(v) if v.is_number() => v.as_f64(),
        _ => None,
    };
    let now_finite = now_ms.map(|m| m.is_finite()).unwrap_or(false);

    let max_staleness = args.get("maxStalenessSeconds");
    let fresh_head = args.get("freshHead");
    let fresh_head_required = args
        .get("freshHeadRequired")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let fresh_head_missing = !args.contains_key("freshHead") || fresh_head.map_or(true, |v| v.is_null());

    if fresh_head_missing {
        if fresh_head_required {
            return "stale";
        }
        return "unknown";
    }

    if !now_finite {
        return "unknown";
    }
    let now_ms = now_ms.unwrap();

    let head = match fresh_head.and_then(|v| v.as_object()) {
        Some(h) => h,
        None => return "unknown",
    };

    let head_ms = head
        .get("observed_at")
        .and_then(|v| v.as_str())
        .and_then(parse_rfc3339_ms)
        .or_else(|| {
            head.get("issued_at")
                .and_then(|v| v.as_str())
                .and_then(parse_rfc3339_ms)
        });
    let head_ms = match head_ms {
        Some(m) => m,
        None => return "unknown",
    };

    let max_sec = match max_staleness {
        Some(v) if v.is_f64() => Some(v.as_f64().unwrap()),
        Some(v) if v.is_u64() => Some(v.as_u64().unwrap() as f64),
        Some(v) if v.is_i64() => Some(v.as_i64().unwrap() as f64),
        _ => None,
    };
    match max_sec {
        Some(s) if s.is_finite() && s >= 0.0 => {}
        _ => return "stale",
    }
    let max_sec = max_sec.unwrap();

    if head_revokes_receipt(head, receipt) {
        return "stale";
    }

    let age_seconds = (now_ms - head_ms) / 1000.0;
    if age_seconds > max_sec {
        return "stale";
    }

    "fresh"
}

fn head_revokes_receipt(fresh_head: &serde_json::Map<String, Value>, receipt: Option<&Value>) -> bool {
    if fresh_head.get("revoked").and_then(|v| v.as_bool()) == Some(true) {
        return true;
    }
    if let Some(lst) = fresh_head.get("revoked_target_hashes").and_then(|v| v.as_array()) {
        if !lst.is_empty() {
            let mut targets = std::collections::HashSet::new();
            for t in lst {
                let h = currency_hex_of(t.as_str().unwrap_or(""));
                if !h.is_empty() {
                    targets.insert(h);
                }
            }
            if !targets.is_empty() {
                let receipt_hash = receipt
                    .and_then(|r| r.get("action_hash"))
                    .and_then(|v| v.as_str())
                    .map(currency_hex_of)
                    .unwrap_or_default();
                let explicit = fresh_head
                    .get("target_hash")
                    .and_then(|v| v.as_str())
                    .map(currency_hex_of)
                    .unwrap_or_default();
                if !receipt_hash.is_empty() && targets.contains(&receipt_hash) {
                    return true;
                }
                if !explicit.is_empty() && targets.contains(&explicit) {
                    return true;
                }
            }
        }
    }
    false
}

fn currency_hex_of(h: &str) -> String {
    let s = h
        .strip_prefix("sha256:")
        .or_else(|| h.strip_prefix("SHA256:"))
        .unwrap_or(h)
        .to_ascii_lowercase();
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        s
    } else {
        String::new()
    }
}

fn parse_rfc3339_ms(s: &str) -> Option<f64> {
    let s = s.trim();
    if !is_rfc3339_currency(s) {
        return None;
    }
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
    let local_ms = days as f64 * 86_400_000.0
        + hour as f64 * 3_600_000.0
        + minute as f64 * 60_000.0
        + second as f64 * 1000.0
        + ms as f64;
    let offset_ms = sign as f64 * (oh as f64 * 3_600_000.0 + om as f64 * 60_000.0);
    Some(local_ms - offset_ms)
}

fn is_rfc3339_currency(value: &str) -> bool {
    if !value.contains('T') {
        return false;
    }
    if value.ends_with('Z') || value.ends_with('z') {
        return true;
    }
    if let Some(idx) = value.rfind('+') {
        let tz = &value[idx..];
        return tz.len() >= 6 && tz.as_bytes().get(3) == Some(&b':');
    }
    if let Some(after_t) = value.split('T').nth(1) {
        if let Some(idx) = after_t.rfind('-') {
            let tz = &after_t[idx..];
            return tz.len() >= 6 && tz.as_bytes().get(3) == Some(&b':');
        }
    }
    false
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