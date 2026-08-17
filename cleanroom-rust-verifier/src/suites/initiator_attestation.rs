// SPDX-License-Identifier: Apache-2.0
// EP-INITIATOR-ATTESTATION-v1 — initiator software attestation validation.

use serde_json::Value;

const INITIATOR_ATTESTATION_VERSION: &str = "EP-INITIATOR-ATTESTATION-v1";
const INITIATOR_STATEMENT_MAX: usize = 280;

const ALLOWED_MEMBERS: &[&str] = &[
    "@version",
    "model_id",
    "model_version",
    "tool_chain_digest",
    "statement",
];

pub fn run(vectors: &Value) -> Vec<(String, bool)> {
    let vecs = vectors["vectors"].as_array().unwrap();
    let mut results = Vec::new();

    for v in vecs {
        let id = v["id"].as_str().unwrap().to_string();
        let valid = validate_initiator_attestation(&v["initiator_attestation"]);
        results.push((id, valid));
    }
    results
}

fn validate_initiator_attestation(att: &Value) -> bool {
    let obj = match att.as_object() {
        Some(o) => o,
        None => return false,
    };

    for key in obj.keys() {
        if !ALLOWED_MEMBERS.contains(&key.as_str()) {
            return false;
        }
    }

    if let Some(ver) = obj.get("@version").and_then(|v| v.as_str()) {
        if ver != INITIATOR_ATTESTATION_VERSION {
            return false;
        }
    }

    for key in ["model_id", "model_version"] {
        match obj.get(key).and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => {}
            _ => return false,
        }
    }

    let digest = match obj.get("tool_chain_digest") {
        Some(v) => normalize_digest(v.as_str().unwrap_or("")),
        None => return false,
    };
    if digest.is_empty() {
        return false;
    }

    if let Some(stmt) = obj.get("statement") {
        if stmt.is_null() {
            // absent statement is fine
        } else if let Some(s) = stmt.as_str() {
            if s.chars().count() > INITIATOR_STATEMENT_MAX {
                return false;
            }
            let _ = neutralize_statement(s);
        } else {
            return false;
        }
    }

    true
}

fn normalize_digest(h: &str) -> String {
    let lower = h.to_ascii_lowercase();
    let s = lower.strip_prefix("sha256:").unwrap_or(&lower);
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        s.to_string()
    } else {
        String::new()
    }
}

fn neutralize_statement(statement: &str) -> NeutralizeReport {
    let bounded: String = statement.chars().take(INITIATOR_STATEMENT_MAX).collect();
    let truncated = statement.chars().count() > INITIATOR_STATEMENT_MAX;

    let mut out = String::new();
    let mut changed = false;
    let mut has_non_ascii_letter = false;
    let mut has_ascii_letter = false;
    let mut has_confusable_script = false;

    for ch in bounded.chars() {
        let cp = ch as u32;
        if ch.is_ascii_alphabetic() {
            has_ascii_letter = true;
        }
        if cp > 0x7f && ch.is_alphabetic() {
            has_non_ascii_letter = true;
        }
        if (0x0400..=0x04ff).contains(&cp) || (0x0370..=0x03ff).contains(&cp) {
            has_confusable_script = true;
        }

        if is_bidi(cp) || is_invisible(cp) || is_hostile_control(cp) {
            changed = true;
            out.push_str(&format!("<U+{:04X}>", cp));
        } else {
            out.push(ch);
        }
    }

    let homoglyph_risk = has_confusable_script || (has_non_ascii_letter && has_ascii_letter);

    NeutralizeReport {
        safe: out,
        changed,
        homoglyph_risk,
        truncated,
    }
}

#[allow(dead_code)]
struct NeutralizeReport {
    safe: String,
    changed: bool,
    homoglyph_risk: bool,
    truncated: bool,
}

fn is_bidi(cp: u32) -> bool {
    matches!(
        cp,
        0x202a | 0x202b | 0x202c | 0x202d | 0x202e | 0x2066 | 0x2067 | 0x2068 | 0x2069
            | 0x200e | 0x200f | 0x061c
    )
}

fn is_invisible(cp: u32) -> bool {
    matches!(cp, 0x200b | 0x200c | 0x200d | 0x2060 | 0xfeff)
}

fn is_hostile_control(cp: u32) -> bool {
    (cp <= 0x1f && cp != 0x09 && cp != 0x0a && cp != 0x0d) || (0x7f..=0x9f).contains(&cp)
}