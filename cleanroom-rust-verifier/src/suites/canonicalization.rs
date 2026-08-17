// SPDX-License-Identifier: Apache-2.0
//
// Canonicalization conformance suite (EP-CANONICALIZATION-v1).
// 35 vectors testing RFC 8785 JCS canonicalization, strict parse gates, and EP I-JSON profile.

use crate::crypto::sha256_hex;
use crate::jcs;
use serde_json::Value;

/// Result for a single canonicalization vector.
pub struct CanonicalizationResult {
    pub id: String,
    pub valid: bool,
}

/// Run the canonicalization suite.
pub fn run(vectors: &Value) -> Vec<CanonicalizationResult> {
    let vecs = vectors["vectors"].as_array().unwrap();
    let mut results = Vec::new();

    for v in vecs {
        let id = v["id"].as_str().unwrap().to_string();
        let expected_valid = v["expect"]["valid"].as_bool().unwrap();
        let input_json = v["canonicalization"]["input_json"].as_str().unwrap();

        let valid = match process_canonicalization(input_json) {
            Ok(digest) => {
                if let Some(expected) = v["canonicalization"]["expected_digest"].as_str() {
                    digest == expected
                } else {
                    // Accept vector with no expected_digest - shouldn't happen
                    true
                }
            }
            Err(_) => false,
        };

        if valid != expected_valid {
            eprintln!(
                "  MISMATCH {}: got={}, expected={}",
                id, valid, expected_valid
            );
        }

        results.push(CanonicalizationResult { id, valid });
    }

    results
}

/// Process a canonicalization vector: parse, apply strict gates, canonicalize, digest.
fn process_canonicalization(input_json: &str) -> Result<String, String> {
    // Step 1: Pre-parse checks on raw JSON text for lone surrogates
    check_surrogate_escapes(input_json)?;

    // Step 2: Check for duplicate keys in raw text
    check_duplicate_keys_raw(input_json)?;

    // Step 3: Parse with standard JSON parser
    let value: Value =
        serde_json::from_str(input_json).map_err(|e| format!("JSON parse error: {}", e))?;

    // Step 4: Check nesting depth (max 64)
    let depth = measure_depth(&value);
    if depth > 64 {
        return Err(format!("nesting depth {} exceeds limit 64", depth));
    }

    // Step 5: Check EP I-JSON profile (isCanonicalizable):
    //   Every number must be an integer with magnitude <= 2^53-1
    check_ep_profile(&value)?;

    // Step 6: Canonicalize and compute SHA-256
    let canonical = jcs::canonicalize(&value);
    Ok(sha256_hex(&canonical))
}

/// Check for unpaired surrogate escapes in the raw JSON text.
/// This operates on the raw text BEFORE parsing: we scan for \uXXXX patterns.
fn check_surrogate_escapes(input: &str) -> Result<(), String> {
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() && bytes[i + 1] == b'u' {
            if i + 5 < bytes.len() {
                let hex_str = &input[i + 2..i + 6];
                if let Ok(code) = u16::from_str_radix(hex_str, 16) {
                    if (0xD800..=0xDBFF).contains(&code) {
                        // High surrogate: must be followed by \uDC00-\uDFFF
                        if i + 11 < bytes.len()
                            && bytes[i + 6] == b'\\'
                            && bytes[i + 7] == b'u'
                        {
                            let hex_str2 = &input[i + 8..i + 12];
                            if let Ok(code2) = u16::from_str_radix(hex_str2, 16) {
                                if (0xDC00..=0xDFFF).contains(&code2) {
                                    // Valid surrogate pair
                                    i += 12;
                                    continue;
                                }
                            }
                        }
                        return Err(format!("unpaired high surrogate \\u{:04X}", code));
                    } else if (0xDC00..=0xDFFF).contains(&code) {
                        return Err(format!("unpaired low surrogate \\u{:04X}", code));
                    }
                }
            }
            i += 6;
        } else {
            i += 1;
        }
    }
    Ok(())
}

/// Check for duplicate object member names at every level in raw JSON text.
/// This must work AFTER escape decoding: \u0061 and "a" are the same key.
fn check_duplicate_keys_raw(input: &str) -> Result<(), String> {
    // We use a custom parser approach: parse into a structure that preserves
    // duplicate keys, then check.
    // Simpler approach: re-parse but track keys ourselves.
    let mut checker = DuplicateKeyChecker::new(input);
    checker.check()
}

struct DuplicateKeyChecker<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> DuplicateKeyChecker<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn check(&mut self) -> Result<(), String> {
        self.skip_ws();
        self.check_value()
    }

    fn peek(&self) -> Option<u8> {
        self.input.as_bytes().get(self.pos).copied()
    }

    fn advance(&mut self) {
        self.pos += 1;
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn check_value(&mut self) -> Result<(), String> {
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.check_object(),
            Some(b'[') => self.check_array(),
            Some(b'"') => {
                self.read_string()?;
                Ok(())
            }
            Some(b't') | Some(b'f') | Some(b'n') => {
                // Skip literal
                while let Some(b) = self.peek() {
                    if b.is_ascii_alphabetic() {
                        self.advance();
                    } else {
                        break;
                    }
                }
                Ok(())
            }
            Some(b) if b == b'-' || b.is_ascii_digit() => {
                // Skip number
                while let Some(b) = self.peek() {
                    if b == b'-'
                        || b == b'+'
                        || b == b'.'
                        || b == b'e'
                        || b == b'E'
                        || b.is_ascii_digit()
                    {
                        self.advance();
                    } else {
                        break;
                    }
                }
                Ok(())
            }
            _ => Err("unexpected character".to_string()),
        }
    }

    fn check_object(&mut self) -> Result<(), String> {
        self.advance(); // skip '{'
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.advance();
            return Ok(());
        }

        let mut keys: Vec<String> = Vec::new();
        loop {
            self.skip_ws();
            let key = self.read_string()?;
            // Decode the key to compare after escape decoding
            let decoded_key = decode_json_string(&key);
            if keys.contains(&decoded_key) {
                return Err(format!("duplicate key: {}", decoded_key));
            }
            keys.push(decoded_key);

            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err("expected ':'".to_string());
            }
            self.advance();

            self.check_value()?;

            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.advance();
                }
                Some(b'}') => {
                    self.advance();
                    return Ok(());
                }
                _ => return Err("expected ',' or '}'".to_string()),
            }
        }
    }

    fn check_array(&mut self) -> Result<(), String> {
        self.advance(); // skip '['
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.advance();
            return Ok(());
        }

        loop {
            self.check_value()?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.advance();
                }
                Some(b']') => {
                    self.advance();
                    return Ok(());
                }
                _ => return Err("expected ',' or ']'".to_string()),
            }
        }
    }

    fn read_string(&mut self) -> Result<String, String> {
        if self.peek() != Some(b'"') {
            return Err("expected '\"'".to_string());
        }
        self.advance(); // skip opening "
        let start = self.pos;

        loop {
            match self.peek() {
                Some(b'\\') => {
                    self.advance();
                    self.advance(); // skip escaped char
                    // For \uXXXX, skip 4 more
                    if self.input.as_bytes().get(self.pos - 1) == Some(&b'u') {
                        for _ in 0..4 {
                            self.advance();
                        }
                    }
                }
                Some(b'"') => {
                    let s = self.input[start..self.pos].to_string();
                    self.advance(); // skip closing "
                    return Ok(s);
                }
                Some(_) => {
                    // Handle multi-byte UTF-8 chars
                    let b = self.input.as_bytes()[self.pos];
                    if b < 0x80 {
                        self.advance();
                    } else if b < 0xC0 {
                        self.advance();
                    } else if b < 0xE0 {
                        self.pos += 2;
                    } else if b < 0xF0 {
                        self.pos += 3;
                    } else {
                        self.pos += 4;
                    }
                }
                None => return Err("unterminated string".to_string()),
            }
        }
    }
}

/// Decode a JSON string (without surrounding quotes) by processing escape sequences.
fn decode_json_string(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('t') => result.push('\t'),
                Some('b') => result.push('\u{0008}'),
                Some('f') => result.push('\u{000C}'),
                Some('"') => result.push('"'),
                Some('\\') => result.push('\\'),
                Some('/') => result.push('/'),
                Some('u') => {
                    let hex: String = (0..4).filter_map(|_| chars.next()).collect();
                    if let Ok(code) = u16::from_str_radix(&hex, 16) {
                        if (0xD800..=0xDBFF).contains(&code) {
                            // High surrogate, look for low
                            if chars.peek() == Some(&'\\') {
                                chars.next();
                                if chars.peek() == Some(&'u') {
                                    chars.next();
                                    let hex2: String =
                                        (0..4).filter_map(|_| chars.next()).collect();
                                    if let Ok(code2) = u16::from_str_radix(&hex2, 16) {
                                        if let Some(c) =
                                            char::from_u32(((code as u32 - 0xD800) << 10) + (code2 as u32 - 0xDC00) + 0x10000)
                                        {
                                            result.push(c);
                                        }
                                    }
                                }
                            }
                        } else if let Some(c) = char::from_u32(code as u32) {
                            result.push(c);
                        }
                    }
                }
                Some(c) => {
                    result.push('\\');
                    result.push(c);
                }
                None => result.push('\\'),
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Measure the maximum nesting depth of a JSON value.
/// Objects and arrays add 1 to depth.
fn measure_depth(value: &Value) -> usize {
    match value {
        Value::Object(map) => {
            let max_child = map.values().map(|v| measure_depth(v)).max().unwrap_or(0);
            1 + max_child
        }
        Value::Array(arr) => {
            let max_child = arr.iter().map(|v| measure_depth(v)).max().unwrap_or(0);
            1 + max_child
        }
        _ => 0,
    }
}

/// Check EP I-JSON profile: every number must be a safe integer (magnitude <= 2^53-1).
fn check_ep_profile(value: &Value) -> Result<(), String> {
    match value {
        Value::Number(n) => {
            let f = n.as_f64().unwrap();
            // Must be integer-valued
            if f.fract() != 0.0 {
                return Err(format!("non-integer real: {}", f));
            }
            // Must be within safe integer range
            let max_safe = (1i64 << 53) - 1;
            if f.abs() > max_safe as f64 {
                return Err(format!("unsafe integer: {}", f));
            }
            Ok(())
        }
        Value::Object(map) => {
            for v in map.values() {
                check_ep_profile(v)?;
            }
            Ok(())
        }
        Value::Array(arr) => {
            for v in arr {
                check_ep_profile(v)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
