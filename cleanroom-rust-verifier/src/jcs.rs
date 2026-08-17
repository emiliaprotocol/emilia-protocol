// SPDX-License-Identifier: Apache-2.0
//
// RFC 8785 JSON Canonicalization Scheme (JCS) — cleanroom implementation.
//
// Key rules from the spec:
// 1. Sort object member names by UTF-16 code units at every depth
// 2. No whitespace in output
// 3. Strings: preserve exact code points (no Unicode normalization)
//    - Characters U+0000..U+001F are escaped: \b, \t, \n, \f, \r for the
//      five shorthand controls, \u00xx (lowercase) for the rest
//    - Characters >= U+0020 are emitted as raw UTF-8 (including U+007F,
//      U+2028, U+2029, etc.)
//    - Backslash and double-quote are escaped with backslash
// 4. Numbers: integer-valued numbers serialize as their integer form (no .0, no exponent)
//    -0 and -0.0 serialize as "0"
// 5. Booleans/null: lowercase literals

use serde_json::Value;

// Re-export and delegate to the primary implementation in canonical.rs
// for consistency (avoids duplication of JCS logic after reviewer optimizations).
// canonicalize here returns bytes for compatibility with suites that hash directly.
pub use crate::canonical::canonicalize as canonicalize_string;
pub use crate::canonical::{is_canonicalizable, strict_parse_gate};

/// Canonicalize to UTF-8 bytes (for direct use in hashing/signing).
pub fn canonicalize(value: &Value) -> Vec<u8> {
    match canonicalize_string(value) {
        Ok(s) => s.into_bytes(),
        Err(_) => b"".to_vec(), // fail closed; callers should check is_canonicalizable first
    }
}

/// Compare two strings by their UTF-16 code unit sequences (for reference).
pub fn compare_utf16(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_basic_canonicalization_bytes() {
        let val = json!({"b": 2, "a": 1});
        let result = String::from_utf8(canonicalize(&val)).unwrap();
        assert_eq!(result, r#"{"a":1,"b":2}"#);
    }
}
