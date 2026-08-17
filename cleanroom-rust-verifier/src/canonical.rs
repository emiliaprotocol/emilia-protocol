use std::collections::HashSet;
use crate::error::Error;

pub fn strict_parse_gate(raw: &str) -> Result<(), Error> {
    let bytes = raw.as_bytes();
    let n = bytes.len();
    let mut i = 0;
    
    struct StackEntry {
        is_obj: bool,
        keys: HashSet<String>,
        expect_key: bool,
    }
    
    let mut stack: Vec<StackEntry> = Vec::new();
    
    while i < n {
        let c = bytes[i];
        if c == b'{' {
            stack.push(StackEntry {
                is_obj: true,
                keys: HashSet::new(),
                expect_key: true,
            });
            if stack.len() > 64 {
                return Err(Error::DepthExceeded("nesting depth exceeds 64".to_string()));
            }
            i += 1;
        } else if c == b'[' {
            stack.push(StackEntry {
                is_obj: false,
                keys: HashSet::new(),
                expect_key: false,
            });
            if stack.len() > 64 {
                return Err(Error::DepthExceeded("nesting depth exceeds 64".to_string()));
            }
            i += 1;
        } else if c == b'}' || c == b']' {
            let popped = stack.pop().ok_or_else(|| {
                Error::InvalidFormat("mismatched closing bracket".to_string())
            })?;
            let expect_obj = c == b'}';
            if popped.is_obj != expect_obj {
                return Err(Error::InvalidFormat("mismatched container type".to_string()));
            }
            i += 1;
        } else if c == b',' {
            if let Some(top) = stack.last_mut() {
                if top.is_obj {
                    top.expect_key = true;
                }
            }
            i += 1;
        } else if c == b'"' {
            let is_key = if let Some(top) = stack.last() {
                top.is_obj && top.expect_key
            } else {
                false
            };
            
            let s = read_string(raw, bytes, &mut i)?;
            
            if is_key {
                if let Some(top) = stack.last_mut() {
                    if top.keys.contains(&s) {
                        return Err(Error::DuplicateKey(format!("duplicate object member name: {}", s)));
                    }
                    top.keys.insert(s);
                    top.expect_key = false;
                }
            }
        } else {
            i += 1;
        }
    }
    
    Ok(())
}

fn read_string(raw: &str, bytes: &[u8], i: &mut usize) -> Result<String, Error> {
    let n = bytes.len();
    *i += 1; // skip opening quote
    let mut out = String::new();
    
    while *i < n {
        let c = bytes[*i];
        if c == b'"' {
            *i += 1;
            return Ok(out);
        }
        if c == b'\\' {
            if *i + 1 >= n {
                return Err(Error::InvalidFormat("unterminated escape sequence".to_string()));
            }
            let e = bytes[*i + 1];
            if e == b'u' {
                if *i + 5 >= n {
                    return Err(Error::InvalidFormat("truncated \\u escape".to_string()));
                }
                let hex_str = raw.get(*i + 2..*i + 6)
                    .ok_or_else(|| Error::InvalidFormat("invalid character boundary".to_string()))?;
                let cu = u16::from_str_radix(hex_str, 16)
                    .map_err(|_| Error::InvalidFormat("invalid hex in \\u escape".to_string()))?;
                *i += 6;
                
                if cu >= 0xd800 && cu <= 0xdbff {
                    // High surrogate
                    if *i + 5 < n && bytes[*i] == b'\\' && bytes[*i + 1] == b'u' {
                        let hex_str2 = raw.get(*i + 2..*i + 6)
                            .ok_or_else(|| Error::InvalidFormat("invalid character boundary in low surrogate escape".to_string()))?;
                        let cu2 = u16::from_str_radix(hex_str2, 16)
                            .map_err(|_| Error::InvalidFormat("invalid hex in low surrogate escape".to_string()))?;
                        if cu2 >= 0xdc00 && cu2 <= 0xdfff {
                            *i += 6;
                            let decoded = char::decode_utf16([cu, cu2].iter().copied())
                                .next()
                                .ok_or_else(|| Error::InvalidFormat("invalid surrogate pair".to_string()))?
                                .map_err(|_| Error::InvalidFormat("invalid surrogate pair decoding".to_string()))?;
                            out.push(decoded);
                            continue;
                        }
                    }
                    return Err(Error::UnpairedSurrogate("unpaired high surrogate escape".to_string()));
                }
                if cu >= 0xdc00 && cu <= 0xdfff {
                    return Err(Error::UnpairedSurrogate("unpaired low surrogate escape".to_string()));
                }
                
                let decoded = char::from_u32(cu as u32)
                    .ok_or_else(|| Error::InvalidFormat("invalid code point".to_string()))?;
                out.push(decoded);
            } else {
                let decoded_char = match e {
                    b'"' => '"',
                    b'\\' => '\\',
                    b'/' => '/',
                    b'b' => '\u{0008}',
                    b'f' => '\u{000c}',
                    b'n' => '\n',
                    b'r' => '\r',
                    b't' => '\t',
                    _ => return Err(Error::InvalidFormat(format!("unknown escape char: {}", e as char))),
                };
                out.push(decoded_char);
                *i += 2;
            }
        } else {
            let remaining = raw.get(*i..)
                .ok_or_else(|| Error::InvalidFormat("invalid utf-8 character boundary".to_string()))?;
            let next_char = remaining.chars().next()
                .ok_or_else(|| Error::InvalidFormat("empty character sequence".to_string()))?;
            out.push(next_char);
            *i += next_char.len_utf8();
        }
    }
    
    Err(Error::InvalidFormat("unterminated string".to_string()))
}

pub fn is_canonicalizable(val: &serde_json::Value) -> bool {
    match val {
        serde_json::Value::Null => true,
        serde_json::Value::Bool(_) => true,
        serde_json::Value::String(_) => true,
        serde_json::Value::Number(num) => {
            if let Some(i) = num.as_i64() {
                i >= -9007199254740991 && i <= 9007199254740991
            } else if let Some(u) = num.as_u64() {
                u <= 9007199254740991
            } else if let Some(f) = num.as_f64() {
                f.fract() == 0.0 && f >= -9007199254740991.0 && f <= 9007199254740991.0
            } else {
                false
            }
        }
        serde_json::Value::Array(arr) => arr.iter().all(is_canonicalizable),
        serde_json::Value::Object(map) => map.values().all(is_canonicalizable),
    }
}

pub fn jcs_escape_string(s: &str) -> String {
    let mut out = String::new();
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x08' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\x0c' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if c < '\x20' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

fn canonicalize_number(num: &serde_json::Number) -> Result<String, Error> {
    let f = num.as_f64().unwrap_or(0.0);
    if f == 0.0 && f.is_sign_negative() {
        return Ok("0".to_string());
    }
    
    if let Some(i) = num.as_i64() {
        if i >= -9007199254740991 && i <= 9007199254740991 {
            return Ok(i.to_string());
        } else {
            return Err(Error::NotCanonicalizable(format!("integer {} out of safe range", i)));
        }
    }
    if let Some(u) = num.as_u64() {
        if u <= 9007199254740991 {
            return Ok(u.to_string());
        } else {
            return Err(Error::NotCanonicalizable(format!("integer {} out of safe range", u)));
        }
    }
    
    let fract = f.fract();
    if fract == 0.0 {
        let val = f as i64;
        if val >= -9007199254740991 && val <= 9007199254740991 {
            return Ok(val.to_string());
        }
    }
    
    Err(Error::NotCanonicalizable(format!("invalid or out-of-bounds number: {}", num)))
}

pub fn canonicalize(val: &serde_json::Value) -> Result<String, Error> {
    match val {
        serde_json::Value::Null => Ok("null".to_string()),
        serde_json::Value::Bool(b) => Ok(if *b { "true".to_string() } else { "false".to_string() }),
        serde_json::Value::String(s) => Ok(jcs_escape_string(s)),
        serde_json::Value::Number(num) => canonicalize_number(num),
        serde_json::Value::Array(arr) => {
            let mut parts = Vec::new();
            for item in arr {
                parts.push(canonicalize(item)?);
            }
            Ok(format!("[{}]", parts.join(",")))
        }
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            // Sort keys by UTF-16 code units (zero-allocation iterator comparison)
            keys.sort_by(|a, b| {
                a.encode_utf16().cmp(b.encode_utf16())
            });
            let mut parts = Vec::new();
            for key in keys {
                let val_str = canonicalize(&map[key])?;
                parts.push(format!("{}:{}", jcs_escape_string(key), val_str));
            }
            Ok(format!("{{{}}}", parts.join(",")))
        }
    }
}
