// SPDX-License-Identifier: Apache-2.0
// EP-TIMESTAMP-PROOF-v1 — RFC 3161 PKCS#7 timestamp token verification.

use crate::crypto;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use rsa::RsaPublicKey;
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384, Sha512};

const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const OID_CT_TSTINFO: &str = "1.2.840.113549.1.9.16.1.4";
const OID_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const OID_SHA384: &str = "2.16.840.1.101.3.4.2.2";
const OID_SHA512: &str = "2.16.840.1.101.3.4.2.3";
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";

pub fn run(vectors: &Value) -> Vec<(String, bool)> {
    let vecs = vectors["vectors"].as_array().unwrap();
    let mut results = Vec::new();

    for v in vecs {
        let id = v["id"].as_str().unwrap().to_string();
        let valid = verify_timestamp_proof(
            v.get("timestamp_proof"),
            v.get("expected_digest"),
            v.get("pinned_tsa_keys"),
        );
        results.push((id, valid));
    }
    results
}

pub fn verify_timestamp_proof(
    timestamp_proof: Option<&Value>,
    expected_digest: Option<&Value>,
    pinned_tsa_keys: Option<&Value>,
) -> bool {
    let token_str = match timestamp_proof {
        Some(Value::String(s)) if !s.trim().is_empty() => s.as_str(),
        _ => return false,
    };

    let want_digest = hex_of(expected_digest.and_then(|v| v.as_str()));
    if want_digest.is_empty() {
        return false;
    }

    let loaded_keys = load_pinned_keys(pinned_tsa_keys);
    if loaded_keys.is_empty() {
        return false;
    }

    let der = match decode_der(token_str) {
        Some(d) if !d.is_empty() => d,
        _ => return false,
    };

    let parsed = match parse_token(&der) {
        Ok(p) => p,
        Err(_) => return false,
    };

    if parsed.tst_info.message_imprint_hex != want_digest {
        return false;
    }
    if parsed.tst_info.gen_time.is_none() {
        return false;
    }

    verify_signer_info(&parsed.signer_info, &parsed.e_content_raw, &loaded_keys)
}

struct TstInfo {
    message_imprint_hex: String,
    gen_time: Option<String>,
}

struct SignerInfo {
    digest_name: Option<String>,
    signed_attrs: Option<TspNode>,
    sig_alg_oid: String,
    signature: Vec<u8>,
}

struct ParsedToken {
    tst_info: TstInfo,
    signer_info: SignerInfo,
    e_content_raw: Vec<u8>,
}

#[derive(Clone)]
struct TspNode {
    cls: u8,
    constructed: bool,
    tag: u32,
    header_len: usize,
    content_start: usize,
    content_end: usize,
    buf: Vec<u8>,
}

impl TspNode {
    fn content(&self) -> &[u8] {
        &self.buf[self.content_start..self.content_end]
    }

    fn raw_body(&self) -> &[u8] {
        &self.buf[self.content_start..self.content_end]
    }
}

struct DerError;

fn read_tlv(buf: &[u8], offset: usize) -> Result<TspNode, DerError> {
    if offset + 2 > buf.len() {
        return Err(DerError);
    }
    let first = buf[offset];
    let cls = (first & 0xC0) >> 6;
    let constructed = (first & 0x20) != 0;
    let mut tag = (first & 0x1F) as u32;
    let mut p = offset + 1;
    if tag == 0x1F {
        tag = 0;
        loop {
            if p >= buf.len() {
                return Err(DerError);
            }
            let b = buf[p];
            p += 1;
            tag = (tag << 7) | ((b & 0x7F) as u32);
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    if p >= buf.len() {
        return Err(DerError);
    }
    let mut length = buf[p] as usize;
    p += 1;
    if length & 0x80 != 0 {
        let num_bytes = length & 0x7F;
        if num_bytes == 0 || num_bytes > 4 {
            return Err(DerError);
        }
        if p + num_bytes > buf.len() {
            return Err(DerError);
        }
        length = 0;
        for _ in 0..num_bytes {
            length = (length << 8) | (buf[p] as usize);
            p += 1;
        }
    }
    let content_start = p;
    let content_end = p + length;
    if content_end > buf.len() {
        return Err(DerError);
    }
    Ok(TspNode {
        cls,
        constructed,
        tag,
        header_len: content_start - offset,
        content_start,
        content_end,
        buf: buf.to_vec(),
    })
}

fn children(node: &TspNode) -> Result<Vec<TspNode>, DerError> {
    let mut out = Vec::new();
    let mut p = node.content_start;
    while p < node.content_end {
        let child = read_tlv(&node.buf, p)?;
        p = child.content_end;
        out.push(child);
    }
    Ok(out)
}

fn decode_oid(node: &TspNode) -> Result<String, DerError> {
    if node.tag != 0x06 || node.cls != 0 {
        return Err(DerError);
    }
    let b = node.content();
    if b.is_empty() {
        return Err(DerError);
    }
    let first = b[0];
    let mut parts: Vec<u64> = vec![(first / 40) as u64, (first % 40) as u64];
    let mut value = 0u64;
    for &byte in &b[1..] {
        value = (value << 7) | ((byte & 0x7F) as u64);
        if byte & 0x80 == 0 {
            parts.push(value);
            value = 0;
        }
    }
    Ok(parts
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join("."))
}

fn digest_name_from_oid(oid: &str) -> Option<String> {
    match oid {
        OID_SHA256 => Some("sha256".to_string()),
        OID_SHA384 => Some("sha384".to_string()),
        OID_SHA512 => Some("sha512".to_string()),
        _ => None,
    }
}

fn hash_bytes(alg: &str, data: &[u8]) -> Vec<u8> {
    match alg {
        "sha384" => Sha384::digest(data).to_vec(),
        "sha512" => Sha512::digest(data).to_vec(),
        _ => Sha256::digest(data).to_vec(),
    }
}

fn decode_generalized_time(node: &TspNode) -> Option<String> {
    let s = std::str::from_utf8(node.content()).ok()?;
    if node.tag == 0x18 {
        let re = regex_simple_gen_time(s);
        return re;
    }
    if node.tag == 0x17 {
        if s.len() == 13 && s.ends_with('Z') {
            let yy: u32 = s[0..2].parse().ok()?;
            let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
            return Some(format!(
                "{}-{}-{}T{}:{}:{}Z",
                year,
                &s[2..4],
                &s[4..6],
                &s[6..8],
                &s[8..10],
                &s[10..12]
            ));
        }
    }
    None
}

fn regex_simple_gen_time(s: &str) -> Option<String> {
    if s.len() < 15 || !s.ends_with('Z') {
        return None;
    }
    let body = &s[..s.len() - 1];
    if body.len() < 14 || !body[..14].chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let y = &s[0..4];
    let mo = &s[4..6];
    let d = &s[6..8];
    let h = &s[8..10];
    let mi = &s[10..12];
    let se = &s[12..14];
    let frac = body
        .get(14..)
        .filter(|rest| rest.starts_with('.') && rest[1..].chars().all(|c| c.is_ascii_digit()))
        .unwrap_or("");
    Some(format!("{}-{}-{}T{}:{}:{}{}Z", y, mo, d, h, mi, se, frac))
}

fn parse_attributes(set_node: &TspNode) -> Result<std::collections::HashMap<String, Vec<TspNode>>, DerError> {
    let mut out = std::collections::HashMap::new();
    for attr in children(set_node)? {
        if attr.tag != 0x10 {
            continue;
        }
        let kids = children(&attr)?;
        if kids.len() < 2 {
            continue;
        }
        let oid = decode_oid(&kids[0])?;
        let vals = children(&kids[1])?;
        out.insert(oid, vals);
    }
    Ok(out)
}

fn parse_tstinfo(der: &[u8]) -> Result<TstInfo, DerError> {
    let seq = read_tlv(der, 0)?;
    if seq.tag != 0x10 {
        return Err(DerError);
    }
    let kids = children(&seq)?;
    if kids.len() < 5 {
        return Err(DerError);
    }
    let mi = &kids[2];
    if mi.tag != 0x10 {
        return Err(DerError);
    }
    let mi_kids = children(mi)?;
    if mi_kids.len() < 2 {
        return Err(DerError);
    }
    let hashed_message = &mi_kids[1];
    if hashed_message.tag != 0x04 {
        return Err(DerError);
    }
    let message_imprint_hex = hex::encode(hashed_message.content());
    let mut gen_time = None;
    for kid in kids.iter().skip(3) {
        if kid.tag == 0x18 || kid.tag == 0x17 {
            gen_time = decode_generalized_time(kid);
            if gen_time.is_some() {
                break;
            }
        }
    }
    Ok(TstInfo {
        message_imprint_hex,
        gen_time,
    })
}

fn parse_signer_info(node: &TspNode) -> Result<SignerInfo, DerError> {
    if node.tag != 0x10 {
        return Err(DerError);
    }
    let kids = children(node)?;
    let mut idx = 0;
    if idx >= kids.len() || kids[idx].tag != 0x02 {
        return Err(DerError);
    }
    idx += 1;
    if idx >= kids.len() {
        return Err(DerError);
    }
    idx += 1;
    if idx >= kids.len() || kids[idx].tag != 0x10 {
        return Err(DerError);
    }
    let digest_alg = &kids[idx];
    idx += 1;
    let digest_alg_oid = decode_oid(&children(digest_alg)?[0])?;
    let digest_name = digest_name_from_oid(&digest_alg_oid);
    let mut signed_attrs = None;
    if idx < kids.len() && kids[idx].cls == 2 && kids[idx].tag == 0 && kids[idx].constructed {
        signed_attrs = Some(kids[idx].clone());
        idx += 1;
    }
    if idx >= kids.len() || kids[idx].tag != 0x10 {
        return Err(DerError);
    }
    let sig_alg = &kids[idx];
    idx += 1;
    let sig_alg_oid = decode_oid(&children(sig_alg)?[0])?;
    if idx >= kids.len() || kids[idx].tag != 0x04 {
        return Err(DerError);
    }
    let signature = kids[idx].content().to_vec();
    Ok(SignerInfo {
        digest_name,
        signed_attrs,
        sig_alg_oid,
        signature,
    })
}

fn parse_token(der: &[u8]) -> Result<ParsedToken, DerError> {
    let content_info = read_tlv(der, 0)?;
    if content_info.tag != 0x10 || !content_info.constructed {
        return Err(DerError);
    }
    let ci_kids = children(&content_info)?;
    if ci_kids.len() < 2 {
        return Err(DerError);
    }
    if decode_oid(&ci_kids[0])? != OID_SIGNED_DATA {
        return Err(DerError);
    }
    let explicit0 = &ci_kids[1];
    if explicit0.cls != 2 || explicit0.tag != 0 || !explicit0.constructed {
        return Err(DerError);
    }
    let sd_list = children(explicit0)?;
    let signed_data = sd_list.first().ok_or(DerError)?;
    if signed_data.tag != 0x10 {
        return Err(DerError);
    }
    let sd_kids = children(signed_data)?;
    if sd_kids.len() < 4 {
        return Err(DerError);
    }
    let encap = sd_kids.get(2).ok_or(DerError)?;
    let mut signer_infos = None;
    for i in (3..sd_kids.len()).rev() {
        if sd_kids[i].tag == 0x11 && sd_kids[i].cls == 0 {
            signer_infos = Some(&sd_kids[i]);
            break;
        }
    }
    if encap.tag != 0x10 {
        return Err(DerError);
    }
    let signer_infos = signer_infos.ok_or(DerError)?;
    let encap_kids = children(encap)?;
    if encap_kids.len() < 2 {
        return Err(DerError);
    }
    if decode_oid(&encap_kids[0])? != OID_CT_TSTINFO {
        return Err(DerError);
    }
    let e_content_explicit = &encap_kids[1];
    if e_content_explicit.cls != 2 || e_content_explicit.tag != 0 {
        return Err(DerError);
    }
    let octet_list = children(e_content_explicit)?;
    let octet = octet_list.first().ok_or(DerError)?;
    if octet.tag != 0x04 {
        return Err(DerError);
    }
    let e_content_raw = octet.content().to_vec();
    let tst_info = parse_tstinfo(&e_content_raw)?;
    let si_list = children(signer_infos)?;
    if si_list.len() != 1 {
        return Err(DerError);
    }
    let signer_info = parse_signer_info(&si_list[0])?;
    Ok(ParsedToken {
        tst_info,
        signer_info,
        e_content_raw,
    })
}

fn der_set_header(length: usize) -> Vec<u8> {
    if length < 0x80 {
        vec![0x31, length as u8]
    } else {
        let mut body = Vec::new();
        let mut n = length;
        while n > 0 {
            body.insert(0, (n & 0xFF) as u8);
            n >>= 8;
        }
        let mut out = vec![0x31, 0x80 | body.len() as u8];
        out.extend(body);
        out
    }
}

fn verify_signer_info(signer_info: &SignerInfo, e_content_raw: &[u8], keys: &[RsaPublicKey]) -> bool {
    let digest_name = match signer_info.digest_name.as_deref() {
        Some(d) => d,
        None => return false,
    };

    let signed_bytes = if let Some(ref signed_attrs) = signer_info.signed_attrs {
        let attrs = match parse_attributes(signed_attrs) {
            Ok(a) => a,
            Err(_) => return false,
        };
        let ct_nodes = match attrs.get(OID_CONTENT_TYPE) {
            Some(n) if n.len() == 1 => n,
            _ => return false,
        };
        let ct_oid = match decode_oid(&ct_nodes[0]) {
            Ok(o) => o,
            Err(_) => return false,
        };
        if ct_oid != OID_CT_TSTINFO {
            return false;
        }
        let md_nodes = match attrs.get(OID_MESSAGE_DIGEST) {
            Some(n) if n.len() == 1 && n[0].tag == 0x04 => n,
            _ => return false,
        };
        let attr_digest = md_nodes[0].content();
        let e_content_digest = hash_bytes(digest_name, e_content_raw);
        if attr_digest != e_content_digest.as_slice() {
            return false;
        }
        let attrs_body = signed_attrs.raw_body();
        let mut signed = der_set_header(attrs_body.len());
        signed.extend_from_slice(attrs_body);
        signed
    } else {
        e_content_raw.to_vec()
    };

    for key in keys {
        if signer_info.sig_alg_oid == OID_RSA_ENCRYPTION
            && crypto::verify_rsa_pkcs1v15(key, digest_name, &signed_bytes, &signer_info.signature)
        {
            return true;
        }
    }
    false
}

fn load_pinned_keys(pinned: Option<&Value>) -> Vec<RsaPublicKey> {
    let mut pinned_list: Vec<&str> = Vec::new();
    match pinned {
        Some(Value::Array(arr)) => {
            for item in arr {
                if let Some(s) = item.as_str() {
                    pinned_list.push(s);
                }
            }
        }
        Some(Value::Object(map)) => {
            for (_, v) in map {
                if let Some(s) = v.as_str() {
                    pinned_list.push(s);
                }
            }
        }
        Some(Value::String(s)) => pinned_list.push(s.as_str()),
        _ => {}
    }
    pinned_list
        .into_iter()
        .filter_map(|p| crypto::parse_rsa_spki_key(p).ok())
        .collect()
}

fn decode_der(token: &str) -> Option<Vec<u8>> {
    let raw: String = token.split_whitespace().collect();
    STANDARD.decode(&raw).or_else(|_| URL_SAFE_NO_PAD.decode(&raw)).ok()
}

fn hex_of(h: Option<&str>) -> String {
    let s = h.unwrap_or("");
    let s = s
        .strip_prefix("sha256:")
        .or_else(|| s.strip_prefix("sha384:"))
        .or_else(|| s.strip_prefix("sha512:"))
        .unwrap_or(s)
        .to_ascii_lowercase();
    if s.len() >= 40 && s.len() % 2 == 0 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        s
    } else {
        String::new()
    }
}