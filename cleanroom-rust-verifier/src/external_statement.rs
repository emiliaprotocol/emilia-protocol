// SPDX-License-Identifier: Apache-2.0
// EP-EXTERNAL-VERIFICATION-STATEMENT-v1 signing (cleanroom).

use crate::canonical::canonicalize;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePublicKey};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

pub const STATEMENT_VERSION: &str = "EP-EXTERNAL-VERIFICATION-STATEMENT-v1";
pub const SIGNING_DOMAIN: &str = "EP-EXTERNAL-VERIFICATION-STATEMENT-v1\0";

pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

pub fn key_id_for_public_key_b64u(public_key_b64u: &str) -> Result<String, String> {
    let der = URL_SAFE_NO_PAD
        .decode(public_key_b64u)
        .map_err(|e| format!("public key decode: {}", e))?;
    let digest = hex::encode(Sha256::digest(&der));
    Ok(format!("ep:external-verifier-key:sha256:{}", &digest[..16]))
}

pub fn unsigned_statement(statement: &Value) -> Result<Value, String> {
    let obj = statement
        .as_object()
        .ok_or_else(|| "statement must be an object".to_string())?;
    let mut body = Map::new();
    for (k, v) in obj {
        if k != "signature" {
            body.insert(k.clone(), v.clone());
        }
    }
    Ok(Value::Object(body))
}

pub fn signing_bytes(unsigned: &Value) -> Result<Vec<u8>, String> {
    let canonical = canonicalize(unsigned).map_err(|e| e.to_string())?;
    let mut bytes = SIGNING_DOMAIN.as_bytes().to_vec();
    bytes.extend_from_slice(canonical.as_bytes());
    Ok(bytes)
}

pub fn statement_digest(unsigned: &Value) -> Result<String, String> {
    let bytes = signing_bytes(unsigned)?;
    Ok(sha256_hex(&bytes))
}

pub fn load_signing_key(pem_path: &Path) -> Result<(SigningKey, String), String> {
    let pem = fs::read_to_string(pem_path)
        .map_err(|e| format!("read key {}: {}", pem_path.display(), e))?;
    let signing_key = SigningKey::from_pkcs8_pem(&pem)
        .map_err(|e| format!("parse PKCS8 PEM: {}", e))?;
    let spki_der = signing_key
        .verifying_key()
        .to_public_key_der()
        .map_err(|e| format!("export SPKI: {}", e))?;
    let public_key_b64u = URL_SAFE_NO_PAD.encode(spki_der.as_ref());
    Ok((signing_key, public_key_b64u))
}

pub struct StatementArgs<'a> {
    pub verifier_id: &'a str,
    pub verifier_name: Option<&'a str>,
    pub organization: Option<&'a str>,
    pub implementation: &'a str,
    pub commit: &'a str,
    pub suite_entries: &'a [SuiteEntry],
}

#[derive(Clone)]
pub struct SuiteEntry {
    pub file: String,
    pub suite_digest: String,
    pub results_digest: String,
    pub passed: usize,
    pub total: usize,
}

pub fn sign_statement(args: &StatementArgs, signing_key: &SigningKey, public_key_b64u: &str) -> Result<Value, String> {
    let key_id = key_id_for_public_key_b64u(public_key_b64u)?;
    let total_vectors: usize = args.suite_entries.iter().map(|s| s.total).sum();
    let all_ok = args.suite_entries.iter().all(|s| s.passed == s.total);

    let mut suite_digests = Map::new();
    let mut results_digests = Map::new();
    let mut checks = Vec::new();

    let mut sorted = args.suite_entries.to_vec();
    sorted.sort_by(|a, b| a.file.cmp(&b.file));

    for entry in &sorted {
        suite_digests.insert(entry.file.clone(), json!(entry.suite_digest));
        results_digests.insert(entry.file.clone(), json!(entry.results_digest));
        checks.push(json!({
            "id": entry.file,
            "ok": entry.passed == entry.total,
            "detail": format!("{}/{}", entry.passed, entry.total),
        }));
    }

    let generated_at = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let mut verifier = Map::new();
    verifier.insert("id".to_string(), json!(args.verifier_id));
    if let Some(name) = args.verifier_name {
        verifier.insert("name".to_string(), json!(name));
    }
    if let Some(org) = args.organization {
        verifier.insert("organization".to_string(), json!(org));
    }

    let body = json!({
        "@version": STATEMENT_VERSION,
        "generated_at": generated_at,
        "verifier": Value::Object(verifier),
        "subject": {
            "kind": "conformance_vector_pack",
            "suites": sorted.len(),
            "vectors": total_vectors,
            "commit": args.commit,
        },
        "procedure": {
            "id": "ep-conformance-own-implementation",
            "version": "EP-CONFORMANCE-RUN-OWN-IMPLEMENTATION-v1",
        },
        "inputs": {
            "commit": args.commit,
            "implementation": args.implementation,
            "suite_digests": Value::Object(suite_digests),
            "results_digests": Value::Object(results_digests),
        },
        "result": {
            "status": if all_ok { "verified" } else { "divergent" },
            "checks": checks,
        },
        "limitations": [
            "Per-vector results were produced by the named implementation outside this harness and are self-reported; this harness only compared them against each suite vector's expect.valid.",
            "This statement records the external verifier procedure and result; it does not authorize the action.",
            "It does not certify business correctness, legal compliance, or human wisdom.",
            "Acceptance depends on the relying party pinning the verifier key out of band.",
        ],
    });

    let digest = statement_digest(&body)?;
    let sig_bytes = signing_bytes(&body)?;
    let signature = signing_key.sign(&sig_bytes);

    let statement = json!({
        "@version": STATEMENT_VERSION,
        "generated_at": generated_at,
        "verifier": body["verifier"].clone(),
        "subject": body["subject"].clone(),
        "procedure": body["procedure"].clone(),
        "inputs": body["inputs"].clone(),
        "result": body["result"].clone(),
        "limitations": body["limitations"].clone(),
        "signature": {
            "algorithm": "Ed25519",
            "key_id": key_id,
            "public_key": public_key_b64u,
            "statement_digest": digest,
            "signature_b64u": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
    });

    Ok(statement)
}

