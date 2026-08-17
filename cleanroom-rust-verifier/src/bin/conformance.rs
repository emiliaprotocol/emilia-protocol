use emilia_rust_verifier::canonical::{canonicalize, is_canonicalizable};
use emilia_rust_verifier::external_statement::{self, sha256_hex, sign_statement, StatementArgs, SuiteEntry};
use emilia_rust_verifier::suites;
use serde_json::{json, Value};
use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const SUITE_FILES: &[&str] = &[
    "receipts.v1.json",
    "signoffs.v1.json",
    "quorum.v1.json",
    "revocation.exec.v1.json",
    "time-attestation.v1.json",
    "trust-receipt.exec.v1.json",
    "trust-receipt.timestamp-forms.v1.json",
    "provenance.exec.v1.json",
    "evidence-record.v1.json",
    "canonicalization.v1.json",
    "boundary.v1.json",
    "currency.v1.json",
    "initiator-attestation.v1.json",
    "consumption-proof.v1.json",
    "witness.v1.json",
    "timestamp-proof.v1.json",
];

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    match args[1].as_str() {
        "verify" => run_verify_mode(&args),
        "canonicalize" => run_canonicalize_mode(&args),
        "statement" => run_statement_mode(&args),
        "--version" | "version" => {
            println!(
                "{}",
                json!({
                    "name": "emilia-cleanroom-conformance",
                    "version": VERSION,
                    "suites": "EP-RECEIPT-v1, EP-TRUST-RECEIPT-v1, EP-TIME-ATTESTATION-v1, ..."
                })
            );
        }
        "--help" | "help" => print_usage(),
        _ => run_vectors_file_mode(&args[1]),
    }
}

fn print_usage() {
    eprintln!("EMILIA cleanroom conformance binary v{}", VERSION);
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  conformance <path_to_vectors_json>");
    eprintln!("  conformance verify --suite <SUITE> --document <file|-> [--public-key <b64>] [--verification <file>]");
    eprintln!("  conformance canonicalize --input <file|-> [--hex-digest]");
    eprintln!("  conformance statement --vectors-dir <dir> --private-key <pem> --output <file> --verifier-id <id> [--verifier-name <name>] [--org <org>] [--implementation <name>]");
    eprintln!("  conformance version");
}

fn read_input(path: &str) -> String {
    if path == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).unwrap_or_default();
        s
    } else {
        std::fs::read_to_string(path).unwrap_or_default()
    }
}

fn run_verify_mode(args: &[String]) {
    let mut suite = String::new();
    let mut doc_path: Option<String> = None;
    let mut verif_path: Option<String> = None;
    let mut public_key: Option<String> = None;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--suite" => {
                i += 1;
                if i < args.len() {
                    suite = args[i].clone();
                }
            }
            "--document" => {
                i += 1;
                if i < args.len() {
                    doc_path = Some(args[i].clone());
                }
            }
            "--verification" => {
                i += 1;
                if i < args.len() {
                    verif_path = Some(args[i].clone());
                }
            }
            "--public-key" => {
                i += 1;
                if i < args.len() {
                    public_key = Some(args[i].clone());
                }
            }
            _ => {}
        }
        i += 1;
    }

    if suite.is_empty() || doc_path.is_none() {
        eprintln!("verify requires --suite and --document");
        std::process::exit(1);
    }

    let doc_content = read_input(doc_path.as_ref().unwrap());
    let doc_val: Value = match serde_json::from_str(&doc_content) {
        Ok(v) => v,
        Err(e) => {
            let out = json!({
                "valid": false,
                "reason": format!("document JSON parse error: {}", e),
                "matched_suite": suite,
                "error_detail": e.to_string()
            });
            print!("{}", serde_json::to_string(&out).unwrap());
            return;
        }
    };

    let mut vector = json!({
        "id": "single",
        "document": doc_val
    });

    if let Some(pk) = public_key {
        vector["public_key"] = json!(pk);
    }

    if let Some(vp) = verif_path {
        let vcontent = read_input(&vp);
        if let Ok(vval) = serde_json::from_str::<Value>(&vcontent) {
            vector["verification"] = vval;
        }
    }

    let root = json!({
        "suite": suite,
        "vectors": [vector]
    });

    let results = run_suite(&suite, &root);
    let valid = results.first().and_then(|r| r.get("valid")).and_then(|v| v.as_bool()).unwrap_or(false);

    let out = json!({
        "valid": valid,
        "reason": if valid { "cleanroom ok" } else { "cleanroom rejected" },
        "matched_suite": suite,
        "results": results,
        "error_detail": if valid { Value::Null } else { results.get(0).cloned().unwrap_or(Value::Null) }
    });

    print!("{}", serde_json::to_string(&out).unwrap());
    if !valid {
        std::process::exit(1);
    }
}

fn run_canonicalize_mode(args: &[String]) {
    let mut input_path: Option<String> = None;
    let mut hex_digest = false;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--input" => {
                i += 1;
                if i < args.len() {
                    input_path = Some(args[i].clone());
                }
            }
            "--hex-digest" => hex_digest = true,
            _ => {}
        }
        i += 1;
    }

    if input_path.is_none() {
        eprintln!("canonicalize requires --input <file|->");
        std::process::exit(1);
    }

    let content = read_input(input_path.as_ref().unwrap());
    let val: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("JSON parse error: {}", e);
            std::process::exit(1);
        }
    };

    if !is_canonicalizable(&val) {
        eprintln!("value is not canonicalizable per JCS rules");
        std::process::exit(1);
    }

    match canonicalize(&val) {
        Ok(s) => {
            if hex_digest {
                use sha2::{Digest, Sha256};
                let digest = Sha256::digest(s.as_bytes());
                let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
                print!("{}", hex);
            } else {
                print!("{}", s);
            }
        }
        Err(e) => {
            eprintln!("canonicalize error: {}", e);
            std::process::exit(1);
        }
    }
}

fn run_statement_mode(args: &[String]) {
    let mut vectors_dir: Option<String> = None;
    let mut private_key: Option<String> = None;
    let mut output: Option<String> = None;
    let mut verifier_id: Option<String> = None;
    let mut verifier_name: Option<String> = None;
    let mut organization: Option<String> = None;
    let mut implementation: Option<String> = None;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--vectors-dir" => {
                i += 1;
                if i < args.len() {
                    vectors_dir = Some(args[i].clone());
                }
            }
            "--private-key" => {
                i += 1;
                if i < args.len() {
                    private_key = Some(args[i].clone());
                }
            }
            "--output" => {
                i += 1;
                if i < args.len() {
                    output = Some(args[i].clone());
                }
            }
            "--verifier-id" => {
                i += 1;
                if i < args.len() {
                    verifier_id = Some(args[i].clone());
                }
            }
            "--verifier-name" => {
                i += 1;
                if i < args.len() {
                    verifier_name = Some(args[i].clone());
                }
            }
            "--org" => {
                i += 1;
                if i < args.len() {
                    organization = Some(args[i].clone());
                }
            }
            "--implementation" => {
                i += 1;
                if i < args.len() {
                    implementation = Some(args[i].clone());
                }
            }
            _ => {}
        }
        i += 1;
    }

    if vectors_dir.is_none() || private_key.is_none() || output.is_none() || verifier_id.is_none() {
        eprintln!("statement requires --vectors-dir, --private-key, --output, and --verifier-id");
        std::process::exit(1);
    }

    let impl_name = implementation.unwrap_or_else(|| format!("emilia-rust-verifier {}", VERSION));
    let vectors_path = PathBuf::from(vectors_dir.as_ref().unwrap());
    let key_path = PathBuf::from(private_key.as_ref().unwrap());
    let out_path = PathBuf::from(output.as_ref().unwrap());

    let (signing_key, public_key_b64u) = match external_statement::load_signing_key(&key_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to load signing key: {}", e);
            std::process::exit(1);
        }
    };

    let commit = git_commit(&vectors_path);
    let mut suite_entries = Vec::new();
    let mut total_passed = 0usize;
    let mut total_vectors = 0usize;

    for filename in SUITE_FILES {
        let filepath = vectors_path.join(filename);
        if !filepath.exists() {
            eprintln!("Suite file not found: {} (skipped)", filename);
            continue;
        }

        let raw_bytes = match fs::read(&filepath) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("Failed to read {}: {}", filename, e);
                std::process::exit(1);
            }
        };
        let suite_digest = sha256_hex(&raw_bytes);

        let content = match String::from_utf8(raw_bytes) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Invalid UTF-8 in {}: {}", filename, e);
                std::process::exit(1);
            }
        };
        let root: Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Failed to parse {}: {}", filename, e);
                std::process::exit(1);
            }
        };

        let suite = root.get("suite").and_then(|s| s.as_str()).unwrap_or("");
        let results = run_suite(suite, &root);
        let results_json = serde_json::to_string(&results).unwrap();
        let results_digest = sha256_hex(results_json.as_bytes());

        let empty_vectors = Vec::new();
        let vectors = root.get("vectors").and_then(|v| v.as_array()).unwrap_or(&empty_vectors);
        let mut passed = 0usize;
        let got_map: std::collections::HashMap<String, bool> = results
            .iter()
            .filter_map(|r| {
                Some((
                    r.get("id")?.as_str()?.to_string(),
                    r.get("valid")?.as_bool()?,
                ))
            })
            .collect();

        for v in vectors {
            let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("");
            let expected = v
                .get("expect")
                .and_then(|e| e.get("valid"))
                .and_then(|x| x.as_bool())
                .unwrap_or(false);
            let got = got_map.get(id).copied().unwrap_or(false);
            if got == expected {
                passed += 1;
            }
            total_vectors += 1;
        }
        total_passed += passed;

        eprintln!(
            "  {}: {}/{} {}",
            filename,
            passed,
            vectors.len(),
            if passed == vectors.len() { "ok" } else { "DIVERGENT" }
        );

        suite_entries.push(SuiteEntry {
            file: filename.to_string(),
            suite_digest,
            results_digest,
            passed,
            total: vectors.len(),
        });
    }

    let args = StatementArgs {
        verifier_id: verifier_id.as_ref().unwrap(),
        verifier_name: verifier_name.as_deref(),
        organization: organization.as_deref(),
        implementation: &impl_name,
        commit: &commit,
        suite_entries: &suite_entries,
    };

    let statement = match sign_statement(&args, &signing_key, &public_key_b64u) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to sign statement: {}", e);
            std::process::exit(1);
        }
    };

    let pretty = serde_json::to_string_pretty(&statement).unwrap();
    if let Some(parent) = out_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Err(e) = fs::write(&out_path, format!("{}\n", pretty)) {
        eprintln!("Failed to write statement: {}", e);
        std::process::exit(1);
    }

    eprintln!("E2E: {}/{} vectors matched expectations", total_passed, total_vectors);
    eprintln!("result.status: {}", statement["result"]["status"]);
    eprintln!("statement: {}", out_path.display());
    eprintln!("statement_digest: {}", statement["signature"]["statement_digest"]);
    eprintln!("public_key: {}", public_key_b64u);
}

fn git_commit(vectors_path: &Path) -> String {
    let repo_root = vectors_path.parent().and_then(|p| p.parent());
    if let Some(root) = repo_root {
        if let Ok(output) = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(root)
            .output()
        {
            if output.status.success() {
                let commit = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if commit.len() == 40 {
                    return commit;
                }
            }
        }
    }
    "unknown".to_string()
}

fn run_vectors_file_mode(path: &str) {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open file {}: {}", path, e);
            std::process::exit(1);
        }
    };

    let mut content = String::new();
    if let Err(e) = file.read_to_string(&mut content) {
        eprintln!("Failed to read file: {}", e);
        std::process::exit(1);
    }

    let root: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to parse JSON: {}", e);
            std::process::exit(1);
        }
    };

    let suite = root.get("suite").and_then(|s| s.as_str()).unwrap_or("");
    let results = run_suite(suite, &root);

    print!("{}", serde_json::to_string(&results).unwrap());
}

fn run_suite(suite: &str, root: &Value) -> Vec<Value> {
    if suite.starts_with("EP-CANONICALIZATION") {
        return suites::canonicalization::run(root)
            .into_iter()
            .map(|r| json!({ "id": r.id, "valid": r.valid }))
            .collect();
    }

    if suite == "EP-RECEIPT-v1" {
        return suites::receipts::run(root)
            .into_iter()
            .map(|(id, valid)| json!({ "id": id, "valid": valid }))
            .collect();
    }

    if suite == "EP-SIGNOFF-v1" {
        return suites::signoffs::run(root)
            .into_iter()
            .map(|(id, valid)| json!({ "id": id, "valid": valid }))
            .collect();
    }

    if suite == "EP-QUORUM-v1" {
        return suites::quorum::run(root)
            .into_iter()
            .map(|(id, valid)| json!({ "id": id, "valid": valid }))
            .collect();
    }

    if suite.starts_with("EP-TRUST-RECEIPT-v1") {
        return suites::trust_receipt::run(root)
            .into_iter()
            .map(|(id, valid)| json!({ "id": id, "valid": valid }))
            .collect();
    }

    if suite == "EP-WITNESS-v1" {
        return suites::witness::run(root)
            .into_iter()
            .map(|(id, valid)| json!({ "id": id, "valid": valid }))
            .collect();
    }

    if suite == "EP-SMT-CONSUME-v1" {
        return suites::consumption_proof::run(root)
            .into_iter()
            .map(|(id, valid)| json!({ "id": id, "valid": valid }))
            .collect();
    }

    if suite == "EP-INITIATOR-ATTESTATION-v1" {
        return suites::initiator_attestation::run(root)
            .into_iter()
            .map(|(id, valid)| json!({ "id": id, "valid": valid }))
            .collect();
    }

    if suite == "EP-CURRENCY-v1" {
        return suites::currency::run(root)
            .into_iter()
            .map(|(id, valid)| json!({ "id": id, "valid": valid }))
            .collect();
    }

    if suite == "EP-REVOCATION-v1" {
        return suites::revocation::run(root)
            .into_iter()
            .map(|(id, valid)| json!({ "id": id, "valid": valid }))
            .collect();
    }

    if suite == "EP-TIME-ATTESTATION-v1" {
        return suites::time_attestation::run(root)
            .into_iter()
            .map(|(id, valid)| json!({ "id": id, "valid": valid }))
            .collect();
    }

    if suite == "EP-BOUNDARY-v1" {
        return suites::receipts::run(root)
            .into_iter()
            .map(|(id, valid)| json!({ "id": id, "valid": valid }))
            .collect();
    }

    if suite == "EP-PROVENANCE-CHAIN-v1" {
        return suites::provenance::run(root)
            .into_iter()
            .map(|(id, valid)| json!({ "id": id, "valid": valid }))
            .collect();
    }

    if suite == "EP-EVIDENCE-RECORD-v1" {
        return suites::evidence_record::run(root)
            .into_iter()
            .map(|(id, valid)| json!({ "id": id, "valid": valid }))
            .collect();
    }

    if suite == "EP-TIMESTAMP-PROOF-v1" {
        return suites::timestamp_proof::run(root)
            .into_iter()
            .map(|(id, valid)| json!({ "id": id, "valid": valid }))
            .collect();
    }

    root.get("vectors")
        .and_then(|v| v.as_array())
        .map(|vectors| {
            vectors
                .iter()
                .filter_map(|v| {
                    let id = v.get("id")?.as_str()?;
                    Some(json!({ "id": id, "valid": false }))
                })
                .collect()
        })
        .unwrap_or_default()
}