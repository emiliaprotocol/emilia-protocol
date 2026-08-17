# EMILIA Protocol External Verification Guide

External verification provides a cryptographically secure way for third parties to independently verify EMILIA protocol data (e.g., statements, conformance runs) and assert their findings. This allows ecosystems to run clean-room implementations and cross-verify each other without placing trust in a single codebase.

## Overview

The standard EMILIA verification statement is known as `EP-EXTERNAL-VERIFICATION-STATEMENT-v1`. It acts as a wrapper that records the result of an independent check and is signed using an Ed25519 key.

This directory contains reference tools for working with these statements:
*   `generate-key.mjs` - Mints a fresh Ed25519 keypair.
*   `sign-statement.mjs` - Compares your verifier's results against the official EMILIA vectors and signs the outcome.
*   `verify-statement.mjs` - Validates the cryptographic signature of an external verification statement against a set of pinned, trusted keys.

## Step-by-Step: Independent Verification Run

### 1. Execute Your Verifier
Build your verifier independently using any programming language. To verify conformance, have it evaluate all vector files in `conformance/vectors/*.json`.

For each vector file, output a matching `.results.json` file structured as an array:
```json
[
  { "id": "vector-1", "valid": true },
  { "id": "vector-2", "valid": false }
]
```

### 2. Generate an Identity Key
Before signing your results, you must establish an identity. Run the key generator:
```bash
node generate-key.mjs --out out/my-key
```
This generates `private-key.pem` and `public.key`, and it will provide you with an auto-derived key ID.

### 3. Sign the Statement
Pass your results to the signing script to evaluate them against the standard vectors and cryptographically sign the outcome:
```bash
node sign-statement.mjs \
  --results out/results \
  --verifier-id ext:verifier:my-custom-verifier \
  --implementation "My Independent Runner v1" \
  --key out/my-key/private-key.pem \
  --out out/
```
The resulting `statement.json` is a highly portable, verifiable declaration of your runner's performance.

### 4. Verify the Statement (Relying Parties)
Other network participants can verify your statement. They must configure their node to pin your `public.key` and map it to your `verifier-id`. They can test this out using:
```bash
node independent-verify-demo.mjs
```

## Critical Requirements
*   **Vector Consistency**: Ensure your local copy of `conformance/vectors/` uses strictly `LF` line endings (`git config core.autocrlf false`), otherwise canonicalization digests will mismatch.
*   **Fresh Keys**: Do not reuse reference keys. Generate unique keys to maintain strong, non-repudiable identities.
