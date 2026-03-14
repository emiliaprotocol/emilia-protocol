#!/usr/bin/env python3
"""
EP Conformance Suite — Python Hash Verification

Verifies that a Python implementation produces identical SHA-256 hashes
to the canonical JavaScript reference implementation.

Usage:
    python3 verify_hashes.py

If all hashes match, this implementation is EP-hash-compatible.
"""

import json
import hashlib
from pathlib import Path


def canonical_json(obj):
    """
    Canonical JSON serialization matching EP's JavaScript implementation.
    Rules:
      - Objects: sort keys lexicographically, recurse
      - Arrays: preserve order, recurse
      - Primitives: standard JSON serialization
      - No whitespace between tokens
      - null, true, false are lowercase
    """
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, (int, float)):
        # Match JavaScript number serialization
        if isinstance(obj, float) and obj == int(obj):
            return str(int(obj))
        return str(obj)
    if isinstance(obj, str):
        return json.dumps(obj)  # Handles escaping
    if isinstance(obj, list):
        return "[" + ",".join(canonical_json(item) for item in obj) + "]"
    if isinstance(obj, dict):
        keys = sorted(obj.keys())
        pairs = [json.dumps(k) + ":" + canonical_json(obj[k]) for k in keys]
        return "{" + ",".join(pairs) + "}"
    raise TypeError(f"Cannot serialize {type(obj)}")


def compute_receipt_hash(receipt, previous_hash=None):
    """
    Compute EP canonical receipt hash.
    Must match the JavaScript computeReceiptHash() output exactly.
    """
    payload_obj = {
        "entity_id": receipt.get("entity_id"),
        "submitted_by": receipt.get("submitted_by"),
        "transaction_ref": receipt.get("transaction_ref"),
        "transaction_type": receipt.get("transaction_type"),
        "context": receipt.get("context"),
        "delivery_accuracy": receipt.get("delivery_accuracy"),
        "product_accuracy": receipt.get("product_accuracy"),
        "price_integrity": receipt.get("price_integrity"),
        "return_processing": receipt.get("return_processing"),
        "agent_satisfaction": receipt.get("agent_satisfaction"),
        "agent_behavior": receipt.get("agent_behavior"),
        "claims": receipt.get("claims"),
        "evidence": receipt.get("evidence"),
        "submitter_score": receipt.get("submitter_score"),
        "submitter_established": receipt.get("submitter_established"),
        "previous_hash": previous_hash,
        "receipt_version": 1,
    }
    
    payload = canonical_json(payload_obj)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def main():
    # Load fixtures
    fixtures_path = Path(__file__).parent / "fixtures.json"
    if not fixtures_path.exists():
        fixtures_path = Path(__file__).parent.parent / "conformance" / "fixtures.json"
    
    with open(fixtures_path) as f:
        fixtures = json.load(f)
    
    print("EP Conformance Suite — Python Hash Verification")
    print("=" * 60)
    print()
    
    passed = 0
    failed = 0
    
    for fixture in fixtures["hash_fixtures"]:
        expected = fixture["expected_hash"]
        computed = compute_receipt_hash(fixture["receipt"], fixture["previous_hash"])
        
        match = computed == expected
        status = "✓ PASS" if match else "✗ FAIL"
        
        print(f"  {status}  {fixture['name']}")
        if not match:
            print(f"         Expected: {expected}")
            print(f"         Got:      {computed}")
            failed += 1
        else:
            passed += 1
    
    print()
    print(f"Results: {passed} passed, {failed} failed")
    print()
    
    if failed == 0:
        print("✓ This Python implementation is EP-hash-compatible.")
        print("  It produces identical SHA-256 hashes to the reference implementation.")
    else:
        print("✗ Hash mismatch detected.")
        print("  Check canonical_json() serialization — key ordering, null handling,")
        print("  and number formatting must match JavaScript exactly.")
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
