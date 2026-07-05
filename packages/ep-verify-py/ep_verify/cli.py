# SPDX-License-Identifier: Apache-2.0
"""ep-verify <receipt.json> [--keys keys.json]

Verifies one EP-RECEIPT-v1 document fully offline against issuer public
key(s) you pin (base64url SPKI, a JSON string, array, or {kid: key} map).
Prints VERIFIED or REFUSED plus a machine-readable JSON line; exit 0 only
on VERIFIED. Fail closed: any error, missing key, or malformed input
refuses. Verification proves signature/binding/anchor integrity against
the pinned keys; it never proves the action was correct or sufficient.
"""
import json
import sys

from emilia_verify import verify_receipt

USAGE = "usage: ep-verify <receipt.json> [--keys keys.json]"


def _load_keys(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, str):
        return [data]
    if isinstance(data, list):
        return [k for k in data if isinstance(k, str)]
    if isinstance(data, dict):
        return [v for v in data.values() if isinstance(v, str)]
    return []


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__ if argv and argv[0] in ("-h", "--help") else USAGE)
        return 0 if argv else 1
    receipt_path, keys_path = argv[0], None
    if "--keys" in argv:
        i = argv.index("--keys")
        if i + 1 >= len(argv):
            print("REFUSED")
            print(json.dumps({"result": "refused", "reason": "keys_flag_without_path"}))
            return 1
        keys_path = argv[i + 1]

    try:
        with open(receipt_path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except Exception:
        print("REFUSED")
        print(json.dumps({"result": "refused", "reason": "receipt_unreadable_or_malformed"}))
        return 1

    keys = []
    if keys_path:
        try:
            keys = _load_keys(keys_path)
        except Exception:
            print("REFUSED")
            print(json.dumps({"result": "refused", "reason": "keys_unreadable_or_malformed"}))
            return 1
    if not keys:
        print("REFUSED")
        print(json.dumps({"result": "refused", "reason": "no_pinned_keys"}))
        return 1

    last_error = None
    for key in keys:
        try:
            result = verify_receipt(doc, key)
        except Exception as e:  # verifier crash on hostile input = refusal
            last_error = f"verifier_error:{type(e).__name__}"
            continue
        if getattr(result, "valid", False) or (isinstance(result, dict) and result.get("valid")):
            checks = getattr(result, "checks", None) or (result.get("checks") if isinstance(result, dict) else None)
            print("VERIFIED")
            print(json.dumps({"result": "verified", "receipt_id": (doc.get("payload") or {}).get("receipt_id"), "checks": checks}, default=str))
            return 0
        err = getattr(result, "error", None) or (result.get("error") if isinstance(result, dict) else None)
        last_error = err or "signature_invalid"

    print("REFUSED")
    print(json.dumps({"result": "refused", "reason": last_error or "no_key_verified"}, default=str))
    return 1


if __name__ == "__main__":
    sys.exit(main())
