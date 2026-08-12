<!-- SPDX-License-Identifier: Apache-2.0 -->

# CCS 1.1.1 L1 release audit

**Status:** private interoperability hardening note. This is not a conformance
claim, an independent implementation, or a finding about Correctover's
unreleased source.

## What 1.1.1 fixed

A clean installation of `ccs-verifier==1.1.1` reports runtime version `1.1.1`
and includes `ccs_verifier.ccs_verifier_l1`. Installing the documented
`ed25519` extra makes the shipped Ed25519 sign-and-verify path run successfully.
This closes the packaging mismatch documented for the source-locked 1.1.0
profile.

## What still blocks a portable exact-action profile

1. **The signing serializer is deterministic Python JSON, not RFC 8785 JCS.**
   It uses `json.dumps(sort_keys=True, separators=(",", ":"),
   ensure_ascii=False)`. Python sorts object names by Unicode code point,
   while RFC 8785 sorts by UTF-16 code units, and Python's number formatting is
   not ECMAScript's serialization. The audit prints two concrete differences:
   the ordering of `U+1F600` and `U+FFFD`, and `0.000001` serialized as
   `1e-06`. A verifier implementing RFC 8785 from the draft would sign or
   verify different bytes.
2. **Material digests remain 64 bits.** `compute_hash`, `args_digest`,
   `request_hash`, `response_hash`, `runtime_context_hash`, and `config_hash`
   return the first 16 hexadecimal characters of SHA-256. The public-key
   fingerprint is also 16 hexadecimal characters. This is not the full
   SHA-256 action coverage described by the CCS-to-AEB profile.
3. **A signed ALLOW need not carry the claimed binding fields.** The shipped
   builder signs a receipt whose `issuer`, `audience`, `action`,
   `issuance_bound`, and `expiry_bound` retain empty or zero defaults. Signature
   validity therefore does not establish that those fields are present or
   acceptable. A relying party needs a closed validation profile before it can
   accept the receipt.
4. **Unknown fields are silently dropped.** `L1Receipt.from_dict` filters input
   to known dataclass fields. A receipt with an added security-critical member
   is reparsed without that member and the original signature still verifies.
   This creates interpretation drift unless the receiving profile rejects every
   unknown member before native verification.
5. **The fingerprint is not a trust root.** Verification still requires the raw
   public key from an authenticated, relying-party-pinned source. The
   `public_key_fingerprint` can select or compare a key, but it cannot provide
   that key or establish why the relying party trusts it.

The older L0 path still uses a colon-delimited HMAC payload. The L1 path signs a
JSON object and therefore does not inherit that delimiter ambiguity. The two
paths should not be discussed as if they have the same signed-byte problem.

## Reproduce

Run in a disposable environment:

```sh
python3 -m venv /tmp/ccs-l1-audit
/tmp/ccs-l1-audit/bin/pip install 'ccs-verifier[ed25519]==1.1.1'
/tmp/ccs-l1-audit/bin/python interop/ccs-aeb/audit_l1_release.py
```

The expected security-relevant observations are:

- Ed25519 signature verification succeeds;
- action, audience, and issuer are empty in the signed builder output;
- the expiry bound is zero;
- the argument digest is 16 hexadecimal characters;
- an unknown member is dropped and the signature still verifies; and
- Python's deterministic JSON bytes differ from RFC 8785 for the printed
  Unicode-key and number cases.

## Disposition

Keep the existing 1.1.0 HMAC adapter source-locked and explicitly local. Do not
silently retarget it to 1.1.1. A portable L1 AEB adapter should wait for a
release that defines one interoperable signed-byte algorithm, uses full
material-action digests, rejects unknown members, requires the issuer,
audience, action, and freshness fields needed by the profile, and leaves trust
root selection and replay consumption to the relying party.
