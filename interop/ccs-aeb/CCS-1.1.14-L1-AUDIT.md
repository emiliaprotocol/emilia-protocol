<!-- SPDX-License-Identifier: Apache-2.0 -->
# CCS 1.1.14 L1 verification receipt

Verified on 2026-08-14 against the public release and mirror:

| Artifact | SHA-256 |
| --- | --- |
| `ccs_verifier-1.1.14.tar.gz` | `9f75676e5b3d6ace8e91742d8b78b6d15b2d4250414326c17cc9e1aa361ec318` |
| `ccs_verifier-1.1.14-py3-none-any.whl` | `04a7857253bac2fca25611d17280cebf92fd0a7a2987a4d7ece973d492b17c83` |

The wheel, source distribution, and Codeberg mirror each passed 157 tests.
The relevant `trust.py`, expiry-regression, and reference-vector bytes matched
between the source distribution and Codeberg at
`ecee6e8ba623fd4fd117a77062a1fe43e3c56de0`. The expiry repair first appears
at `bf2e48671b580a513fb1638b5c3eafba4858243f`.

The source-locked adapter verifies the exact published reference vector. It
requires the receipt's Ed25519 signature, embedded-key fingerprint, and raw
key to agree with one relying-party-pinned issuer key. It separately enforces
audience, expiry, maximum clock skew, rule version, action, and tool.

For action mapping, the executor supplies the action it is about to perform.
The adapter verifies that the signed CCS `action` and `tool` match and that the
full signed `args_digest` equals the RFC 8785 SHA-256 digest of the executor's
arguments. Only then does it derive the CAID. The receipt's `params_hash` is
not used for this join because the shipped reference value is profile-specific
and is not the full argument digest.

The reference key is deterministic public test material. A passing result is
not production trust, an independent CCS implementation, or evidence of
provider entry or effect.
