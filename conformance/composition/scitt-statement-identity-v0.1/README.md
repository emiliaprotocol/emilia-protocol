# SCITT Signed Statement identity separation

This independent runner reproduces the identity problem reported in
[Anton Sokolov's SCITT thread](https://mailarchive.ietf.org/arch/msg/scitt/fzyFaUKmPlrDxibLm6Ejq7PEABg/).
A fixed P-256 signing input has two mathematically equivalent signatures. Both
verify, both envelopes are deterministically encoded, and the exact envelope
digests differ.

The fixture is the classic ECDSA `s`-malleability pair: both signatures have
the same `r`, and `s_B = n - s_A`; signature A is high-S and signature B is
the canonical low-S form. They are not two separate signing executions.
Rejecting high-S signatures at an ingress can prevent that verifier from
accepting the non-canonical form. It does not, by itself, decide whether a
Transparency Service entry, a signing input, and an application claim should
share one identifier, especially when an envelope was registered or transformed
before that check.

The profile keeps three identities separate:

| Identity | Computation | Meaning |
| --- | --- | --- |
| `statement_entry_digest` | SHA-256 over exact tagged `COSE_Sign1` bytes | one exact envelope or registration entry |
| `signing_input_digest` | SHA-256 over the RFC 9052 `Sig_structure` | the protected header and payload presented to the signature algorithm |
| `authorization_payload_digest` | SHA-256 over the canonical EP receipt payload | the profile-defined authorization claim, subject to separate issuer, signature, mapping, and policy checks |

An entry digest can locate an exact logged envelope. It cannot replace the
authorization payload digest. A signature-only envelope difference is reported
as `same_signing_input_different_envelope`, not as payload tampering.

## Run

```sh
npm --prefix packages/verify run build
npm run build:standalone-runtimes
node --test conformance/composition/scitt-statement-identity-v0.1/run.node-test.mjs
node conformance/composition/scitt-statement-identity-v0.1/run.mjs --check
```

The static public key and signatures are conformance fixtures only. This is an
identity and composition result. It does not claim a signature forgery,
authorization bypass, Transparency Service registration, or SCITT WG
conformance.
