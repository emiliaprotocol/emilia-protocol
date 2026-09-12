# Rust current-corpus diagnostic, 2026-09-12

This is a same-team evaluator diagnostic against externally authored source.
It is not an implementer submission, construction statement, independent
attestation, acceptance, or replacement for the frozen 164-vector result.

## Exact inputs

- EMILIA source: `b1275b08f91939a2330aee26a03d0a6bfda375d6`
- live manifest SHA-256: `375e96ecf7dfc21ce0d890c2ec1165fd53593c03db44b8fc46881e6409996971`
- Rust repository: `https://github.com/jdieselny/ecr-wg`
- Rust source commit: `7faba36010e7590727bebbc5b9dcceee60539b9b`
- Rust tree: `0553c5fa0a5c4b566703e0d8ef9864dc33e5176d`
- `Cargo.lock` SHA-256: `8e81ab335145e9a82e50a9c1731227a47b22c40dcbbf0e40b74751bd08225265`
- build image: `rust@sha256:652612f07bfbbdfa3af34761c1e435094c00dde4a98036132fca28c7bb2b165c`
- rebuilt binary SHA-256: `96bb373649fc65e812565d52e9d71157dd703fe7b5e6320784078c65f3ea3472`
- current hostility corpus SHA-256: `5cd69b7f801e864b6a25d7bd8f9dc92907583627a36ecd37956d0b4442f6ff3a`

Dependencies were fetched according to the locked checksums, then the build
was repeated with the source mounted read-only and networking disabled. The
runner was executed with networking disabled, a read-only root filesystem,
all capabilities dropped, `no-new-privileges`, and PID and memory limits.
Only each input file and the rebuilt binary volume were mounted read-only.

## Result

The three EMILIA-maintained ports agreed over 402 structured cases and six
raw-parser refusals. The immutable Rust source produced 32 divergences. These
include resolution, quorum, revocation, outcome binding, authority-document
proof join, trust receipt, AEC role, and the required malformed
`predicted_effects` regression. For that regression, all three same-team ports
returned `{"outcome":"incomparable"}` while Rust returned
`{"valid":false}`.

The complete machine-readable diagnostic is
`diagnostic-rust-current-hostility-2026-09-12.json`. Its external
implementation entry distinguishes the rebuilt binary digest from the
evaluator-owned Docker wrapper digest.

An updated external submission needs to implement the v3 typed result
contract for these current suites, return `outcome: incomparable` for malformed
`predicted_effects`, and pass the same manifest-bound corpus. Clean-room
acceptance additionally requires the implementer's signed construction
statement and a separate independent-organization attestation.
