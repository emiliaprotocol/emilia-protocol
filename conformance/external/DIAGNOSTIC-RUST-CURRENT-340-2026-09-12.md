# Rust final 340-vector diagnostic, 2026-09-12

This is a same-team evaluator diagnostic against externally authored source.
It is not an implementer submission, construction statement, independent
attestation, strict clean-room acceptance, or replacement for either the
frozen 164-vector result or the earlier 335-vector diagnostic.

## Exact inputs

- EMILIA source commit: `9cd4e6df2ab801e7ccad04bfe63647d67fb234ea`
- EMILIA source tree: `81c97af2399dd44b1c82e8e08b342d0cf2fb3b78`
- canonical conformance claim: `f7c6047d39dc5a553de61901d85a42ce5a18e51289f6437d57824e81d916fe99`
- manifest SHA-256: `4d452c38a9ce9f6b78e916246a1733d56cd8ae2d0bd1123d39df329d0401d6fa`
- manifest coverage: 21 suites, 340 vectors
- Rust repository: `https://github.com/jdieselny/ecr-wg`
- Rust source commit: `7faba36010e7590727bebbc5b9dcceee60539b9b`
- Rust tree: `0553c5fa0a5c4b566703e0d8ef9864dc33e5176d`
- `Cargo.lock` SHA-256: `8e81ab335145e9a82e50a9c1731227a47b22c40dcbbf0e40b74751bd08225265`
- pinned image: `rust@sha256:652612f07bfbbdfa3af34761c1e435094c00dde4a98036132fca28c7bb2b165c`
- local image ID: `sha256:652612f07bfbbdfa3af34761c1e435094c00dde4a98036132fca28c7bb2b165c`
- unchanged Rust binary SHA-256: `96bb373649fc65e812565d52e9d71157dd703fe7b5e6320784078c65f3ea3472`
- evaluator wrapper SHA-256: `42feec42d184f5761edbd6fae1af825ad1c251f01b1e89c6c865e5d14b63edc0`
- generated hostility corpus SHA-256: `d7dc50bc255b4b4720910abe1c72f18563728a45a391b3feb46b74db2bc49e53`

No source or dependency was downloaded and the Rust binary was not rebuilt.
The evaluator reused the previously built binary volume and runner config at
`/tmp/ep-rust-250.gCdBtE`. Execution used a read-only root filesystem, no
network, all capabilities dropped, `no-new-privileges`, PID and memory limits,
and read-only mounts for the binary volume and each generated input.

## Result

The three EMILIA-maintained ports agreed over 402 structured cases and six
raw-parser refusals. The unchanged Rust binary produced 36 divergences. The
increase from the earlier 32 is caused by the final quorum corpus additions;
the earlier report remains preserved rather than rewritten.

The required malformed `predicted_effects` regression still diverges: all
three same-team ports returned `{"outcome":"incomparable"}`, while Rust
returned `{"valid":false}`. Other divergences cover resolution, quorum,
revocation, outcome binding, authority-document proof join, trust receipt,
and AEC role behavior.

The complete machine-readable result is
`diagnostic-rust-current-hostility-340-2026-09-12.json`. Its implementation
record distinguishes the Rust binary digest from the evaluator-owned wrapper
digest. An updated external implementation and signed construction statement,
plus a separate independent-organization attestation, remain required for
strict clean-room acceptance.
