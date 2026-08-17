# Preprint staging: Action-Bound Injective Authorization

**Status: IACR submission `xxxx/111011` was rejected on 15 August 2026. The focused revision was published as an unrefereed Zenodo preprint on 16 August 2026.**

The editor asked for a paper that is clear, readable, self-contained, somewhat new and interesting, and supported by proofs or convincing arguments. The rejected 27-page package remains preserved under `submissions/xxxx-111011/`. It did not receive a permanent ePrint number.

The replacement package is under `eprint-revision/`. It is a shorter cryptology paper, not a product or standards report. It now contains:

- a precise signer-harvesting adversary;
- closed action, policy, initiator, audience, authorization-instance, and slot contexts;
- explicit transplantation, duplicate-admission, and quorum-substitution games;
- explicit per-key reductions, an advantage table, necessity propositions, and a composition theorem with cryptographic and state-service failure terms;
- an acceptance-prefix integrity lemma with a stated impossibility boundary for offline anti-backdating;
- Ed25519 and ML-DSA instantiations plus a symbolic-to-computational correspondence table;
- direct comparison with transaction authorization, policy-compliant signatures, attribute-based signatures, capabilities, and StatefulAuth;
- the exact positive and negative Tamarin results already recorded in the repository; and
- clear limits on human identity, rendering fidelity, enforcement bypass, and provider effects.

## Current revision

| Artifact | State |
|---|---|
| `eprint-revision/main.tex` | Focused source |
| `eprint-revision/main.pdf` | Reproducible PDF built from the focused source |
| `eprint-revision/check.mjs` | Source, PDF, proof-record, and citation guard |
| `eprint-revision/README.md` | Build and review record |
| `eprint-revision/VERIFICATION.md` | Source digests, exact proof results, and deterministic PDF receipt |

## Verification

From the repository root:

```sh
cd papers/preprint/eprint-revision
SOURCE_DATE_EPOCH=1786752000 tectonic --keep-logs --outdir build main.tex
cp build/main.pdf main.pdf
node check.mjs
```

The Tamarin model runners are:

```sh
cd formal/tamarin
TAMARIN_OUT_DIR=/tmp/emilia-tamarin-receipt ./run-receipt-core.sh
TAMARIN_OUT_DIR=/tmp/emilia-tamarin-quorum ./run-quorum.sh
```

They use the repository-pinned Docker image and require a working Docker daemon.

The broader rejected package remains governed by the repository's legacy
preprint synchronization guard. These are dated synchronization values for that
preserved package, not claims added back to the focused cryptology revision:

- Conformance 21 suites / 331 vectors
- 20 composed obligations + 8 deliberate falsifications
- TLA+ 413,137 states / 26 invariants
- Alloy 32 assertions across four CI-gated models, version 6.2.0
- Rust external verifier / 164 vectors / 359 hostility cases

Reproduce the preserved broader package's synchronization checks separately:

```sh
npm run preprint:build
npm run check:preprint
npm run test:preprint
```

## Publication boundary

- Zenodo v3 is public at version DOI `10.5281/zenodo.21968577`; the all-versions concept DOI is `10.5281/zenodo.21520972`.
- The exact public PDF is `eprint-revision/main.pdf`, 19 pages, SHA-256 `f158dbcd36f8831cc8f39aa7d37cfd505679483b57b29bb33dc676a9af75867e`.
- Zenodo publication is not refereed acceptance, IACR acceptance, or an IETF status claim.
- The rejected IACR PDF remains immutable provenance and must not be described as the Zenodo revision.
- The paper remains single-author: Iman Schrock, EMILIA Protocol, Inc.
- The revision does not claim exactly-once physical execution.
