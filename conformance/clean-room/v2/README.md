# Current-bundle clean-room kit v2

This directory defines a source-free, byte-pinned challenge over the exact
21-suite, 329-vector conformance manifest at base commit
`b83cc4361c8cb0a0531eda309b7d117bb9964a83`.

The kit separates three results:

1. **Conformance** means a pinned runner returned every expected typed result.
2. **Construction claim verification** means a separately supplied statement
   was signed by an evaluator-pinned attestor outside the implementation team.
3. **Acceptance** requires both. It remains `false` when the independent
   attestation is absent.

No v2 result is, by itself, evidence that an implementation was independently
constructed. The evaluator does not infer independence from language,
repository ownership, successful vectors, or an implementation-team signature.

## Runner protocol

The evaluator invokes the exact read-only executable named by the submission:

```text
runner [fixed arguments...] /absolute/path/to/execution-suite.json
```

The runner writes only a JSON array:

```json
[
  {
    "id": "accept_valid",
    "result": {
      "valid": true
    }
  }
]
```

`result` MUST be an object. Every vector ID MUST appear exactly once. Unknown,
missing, and duplicate IDs are refused. The complete typed result object is
compared with the vector's `expect` object. When an expectation contains
`reason_contains`, the runner returns the remaining expected fields plus a
`reasons` array of strings containing that text.

For `authority-document-proof-join.v1.json`, the evaluator executes the
byte-pinned companion
`authority-document-proof-join.exec.v1.json`. The companion supplies the full
machine result and digest set while the catalogue remains the counted public
suite.

## Separate construction attestation

The submission manifest contains no embedded independence signature. Supply a
distinct `EP-CLEAN-ROOM-INDEPENDENT-ATTESTATION-v2` document and an
evaluator-controlled trusted-attestor list. The signature covers the canonical
JSON form of the attestation with `signature` omitted.

The signed claim binds:

- the canonical submission digest;
- implementation identity, team, source commit, and runner artifact;
- vector-bundle, current-manifest, and Authority companion hashes; and
- explicit `reference_source_access: "none"` and
  `emilia_affiliation: "none"` statements.

An unsigned claim, an unpinned key, a same-team signer, an EMILIA-affiliated
signer, or a signature over different bytes is refused. A missing attestation
does not become a claim: conformance may be reported, but acceptance remains
false.

See `docs/conformance/CLEAN-ROOM-V2.md` for build and evaluation commands.
