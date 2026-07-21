# Citation annotations

EMILIA statements about implementation, testing, and formal analysis use a
method-and-scope annotation. The annotation is a compact index into executable
evidence; it is not a substitute for the assumptions and exclusions in
`security/claims.v1.json`.

## Form

Use this order:

```text
[STATUS; method=METHOD; scope=SCOPE; artifact=PATH; result=PATH; assumptions=SHORT-LIST]
```

Every field is required for a claim about verification. `result` must identify
an immutable or content-bound result produced from the named artifact. A paper
may shorten the annotation in running text only when its claim-to-evidence
table contains the complete form.

## Status vocabulary

| Status | Permitted meaning |
|---|---|
| `IMPLEMENTED-REFERENCE` | The named reference implementation contains the behavior. This does not imply deployment or independent use. |
| `EXECUTABLE-CROSS-LANGUAGE` | Shared vectors execute successfully against the named language implementations. This is conformance testing, not a refinement proof. |
| `FORMAL-TLC-BOUNDED` | TLC found no counterexample in the exact finite configuration named by the annotation. |
| `FORMAL-ALLOY-BOUNDED` | Alloy found no counterexample in the exact finite scope named by the annotation. |
| `FORMAL-TAMARIN-SYMBOLIC` | Tamarin established the named lemma under the symbolic model and its assumptions. |
| `BOUNDED-EXHAUSTIVE-SAME-TEAM` | The repository's deterministic explorer checked every state in its declared finite domain and demonstrated a counterexample after weakening the property. This is same-team evidence, not an independent formal proof. |
| `EXTERNAL-DEPENDENCY` | The result depends on an external verifier, operator, service, hardware root, or deployment that EMILIA does not establish. |
| `STAGED-PRIVATE` | The artifact exists locally but is unpublished and must not be described as a posted standard or public implementation. |
| `VISION` | The statement is a proposed direction, not an implemented or verified property. |

`VERIFIED` is not a standalone status. `PROVEN` is reserved for a named theorem
with an explicit proof system, assumptions, and proof artifact; bounded TLC or
Alloy results must not be relabeled as an unbounded proof.

## Examples

```text
[FORMAL-TLC-BOUNDED; method=TLC 1.7.4; scope=2 attempts/1 stable operation;
 artifact=formal/ep_receipt_program.tla;
 result=formal/results/ep-receipt-program.tlc.summary.txt;
 assumptions=atomic operation reservation, modeled transitions]
```

```text
[EXTERNAL-DEPENDENCY; method=RATS appraisal result consumed as EAT/JWT;
 scope=RP-pinned signer/profile/nonce/action/build/freshness;
 artifact=packages/verify/src/platform-attestation.ts;
 result=packages/verify/platform-attestation.test.js;
 assumptions=external verifier correctly appraised raw platform evidence]
```

## Publication rule

Before a claim is used in a paper, deck, website, or diligence response:

1. Add or update its entry in `security/claims.v1.json`.
2. Run the security-case emitter and checker so paths, symbols, vectors, tests,
   formal result hashes, assumptions, and exclusions are revalidated.
3. Copy the claim's exact scope into the publication's claim-to-evidence table.
4. Keep external dependencies and unpublished artifacts visible in the prose.

The repository claim is the narrowest statement that all named evidence
supports. Marketing language may simplify vocabulary, but it may not enlarge
that statement.
