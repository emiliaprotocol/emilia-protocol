# ep-qualify

`ep-qualify` is a thin, offline command-line interface over EMILIA Gate Qualification v2's `evaluateQualification`. It verifies and evaluates a supplied qualification graph without fetching evidence, invoking a model or provider, reserving or consuming anything, or mutating storage.

## Usage

```sh
npx ep-qualify qualification.json
```

Use `-` to read from standard input:

```sh
ep-qualify - < qualification.json
```

The input must be exactly one JSON object with both fields:

```json
{
  "bundle": {},
  "context": {}
}
```

`bundle` is the complete Gate Qualification v2 evidence graph. `context` supplies the expected candidate, assignment, policy, protected-request and status-authority bindings, freshness limits, minimum model-pinning strength, and explicit trust policies used by `evaluateQualification`.

The CLI never infers trusted keys from the bundle and supplies no trust defaults. The caller is responsible for obtaining and pinning the `context.trust` policy independently; placing keys in this input does not by itself establish their provenance. The CLI also does not fetch current time or status: evaluation is relative to the supplied `context.now` and status observation.

Input is limited to 8 MiB, decoded as strict UTF-8, checked with `@emilia-protocol/verify/strict-json`, and rejected on malformed JSON, duplicate object member names, or excessive JSON nesting before evaluation.

## Output and exit status

Every evaluation prints exactly two lines (the JSON below is abridged):

```text
QUALIFIED
{"decision":"QUALIFIED","reason":"qualified","verification":"VERIFIED","acceptance":"ACCEPTED"}
```

The second line is the complete machine-readable decision returned by the evaluator. Input and CLI failures produce an `INDETERMINATE` decision with a machine-readable reason.

- `QUALIFIED` means the supplied evidence graph verifies, is accepted under the supplied trust policy, is bound to the supplied context, and is current as observed. Exit status: `0`.
- `NOT_QUALIFIED` is a closed refusal when the evaluator has a definitive disqualifying result, such as revocation. Exit status: `1`.
- `INDETERMINATE` means qualification could not be established, including stale, malformed, incomplete, untrusted, or unverifiable input. Exit status: `1`.

`QUALIFIED` is a verification result, not an authorization decision. It does not grant permission, establish legality or business appropriateness, invoke an action, or claim that an action was reserved, consumed, or executed.

## Development

```sh
npm test
```

The CLI tests mint a complete signed fixture and cover valid qualification, signed-artifact tampering, stale and revoked status, indeterminate evaluation, malformed and duplicate-key input, the input-size bound, immutable input bytes, and absence of implicit trust.
