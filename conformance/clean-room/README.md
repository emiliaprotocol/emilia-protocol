# External implementation intake

This kit separates three claims that must not be collapsed:

1. **Conformant:** the submitted executable returns the expected verdict for
   every byte-pinned vector.
2. **Self-attested clean-room:** its authors state that they implemented from
   specifications without access to EMILIA reference source. This is a claim,
   not proof.
3. **Third-party attested clean-room:** the unsigned manifest bytes are signed
   by an attestor key the evaluator pinned independently. This establishes who
   made the statement, not that the implementation is bug-free.

EMILIA's JavaScript, Python, and Go ports are deliberately labeled one-team
ports. They may pass this harness as reference implementations, but they cannot
earn either clean-room status.

## Runner protocol

The evaluator invokes the submitted executable once per suite:

```
runner [fixed arguments...] /absolute/path/to/vectors.json
```

The executable writes only a JSON array to stdout:

```json
[{"id":"accept_valid","valid":true},{"id":"reject_tampered","valid":false}]
```

It must return every vector exactly once, add no vector IDs, and exit nonzero on
internal failure. Network access is not part of the protocol. The evaluator
checks every suite SHA-256 against `bundle.v1.json` before execution.

## Evaluate

```
node scripts/verify-clean-room-submission.mjs \
  --manifest /path/to/submission.json \
  --emit /tmp/submission-result.json \
  -- /path/to/runner --fixed-argument
```

To recognize a third-party attestation, also pass a JSON trust list with
`--trusted-attestors /path/to/pins.json`. The trust list has
`{"keys":[{"key_id","organization","public_key_spki_base64url"}]}`. The
Ed25519 signature covers the RFC 8785 canonical form of the manifest with its
`attestation` member omitted.

The checked-in `reference-port.manifest.json` is a harness self-test and
explicitly claims no independence.
