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

Candidates receive the byte-pinned `specification-bundle.v1.json` and
`bundle.v1.json`; neither bundle includes EMILIA implementation source. The
public procurement-ready requirements are in `EXTERNAL-CHALLENGE.md`.

The bundle paths are stable protocol identifiers, while evaluator reads are
served from `frozen-v1/`. That directory contains the exact historical bytes
named by both bundles. Live specifications and vectors may evolve without
silently changing an already-issued clean-room challenge.

The public challenge release includes a standalone archive containing only the
allowed inputs. Maintainers build it from an immutable commit with:

```sh
npm run conformance:clean-room:kit
```

The command verifies every declared file hash, refuses implementation-source
paths, produces the archive twice, requires byte-identical output, and emits a
sidecar report binding the source commit, archive hash, and exact file allowlist.

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
checks every suite SHA-256 against `bundle.v1.json` before execution. The signed
manifest also binds the exact runner artifact hash and fixed arguments, so the
evaluator cannot accidentally test a different executable than the one attested.

## Evaluate

```
node scripts/verify-clean-room-submission.mjs \
  --manifest /path/to/submission.json \
  --emit /tmp/submission-result.json \
  -- /path/to/runner --fixed-argument
```

To recognize a third-party attestation, also pass a JSON trust list with
`--trusted-attestors /path/to/pins.json`. The trust list has
`{"keys":[{"key_id","organization","independent":true,"public_key_spki_base64url"}]}`. The
Ed25519 signature covers the RFC 8785 canonical form of the manifest with its
`attestation` member omitted.

Production acceptance uses `--require-external`. That mode refuses same-team
ports, mutable source references, EMILIA-affiliated implementers or attestors,
self-attestation, an unpinned specification bundle, and any attestation not
marked independently pinned. Exercise the complete acceptance contract with:

```sh
npm run conformance:clean-room:contract
```

The checked-in `reference-port.manifest.json` is a harness self-test and
explicitly claims no independence.
