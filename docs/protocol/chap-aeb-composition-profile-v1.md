<!-- SPDX-License-Identifier: Apache-2.0 -->
# CHAP to AEB composition profile v1

Status: experimental interoperability profile

## Purpose

CHAP records structured human review decisions. AEB evaluates independently
verifiable evidence roles against the exact action a relying party may admit.
This profile composes those responsibilities without turning a CHAP decision
into execution authority and without changing CHAP's coordination model.

## Source lock

The profile pins `https://github.com/BrightbeamAI/chap` at commit
`9e7af2b811d3368b4afba7c6d318764959c2fd0d`. The adapter recognizes only the
JSON-RPC envelope used by the reference coordinator and the
`security-signed/1.0` profile. It refuses alternate envelope shapes rather than
guessing across the current schema/reference-code difference.

Pinned source bytes:

| Upstream path | SHA-256 |
| --- | --- |
| `profiles/review.md` | `2a971b084ea192daafcdac275b5aa1b9e6ceb60d0cb3879db0df06ee7b430539` |
| `profiles/security-signed.md` | `83f455763b08d0d9993fecf3c5ddf94d2cd6266d79b42a574f52ce94a313aee2` |
| `packages/coordinator-py/chap_coordinator/patch.py` | `78ff3b3d898f58e5d043582705e46c06833336f411ef0caf08d11221148da7ff` |

## Composition rule

The relying party pins the CHAP participant key, reviewer identity, adapter
version, action-mapping profile, decision age, and status age. Presenter-carried
keys or mapping rules are not accepted.

For `decide.override`, the adapter verifies the signature, applies the bounded
RFC 6902 patch to `based_on_artefact`, and requires the resulting artifact to
equal the native action expected at Gate. Only then may it derive a CAID.

For `decide.approve`, a signature over `task_id` alone is insufficient for
offline exact-action mapping. The result is `INDETERMINATE`. A profile may add
the following field to the signature-covered parameters:

```json
{
  "approved_artefact_digest": "sha256:<64 lowercase hexadecimal characters>"
}
```

The digest is SHA-256 over the AEB strict-canonical JSON bytes of the approved
artifact. A mismatch is `REJECTED`; absence remains `INDETERMINATE`.

## Responsibility boundary

CHAP answers what human-review decision was recorded. This adapter verifies
that evidence and maps it to an exact action. AEB may determine that a required
evidence role is satisfied. Gate remains responsible for local execution
policy, reservation, provider entry, one admitted provider attempt on covered
shared-durable paths, and honest reconciliation of an unknown outcome.

No CHAP decision, AEB evaluation, or CAID alone authorizes or executes an
external effect.

The profile verifies integrity and exact-action binding for a CHAP record that
is presented. It does not prove that all decisions that should exist were
emitted. Where completeness is required, the producer must make durable record
creation a condition of the governed act or provide a separately verifiable
omission signal. A transparency inclusion proof cannot supply that property by
itself.

## Executable evidence

Run:

```bash
npm run conformance:composition:chap-aeb
```

The suite executes eleven checks across the positive mapping, the current
approve limitation, the additive digest proposal, signature tampering, action
substitution, patch safety, signer substitution, status freshness,
consumption, and replay-unit stability.
