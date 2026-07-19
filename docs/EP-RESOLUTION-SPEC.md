<!-- SPDX-License-Identifier: Apache-2.0 -->

# EP-RESOLUTION-v1: durable four-outcome binding-moment evidence

**Status:** Experimental, additive profile. This document does not change the
frozen EP-RECEIPT-v1 or EP-SIGNOFF-v1 formats. It supplies a concrete durable
resolution object for the transient `binding_moment` defined by
`draft-morrison-binding-moment-envelope-00`, an active individual Internet-Draft
and work in progress.

Implementation: `packages/verify/resolution.js` (JavaScript),
`packages/python-verify/emilia_verify/__init__.py` (Python), and
`packages/go-verify/resolution.go` (Go). Shared vectors:
`conformance/vectors/resolution.v1.json`.

## 1. Composition boundary

The binding-moment envelope owns the question: the briefing, answer space,
recommendation, and two escape hatches. Its current Section 7.3 requires the
returned resolution to distinguish option selection, answer-space revision, and
question-space rejection, but deliberately does not mandate a returned wire
format or persistent record.

EP-RESOLUTION-v1 owns the durable evidence: which role-pinned principal key
resolved the exact envelope, for which exact action, under which WebAuthn RP ID,
nonce, initiator, and validity window. The join is
`SHA-256(JCS(binding_moment))`.

The profile preserves four meanings at the type level:

| Outcome | Meaning | Authorizes the original action? |
|---|---|---|
| `approved` | The question and answer space stand; the principal selected one option. | Only when the relying party independently maps that option to the exact action hash. |
| `declined` | The question was valid; the principal's answer is no. | No. |
| `amended` | The question stands; the offered answer space was wrong or incomplete. | No. |
| `rejected` | The question or its premises were wrong; deliberation reopens. | No. |

A valid negative outcome is evidence. It is never authority.

## 2. Wire object

```json
{
  "profile": "EP-RESOLUTION-v1",
  "signoff": {
    "@type": "ep.signoff",
    "context": {
      "ep_version": "1.0",
      "context_type": "ep.resolution.v1",
      "envelope_hash": "sha256:<64 lowercase hex>",
      "action_hash": "sha256:<64 lowercase hex>",
      "principal": "ep:principal:jchen",
      "principal_key_id": "ep:key:jchen#resolution-1",
      "initiator": "spiffe://operator.example/agent/7",
      "nonce": "res_8c0f0e9e7f8a4c9aa3c7",
      "issued_at": "2026-07-14T05:25:00Z",
      "expires_at": "2026-07-14T05:35:00Z",
      "resolution": {
        "outcome": "approved",
        "selected_option": 0
      }
    },
    "webauthn": {
      "authenticator_data": "<base64url>",
      "client_data_json": "<base64url>",
      "signature": "<base64url>"
    }
  }
}
```

The schema is `public/schemas/ep-resolution.schema.json`. Unknown members fail
closed. The receipt carries no public key. A key named by the presenter cannot
establish its own authority.

The `resolution` member is a discriminated union:

```text
approved = { outcome: "approved", selected_option: uint }
declined = { outcome: "declined" }
amended = { outcome: "amended", response_hash: sha256,
            successor_envelope_hash?: sha256 }
rejected = { outcome: "rejected", objection_hash?: sha256,
             successor_envelope_hash?: sha256 }
```

Amendment and objection text is represented by a digest so a verifier can bind
the response without forcing its disclosure into a portable artifact. A
successor pointer is optional because the successor envelope is commonly created
after the principal signs the response. Whether or not a pointer is present,
`amended` and `rejected` return `requires_successor: true` and authorize nothing.
A self-successor is malformed.

## 3. WebAuthn signing input

The WebAuthn challenge is:

```text
base64url(SHA-256(JCS(signoff.context)))
```

The exact envelope digest, action digest, principal, key identifier, initiator,
nonce, time window, and typed resolution are therefore covered by the same
device-bound signature. Relabeling a signed decline as approval invalidates the
challenge binding.

## 4. Relying-party inputs

`verifyResolutionReceipt(receipt, opts)` requires independent inputs:

- `bindingMoment`: the exact source `binding_moment` value;
- `expectedActionHash`: the action the executor is considering;
- `principalKeys`: role-scoped `{ key_id: { principal, public_key } }` pins;
- `rpId`: the expected WebAuthn relying-party ID; and
- `allowedOrigins`: an exact relying-party-controlled WebAuthn origin allowlist.

For an approval to set `authorizes_action: true`, the relying party must also
provide `expectedSelectedOption`, `expectedNonce`, `expectedInitiator`, and an
`evaluationTime` inside the signed validity window. The verifier checks that the
signed `selected_option` equals that local mapping. This is load-bearing: the Morrison
envelope has human-readable option labels but no normative option-to-action
digest map. A valid signature over "Hold" must never silently authorize
"Release."

Those four acceptance inputs are optional only when verifying historical
evidence. If one is absent, an authentic receipt can still return `valid: true`,
but it MUST return `authorizes_action: false`. A wrong supplied nonce, initiator,
or evaluation time fails verification rather than being treated as absent.

## 5. Verification result

The verifier returns separate evidence and authority judgments:

```json
{
  "valid": true,
  "authorizes_action": false,
  "outcome": "declined",
  "requires_successor": false,
  "checks": { "...": true }
}
```

`valid` means the object, source-envelope grammar, canonicalization profile,
bindings, signed time window, role pin, RP ID, origin allowlist, and WebAuthn
proof verified. `authorizes_action` means all of that is true, the outcome is
`approved`, and the relying party also pinned the option mapping, nonce,
initiator, and an in-window evaluation time. A caller evaluating authorization
evidence MUST test `authorizes_action`, not merely `valid`. An executor MUST
also enforce one-time consumption and its local policy before acting.

## 6. Fail-closed cases

The shared suite includes authentic examples of all four outcomes and refusals
for non-approval presented as authority, approval with an incomplete local
acceptance context, outcome relabeling, malformed or non-canonical source
envelopes, envelope or action substitution, unpinned and cross-principal keys,
wrong RP ID or origin, expired and impossible calendar instants, nonce or
initiator substitution, malformed outcome shapes, self-successors, unknown
outcomes, and hostile empty input. JavaScript, Python, and Go execute the same
vectors.

Run:

```bash
node examples/binding/four-outcome-resolution.mjs
node conformance/run.mjs
```

## 7. Honest limits

This profile proves a device signed one typed resolution over specific bytes
under relying-party-pinned trust inputs. It does not prove:

- that the briefing was truthful, complete, or unbiased;
- that the renderer showed the human the signed action faithfully;
- that the decision was wise or uncoerced;
- that the enrolled key belongs to a natural person beyond the enrollment grade;
- that signer-provided time is trusted time;
- that a valid approval was consumed exactly once; or
- that a later revocation does not exist.

Display attestation, trusted time, revocation currency, quorum, and one-time
consumption remain separate EP evidence or enforcement layers. They compose;
this profile does not collapse them into the resolution record.
