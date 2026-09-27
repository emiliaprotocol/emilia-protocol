<!-- SPDX-License-Identifier: Apache-2.0 -->

# EP-RESOLUTION / binding-moment-envelope -04 candidate gate

**Status:** test plan for unpublished upstream text. Not an Internet-Draft,
published profile, supported verifier mode, or authorization credential.
The published envelope revision checked on 2026-09-26 is -02. The upstream
author says an imminent -03 is editorial and reserves the option-to-action
binding and native decline for -04. The final -04 text may differ from the
candidate in [issue #380](https://github.com/emiliaprotocol/emilia-protocol/issues/380).

## Compatibility boundary

`EP-RESOLUTION-v1` remains pinned to the published -02 option grammar:
`{label, reasoning}`. The JavaScript, Python, and Go v1 verifiers reject an
`action_digest` member in a source option. A presenter cannot unlock candidate
semantics by renaming the v1 receipt's `profile`; the verifiers reject the
unknown profile. The current relying-party `expectedSelectedOption` mapping
remains required for authorization on v1.

No verifier should auto-detect the candidate from an extra field. A future
implementation needs a separately named profile and signed context type,
plus an independently configured relying-party policy admitting that profile.
Unrecognized, absent, or mismatched version pins must withhold authority.

## Candidate acceptance matrix, conditional on published -04

The candidate profile must check the exact source envelope digest and its
canonicalization profile, the signed selected option index, and the digest of
the action the executor is about to perform. It must not ask the relying party
to tell it what the index meant. Positive and negative fixtures, produced from
the final published wire shape, must run through JavaScript, Python, and Go:

| Case | Evidence | Authority |
|---|---|---|
| Selected option digest equals independently computed action digest | valid | possible only with all other pins, freshness, and consumption checks |
| Missing, malformed, or substituted option digest | invalid | no |
| Selected index points to a different action digest | authentic selection may remain evidence | no |
| Bare native decline bound to its envelope digest | valid negative evidence | no |
| Decline carries an option index or action digest | invalid | no |
| Unknown source revision or v1/candidate profile relabel | invalid | no |
| Replay, wrong initiator, stale window, unpinned principal key | invalid | no |

The exact treatment of an authentic selection with a wrong action digest
depends on the final source draft and EP profile. Regardless of that evidence
classification, it must never set `authorizes_action: true`.

## Publication and closure gates

1. Read the **published** -04 bytes and compare them to the issue candidate;
   do not infer semantics from the issue comment alone.
2. Name a new EP profile and signed context type. Make v1 and candidate
   non-interchangeable under both the verifier API and relying-party policy.
3. Generate a separate candidate vector suite, including each refusal above,
   and run it across all three verifiers. Keep v1's existing vectors stable.
4. Verify the origin, principal-key pin, exact action computation, freshness,
   and one-time consumption at the executor. The option digest is one binding,
   not a substitute for the rest of the Gate.
5. Only then update conformance claims and close issue #380. A draft filing or
   one language's passing test is not that closure evidence.
