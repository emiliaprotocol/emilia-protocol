<!-- SPDX-License-Identifier: Apache-2.0 -->

# The Canonical Demo — "The $2.4M Vendor Bank Change Crash Test"

One demo, used everywhere (homepage · FinGuard · GovGuard · Agent Guard · investor deck · cold outreach · GitHub README). Repetition is positioning. Built on the existing `/try` Face-ID flow and `examples/crash-test.mjs`.

## The premise (one sentence)
An agent (or operator) tries to change a vendor's bank account to redirect a $2.4M payment — existing controls wave it through; EMILIA stops it until a named human cryptographically owns the decision, then proves it.

## The 11 beats
1. **The action.** An agent/operator initiates: change Vendor X bank account from Account A → Account B (a $2.4M payee).
2. **IAM is satisfied.** The actor is authenticated — green check. (Identity ≠ authority.)
3. **Workflow is satisfied.** The ticket shows "approved." (A flag ≠ action-bound authorization.)
4. **EMILIA blocks execution.** The change is irreversible and high-value → held pre-execution. Nothing has moved.
5. **Policy requires named signoff.** Controller + CFO-delegate, dual approval above the threshold — hash-pinned policy.
6. **Self-approval fails.** The initiator cannot be the approver (segregation of duties, by construction).
7. **Correct signoff happens.** A named approver signs the *exact* change (A → B, the exact amount) via passkey / Face ID / Touch ID on their own device.
8. **One-time receipt consumed.** The authorization is single-use.
9. **Evidence packet generated.** Receipt binds actor · authority chain · exact-action hash · policy version · approver identity · timestamp · nonce · consume event.
10. **Replay fails.** Re-presenting the same authorization is rejected.
11. **Auditor view in 30 seconds.** Paste the receipt into the open-source verifier → the whole event reconstructs offline, no trust in the operator required.

## The line under it
**Nothing irreversible without a signed human yes.**

## Asset formats (produce once, reuse)
- **~30–60s screen capture** (the 11 beats) — homepage hero + social.
- **Animated GIF** (existing `crash-test.gif` is the seed) — README + email.
- **Live self-serve** — `/try` already does the Face-ID + verify + tamper-fails arc; point every CTA at it.
- **CLI** — `node examples/crash-test.mjs` (offline, no key) for technical viewers.

## Surface-specific framings (same demo, swapped noun)
- **FinGuard:** "vendor bank change / wire release."
- **GovGuard:** "benefit payment-destination change / operator override."
- **Agent Guard:** "an autonomous agent's irreversible tool call."

## Honest boundary (keep on every surface)
The receipt proves a named human approved this exact action under a stated policy before it executed, verifiable offline. It does not assert the decision was correct; one-time-use and revocation are relying-party server state.
