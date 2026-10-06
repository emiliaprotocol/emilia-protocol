<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

## Unreleased

## 0.5.3 (2026-10-06)

- Pin the 0.9.0 `@emilia-protocol/require-receipt` executor-action
  boundary so new installs cannot silently retain the obsolete `caid:`
  selector behavior while claiming current `canactid:` support.
- Retain optional offline receipt verification across Verify 3.21.x through
  Verify 8.x. This compatibility release does not reinterpret historical
  receipts or change the guard's configured enforcement boundary.

## 0.5.2 (2026-10-04)

- Expand the optional verifier peer to include 5.x, 6.x, and 7.x alongside
  the existing 3.21.x and 4.x lines, allowing installation with Gate 0.29.0
  and its Verify 7.0.0 dependency without bypassing peer checks.
- Exercise signed and tampered receipts, forged signatures, wrong trust keys,
  exact tool arguments, replay refusal, and duplicate JSON with the packed
  Verify 7.0.0 candidate installed in a blank consumer.
- The optional offline client calls the unchanged root `verifyReceipt()` API.
  This compatibility update does not reinterpret historical AEC replay records,
  add AEC evaluation to the guard, or widen its configured enforcement boundary.

## 0.5.1 (2026-09-13)

- Allow the optional verifier peer to use either 3.21.x or 4.x. Receipt
  verification remains compatible; this lets the guard install alongside
  Gate 0.25.0 without ignoring peer-dependency checks.
- Test valid and tampered signed receipts through the optional verifier API.

## 0.5.0 (2026-08-30)

### Security

- Bind the action to the tool name and the exact executing arguments
  unconditionally, matching the LangChain and OpenAI-Agents adapters. The
  documented simple form `action: 'payment.release'` was NOT argument-bound, so
  one receipt for that action authorized ANY arguments: a receipt approved for
  $100 to one account executed $9,999,999 to another. `actionFor` may now only
  refine the base action type; it cannot replace or disable the digest.
- Hash the arguments that actually execute. The guard previously hashed the
  snapshot including the `__ep` receipt envelope while executing the stripped
  arguments, so the digest covered something other than the effect.
- Accept an explicit `toolName` and bind the model-supplied tool name inside
  `runToolCalls`, so the digest does not move with a local (or minified)
  function identifier.

### Changed

- Advance the executor-action boundary to the current `require-receipt` line
  and publish the Node type-resolution metadata used by the verified build.
- Rebaseline the optional offline verifier peer on
  `@emilia-protocol/verify` `^3.21.0`.
