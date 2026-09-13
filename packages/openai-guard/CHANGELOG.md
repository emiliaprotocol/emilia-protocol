<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

## Unreleased

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
