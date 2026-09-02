<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

## Unreleased

### Security

- Gate EVERY execution entry point, not only `.invoke()`. The Proxy previously
  bound every other function to the raw target, so langchain-core's `.call()`,
  `.batch()` and `.stream()` (which reach the effect through `this.invoke`)
  resolved to the ungated original and ran with no receipt at all. `.call`,
  `.batch`, `.stream`, `.func` and `._call` are now gated explicitly, and every
  other method is bound to the proxy so an internal `this.invoke(...)` also
  lands on the gate. Each entry point runs exactly once per authorized action.
  The legacy `withGuard` proxy refuses on the same entry points.
- Spread caller gate options FIRST so the derived exact action and the
  consumption store are not caller-overridable.

## 0.4.1 (2026-08-30)

- Rebaseline the executor-action boundary on
  `@emilia-protocol/require-receipt` `^0.8.1`.
