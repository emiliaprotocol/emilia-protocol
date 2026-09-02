<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

## Unreleased

### Security

- A caller-supplied `opts.action` can no longer override the derived,
  argument-bound action. `action` was not destructured out of `opts` and the
  gate options were spread AFTER it, so one receipt for an arbitrary caller
  string approved every tool and every argument set while the returned decision
  still reported the derived action. `action` is now discarded and the gate
  options are spread first, matching `packages/langgraph`.

## 0.3.1 (2026-08-30)

- Publish the Node type-resolution metadata already used by the verified build
  and advance the receipt-boundary dependency floor.
