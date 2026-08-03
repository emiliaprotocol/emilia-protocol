<!-- SPDX-License-Identifier: Apache-2.0 -->
# @emilia-protocol/scan

Collapses the integration overhead of putting EMILIA in front of an AI app's
consequential actions. Point it at what your agent can do; it tells you what
should require authorization evidence, and hands you proposed config to review.

```bash
npx @emilia-protocol/scan authority               # local config-derived authority inventory
npx @emilia-protocol/scan --sample                 # classify the built-in surface
npx @emilia-protocol/scan ./tools.json             # classify your MCP tool list
npx @emilia-protocol/scan ./openapi.json           # classify your HTTP API surface

# generate reviewed protection files (dry-run by default)
npx @emilia-protocol/scan protect ./tools.json
npx @emilia-protocol/scan protect ./tools.json --apply
node emilia/verify-setup.mjs                       # synthetic local refusal check
```

`scan protect` (also available as the legacy `emilia-harden` bin) reads the
surface and generates the matching guard: an MCP
`withMcpGuard` wrap for a tool list, or an Express middleware (`requireEmiliaReceipt`,
`428 Receipt-Required` per consequential route) for an OpenAPI spec.

It does exactly three things, and never more:

1. **Scan** the actions it can see (MCP tool list, OpenAPI spec, or a plain list).
2. **Classify** each one against the same risk packs the EMILIA Gate ships:
   money movement, bank-detail changes, production deploys, IAM grants, data
   export, record deletion, decision overrides. Each match carries an assurance
   tier (`class_a` or `quorum`) and the fields the receipt must bind.
3. **Protect one declared surface** — emit a proposed `agent-action-control`
   manifest, a production wrapper, integration instructions, and (for MCP) a
   local synthetic refusal check. You still review and install the wrapper.

The MCP production wrapper requires a durable provenance ledger and a shared
atomic consumption store. It refuses to initialize without both. The generated
`verify-setup.mjs` deliberately uses ephemeral demo state so it can prove one
narrow fact locally: a synthetic destructive call without a receipt was refused
and its handler was not invoked. That check does not prove provider credentials
are unreachable through some other path, that your production state is durable,
or that your keys and approval adapters are correctly configured.

The `authority` command is a separate passive diagnostic:

```bash
npx @emilia-protocol/scan authority
npx @emilia-protocol/scan authority --json
npx @emilia-protocol/scan authority --out authority-report.json
```

It reads bounded local configuration files to inventory supported agent
runtimes, declared MCP servers, credential-shaped fields, ambient credential
files, and permission declarations. After it starts, scanner code launches no
configured server or child process and performs no network I/O. When invoked
through `npx`, npm may download the package before scanner startup.
Configuration values are parsed locally in memory; credential values are not
intentionally emitted. Report files are created owner-only and existing or
symlinked report paths are refused. Symlinked configuration sources are excluded,
and any reached discovery limit is printed in the report.

## What it will not do

- **It will not decide your risk model.** Which actions are consequential is a
  semantic judgment only you can make. It *proposes*; you confirm. Anything it
  cannot map to a known category but that mutates state is defaulted to
  **fail-closed** (require a receipt) and flagged for your review, never waved
  through.
- **It does not trust MCP hints as policy.** `readOnlyHint` is advisory. A
  high-risk semantic match overrides it, and an otherwise opaque action defaults
  to receipt-required until a reviewer confirms it is read-only.
- **It will not edit your code.** It emits the manifest and the wrap; you apply
  them after review.
- **It will never tell you that you are "protected."** It reports what it could
  not see (runtime-registered tools, risk that depends on argument values, and
  whether your organization will actually fail-closed on a denial — which is a
  decision, not a setting). Nothing is enforced until you add the wrap and pin
  your keys.
- **The authority scan cannot see a server's real tool surface.** It does not
  launch servers. Run the static surface scan against a tool list or OpenAPI
  document separately; a configuration-only authority scan exits non-zero
  rather than implying complete coverage.

That honesty is the point. A tool that claimed to make AI safe by installing it
would be lying; risk is specific to your application, and only you know it. This
makes declaring it cheap, and keeps you in control of the declaration.

JSON input is capped at 8 MiB, duplicate member names are refused, and scans are
limited to 10,000 bounded action records. `--emit` refuses to overwrite an
existing manifest. `protect` is dry-run by default, writes only inside the
current working directory, refuses symlink traversal, and does not overwrite
existing files unless you explicitly pass `--force`.

Part of [EMILIA Protocol](https://www.emiliaprotocol.ai). Apache-2.0.
