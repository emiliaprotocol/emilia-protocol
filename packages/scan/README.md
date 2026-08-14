<!-- SPDX-License-Identifier: Apache-2.0 -->
# @emilia-protocol/scan

Collapses the integration overhead of putting EMILIA in front of an AI app's
consequential actions. Point it at what your agent can do; it tells you what
should require authorization evidence, and hands you proposed config to review.

```bash
npx @emilia-protocol/scan brain ./tools.json       # local, interactive Authority Map
npx @emilia-protocol/scan brain --sample           # generate the built-in demonstration

npx @emilia-protocol/scan authority               # local config-derived authority inventory
npx @emilia-protocol/scan --sample                 # classify the built-in surface
npx @emilia-protocol/scan ./tools.json             # classify your MCP tool list
npx @emilia-protocol/scan ./openapi.json           # classify your HTTP API surface

# generate reviewed protection files (dry-run by default)
npx @emilia-protocol/scan protect ./tools.json
npx @emilia-protocol/scan protect ./tools.json --apply
node emilia/verify-setup.mjs                       # synthetic local refusal check
node emilia/verify-setup.mjs --emit-handoff \
  --reviewed-manifest-digest 'sha256:<reviewed-digest>' \
  --action '<reviewed-tool-name>'                  # replace placeholders after review
```

## Local Authority Map

**See where your AI can act. Put a human in control before it matters.**

`scan brain` runs the real static scanner and writes
`emilia-authority-brain.html`, a responsive, interactive Authority Map that
opens directly in a browser. It shows the declared source type, visible action
counts, proposed classifications, confidence, reasons, material fields, and
blind spots across the **Discover → Map → Protect → Prove** loop.

The HTML is one self-contained local file. It contains no remote font, script,
image, account flow, telemetry, upload, or network request. Dynamic values are
rendered as text from an inert, HTML-escaped JSON model; arbitrary tool fields
such as credential and argument objects are not copied into the dashboard.

```bash
# Default: owner-only ./emilia-authority-brain.html; refuses overwrite
npx @emilia-protocol/scan brain ./tools.json

# The output must remain one direct-child .html file in the current directory
npx @emilia-protocol/scan brain ./tools.json --out authority-map.html

# Explicit replacement of one existing regular, single-link output file
npx @emilia-protocol/scan brain ./tools.json --out authority-map.html --force
```

Output is staged completely before installation and created with mode `0600`.
Non-`.html`, nested, escaping, source-confusing, symlinked, hard-linked, and
non-regular output paths are refused, as is silent overwrite. Forced replacement
uses a no-replace install; if another file appears during replacement, it is not
overwritten and the displaced original remains recoverable as a named backup.

For a consequential MCP action, **Protect this action** selects the action and
offers copyable versions of the existing `scan protect <input> --apply` and
reviewed-action handoff commands, with the synthetic local refusal check between
them. The action name is needed only by the handoff command; supported action
names and input paths are POSIX-quoted as hostile values. Source-confusing
control and bidirectional characters are refused. A leading-dash input filename
is normalized to a relative path; a leading-dash action name remains visible but
its unusable handoff command is withheld until the tool is renamed. The
interaction does not edit the input or install a control. Review and place the
generated Gate at the credential-owning dispatch boundary before making an
enforcement claim.

OpenAPI dashboards are deliberately passive-only until a durable, one-use HTTP
admission edge is wired. They show the route-level proposal and the limitation;
they do not emit a verification-only middleware or a protection command.

**The scanner proposes. The owner reviews. Gate enforces.** A dashboard is a
proposal, not an owner review, protected deployment, certification, or proof of
complete mediation.

`scan protect` (also available as the legacy `emilia-harden` bin) currently
accepts MCP tool lists and generates a `withMcpGuard` wrap. OpenAPI remains a
passive scan/manifest surface in this release: the command refuses to generate
a verification-only HTTP middleware until durable one-use consumption is wired.
Generated integration instructions install the audited runtime exactly with
`npm install --save-exact @emilia-protocol/mcp-guard@0.4.5`.

It does exactly three things, and never more:

1. **Scan** the actions it can see (MCP tool list, OpenAPI spec, or a plain list).
2. **Classify** each one against the same risk packs the EMILIA Gate ships:
   money movement, bank-detail changes, production deploys, IAM grants, data
   export, record deletion, decision overrides. Each match carries an assurance
   tier (`class_a` or `quorum`) and the fields the receipt must bind.
3. **Protect one declared MCP surface** — emit a proposed `agent-action-control`
   manifest, a production wrapper, integration instructions, and a local
   synthetic refusal check. You still review and install the wrapper.

The MCP production wrapper requires a durable provenance ledger and a shared
atomic consumption store. It refuses to initialize without both. The generated
`verify-setup.mjs` deliberately uses ephemeral demo state so it can prove one
narrow fact locally: a synthetic destructive call without a receipt was refused
and its handler was not invoked. That check does not prove provider credentials
are unreachable through some other path, that your production state is durable,
or that your keys and approval adapters are correctly configured.

## Machine-readable adoption handoff

`verify-setup.mjs` is read-only by default. It prints the exact manifest and
generated-scaffold digests after the local refusal check. Once you have reviewed
`action-control.manifest.json`, you can acknowledge those exact bytes and select
which visible consequential MCP tools may appear in a local handoff:

```bash
node emilia/verify-setup.mjs \
  --emit-handoff \
  --reviewed-manifest-digest sha256:<reviewed-digest> \
  --action deleteCustomer \
  --action deployToProduction
```

This explicitly creates `emilia/scan-adoption-handoff.json` with mode `0600`.
Creation is no-replace: an existing regular file, symlink, or hard link is never
followed or overwritten. The verification command makes no network request,
launches no process, and never invokes the supplied consequential handler.

The JSON contract is `EP-SCAN-ADOPTION-HANDOFF-v1`:

- `reviewed_manifest` binds the SHA-256 digest of the exact reviewed manifest
  file bytes. Emission fails unless the caller-supplied digest matches.
- `generated_scaffold` lists SHA-256 digests for `guard.mjs`,
  `verify-setup.mjs`, and `INTEGRATION.md`. Its aggregate SHA-256 is computed
  over the UTF-8 bytes of `JSON.stringify(files)` in that fixed order.
- `selected_actions` contains only explicitly selected, discovered,
  receipt-required MCP actions: manifest id, MCP selector, action type,
  assurance class, and `receipt_required: true`.
- `local_refusal` records `status: "passed"`, that the supplied handler was not
  called, and a machine-readable boundary. It asserts only a local synthetic
  refusal. It explicitly does not assert production enforcement, complete
  mediation, credential isolation, durable state, trusted-key configuration, a
  signed refusal artifact, or public verification.

The handoff has no timestamp and reads no ambient identity or host source. It
does not include tool arguments, credential values, input descriptions, source
paths, paths outside the generated output directory, usernames, or host data.
Only explicitly selected visible action names and generated-output basenames are
included. Treat it as a privacy-bounded local adoption handoff, not a production
attestation or an `EP-ACTION-REFUSAL-STATEMENT-v1` artifact.

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
emitted. Credential descriptors may include key name, class, exact length,
prefix class, detection evidence, and scheme, but never the credential value.
Report files are created owner-only and existing or symlinked report paths are
refused. Symlinked configuration sources are excluded, and any reached discovery
limit is printed in the report.

The authority command uses these exit codes: `0` for complete visible coverage
with no signals (not currently reachable in configuration-only mode), `1` when
signals are present, `2` for a malformed configuration source, `3` when the
operation surface is not visible or classifiable, and `64` for a usage, argument,
or filesystem error.

## What it will not do

- **It will not decide your risk model.** Which actions are consequential is a
  semantic judgment only you can make. It *proposes*; you confirm. Anything it
  cannot map to a known category but that mutates state is defaulted to
  **fail-closed** (require a receipt) and flagged for your review, never waved
  through.
- **It does not trust MCP hints as policy.** `readOnlyHint` is advisory. A
  high-risk semantic match overrides it, and an otherwise opaque action defaults
  to receipt-required until a reviewer confirms it is read-only.
- **Read words cannot hide another operation.** The classifier applies a public,
  data-shaped precedence policy: category and destructive evidence first, then
  state-change verbs (including ordinary inflections such as `updates`,
  `archived`, and `rotating`) and write methods, then hybrid markers such as
  `and` or `then`. Only a leading read verb with no higher-precedence signal is
  proposed for pass-through; mutation or ambiguity defaults receipt-required.
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

JSON input is required to be a regular file and is bounded to 8 MiB before any
content read; non-regular files, symlinked path components, files that change
during the read, and duplicate member names are refused. Scans are limited to
10,000 bounded action records. Unknown options fail with usage status rather
than silently degrading a requested operation. `--emit` refuses to overwrite an
existing manifest. `protect` is dry-run by default and accepts one direct-child
output directory under the current working directory. It builds the complete
scaffold in a private staging directory and installs it as one directory rename,
refuses symlink traversal, and does not replace an existing output unless you
explicitly pass `--force`.

Part of [EMILIA Protocol](https://www.emiliaprotocol.ai). Apache-2.0.
