<!-- SPDX-License-Identifier: Apache-2.0 -->
# @emilia-protocol/scan

Collapses the integration overhead of putting EMILIA in front of an AI app's
consequential actions. Point it at what your agent can do; it tells you what
should require authorization evidence, and hands you proposed config to review.

```bash
npx @emilia-protocol/scan@0.5.0 brain ./tools.json       # local, interactive Authority Map
npx @emilia-protocol/scan@0.5.0 brain --sample           # generate the built-in demonstration

npx @emilia-protocol/scan@0.5.0 authority               # local config-derived authority inventory
npx @emilia-protocol/scan@0.5.0 source ./src             # passive source registration discovery
npx @emilia-protocol/scan@0.5.0 diff --baseline reviewed-source.json ./src
npx @emilia-protocol/scan@0.5.0 --sample                 # classify the built-in surface
npx @emilia-protocol/scan@0.5.0 ./tools.json             # classify your MCP tool list
npx @emilia-protocol/scan@0.5.0 ./openapi.json           # classify your HTTP API surface

# generate one selected-action Gate Starter (dry-run by default)
npx @emilia-protocol/scan@0.5.0 protect ./tools.json
npm install --save-exact @emilia-protocol/mcp-guard@0.6.0
npx @emilia-protocol/scan@0.5.0 protect ./tools.json --action sendWire --apply --verify

# after reading emilia/authority-map.html and action-control.manifest.json
npx @emilia-protocol/scan@0.5.0 protect ./tools.json --action sendWire --reviewed \
  --crossing-profile ccs-wang-draft08-v13
```

## Source discovery and reviewed diffs

`scan source` walks a bounded non-symlink directory tree and recognizes literal
tool registrations for MCP, LangChain, the Vercel AI SDK, Genkit, Python tool
decorators, and Java tool annotations. Each observed registration carries its
relative path, line, framework, parser version, confidence, exact file digest,
and registration-line digest. Dynamic names remain explicit unresolved entries.

```bash
npx @emilia-protocol/scan@0.5.0 source ./src --json --out source-review.json
npx @emilia-protocol/scan@0.5.0 diff --baseline source-review.json ./src --json
```

The source report contains a non-authorizing
`EP-SOURCE-DISCOVERY-BASELINE-v1` proposal. After an owner reviews those exact
bytes, `scan diff` identifies new, removed, moved, or source-changed actions,
dynamic registrations, duplicate names, and dangerous capability composition.
It exits `1` when review is required, so CI can block a newly observed surface.

Composition findings cover untrusted input plus money movement, mutable
destination data plus money movement, untrusted readers plus shell execution,
and credential access plus external transmission. They may only tighten a
classification. Static co-presence does not prove data flow, exploitability,
runtime reachability, or complete mediation.

Neither command has a `--fix` mode. They do not edit source, install a handler,
produce a reviewed action-control manifest, or create or consume authority.

## Local Authority Map

**See where your AI can act. Put the owner's authority at the boundary.**

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
npx @emilia-protocol/scan@0.5.0 brain ./tools.json

# The output must remain one direct-child .html file in the current directory
npx @emilia-protocol/scan@0.5.0 brain ./tools.json --out authority-map.html

# Explicit replacement of one existing regular, single-link output file
npx @emilia-protocol/scan@0.5.0 brain ./tools.json --out authority-map.html --force
```

Output is staged completely before installation and created with mode `0600`.
Non-`.html`, nested, escaping, source-confusing, symlinked, hard-linked, and
non-regular output paths are refused, as is silent overwrite. Forced replacement
uses a no-replace install; if another file appears during replacement, it is not
overwritten and the displaced original remains recoverable as a named backup.

For a consequential MCP action, **Protect this action** offers two copyable
commands. The first creates one selected-action Gate Starter and runs the
synthetic four-case RR-1 check. The second is deliberately separate: only after
the owner reads the generated map and manifest does it bind the current bytes
into the reviewed handoff and create an unsealed Crossing Lab workspace. The
owner never has to calculate or copy a digest.
Supported action names, input paths, and output paths are POSIX-quoted as
hostile values. Source-confusing control and bidirectional characters are
refused. A leading-dash input filename is normalized to a relative path; a
leading-dash action name remains visible but its unusable selected-action
commands are withheld until the tool is renamed. The interaction does not edit
the input or install a control. Review and place the generated Gate at the
credential-owning dispatch boundary before making an enforcement claim.

OpenAPI dashboards are deliberately passive-only until a durable, one-use HTTP
admission edge is wired. They show the route-level proposal and the limitation;
they do not emit a verification-only middleware or a protection command.

**The scanner proposes. The owner reviews. Gate enforces.** A dashboard is a
proposal, not an owner review, protected deployment, certification, or proof of
complete mediation.

`scan protect` (also available as the legacy `emilia-harden` bin) currently
accepts MCP tool lists and generates a self-contained local Authority Map plus a
`withMcpGuard` wrap. OpenAPI remains a
passive scan/manifest surface in this release: the command refuses to generate
a verification-only HTTP middleware until durable one-use consumption is wired.
Generated integration instructions install the audited runtime exactly with
`npm install --save-exact @emilia-protocol/mcp-guard@0.6.0`.
Each generated directory also contains an owner-only
`.emilia-gate-starter.json` marker that binds all five generated artifacts and
states `not_activated`. `--force` can replace only an exact, owner-only starter
whose marker and file digests still verify. It refuses arbitrary directories,
extra files, changed files, and reserved roots such as `.git` and
`node_modules`. Protection output names are restricted to portable direct-child
slugs made from letters, numbers, dots, underscores, and hyphens.

It does exactly four things, and never more:

1. **Scan** the actions it can see (MCP tool list, OpenAPI spec, or a plain list).
2. **Classify** each one against the same risk packs the EMILIA Gate ships:
   money movement, bank-detail changes, production deploys, IAM grants, data
   export, record deletion, decision overrides. Each match carries an assurance
   tier (`class_a` or `quorum`) and the fields the receipt must bind.
3. **Package one selected consequential MCP action** — atomically emit a local
   Authority Map, proposed `agent-action-control` manifest, production wrapper,
   integration instructions, and local synthetic four-case receipt-required
   check. Every other visible consequential action remains review-pending and
   is refused by the selected-action wrapper before receipt processing. Runtime
   tools absent from the declared surface are refused at the same boundary even
   if they carry an otherwise exact synthetic receipt; only the selected action
   and explicitly visible read-only tools can reach the underlying guard.
4. **Bind an explicit owner review** — after the generated bytes are visible,
   validate the unchanged manifest against the current input, rerun RR-1, emit
   the privacy-bounded handoff, and create an unsealed three-file Crossing Lab
   workspace without asking the owner to copy a digest.

The MCP production wrapper requires a durable provenance ledger and a shared
atomic consumption store. It refuses to initialize without both. The generated
`verify-setup.mjs` deliberately uses an ephemeral key, synthetic assurance, and
process-local state to exercise four control-flow cases: no receipt refuses, a
receipt for the exact action admits, changed arguments refuse, and a spent
receipt cannot admit again. Its only handler is a synthetic local function. The
check does not establish named-human approval, hardware assurance, production
issuer trust, credential isolation, durable state, complete mediation, or a
real-world effect.

## Machine-readable adoption handoff

`verify-setup.mjs` is read-only by default. It prints the exact manifest and
generated-scaffold digests after the local refusal check. The primary path is
two-stage so generation can never silently become owner review:

```bash
# Install the exact audited local runtime once. The scanner never auto-installs.
npm install --save-exact @emilia-protocol/mcp-guard@0.6.0

# Stage 1: create the Gate Starter and run RR-1. No handoff is emitted.
npx @emilia-protocol/scan@0.5.0 protect ./tools.json \
  --action deleteCustomer --apply --verify

# Read emilia/authority-map.html and emilia/action-control.manifest.json.

# Stage 2: validate the existing unchanged bytes and emit the reviewed handoff.
npx @emilia-protocol/scan@0.5.0 protect ./tools.json \
  --action deleteCustomer --reviewed \
  --crossing-profile ccs-wang-draft08-v13
```

The candidate launch profile must be one of:

- `ccs-wang-draft08-v13`
- `cedulon-aeb-crossing-v0.1`
- `pinto-cbap1-aeb-v0.1`

Use `--crossing-out <direct-child-directory>` to override the default
`emilia-crossing-lab` workspace path.

The second command does not regenerate or overwrite the Gate Starter. It fails
if the current input no longer produces the exact existing manifest or declared
control-surface digest, if the action is not the starter's selected
consequential action, or if RR-1 fails. If review required an edit, keep the
explicit digest path so the edited bytes, rather than a fresh scanner proposal,
are acknowledged:

```bash
node emilia/verify-setup.mjs \
  --emit-handoff \
  --reviewed-manifest-digest sha256:<reviewed-digest> \
  --action deleteCustomer \
  --action deployToProduction
```

The reviewed shortcut creates `emilia/scan-adoption-handoff.json` and
`emilia/scan-crossing-seed.json` with mode `0600`, plus a three-file owner-only
workspace at `emilia-crossing-lab/`. Creation is no-replace: an existing regular
file, symlink, hard link, seed, or workspace is never followed or overwritten.
The verification command makes no network request and never invokes the
supplied consequential handler. After RR-1 passes, Scan resolves the Lab
initializer from its exact `@emilia-protocol/verify@3.21.0` dependency and
passes that local module to the generated verifier. A separate consumer-level
Verify installation is not required.

The seed binds the candidate launch profile and its published action contract,
the exact Verify 3.21.0 initializer version, exact reviewed-manifest bytes,
generated-scaffold digest, RR-1 result digest, selected action, and its material
field names. The workspace is explicitly
`UNSEALED_OPERATOR_INPUT_REQUIRED`; its refusal-only draft adapter cannot be run
or sealed as a normal Lab workspace. An operator must still supply the native
artifact, real adapter bytes, trust roots, live status source, relying-party id,
exact material values, and an explicit compatibility confirmation between the
reviewed action and the candidate profile. Scan proposes and binds the review;
it does not invent those inputs or claim compatibility.

The legacy explicit-digest handoff remains
`EP-SCAN-ADOPTION-HANDOFF-v2`. The reviewed Crossing Lab shortcut emits
`EP-SCAN-ADOPTION-HANDOFF-v3`, which has the same six base members plus the
required `crossing_seed` member. This avoids giving one version two schemas.

- `reviewed_manifest` binds the SHA-256 digest of the exact reviewed manifest
  file bytes. Emission fails unless the caller-supplied digest matches.
- `generated_scaffold` lists SHA-256 digests for `guard.mjs`,
  `verify-setup.mjs`, and `INTEGRATION.md`. Its aggregate SHA-256 is computed
  over the UTF-8 bytes of `JSON.stringify(files)` in that fixed order.
  `authority-map.html` is installed atomically beside the runtime files but is
  deliberately outside this v2 binding; a future contract can bind presentation
  artifacts without silently changing the published v2 digest semantics.
- `selected_actions` contains only explicitly selected, discovered,
  receipt-required MCP actions: manifest id, MCP selector, action type,
  assurance class, and `receipt_required: true`.
- `local_refusal` records `status: "passed"`, that the supplied handler was not
  called, and a machine-readable boundary. It asserts only a local synthetic
  refusal. It explicitly does not assert production enforcement, complete
  mediation, credential isolation, durable state, trusted-key configuration, a
  signed refusal artifact, or public verification.
- `local_rr1` binds the manifest digest and tested action contracts, records the
  ordered four-case result for every selected action and the number of synthetic
  handler calls, then computes a deterministic SHA-256 over those fields. It is
  a self-attested local reproduction with synthetic assurance and ephemeral
  state, not evidence of a real approver or protected deployment.
- `crossing_seed` in v3 binds
  the raw SHA-256 of the owner-only `scan-crossing-seed.json` used to initialize
  the unsealed workspace. It does not assert that a native adapter passed.

The Verify dependency is pinned exactly to 3.21.0 for this synchronized release
train. The seed records that version and the profile's expected native action
type and material fields. A different Scan or Verify train must emit a new
reviewed seed rather than silently changing workspace bytes.

The handoff has no timestamp and reads no ambient identity or host source. It
does not include tool arguments, credential values, input descriptions, source
paths, paths outside the generated output directory, usernames, or host data.
Only explicitly selected visible action names and generated-output basenames are
included. Treat it as a privacy-bounded local adoption handoff, not a production
attestation or an `EP-ACTION-REFUSAL-STATEMENT-v1` artifact.

The `authority` command is a separate passive diagnostic:

```bash
npx @emilia-protocol/scan@0.5.0 authority
npx @emilia-protocol/scan@0.5.0 authority --json
npx @emilia-protocol/scan@0.5.0 authority --out authority-report.json
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
