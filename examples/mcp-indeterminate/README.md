# An outcome-unknown expression at MCP `tools/call`

A runnable MCP server and client pair, on the official TypeScript SDK, showing
the state the Model Context Protocol wire cannot express today: **the effect
may have happened**.

A tool annotated `idempotentHint: false` performs an irreversible effect. A
deterministic fault kills the server process between the effect and the
response. The host sees a dropped connection and nothing else. What it does
next is the whole problem.

```
node examples/mcp-indeterminate/run.mjs                   # both transcripts
node --test examples/mcp-indeterminate/run.test.mjs       # 13 tests
node examples/mcp-indeterminate/generate-vectors.mjs --check
```

Nothing here is a proposed change to MCP's schema. Nothing here is a SEP. It
is a vocabulary carried in `_meta`, a field MCP already defines, published so
that the outcome axis that every agent-gate draft already carries has one
wire home instead of one per draft.

---

## 1. What MCP defines today

Read this run, 2026-09-02, from `modelcontextprotocol/modelcontextprotocol`
at `main`.

### `CallToolResult`

`schema/2026-07-28/schema.ts`, lines 1809 to 1838
(SHA-256 of the file as fetched: `742750af0bb8c716e7030c4977c992b55d1adc4407e9e66997db5846baedc2cd`):

```typescript
export interface CallToolResult extends Result {
  /**
   * A list of content objects that represent the unstructured result of the tool call.
   */
  content: ContentBlock[];

  /**
   * An optional JSON value that represents the structured result of the tool call.
   *
   * This can be any JSON value (object, array, string, number, boolean, or null)
   * that conforms to the tool's outputSchema if one is defined.
   */
  structuredContent?: unknown;

  /**
   * Whether the tool call ended in an error.
   *
   * If not set, this is assumed to be false (the call was successful).
   * ...
   */
  isError?: boolean;
}
```

Three fields. `isError` is a boolean about whether the call errored, not about
whether the effect landed. There is no third value, and there is no field that
survives the response never being written at all.

`ToolAnnotations` in the same file (line 1912) carries `idempotentHint`
(line 1943): "If true, calling the tool repeatedly with the same arguments
will have no additional effect on its environment." That is a hint about the
tool. It is not a statement about a particular call. A host that reads
`idempotentHint: false` learns that retrying is dangerous and learns nothing
about whether it needs to.

Case-insensitive grep counts over that exact file, this run:

| term | hits | where |
| --- | --- | --- |
| `indeterminate` | 0 | |
| `reconcil` | 0 | |
| `replay` | 0 | |
| `idempoten` | 1 | line 1943, the `idempotentHint` field name |
| `retry` | 3 | lines 213 and 586 (`input_required`: retry the request after supplying input), line 492 (version negotiation) |
| `duplicat` | 1 | line 694, guidance not to duplicate text in annotations |

Not one of those hits is about whether an effect occurred.

### The Tasks extension

`seps/2663-tasks-extension.md`
(SHA-256 as fetched: `2bd75e527a0796ffbc07ed34c47307a43c78de1e3001eada52e601051c09a385`).

Line 142, the closed status set:

```typescript
  status: "working" | "input_required" | "completed" | "cancelled" | "failed";
```

Line 41: "Each task is uniquely identifiable by a **server-generated task
ID**." Lines 180 to 190 define the five states, including:

- `completed`: "The request completed successfully and results are available
  in the `result` field. This includes tool calls that returned results with
  `isError: true`."
- `failed`: "The request failed due to a JSON-RPC error during execution ...
  This status **MUST NOT** be used for non-JSON-RPC errors."

None of the five means "unknown". `failed` is explicitly reserved for a
JSON-RPC error, which is not the same claim as "the effect did not happen".
Grep counts over that exact file, this run:

| term | hits | where |
| --- | --- | --- |
| `indeterminate` | 0 | |
| `reconcil` | 0 | |
| `retry` | 0 | |
| `idempoten` | 2 | lines 910 and 912, on `tasks/get` being a pure idempotent read that any layer can cache or replay safely |
| `replay` | 1 | line 910, the same sentence |
| `duplicat` | 5 | lines 350, 352, 637, 910, 940, all about deduplicating `inputRequests` keys across polls so a user is not shown the same prompt twice |

Every one of those is about the read path or about UX deduplication of
prompts. None is about an effect. Because the task ID is server-generated, a
client cannot create a task idempotently: it has no key to present twice.

### Where the topic sits on the roadmap

The roadmap update of 2026-03-09
(`blog/content/posts/2026-03-09-roadmap-update.md`, line 45) names the gap in
the language of transient failure:

> "Early production use has surfaced a concrete list of lifecycle gaps to
> close: retry semantics when a task fails transiently, and expiry policies
> for how long results are retained after completion."

**Correction to our own prior note, verified this run:** the current roadmap
(`docs/development/roadmap.mdx`, last updated 2026-08-22) contains no retry
item at all. A grep for `retry`, `transient` and `idempot` in that file
returns zero matches. What it does carry, under "Improved Primitives", is:

> "**Tool result shape**: Core Primitives WG (forming during this roadmap
> period). Redesign the `tools/call` interface to resolve fidelity
> disparities among return types and streamline the handling of structured
> and unstructured output."

There is no "Agent Communication WG" and no `core-primitives` charter in
`docs/community/working-groups/` on `main` as of this run; the Core Primitives
WG is described as forming. `seps/3004-*` does not exist in `seps/` on `main`
either. Treat any earlier note of ours that named a live retry item, an Agent
Communication WG, or a merged SEP-3004 as stale until re-read.

---

## 2. What this adds

Three fields, in `_meta`, under the prefix `ai.emiliaprotocol/`. The MCP
`MetaObject` key rules (schema.ts lines 34 to 53) reserve any prefix whose
second label is `modelcontextprotocol` or `mcp`; `ai.emiliaprotocol` is not
reserved, so this is a legal extension key today, on an unmodified server and
an unmodified client.

**1. A replay unit, supplied by the caller.**

```
replay_unit = "sha256:" + hex(SHA-256(
    "EP-MCP-REPLAY-UNIT-v1" || " " || authority_instance_digest || " " || caid))
```

`authority_instance_digest` is the digest of the authorization the human
actually granted. `caid` is the canonical action identifier over the exact
frozen arguments (`caid/registry/action-types.json`, type
`payment.release.1`). **The replay unit is supplied by the caller and derived
from the authority. It is never chosen by the model, and it is never minted by
the server.** Both inputs are content-addressed and executor-observed. Change
one material argument and the CAID changes, so the unit changes; there is no
value a model can emit that makes two different actions look like one replay
unit, and none that mints a fresh unit for the same action to escape dedup.

The server does not trust the presented value: it recomputes the derivation
over the authority it was shown and the action it actually froze, and refuses
before dispatch if they differ. Vector `EPMCP-06` is that refusal.

This is the property server-generated task IDs make impossible by
construction: idempotent creation keyed by something the caller holds before
the first attempt. (An earlier note of ours attributed a decision against
client-supplied IDs to SEP-2557. That is not verified here; `seps/2557-*` is
not in `seps/` on `main`, and we did not read the pull request this run.)

**2. A closed outcome value that includes `indeterminate`.**

`executed | failed | indeterminate`, with `retry`
(`not_applicable | refuse | requires_new_admission`) and `reconciliation`
(`not_applicable | required | applied | refused`). Unknown values are refused
by the parser, not passed through: a host that cannot recognise the outcome
must not proceed to a second effect.

`indeterminate` is not an error. `isError` stays `false`. The call did not
fail; the outcome is unknown.

**3. A reconcile handle bound to the same replay unit.**

```json
{ "method": "tools/call", "tool": "reconcile_effect", "replay_unit": "sha256:..." }
```

The parser refuses an envelope whose handle names a different replay unit, so
the only follow-up an `indeterminate` result can authorise is a read against
the same unit. In `client.mts` this is mechanical rather than advisory:
`nextLegalMove()` is the single function through which the host acts, and it
has no branch that returns "call the tool again".

### Mapping onto AEB-04 sections 5.10 and 5.11

`standards/posted/draft-schrock-action-evidence-boundary-04.xml`, section 5.10
(anchor `outcome`) and 5.11 (anchor `reconcile`).

| AEB-04 state | outcome | retry | reconciliation | AEB locator |
| --- | --- | --- | --- | --- |
| EXECUTED | `executed` | `not_applicable` | `not_applicable` | 5.10 |
| EXECUTED (via reconciliation) | `executed` | `not_applicable` | `applied` | 5.11, "Reconciliation MAY move INDETERMINATE to EXECUTED" |
| FAILED | `failed` | `requires_new_admission` | `not_applicable` | 5.10 |
| INDETERMINATE | `indeterminate` | `refuse` | `required` | 5.10, restart promotion of a stranded `DISPATCH_PENDING` |
| REQUIRES_NEW_ADMISSION | `failed` | `requires_new_admission` | `applied` | 5.11, plus the referee retry axis in `packages/verify/src/aeb-crossing-record.ts` |

The machine-readable form of this table, with a full worked example and six
`tools/call` vectors, is `vectors.v1.json`.

---

## 3. The two transcripts, verbatim from the run

Produced by `node examples/mcp-indeterminate/run.mjs` on Node v26.5.0 with
`@modelcontextprotocol/sdk` 1.30.0. Two consecutive runs are byte-identical:
the fault is injected at a fixed line by `EP_CRASH=after-effect`, and the
server uses a deterministic clock.

### Transcript 1: naive retry on today's MCP

```
==============================================================================
TRANSCRIPT 1  naive retry on today's MCP  ->  duplicate effect
==============================================================================
host   | connecting to the server (EP_MCP_MODE=legacy, EP_CRASH=after-effect)
wire   | tools/list -> release_payment annotations: idempotentHint=false destructiveHint=true
host   | the tool is marked non-idempotent and destructive. I read that hint and proceed.
wire   | tools/call release_payment {"amount":"82000.00","currency":"USD",...}
server | [server legacy] tools/call release_payment (no replay unit on the wire) caid=caid:1:payment.release.1:jcs-sha256:yfDuAnQWP2ZrOxYQjETOp2hkRUoF4Op1_fWE-K01eK8
server | [server legacy] effect applied at provider, operation_id=op-legacy-1
server | [server legacy] CRASH INJECTED after effect, before the CallToolResult is written
wire   | tools/call rejected: MCP error -32000: Connection closed
host   | CallToolResult is content + structuredContent + isError. I received none of them. Nothing on the wire distinguishes "never dispatched" from "already settled".
host   | RETRYING. This is the only move the current vocabulary leaves me.
server | [server legacy] tools/call release_payment (no replay unit on the wire) caid=caid:1:payment.release.1:jcs-sha256:yfDuAnQWP2ZrOxYQjETOp2hkRUoF4Op1_fWE-K01eK8
server | [server legacy] effect applied at provider, operation_id=op-legacy-2
wire   | tools/call -> released 82000.00 USD (operation op-legacy-2)
ledger | provider record now holds 2 entries:
ledger |   seq=1 operation_id=op-legacy-1 amount=82000.00 USD
ledger |   seq=2 operation_id=op-legacy-2 amount=82000.00 USD
ledger | HARM: 2 payments of 82000.00 USD settled from one authorization. The retry was the duplicate.
```

The host did nothing wrong. It read `idempotentHint: false`, it saw a
transport error, and it had no field in which the server could have told it
anything else. The gap is in the wire.

### Transcript 2: the same crash with the field group

```
==============================================================================
TRANSCRIPT 2  EP-MCP-OUTCOME-v1  ->  indeterminate, reconcile, one effect
==============================================================================
host   | authority instance digest: sha256:11ac1caa1b6f24e2f4b0e6a5f9a1a2c3d4e5f60718293a4b5c6d7e8f90a1b2c3
host   | frozen action: caid:1:payment.release.1:jcs-sha256:yfDuAnQWP2ZrOxYQjETOp2hkRUoF4Op1_fWE-K01eK8
host   | replay unit = SHA-256("EP-MCP-REPLAY-UNIT-v1" || authority || caid) = sha256:54572b4fe47fd4165209c356f9c62bf37b04440005d44aa6e9122546e8ef7790
host   | the model chose none of those three values.
host   | connecting to the server (EP_MCP_MODE=fieldgroup, EP_CRASH=after-effect)
wire   | tools/call release_payment _meta.ai.emiliaprotocol/replay-unit=sha256:54572b4fe47fd416...
server | [server fieldgroup] DISPATCH_PENDING written for op-54572b4fe47f, replay_unit=sha256:54572b4fe47fd416...
server | [server fieldgroup] effect applied at provider, operation_id=op-54572b4fe47f
server | [server fieldgroup] CRASH INJECTED after effect, before the CallToolResult is written
wire   | tools/call rejected: MCP error -32000: Connection closed
host   | reconnecting. I re-send the SAME request bound to the SAME replay unit.
server | [server fieldgroup] promoted stranded DISPATCH_PENDING to INDETERMINATE for op-54572b4fe47f
wire   | _meta["ai.emiliaprotocol/outcome"] -> outcome=indeterminate retry=refuse reconciliation=required reason=stranded_dispatch_pending_promoted_on_restart
host   | AEB-04 state: INDETERMINATE (draft-schrock-action-evidence-boundary-04 section 5.10, anchor "outcome")
host   | legal moves for this outcome: reconcile. Retry is not among them.
wire   | tools/call reconcile_effect {"replay_unit":"sha256:54572b4fe47fd416..."}
server | [server fieldgroup] reconciled op-54572b4fe47f to EXECUTED against a signed provider record
wire   | _meta["ai.emiliaprotocol/outcome"] -> outcome=executed retry=not_applicable reconciliation=applied reason=provider_record_matched
host   | AEB-04 state: EXECUTED
host   | legal moves now: done
ledger | provider record holds 1 entry:
ledger |   seq=1 operation_id=op-54572b4fe47f amount=82000.00 USD
ledger | one authorization, 1 effect. No duplicate.

same crash, same action, same authority: 2 effects without the field group, 1 with it.
```

Note the shape of the second exchange. The host does re-send the `tools/call`,
because MCP has no "read the outcome of a replay unit" method and inventing
one would be a protocol change. What the replay unit does is turn that
re-send from a second effect into a read: the server finds the unit already
has a dispatch record, so it answers with the outcome instead of acting. The
act the host is forbidden is a call carrying no replay unit or a fresh one.

### Reconciliation is honest about absence

The `failed` path (`runFailedPath`, exercised by the test suite) crashes
*before* the effect. Reconciliation does not conclude `failed` merely because
it sees no provider entry. It concludes `failed` only when the provider's
signed statement carries a completeness watermark covering the dispatch
window. Without that watermark the operation stays `indeterminate`, which is
vector `EPMCP-04`. AEB-04 section 5.11: "Missing, stale, conflicting,
unauthenticated, or action-mismatched observations MUST leave the operation
INDETERMINATE."

The provider statement is signed with real Ed25519 (`node:crypto`) and
verified against a pinned key. An unpinned key is refused with
`provider_key_not_pinned`.

---

## 4. Fail-closed, demonstrated against the bad input

Every refusal below is a returned refusal with a stated reason, observed in
the test suite. None of them is a thrown exception or a crash.

| Bad input | Response |
| --- | --- |
| replay unit not derived from the authority and the frozen action | `isError: true`, `refusals: ["replay_unit_not_derived_from_authority_and_action"]`, zero provider entries |
| envelope whose reconcile handle names a different replay unit | parser refusal `reconcile_handle_not_bound_to_replay_unit` |
| `outcome: "indeterminate"` with `retry: "not_applicable"` | parser refusal `indeterminate_must_refuse_retry` |
| unknown outcome value (`"probably_fine"`) | parser refusal `unknown_outcome_value` |
| `null`, `"x"`, `42`, `{}` passed to the derivation | refusal with a reason, no throw |
| provider statement under an unpinned key | refusal `provider_key_not_pinned` |

---

## 5. What this does not claim

- **It is not an MCP protocol change and it is not a SEP.** It uses `_meta`,
  which MCP already defines, under a prefix MCP does not reserve. Ownership of
  the protocol stays where it is.
- **It does not prove any deployed host behaves this way.** The naive host in
  transcript 1 is our own code written to do what today's vocabulary allows.
  It is a demonstration of what the wire permits, not a survey of shipped
  hosts. We have not measured how real hosts retry.
- **It does not make an effect atomic across two systems.** AEB-04 says so
  directly and so does this code: the boundary journal and the provider record
  are separate stores, and the entire example lives in the gap between them.
- **`indeterminate` does not mean "probably fine".** It means the evidence
  settles nothing. Reconciliation can leave it unresolved, and that is a
  correct answer.
- **Reconciliation does not resurrect an authorization.** Moving to `failed`
  does not release the replay unit; a later attempt is a new action instance
  under a new admission.
- **The `_meta` prefix is ours, not a registered one.** `ai.emiliaprotocol/`
  is legal under MCP's key rules and is not an allocation. If this vocabulary
  ever lands in MCP, the key belongs to MCP.

### What the example does not cover

- **Only stdio transport.** Streamable HTTP, and in particular a resumable
  stream where the response might still be recoverable, is not exercised.
- **No Tasks-extension path.** The whole point is a plain `tools/call` with a
  lost response; a task-augmented call would be a second, separate mapping,
  and this repository does not implement one.
- **One crash point, injected in-process.** `process.exit(70)` at two fixed
  lines. Not a partitioned network, not a half-written frame, not a provider
  that accepts and then reverses, not clock skew, not a Byzantine server.
- **A single-process boundary.** No replica fencing, no concurrent callers
  racing the same replay unit, no store failover. AEB-04 section 5.8 requires
  atomicity across replicas and this example does not test it.
- **The provider is a local file.** The signed statement and completeness
  watermark model what a provider would have to expose. No real provider
  exposes exactly this today, and getting one to is a separate problem.
- **No retention policy.** Replay units live forever in the journal here. A
  real deployment has to answer how long a unit is remembered relative to the
  lifetime of the authorization, and that question is open.
- **No authorization step.** The authority instance digest is a constant. The
  human approval that would produce it is out of scope for this example.
- **Not measured against a real host loop.** No Claude Desktop, no Inspector,
  no third-party client was driven through this.

---

## 6. Files

| File | What it is |
| --- | --- |
| `field-group.mts` | The vocabulary: derivation, closed value sets, envelope parser, AEB-04 mapping table |
| `ledger.mts` | Boundary journal and provider system of record, with the Ed25519 signed statement and completeness watermark |
| `server.mts` | MCP server on the official SDK, `legacy` and `fieldgroup` modes, deterministic fault injection |
| `client.mts` | The two host loops, plus `nextLegalMove()` |
| `run.mts` | Prints both transcripts |
| `run.test.mts` | 13 tests, including the fail-closed probes |
| `generate-vectors.mts` / `vectors.v1.json` | The vector pack |
| `CONTRIBUTION-STAGED.md` | Contribution text for the MCP community. **Staged and unsent.** |
