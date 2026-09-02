# CONTRIBUTION, STAGED AND UNSENT

**REWRITTEN 2026-09-02 after the refuters.** The original text offered an
outcome vocabulary. SEP-2848 already has one. This is now a contribution
*into* SEP-2848, offering the two things that survived: the derived replay
unit its own Limitations section says is missing, and the executed
demonstration. Read `PRIOR-WORK.md` first. Do not send the version below
without re-reading it; every quote in `PRIOR-WORK.md` and `README.md` was
verified on 2026-09-02 and goes stale when those files move.

**Intended venue, corrected:** the SEP-2848 pull request thread
(`modelcontextprotocol/modelcontextprotocol` PR 2848), not the roadmap and
not the Tasks extension in isolation.

**Explicitly not:** a competing SEP, a schema pull request, or a claim that
the outcome vocabulary is ours.

---


## Draft text

Subject: indeterminate is not a transient failure: a tools/call outcome an
agent host can act on

Hi all,

I want to put one problem in front of the tool-result-shape work while the
shape is still open, and I have running code and vectors rather than a
proposal.

A tool marked `idempotentHint: false` performs an irreversible effect. The
server process dies between the effect and the response. The host sees a
closed connection. `CallToolResult` is `content`, `structuredContent` and
`isError`, and the host received none of them, so nothing on the wire
separates "never dispatched" from "already settled". The host retries,
because that is the only move the vocabulary leaves it. The retry is the
duplicate.

The Tasks extension does not close this. Its five statuses are `working`,
`input_required`, `completed`, `cancelled` and `failed`, and `failed` is
scoped to a JSON-RPC error during execution, which is a different claim from
"the effect did not happen". Task IDs are server-generated, so a client has
no key it held before the first attempt and cannot create a task
idempotently. The roadmap update in March framed the gap as retry semantics
for a task that fails transiently. I think transient is the wrong frame.
Indeterminate is not a failure at all. The call did not fail. The outcome is
unknown, and unknown is a state a host has to be able to read.

What I built is three fields in `_meta`, on an unmodified SDK server and
client, under a prefix that is not reserved by the MetaObject key rules:

1. A replay unit, supplied by the caller and derived from the authorization
   instance digest and the canonical digest of the exact frozen arguments.
   The model does not choose it and the server does not mint it. The server
   recomputes the derivation over what it actually froze and refuses before
   dispatch if the presented value does not match, so the property is
   enforced rather than advised.
2. A closed outcome value: `executed`, `failed`, `indeterminate`, with a
   retry disposition and a reconciliation disposition alongside it.
   `isError` stays false for `indeterminate`.
3. A reconcile handle carrying the same replay unit, so the only follow-up an
   `indeterminate` result authorizes is a read against the same unit rather
   than a second effect.

The example is at `examples/mcp-indeterminate/` in the emilia-protocol
repository. It runs both host loops against the same deterministic crash. In
the first, on today's vocabulary, one authorization settles two payments of
82,000 USD. In the second, the reconnecting host re-sends the same request
bound to the same replay unit, gets `indeterminate` with a reconcile handle,
reconciles against a signed provider record, and settles at one payment. Both
transcripts are in the README verbatim and two runs are byte-identical.

Two things I want to be careful about, because they are where this kind of
proposal usually goes wrong.

The reconciliation half is only honest if absence can be authoritative. In
the example, reconciliation concludes `failed` only when the provider's
signed statement carries a completeness watermark covering the dispatch
window. Without that watermark the operation stays `indeterminate`, and I
treat that as a correct answer rather than a failure to resolve. I do not
know of a provider that exposes such a watermark today. That is a real gap
and I would rather name it than paper over it.

The second is scope. This does not make an effect atomic across two systems,
and it does not claim to. The whole thing lives in the gap between a
boundary's own journal and the effecting system's record. What it buys is
that the gap becomes something a host can read and refuse on, instead of
something it has to guess about.

There is a vector pack, `vectors.v1.json`, with six `tools/call` exchanges
including the duplicate one. It is deliberately implementation-independent:
you can build against the vectors without running any of my code. If the
maintainers want a different key shape, a different value set, or this
carried somewhere other than `_meta`, I would rather adopt yours than argue
for mine. What I care about is that `indeterminate` exists somewhere in the
result, because once it does, a host that retries anyway is doing something
the protocol says not to do, and every agent-gate design that currently
carries its own private unknown state has one place to compile to.

Happy to bring the runnable pair to whichever venue is right for it, and
happy to be told it belongs somewhere else entirely.

Iman Schrock, EMILIA Protocol

---

## Claim to evidence, for the pre-send review

| Claim in the draft | Evidence |
| --- | --- |
| `CallToolResult` is content, structuredContent, isError | `schema/2026-07-28/schema.ts` lines 1809 to 1838, fetched this run, file SHA-256 `742750af0bb8c716e7030c4977c992b55d1adc4407e9e66997db5846baedc2cd` |
| Zero occurrences of indeterminate, reconcil, replay in that file | grep counts recorded in `README.md` section 1 |
| The five task statuses | `seps/2663-tasks-extension.md` line 142, file SHA-256 `2bd75e527a0796ffbc07ed34c47307a43c78de1e3001eada52e601051c09a385` |
| `failed` is scoped to a JSON-RPC error | same file, line 186 |
| Task IDs are server-generated | same file, line 41 |
| The March roadmap framing | `blog/content/posts/2026-03-09-roadmap-update.md` line 45 |
| Tool result shape is a live roadmap item, Core Primitives WG forming | `docs/development/roadmap.mdx` line 73, last updated 2026-08-22 |
| `ai.emiliaprotocol/` is not a reserved `_meta` prefix | `schema.ts` lines 34 to 53 |
| Two payments settle in the naive run, one in the field-group run | `node examples/mcp-indeterminate/run.mjs`, transcripts in `README.md` section 3, asserted in `run.test.mts` |
| The server refuses a replay unit it did not derive, with no effect | `run.test.mts`, "a model-chosen replay unit is refused with a stated reason and no effect" |
| The provider statement is really signed | `ledger.mts`, Ed25519 via `node:crypto`, verified against a pinned key; unpinned key refused |

Not verified this run, and therefore not claimed in the draft: any disposition
of SEP-2557, the existence of an Agent Communication working group, and the
behaviour of any shipped MCP host under a lost response.
