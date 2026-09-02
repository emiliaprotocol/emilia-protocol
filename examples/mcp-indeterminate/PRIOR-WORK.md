# Prior work, and what this example may and may not claim

Written 2026-09-02, after three adversarial refuters ran against the thesis
this example was built from. All three refuted it. This file records what
they found so that nobody reads the code or the transcripts as a claim of
novelty, and so the staged contribution offers only what is actually ours.

## SEP-2848 already defines the outcome vocabulary

`SEP-2848: Asynchronous Approval for Tool Calls`, pull request 2848 in
`modelcontextprotocol/modelcontextprotocol`, author `mcguinness`, opened
2026-06-03, last updated 2026-08-26, 6 comments, open and unmerged as of
2026-09-02. Verified this run through the GitHub API; the SEP text was
fetched at head `e7fff475323f5f6f930396d7a43df06115fe1e6f`, file
`seps/2848-asynchronous-approval-for-tool-calls.md`, 44881 bytes, SHA-256
`e9265765cb9617f2ffa7e161b5335f8f4979da7465e74a8c31c4a6ac2f96a9ec`.

It defines, at lines 382 to 386:

- `execution-error`: the tool was authorized and ran but failed; a side
  effect may have occurred.
- `outcome-unknown`: execution was claimed but the server cannot determine
  whether invocation or the side effect completed.

That is the closed outcome value this example was built to propose. It is not
ours, it is three months older, and it is in the venue's own process. Our
outcome names are superseded. The mapping table in `field-group.mts` must be
read as a mapping onto SEP-2848's dispositions, not as an alternative to
them.

`draft-saha-aadp-01` sections 5.3 and 7, in the standards corpus, separately
specifies the same discipline normatively: a closed outcome enum including
`timeout`, and the rule that a policy enforcement point must not re-issue
unless it can positively establish non-effect.

## What SEP-2848 says it does not have

Its Limitations section, quoted literally:

> **No general request idempotency in MCP.** Cross-task duplicate suppression
> is therefore best-effort; a general key belongs in the core or the tasks
> extension, and this extension should adopt one if it is added.

And at line 230, on its own duplicate matching:

> This is best-effort: a client-local nonce in the arguments defeats it,
> identical arguments from two distinct intents collide, and MCP has no
> request-level idempotency key that would make it exact (see Limitations).
> So the at-most-once guarantee is per task, and a non-idempotent tool can
> still run more than once through distinct tasks.

And, separately:

> **A lost `taskId` has no recourse.** With `tasks/list` and sessions removed,
> an agent that did not persist its `taskId` cannot rediscover a
> possibly-executed task, so clients MUST persist task IDs durably.

## What is left that is ours to offer

Two things, and neither is a vocabulary.

1. The replay unit. A caller-supplied key derived from the authority and the
   frozen action rather than chosen by the model, which is the general
   request-level key SEP-2848 says belongs in the core or the tasks extension
   and that it would adopt if one existed. Because it is derived, it also
   answers the lost-taskId limitation: a host that lost its handle recomputes
   the key from the authorization it still holds, instead of needing durable
   storage of a server-generated identifier.

2. The executed demonstration. Two payments settle from one authorization on
   today's vocabulary and one settles with the field group, from the same
   injected crash, reproducibly and byte-identically across runs. That is
   evidence for SEP-2848's case, not a competing proposal.

## What this example must not be called

Not white space. Not a plate. Not a new vocabulary. The refuter verdict was
three of three, and the corpus refuter's finding stands: the decision rule is
already specified elsewhere. This directory is a demonstration and a vector
pack offered into someone else's open proposal.
