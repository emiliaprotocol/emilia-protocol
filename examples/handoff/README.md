# Laptop-on-fire — verifiable agent context-handoff

A runnable proof that an **authorization receipt is one primitive across two trust
boundaries**: the operator↔auditor boundary (GRACE / distributed-trace audit) and
the **agent↔agent context-handoff** boundary (this demo).

```bash
python3 examples/handoff/laptop_on_fire.py
```

(Needs `cryptography`; imports the published `emilia_verify`, falling back to the
in-repo copy so a fresh clone runs with no install.)

## What it shows

An agent runs a multi-step task, writing a receipt to disk **before and after**
each action — `intent → act → result` — as a signed, hash-linked chain (the
"git-backed JSON memory"). Mid-task the context window dies (token wall / laptop
on fire): the step-2 intent is on disk, its result is not, and the agent's
in-memory state is gone.

A **fresh agent cold-boots** from the chain — `git pull → inject JSON memory →
verify → resume`. It:

1. Verifies **every** receipt offline (Ed25519 over RFC-8785/JCS canonical bytes)
   with the published verifier, plus the `prev`-hash linkage — **zero trust** in
   the prior runtime.
2. Reconstructs what is *done* vs *unfinished* from the **receipts, not a summary**
   (steps 0–1 have intent+result; step 2 has intent only).
3. Resumes the unfinished step and re-verifies the chain end-to-end.
4. **Fail-closed:** a tampered receipt breaks the signature → the boot **refuses**
   to resume on an unverifiable handoff.

## Why it matters

The next agent and the prior agent don't share state, so a mutable local memory
can't answer *"what was authorized / what actually ran"* across the cut. A signed
receipt chain can — the same trust-boundary argument EMILIA makes for irreversible
actions, here pointed at the context window. **Verify the chain; don't trust the
summarizer.**

See the combined design sketch (`purpose-bound-receipt`) for the full
two-boundary framing and the benchmark list for the distributed-trace side.
