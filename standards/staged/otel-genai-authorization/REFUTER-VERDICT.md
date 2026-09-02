# Refuter verdict on this work, 2026-09-02

Three adversaries ran against the thesis behind this directory. Two refuted
it. This file exists so the attribute model and the staged upstream text are
not read as a claim of white space.

## What they found

**The world refuter.** Nothing has merged upstream, and that part of the
thesis held: `gen_ai.tool.*` in the registry is still exactly seven keys with
no attribute matching approve, authoriz, human, consent, permission or
policy. But parties reached the same slot one to four months before this
thesis was written, and issue 239 (2026-06-03) proposes that values be opaque
handles, listing in its own Non-goals: "If an implementation wants hashes,
signatures, or receipts, those live behind the opaque ref." That names
evidence hashes in the exclusion list, inside the proposal the issue-95
thread keeps deferring to. If the SIG adopts that exclusion as written, three
of the seven attributes here die and four still work.

**The filter refuter.** The compelled read fails, and the thesis concedes it
in its own text: ingestion by a backend is a compelled read, not a compelled
verification. No rule, contract or economic force with a date was named.
Content-wise it carries the already-killed reference triple into another
reserved slot.

**The corpus refuter** did not refute: no draft in the 856-file corpus
specifies a vendor-neutral authorization attribute group on the tool-call
span. It noted the residual is thinner than the thesis stated, because three
of the four structural pieces already have named occupants.

## What this directory may be called

A contribution offered into issue 95, composing with 373, 159 and 132 and
mapping to the Traceloop shape. Not white space, not a plate, and not land.
The crosswalk in `CROSSWALK.md` states the issue-239 objection without
softening it, which is the right posture and should stay that way.

## Correction carried over from the build

The status values were specified from a vocabulary described as already
decided for the insurance taxonomy work. Those literal values do not exist in
this repository; a grep for `no_authorization_step`, `authorized_in_scope`
and `step_bypassed` returns zero hits. Two different vocabularies are what is
actually shipped. Reconcile that before the upstream text is sent, or the
first reviewer who greps will find the same gap.
