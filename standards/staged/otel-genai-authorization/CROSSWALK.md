<!-- SPDX-License-Identifier: Apache-2.0 -->

# Crosswalk: how `gen_ai.tool.authorization.*` composes with existing work

Every quotation below was read on 2026-09-02 from the GitHub API
(`gh api repos/<owner>/<repo>/issues/<n>`), not from a summary. Each source
carries its URL. Anything not opened is marked UNVERIFIED and is not relied on.

The purpose of this file is the opposite of a competitive claim. Four of the six
sources below already name the slot this group fills; the point is to fill it in
their shape, under their issue, with their scope boundary, not to open a
competing surface.

---

## 1. semantic-conventions-genai #95, the slot itself

- URL: <https://github.com/open-telemetry/semantic-conventions-genai/issues/95>
- Title: "GenAI Sem Conv enhancement to capture MCP Tool approval"
- Opened 2026-04-28. State at read time: **open**. Labels: `area:mcp`,
  `area:tools`. 11 comments.

The whole of the issue's proposal section, quoted:

> Most of the coding agents support human in the loop for tool execution
> approval. Having gen-ai sem conv to capture it as part of tool execution by
> agent.
>
> Enhance existing gen-ai sem conv to capture approval as part of tool execution
> flow.
>
> TODO : Add more details

The slot is named and empty. Four months of comments have shaped what belongs in
it without anyone posting a model. **This group is the fill**, and it takes its
shape from those comments rather than from our own prior work.

What the thread converged on, and where this group lands:

**Approval is a pre-execution control state, not a tool result.**
@rpelevin, 2026-06-06:

> One distinction I would preserve in the semantic convention is that approval
> is a pre-execution control state, not a tool execution result.

Kept. `status` describes the decision, and the span's own `error.type` and
result attributes still describe the execution. A call can be approved and still
fail; both are recorded, separately.

**A denied call must leave a trace.** @AgentGymLeader, 2026-06-08:

> Strong +1 on the regression case, and I'd make it normative: a denied or
> expired call id must not have a downstream success span. That absence
> (denied/expired, no execute span) is what lets an auditor tell "blocked" apart
> from "never ran" or "lost telemetry."

Kept, as the `rejected` note in the model: a rejected call SHOULD NOT have a
successful downstream execution span for the same `gen_ai.tool.call.id`.

**No raw approver identity.** @AgentGymLeader, 2026-06-09:

> One caution on the audit fields though: I'd avoid having the convention
> require a raw approver identity. These spans can leave the originating system,
> so an opaque actor reference (or role / decision actor id) is safer than an
> `approver_id` that carries PII.

Kept, and taken further than the thread asked. This group defines **no approver
attribute at all**, opaque or otherwise. The thesis this work started from
listed an `.approver.ref`; it was dropped on reading this comment and
@rpelevin's follow-up. An approver reference adds nothing the evidence locator
does not already carry, and it adds a re-identification surface. If the SIG
later wants one, it belongs in #239's actor-ref shape, not here.

**Telemetry observes; it is not the authority.** @Rul1an, 2026-06-14:

> The boundary I'd keep explicit is that telemetry observes the approval
> decision. It does not become the approval authority. Whether an approval is
> valid, stale, already consumed, scoped to these args, or backed by a richer
> evidence record stays in the originating system.

Kept, and stated in the `status` note in exactly these terms. This is also why
`evidence.grade` exists: a consumer that cannot verify still needs to see which
statuses are worth trying to verify.

**A third outcome beyond approved and declined.** @JM-Lab, 2026-07-11, from a
shipping implementation (Spring AI Playground, Apache-2.0):

> Three outcomes proved necessary in practice, not two:
>
> - approved: a human explicitly allowed the call before execution
> - declined: a human explicitly refused it
> - ask-failed: the approval interaction itself failed (timeout, closed
>   dialog, transport error) and the call was refused fail-safe

**This is the one substantive gap in the group as staged.** `rejected` currently
covers both a human decline and a fail-closed refusal after the approval
interaction broke. Those are operationally different: one is a working control,
the other is approval fatigue or a broken approval path. The honest options are
a tenth status value or a separate reason attribute, and the choice belongs to
the SIG, not to us. Recorded here rather than silently resolved.

**Argument drift invalidates an approval.** @rpelevin, 2026-06-09:

> Changed args digest, resource scope, tool call id, audience, or policy version
> creates a new decision or a rejected/stale decision, not reuse of the old
> approval.

This is what `action.digest` and `policy.digest` are for, and it is why they are
digests rather than free strings. Two records naming the same action digest are
about the same action; if the arguments changed, the digest changed, and
`authorized_out_of_scope` is available to say so.

---

## 2. semantic-conventions-genai #239, the shared decision-point model

- URL: <https://github.com/open-telemetry/semantic-conventions-genai/issues/239>
- Title: "Opaque governance references for GenAI agent decision points"
- Opened 2026-06-03. State at read time: **open**.

Three commenters in #95 point at #239 as the shape MCP approval should line up
with, so it is the most important composition target and also the sharpest
objection to this group.

#239 proposes `gen_ai.agent.decision.id`, `gen_ai.agent.decision.outcome` and
`gen_ai.agent.governance.ref`, and says of their values:

> Values should be opaque handles (`ctx_7f3a9c`, `decision_01J...`), never
> embedded JSON, prompts, tool arguments, policy bodies, evidence hashes, or
> user data.

and, under Non-goals:

> If an implementation wants hashes, signatures, or receipts, those live behind
> the opaque ref.

**Read that plainly: #239 names "evidence hashes" in its exclusion list.** That
is the live objection to `evidence.digest`, `action.digest` and `policy.digest`,
stated on the record before this group existed, by the proposal the #95 thread
keeps deferring to. It is close to kill condition (a) for this whole line of
work and it is not softened here.

The counter-argument, offered as a question for the SIG rather than as a settled
answer: #239's stated reason for the exclusion is payload and PII leakage, and
its own worked examples of what to exclude are JSON, prompts, tool arguments,
policy bodies and user data. A digest is the opposite of a payload: it is fixed
length, carries no plaintext, and is the only thing that makes an opaque handle
substitution-resistant. A locator alone tells a reader where to look; a locator
plus a digest tells the reader whether what they found is what the call was
decided on. If #239's exclusion is aimed at payloads, digests are compatible
with it. If the exclusion is aimed at digests as such, this group loses three of
its seven attributes, and the remaining four still work.

Composition, if #239 lands: `evidence.locator` and `gen_ai.agent.governance.ref`
are the same kind of handle and a producer emitting both SHOULD use the same
value. `status` is the tool-call specialization of `decision.outcome` and can be
generated from the same producer state. Nothing in this group needs a decision
id of its own.

Namespace: #239 leaves open whether it belongs under `gen_ai.agent.*` or the
broader `agent.*` direction from #132. If the SIG moves decision surfaces to
`agent.*`, this group moves with them.

---

## 3. semantic-conventions-genai #373, tool risk attributes

- URL: <https://github.com/open-telemetry/semantic-conventions-genai/issues/373>
- Title: "Proposal: tool risk attributes for execute_tool and MCP tool call telemetry"
- Opened 2026-07-11. State at read time: **open**.

#373 proposes `gen_ai.tool.risk.level`, `.override` and `.method`, and defers
approval to #95 explicitly:

> Related, non-overlapping work: #95 captures the human approval decision for
> a tool call (this proposal carries the assessed risk that often *triggers*
> that approval)

The two are complementary by #373's own construction, and the composition is the
query in the docs: risk level is the assessed input, authorization status is the
observed outcome.

#373 also fixes the shape both proposals should share:

> All three are opt-in and carry no payloads, prompts, or policy bodies, in
> line with the opaque-reference direction discussed in #239. The level is the
> observed output of the producer's assessment, not a claim the consumer must
> trust; the convention only standardizes where the signal travels.

This group follows that sentence exactly, including the last clause. `status` is
the observed output of the producer's decision, not a claim the consumer must
trust, and `evidence.grade` is what makes that visible rather than merely
disclaimed in prose.

#373's scope boundary also applies here, unchanged:

> When a host never exposes a tool because its assessed posture exceeds an
> exposure ceiling, no tool-call span is emitted at all

An authorization status only exists where a tool-call span exists. A capability
that was never reachable is #239's concern, not this group's.

---

## 4. semantic-conventions-genai #159, async agent lifecycle events

- URL: <https://github.com/open-telemetry/semantic-conventions-genai/issues/159>
- Title: "Add async/long-running agent lifecycle events: gen_ai.agent.paused / .resumed / .checkpointed"
- Opened 2026-05-14. State at read time: **open**. Label: `area:agent`.

#159 proposes span events on the agent span, with:

> `gen_ai.agent.pause.reason` | Why execution paused (`human_input`,
> `external_system`, `rate_limit`, `scheduled_delay`) | string

and motivates them:

> An agent that paused for 3 hours waiting on human approval needs observability
> on *when* and *why* it paused, not just whether it ultimately completed.

**Exactly orthogonal, and the pairing is useful.** #159 records that the agent
paused for a human and when it resumed. It records nothing about what the human
decided. This group records the decision and nothing about the waiting.
`pause.reason = human_input` with no authorization status on the child
`execute_tool` span is a visible gap; the two together give the full shape of a
long-running approval: paused at t, resumed at t+3h, resolved
`authorized_in_scope` at grade `third_party_logged`.

It is also the cleanest answer to the pending-status question. A step that is
waiting is an #159 pause event, not a #95 status. That is why this group omits
the attribute for a pending step instead of adding a `pending` value.

---

## 5. semantic-conventions-genai #132, runtime threat detection

- URL: <https://github.com/open-telemetry/semantic-conventions-genai/issues/132>
- Title: "Proposal: gen_ai.threat.detection.* attributes for runtime threat detection on agent spans"
- Opened 2026-05-09. State at read time: **open**. Label: `area:agent`.
  Draft PR #165 referenced from the body.

#132 proposes five `agent.threat.detection.*` attributes plus an event, and its
`action` enum reaches into #95's territory:

> `agent.threat.detection.action` (enum: `allow` | `block` | `warn` | `ask`) —
> enforcement decision at detection time, not necessarily the final outcome.
> `ask` covers the MCP tool-approval pending state from #95 where the absence of
> execution is intentional and successful.

This is the overlap to name rather than paper over: `ask` and an
authorization status could both try to describe the same moment. They do not, if
the split is kept clean, and #132's own wording gives the split: `ask` is the
**detection-time enforcement decision**, "not necessarily the final outcome".
This group records the **final outcome of the human step**. A single call can
carry both: `agent.threat.detection.action = ask` when the guard decided to
escalate, then `gen_ai.tool.authorization.status = rejected` when the human said
no. A producer emitting only the first cannot answer what the human decided; a
producer emitting only the second cannot answer why the human was asked.

#132 also moved its namespace to `agent.*`, for a reason that matters here:

> control points that sit outside provider spans (forward proxy, MCP proxy, CI
> wrapper, host-level network filter) should not be forced to misrepresent where
> enforcement happened

An authorization step often resolves in exactly those places. If the SIG settles
on `agent.*` for control-point surfaces, `agent.tool.authorization.*` is the
correct name for this group and the argument for `gen_ai.*` is only that the
tool-call span is already `gen_ai.*`. We do not hold a position on this and
would follow whatever #132/#165 settles.

Draft PR #165 is referenced in #132's body as
"marked draft pending SIG confirmation of the `model/agent/` namespace folder
location". **UNVERIFIED**: PR #165 itself was not opened and read.

---

## 6. Traceloop OpenLLMetry RFC #3460

- URL: <https://github.com/traceloop/openllmetry/issues/3460>
- Title: "[RFC] Semantic Conventions for AI Agent Observability"
- Opened 2025-11-23. State at read time: **open**. Vendor repository, not an
  OpenTelemetry repository.

RFC #3460 is a 20-span-type convention proposal and is the only concrete
human-approval shape published anywhere in this space. Section 7.3, quoted in
full:

> ### 7.3 `gen_ai.human.review`
>
> **Description**: Human-in-the-loop review or approval.
>
> **Span Kind**: `INTERNAL`
>
> **Required Attributes**:
>
> | `gen_ai.human.approval_required` | boolean | Whether approval needed | `true`, `false` |
> | `gen_ai.human.intervention_type` | string | Type of human intervention | `"approval"`, `"feedback"`, `"correction"`, `"guidance"` |
>
> **Optional Attributes**:
>
> | `gen_ai.human.approval_granted` | boolean | Whether approved | `true`, `false` |
> | `gen_ai.human.feedback` | string | Human feedback text | `"Looks good, proceed"` |
> | `gen_ai.human.response_time_ms` | int | How long human took | `45000` |
> | `gen_ai.human.reviewer_id` | string | Reviewer identifier (hashed) | `"reviewer_hash_xyz"` |

The RFC's stated design principle is:

> 2. **Extend, Don't Replace** - Build on existing `gen_ai.*` conventions

**These two proposals do different jobs and both are needed.**

RFC 3460 models the review as its own span, which is the right shape for the
things a span is good at: duration (`response_time_ms`), nesting, and the fact
that a review is an activity with a start and an end. This group models the
outcome as attributes on the tool call, which is the right shape for filtering:
you cannot write "show me every irreversible tool call with no human step" over
a span type that is absent when there was no review.

The composition, concretely:

| RFC 3460 §7.3 | This group | Note |
|---|---|---|
| `gen_ai.human.approval_granted = true` | `status = auto_approved`, `evidence.grade = self_attested` | A boolean with no scope supports no more than this |
| `gen_ai.human.approval_granted = false` | `status = rejected`, `evidence.grade = self_attested` | |
| `gen_ai.human.approval_required = false` | `status = no_authorization_step` on the tool call | The RFC's span is usually absent in this case; the attribute is not |
| `gen_ai.human.intervention_type = "correction"` | `status = edited_then_approved` | The RFC has the type but not the outcome |
| `gen_ai.human.response_time_ms` | no equivalent, and none wanted | Span duration is a span's job |
| `gen_ai.human.reviewer_id` | **no equivalent, deliberately** | See #95's PII caution above; this group defines no approver attribute |
| `gen_ai.human.feedback` (free text) | **no equivalent, deliberately** | Free-text human input on an exported span is a payload |
| no equivalent | `evidence.grade`, `evidence.digest`, `action.digest`, `policy.digest` | The RFC's shape cannot distinguish a boolean from a checkable artifact |

A producer implementing RFC 3460 can emit this group from the same state, with
no new plumbing: it already has the decision and the tool name at review time.

---

## 7. Crosswalk to EMILIA's own shipped vocabularies

This matters for internal honesty. The status values in this group are the ones
named for this work, and **they are not identical to what this repository has
already shipped.** Two related vocabularies exist here and both use different
value names:

### 7a. `standards/aiuc/incident-fields-v0` (shipped, JSON Schema)

`incident-fields.schema.json` `$defs.authorization.status` enumerates:
`standing_authority`, `specific_approval`, `denied`, `revoked`, `outside_scope`,
`authority_absent`, `indeterminate`. Its `evidence_grade` enumerates
`E0_no_reviewable_evidence`, `E1_party_attested`, `E2_independently_correlated`,
`E3_artifact_verifiable`.

| OTel group | AIUC incident-fields v0.1 | Note |
|---|---|---|
| `authorized_in_scope` | `specific_approval` | |
| `authorized_out_of_scope` | `outside_scope` | |
| `authorized_without_standing` | no exact equivalent | AIUC has `authority_absent`, which is closer to `no_authorization_step` |
| `standing_preauthorization` | `standing_authority` | |
| `no_authorization_step` | `authority_absent` | |
| `step_bypassed` | no exact equivalent | AIUC's `execution.status = effected` with `authority_absent` is the nearest coding |
| `auto_approved` | no equivalent | AIUC codes incidents after the fact and does not distinguish a rule from a human |
| `rejected` | `denied` | |
| `edited_then_approved` | no equivalent | |
| `evidence.grade = self_attested` | `E1_party_attested` | |
| `evidence.grade = third_party_logged` | `E2_independently_correlated` | Not an exact match: E2 requires correlation, not merely a third-party record |
| `evidence.grade = independently_verifiable` | `E3_artifact_verifiable` | |
| (no equivalent) | `E0_no_reviewable_evidence` | AIUC forces `status = indeterminate` at E0; this group instead omits the status |

Three of the nine OTel values have no AIUC equivalent and two AIUC values have
no OTel equivalent. **The two vocabularies are not the same vocabulary and this
document does not claim they are.** They are reconcilable and the mapping above
is the reconciliation, but any statement that the OTel group "uses the AIUC
codes" would be false.

### 7b. `standards/staged/action-authorization-status.reference.ts` (shipped, TypeScript)

`ACTION-AUTHORIZATION-STATUS-v1` is not an enum at all. It is a tuple of
`AUTHORITY_STATES` x `ACTION_BINDINGS` x `ADMISSION_STATES` x `EFFECT_STATES`,
with a separate `AUTHORIZATION_EVIDENCE_CLASSES` ladder `E0_NONE` through
`E5_RECONCILED_NAMED_POPULATION`. It is richer than a span attribute can be and
was designed for a claims record, not a telemetry field.

The projection onto this group is lossy and one-way:

| Tuple | OTel status |
|---|---|
| `admission = bypassed` | `step_bypassed` |
| `admission = refused` | `rejected` |
| `authority = valid` and `binding = exact_action` | `authorized_in_scope` |
| `authority = valid` and `binding = outside_bound` | `authorized_out_of_scope` |
| `authority = invalid` or `revoked`, `admission = admitted` | `authorized_without_standing` |
| `requirement = standing_scope`, `binding = within_bound` | `standing_preauthorization` |
| `requirement = none` | `no_authorization_step` |
| anything `indeterminate` or `not_evaluated` | omit the attribute |

Evidence class E0/E1 map to `self_attested`, E2 to `third_party_logged`, E3-E5
to `independently_verifiable`. E4 and E5 are strictly stronger than
`independently_verifiable` and the span cannot carry the difference; a consumer
that needs it reads the artifact, not the span.

**A span attribute is a lossy projection of a claims record, on purpose.** That
is the trade this whole line of work makes: three characters of vocabulary that
millions of tool calls can emit for free, in exchange for a coding record that
almost nobody will ever fill in.

---

## What is unverified

- **Weaver was not run.** See `docs/gen-ai-tool-authorization.md`.
- **PR #165 was not read.** Only #132's description of it.
- **The Vercel AI SDK, Langfuse, LangSmith, SigNoz, Sentry and Logfire
  ingestion claims were not re-verified in this session.** They are load-bearing
  for the "compelled reader" argument and are carried here as UNVERIFIED. The
  narrow claim this work does rest on is weaker and is not in doubt: an
  observability backend indexes the span attributes it receives. That is
  ingestion, not verification, and it is a compelled read only in the sense that
  a backend cannot choose not to index what it is sent.
- **AIUC-1's treatment of runtime telemetry as a human-oversight evidence
  source** is carried from memory and was NOT re-read in this session.
- **No OpenTelemetry maintainer has seen this.** Nothing here has been
  submitted, commented, or discussed upstream.
