# Agent Authorization Coverage, rubric v1

A vocabulary for one question: **when an autonomous agent can take a
consequential action, does the thing that exposes that action declare a human
authorization precondition?**

This rubric is implementation-neutral and free to adopt. Citing it does not
require citing, adopting, or endorsing any product. If you are writing about
agent authorization and you need categories and verdicts that mean the same
thing to two different readers, use these and change nothing.

Rubric identifier: `EP-COVERAGE-RUBRIC-v1`

## 1. Scope, and what this rubric is not

A rubric verdict is a statement about **a declaration, as published on a date**.

It is not a statement about runtime behaviour, and it must never be written as
one. A system whose runtime genuinely does require human approval, but whose
published declaration does not say so, is correctly described as
`DECLARATION_SILENT`. That sentence is true either way, which is exactly why it
is the only kind of sentence this rubric permits.

A verdict is therefore **not** a vulnerability report, not a security finding,
and not an accusation. It is a dated observation about a document.

Three prohibitions follow, and they are normative:

1. **Do not probe.** Do not invoke, call, or exercise a third party's declared
   capability to observe whether it refuses. Read what they published.
2. **Do not infer runtime.** No verdict may contain "vulnerable", "insecure",
   "does not require", "unprotected", or any equivalent.
3. **Do not publish on machine output alone.** Automated classification of prose
   is imprecise. A human confirms each finding before it is attached to a named
   party. See section 5.

## 2. The seven consequential-action categories

A capability is consequential when performing it wrongly cannot be undone by
retrying, and the loss lands on somebody who did not choose it.

| Category | Identifier | Why it qualifies |
| --- | --- | --- |
| Money movement | `money_movement.release` | Releases funds or value. The loss is immediate and external. |
| Bank-detail change | `money_movement.bank_details_change` | Changes where future money flows. The loss is deferred and compounding. |
| Production deploy | `production.deploy` | Changes live system behaviour for everyone at once. |
| Permission or admin change | `permissions.admin_change` | Changes who else can act, so it multiplies every other category. |
| Bulk data export | `data.bulk_export` | Irreversible disclosure. Cannot be recalled once out. |
| Record destruction | `records.delete` | Irreversible loss of the record of what was true. |
| Regulated determination override | `regulated.decision_override` | Decides a benefit, claim, or eligibility for a person. |

The set is deliberately small and closed. A capability that mutates state and
matches none of the seven should be recorded as indeterminate rather than
squeezed into the nearest label.

## 3. Verdicts

| Verdict | Meaning | Finding? |
| --- | --- | --- |
| `NO_CONSEQUENTIAL_ACTION_DECLARED` | The declaration advertises nothing in the seven categories. | No |
| `DECLARED_AUTHORIZATION` | It advertises at least one category and states a human authorization precondition. | No |
| `DECLARATION_SILENT` | It advertises at least one category and states no such precondition. | Yes |
| `INDETERMINATE` | It could not be classified. | No |

Each verdict renders to one sentence, and every sentence opens with
`As published on <YYYY-MM-DD>`. The date is mandatory. An undated verdict is not
reproducible and must not be published.

## 4. Evidence obligations

Every finding carries:

- the **exact quoted span** of the declaration that produced it, and the term
  matched, so the subject can see precisely what to change;
- a **digest of the exact declaration bytes** assessed, so there is never a
  dispute about which revision was read;
- the **remedy**, which for `DECLARATION_SILENT` is always the same: publish the
  precondition, and the verdict changes in the next edition.

A finding without a quoted span is not a finding. It is an opinion.

## 5. Precision, and the human gate

Classifying a one-line prose description is imprecise, and honesty about the
rate is part of the rubric rather than a footnote.

Measured by hand on the first live 200-row sample of the public MCP registry,
before tightening: **roughly 55% precision**, with false positives including a
merchant *directory* scored as money movement, a screenplay tool's file export
scored as bulk data export, and eight servers scored as permission changes on
the strength of one vendor's boilerplate phrase "no API keys", which negates the
capability. After adding negation detection, read-only suppression, and
mutation-shaped keywords: **roughly 80%**, with the surviving error reading
"debug deployment" as a deploy capability.

Eighty percent is not publishable against a named party. Therefore:

**Machine output produces candidates. A human confirms or rejects each one by
reading the declaration. Only confirmed findings may be published.**

An edition containing any unreviewed candidate is `DRAFT` and must not ship.

## 6. Corrections

Any subject may dispute a verdict. Because every finding carries the declaration
digest and the quoted span, a dispute is settled by re-deriving rather than by
argument. A disputed verdict is corrected publicly within 24 hours or withdrawn.

One uncorrected wrong verdict about a named party costs more than an entire
register is worth. That asymmetry is the reason for every rule above.

## 7. Reaching `DECLARED_AUTHORIZATION`

Publish, in the declaration itself, that a human authorization precondition
applies to the consequential capabilities. Any of these phrasings is honoured:
human approval, human in the loop, requires approval, approval required,
requires confirmation, requires authorization, manual approval, explicit
consent, dual control, two-person, four-eyes, or a named authorization receipt.

The generosity is intentional. A subject gets the benefit of any reasonable
reading, because a false finding costs more than a missed one.
