# July 27 Thin Core

Status: private local planning and release-control artifact. Sources may be
committed on the local private branch; nothing in this slate is published,
submitted, or pushed by this worktree task.

## Decision

The July 27 line is exactly five documents:

1. `draft-schrock-action-evidence-boundary-00` (AEB-00)
2. `draft-schrock-ep-architecture-02` (Architecture-02)
3. `draft-schrock-ep-authorization-receipts-08` (Authorization Receipts-08)
4. `draft-schrock-ep-authorization-evidence-chain-04` (AEC-04)
5. `draft-schrock-ep-revocation-statement-00` (Revocation Statement-00)

This is one continuity core, not five competing protocols:

```text
native VERIFIED
  -> CAID MATCH
  -> AEC SATISFIED
  -> local AUTHORIZED
  -> atomic CONSUMED / RESERVED
  -> durable DISPATCH_PENDING
  -> INVOKED
  -> EXECUTED / FAILED / INDETERMINATE
  -> authenticated reconciliation when indeterminate
```

No additional document enters the July 27 slate.

## The five documents

| Document | Owns | Must not absorb |
| --- | --- | --- |
| AEB-00 | The effect-boundary lifecycle: live relying-party enforcement configuration, optional discovery declarations, action-bound challenge semantics, native verification ordering, CAID match, AEC satisfaction, local authorization, atomic consumption or reservation, durable dispatch intent, invocation, closed effect outcomes, and authenticated reconciliation | A new receipt or token, native verifier semantics, a policy language, a universal evidence taxonomy, or a registry |
| Architecture-02 | The one-architecture narrative, applicability test, non-collapsing vocabulary, layer boundaries, and document map | Format-specific claims or a second execution state machine |
| Authorization Receipts-08 | The EMILIA action-bound organizational approval evidence profile, including its own ceremony, verifier, offline claim boundary, and receipt-specific replay semantics | Every approval mechanism, workload identity, machine-policy permits, or universal human-operation claims |
| AEC-04 | Native-verifier dispatch, exact action binding, relying-party evidence requirements, SATISFIED or UNSATISFIED, and the useful evidence-policy replay substance from AEG-00 | Local authorization, execution, effect truth, or a replacement format for native evidence |
| Revocation Statement-00 | Terminal negative evidence and authenticated status semantics, including the distinction between credential status and per-action authorization evidence | Authorization receipts, AEB lifecycle control, or an implication that current credentials authorize an action |

## Replacement and supersession map

The portfolio mapping is decisive:

| Earlier document | Canonical owner after July 27 | Disposition |
| --- | --- | --- |
| `draft-schrock-agent-action-manifest-00` | AEB-00 | Absorbed. Static declaration remains discovery; live relying-party enforcement configuration is authoritative. No separate Manifest revision. |
| `draft-schrock-authorization-evidence-challenge-00` | AEB-00 | Absorbed. Dynamic missing-evidence challenge, action binding, expiry, and single-use semantics live in the AEB lifecycle. No separate Challenge revision. |
| `draft-schrock-ep-enforcement-point-00` | AEB-00 | Absorbed. Fail-closed boundary placement, consume-before-effect, invocation, outcome, and reconciliation live in AEB. No separate Enforcement Point revision. |
| `draft-schrock-ep-action-evidence-graph-00` (AEG-00) | AEC-04 | Absorbed. Purpose-relative relying-party requirements and evidence-policy replay become AEC responsibilities. No separate AEG revision. |
| `draft-schrock-ep-architecture-01` | Architecture-02 | Superseded by the same-series revision when -02 is published. |
| `draft-schrock-ep-authorization-receipts-07` | Authorization Receipts-08 | Superseded by the same-series revision when -08 is published. |
| `draft-schrock-ep-authorization-evidence-chain-03` | AEC-04 | Superseded by the same-series revision when -04 is published. |

Same-series revisions supersede older revisions. Until a new revision is
actually published, the posted older revision remains the public historical
and Datatracker truth. A local source file, render, or upload plan is not a
published revision.

## Second wave: held, not abandoned

These documents do not enter the July 27 slate:

| Held document | Second-wave purpose | Release trigger |
| --- | --- | --- |
| Authority Introduction-02 | Tighten trust-root introduction, scoped authority, and authority-status composition after the thin core is coherent | Reconcile terminology with Revocation Statement-00 and AEC-04; no duplicate status semantics |
| Outcome Binding-00 | Define portable action-to-outcome binding beyond AEB's local lifecycle | At least one external outcome format and one executor integration validate the boundary |
| Remedy-00 | Define post-failure or disputed-effect remedy evidence | Named legal, insurer, regulator, or counterparty review; do not infer legal effect from protocol state |
| Model-to-Matter revision | Revise the Experimental physical-executor profile against AEB | A real executor partner or independent implementation evidence; no wet-lab, physical-truth, safety, or endorsement overclaim |

"Held" means second wave with an explicit dependency. It does not mean an
open-ended filing queue, and it does not authorize opportunistic July 27
uploads.

## External-review boundaries the five documents must preserve

- WIMSE workload credentials and WIMSE's HTTP Message Signatures profile own
  workload authentication and end-to-end integrity of covered message
  components. AEB consumes those native results.
- Intermediary-mutable context is routing or diagnostic context, not
  load-bearing authorization evidence. A material field must be derived at the
  effect boundary or covered by accepted end-to-end integrity and exact action
  binding.
- OASNT-like attested per-action tokens and Munoz Permit records remain native
  evidence formats. AEB does not repackage them. AEC-04 composes only their
  native-verifier outputs under relying-party pins.
- Credential revocation or current status is distinct from evidence that a
  particular action was authorized. Neither fills the other's slot.
- A valid signature proves only the signer and covered-statement semantics of
  its native profile. It does not by itself prove human operation,
  comprehension, authority, approval ceremony, or execution.
- Native verification occurs before correlation. CAID matching uses exact
  material fields and exact relying-party-pinned definitions and mapping
  profiles. Unknown, lossy, missing, unpinned, conflicting, or ambiguous input
  fails closed.
- Replay and freshness are separate checks. One-time and bounded authority is
  consumed or reserved atomically before invocation.
- An invocation timeout or lost response is INDETERMINATE, not FAILED. There is
  no blind replay. Only authenticated, action-matched provider or
  system-of-record evidence reconciles the original operation.

## Upload gate

Each of the five sources must clear all of these before any upload decision:

1. RFCXML renders successfully with local `xml2rfc`.
2. `idnits` has no actionable submission blocker; any unavoidable warning is
   recorded with the exact output.
3. Every normative and informative reference names the intended current
   revision and resolves.
4. The abstract, introduction, security considerations, and IANA section all
   preserve the document's claim boundary.
5. AEB-00 creates no receipt, token, universal evidence type, policy language,
   or registry.
6. Architecture-02, Receipts-08, AEC-04, and Revocation Statement-00 use the same
   non-collapsing vocabulary and do not claim another document's role.
7. Replacement mappings are stated consistently in the affected sources and
   private packet notes.
8. Generated TXT and HTML are reviewed from the exact upload source and the
   working tree is checked again for unrelated edits.

Passing this gate makes a source upload-ready. It does not make the source
published, adopted, endorsed, merged, committed, or pushed.
