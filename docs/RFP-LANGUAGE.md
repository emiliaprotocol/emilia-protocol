<!-- SPDX-License-Identifier: Apache-2.0 -->
# RFP and procurement language for human-authorization evidence

**Status:** buyer enablement. Copy-paste requirement language a purchasing organization can
put into an RFP, a vendor security questionnaire, or a contract when it wants to require that
high-risk automated actions carry independently verifiable proof of human authorization. The
clauses are written to be **capability requirements, not brand requirements**: they describe
the property, so more than one vendor can answer and the buyer is not locked in. EMILIA meets
every clause with running code, but the clauses never name EMILIA.

Adapt freely. Delete verticals you do not need. Strike any clause your risk owner does not
want. These are drafting aids, not legal advice.

## Core requirement (use in any vertical)

> **Human-authorization evidence for high-risk actions.** For each action class the buyer
> designates as high-risk, the system SHALL, before the action executes, produce a signed
> authorization artifact that binds a named, accountable human's approval to the exact
> parameters of that action. The artifact SHALL be verifiable by the buyer, an auditor, or a
> regulator **offline**, against a key the verifier has pinned, **without any call back to the
> vendor's infrastructure**. Absence of a valid artifact SHALL cause the action to be refused
> before execution, not logged after it.

> **Non-repudiation and replay.** A valid artifact SHALL be bound to a single action instance
> such that it cannot be replayed to authorize a second action, and an artifact valid for one
> action SHALL NOT verify against a different action.

> **Independence from the vendor's continued operation.** The buyer SHALL be able to verify
> historical authorization artifacts using only the published verification algorithm and pinned
> keys, with no dependency on the vendor remaining in business or reachable.

## Financial services (payments, wire, treasury, trading)

> For payment-destination changes, new-beneficiary additions, wire transfers above
> $[THRESHOLD], and any action that would trigger regulatory reporting, the system SHALL require
> a fresh, named-human authorization artifact bound to the amount and counterparty, satisfying
> the dynamic-linking property (the approved amount and payee cannot change after approval
> without invalidating the artifact). The artifact SHALL be retained as dispute and
> examination evidence and SHALL be independently verifiable by the buyer's fraud, audit, and
> compliance functions.

*Maps to: PSD2 SCA dynamic linking; SEC Rule 15c3-5 pre-trade controls; DORA Art. 9.*

## Government disbursement and benefits

> For benefit payment-destination changes, grant releases, vendor-payment changes, and
> operator overrides, the system SHALL produce an authorization artifact naming the accountable
> official and bound to the exact disbursement parameters, verifiable offline by the agency's
> Inspector General or GAO without access to the vendor's systems. The artifact SHALL
> distinguish an operator-asserted action from a device-verified human approval.

*Maps to: improper-payment controls; GAGAS / Green Book; NIST AI RMF.*

## Healthcare and life sciences

> For medication changes, controlled-substance actions, release of protected health
> information outside a standing scope, and any command to an AI-enabled medical device, the
> system SHALL produce an authorization artifact naming the accountable clinician and bound to
> the exact action, retained as an audit record and independently verifiable. The artifact
> SHALL support a distinct-human, multi-party approval where the buyer's policy requires it.

*Maps to: HIPAA audit controls; FDA human-oversight expectations for AI/ML-enabled devices.
The system supplies the authorization evidence; it does not make clinical or safety judgments.*

## Critical infrastructure and OT

> For safety-critical control actions the buyer designates (setpoint changes, protective
> disables, cross-segment commands), the system SHALL require a named-human authorization
> artifact bound to the exact command, verifiable offline by the operator and by regulators.
> The requirement SHALL NOT gate a safety function: a missing or refused authorization artifact
> SHALL NOT delay or block a safety interlock.

*Maps to: NERC CIP; IEC 62443. Authorization is gated; safety is never gated on authorization.*

## AI agents and autonomous systems (any vertical)

> Where an autonomous or semi-autonomous agent can take an action the buyer designates as
> high-risk, the agent SHALL be unable to execute that action on its own session authority
> alone. Execution SHALL require a fresh human-authorization artifact that the agent can
> present but cannot itself produce, bound to the exact action, and independently verifiable.
> A compromised or prompt-injected agent SHALL be able to request, but not to forge, the
> artifact.

## Vendor security questionnaire items

- Does the product produce a signed, per-action human-authorization artifact bound to the
  exact action parameters? (Y/N; describe)
- Can that artifact be verified offline, against pinned keys, with no callback to your
  infrastructure? (Y/N; provide the verification tool)
- Is the verification algorithm publicly specified and independently implementable? (Y/N;
  provide the specification)
- Are conformance test vectors (accept and refuse) published for the verifier? (Y/N; link)
- Does an invalid or absent artifact cause refusal before execution? (Y/N; describe)
- Is the artifact bound to a single action instance to prevent replay? (Y/N; describe)

## How EMILIA answers (for the vendor's own bid response, not the RFP)

Every clause above is met by the filed EMILIA Internet-Drafts and their public reference
verifiers (JavaScript, Python, Go) with published accept/refuse vectors. The verification
tool for the questionnaire is `@emilia-protocol/verify` (offline, Apache-2.0); the
specification is `draft-schrock-ep-authorization-receipts` and companions; the conformance
vectors are in the public repository. EMILIA is the authorization-evidence layer only; it
does not assert identity proofing, does not run the audit, and does not make domain judgments.
