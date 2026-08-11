# DMSC action-level authorization contribution

Status: proposed coauthor contribution text; not a DMSC working-group
document and not a Datatracker upload packet

Source reviewed: public
[`draft-dunbar-dmsc-gw-scenarios-gap-analysis-03`](https://datatracker.ietf.org/doc/draft-dunbar-dmsc-gw-scenarios-gap-analysis/),
6 August 2026

Scope: proposed mechanism-neutral text for Sections 7.7 and 8. This note does
not edit the coauthors' draft source, claim DMSC adoption, define a DMSC wire
format, transfer admission ownership, or solve cross-gateway double admission.

## Proposed text for Section 7.7

The following text is proposed as a replacement for the current
"Standardization candidate" paragraph. The scenario and gap paragraphs that
precede it in `-03` remain unchanged.

> **Standardization candidate:** A mechanism-neutral interoperability profile
> for carrying and evaluating action-bound authorization evidence at a
> receiving Agent Gateway. The profile should identify the exact action and
> every material parameter under a pinned action representation; identify the
> evidence type, issuer, audience, trust-anchor requirements, and applicable
> policy; carry or reference the evidence; express required freshness, expiry,
> and status constraints; and define deterministic refusal behavior for
> missing, mismatched, stale, revoked, replayed, or unverifiable evidence. The
> receiving Gateway evaluates the evidence under its own trust anchors and
> local policy. Identity systems, policy languages, gateway transports,
> evidence-generation mechanisms, and physical-effect verification remain
> outside this profile.
>
> When a receiving Gateway refuses an action because required authorization
> evidence is missing, stale, or unverifiable, it may issue an Authorization
> Evidence Challenge [AE-CHALLENGE]. The challenge identifies the exact action,
> the outstanding evidence requirements, applicable freshness or status
> constraints, and supported presentation profiles. It is a refusal with
> information. It does not authorize the action, transfer admission ownership,
> reserve or consume authority at an executor, or establish that a later
> presentation will be admitted.
>
> A challenge exchanged during gateway handoff or federation communicates what
> the receiving Gateway requires; it does not establish exclusive authority
> between gateways. In particular, challenge authentication and single-use
> presentation state do not prevent two independently operated gateways from
> admitting the same underlying authority. Conserved admission across gateway
> boundaries requires a separate mechanism that establishes one authoritative
> admission owner or otherwise proves exclusivity. If that condition is
> required but cannot be established, the receiving Gateway does not admit the
> action.

The exact-action identifier can be supplied by any profile that covers every
material field and is pinned by the receiving Gateway. CAID [CAID] is one
informative example. An authorization receipt [AUTH-RECEIPTS] is one possible
human-approval evidence type, not a required evidence format. The Action
Evidence Boundary [AEB] is an informative example of keeping native evidence
verification, action matching, local authorization, admission state, and
effect reconciliation separate.

## Proposed text for Section 8

> ## 8. Security Considerations
>
> Agent Gateways operate at administrative, policy, and often physical-effect
> boundaries. Authentication of an agent or peer Gateway establishes the
> authenticated party's identity under the selected mechanism. It does not by
> itself establish that a particular action is authorized. A receiving Gateway
> evaluates the action, evidence, and current policy under its own trust
> configuration before admitting an action.
>
> **Compromised or unauthorized evidence issuers.** Cryptographic verification
> establishes that an artifact was protected by a particular key; it does not
> establish that the signer was authorized to issue that evidence for the
> action, audience, role, or time in question. A receiving Gateway pins
> acceptable issuers or trust anchors by evidence type and purpose, validates
> issuer authority and key status where required, and refuses evidence from an
> untrusted, unauthorized, or compromised issuer. Trust material received from
> the presenter must not silently replace the receiving Gateway's configured
> trust anchors.
>
> **Stale, expired, or revoked evidence.** Freshness, validity interval, and
> revocation are separate checks. The receiving Gateway evaluates each against
> an authoritative local time source and the status mechanism required by its
> policy. An expired artifact, a stale observation, or affirmative revocation
> is not acceptable. When required status or freshness information is
> unavailable or cannot be authenticated, the result is INDETERMINATE rather
> than valid. An INDETERMINATE result must not be converted to authorization by
> assuming that the last known state remains current.
>
> **Action substitution and mapping.** The receiving Gateway derives the action
> to be admitted from the request and its own target-side context. It does not
> copy an action identifier supplied only by the presenter. The selected action
> profile covers every field whose change can alter authorization, target or
> resource selection, provider input, or an externally observable effect.
> Gateways compare both the profile identifier and the resulting action digest.
> A handoff transformation, protocol translation, or local command mapping that
> cannot establish equivalence under an agreed and pinned mapping causes
> refusal, not best-effort substitution.
>
> **Replay and one-time use.** Challenge replay protection, evidence replay
> protection, and executor admission are distinct state machines. A single-use
> challenge prevents reuse of one evidence-presentation attempt; it does not by
> itself consume an authorization or reserve an external effect. If policy
> requires one-time admission, the authoritative admission domain atomically
> reserves or consumes that right before entering the protected executor path.
> State unavailability must not be reported as successful admission, and a
> replay result must be returned only when authoritative state actually
> establishes replay.
>
> **Split authority domains and cross-gateway double admission.** An
> authenticated challenge, evidence presentation, or sending-Gateway decision
> does not transfer an admission ledger. If two gateways can independently
> admit the same authority without one shared authoritative admission domain,
> deterministic ownership partition, or separate exclusivity protocol, both
> can admit it. This document does not solve that condition. A deployment that
> requires conserved admission across independently operated gateways must use
> a separate mechanism that proves which domain owns the admission right. When
> the receiving Gateway cannot establish the required ownership or reach its
> authoritative owner, it refuses or reports INDETERMINATE; it does not treat
> the condition as replay or as permission to proceed.
>
> **Sending-Gateway decisions.** A sending Gateway's allow decision is an input
> to audit or policy evaluation, not authorization for the receiver. The
> receiving Gateway independently verifies the evidence it requires, derives
> the exact action, applies its own policy, and creates its own decision record.
> A sender's decision, capability advertisement, or assertion must not replace
> evidence or local checks required by the receiver.
>
> **Uncertain effects and reconciliation.** Authorization, admission, provider
> entry, and physical effect are separate events. If a Gateway admitted an
> action and entered a provider or actuator boundary but cannot determine
> whether the effect occurred, it records an INDETERMINATE outcome. It does not
> silently retry the action or release single-use authority as though no
> attempt occurred. Reconciliation requires authenticated outcome evidence
> bound to the same action, provider, and operation under a deployment-defined
> profile. A compensating or remedial action requires its own authorization.
> AEB [AEB] describes one example of this separation.
>
> **Audit-record limits.** Signed or tamper-evident records can support
> correlation and later verification of recorded bytes. They do not by
> themselves prove that source claims were true, that all relevant events were
> recorded, that local policy was correct, or that a physical effect occurred.
> Deployments keep evidence verification, local authorization, admission,
> provider entry, and observed outcome as distinguishable records.
>
> **Confidentiality and denial of service.** Authorization evidence and
> challenges can disclose identities, intended actions, capabilities, policy
> identifiers, or operational state. Gateways minimize disclosed fields,
> authenticate peers before disclosing sensitive evidence, protect references
> and retrieval channels, and apply appropriate transport confidentiality.
> Challenge issuance and verification also consume storage and cryptographic
> resources. Implementations bound message size, evidence count, outstanding
> state, lifetime, and retry rate, and fail closed when security-relevant state
> cannot be stored or reached.

## Informative reference candidates

These references identify existing work that illustrates parts of the proposed
profile. They are not DMSC requirements, working-group adoption, or evidence
that the DMSC draft depends on EMILIA.

- **[AE-CHALLENGE]** I. Schrock, "An Authorization Evidence Challenge for
  High-Risk Agent Actions,"
  [`draft-schrock-ae-challenge-07`](https://datatracker.ietf.org/doc/draft-schrock-ae-challenge/),
  work in progress.
- **[CAID]** I. Schrock, "The Canonical Action Identifier (CAID),"
  [`draft-schrock-canonical-action-identifier-02`](https://datatracker.ietf.org/doc/draft-schrock-canonical-action-identifier/),
  work in progress.
- **[AUTH-RECEIPTS]** I. Schrock, "Authorization Receipts for High-Risk Agent
  Actions,"
  [`draft-schrock-ep-authorization-receipts-11`](https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-receipts/),
  work in progress.
- **[AEB]** I. Schrock, "The Action Evidence Boundary for Consequential Agent
  Effects,"
  [`draft-schrock-action-evidence-boundary-03`](https://datatracker.ietf.org/doc/draft-schrock-action-evidence-boundary/),
  work in progress.

## Existing executable case

The repository already contains the executable example
`examples/cross-gateway/dmsc-physical-action.mjs` and its focused regression in
`tests/dmsc-physical-action.test.ts`.

Run:

```bash
node examples/cross-gateway/dmsc-physical-action.mjs
npx vitest run tests/dmsc-physical-action.test.ts
```

The example demonstrates that Gateway B derives the concrete action, issues an
action-bound challenge, verifies carried human-authorization evidence under
its own pinned trust material and policy, and refuses missing or revoked
evidence, an expired challenge, unavailable challenge state, action
substitution, an unpinned issuer, challenge replay, and a second clearance for
an already consumed action. It also verifies a separate decision bundle and
refuses a tampered bundle.

The example uses one single-process memory-backed authority domain. It does not
exercise independently operated admission domains, establish conserved
admission across gateways, execute a physical effect, or prove physical or
sensor truth. It therefore supports the local action-binding and refusal cases
only, not a cross-domain double-admission claim.
