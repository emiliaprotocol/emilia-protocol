# DMSC action-level authorization contribution

Status: proposed text for discussion on `dmsc@ietf.org`

Source reviewed: [`draft-dunbar-dmsc-gw-scenarios-gap-analysis-02`](https://datatracker.ietf.org/doc/html/draft-dunbar-dmsc-gw-scenarios-gap-analysis-02), 2 July 2026

Scope: Sections 6.9 and 7.7; no claim of DMSC adoption

## Proposed addition to Section 6.9

Where local policy requires human supervisory approval, an Agent Gateway needs
a mechanism to receive, carry, or reference evidence that identifies the
approving subject and binds the approval to the specific action and its material
parameters. The receiving Gateway remains the enforcement point. It evaluates
the evidence against locally configured trust anchors, the current action
context, and local policy before permitting execution. A statement by the
sending agent or Gateway alone is not sufficient to establish the approval.

Approval evidence and the receiving Gateway's enforcement decision are distinct
artifacts. The approval evidence records who approved which action under which
policy. The enforcement record identifies the policy and contextual inputs the
Gateway evaluated and records its allow or refuse decision. Keeping these
artifacts separate permits another party to verify the approval independently
and, when the policy and inputs are available, reproduce the Gateway's decision.
Neither artifact by itself establishes that the physical action occurred or
that its observed outcome was correct.

In a cross-domain deployment, the receiving Gateway may accept approval
evidence inline or by digest reference. In either case, the protocol needs to
bind the evidence to the exact action, identify the evidence type and trust
anchor, and carry sufficient freshness, expiry, revocation, and policy context
for the receiving Gateway to evaluate it. A missing referenced artifact, a
binding mismatch, unavailable required trust state, or an indeterminate
one-time-consumption result needs to produce a refusal rather than fallback to
the sending Gateway's assertion.

For actions intended to execute at most once, a fresh action-bound challenge
and atomic consumption state prevent the same approval from authorizing a
different action or a second execution. The challenge is not itself permission
to act; satisfying it only supplies evidence to the Gateway's local policy
decision.

## Proposed replacement for the standardization candidate in Section 7.7

**Standardization candidate:** A common model for action-level authorization
evidence and its use at an Agent Gateway, distinct from session- or
request-level trust. The model should enable a receiving Gateway to:

1. identify the exact physical-world action and material parameters being
   evaluated;
2. receive or reference evidence of any required human supervisory approval;
3. verify that evidence under the receiving Gateway's own trust configuration,
   rather than relying solely on an assertion by an intermediate agent or
   Gateway;
4. evaluate spatial, temporal, approval, risk, freshness, and revocation inputs
   under local policy;
5. refuse missing, mismatched, stale, revoked, replayed, or unverifiable
   evidence with a structured reason; and
6. record a separate, reproducible enforcement decision without treating that
   decision as proof of physical execution or sensor truth.

The work should profile existing identity, authorization, signature, and
evidence mechanisms where they satisfy these requirements instead of defining
new cryptography. A gateway-to-gateway protocol may carry the evidence inline
or carry a content digest and retrieval information, but the binding between
the evidence, action, and policy must survive the administrative-domain
handoff.

## Running composition

The repository includes an executable example at
`examples/cross-gateway/dmsc-physical-action.mjs`. It demonstrates:

* Gateway B computing the concrete action and issuing an action-bound challenge;
* Gateway A carrying, but not vouching for, Class-A human-authorization evidence;
* Gateway B verifying under its own pinned trust material and policy;
* a separate signed reliance decision;
* one-time consumption; and
* offline re-performance plus refusal of missing or revoked approval, expired
  challenges, storage outage, action substitution, unpinned issuer keys,
  replay, and evidence mutation.

Run:

```bash
node examples/cross-gateway/dmsc-physical-action.mjs
```

The gateway carrier is illustrative. The example does not propose a DMSC wire
format, does not require every action to receive human approval, and does not
claim that authorization evidence proves physical truth.
