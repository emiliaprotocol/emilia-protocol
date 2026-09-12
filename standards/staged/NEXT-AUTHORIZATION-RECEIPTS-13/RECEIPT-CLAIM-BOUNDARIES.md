# RECEIPTS-13 CANDIDATE: consolidated receipt claim boundaries

STATUS: STAGED, NOT FILED. This is working text for a possible future
`draft-schrock-ep-authorization-receipts-13`. Revision -12 was the current
published revision when this text was checked on 2026-09-11. Check the live
Datatracker record before assigning a revision number or filing it. This text
is not an RFC, an adopted working-group document, IETF consensus, or IETF
endorsement.

Intended placement: Security Considerations, as a short consolidated boundary
subsection. The current -12 already states the identity boundary in Sections
1.2, 5.2, and 13.7, and the presentation boundary in Sections 4.1 and 13.4.
This candidate does not replace those sections. It gives a reader one place to
find the residual claims that must not be inferred from successful receipt
verification.

## 13.X. What successful verification does not establish

A successfully verified receipt establishes the claims of the selected
verification profile over the supplied artifact and relying-party trust
inputs. It does not, by itself, establish any of the following:

* that the approved decision was wise, correct, lawful, safe, or successful;
* that the policy was adequate for the action;
* that an approver was uncoerced or that distinct enrolled identifiers denote
  distinct natural persons;
* that the signing surface faithfully rendered the Action Object to the
  approver;
* that an approver identifier denotes a particular natural person beyond the
  binding asserted by the independently trusted directory and identity layer;
* that the named approver personally authorized enrollment of the signing key;
* that the artifact is currently unrevoked, globally unconsumed, or acceptable
  under the relying party's current policy; or
* that the action was executed or produced the claimed external effect.

The verifier and relying party MUST NOT promote any of those properties from a
successful receipt-verification result. Deployments that require one of them
need separate evidence, controls, or online state selected by the relying
party. In particular, presentation evidence can bind profile-defined display
bytes to the signed action, but a compromised physical display path remains
outside the cryptographic claim. Directory evidence can bind a key to an
approver identifier, but the strength of the identifier-to-person mapping is a
property of the selected directory and identity-proofing layer.

## Assembly check

Before this text is assembled into a future revision:

1. compare every bullet with the then-current Scope, Enrollment,
   Pre-Execution Verification, Offline Verification, and Security
   Considerations sections;
2. preserve the stronger existing normative requirements rather than replacing
   them with this summary;
3. update section references only after the XML is assembled; and
4. verify the rendered text and Datatracker revision independently before
   describing it as published.
