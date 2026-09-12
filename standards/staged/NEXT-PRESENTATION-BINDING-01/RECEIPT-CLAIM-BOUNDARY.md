# PRESENTATION-BINDING-01 CANDIDATE: receipt claim boundary

STATUS: STAGED, NOT FILED. This is working text for a possible future
`draft-schrock-ep-presentation-binding-01`. It has not been submitted to the
IETF and is not an RFC, an adopted working-group document, IETF consensus, or
IETF endorsement.

Intended placement: Security Considerations, beside the residual presentation
risk. It records the composition boundary with the authorization-receipt draft
without claiming that presentation evidence proves what a physical display
showed.

## Receipt evidence and presentation evidence remain distinct

Verification of an authorization receipt proves that the enrolled key signed
the exact covered Authorization Context under the selected receipt profile. It
does not prove that the signing surface faithfully rendered that context to the
approver. Presentation evidence narrows this gap only to the extent stated by
its own profile: it can bind deterministic or attested display bytes to the
same action, but it cannot prove that an uncompromised human perceived those
bytes or that a compromised physical display path showed them faithfully.

A relying party MUST evaluate receipt verification and presentation-evidence
verification as separate results under independently selected trust inputs. A
valid receipt MUST NOT be promoted to presentation-accepted merely because its
signature verifies, and valid presentation evidence MUST NOT be promoted to
authorization merely because its display binding verifies.
