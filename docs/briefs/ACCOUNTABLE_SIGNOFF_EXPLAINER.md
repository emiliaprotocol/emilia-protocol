# Accountable Signoff vs MFA: Technical Explainer

## Three Approaches to Human Verification

### Multi-Factor Authentication (MFA)

MFA verifies **who is acting**. It confirms identity through multiple factors
(password + device, biometric + token). It does not know what the user is about
to do. A valid MFA session authorizes every action equally. An attacker who
compromises an MFA-authenticated session inherits full session permissions.

**Limitation:** MFA answers WHO. It does not answer WHAT, WHEN, or WHY.

### Generic Human-in-the-Loop (HITL)

Generic HITL asks a human to approve an action. The human sees a description and
clicks approve or deny. The approval is not cryptographically bound to the action
parameters. If the action changes between approval and execution, the approval
still applies. If the approval is captured, it can be replayed.

**Limitation:** HITL answers WHO APPROVED. It does not bind the approval to
EXACTLY WHAT will execute.

### Accountable Signoff (Emilia Protocol)

A named human principal attests to a specific high-risk action under a specific
policy. The attestation is cryptographically bound to the exact action that will
execute. The binding covers all action parameters: recipient, amount, account,
timestamp, policy version.

**Properties:**
- Non-replayable: each signoff is consumed exactly once
- Non-transferable: a signoff for action A cannot authorize action B
- Auditable: the evidence record links WHO approved WHAT under WHICH policy
- Verifiable: any party can verify the binding without trusting the signoff system

## Comparison

| Property | MFA | Generic HITL | Accountable Signoff |
|----------|-----|-------------|---------------------|
| Verifies identity | Yes | Yes | Yes |
| Knows the action | No | Partially | Exact binding |
| Prevents replay | No | No | Yes |
| Prevents transfer | No | No | Yes |
| Audit evidence | Session log | Approval log | Bound attestation record |
| Survives parameter change | N/A | Approval still valid | Invalidated automatically |

## Five Signoff Methods

| Method | Mechanism | Use Case |
|--------|-----------|----------|
| Passkey | FIDO2/WebAuthn hardware or platform key | Highest assurance, phishing-resistant |
| Secure App | Mobile application with push notification | Standard enterprise workflow |
| Platform Authenticator | OS-level biometric (Touch ID, Windows Hello) | Desktop-integrated approval |
| Out-of-Band | Secondary channel (SMS, voice, email token) | Fallback when primary unavailable |
| Dual Signoff | Two named principals each provide independent signoff | Treasury, high-value, regulatory |

All five methods produce the same cryptographically bound attestation record.
The method determines the authentication factor, not the binding strength.

## When Signoff Is Required

Signoff requirements are **policy-driven**, not blanket.

- **Low-risk actions** flow through without human intervention. Policy evaluates
  the action and permits execution automatically.
- **High-risk actions** require one or more named human signoffs before execution
  proceeds. Risk classification is based on action class, parameters, and context.
- **Thresholds are configurable** per action class. Organizations set their own
  boundaries for what constitutes high-risk in their environment.

Example: a payment below $1,000 to a known beneficiary flows through. A payment
above $50,000 to a new beneficiary requires dual signoff.

## What Accountable Signoff Proves

For every signoff-required action, the evidence record answers:

| Question | Evidence Field |
|----------|---------------|
| **WHO** owned the decision? | Named principal identity, authentication method |
| **WHAT** did they approve? | Cryptographically bound action parameters |
| **WHEN** did they approve? | Timestamp with anti-replay nonce |
| **Under WHAT policy?** | Policy version, rule evaluated, risk classification |

This evidence is generated automatically. It does not depend on the signoff
principal writing a justification or the system operator configuring logging.
