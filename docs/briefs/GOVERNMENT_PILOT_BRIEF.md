# Government Pilot Brief: Emilia Protocol

## Problem

Fraud inside government systems increasingly executes through approved-looking workflows.
Payment destination changes, benefit redirects, and operator overrides proceed with
valid credentials through authenticated sessions. Existing controls verify identity
but not whether the specific action should proceed. The result: fraudulent transactions
that pass every auth check and leave no distinguishing audit trail.

## What Emilia Protocol Does

EP is an open authorization protocol for high-risk actions. It operates after
authentication and before execution:

1. **Action Binding** -- Cryptographically binds authorization to the exact action
   (recipient, amount, account, timestamp). Authorization cannot be transferred to
   a different action.
2. **Policy Enforcement** -- Evaluates each action against configurable policy rules.
   Low-risk actions flow through. High-risk actions require named human signoff.
3. **Replay Prevention** -- Each authorization token is consumed exactly once.
   Captured tokens cannot be reused.
4. **Accountable Signoff** -- When policy requires human approval, a named principal
   attests to the specific action under a specific policy. The attestation is
   cryptographically bound, non-transferable, and non-replayable.
5. **Evidence Generation** -- Every decision produces a tamper-evident record:
   who authorized, what was authorized, when, under what policy, and whether
   signoff was required and obtained.

## Recommended First Workflow

**Payment destination change in a benefits disbursement system.**

This is the highest-fraud-risk action in most benefits systems. A destination change
redirects all future payments. EP wraps this single action class:

- Binds authorization to the exact new destination account
- Enforces dual signoff for changes above a configurable threshold
- Prevents replay of a captured change authorization
- Generates per-change evidence records

No changes to the benefits application logic. EP integrates at the API layer.

## What the Pilot Proves in 30 Days

| Week | Milestone |
|------|-----------|
| 1    | Integration with payment destination change endpoint |
| 2    | Policy configuration, signoff workflow activation |
| 3    | Red team exercise: attempt replay, credential reuse, context manipulation |
| 4    | Evidence review with IG/GAO-grade audit trail |

**Primary finding:** EP catches approved-looking fraud that ordinary authentication
and role-based access control miss. Every blocked action and every approved action
produces evidence sufficient for Inspector General or GAO review.

## Proof Points

| Metric | Value |
|--------|-------|
| Automated test cases | 1,511 |
| TLA+ formal verification theorems | 19 |
| Red team attack scenarios | 85 |
| Write discipline exceptions in codebase | 0 |

The protocol is formally verified against replay, context manipulation, token reuse,
and signoff bypass. Red team scenarios cover credential theft, session hijacking,
insider override, and social engineering of approval workflows.

## Next Step

Request a 30-day pilot deployment:

**emiliaprotocol.ai/partners**

Includes integration support, policy configuration, and evidence review.
