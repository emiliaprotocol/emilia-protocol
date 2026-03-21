# Why EP

Identity is not authorization. Authentication is not action control.

Most damaging fraud and abuse occurs inside approved-looking workflows: authenticated users, valid sessions, legitimate access, weak action-level constraints.

**EMILIA Protocol (EP)** closes that gap by enforcing trust before high-risk action. It binds actor identity, authority chain, action parameters, policy version and hash, nonce, expiry, and one-time consumption into a single replay-resistant authorization flow. The action does not execute until the handshake is verified and consumed.

## The problem

Most systems answer:
- who is acting?
- what broad permissions do they have?

Far fewer systems answer:
- should this exact high-risk action be allowed?
- under this exact policy?
- under this exact authority chain?
- with protection against replay and reuse?
- with immutable evidence if something goes wrong later?

EP is designed to answer those questions.

## The result

EP creates a trust-control layer between authentication and execution. It is built for:
- government fraud prevention
- banking and payment-change controls
- high-risk enterprise approvals
- agent execution governance

That is the category EP should now own: **trust before high-risk action**.
