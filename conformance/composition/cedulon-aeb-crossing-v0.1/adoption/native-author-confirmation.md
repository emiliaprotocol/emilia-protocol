# Native-author semantic confirmation

This checklist asks whether the pinned profile preserves Cedulon's intended
meaning. It is not a request to certify EMILIA, approve a deployment, validate
the independent adapter implementation, or endorse any security claim.

Please mark each item **confirmed**, **correction needed**, or **not within my
review**, and add exact replacement text where useful.

| Item | Proposed interpretation | Response / correction |
| --- | --- | --- |
| Reviewed source | The profile is scoped to `draft-dogru-cedulon-04`, the annotated Cedulon `v0.7.0` tag at `4a5eab26dde9edbd71db01f6253cc0a7aff72a37`, and the package integrities in `../source-lock.json`. | |
| Artifact role | A Decision Token is pre-settlement machine-policy evidence. It is not human approval, provider-entry authorization, a Spend Receipt, or proof of settlement. | |
| Exact request | `requestHash` covers `amount`, `currency`, `payee`, `tool`, `nonce`, and `manifestHash`; changing any one changes the request being evaluated. | |
| Mapping | Those six fields map by exact copy to `cedulon.payment.attempt.1`, with `manifestHash` represented as `manifest_hash`. | |
| Narrow subset | This v0.1 profile withholds acceptance when `tool` or `manifestHash` is null instead of inventing a sentinel that Cedulon did not sign. | |
| Trust | The consumer pins the PDP issuer key outside the presented token. A token-carried key is not treated as a trust root. | |
| COSE strictness | The profile requires the actual COSE_Sign1 unprotected map to be empty, in addition to checking the protected headers and signature. | |
| Status | Revoked or consumed decisions are rejected. Unavailable, unchecked, or stale status withholds acceptance. The profile does not claim Cedulon defines the authenticated status service used by a deployment. | |
| Replay identities | `singleUseId` and `nonce` are distinct native identities. A production consumer must enforce both independently and atomically in an issuer-and-deployment namespace. Cedulon's allow is consumed on the first settlement attempt, including a fail-closed abort. | |
| Terminal consumption | Neither replay identity becomes reusable after `EXECUTED`, `NOT_ENTERED`, or `INDETERMINATE`. Reconciliation may establish the outcome but never restores the consumed Decision Token. A retry requires a newly issued Decision Token with fresh identities. | |
| Audience | The pinned Decision Token does not itself carry a relying-party audience. This profile is limited to one configured consumer/PDP trust domain and does not manufacture cross-domain audience binding. | |
| Limits | A passing profile does not prove payment execution, settlement, finality, rail completeness, human approval, authorization, production deployment, certification, or general protocol security. | |

Reviewer name:

Affiliation (optional):

Cedulon source revision reviewed:

Date:

Corrections or additional limits:

Confirmation method (email, signed note, pull-request review, or other):
