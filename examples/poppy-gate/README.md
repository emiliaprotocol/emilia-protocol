<!-- SPDX-License-Identifier: Apache-2.0 -->
# Poppy Operations with EMILIA Gate

Let a personal agent propose the work. Apply the company's authority at the
system that performs it. Keep evidence that a reviewer can check.

This is an **EMILIA-authored integration candidate** for Personal Agent Protocol
Draft 0.1 and its Operations v1 extension, both read on October 12, 2026.
It is not a complete Poppy implementation, a deployment, an endorsed extension,
or independent interoperability evidence.

## Run the reference

From a repository checkout with its dependencies installed:

```sh
node --test examples/poppy-gate/*.test.mjs
node examples/poppy-gate/demo.mjs
```

The demo is offline. It uses throwaway cryptographic keys, synthetic authenticator
assertions and a mock business provider. No money moves and no customer account
is contacted. A passing test does not establish a genuine device ceremony.
The synthetic session authority verifies signed tokens, key-bound DPoP requests
and replay refusal in process; it is not an OAuth authorization-server deployment.

## What this adds

Poppy already defines revision-specific approval, at-most-once operations and
keeping unknown outcomes in progress. This example implements those requirements
through the existing Gate. It does not claim to have discovered missing approval
or retry semantics.

Poppy Operations section 8 says a confirmation records the personal agent's
approval statement; it does not establish that the user made that decision.
The optional `emiliaprotocol.ai/approval-evidence` profile lets a company require
an existing EP Class-A authorization artifact for selected operations. It binds
that artifact to the company's exact operation revision and terms. It does not
prove human comprehension, honest screen pixels or business correctness.

The operation adapter and approval verifier have different jobs:

- `operations.mts` owns Poppy's operation lifecycle and calls the configured Gate.
- `evidence.mts` verifies existing EP evidence under company-pinned inputs.
- `demo-auth.mts` supplies the deliberately synthetic local token/DPoP authority.
- Gate separately checks its native authority record, reserves before provider
  entry and preserves uncertainty after an attempted effect.
- The provider's result remains its account of the outcome, not physical truth.

Nothing in the optional profile makes `approved_by: "user"` a cryptographic proof.
Native standing permission remains available when the company's selected profile
allows it. The stronger fresh-human profile does not turn standing permission
into a fresh ceremony.

## Integration boundary

The hosting company supplies and owns:

1. Poppy discovery, client metadata, session issuance and OAuth authorization.
2. The native token/DPoP verifier used by `authenticateRequest`. The adapter does
   not infer authentication from headers or a caller-supplied principal.
3. A reviewed resolver from immutable operation terms to executor-owned action
   facts, required scopes and the existing Gate's authority policy.
4. Durable, locally atomic operation and Gate-consumption stores shared by all
   workers, plus the required evidence log and protected credential-owning adapter.
5. Authenticated provider reconciliation and operational monitoring.

The stronger verifier also pins one owner-to-approver-profile association at
construction. A multi-account host must select the correct preconfigured verifier
through its own authenticated routing, not trust a request-carried profile.

Confirmation responses wait at most 2.5 seconds by default. Admitted work that
has not finished returns `in_progress`; the service continues the admitted job
without starting another attempt. Process recovery must reconcile the persistent
operation rather than take over its effect. In-progress cancellation here has no
provider stop capability: it reports the existing state, not a fictional rollback.

The memory operation store and ephemeral Gate are explicitly test-only. They are
not a production persistence option. Token signatures, a durable-store flag or
this demo alone do not prove a correct deployment.

## Read next

- [Optional evidence profile](PROFILE.md)
- [Source and requirement map](SOURCES.md)
- [Poppy Operations specification](https://personalagentprotocol.org/docs/extensions/operations)
- [Poppy core specification](https://personalagentprotocol.org/docs/spec)

No new IETF submission, registered protocol name, standardized payment rail,
Poppy design-partner membership or exclusive capability is claimed.
