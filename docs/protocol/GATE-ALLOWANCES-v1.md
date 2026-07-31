# Gate Allowances v1

## Status and scope

`EP-GATE-ALLOWANCE-v1` is an experimental Gate profile for unattended execution
inside one customer-signed, time-bounded envelope. The public implementation
ships three deliberately narrow typed connector profiles:

- Stripe payout: `stripe:<account-id>` / `stripe.payout.create`
- GitHub production workflow dispatch:
  `github:installation:<installation-id>` / `github.workflow.dispatch`
- Supabase RLS policy replacement:
  `supabase:project:<project-ref>` / `supabase.rls.change`

Each adapter derives a closed action from its typed input and pins the signed
connector instance to identity read from the configured provider client:
Stripe retrieves the authenticated account, GitHub calls the authenticated
installation endpoint, and Supabase parses the project reference from the
configured project URL. An action caller cannot pair an arbitrary client with
a separately asserted connector identifier. Stripe uses monetary amounts.
GitHub and Supabase use one occurrence unit per admitted mutation; they are not
represented as money.

Across the profiles:

- exact material fields are closed—extra or omitted fields refuse;
- target control uses a closed allowlist;
- optional exact-value allowlists for any other material field used by a typed
  connector
- amount controls provide one per-action ceiling and one aggregate capability
  budget in the profile's declared denomination
- time control: one `valid_from` / `expires_at` period

An allowance is not an unrestricted approval and is not a substitute for the
authorizing receipt. The signed allowance binds the authorizing receipt digest,
the customer and agent context, the audience, the reviewed presentation digest,
the connector instance and action type, the exact field selectors, the target
allowlist, the amount limits, one capability identifier and issuer-key digest,
and the validity window.

The implementation claim boundary is:

```text
one_bounded_period_and_typed_connector_not_recurring_schedule_generic_tool_safety_or_complete_mediation
```

## Security boundary

Gate Allowances use two deliberately separate planes.

### Local execution plane

The customer-run Gate process:

1. holds provider credentials;
2. verifies the signed allowance and its exact relying-party context;
3. verifies current allowance status through a deployment-pinned status source;
4. verifies the bound authorizing receipt through a caller-supplied verifier;
5. constructs one typed connector action;
6. atomically reserves the amount and operation identifier;
7. calls the local provider client; and
8. commits `executed` or `indeterminate`.

The provider client is passed directly to its typed wrapper. Credentials remain
in that process or its customer-controlled sidecar. They are not fields in the
allowance, capability, receipt, or hosted approval messages.

### Hosted coordination plane

A future hosted approval plane may route intent summaries, proposed allowance
changes, passkey-backed decisions, policy synchronization, and receipt custody.
It MUST NOT receive Stripe API keys, provider access tokens, database
credentials, or direct authority to invoke the provider.

There is no production hosted allowance service in this release.

## Artifact and capability binding

`issueGateAllowance()` produces two bound artifacts:

1. a customer-signed `EP-GATE-ALLOWANCE-v1` artifact; and
2. an `EP-CAPABILITY-RECEIPT-v1` monetary capability.

The capability scope uses `EP-CAPABILITY-ALLOWANCE-SCOPE-v1` and binds:

- a tenant-scoped allowance-lineage identifier;
- the digest of the complete signed allowance;
- the single capability identifier and capability-issuer key digest;
- the operation-ID field;
- the aggregate amount and currency; and
- the allowance expiry.

The signed allowance permits exactly one root capability envelope. Re-registering
the byte-identical envelope is idempotent; a different envelope under the same
capability identifier is refused by the atomic capability store. Delegation is
not permitted in v1.

The capability also binds the exact authorizing receipt bytes. Issuance does
not itself establish that the receipt is trustworthy. Every execution requires
the relying party's `verifyAuthorizationReceipt` callback and a
`verifyAllowanceStatus` callback proving that this signed allowance revision is
still the locally accepted one.

## Admission and execution

For a Stripe payout, the adapter constructs exactly:

```json
{
  "action_type": "stripe.payout.create",
  "amount": 2500,
  "currency": "USD",
  "destination": "acct_known_a",
  "operation_id": "payout:2026-07-30:0001"
}
```

Gate refuses before provider entry when:

- the signature, validity window, tenant, subject, audience, connector instance,
  authorizer, or allowance identifier does not match;
- no deployment-pinned current-status verifier is available, or the allowance
  is suspended, revoked, or superseded;
- the authorizing receipt is missing, substituted, or rejected;
- the capability identifier, issuer key, root delegation state, or profile does
  not bind the signed allowance exactly;
- the action has a missing or extra material field;
- the action type or operation identifier does not match;
- the amount is invalid or exceeds the per-action ceiling;
- the currency differs from the allowance;
- the destination is not allowlisted;
- the operation identifier was already reserved or committed; or
- the aggregate budget cannot cover the new reservation.

The capability store linearizes concurrent reservations. Two operations cannot
both spend the same remaining budget. Operation identities are scoped by
tenant and stable allowance lineage—not by the replaceable capability ID—so a
successor cannot replay an operation consumed under its predecessor. An
unrelated tenant or allowance can still use the same local operation string
without causing a collision.

## Post-entry uncertainty

Once the provider call begins, a lost response is not safe evidence that the
effect failed. Gate commits the operation as `indeterminate` and returns:

```json
{ "ok": false, "reason": "effect_indeterminate" }
```

The same operation identifier cannot be retried blindly. A repeat returns
`operation_already_committed`. Authenticated, action-specific reconciliation
must determine the provider outcome. The generic capability reconciliation path
can record a proven `executed` outcome; it does not restore budget from an
assertion that an effect did not occur.

If the provider returns success but the following local commit cannot be
confirmed, Gate returns `capability_commit_indeterminate` and leaves the
reservation fenced. The same authenticated reconciliation path can atomically
convert that reserved operation to consumed `indeterminate` state and record a
proven provider execution. The provider is not called a second time. The Stripe
adapter also supplies the stable operation identifier as the provider-side
idempotency key.

## Exceptions and successor allowances

An out-of-envelope request is refused. It is not converted into an event-level
bypass.

If the customer wants the action class to continue with a changed destination,
ceiling, aggregate budget, or time window, the customer reviews a new
presentation and signs a new allowance backed by a new authorizing receipt and
capability. Revision 1 carries a null predecessor. Every later revision binds
the complete signed predecessor digest in `supersedes_allowance_digest`.
`issueGateAllowance()` requires the complete predecessor for every successor
and refuses a changed allowance ID, tenant, subject, audience, connector, or
action type. The allowance ID is the stable lineage ID; it does not change when
the revision or capability changes.

The local status source then makes the successor current and refuses the old
revision. Signing a successor does not mutate an old bearer artifact by magic:
the mandatory, deployment-pinned status verifier is what makes the transition
effective at the protected execution boundary.

## Explicit nonclaims

Gate Allowances v1 does **not** provide:

- recurring daily, weekly, or calendar-based budget resets;
- strong safety for arbitrary tools or free-form tool payloads;
- complete mediation for calls made outside the wrapped local connector path;
- a production hosted approval service;
- a native mobile application;
- proof that a human understood a display merely because a presentation digest
  was signed;
- proof of the provider-side effect when execution becomes indeterminate; or
- revocation of an older artifact outside a protected path whose status source
  has learned the successor.

## Runnable example

From the repository root:

```bash
node examples/gate-allowance/demo.mjs
```

The example uses ephemeral keys, the real public Gate allowance and Stripe
adapter APIs, the reference in-memory capability store, and a local
Stripe-compatible stub. It makes no network request and moves no money.
