# Muse Code / EMILIA exact-action Gate demo

This integration exposes a real stdio MCP tool named `release_payment`. Its
handler is wrapped by the repository's `gateMcpTool()` and
`createTrustedActionFirewall()` implementations. That MCP wrapper, not the Muse
hook, is the consequential enforcement point.

The demo uses only public Muse interfaces: stdio MCP plus `PreToolUse` and
`PostToolUse` JSON on stdin. It was shaped for Muse Code 1.3.0-R3401.1.

## Control boundary

1. Muse calls `mcp__emilia_payment_gate__release_payment` with five material
   fields and an EP authorization receipt.
2. The optional `PreToolUse` hook rejects malformed requests or a missing
   receipt early. A well-shaped request produces no stdout and exits 0.
3. The MCP server maps the exact payee, account, amount, currency, and operation
   to `payment.release.1`, computes its CAID with the repository reference
   implementation, and passes the executor-observed action into EMILIA Gate.
4. Gate verifies the pinned issuer, Class-A evidence, exact execution fields,
   freshness, and one-time consumption. It reserves authority before invoking
   the provider handler.
5. Only the MCP server's provider function owns the effect boundary. A normal
   return is recorded as `EXECUTED`. An exception after invocation is recorded
   as `INDETERMINATE`, burns the authority, and must not be blindly retried.
6. The response carries an `EP-RECEIPT-v1` outcome receipt. The repository's
   offline verifier checks its signature and this adapter checks its closed
   outcome semantics.

`PostToolUse` is observational only. Muse hooks do not own the payment
credential, do not wrap the provider call atomically, and cannot by themselves
establish exact-action authorization or provider outcome. Removing the MCP Gate
and keeping only the hooks is not this security architecture.

## Run the local demo

Install the lockfile dependencies, then generate ephemeral demo keys and one
short-lived, single-use authorization. The generated directory contains private
key material and must not be committed.

```sh
npm ci --ignore-scripts
node integrations/muse-code-gate/demo-config.mjs .muse/emilia-payment-gate-demo
```

Merge the `mcpServers` entry from
[`examples/settings.json`](./examples/settings.json) into
`${XDG_CONFIG_HOME:-$HOME/.config}/muse/settings.json`. Muse Code 1.3.0 uses
the camel-case `mcpServers` key; the legacy `mcp_servers` key is not the
current configuration shape. The current stdio form is:

```json
{
  "schema_version": 1,
  "mcpServers": {
    "emilia_payment_gate": {
      "type": "stdio",
      "command": "node",
      "args": ["./integrations/muse-code-gate/server.mjs"],
      "env": {
        "EMILIA_MUSE_GATE_CONFIG": "./.muse/emilia-payment-gate-demo/gate-config.json"
      },
      "enabled": true,
      "mode": "required"
    }
  }
}
```

This shape was startup-tested with the server in `mode: "required"` against
Muse Code 1.3.0-R3401.1. A required server that cannot start aborts the Muse
session rather than silently removing the Gate tool.

`authorized-call.json` in the generated directory contains the exact arguments
and receipt for one local call. The bundled provider is intentionally harmless:
it appends the accepted request to `demo-provider-ledger.jsonl`; it does not move
money. Replace only the `provider` function passed to
`createPaymentReleaseTool()` when integrating a credential-owning payment SDK.

To exercise the ambiguous-outcome path, start the server with
`EMILIA_MUSE_PROVIDER_MODE=throw_after_entry`. The ledger append occurs and the
simulated response is then lost, so the result is `INDETERMINATE` and replay is
refused.

## Optional `.muse/hooks.json`

The exact example is in [`examples/hooks.json`](./examples/hooks.json):

```json
{
  "schema_version": 1,
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "mcp__emilia_payment_gate__release_payment",
        "hooks": [
          {
            "type": "command",
            "command": "node ./integrations/muse-code-gate/hook.mjs"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "mcp__emilia_payment_gate__release_payment",
        "hooks": [
          {
            "type": "command",
            "command": "node ./integrations/muse-code-gate/hook.mjs"
          }
        ]
      }
    ]
  }
}
```

For a PreToolUse refusal, the command writes the Muse-specific shape below and
exits 2:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "EMILIA Gate: authorization_receipt_required"
  }
}
```

On allow it writes nothing and exits 0. A bare `permissionDecision: "allow"`
is deliberately not emitted. PostToolUse also writes nothing; set
`EMILIA_MUSE_OBSERVATION_FILE` if a local JSONL observation trail is useful.

## Input and receipt contract

The MCP schema rejects additional properties. The provider receives only:

```json
{
  "payee": "vendor:acme",
  "account": "acct:us:0001842",
  "amount": "1250.00",
  "currency": "USD",
  "operation": "invoice-1842"
}
```

The adapter maps those fields to:

- `payee_ref`: exact payee string;
- `beneficiary_account`: `sha256:` of the exact validated account UTF-8 bytes;
- `amount`: exact positive decimal string, with at most two fractional digits;
- `currency`: exact uppercase three-letter code;
- `payment_instruction_id`: exact operation string.

`payee_ref` is an adapter-profile extension to the registered
`payment.release.1` content. CAID hashes the complete action object, so it is
material even though the base registry entry does not require that field.
Changing any of the five inputs changes the action commitment and is refused by
Gate when the receipt authorized the original action.

The `_emilia_receipt` carrier is stripped before provider entry. Multiple
receipt carriers and any unbound extra provider option fail closed.

Every terminal provider-entry response includes:

- `provider_entry: "ENTERED"` plus `outcome: "EXECUTED"`; or
- `provider_entry: "ENTERED"` plus `outcome: "INDETERMINATE"` and
  `retry: "REFUSE"`.

Pre-entry refusals report `provider_entry: "NOT_ENTERED"` and no terminal
outcome. A missing response is not evidence of non-entry; inspect the durable
Gate state and reconcile the stable operation identifier.

## Offline verification

Save `_emilia.outcome_receipt` from the MCP result and verify it with the public
key returned as `_emilia.outcome_verification_key`:

```sh
node integrations/muse-code-gate/verify-receipt.mjs outcome-receipt.json PUBLIC_KEY_B64URL
```

Verification proves that the pinned Gate outcome key signed those exact bytes.
The receipt is evidence, not authority for another execution. It does not prove
that the payee was wise or legitimate, that settlement became final, that fraud
was absent, or that a provider's claim was true. `EXECUTED` means the wrapped
provider returned normally; `INDETERMINATE` means the effect may or may not have
occurred and requires reconciliation.

## Test

```sh
npm run test:muse-code-gate
```

The hostile suite covers every material-field mutation, unbound extra fields,
numeric money, noncanonical currency/account strings, replay, provider-response
loss, offline receipt verification, Muse denial/allow process semantics, and a
real stdio MCP `tools/list` + `tools/call` round trip.

## Deployment boundaries

- The generated issuer and outcome keys are local fixtures, not enrollment or
  production key custody.
- The JSON file consumption backend is ownership-fenced through Gate's existing
  durable-store wrapper and suitable for one local server process. A fleet must
  use a linearizable shared backend and operational reconciliation.
- The demo ledger is not a payment provider and supplies no settlement proof.
- CAID commits to content; it does not authorize, execute, or judge the action.
- The outcome receipt is not a retry token. Replay remains refused even after an
  indeterminate result.
- Muse approval mode, sandboxing, authentication, provider permissions, and
  administrator policy remain separate controls.
