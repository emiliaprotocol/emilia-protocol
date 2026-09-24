# Muse Code / EMILIA exact-action Gate demo

This integration exposes two real stdio MCP tools: the consequential
`release_payment` boundary and the read-only `reconcile_payment` recovery path.
The release handler is wrapped by the repository's `gateMcpTool()` and
`createTrustedActionFirewall()` implementations. That MCP wrapper, not a Muse
hook, is the consequential enforcement point.

The demo uses only public Muse interfaces: stdio MCP plus `PreToolUse`,
`PostToolUse`, and `PostToolUseFailure` JSON on stdin. It was shaped for Muse
Code 1.3.0-R3401.1.

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
5. Only the MCP server's credential-owning provider adapter owns the effect
   boundary. An authenticated `ACCEPTED` result is recorded as `EXECUTED`. An
   explicit `AGENT_ACCESS_DENIED` or `PROVIDER_DECLINED` result is recorded as
   `REFUSED` / `NOT_ACCEPTED`, but still consumes the authority. An exception,
   unknown response, or generic MCP error after invocation is recorded as
   `INDETERMINATE`, burns the authority, and must not be blindly retried.
6. The response carries an `EP-RECEIPT-v1` outcome receipt. The repository's
   offline verifier checks its signature and this adapter checks its closed
   outcome semantics.

`PostToolUse` and `PostToolUseFailure` are observational only. Muse hooks do not
own the payment credential, do not wrap the provider call atomically, and
cannot by themselves establish exact-action authorization or provider outcome.
Removing the MCP Gate and keeping only the hooks is not this security
architecture.

## Reconcile before any retry

After an `INDETERMINATE` result, call `reconcile_payment` with the same five
material fields and the Gate-signed `_emilia_outcome_receipt`. The tool first
verifies that the receipt is a valid, matching `INDETERMINATE` outcome. It then
queries the deployment-owned provider adapter by stable operation identifier.
The result is another signed receipt:

- `ACCEPTED` resolves the outcome to `EXECUTED`; retry remains refused.
- authoritative `NOT_ACCEPTED` resolves the outcome to `REFUSED`; a new attempt
  requires a **fresh authorization**. The consumed receipt is never restored.
- an unauthenticated, non-authoritative, unknown, or failed lookup remains
  `INDETERMINATE`; retry remains refused.

The first decisive reconciliation is durably pinned by the prior outcome
receipt ID before it is returned. Repeating the lookup returns that exact
signed terminal receipt, even if the provider later reports something else.
A concurrent lookup sees the pending reservation and fails closed. If the
process dies while a lookup is pending, the marker is deliberately not reaped;
an operator must inspect the provider before repairing it. This demo store is
single-host only. Multi-host deployments need a linearizable shared store.

The receipt's `provider_assertion_digest` commits to the normalized assertion
made by the credential-owning adapter, including the provider reference for an
accepted result. The adapter's authenticated provider channel is what supports
that assertion. The digest does **not** independently prove provider truth and
does not claim to hash raw provider-signed evidence.

The bundled local ledger is treated as an authoritative demo fixture. In production,
replace its lookup with the payment provider's credentialed status/idempotency
API. Merely receiving a caller-supplied status is not authenticated
reconciliation.

Automated reconciliation requires the caller to retain the signed
`INDETERMINATE` outcome receipt. If the process or transport dies after provider
entry but before that receipt reaches the caller, this demo cannot reconstruct
it from the consumption file alone. Authority remains consumed and replay is
still refused; an operator must reconcile directly at the provider. A
production adapter should durably journal the provider attempt and outcome
receipt at the effect boundary before acknowledging the call.

## Run the local demo

Install the lockfile dependencies, then generate ephemeral demo keys and one
short-lived, single-use authorization. The generated directory contains private
key material and must not be committed.

```sh
npm ci --ignore-scripts
node integrations/muse-code-gate/demo-config.mjs .muse/emilia-payment-gate-demo
```

Merge the `mcp_servers` entry from
[`examples/settings.json`](./examples/settings.json) into
`${XDG_CONFIG_HOME:-$HOME/.config}/muse/settings.json`. This example follows
[Meta's published Extending documentation](https://dev.meta.ai/docs/muse-code/extending):

```json
{
  "schema_version": 1,
  "mcp_servers": {
    "emilia_payment_gate": {
      "transport": "stdio",
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

This documented shape was startup-tested with the server in `mode: "required"`
against Muse Code 1.3.0-R3401.1. That build also accepts the newer
`mcpServers` / `type` aliases, but do not put both forms in one file. A required
server that cannot start aborts the Muse session rather than silently removing
the Gate tool. Revalidate the configuration against the installed Muse build
when upgrading.

`authorized-call.json` in the generated directory contains the exact arguments
and receipt for one local call. The bundled provider is intentionally harmless:
it appends only an operation digest, CAID, status, and timestamp to
`demo-provider-ledger.jsonl`; it does not move money or retain the raw payment.
Replace only the `provider` function passed to
`createPaymentReleaseTool()` when integrating a credential-owning payment SDK.

To exercise the ambiguous-outcome path, start the server with
`EMILIA_MUSE_PROVIDER_MODE=throw_after_entry`. The ledger append occurs and the
simulated response is then lost, so the result is `INDETERMINATE` and replay is
refused. Calling `reconcile_payment` then finds the accepted ledger record
without invoking `release_payment` again. Use
`EMILIA_MUSE_PROVIDER_MODE=decline_agent_access` to exercise the explicit
provider refusal path.

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
    ],
    "PostToolUseFailure": [
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
is deliberately not emitted. PostToolUse and PostToolUseFailure also write
nothing. The failure observation excludes request arguments and free-text
errors because neither proves the provider outcome and both may contain
secrets. Set `EMILIA_MUSE_OBSERVATION_FILE` if a local JSONL observation trail
is useful.

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

- `provider_entry: "ENTERED"`, `provider_effect: "ACCEPTED"`, and
  `outcome: "EXECUTED"`;
- `provider_entry: "ENTERED"`, `provider_effect: "NOT_ACCEPTED"`, and
  `outcome: "REFUSED"`; or
- `provider_entry: "ENTERED"`, `provider_effect: "UNKNOWN"`,
  `outcome: "INDETERMINATE"`, and `retry: "REFUSE"`.

Pre-entry refusals report `provider_entry: "NOT_ENTERED"` and no terminal
outcome. A missing response is not evidence of non-entry; inspect the durable
Gate state and reconcile the stable operation identifier.

## Offline verification

Save `_emilia.outcome_receipt` from the MCP result and verify it with the Gate
outcome public key that your deployment pinned out of band. For the local demo,
that key is in the privately generated `authorized-call.json`; it is not taken
from the MCP result:

```sh
node integrations/muse-code-gate/verify-receipt.mjs outcome-receipt.json PUBLIC_KEY_B64URL
```

Never trust a verification key delivered beside the receipt it is meant to
verify. An attacker could replace both. Verification proves that the separately
pinned Gate outcome key signed those exact bytes.
The receipt is evidence, not authority for another execution. It does not prove
that the payee was wise or legitimate, that settlement became final, that fraud
was absent, or that a provider's claim was true. `EXECUTED` means the wrapped
provider returned an explicit accepted result; `INDETERMINATE` means the effect
may or may not have occurred and requires reconciliation. A reconciliation
receipt is also evidence rather than authority; even `NOT_ACCEPTED` requires a
fresh authorization before a new release attempt.

## Privacy canary scan

Run the standalone synthetic scan:

```sh
node integrations/muse-code-gate/privacy-scan.mjs
```

It plants canaries in an account identifier, provider credential/payload, hook
error, authorization signature, and private outcome key. It then checks the
signed outcome, projected MCP result, demo provider ledger, and
PostToolUseFailure observation. The JSON artifact reports per-surface digests
and PASS/FAIL without printing the canaries. This is a regression proof for
those surfaces, not a claim about a real provider or external telemetry sink.

## Test

```sh
npm run test:muse-code-gate
```

The hostile suite covers every material-field mutation, unbound extra fields,
numeric money, noncanonical currency/account strings, replay, provider-response
loss, explicit agent-access refusal, authenticated reconciliation across a
restart, offline receipt verification, Muse denial/allow/failure-hook process
semantics, privacy canaries, and a real stdio MCP `tools/list` + `tools/call`
round trip.

If Muse Code 1.3 is installed, an optional isolated live smoke proves that the
documented required-server configuration admits the Gate server and that a
broken required server stops the session before the echo provider runs:

```sh
MUSE_BIN=/absolute/path/to/muse npm run smoke:muse-code-gate
```

The smoke uses temporary XDG directories, the `mcp_servers` / `transport`
settings shape above, and no Meta credentials. It proves startup, handshake,
two-tool discovery, tool inventory, and required-server failure. It also probes
the deterministic execution boundary honestly: Muse Code 1.3's `echo` provider
returns a requested tool call as text, and `muse exec` exposes no forced or
scripted tool-call option. Therefore the smoke does not pretend a model selected
`release_payment`; the direct MCP round-trip test executes it deterministically.
Set `MUSE_SMOKE_KEEP=1` to retain temporary evidence.

## Deployment boundaries

- The generated issuer and outcome keys are local fixtures, not enrollment or
  production key custody.
- The JSON consumption backend fsyncs the replacement file and its containing
  directory, and serializes independent backend instances with single-host
  PID/hostname/token lock ownership. It recovers same-host dead owners and,
  after a grace period plus inode revalidation, abandoned partial locks. A
  surviving `recovery.json` marker, including one left by a process that died
  during recovery, fails closed and requires operator inspection and removal;
  it is never reclaimed automatically. Live, foreign-host, symlink, and
  identity-ambiguous locks also fail closed. It is for one local filesystem;
  a fleet or
  network filesystem must use a linearizable shared backend and operational
  reconciliation.
- Reconciliation decisions use a separate JSON store with the same durable,
  ownership-fenced, atomic, non-expiring single-host backend contract. Passing
  an object that merely exposes similarly named methods, or a store that can
  evict terminal keys, is refused. The in-memory store is enabled only inside
  the explicit test fixture.
- The demo ledger is not a payment provider and supplies no settlement proof.
- CAID commits to content; it does not authorize, execute, or judge the action.
- The outcome receipt is not a retry token. Replay remains refused even after an
  indeterminate result. Reconciliation does not reopen consumed authority.
- Muse approval mode, sandboxing, authentication, provider permissions, and
  administrator policy remain separate controls.
