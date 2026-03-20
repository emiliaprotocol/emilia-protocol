# EMILIA Protocol -- Write Path Invariant

## THE LAW

**Every trust-changing write flows through `protocolWrite()`.**

This is not a convention. It is enforced at three layers: static analysis (CI), runtime proxy (write-guard), and architectural constraint (canonical functions are only imported by `protocol-write.js`).

`protocolWrite()` is defined in `lib/protocol-write.js`. It accepts a command object with `{ type, input, actor, requestMeta }` and returns the result projection from the underlying canonical function.

## What Counts as a Write

There are exactly 17 `COMMAND_TYPES`, organized by aggregate:

### Receipt Commands
| Command Type | Constant | Handler |
|---|---|---|
| `submit_receipt` | `COMMAND_TYPES.SUBMIT_RECEIPT` | `canonicalSubmitReceipt()` |
| `submit_auto_receipt` | `COMMAND_TYPES.SUBMIT_AUTO_RECEIPT` | `canonicalSubmitAutoReceipt()` |
| `confirm_receipt` | `COMMAND_TYPES.CONFIRM_RECEIPT` | `canonicalBilateralConfirm()` |

### Commit Commands
| Command Type | Constant | Handler |
|---|---|---|
| `issue_commit` | `COMMAND_TYPES.ISSUE_COMMIT` | `issueCommit()` |
| `verify_commit` | `COMMAND_TYPES.VERIFY_COMMIT` | `verifyCommit()` |
| `revoke_commit` | `COMMAND_TYPES.REVOKE_COMMIT` | `revokeCommit()` |

### Dispute Commands
| Command Type | Constant | Handler |
|---|---|---|
| `file_dispute` | `COMMAND_TYPES.FILE_DISPUTE` | `canonicalFileDispute()` |
| `resolve_dispute` | `COMMAND_TYPES.RESOLVE_DISPUTE` | `canonicalResolveDispute()` |
| `respond_dispute` | `COMMAND_TYPES.RESPOND_DISPUTE` | `canonicalRespondDispute()` |
| `appeal_dispute` | `COMMAND_TYPES.APPEAL_DISPUTE` | `canonicalAppealDispute()` |
| `resolve_appeal` | `COMMAND_TYPES.RESOLVE_APPEAL` | `canonicalResolveAppeal()` |
| `withdraw_dispute` | `COMMAND_TYPES.WITHDRAW_DISPUTE` | `canonicalWithdrawDispute()` |

### Report Commands
| Command Type | Constant | Handler |
|---|---|---|
| `file_report` | `COMMAND_TYPES.FILE_REPORT` | `canonicalFileReport()` |

### Handshake Commands
| Command Type | Constant | Handler |
|---|---|---|
| `initiate_handshake` | `COMMAND_TYPES.INITIATE_HANDSHAKE` | `_handleInitiateHandshake()` |
| `add_presentation` | `COMMAND_TYPES.ADD_PRESENTATION` | `_handleAddPresentation()` |
| `verify_handshake` | `COMMAND_TYPES.VERIFY_HANDSHAKE` | `_handleVerifyHandshake()` |
| `revoke_handshake` | `COMMAND_TYPES.REVOKE_HANDSHAKE` | `_handleRevokeHandshake()` |

Each command type maps to exactly one aggregate type via `COMMAND_TO_AGGREGATE`:

| Aggregate | Commands |
|---|---|
| `receipt` | submit_receipt, submit_auto_receipt, confirm_receipt |
| `commit` | issue_commit, verify_commit, revoke_commit |
| `dispute` | file_dispute, resolve_dispute, respond_dispute, appeal_dispute, resolve_appeal, withdraw_dispute |
| `report` | file_report |
| `handshake` | initiate_handshake, add_presentation, verify_handshake, revoke_handshake |

## What Is Forbidden

Direct `insert()`, `update()`, `upsert()`, or `delete()` on any trust table from route handlers is forbidden. This includes:

- Importing canonical functions (`canonicalSubmitReceipt`, `canonicalFileDispute`, `issueCommit`, etc.) in route files under `app/api/`.
- Importing `getServiceClient()` in route files (must use `getGuardedClient()` instead).
- Any `.from('trust_table').insert(...)` or `.from('trust_table').update(...)` outside the canonical write layer.

## What Is Allowed

- **Reads**: Any code may read from any table. `getGuardedClient()` does not block `select()`.
- **Schema operations**: Table creation, migration, indexing.
- **Auth helpers**: Authentication middleware, session management.
- **`protocolWrite()`**: The only authorized entry point for trust-changing writes.
- **Non-trust tables**: Writes to tables not in TRUST_TABLES are unrestricted.

## TRUST_TABLES

The complete list of protected tables (from `lib/write-guard.js`):

```
receipts
commits
disputes
trust_reports
protocol_events
handshakes
handshake_parties
handshake_presentations
handshake_bindings
handshake_results
handshake_policies
handshake_events
handshake_consumptions
```

## CI Enforcement

### `scripts/check-write-discipline.js`

Scans all `route.js` / `route.ts` files under `app/api/`. Fails CI if:

1. **Forbidden canonical function imports**: Any route file that references a canonical function name (e.g., `canonicalSubmitReceipt`, `issueCommit`, `verifyCommit`, etc.) in a non-comment line.

2. **`getServiceClient` usage**: Any route file (not in `SERVICE_CLIENT_ALLOWLIST`) that imports or calls `getServiceClient`. Routes must use `getGuardedClient()`.

The `SERVICE_CLIENT_ALLOWLIST` contains exactly two files that have known trust-table writes pending migration to `protocolWrite` commands:
- `app/api/cron/expire/route.js` (needs `EXPIRE_RECEIPT` command)
- `app/api/trust/gate/route.js` (needs `CONSUME_HANDSHAKE_BINDING` command)

Exit code 1 on any violation. Exit code 0 on pass.

### `scripts/check-protocol-discipline.js`

Broader CI guardrail. Checks:

1. **Trust-table writes**: Scans all route files for `.from('table').insert()` patterns on trust-bearing tables. Allowlisted files: `canonical-writer.js`, `protocol-write.js`, `commit.js`, `create-receipt.js`.

2. **Handshake-table writes**: Scans all application and library files for `.from('handshake_table').insert/update/upsert()` outside the handshake module (`lib/handshake/`) and allowlisted files.

3. **`process.env.EP_` reads**: Only `lib/env.js` may read `process.env.EP_*` variables directly.

4. **Handler complexity**: Route handler functions exceeding 80 significant lines trigger a warning.

5. **Embedded issuer keys**: Detects `presentation.publicKey`, `presentation.signingKey`, `payload.key` patterns in handshake code.

6. **Test suite presence**: Warns if `tests/handshake.test.js` or `tests/handshake-attack.test.js` are missing or lack invariant/attack coverage.

Critical violations cause CI failure (exit code 1). Warnings pass but are reported.

## Runtime Enforcement

### `lib/write-guard.js` -- `getGuardedClient()`

Returns a Proxy-wrapped Supabase client. The proxy intercepts `.from(table)` calls:

- If `table` is in `TRUST_TABLES`: returns a second Proxy that intercepts `insert()`, `update()`, `upsert()`, and `delete()` calls. These throw immediately with `WRITE_DISCIPLINE_VIOLATION`.
- If `table` is not in `TRUST_TABLES`: returns the normal query builder (no interception).

The proxy does **not** mutate the original client. This is critical because `getServiceClient()` may return the same object reference, and `protocol-write.js` needs the unrestricted client for event persistence.

The blocked operations are: `insert`, `update`, `upsert`, `delete`.

Reads (`select()`) are always allowed on all tables.

### Error Message on Violation

```
WRITE_DISCIPLINE_VIOLATION: Direct {operation}() on trust table "{table}" is forbidden.
All trust-bearing writes MUST go through protocolWrite().
This is a runtime enforcement -- not a convention.
```
