# Audit Log Retention

Security-relevant activity is split across:

- `protocol_events`: trust-changing event source of truth
- `audit_events`: domain audit timeline and evidence records
- `security_events`: hash-chained security and incident-response ledger

Recommended default retention:

- hot searchable logs: 365 days
- cold retained evidence: 2190 days
- export: customer SIEM or GRC archive

Minimum security event types:

- receipt challenge issued
- receipt verified
- receipt consumed
- replay refused
- forged/tampered receipt refused
- authority revoked
- key rotated
- admin/security configuration changed
- incident declared

The `security_events` table is append-only and hash-chained. Mutating historical rows is a database-level violation.
