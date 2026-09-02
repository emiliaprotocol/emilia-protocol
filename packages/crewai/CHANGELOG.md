# Changelog

## Unreleased

### Security

- Enforce a signed `expires_at` as an absolute validity boundary, mirroring
  `verifyEmiliaReceipt` in `packages/require-receipt`. It was never read, so a
  gate built with `max_age_sec=None` accepted a receipt that expired 30 days
  ago, and even under the default age policy a fresh `created_at` with a past
  `expires_at` ran. A present-but-unparseable `expires_at` fails closed.
- Require an explicit affirmative from `verify_assurance`. A bare string return
  was read as "ok, and here is the tier", so a verifier returning a diagnostic
  label, an error code, or an unproven tier passed the assurance check. Only
  `{"ok": True, "tier": ...}` or the literal `True` now authorizes.

## 0.3.4 (2026-08-30)

- Set the supported Python floor to 3.10 so package metadata matches the
  current reproducible build toolchain. Guard behavior is unchanged.

## 0.3.3 (2026-08-02)

- Publish the CrewAI consequence guard with the current verifier dependency.
