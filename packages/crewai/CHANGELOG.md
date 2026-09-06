# Changelog

## 0.3.5 (2026-09-05)

- Require `emilia-verify>=2.8.5,<3`, including its packaging correction and
  existing security fixes. Gate behavior is unchanged from 0.3.4.
- Use a fresh release version so the existing 0.3.4 source tag stays immutable.

## 0.3.4 (2026-09-05)

### Security

- Recheck receipt validity after blocking assurance and reservation work, before
  invoking the provider. Snapshot signed input so callbacks cannot replace it.
- Reject async and generator tools before reservation. Refuse lazy results from
  synchronous tools while keeping the attempted receipt consumed.
- Return a closed refusal for malformed nested receipt fields instead of raising
  an attribute-access error.
- Enforce a signed `expires_at` as an absolute validity boundary, mirroring
  `verifyEmiliaReceipt` in `packages/require-receipt`. It was never read, so a
  gate built with `max_age_sec=None` accepted a receipt that expired 30 days
  ago, and even under the default age policy a fresh `created_at` with a past
  `expires_at` ran. A present-but-unparseable `expires_at` fails closed.
- Require an explicit affirmative from `verify_assurance`. A bare string return
  was read as "ok, and here is the tier", so a verifier returning a diagnostic
  label, an error code, or an unproven tier passed the assurance check. Only
  `{"ok": True, "tier": ...}` or the literal `True` now authorizes.

### Changed

- Set the supported Python floor to 3.10 so package metadata matches the
  current reproducible build toolchain.
- Require `emilia-verify>=2.8.4,<3` so installation includes the verifier's
  malformed-receipt fixes.

## 0.3.3 (2026-08-02)

- Publish the CrewAI consequence guard with the current verifier dependency.
