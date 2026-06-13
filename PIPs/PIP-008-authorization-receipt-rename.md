# PIP-008: Rename Core Object "Trust Receipt" → "Authorization Receipt"

**Status:** Draft
**Type:** Core
**Created:** 2026-06-13
**Author(s):** Iman Schrock
**Requires:** PIP-001 (Core Freeze)

## Abstract

This PIP proposes renaming the EP Core v1.0 object **"Trust Receipt"** to
**"Authorization Receipt"** across the EP canon, to align the constitution
and the reference implementation with the IETF Internet-Draft that already
carries that name (`draft-schrock-ep-authorization-receipts`) and with the
project's existing buyer-facing language rule. This is a **naming change
only** — it does **not** alter the EP-RECEIPT-v1 wire format, the
canonicalization, the signature, or any verification logic. Because
"Trust Receipt" is a frozen Core Object (Constitution Art. II, "EP Core
v1.0 … is frozen"), the change runs the full Core process: this PIP, a
90-day review, consensus, a **major version bump to EP Core v2.0**, and a
**24-month deprecation** window during which "Trust Receipt" remains a
recognized alias. The sibling Core Objects **Trust Profile** and **Trust
Decision** are unchanged by this PIP (see Open Questions).

## Motivation

The EP canon currently names one concept two ways, and the split is now a
liability for adoption rather than a stylistic quibble:

- **The standard already says "authorization receipt."** The published
  Internet-Draft is `draft-schrock-ep-authorization-receipts` (at -01 on
  the IETF datatracker). For EP to become *the* referenceable standard, the
  thing the ecosystem cites must match across the I-D, the spec, the SDK,
  and the site. A reader who finds "authorization receipt" in the I-D and
  "Trust Receipt" on the site sees two terms and wonders which is real.
- **"Trust receipt" is a taken term.** It is an established trade-finance
  instrument (a bank financing arrangement), which is bad for search,
  clarity, and trademark distinctiveness.
- **The project already decided this for buyer-facing language.** The
  adoption plan's language rule states: *"Say authorization receipt, not
  'Trust Receipt,' in buyer-facing language"* (`docs/strategy/`), and the
  marketing/docs prose was converged to "authorization receipt" in commit
  `7ab3a18`. The `@emilia-protocol/issue` SDK package already exposes
  `assembleAuthorizationReceipt` / `issueAuthorizationReceipt` as the
  primary names with `assembleTrustReceipt` / `issueTrustReceipt` as
  deprecated aliases. This PIP completes a migration the codebase has
  already begun, rather than starting a new one.

The only reason this is non-trivial is governance: "Trust Receipt" is a
*frozen* Core Object, so the change cannot be a silent rename — it must go
through the Core process and carry a deprecation window.

## Specification

On acceptance:

1. **Canonical name.** The Core Object formerly named "Trust Receipt" is
   renamed **"Authorization Receipt."** Update the Constitution Core
   Objects table, `PIP-001`, `docs/PROTOCOL-STANDARD.md`,
   `docs/EP-CORE-RFC.md`, `docs/FEDERATION-SPEC.md`,
   `docs/trust-receipt-spec.md`, and all remaining canon/spec references.
2. **Version.** Bump EP Core **v1.0 → v2.0**. The frozen object *set* is
   unchanged in count and semantics; only the name of one object changes.
3. **What does NOT change (frozen wire contracts, explicitly preserved):**
   - The **`EP-RECEIPT-v1`** document schema, canonicalization (JCS,
     RFC 8785), Ed25519 signature, and Merkle anchor — byte-for-byte
     unchanged. Receipts issued before and after this PIP verify
     identically. The version tag stays `EP-RECEIPT-v1`.
   - The HTTP path **`/api/v1/trust-receipts`** — frozen as a wire
     contract; not renamed (a URL slug is not a brand surface, and renaming
     it would break integrations for no semantic gain).
   - JSON field names / enum values already on the wire (e.g.
     `receipt_status`) — unchanged.
4. **SDK / API aliases (24-month deprecation).** Type and function names
   that say `TrustReceipt` (e.g. `verifyTrustReceipt`, `TrustReceiptResult`
   in `@emilia-protocol/verify`) gain `Authorization*` primaries with
   `TrustReceipt*` retained as deprecated aliases through the deprecation
   window, mirroring what `@emilia-protocol/issue` already did.
5. **Term alias.** Throughout the 24-month window, "Trust Receipt" is a
   recognized synonym of "Authorization Receipt" in documentation, and a
   one-time "(formerly Trust Receipt)" bridge is acceptable on key pages.

## Backward compatibility

Fully backward compatible at the wire/cryptographic layer — no receipt,
verifier, or anchored log is invalidated, because nothing the signature
covers changes. The only breakage risk is *symbolic* (code that imports a
`TrustReceipt*` identifier), and that is covered by the alias period.
Migration cost is therefore documentation + SDK-alias upkeep, not a
flag-day.

## Open questions

1. **Triad parallelism.** EP Core names three objects: *Trust Receipt,
   Trust Profile, Trust Decision.* This PIP renames only the receipt
   (the sole object that is also an interoperable IETF artifact and thus
   must match the standard). The result is a mixed set —
   *Authorization Receipt / Trust Profile / Trust Decision* — which is
   acceptable because the three are distinct concepts, but reviewers should
   decide whether a follow-on PIP should also revisit Profile/Decision for
   naming consistency, or whether "Trust" is the right family name for the
   derived-state objects while "Authorization" names the signed artifact.
2. **`/spec/trust-receipt` URL.** Recommend keeping the existing URL (for
   backlinks/SEO) with the page content already converged, and adding a
   `301` to `/spec/authorization-receipt` as optional follow-up — out of
   scope for this Core PIP.

## Rationale

Adopting the standard's term as the canonical Core name is the
lowest-regret path to one coherent narrative across the I-D, the spec, the
SDK, and the product — the property that compounds into ecosystem
adoption. The Core process and deprecation window are the cost of doing it
honestly under the constitution rather than around it.
