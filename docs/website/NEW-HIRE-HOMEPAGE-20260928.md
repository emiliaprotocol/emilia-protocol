<!-- SPDX-License-Identifier: Apache-2.0 -->
# New-hire homepage artwork and story

The homepage tells one illustrative story: Rosa pays the bills at her family's
flooring company, the new hire is an AI, and at 2:14 a.m. a fake "we've changed
banks" email asks it to pay a real $8,400 bill to a new account. The gate stops
it because the account is not the supplier's usual account. Rosa, her company,
the limit and the amounts are made up, and the page says so beside the first
image. The FBI figure is the only statistic: IC3 2025 Annual Report, business
email compromise losses of $3,046,598,558.

## Claims the page keeps bounded

- The gate covers only the payment paths a company connects through EMILIA.
- Payment details come from the system of record, never the agent request
  (`packages/gate/src/execution-binding.ts`, `verifyExecutionBinding`).
- Delegated limits cannot widen a parent allocation
  (`packages/gate/src/authority-allocation.ts`, `child_budget_widening`).
- An interrupted provider call stays open until reconciled, so it cannot be
  blindly retried (`packages/gate/src/open-exposure-ledger.ts`).
- Only allowed actions carry signed receipts. A receipt check shows the receipt
  is genuine and unchanged; which signers to trust stays the reader's call.
- No customer, revenue, savings, certification or independence claim.

## Assets

- `public/home-newhire-{cover,kitchen,ledger,openlane,barrier,signalbox,seal,dawnroad}-v1.webp`
- AI-generated photographic key art (Gemini image model), converted from PNG
  with `cwebp -resize 1920 0 -q 74 -metadata none`. No semantic edits.
- Palette: asphalt `#0E0F0C`, bone `#F2EFE6`, one sodium accent `#E8581C`.
  Type: Barlow Condensed headlines, Newsreader body. Latin-subset woff2 files
  from Google Fonts with each family's OFL, committed in `app/fonts/` and
  loaded by `next/font/local` so the build never fetches fonts.
- The kitchen image shows an illustrative person from behind, not a real
  customer or employee. No logos or readable text in any image.
