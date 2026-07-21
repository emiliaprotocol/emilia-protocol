# AML Screening

EP adds AML (anti-money-laundering) **risk signals** to the guard decision on
financial actions. It is the evidence layer beneath a human decision — not a
replacement for a bank's BSA/AML program or a transaction-monitoring system.

When AML context is attached to a FinGuard/GovGuard action, the policy engine:

- **fails closed** on a sanctions/PEP match or an embargoed jurisdiction
  (`decision: deny` — OFAC blocking is not a discretionary approval);
- **escalates to accountable signoff** on a structuring pattern, high velocity,
  or a near-threshold amount (`decision: allow_with_signoff`);
- **surfaces every signal** as `aml_signals` on the decision, the API response,
  and the audit record — so the reason a payment was held is provable.

AML never *weakens* an existing control: a large payment that already requires
signoff still requires it.

## Passing AML context

Any FinGuard adapter accepts these optional fields (or an explicit `aml` block):

| Field | Meaning |
|---|---|
| `counterparty_name` (`beneficiary_name` / `payee_name`) | screened against the watchlist |
| `counterparty_country` (`beneficiary_country`) | ISO-3166 alpha-2; checked against embargoes |
| `amount` | this transaction (USD) |
| `recent_amounts` | recent transfers to the same counterparty (optional — EP looks this up from its own history when omitted) |

```bash
curl -s .../api/v1/adapters/fin/payment-release/precheck \
  -H "authorization: Bearer ep_live_..." -H "content-type: application/json" \
  -d '{"organization_id":"...","payment_instruction_id":"pi_1","amount":9500,
       "counterparty_name":"Acme Trading","recent_amounts":[9400,9600],
       "before_state":{"status":"pending"},"after_state":{"status":"released"}}'
# -> decision: allow_with_signoff, aml_signals: ["structuring:..."]
```

## Detection logic (`lib/aml/screening.js`)

- **Sanctions / PEP** — name normalization (case, punctuation, diacritics) +
  exact and Jaccard token-overlap fuzzy matching against the watchlist, plus an
  embargoed-jurisdiction check.
- **Structuring** — transfers kept just under the $10,000 CTR threshold,
  especially repeated; and aggregation of sub-threshold transfers over the window.
- **Velocity** — an unusual count of transfers in the window.

## Counterparty history

Structuring and velocity must not depend on the monitored system reporting the
pattern it might be hiding. EP records every financial precheck that names a
counterparty into `aml_history` (migration 097) and, when the caller supplies no
`recent_amounts`, looks the 30-day / 20-transfer window up **itself**. A
caller-supplied window still takes precedence (a core-banking system may have a
longer view). History lookups and writes are best-effort: a failure degrades to
"no history" and never blocks the decision.

## Watchlist

The bundled `lib/aml/watchlist.js` is a small **synthetic snapshot** so the
screening logic ships working and is deterministically tested. In production the
watchlist is refreshed from the official feeds (OFAC SDN + consolidated, EU, UN)
by an operations job; `screenSanctions({ list })` / `loadWatchlist()` is the
injection point. The matching/structuring/velocity logic is correct regardless of
which list is loaded.

## Conformance

`tests/aml-screening.test.ts` (25) covers normalization, exact/alias/fuzzy
sanctions matching, embargo, structuring (repeated / single / aggregation),
velocity, and the aggregate recommendation. `tests/guard-adapter-aml.test.ts` (9, incl. structuring detected purely from EP-persisted history)
proves the end-to-end adapter flow: sanctions → deny, structuring → signoff,
clean → allow, and observe-mode never blocks.
