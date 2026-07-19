# CAID reference implementation (JavaScript)

Pure ESM, `node:crypto` only, zero dependencies. Conforms to `../../DESIGN.md`.

Suite support: `jcs-sha256` only. `cbor-sha256` is defined in the suite
registry but is not implemented here; this implementation refuses it as
`unknown_suite`.

Scope, stated plainly: CAID carries no trust semantics. A CAID proves that
artifacts reference the same typed content. It does not prove the action was
authorized, executed, safe, or wise. Nothing in this module verifies
signatures, identity, or authorization.

## Usage

```js
import { computeCaid, verifyCaid, parseCaid, canonicalize } from "./caid.mjs";

const definitions = [
  {
    action_type: "payment.release.1",
    required_fields: [
      { name: "amount", type: "amount-string" },
      { name: "currency", type: "enum", values_ref: "ISO 4217 alpha-3" },
      { name: "beneficiary_account", type: "digest" },
      { name: "payment_instruction_id", type: "string" },
    ],
    optional_fields: [{ name: "memo", type: "string" }],
  },
];

const action = {
  action_type: "payment.release.1",
  amount: "250.00",
  currency: "EUR",
  beneficiary_account: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  payment_instruction_id: "pi-2026-000117",
};

const out = computeCaid(action, { suite: "jcs-sha256", definitions });
// success: { caid: "caid:1:payment.release.1:jcs-sha256:<b64url>", digest: "sha256:<hex>" }
// failure: { refusals: ["missing_material_field:currency", ...] } and no caid

const check = verifyCaid(action, out.caid, { definitions });
// { valid: true, reasons: [] }
// or { valid: false, reasons: ["digest_mismatch"] } etc.

const parsed = parseCaid(out.caid);
// { ok: true, caid: { version, action_type, suite, digest } }
// or { ok: false, refusals: ["malformed_caid"] }

const canon = canonicalize(action);
// { ok: true, canonical: "<RFC 8785 JCS string>" }
// or { ok: false, refusals: ["unsupported_number"] }
```

All four functions are fail-closed: junk input returns refusals with
reasons, never throws.

## Conformance

```
node run-vectors.mjs
```

Runs every vector in `../../conformance/vectors.json` and exits nonzero on
any failure. The vectors carry their own inline type definitions, so
conformance never depends on the public registry's contents.
