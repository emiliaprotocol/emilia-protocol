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
import { readFileSync } from "node:fs";
import { computeCaid, verifyCaid, parseCaid, canonicalize } from "./caid.mjs";

const iso4217 = JSON.parse(readFileSync(
  new URL("../../registry/value-sets/iso-4217-alpha-3.2026-09-17.json", import.meta.url),
  "utf8",
));

const definitions = [
  {
    action_type: "payment.release.1",
    required_fields: [
      { name: "amount", type: "amount-string" },
      {
        name: "currency",
        type: "enum",
        values_ref: iso4217.values_ref,
        values_snapshot: iso4217.values_snapshot,
        values_sha256: iso4217.values_sha256,
      },
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

const enumSnapshots = [iso4217];
const out = computeCaid(action, { suite: "jcs-sha256", definitions, enumSnapshots });
// success: { caid: "caid:1:payment.release.1:jcs-sha256:<b64url>", digest: "sha256:<hex>" }
// failure: { refusals: ["missing_material_field:currency", ...] } and no caid

const check = verifyCaid(action, out.caid, { definitions, enumSnapshots });
// { valid: true, reasons: [] }
// or { valid: false, reasons: ["digest_mismatch"] } etc.

const parsed = parseCaid(out.caid);
// { ok: true, caid: { version, action_type, suite, digest } }
// or { ok: false, refusals: ["malformed_caid"] }

const canon = canonicalize(action);
// { ok: true, canonical: "<RFC 8785 JCS string>" }
// or { ok: false, refusals: ["unsupported_number"] }
// or { ok: false, refusals: ["unsupported_value"] } for a string or member
//    name containing an unpaired surrogate (RFC 8785 section 3.2.2.2)
```

All four functions are fail-closed: junk input returns refusals with
reasons, never throws.

Code inside this repository that uses the full registry definitions can import
`REGISTRY_ENUM_SNAPSHOTS` and `activeRegistryDefinition()` from
`caid/registry/enum-snapshots.mjs` instead of naming value-set files or
copying a registered definition. It loads exactly the files listed in the
registry's `enum_snapshot_files` and throws if a file's reference, edition
label, values digest, or whole-file `snapshot_sha256` differs from the
registry entry. Next.js server code uses `CAID_REGISTRY_ENUM_SNAPSHOTS` from
`lib/caid-registry.ts`, which imports the same files statically and applies
the same checks at module load. Without a snapshot, a present currency field
refuses with `mistyped_field:currency`.

## Conformance

```
node run-vectors.mjs
```

Runs every vector in `../../conformance/vectors.json` and exits nonzero on
any failure. The vectors carry their own type definitions and enum snapshot,
so conformance never depends on mutable network state or the public registry's
current contents.
