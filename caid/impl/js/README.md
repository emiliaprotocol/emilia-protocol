# CAID reference implementation (JavaScript)

Pure ESM, `node:crypto` only, zero dependencies. Implements
draft-schrock-canonical-action-identifier-04; the draft is the normative
text. The grammars, limits, reason codes, reason ranks, field types and
definition rules come from the generated region of `caid.mjs`, which
`node caid/spec/gen.mjs --write` compiles from the draft's ABNF
(`caid/spec/caid.abnf`), `caid/spec/core.json` and the suite registry. The
same command writes `packages/verify/vendor/caid.mjs` as a byte copy of
`caid.mjs`; `--check` fails on any difference. Never edit the region by hand.

Suite support: `jcs-sha256` only. `cbor-sha256` is registered, so its CAIDs
parse, but `computeCaid` and `verifyCaid` refuse it as `unknown_suite`. A
grammatical suite outside the registry is `unknown_suite` at parse.

Scope, stated plainly: CAID carries no trust semantics. A CAID proves that
artifacts reference the same typed content. It does not prove the action was
authorized, executed, safe, or wise. Nothing in this module verifies
signatures, identity, or authorization.

## Entry points

| Function | Input | Result |
|---|---|---|
| `computeCaidJson(bytes, options)` | received JSON text, as a `Uint8Array` | `{caid, digest, definition_sha256}` or `{refusals}` |
| `verifyCaidJson(bytes, caid, options)` | received JSON text | `{valid, reasons, details[, definition_sha256]}` |
| `decodeCaidJson(bytes)` | an action object or mapping source as text | `{ok: true, value}` or `{ok: false, refusals: ["malformed_json"]}` |
| `decodeCaidDocument(bytes)` | a definition, registry, enum snapshot or mapping profile as text | the same, without the size cap |
| `computeCaid(value, options)` | a value the application constructed | as `computeCaidJson` |
| `verifyCaid(value, caid, options)` | a value the application constructed | as `verifyCaidJson` |
| `parseCaid(string)` | an identifier | `{ok: true, caid}` or `{ok: false, refusals: [one reason]}` |
| `definitionSha256(definition)` | a type definition | `{definition_sha256}` or `{refusals: ["invalid_definition"]}` |
| `resolveCaidDefinition(type, definitions)` | an action type and definitions | `{ok: true, definition, definition_sha256}` or one refusal |
| `canonicalize(value)` | any document | `{ok: true, canonical}` or `{ok: false, refusals}` |
| `toCaidData(value)` | any host value | a data-model copy, or `unsupported_value` |

Options: `suite`, `definitions` and `enumSnapshots` for compute;
`definitions`, `enumSnapshots` and `expectedDefinitionSha256` for verify. An
option of the wrong type counts as absent. Every entry point refuses junk
with reasons and never throws.

**Received JSON text must go through the byte entry points.**
`computeCaid(JSON.parse(text))` is not conforming for received text:
`JSON.parse` keeps the last of duplicate member names, and decoding octets
to a string first substitutes U+FFFD for invalid UTF-8. The strict decoder
takes octets only (a string is refused, since re-encoding it would replace
lone surrogates) and refuses, as `malformed_json`: invalid UTF-8; a byte
order mark; anything other than exactly one JSON text and JSON whitespace;
duplicate member names after unescaping; a surrogate or noncharacter code
point in a string or member name, escaped or not (RFC 7493); nesting deeper
than 64; and an action object or mapping source over 33554432 octets.
Numbers are never refused by the decoder: a token's value is the correctly
rounded binary64 value (`1e400` overflows to infinity and then refuses as
`unsupported_number`; `1e-400` is the integer 0).

## Host values

The native entry points read a host value once into a copy of the data
model, iteratively, without invoking a getter, and refuse whatever is outside
it:

- accepted: `null`, booleans, numbers, strings, arrays with prototype
  `Array.prototype` that are dense with no extra properties, and objects with
  prototype `Object.prototype` or `null` whose members are own, enumerable,
  string-keyed data properties; an own member whose value is `undefined` is
  absent for field presence and refuses the value as `unsupported_value`;
- refused as `unsupported_value` (or `mistyped_field:<field>` when a declared
  field holds it): `Map`, `Set`, `Date`, typed arrays, boxed primitives, class
  instances, functions, symbols, bigints, accessors, non-enumerable members,
  symbol-keyed properties, holes and `undefined` in arrays, cycles, a `Proxy`
  (whose traps are never trusted: an object that contains one refuses), and
  containers nested deeper than 64.

For every value the strict decoder can produce, the native result equals the
byte result. A member named `__proto__` is an ordinary own member on both
paths. Strings with lone surrogates can only arrive through the native path;
they refuse as `unsupported_value`.

## Reasons

Compute runs two gates, each yielding exactly one reason and stopping:
`invalid_action_type`, then `unknown_action_type` or `invalid_definition`.
After them every check runs, and the reasons are deduplicated and ordered by
rank, then field position: `missing_material_field:<f>`; `mistyped_field`,
`invalid_amount` or `invalid_code` `:<f>` (one per field); `unknown_suite`;
`unsupported_number`; `unsupported_value` (which includes the nesting limit
and an RFC 8785 encoding over 16777216 octets). Verify runs the parse gate
(`malformed_caid` or `unknown_suite`), the JSON text gate on the byte path,
and `invalid_object` alone for a non-object; then `action_type_mismatch`,
`definition_mismatch`, `unknown_suite` or `digest_mismatch`, and
`invalid_object` when computation refuses. `details` holds one
`{reason, field, rule, observed}` per reason, except that `invalid_object`
is replaced by one detail per underlying compute reason.

A definition must conform (`required_fields` a non-empty array, unique field
names that are non-empty strings without `:` and not `action_type`, members
limited to those of the field's registered type), or computation refuses with
`invalid_definition`; so do two definitions of one type whose validation
projections differ. `status` never affects computation: deprecated types
resolve, compute and verify.

## Usage

```js
import { readFileSync } from "node:fs";
import { computeCaid, computeCaidJson, verifyCaid } from "./caid.mjs";

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

const options = { suite: "jcs-sha256", definitions, enumSnapshots: [iso4217] };
const out = computeCaid(action, options);
// { caid: "caid:1:payment.release.1:jcs-sha256:<b64url>", digest: "sha256:<hex>",
//   definition_sha256: "sha256:<hex>" }

const fromText = computeCaidJson(Buffer.from(JSON.stringify(action)), options);
// the same result, from the exact octets

const check = verifyCaid(action, out.caid, { definitions, enumSnapshots: [iso4217] });
// { valid: true, reasons: [], details: [], definition_sha256: "sha256:<hex>" }
```

Code inside this repository that uses the full registry definitions can import
`REGISTRY_ENUM_SNAPSHOTS`, `registryDefinition()` (any status) and
`activeRegistryDefinition()` from `caid/registry/enum-snapshots.mjs` instead of
naming value-set files or copying a registered definition. Next.js server code
uses `CAID_REGISTRY_ENUM_SNAPSHOTS` from `lib/caid-registry.ts`. Without a
snapshot, a present currency field refuses with `mistyped_field:currency`.

## Mapping profiles

`mapping.mjs` implements the Action-Mapping Profile of -04 Section 8:
`omitted_source_fields`, the `no-material-field-loss` and
`declared-source-semantic-loss` policies, the `copy`, `sha256-utf8`,
`sha256-jcs` and `sha256-hex-to-digest` transforms, limits in UTF-8 octets,
exactly one rule per source path, and the normative reason order: stage A
(profile checks, with a shape gate that yields exactly
`invalid_mapping_profile`), stage B (pin and source checks, sorted with A by
rank; the mapping stops if either produced a reason), stage C (one reason per
rule, in rule order), stage D (`mapped_action:<reason>` in compute order). A
comparison reports `left:` reasons, then `right:` reasons, then
`target_action_type_mismatch`, and `NOT_EQUIVALENT` carries
`material_projection_mismatch`. A source received as JSON text is decoded
with `decodeCaidJson` first.

## Tests

```
node --test unit-tests.mjs                      # unit tests
node run-vectors.mjs [--corpus FILE]            # core corpus v5, with native parity
node run-grammar-vectors.mjs [--corpus FILE]    # grammar cases through the public API
node run-mapping-vectors.mjs [--corpus FILE]    # mapping and interoperability corpora
```

The corpora are read with this port's strict decoder, except the grammar
case list, which carries lone-surrogate escapes on purpose.
`node caid/spec/abnf-check.mjs --out FILE` writes the full grammar case list.
