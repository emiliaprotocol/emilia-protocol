# CAID implementation (Python)

Python 3.11 or later, standard library only. Implements
draft-schrock-canonical-action-identifier-05. Grammar, code formats, limits,
reason ranks, field types and mapping rules come from `caid_spec.py`, which
`node caid/spec/gen.mjs --write` generates from `caid/spec/caid.abnf` and
`caid/spec/core.json`. Do not edit `caid_spec.py` by hand.

Suite support: `jcs-sha256` only. `cbor-sha256` is registered, so a
`cbor-sha256` CAID parses, but compute and verify refuse it as
`unknown_suite`. A grammatical suite outside the registry is `unknown_suite`
at parse.

Scope: a CAID proves that artifacts reference the same typed content. It
does not prove that an action was authorized, executed, safe or wise, and
nothing here verifies signatures, identity or authorization.

## Entry points

| Function | Input | Result |
|---|---|---|
| `decode_caid_json(data)` | action object or mapping source as `bytes` | `{"ok": True, "value"}` or `{"ok": False, "refusals": ["malformed_json"]}` |
| `decode_json_document(data)` | definition, registry, snapshot or profile as `bytes` | same, without the text size cap |
| `compute_caid_json(data, options)` | received JSON text | `{"caid", "digest", "definition_sha256"}` or `{"refusals"}` |
| `verify_caid_json(data, caid, options)` | received JSON text | `{"valid", "reasons", "details"}` plus `definition_sha256` when a definition resolved |
| `compute_caid(value, options)` | a value the application built | as `compute_caid_json` |
| `verify_caid(value, caid, options)` | a value the application built | as `verify_caid_json` |
| `parse_caid(caid)` | identifier string | `{"ok": True, "caid": {...}}` or one of `malformed_caid`, `unknown_suite` |
| `parse_legacy_caid_v04(caid)` | existing CAID-04 `caid:` identifier | the same parse result, explicitly profiled as legacy |
| `verify_legacy_caid_v04(value, caid, options)` | host value and existing CAID-04 identifier | normal verification without rewriting the identifier |
| `verify_legacy_caid_v04_json(data, caid, options)` | received JSON text and existing CAID-04 identifier | byte-path verification without rewriting the identifier |
| `definition_sha256(definition)` | type definition | `{"definition_sha256"}` or `{"refusals": ["invalid_definition"]}` |
| `canonicalize(value)` | data-model value | RFC 8785 text or `unsupported_number` / `unsupported_value` |

Options: `suite`, `definitions`, `enum_snapshots`, and for verify
`expected_definition_sha256` (a mismatch is `definition_mismatch`). An
option of the wrong type counts as absent; nothing raises.

Current compute, parse, and verify APIs use only `canactid:`. They fail closed
on `caid:`. The separately named legacy functions exist only to verify
already signed CAID-04 artifacts in place; there is no legacy compute API.

Received JSON text goes through the byte entry points. `json.loads` keeps
the last of two duplicate members, accepts `NaN`, a byte order mark and
UTF-16, and raises on a 5000-digit integer, so it must not stand in front of
`compute_caid`.

## Host values

`dict`, `list`, `str`, `int`, `float`, `bool` and `None` are the data model,
and subclasses are read through the base-class methods. Everything else is
refused, never rewritten: tuples, sets, bytes, other objects, non-`str` keys,
a string with an unpaired surrogate or a noncharacter, nesting beyond 64, and
cycles are `unsupported_value`; a number that is not a finite integer of
magnitude at most 2^53-1 is `unsupported_number`. `True` is never an
integer. The decoder and the canonicalizer are iterative, so no input depth
reaches the recursion limit.

## Example

```python
import caid

definitions = [{
    "action_type": "doc.sign.1",
    "required_fields": [
        {"name": "document_digest", "type": "digest"},
        {"name": "signer_ref", "type": "string"},
    ],
}]
text = (b'{"action_type":"doc.sign.1","document_digest":"sha256:'
        + b"ab" * 32 + b'","signer_ref":"u-7"}')
result = caid.compute_caid_json(text, {"suite": "jcs-sha256", "definitions": definitions})
check = caid.verify_caid_json(text, result["caid"], {"definitions": definitions})
assert check["valid"] and check["definition_sha256"] == result["definition_sha256"]
```

## Tests and conformance

```sh
python3 caid/impl/python/test_caid.py
python3 caid/conformance/runners/run.py            # core corpus v6 and grammar corpus
python3 caid/impl/python/run_mapping_vectors.py    # caid/conformance/mapping-vectors.json
python3 caid/impl/python/run_mapping_vectors.py --corpus caid/interop/consequential-action-v1/mapping-vectors.json
node caid/spec/abnf-check.mjs --out /tmp/grammar.json
python3 caid/impl/python/run_grammar_vectors.py --corpus /tmp/grammar.json
```

The shared runner `caid/conformance/runners/run.py` checks, for every compute
and verify vector given as JSON text that decodes, that the native entry point
returns the identical result.
`run_grammar_vectors.py` drives each grammar case through `parse_caid`,
`compute_caid` or `map_action`, never through the generated patterns.
