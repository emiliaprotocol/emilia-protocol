// SPDX-License-Identifier: Apache-2.0
// Root-cause taxonomy for fuzz classes. A class key has the form
//   "op | lane | cause | oracle=<shape> | lane=<shape>[ | detail]"
// and a rule names the root cause for reporting. Classification never
// excuses a class: with the empty allow list every class fails CI. The
// rules name the pre-04 behaviors the harness was built to detect, so a run
// against a pre-04 tree reports them by name.

export const ROOT_CAUSES = [
  { id: "L1", match: /\| legacy front end$/, title: "The lane has no -04 JSON text entry points and was driven through a host JSON parser" },
  { id: "J1", match: /JSON text: duplicate member name/, title: "Duplicate member names accepted (last value wins) instead of malformed_json" },
  { id: "J2", match: /JSON text: not UTF-8/, title: "Octets that are not UTF-8 accepted (U+FFFD substitution or surrogate decoding) instead of malformed_json" },
  { id: "J3", match: /JSON text: byte order mark/, title: "A leading byte order mark ignored instead of malformed_json" },
  { id: "J4", match: /JSON text: (unexpected character|bad number|bad escape|trailing content|expected [a-z ]+|unterminated string|unexpected end of input|bad \\u escape)/, title: "Text outside RFC 8259 accepted, or refused with a reason other than malformed_json" },
  { id: "J5", match: /JSON text: unescaped control character/, title: "An unescaped control character accepted inside a string" },
  { id: "J6", match: /big-int-|[0-9]{4,}-digit|number (in|nested|canonicalize|verify)/, title: "A number literal the host parser cannot represent refused as a parse error instead of unsupported_number" },
  { id: "J7", match: /JSON text: nesting deeper than 64|deep-(array|object)-\d+|native deep/, title: "Nesting beyond 64 accepted, or a stack exhausted, instead of malformed_json (text) or unsupported_value (native)" },
  { id: "J8", match: /JSON text: unpaired (high|low) surrogate escape/, title: "An unpaired-surrogate escape decoded and refused later as unsupported_value instead of malformed_json" },
  { id: "J9", match: /JSON text: noncharacter|native noncharacter/, title: "A noncharacter accepted; I-JSON excludes it (malformed_json from text, unsupported_value native)" },
  { id: "N1", match: /native (opaque|cyclic|nan|infinity|-infinity|negative zero|lone|reversed|pair)/, title: "A host value outside the data model rewritten, thrown on, or ordered by traversal instead of refused in phase order" },
  { id: "A1", match: /\| crash$|=THROWS:/, title: "An implementation threw or panicked instead of refusing" },
  { id: "D1", match: /def-shape|definition shape|def-field-type|code field shape/, title: "A malformed or conflicting definition computed instead of refusing as invalid_definition" },
  { id: "C1", match: /\| code \||^[a-z]+ \| [a-z]+ \| code /, title: "The code field type or a named code format behaves differently from the oracle" },
  { id: "P1", match: /^parse \|/, title: "Strict parse differs from the oracle (for example unknown_suite for a grammatical unregistered suite)" },
  { id: "M1", match: /omitted_source_fields=null/, title: "omitted_source_fields: null read as [] instead of refused" },
  { id: "M2", match: /target_field=/, title: "A non-string or non-field-name target_field coerced or refused differently" },
  { id: "M3", match: /LF-joined|join collision/, title: "Rule sources compared with material paths as a joined string instead of as sets" },
  { id: "M4", match: /long [0-9a-f]+: \d+ UTF-16 units/, title: "Profile string limits counted in a unit other than UTF-8 octets" },
  { id: "M5", match: /target_action_type \d+ chars/, title: "target_action_type bounded differently from 512 UTF-8 octets" },
  { id: "M6", match: /suite=""/, title: "An empty mapping suite taken as the default instead of refused" },
  { id: "M8", match: /^(map|compare) \|/, title: "Mapping result or reason order differs from the -04 stage order" },
  { id: "R1", match: /\| detail$/, title: "Same outcome class, different detail: missing definition_sha256 or verification details, or a different reason order" },
];

export function rootCauseOf(key) {
  for (const rc of ROOT_CAUSES) if (rc.match.test(key)) return rc;
  return null;
}
