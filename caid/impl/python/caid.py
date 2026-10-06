# SPDX-License-Identifier: Apache-2.0
"""CAID v1, Python port (standard library only).

Implements draft-schrock-canonical-action-identifier-05. The rule data
(grammar, code formats, limits, reason ranks, field types, definition and
verification-detail rules) comes from caid_spec.py, which caid/spec/gen.mjs
generates from caid/spec/caid.abnf and caid/spec/core.json. Nothing here
translates a grammar by hand.

Suite support: jcs-sha256 only. cbor-sha256 is registered but not
implemented here, so compute and verify refuse it as unknown_suite.

Scope: a CAID proves that artifacts reference the same typed content. It
does not prove that an action was authorized, executed, safe or wise, and
nothing in this module verifies signatures, identity or authorization.

Entry points:

  decode_caid_json(data)            strict JSON text (Section 2.4) for an
                                    action object or mapping source
  decode_json_document(data)        the same decoder rules without the text
                                    size cap, for definitions, registries,
                                    enum snapshots and mapping profiles
  compute_caid_json(data, options)  compute over received JSON text
  verify_caid_json(data, caid, options)
  compute_caid(value, options)      compute over a value the application built
  verify_caid(value, caid, options)
  parse_caid(caid)
  parse_legacy_caid_v04(caid)        explicit obsolete-scheme parser
  verify_legacy_caid_v04(value, caid, options)
  verify_legacy_caid_v04_json(data, caid, options)
  definition_sha256(definition)
  canonicalize(value)               RFC 8785 over the data model

Every entry point returns a result and never raises for any input: host
values outside the data model (tuples, sets, bytes, non-str keys, cycles,
arbitrary objects) are refused, never rewritten. The decoder and the
canonicalizer are iterative, so input depth never reaches the interpreter's
recursion limit.
"""

import base64
import hashlib
import re

try:  # imported as part of a package
    from . import caid_spec as _generated
except ImportError:  # imported with this directory on sys.path
    import caid_spec as _generated

SPEC = _generated.SPEC
PATTERNS = _generated.PATTERNS
CODE_FORMATS = _generated.CODE_FORMATS
SUITE_DIGEST_PATTERNS = _generated.SUITE_DIGEST_PATTERNS
LIMITS = _generated.LIMITS

CAID_VERSION = SPEC["identifier"]["version"]
LEGACY_CAID_V04_SCHEME = SPEC["identifier"]["legacy_v04_scheme"]
SUPPORTED_SUITES = frozenset(["jcs-sha256"])
REGISTERED_SUITE_DIGEST_OCTETS = dict(_generated.SUITE_DIGEST_OCTETS)

MAX_SAFE_INTEGER = LIMITS["max_safe_integer"]
MAX_NESTING_DEPTH = LIMITS["nesting_depth"]
MAX_JSON_TEXT_OCTETS = LIMITS["json_text_octets"]
MAX_CANONICAL_OCTETS = LIMITS["canonical_octets"]

# Section 2.6: canonicalization reads at most value_count values, counting a
# value once for every path that reaches it, and refuses a value past that
# as unsupported_value alone; a document with no canonical limit of its own
# (a definition, value set, mapping profile or source) takes the ceiling
# document_canonical_octets. No value the decoder produces from a text
# within MAX_JSON_TEXT_OCTETS reaches either bound; they stop a native value
# with shared substructure from growing without limit.
_VALUE_BUDGET = LIMITS["value_count"]
_DOCUMENT_CANONICAL_OCTETS = LIMITS["document_canonical_octets"]
_PATTERN_MAX_OCTETS = SPEC["pattern_max_octets"]

_MALFORMED_JSON = "malformed_json"
_FIELD_TYPES = {t["type"]: t for t in SPEC["field_types"]}
_UNKNOWN_FIELD_TYPE_REFUSAL = SPEC["unknown_field_type_refusal"]
_DEFINITION = SPEC["definition"]
_FIELD_NAME = _DEFINITION["field_name"]
_FORBIDDEN_NAME_CHARS = frozenset(chr(cp) for cp in _FIELD_NAME["forbidden_code_points"])
_RESERVED_NAMES = frozenset(_FIELD_NAME["reserved"])
_COMMON_MEMBERS = frozenset(_DEFINITION["field_common_members"])
_PROJECTION = _DEFINITION["projection"]
_EXCLUDED_FIELD_MEMBERS = frozenset(_PROJECTION["field_members_excluded"])
_ENUM = SPEC["enum"]
_COMPUTE_RANK = SPEC["sort_rank"]["compute"]
_VERIFY_RANK = SPEC["sort_rank"]["verify"]
_VERIFY_DETAILS = SPEC["verify_details"]["reasons"]
_DETAIL_EXPAND_OMIT = frozenset(SPEC["verify_details"]["expand"]["invalid_object"]["omit"])
_DATE = SPEC["timestamp_date_offsets"]

# A string outside the data model: an unpaired surrogate (not a Unicode
# scalar value, RFC 8785 section 3.2.2.2) or a noncharacter (I-JSON,
# RFC 7493 section 2.1, which the draft profiles wholesale). The
# noncharacter ranges are generated from core.json.
_NONCHARACTERS = "".join(
    re.escape(chr(lo)) + "-" + re.escape(chr(hi)) for lo, hi in SPEC["json_text"]["noncharacter_ranges"]
)
_NONCHARACTER_RE = re.compile("[" + _NONCHARACTERS + "]")
_OUTSIDE_MODEL_RE = re.compile("[\ud800-\udfff" + _NONCHARACTERS + "]")
_LONE_SURROGATE_RE = re.compile("[\ud800-\udfff]")


def _outside_model(text):
    """True for a str that is not a data-model string. An ASCII string never
    holds a surrogate or a noncharacter, so it skips the search."""
    return not text.isascii() and _OUTSIDE_MODEL_RE.search(text) is not None


def _has_noncharacter(text):
    return not text.isascii() and _NONCHARACTER_RE.search(text) is not None


def _has_lone_surrogate(text):
    return not text.isascii() and _LONE_SURROGATE_RE.search(text) is not None


def _is(value, cls):
    """isinstance by the value's real type. A value can report any class as
    its __class__ (unittest.mock does), which isinstance believes; the base
    methods this module reads through would then raise. type() cannot be
    spoofed."""
    return issubclass(type(value), cls)


def _match(pattern_id, text):
    """Whole-string match of a generated pattern, with its length limit, if
    it has one, checked first (Section 2.6). Every string such a pattern
    matches is ASCII, so its length in code points is its length in
    octets."""
    limit = _PATTERN_MAX_OCTETS.get(pattern_id)
    if limit is not None and len(text) > limit:
        return False
    return PATTERNS[pattern_id].match(text) is not None


class _Absent:
    """Marks an argument the caller did not supply."""

    __slots__ = ()

    def __repr__(self):
        return "<absent>"


_ABSENT = _Absent()


# ---------------------------------------------------------------------------
# Host values: read through the base-class methods only, so a subclass that
# overrides items(), __iter__, __eq__ or __str__ cannot change what is read
# or make a lookup raise.
# ---------------------------------------------------------------------------


def _plain_str(value):
    """The exact str behind a str (or str subclass); None for anything else."""
    return str.__str__(value) if _is(value, str) else None


def _members(obj):
    """The str-keyed members of a dict (or subclass) as a plain dict.

    Keys that are not strings are left out here; canonicalization refuses
    them as unsupported_value.
    """
    out = {}
    for key, value in dict.items(obj):
        if _is(key, str):
            key = str.__str__(key)
            if key not in out:
                out[key] = value
    return out


def _seq(value):
    """The elements of a list (or subclass) as a tuple; None otherwise."""
    return tuple(list.__iter__(value)) if _is(value, list) else None


def _kind(value):
    """The data-model kind of a host value, or None outside the model."""
    if value is None:
        return "null"
    if value is True or value is False:
        return "boolean"
    if _is(value, (int, float)):
        return "number"
    if _is(value, str):
        return "string"
    if _is(value, list):
        return "array"
    if _is(value, dict):
        return "object"
    return None


def _is_integer_value(value):
    """JavaScript Number.isInteger over the binary64 value of a number.

    12, 12.0 and 1.2e1 are the integer 12. An int too large for binary64 is
    infinite there, so it is not an integer.
    """
    if value is True or value is False:
        return False
    if _is(value, int):
        try:
            float(int.__int__(value))
        except OverflowError:
            return False
        return True
    if _is(value, float):
        return float.__float__(value).is_integer()
    return False


def _utf8_octets(text):
    """UTF-8 length in octets, or None for a string with a lone surrogate."""
    if text.isascii():
        return len(text)
    if _LONE_SURROGATE_RE.search(text):
        return None
    return len(text.encode("utf-8"))


def _is_field_name(name):
    """ABNF field-name: one or more scalar values, none of them ":"."""
    return (
        _is(name, str)
        and len(name) >= _FIELD_NAME["min_length"]
        and not _has_lone_surrogate(name)
        and not any(ch in _FORBIDDEN_NAME_CHARS for ch in name)
    )


# ---------------------------------------------------------------------------
# Strict JSON text decoder (Section 2.4). I-JSON [RFC7493] plus: no byte
# order mark, exactly one text, no unpaired-surrogate escapes, nesting at
# most 64. Numbers are never refused here: a token's value is its correctly
# rounded binary64 value (float(token)); overflow is infinite and underflow
# is 0, and the data model decides whether the value is accepted. The
# parser keeps an explicit stack and never recurses.
# ---------------------------------------------------------------------------


class _Refused(Exception):
    pass


_BOM = bytes(SPEC["json_text"]["byte_order_mark"])
_WS = re.compile("[" + "".join(re.escape(chr(c)) for c in SPEC["json_text"]["whitespace"]) + "]*").match
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?").match
_STRING_CHUNK = re.compile(r'([^"\\\x00-\x1f]*)(.?)', re.S).match
_HEX4 = re.compile(r"[0-9A-Fa-f]{4}").fullmatch
_SIMPLE_ESCAPES = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


def _hex4(text, i):
    digits = text[i:i + 4]
    if _HEX4(digits) is None:
        raise _Refused
    return int(digits, 16)


def _scan_string(text, i, keep):
    """Scans a string body starting after its opening quote."""
    parts = []
    while True:
        m = _STRING_CHUNK(text, i)
        chunk, term = m.group(1), m.group(2)
        if chunk:
            parts.append(chunk)
        i = m.end()
        if term == '"':
            break
        if term != "\\":  # an unescaped control character, or the end of input
            raise _Refused
        escape = text[i:i + 1]
        if escape == "u":
            cp = _hex4(text, i + 1)
            i += 5
            if 0xD800 <= cp <= 0xDBFF and text.startswith("\\u", i):
                low = _hex4(text, i + 2)
                if 0xDC00 <= low <= 0xDFFF:
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00)
                    i += 6
            if 0xD800 <= cp <= 0xDFFF and not keep:
                raise _Refused
            parts.append(chr(cp))
        else:
            ch = _SIMPLE_ESCAPES.get(escape)
            if ch is None:
                raise _Refused
            parts.append(ch)
            i += 1
    text_value = "".join(parts)
    if not keep and _has_noncharacter(text_value):
        raise _Refused
    return text_value, i


def _number(token):
    value = float(token)
    if value.is_integer() and -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
        return int(value)  # -0 is the integer 0
    return value


def _member_name(text, i, keep, frame):
    if not text.startswith('"', i):
        raise _Refused
    name, i = _scan_string(text, i + 1, keep)
    if name in frame[0]:  # the same code points after unescaping
        raise _Refused
    frame[2] = name
    i = _WS(text, i).end()
    if not text.startswith(":", i):
        raise _Refused
    return _WS(text, i + 1).end()


def _parse(text, keep, max_depth):
    n = len(text)
    stack = []  # open containers: [container, is_object, pending member name]
    i = _WS(text, 0).end()
    while True:
        c = text[i:i + 1]
        if c == "{" or c == "[":
            if max_depth is not None and len(stack) >= max_depth:
                raise _Refused
            i = _WS(text, i + 1).end()
            if c == "{":
                if text.startswith("}", i):
                    value = {}
                    i += 1
                else:
                    frame = [{}, True, None]
                    i = _member_name(text, i, keep, frame)
                    stack.append(frame)
                    continue
            elif text.startswith("]", i):
                value = []
                i += 1
            else:
                stack.append([[], False, None])
                continue
        elif c == '"':
            value, i = _scan_string(text, i + 1, keep)
        elif c == "t" and text.startswith("true", i):
            value = True
            i += 4
        elif c == "f" and text.startswith("false", i):
            value = False
            i += 5
        elif c == "n" and text.startswith("null", i):
            value = None
            i += 4
        else:
            m = _NUMBER(text, i)
            if m is None:
                raise _Refused
            value = _number(m.group())
            i = m.end()
        while True:
            if not stack:
                if _WS(text, i).end() != n:
                    raise _Refused
                return value
            frame = stack[-1]
            container = frame[0]
            if frame[1]:
                container[frame[2]] = value
            else:
                container.append(value)
            i = _WS(text, i).end()
            c = text[i:i + 1]
            if c == ",":
                i = _WS(text, i + 1).end()
                if frame[1]:
                    i = _member_name(text, i, keep, frame)
                break
            if c == ("}" if frame[1] else "]"):
                i += 1
                stack.pop()
                value = container
                continue
            raise _Refused


def _decode(data, max_octets, keep=False):
    if not _is(data, (bytes, bytearray)):
        return {"ok": False, "refusals": [_MALFORMED_JSON]}
    # The size is checked before anything is copied (rule 1).
    if max_octets is not None and len(memoryview(data)) > max_octets:
        return {"ok": False, "refusals": [_MALFORMED_JSON]}
    raw = data if type(data) is bytes else bytes(memoryview(data))
    if raw.startswith(_BOM):
        return {"ok": False, "refusals": [_MALFORMED_JSON]}
    try:
        text = raw.decode("utf-8")  # strict: refuses overlongs, surrogates, truncation
    except UnicodeDecodeError:
        return {"ok": False, "refusals": [_MALFORMED_JSON]}
    # The process-wide garbage collector is left alone: pausing it here
    # would change it for every other thread of the application.
    try:
        value = _parse(text, keep, None if keep else MAX_NESTING_DEPTH)
    except _Refused:
        return {"ok": False, "refusals": [_MALFORMED_JSON]}
    return {"ok": True, "value": value}


def decode_caid_json(data):
    """Decodes an action object or mapping source received as JSON text.

    data must be bytes or bytearray. Returns {"ok": True, "value": v} or
    {"ok": False, "refusals": ["malformed_json"]}. Applies every Section 2.4
    rule, including the 33,554,432-octet text limit.
    """
    return _decode(data, MAX_JSON_TEXT_OCTETS)


def decode_json_document(data):
    """Decodes a definition, registry, enum snapshot or mapping profile.

    The same decoder rules as decode_caid_json, without the text size cap.
    """
    return _decode(data, None)


def _decode_corpus_json(data):
    """For conformance runners only: the strict decoder, except that
    unpaired-surrogate escapes and noncharacters are kept and nesting is not
    bounded, so a corpus can carry the host values a native-path vector
    needs. Never use it on received input."""
    return _decode(data, None, keep=True)


# ---------------------------------------------------------------------------
# Canonicalization: RFC 8785 over the data model (Section 2.2), iterative.
# Numbers must be finite integers of magnitude at most 2^53-1 and serialize
# in plain decimal; strings must be scalar-value, noncharacter-free text;
# objects have unique str member names sorted by UTF-16 code units; nesting
# is at most 64. Outside the model: unsupported_number for a number,
# unsupported_value for anything else, in that fixed order. A container
# beyond the depth limit, or one already open on the current path (a cycle),
# is refused without visiting anything inside it.
# ---------------------------------------------------------------------------

_ESCAPE_RE = re.compile('[\x00-\x1f"\\\\]')
_SHORT_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}


def _escape(match):
    ch = match.group()
    return _SHORT_ESCAPES.get(ch) or "\\u%04x" % ord(ch)


def _quote(text):
    return '"' + _ESCAPE_RE.sub(_escape, text) + '"'


def _utf16_order(item):
    return item[0].encode("utf-16-be", "surrogatepass")


def _object_items(obj):
    items = []
    seen = set()
    outside = False
    for key, value in dict.items(obj):
        if not _is(key, str):
            outside = True
            continue
        key = str.__str__(key)
        if key in seen:  # two str-subclass keys with the same text
            outside = True
            continue
        seen.add(key)
        if _outside_model(key):
            outside = True
        items.append((key, value))
    items.sort(key=_utf16_order)
    return items, outside


def _canonicalize(value, cap):
    """Returns (canonical text or None, refusals).

    cap is the canonical-size limit in octets (the action-object limit for
    compute and verify), or None for a document, which takes the document
    ceiling. Past the value budget the value is unsupported_value alone.

    Values count once for every path that reaches them, so the budget is
    that of the expansion. A container reached through several paths is
    traversed once: when nothing inside it was cut short (by the depth limit
    or a cycle), a later path that reaches it where it still fits within the
    depth limit reuses its count, its flags and its text, so a value with
    shared references costs its distinct containers, not its expansion.
    """
    limit = _DOCUMENT_CANONICAL_OCTETS if cap is None else cap
    parts = []
    size = 0
    emit = True
    bad_number = 0  # event counters, so a frame can tell what happened inside it
    outside = 0
    cut = 0
    visited = 0
    ancestors = set()
    memo = {}  # id -> (count, height, bad, out, parts start, parts end, octets)
    # frame: [items, next index, id, is_object, visited at entry, bad_number,
    #         outside, cut, parts start, size, emitting, height]
    stack = []
    pending = value
    have_pending = True
    while True:
        if have_pending:
            have_pending = False
            v = pending
            visited += 1
            if visited > _VALUE_BUDGET:
                return None, ["unsupported_value"]
            chunk = None
            if v is None:
                chunk = "null"
            elif v is True:
                chunk = "true"
            elif v is False:
                chunk = "false"
            elif _is(v, int):
                n = v if type(v) is int else int.__int__(v)
                if -MAX_SAFE_INTEGER <= n <= MAX_SAFE_INTEGER:
                    chunk = str(n)
                else:
                    bad_number += 1
            elif _is(v, float):
                f = v if type(v) is float else float.__float__(v)
                if f.is_integer() and -MAX_SAFE_INTEGER <= f <= MAX_SAFE_INTEGER:
                    chunk = str(int(f))
                else:
                    bad_number += 1
            elif _is(v, str):
                s = v if type(v) is str else str.__str__(v)
                if _outside_model(s):
                    outside += 1
                elif emit:
                    chunk = _quote(s)
            elif _is(v, (list, dict)):
                vid = id(v)
                depth = len(stack)
                if depth >= MAX_NESTING_DEPTH or vid in ancestors:
                    outside += 1
                    cut += 1
                else:
                    known = memo.get(vid)
                    if known is not None and depth + known[1] <= MAX_NESTING_DEPTH:
                        count, height, bad, out, first, last, octets = known
                        visited += count - 1
                        if visited > _VALUE_BUDGET:
                            return None, ["unsupported_value"]
                        bad_number += bad
                        outside += out
                        if bad or out:
                            emit = False
                        elif emit:
                            parts.extend(parts[first:last])
                            size += octets
                            if size > limit:
                                emit = False
                        if stack and height + 1 > stack[-1][11]:
                            stack[-1][11] = height + 1
                    else:
                        frame = [None, 0, vid, False, visited, bad_number, outside, cut,
                                 len(parts), size, False, 1]
                        if _is(v, list):
                            frame[0] = tuple(list.__iter__(v))
                            chunk = "["
                        else:
                            frame[0], bad_keys = _object_items(v)
                            if bad_keys:
                                outside += 1
                            frame[3] = True
                            chunk = "{"
                        stack.append(frame)
                        ancestors.add(vid)
            else:
                outside += 1
            if bad_number or outside:
                # Output stops, but the traversal goes on: whether the value
                # passes the value budget depends on every value it holds.
                emit = False
            if emit and chunk is not None:
                parts.append(chunk)
                size += len(chunk) if chunk.isascii() else len(chunk.encode("utf-8"))
                if size > limit:
                    emit = False
            if stack and stack[-1][4] == visited and chunk in ("[", "{"):
                stack[-1][10] = emit  # the container's text is being written
        if not stack:
            break
        frame = stack[-1]
        items, index = frame[0], frame[1]
        if index < len(items):
            frame[1] = index + 1
            if frame[3]:
                key, pending = items[index]
                if emit:
                    chunk = ("," if index else "") + _quote(key) + ":"
                    parts.append(chunk)
                    size += len(chunk) if chunk.isascii() else len(chunk.encode("utf-8"))
            else:
                pending = items[index]
                if emit and index:
                    parts.append(",")
                    size += 1
            if size > limit:
                emit = False
            have_pending = True
        else:
            stack.pop()
            ancestors.discard(frame[2])
            if emit:
                parts.append("}" if frame[3] else "]")
                size += 1
                if size > limit:
                    emit = False
            if cut == frame[7]:
                # Nothing inside was cut short, so another path may reuse it.
                # Its text is reusable only if all of it was written.
                written = frame[10] and emit
                memo[frame[2]] = (
                    visited - frame[4] + 1,
                    frame[11],
                    1 if bad_number > frame[5] else 0,
                    1 if outside > frame[6] else 0,
                    frame[8],
                    len(parts) if written else frame[8],
                    size - frame[9] if written else 0,
                )
            if stack and frame[11] + 1 > stack[-1][11]:
                stack[-1][11] = frame[11] + 1
    if not bad_number and not outside and size > limit:
        outside = 1
    refusals = []
    if bad_number:
        refusals.append("unsupported_number")
    if outside:
        refusals.append("unsupported_value")
    if refusals:
        return None, refusals
    return "".join(parts), refusals


def canonicalize(value):
    """canonicalize(value) -> {"ok": True, "canonical": str}
                            | {"ok": False, "refusals": [str]}

    RFC 8785 over the data model. Refusals, in this order:
      unsupported_number  a number that is not a finite integer of
                          magnitude at most 2^53-1
      unsupported_value   anything else outside the data model: a string
                          with an unpaired surrogate or a noncharacter, a
                          non-str member name, nesting beyond 64, a cycle,
                          a host value that is not dict, list, str, int,
                          float, bool or None, more values than the value
                          budget (then alone), or an encoding longer than
                          134,217,728 octets
    The action-object size limit applies in compute and verify, not here.
    """
    canonical, refusals = _canonicalize(value, None)
    if refusals:
        return {"ok": False, "refusals": refusals}
    return {"ok": True, "canonical": canonical}


def _sha256(text):
    return hashlib.sha256(text.encode("utf-8")).digest()


def _b64url(digest_bytes):
    return base64.urlsafe_b64encode(digest_bytes).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# Definitions: conformance, digest and resolution (Section 4.2).
# ---------------------------------------------------------------------------


class _Resolved:
    __slots__ = ("required", "optional", "sha256")

    def __init__(self, required, optional, sha256):
        self.required = required
        self.optional = optional
        self.sha256 = sha256


def _projection_entry(entry):
    # Raw keys are kept, so a non-str key makes the projection refuse.
    return {k: v for k, v in dict.items(entry) if _plain_str(k) not in _EXCLUDED_FIELD_MEMBERS}


def _conform(members):
    """The resolved field views and definition_sha256 of a conforming
    definition, or None when it does not conform."""
    action_type = _plain_str(members.get("action_type"))
    if action_type is None or not _match("action_type", action_type):
        return None
    lists = {}
    for list_name in _DEFINITION["field_lists"]:
        if list_name in members:
            entries = _seq(members[list_name])
        elif list_name in _PROJECTION["defaults"]:
            entries = tuple(_PROJECTION["defaults"][list_name])
        else:
            entries = None
        if entries is None:
            return None
        lists[list_name] = entries
    required = lists["required_fields"]
    optional = lists["optional_fields"]
    if len(required) < _DEFINITION["required_fields_min"]:
        return None
    names = set()
    views = []
    for entry in required + optional:
        if not _is(entry, dict):
            return None
        view = _members(entry)
        name = _plain_str(view.get("name"))
        if not _is_field_name(name) or name in _RESERVED_NAMES or name in names:
            return None
        names.add(name)
        field_type = _plain_str(view.get("type"))
        if field_type is None:
            return None
        spec = _FIELD_TYPES.get(field_type)
        if spec is not None:
            allowed = _COMMON_MEMBERS.union(spec["members"])
            if any(key not in allowed for key in view):
                return None
            for member, pattern in spec["required_members"].items():
                text = _plain_str(view.get(member))
                if text is None or not _match(pattern, text):
                    return None
        view["name"] = name
        view["type"] = field_type
        views.append(view)
    projection = {
        "action_type": action_type,
        "required_fields": [_projection_entry(e) for e in required],
        "optional_fields": [_projection_entry(e) for e in optional],
    }
    canonical, refusals = _canonicalize(projection, None)
    if refusals:
        return None
    digest = _PROJECTION["prefix"] + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return _Resolved(views[:len(required)], views[len(required):], digest)


def _resolve(action_type, definitions):
    """Resolution (Section 4.2.3): unknown_action_type, invalid_definition,
    or the one definition whose action_type matches."""
    candidates = []
    for entry in definitions:
        if _is(entry, dict):
            members = _members(entry)
            if _plain_str(members.get("action_type")) == action_type:
                candidates.append(members)
    if not candidates:
        return _DEFINITION["resolution"]["none"]
    resolved = None
    digests = set()
    for members in candidates:
        conforming = _conform(members)
        if conforming is None:
            return _DEFINITION["resolution"]["nonconforming"]
        digests.add(conforming.sha256)
        if resolved is None:
            resolved = conforming
    if len(digests) != 1:
        return _DEFINITION["resolution"]["conflict"]
    return resolved


def definition_sha256(definition):
    """definition_sha256(definition) -> {"definition_sha256": "sha256:<hex>"}
                                      | {"refusals": ["invalid_definition"]}

    SHA-256 over the RFC 8785 encoding of the validation projection:
    action_type, required_fields and optional_fields (absent is []), with
    each field entry's notes member removed.
    """
    refusal = SPEC["results"]["definition_sha256"]["refusal"]
    if not _is(definition, dict):
        return {"refusals": [refusal]}
    conforming = _conform(_members(definition))
    if conforming is None:
        return {"refusals": [refusal]}
    return {"definition_sha256": conforming.sha256}


# ---------------------------------------------------------------------------
# Field validation (Section 4.3) and enum resolution (Section 4.4).
# ---------------------------------------------------------------------------


def _valid_enum_values(values):
    if values is None or not values:
        return False
    plain = [_plain_str(v) for v in values]
    return all(v is not None and len(v) > 0 for v in plain) and len(set(plain)) == len(plain)


def _trim_inline_member(member):
    trim = "".join(_ENUM["inline_trim"])
    return member.strip(trim)


def _resolve_enum(field, snapshots):
    """The closed, integrity-checked value list of an enum field, or None.

    A member written as null is present and malformed, never absent.
    """
    has_ref = "values_ref" in field
    has_values = "values" in field
    ref = _plain_str(field.get("values_ref"))
    declared = _seq(field.get("values")) if has_values else None
    prefix = _ENUM["inline_prefix"]
    if ref is not None and ref.startswith(prefix):
        values = tuple(_trim_inline_member(m) for m in ref[len(prefix):].split(_ENUM["inline_separator"]))
        if not _valid_enum_values(values):
            return None
        if has_values and (declared is None or tuple(_plain_str(v) for v in declared) != values):
            return None
        return values
    if not has_ref:
        return tuple(_plain_str(v) for v in declared) if _valid_enum_values(declared) else None
    snapshot_name = _plain_str(field.get("values_snapshot"))
    pinned = _plain_str(field.get("values_sha256"))
    if not ref or not snapshot_name or pinned is None or not _match("digest_field", pinned):
        return None
    if not has_values:
        for snapshot in snapshots:
            if not _is(snapshot, dict):
                continue
            s = _members(snapshot)
            if (
                _plain_str(s.get("values_ref")) == ref
                and _plain_str(s.get("values_snapshot")) == snapshot_name
                and _plain_str(s.get("values_sha256")) == pinned
            ):
                declared = _seq(s.get("values"))
                break
    if not _valid_enum_values(declared):
        return None
    values = [_plain_str(v) for v in declared]
    canonical, refusals = _canonicalize(values, None)
    if refusals:
        return None
    actual = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return tuple(values) if actual == pinned else None


def _days_in_month(year, month):
    if month == 2:
        return 29 if (year % 4 == 0 and year % 100 != 0) or year % 400 == 0 else 28
    return 30 if month in (4, 6, 9, 11) else 31


def _within_month(text):
    year = int(text[_DATE["year"][0]:_DATE["year"][1]])
    month = int(text[_DATE["month"][0]:_DATE["month"][1]])
    day = int(text[_DATE["day"][0]:_DATE["day"][1]])
    return day <= _days_in_month(year, month)


def _check_field(value, field, snapshots):
    """None when the value is valid for the field, else the reason code."""
    spec = _FIELD_TYPES.get(field["type"])
    if spec is None:
        return _UNKNOWN_FIELD_TYPE_REFUSAL
    kind = _kind(value)
    if spec["json"] == "number":
        return None if kind == "number" and _is_integer_value(value) else "mistyped_field"
    if kind != spec["json"]:
        return "mistyped_field"
    if kind != "string":
        return None
    text = str.__str__(value)
    if spec["type"] == "enum":
        values = _resolve_enum(field, snapshots)
        return None if values is not None and text in values else "mistyped_field"
    if spec["type"] == "code":
        matcher = CODE_FORMATS.get(_plain_str(field.get("format")))
        if matcher is None:
            return spec["unregistered_format_refusal"]
        return None if matcher.match(text) else spec["format_refusal"]
    pattern = spec.get("pattern")
    if pattern is not None:
        if not _match(pattern, text):
            return spec["pattern_refusal"]
        if spec.get("calendar_check") == "day_within_month" and not _within_month(text):
            return spec["pattern_refusal"]
    return None


# ---------------------------------------------------------------------------
# Options: each is read with a type guard; a wrong type counts as absent.
# ---------------------------------------------------------------------------


def _options(options):
    """The options, each read with a type guard: a suite, definitions or
    enum_snapshots of the wrong type counts as absent. An expected
    definition_sha256 is supplied whenever its member is present, whatever
    its value, including None; a value that is not a str can never equal a
    definition_sha256, so a pin of the wrong type fails closed."""
    members = _members(options) if _is(options, dict) else {}
    definitions = _seq(members.get("definitions"))
    snapshots = _seq(members.get("enum_snapshots"))
    pinned = "expected_definition_sha256" in members
    return {
        "suite": _plain_str(members.get("suite")),
        "definitions": definitions if definitions is not None else (),
        "enum_snapshots": snapshots if snapshots is not None else (),
        "pinned": pinned,
        "expected_definition_sha256": _plain_str(members.get("expected_definition_sha256")) if pinned else None,
    }


# ---------------------------------------------------------------------------
# Computation (Section 5).
# ---------------------------------------------------------------------------


class _Evaluation:
    __slots__ = ("refusals", "resolved", "canonical", "action_type")

    def __init__(self, refusals, resolved=None, canonical=None, action_type=None):
        self.refusals = refusals
        self.resolved = resolved
        self.canonical = canonical
        self.action_type = action_type


def _order(found):
    found.sort(key=lambda item: (item[0], item[1]))
    out = []
    seen = set()
    for _, _, reason in found:
        if reason not in seen:
            seen.add(reason)
            out.append(reason)
    return out


def _evaluate(obj, opts, check_suite, canonical_result=None):
    """The compute phases after the entry gate. Gates (phases 1 and 2) yield
    exactly one reason; after them every check runs and the reasons are
    sorted by (phase rank, field position) and deduplicated."""
    if not _is(obj, dict):
        return _Evaluation(["invalid_action_type"])
    members = _members(obj)
    action_type = _plain_str(members.get("action_type"))
    if action_type is None or not _match("action_type", action_type):
        return _Evaluation(["invalid_action_type"])
    resolved = _resolve(action_type, opts["definitions"])
    if _is(resolved, str):
        return _Evaluation([resolved], action_type=action_type)
    found = []
    for position, field in enumerate(resolved.required):
        if field["name"] not in members:
            found.append((_COMPUTE_RANK["missing_material_field"], position, "missing_material_field:" + field["name"]))
    for position, field in enumerate(resolved.required + resolved.optional):
        name = field["name"]
        if name in members:
            code = _check_field(members[name], field, opts["enum_snapshots"])
            if code is not None:
                found.append((_COMPUTE_RANK[code], position, code + ":" + name))
    if check_suite and opts["suite"] not in SUPPORTED_SUITES:
        found.append((_COMPUTE_RANK["unknown_suite"], 0, "unknown_suite"))
    canonical, refusals = canonical_result if canonical_result is not None else _canonicalize(obj, MAX_CANONICAL_OCTETS)
    for code in refusals:
        found.append((_COMPUTE_RANK[code], 0, code))
    return _Evaluation(_order(found), resolved, canonical, action_type)


def compute_caid(action_object, options=None):
    """compute_caid(value, {"suite": ..., "definitions": [...],
                            "enum_snapshots": [...]})
      -> {"caid": str, "digest": "sha256:<hex>", "definition_sha256": str}
      -> {"refusals": [str]}

    For a value the application constructed. Received JSON text goes
    through compute_caid_json instead.
    """
    opts = _options(options)
    evaluation = _evaluate(action_object, opts, check_suite=True)
    if evaluation.refusals:
        return {"refusals": evaluation.refusals}
    digest_bytes = _sha256(evaluation.canonical)
    return {
        "caid": "%s:%s:%s:%s:%s" % (SPEC["identifier"]["scheme"], CAID_VERSION, evaluation.action_type, opts["suite"], _b64url(digest_bytes)),
        "digest": "sha256:" + digest_bytes.hex(),
        "definition_sha256": evaluation.resolved.sha256,
    }


def compute_caid_json(data, options=None):
    """compute_caid over an action object received as JSON text (bytes)."""
    decoded = decode_caid_json(data)
    if not decoded["ok"]:
        return {"refusals": decoded["refusals"]}
    return compute_caid(decoded["value"], options)


# ---------------------------------------------------------------------------
# Parsing (Section 3.4): exactly one reason.
# ---------------------------------------------------------------------------


def parse_caid(caid_input):
    """parse_caid(caid)
      -> {"ok": True, "caid": {"version", "action_type", "suite", "digest"}}
      -> {"ok": False, "refusals": ["malformed_caid" | "unknown_suite"]}

    Checks, in order: the caid ABNF, with the identifier and its action
    type within their length limits (malformed_caid); the suite is
    registered (unknown_suite); the digest matches the suite's digest
    syntax (malformed_caid). No trimming, case folding or normalization.
    """
    text = _plain_str(caid_input)
    if text is None or not _match("caid", text):
        return {"ok": False, "refusals": ["malformed_caid"]}
    _, version, action_type, suite, digest = text.split(SPEC["identifier"]["separator"])
    if not _match("action_type", action_type):
        return {"ok": False, "refusals": ["malformed_caid"]}
    digest_pattern = SUITE_DIGEST_PATTERNS.get(suite)
    if digest_pattern is None:
        return {"ok": False, "refusals": ["unknown_suite"]}
    if digest_pattern.match(digest) is None:
        return {"ok": False, "refusals": ["malformed_caid"]}
    return {
        "ok": True,
        "caid": {"version": version, "action_type": action_type, "suite": suite, "digest": digest},
    }


def parse_legacy_caid_v04(caid_input):
    """Strictly parse the obsolete ``caid:1:`` CAID-04 spelling.

    This explicit compatibility entry point is verification-only. New
    issuance and the default parser use ``canactid:`` and refuse ``caid:``.
    """
    text = _plain_str(caid_input)
    octets = _utf8_octets(text) if text is not None else None
    if octets is None or octets > LIMITS["caid_octets"]:
        return {"ok": False, "refusals": ["malformed_caid"]}
    parts = text.split(SPEC["identifier"]["separator"])
    if (len(parts) != SPEC["identifier"]["parts"] or
            parts[0] != LEGACY_CAID_V04_SCHEME or parts[1] != CAID_VERSION):
        return {"ok": False, "refusals": ["malformed_caid"]}
    _, version, action_type, suite, digest = parts
    if not (_match("action_type", action_type) and _match("suite", suite) and _match("digest", digest)):
        return {"ok": False, "refusals": ["malformed_caid"]}
    digest_pattern = SUITE_DIGEST_PATTERNS.get(suite)
    if digest_pattern is None:
        return {"ok": False, "refusals": ["unknown_suite"]}
    if digest_pattern.match(digest) is None:
        return {"ok": False, "refusals": ["malformed_caid"]}
    return {
        "ok": True,
        "caid": {"version": version, "action_type": action_type, "suite": suite, "digest": digest},
    }


# ---------------------------------------------------------------------------
# Verification (Section 6).
# ---------------------------------------------------------------------------


def _observed_kind(value):
    if value is _ABSENT:
        return "absent"
    return _kind(value) or "unsupported"


def _detail(reason, value, caid_argument):
    """The closed-shape detail of one reason (core.json verify_details)."""
    code, _, param = reason.partition(":")
    rule = _VERIFY_DETAILS[code]
    field = param if rule["field"] == "param" else rule["field"]
    observed = None
    if rule["observed"] == "argument":
        observed = _observed_kind(caid_argument)
    elif rule["observed"] == "member":
        if _is(value, dict):
            members = _members(value)
            observed = _observed_kind(members[field]) if field in members else "absent"
        else:
            observed = _observed_kind(value)
    return {"reason": reason, "field": field, "rule": rule["rule"], "observed": observed}


def _verify_parsed(obj, parsed, caid_argument, opts):
    check_suite = "unknown_suite" not in _DETAIL_EXPAND_OMIT
    if not _is(obj, dict):
        evaluation = _evaluate(obj, opts, check_suite)
        return {
            "valid": False,
            "reasons": ["invalid_object"],
            "details": [_detail(r, obj, caid_argument) for r in evaluation.refusals],
        }
    canonical_result = _canonicalize(obj, MAX_CANONICAL_OCTETS)
    evaluation = _evaluate(obj, opts, check_suite, canonical_result)
    # Every reason after the gates takes its rank from sort_rank.verify, and
    # the result lists them in rank order.
    reasons = []
    if _plain_str(_members(obj).get("action_type")) != parsed["action_type"]:
        reasons.append("action_type_mismatch")
    resolved = evaluation.resolved
    definition_digest = resolved.sha256 if resolved is not None else None
    if opts["pinned"] and definition_digest is not None and opts["expected_definition_sha256"] != definition_digest:
        reasons.append("definition_mismatch")
    canonical = canonical_result[0]
    if parsed["suite"] not in SUPPORTED_SUITES:
        reasons.append("unknown_suite")
    elif canonical is not None and _b64url(_sha256(canonical)) != parsed["digest"]:
        reasons.append("digest_mismatch")
    if evaluation.refusals:
        reasons.append("invalid_object")
    reasons.sort(key=lambda reason: _VERIFY_RANK[reason])
    details = []
    for reason in reasons:
        if reason == "invalid_object":
            details.extend(_detail(r, obj, caid_argument) for r in evaluation.refusals)
        else:
            details.append(_detail(reason, obj, caid_argument))
    result = {"valid": not reasons, "reasons": reasons, "details": details}
    if definition_digest is not None:
        result["definition_sha256"] = definition_digest
    return result


def verify_caid(action_object, caid_string=_ABSENT, options=None):
    """verify_caid(value, caid, {"definitions": [...], "enum_snapshots": [...],
                                 "expected_definition_sha256": str})
      -> {"valid": bool, "reasons": [str], "details": [detail, ...],
          "definition_sha256": str (when a conforming definition resolved)}

    Reasons: malformed_caid or unknown_suite from parsing (alone); else
    action_type_mismatch, definition_mismatch, unknown_suite or
    digest_mismatch, invalid_object, in that order. Each detail is
    {reason, field, rule, observed}; invalid_object is replaced in details
    by one detail per compute reason. A valid result proves only that this
    object is the typed content the identifier was computed over.
    """
    opts = _options(options)
    parsed = parse_caid(caid_string)
    if not parsed["ok"]:
        reason = parsed["refusals"][0]
        return {"valid": False, "reasons": [reason], "details": [_detail(reason, action_object, caid_string)]}
    return _verify_parsed(action_object, parsed["caid"], caid_string, opts)


def verify_caid_json(data, caid_string=_ABSENT, options=None):
    """verify_caid over an action object received as JSON text (bytes).

    The CAID is parsed first; then the text is decoded (malformed_json)."""
    opts = _options(options)
    parsed = parse_caid(caid_string)
    if not parsed["ok"]:
        reason = parsed["refusals"][0]
        return {"valid": False, "reasons": [reason], "details": [_detail(reason, None, caid_string)]}
    decoded = decode_caid_json(data)
    if not decoded["ok"]:
        reason = decoded["refusals"][0]
        return {"valid": False, "reasons": [reason], "details": [_detail(reason, None, caid_string)]}
    return _verify_parsed(decoded["value"], parsed["caid"], caid_string, opts)


def verify_legacy_caid_v04(action_object, caid_string=_ABSENT, options=None):
    """Verify an immutable CAID-04 ``caid:`` identifier explicitly."""
    opts = _options(options)
    parsed = parse_legacy_caid_v04(caid_string)
    if not parsed["ok"]:
        reason = parsed["refusals"][0]
        return {"valid": False, "reasons": [reason], "details": [_detail(reason, action_object, caid_string)]}
    return _verify_parsed(action_object, parsed["caid"], caid_string, opts)


def verify_legacy_caid_v04_json(data, caid_string=_ABSENT, options=None):
    """Verify JSON text against an immutable CAID-04 ``caid:`` identifier."""
    opts = _options(options)
    parsed = parse_legacy_caid_v04(caid_string)
    if not parsed["ok"]:
        reason = parsed["refusals"][0]
        return {"valid": False, "reasons": [reason], "details": [_detail(reason, None, caid_string)]}
    decoded = decode_caid_json(data)
    if not decoded["ok"]:
        reason = decoded["refusals"][0]
        return {"valid": False, "reasons": [reason], "details": [_detail(reason, None, caid_string)]}
    return _verify_parsed(decoded["value"], parsed["caid"], caid_string, opts)
