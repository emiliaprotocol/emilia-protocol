# SPDX-License-Identifier: Apache-2.0
"""CAID Action-Mapping Profile v1 (Python, standard library only).

Implements Section 8 of draft-schrock-canonical-action-identifier-04. The
profile members, member rules, limits, closed sets and reason ranks come
from caid_spec.py (generated from caid/spec/core.json).

Mapping proves content correlation under a caller-pinned profile. It does
not authorize an action or establish trust in the profile author.

Reason order (normative):
  Stage A  the profile. A profile that is not an object, has the wrong
           @version, an unknown, missing or null member, or a member that
           breaks its rule yields exactly invalid_mapping_profile. Otherwise
           the cross-member checks (distinct paths and targets, rule paths
           equal to material_source_paths, omissions disjoint from rules,
           the loss policy) add invalid_mapping_profile, and definition
           resolution adds unknown_action_type, invalid_definition, or
           unmapped_material_field:<f> in required_fields order.
  Stage B  native verification, the profile pin, the source descriptor and
           the source, and a declared semantic loss. A and B sort together
           by reason rank and stop the mapping if either produced a reason.
  Stage C  each rule in rule order, at most one reason per rule,
           <reason>:<source_path>; stop if any.
  Stage D  mapped_action:<reason> for each compute reason, in compute order.
A comparison lists left: reasons, then right: reasons; then
target_action_type_mismatch; NOT_EQUIVALENT carries
material_projection_mismatch.
"""

import hashlib

import caid as _core
from caid import canonicalize, compute_caid

_SPEC = _core.SPEC
_MAP = _SPEC["mapping"]
_LIMITS = _core.LIMITS
_PATTERNS = _core.PATTERNS

MAPPING_PROFILE_VERSION = _MAP["profile_version"]
EQUIVALENT_UNDER_PROFILE, NOT_EQUIVALENT, INDETERMINATE = _MAP["verdicts"]

_PROFILE_MEMBERS = frozenset(_MAP["members"]["profile"])
_OPTIONAL_PROFILE_MEMBERS = frozenset(_MAP["optional_members"]["profile"])
_CONTAINER_MEMBERS = {
    "source_format": frozenset(_MAP["members"]["source_format"]),
    "rules": frozenset(_MAP["members"]["rule"]),
    "omitted_source_fields": frozenset(_MAP["members"]["omitted_source_field"]),
}
_CLOSED_SETS = {
    "transforms": frozenset(t["transform"] for t in _MAP["transforms"]),
    "loss_policies": frozenset(p["policy"] for p in _MAP["loss_policies"]),
}
_TRANSFORMS = {t["transform"]: t for t in _MAP["transforms"]}
_LOSS_POLICIES = {p["policy"]: p for p in _MAP["loss_policies"]}
_REASON_RANK = _MAP["reason_rank"]
_COMPARISON_PREFIXES = _MAP["comparison"]["prefixes"]
_REASON_VERDICTS = _MAP["comparison"]["reason_verdicts"]
_PREFIXED_VERDICT = _MAP["comparison"]["prefixed_verdict"]
_FAULT = _MAP["fault_reasons"][0]
_INVALID_PROFILE = _MAP["null_member_refusal"]
_ARRAY_INDEX = _PATTERNS["array_index"]


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _hash_json(value):
    result = canonicalize(value)
    if not result["ok"]:
        return None
    return "sha256:" + _digest(result["canonical"].encode("utf-8"))


def mapping_profile_hash(profile):
    """SHA-256 of the RFC 8785 encoding of the profile, or None."""
    return _hash_json(profile)


# ---------------------------------------------------------------------------
# Stage A: the profile.
# ---------------------------------------------------------------------------


def _valid_source_path(text):
    """ABNF source-path: "/" then reference tokens with ~ only as ~0 or ~1,
    no unpaired surrogate."""
    if not text.startswith("/") or _core._LONE_SURROGATE_RE.search(text):
        return False
    index = text.find("~")
    while index >= 0:
        if text[index + 1:index + 2] not in ("0", "1"):
            return False
        index = text.find("~", index + 2)
    return True


def _closed_object(value, allowed, optional=frozenset()):
    """The plain members of a dict with exactly the allowed members (the
    optional ones may be absent) and no null member; None otherwise."""
    if not isinstance(value, dict):
        return None
    members = {}
    for key, member in dict.items(value):
        if not isinstance(key, str):
            return None
        key = str.__str__(key)
        if key not in allowed or key in members or member is None:
            return None
        members[key] = member
    if any(name not in members for name in allowed if name not in optional):
        return None
    return members


def _check_member(value, rule):
    """One core.json member rule against one value."""
    if rule["json"] == "string":
        text = _core._plain_str(value)
        if text is None:
            return False
        octets = _core._utf8_octets(text)
        if octets is None:
            return False
        if "min_octets" in rule and octets < _LIMITS[rule["min_octets"]]:
            return False
        if "max_octets" in rule and octets > _LIMITS[rule["max_octets"]]:
            return False
        if rule.get("rule") == "source-path" and not _valid_source_path(text):
            return False
        if rule.get("rule") == "field-name" and not _core._is_field_name(text):
            return False
        if text in rule.get("reserved", ()):
            return False
        if "closed" in rule and text not in _CLOSED_SETS[rule["closed"]]:
            return False
        return True
    if rule["json"] == "array":
        items = _core._seq(value)
        if items is None:
            return False
        if "min_items" in rule and len(items) < _LIMITS[rule["min_items"]]:
            return False
        if "max_items" in rule and len(items) > _LIMITS[rule["max_items"]]:
            return False
        return True
    return False


def _values_at(profile, path):
    """Every value at a member path ("*" is each array element)."""
    current = [profile]
    for step in path:
        following = []
        for value in current:
            if step == "*":
                items = _core._seq(value)
                if items is not None:
                    following.extend(items)
            elif isinstance(value, dict) and step in value:
                following.append(value[step])
        current = following
    return current


def _profile_shape(profile):
    """The closed, rule-checked profile as plain nested values, or None."""
    top = _closed_object(profile, _PROFILE_MEMBERS, _OPTIONAL_PROFILE_MEMBERS)
    if top is None or _core._plain_str(top.get("@version")) != MAPPING_PROFILE_VERSION:
        return None
    shaped = dict(top)
    source_format = _closed_object(top["source_format"], _CONTAINER_MEMBERS["source_format"])
    if source_format is None:
        return None
    shaped["source_format"] = source_format
    for name in ("rules", "omitted_source_fields"):
        if name not in top:
            continue
        items = _core._seq(top[name])
        if items is None:
            return None
        closed = []
        for item in items:
            members = _closed_object(item, _CONTAINER_MEMBERS[name])
            if members is None:
                return None
            closed.append(members)
        shaped[name] = closed
    for rule in _MAP["member_rules"]:
        path = rule["path"]
        if path[0] in _OPTIONAL_PROFILE_MEMBERS and path[0] not in shaped:
            continue
        values = _values_at(shaped, path)
        if "*" not in path and len(values) != 1:
            return None
        if not all(_check_member(value, rule) for value in values):
            return None
    # Every string member is now a plain str.
    for name in ("profile_id", "target_action_type", "loss_policy"):
        shaped[name] = _core._plain_str(shaped[name])
    shaped["source_format"] = {k: _core._plain_str(v) for k, v in source_format.items()}
    shaped["material_source_paths"] = [_core._plain_str(v) for v in _core._seq(top["material_source_paths"])]
    shaped["rules"] = [{k: _core._plain_str(v) for k, v in r.items()} for r in shaped["rules"]]
    shaped["omitted_source_fields"] = [
        {k: _core._plain_str(v) for k, v in o.items()} for o in shaped.get("omitted_source_fields", [])
    ]
    return shaped


def _stage_a(profile, definitions):
    """Stage A reasons as (rank, position, reason) triples, plus the shaped
    profile when it passed the shape gate."""
    shaped = _profile_shape(profile)
    if shaped is None:
        return [(_REASON_RANK[_INVALID_PROFILE], 0, _INVALID_PROFILE)], None
    found = []
    invalid = False
    for path in _MAP["unique"]:
        values = _values_at(shaped, path)
        if len(set(values)) != len(values):
            invalid = True
    for left, right in _MAP["equal_sets"]:
        if set(_values_at(shaped, left)) != set(_values_at(shaped, right)):
            invalid = True
    for left, right in _MAP["disjoint"]:
        if set(_values_at(shaped, left)) & set(_values_at(shaped, right)):
            invalid = True
    requirement = _LOSS_POLICIES[shaped["loss_policy"]]["omitted_source_fields"]
    omissions = len(shaped["omitted_source_fields"])
    if (requirement == "absent_or_empty" and omissions != 0) or (requirement == "non_empty" and omissions == 0):
        invalid = True
    if invalid:
        found.append((_REASON_RANK[_INVALID_PROFILE], 0, _INVALID_PROFILE))
    resolved = _core._resolve(shaped["target_action_type"], _core._options({"definitions": definitions})["definitions"])
    if isinstance(resolved, str):
        found.append((_REASON_RANK[resolved], 0, resolved))
    else:
        targets = set(rule["target_field"] for rule in shaped["rules"])
        for position, field in enumerate(resolved.required):
            if field["name"] not in targets:
                found.append((_REASON_RANK["unmapped_material_field"], position, "unmapped_material_field:" + field["name"]))
    return found, shaped


# ---------------------------------------------------------------------------
# Stage C: rules.
# ---------------------------------------------------------------------------


def _pointer_segments(pointer):
    return [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]


def _at_pointer(value, pointer):
    current = value
    for segment in _pointer_segments(pointer):
        if isinstance(current, list):
            if _ARRAY_INDEX.match(segment) is None:
                return None, "invalid_source_path"
            items = _core._seq(current)
            # A safe integer has at most 16 digits; longer is past any end.
            if len(segment) > 16 or int(segment) >= len(items):
                return None, "missing_source_field"
            current = items[int(segment)]
        elif isinstance(current, dict):
            members = _core._members(current)
            if segment not in members:
                return None, "missing_source_field"
            current = members[segment]
        else:
            return None, "missing_source_field"
    return current, None


def _apply_transform(value, transform):
    spec = _TRANSFORMS.get(transform)
    if spec is None:
        return None, "unknown_transform"
    if spec["input"] == "string":
        text = _core._plain_str(value)
        if text is None:
            return None, "source_value_type_mismatch"
        if "pattern" in spec and _PATTERNS[spec["pattern"]].match(text) is None:
            return None, "source_value_type_mismatch"
        if _core._OUTSIDE_MODEL_RE.search(text):
            return None, "source_value_not_canonicalizable"
    if transform == "sha256-hex-to-digest":
        return "sha256:" + text, None
    if transform == "sha256-utf8":
        return "sha256:" + _digest(text.encode("utf-8")), None
    canonical = canonicalize(value)
    if not canonical["ok"]:
        return None, "source_value_not_canonicalizable"
    if transform == "sha256-jcs":
        return "sha256:" + _digest(canonical["canonical"].encode("utf-8")), None
    # copy: an independent data-model copy of the source value.
    copied = _core.decode_json_document(canonical["canonical"].encode("utf-8"))
    return copied["value"], None


# ---------------------------------------------------------------------------
# map_action and compare_mapped_actions
# ---------------------------------------------------------------------------


def _ordered(found):
    found.sort(key=lambda item: (item[0], item[1]))
    out = []
    seen = set()
    for _, _, reason in found:
        if reason not in seen:
            seen.add(reason)
            out.append(reason)
    return out


def _failure(reasons, profile_hash, source_digest):
    return {"ok": False, "reasons": reasons, "profile_hash": profile_hash, "source_digest": source_digest}


def _map(source, profile, source_descriptor, expected_profile_hash, native_verified, definitions, enum_snapshots, suite):
    found, shaped = _stage_a(profile, definitions)
    rank = _REASON_RANK
    if native_verified is not True:
        found.append((rank["native_verification_required"], 0, "native_verification_required"))
    profile_hash = mapping_profile_hash(profile)
    if profile_hash is None:
        found.append((rank[_INVALID_PROFILE], 0, _INVALID_PROFILE))
    if _core._plain_str(expected_profile_hash) is None or _core._plain_str(expected_profile_hash) != profile_hash:
        found.append((rank["mapping_profile_unpinned"], 0, "mapping_profile_unpinned"))
    declared_format = _core._members(profile).get("source_format") if isinstance(profile, dict) else None
    if not isinstance(source_descriptor, dict) or not _same_canonical(source_descriptor, declared_format):
        found.append((rank["source_format_mismatch"], 0, "source_format_mismatch"))
    source_digest = None
    if not isinstance(source, dict):
        found.append((rank["source_not_object"], 0, "source_not_object"))
    else:
        source_digest = _hash_json(source)
    if source_digest is None:
        found.append((rank["source_not_canonicalizable"], 0, "source_not_canonicalizable"))
    loss_policy = _core._plain_str(_core._members(profile).get("loss_policy")) if isinstance(profile, dict) else None
    stage_reason = _LOSS_POLICIES[loss_policy].get("stage_reason") if loss_policy in _LOSS_POLICIES else None
    if stage_reason is not None:
        found.append((rank[stage_reason], 0, stage_reason))
    if found:
        return _failure(_ordered(found), profile_hash, source_digest)

    reasons = []
    action = {"action_type": shaped["target_action_type"]}
    for rule in shaped["rules"]:
        value, reason = _at_pointer(source, rule["source_path"])
        if reason is None:
            value, reason = _apply_transform(value, rule["transform"])
        if reason is not None:
            reasons.append(reason + ":" + rule["source_path"])
            continue
        action[rule["target_field"]] = value
    if reasons:
        return _failure(reasons, profile_hash, source_digest)

    computed = compute_caid(action, {"suite": suite, "definitions": definitions, "enum_snapshots": enum_snapshots})
    if "caid" not in computed:
        return _failure(["mapped_action:" + reason for reason in computed["refusals"]], profile_hash, source_digest)
    return {
        "ok": True,
        "action": action,
        "caid": computed["caid"],
        "digest": computed["digest"],
        "definition_sha256": computed["definition_sha256"],
        "suite": suite,
        "profile_hash": profile_hash,
        "source_digest": source_digest,
    }


def _same_canonical(left, right):
    a = canonicalize(left)
    b = canonicalize(right)
    return a["ok"] and b["ok"] and a["canonical"] == b["canonical"]


def map_action(
    source,
    *,
    profile=None,
    source_descriptor=None,
    expected_profile_hash=None,
    native_verified=False,
    definitions=None,
    enum_snapshots=None,
    suite="jcs-sha256"
):
    """Maps a native source through a pinned profile to an action object.

    -> {"ok": True, "action", "caid", "digest", "definition_sha256", "suite",
        "profile_hash", "source_digest"}
    -> {"ok": False, "reasons": [...], "profile_hash", "source_digest"}
    """
    try:
        return _map(source, profile, source_descriptor, expected_profile_hash, native_verified,
                    definitions, enum_snapshots, suite)
    except Exception:  # an implementation fault; a conforming mapper never gets here
        return _failure([_FAULT], None, None)


def compare_mapped_actions(left, right, *, definitions=None, enum_snapshots=None, suite="jcs-sha256"):
    """Maps both sides and compares the projected actions by CAID."""

    def map_one(side):
        members = _core._members(side) if isinstance(side, dict) else {}
        return map_action(
            members.get("source"),
            profile=members.get("profile"),
            source_descriptor=members.get("source_descriptor"),
            expected_profile_hash=members.get("expected_profile_hash"),
            native_verified=members.get("native_verified"),
            definitions=definitions,
            enum_snapshots=enum_snapshots,
            suite=suite,
        )

    mapped = [map_one(left), map_one(right)]
    if not all(m["ok"] for m in mapped):
        reasons = []
        for prefix, result in zip(_COMPARISON_PREFIXES, mapped):
            if not result["ok"]:
                reasons.extend(prefix + ":" + reason for reason in result["reasons"])
        return {"verdict": _PREFIXED_VERDICT, "reasons": reasons, "left": mapped[0], "right": mapped[1]}
    if mapped[0]["action"]["action_type"] != mapped[1]["action"]["action_type"]:
        reason = "target_action_type_mismatch"
        return {"verdict": _REASON_VERDICTS[reason], "reasons": [reason], "left": mapped[0], "right": mapped[1]}
    if mapped[0]["caid"] == mapped[1]["caid"]:
        return {"verdict": EQUIVALENT_UNDER_PROFILE, "reasons": [], "left": mapped[0], "right": mapped[1]}
    reason = "material_projection_mismatch"
    return {"verdict": _REASON_VERDICTS[reason], "reasons": [reason], "left": mapped[0], "right": mapped[1]}
