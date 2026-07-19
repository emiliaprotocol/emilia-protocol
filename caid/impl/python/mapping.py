# SPDX-License-Identifier: Apache-2.0
"""CAID Action-Mapping Profile v1 (Python, standard library only).

Mapping proves content correlation under a caller-pinned profile. It does not
authorize an action or establish trust in the profile author.
"""

import hashlib
import json
import re

from caid import canonicalize, compute_caid

MAPPING_PROFILE_VERSION = "CAID-MAPPING-PROFILE-v1"
EQUIVALENT_UNDER_PROFILE = "EQUIVALENT_UNDER_PROFILE"
NOT_EQUIVALENT = "NOT_EQUIVALENT"
INDETERMINATE = "INDETERMINATE"

_FIELD_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_INDEX_RE = re.compile(r"^(0|[1-9][0-9]*)$")
_TRANSFORMS = frozenset(["copy", "sha256-utf8", "sha256-jcs"])
_PROFILE_KEYS = frozenset([
    "@version", "profile_id", "source_format", "target_action_type",
    "loss_policy", "material_source_paths", "rules",
])
_SOURCE_FORMAT_KEYS = frozenset(["media_type", "schema", "version"])
_RULE_KEYS = frozenset(["source_path", "target_field", "transform"])
_MAX_RULES = 128
_MAX_POINTER_BYTES = 2048


def _is_object(value):
    return isinstance(value, dict)


def _has_only_keys(value, allowed):
    return isinstance(value, dict) and set(value) <= allowed


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _hash_json(value):
    result = canonicalize(value)
    if not result.get("ok"):
        return None
    return "sha256:" + _digest(result["canonical"].encode("utf-8", "surrogatepass"))


def _valid_string(value, maximum=512):
    return isinstance(value, str) and 0 < len(value) <= maximum


def _valid_pointer(pointer):
    if (
        not isinstance(pointer, str)
        or not pointer.startswith("/")
        or len(pointer.encode("utf-8", "surrogatepass")) > _MAX_POINTER_BYTES
    ):
        return False
    for segment in pointer[1:].split("/"):
        index = 0
        while index < len(segment):
            if segment[index] == "~":
                if index + 1 >= len(segment) or segment[index + 1] not in ("0", "1"):
                    return False
                index += 2
            else:
                index += 1
    return True


def _pointer_segments(pointer):
    if not _valid_pointer(pointer):
        return None
    return [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]


def _at_pointer(value, pointer):
    segments = _pointer_segments(pointer)
    if segments is None:
        return {"found": False, "reason": "invalid_source_path"}
    current = value
    for segment in segments:
        if isinstance(current, list):
            if not _INDEX_RE.match(segment):
                return {"found": False, "reason": "invalid_source_path"}
            index = int(segment)
            if index >= len(current):
                return {"found": False, "reason": "missing_source_field"}
            current = current[index]
        elif isinstance(current, dict):
            if segment not in current:
                return {"found": False, "reason": "missing_source_field"}
            current = current[segment]
        else:
            return {"found": False, "reason": "missing_source_field"}
    return {"found": True, "value": current}


def _descriptor_equal(left, right):
    a = canonicalize(left)
    b = canonicalize(right)
    return a.get("ok") and b.get("ok") and a["canonical"] == b["canonical"]


def _definition(action_type, definitions):
    if not isinstance(definitions, list):
        return None
    for entry in definitions:
        if isinstance(entry, dict) and entry.get("action_type") == action_type:
            return entry
    return None


def _validate_profile(profile, definitions):
    reasons = []
    if (
        not isinstance(profile, dict)
        or profile.get("@version") != MAPPING_PROFILE_VERSION
        or not _has_only_keys(profile, _PROFILE_KEYS)
    ):
        return ["invalid_mapping_profile"]
    source_format = profile.get("source_format")
    rules = profile.get("rules")
    material = profile.get("material_source_paths")
    if (
        not _valid_string(profile.get("profile_id"))
        or not _has_only_keys(source_format, _SOURCE_FORMAT_KEYS)
        or not _valid_string(source_format.get("media_type"))
        or not _valid_string(source_format.get("schema"))
        or not _valid_string(source_format.get("version"))
        or not _valid_string(profile.get("target_action_type"))
        or profile.get("loss_policy") != "no-material-field-loss"
        or not isinstance(rules, list)
        or not (1 <= len(rules) <= _MAX_RULES)
        or not isinstance(material, list)
        or not material
    ):
        return ["invalid_mapping_profile"]

    targets = set()
    rule_sources = []
    for rule in rules:
        if (
            not _has_only_keys(rule, _RULE_KEYS)
            or not _valid_pointer(rule.get("source_path"))
            or not isinstance(rule.get("target_field"), str)
            or not _FIELD_RE.match(rule["target_field"])
            or rule["target_field"] == "action_type"
            or rule.get("transform") not in _TRANSFORMS
            or rule["target_field"] in targets
        ):
            reasons.append("invalid_mapping_profile")
            break
        targets.add(rule["target_field"])
        rule_sources.append(rule["source_path"])

    if (
        len(set(material)) != len(material)
        or any(not _valid_pointer(item) for item in material)
        or sorted(set(rule_sources)) != sorted(material)
    ):
        reasons.append("invalid_mapping_profile")

    definition = _definition(profile.get("target_action_type"), definitions)
    if definition is None:
        reasons.append("unknown_action_type")
    else:
        required = definition.get("required_fields")
        if not isinstance(required, list):
            required = []
        for field in required:
            name = field.get("name") if isinstance(field, dict) else None
            if not isinstance(name, str) or not _FIELD_RE.match(name) or name not in targets:
                reasons.append("unmapped_material_field:" + (name if isinstance(name, str) else "?"))
    return list(dict.fromkeys(reasons))


def _apply_transform(value, transform):
    if transform == "copy":
        result = canonicalize(value)
        if not result.get("ok"):
            return {"ok": False, "reason": "source_value_not_canonicalizable"}
        return {"ok": True, "value": json.loads(result["canonical"])}
    if transform == "sha256-utf8":
        if not isinstance(value, str):
            return {"ok": False, "reason": "source_value_type_mismatch"}
        return {"ok": True, "value": "sha256:" + _digest(value.encode("utf-8", "surrogatepass"))}
    if transform == "sha256-jcs":
        result = canonicalize(value)
        if not result.get("ok"):
            return {"ok": False, "reason": "source_value_not_canonicalizable"}
        return {
            "ok": True,
            "value": "sha256:" + _digest(result["canonical"].encode("utf-8", "surrogatepass")),
        }
    return {"ok": False, "reason": "unknown_transform"}


def mapping_profile_hash(profile):
    return _hash_json(profile)


def map_action(
    source,
    *,
    profile=None,
    source_descriptor=None,
    expected_profile_hash=None,
    native_verified=False,
    definitions=None,
    suite="jcs-sha256"
):
    try:
        reasons = _validate_profile(profile, definitions)
        if native_verified is not True:
            reasons.append("native_verification_required")
        profile_hash = mapping_profile_hash(profile)
        if profile_hash is None:
            reasons.append("invalid_mapping_profile")
        if not isinstance(expected_profile_hash, str) or expected_profile_hash != profile_hash:
            reasons.append("mapping_profile_unpinned")
        if not isinstance(source_descriptor, dict) or not _descriptor_equal(
            source_descriptor, profile.get("source_format") if isinstance(profile, dict) else None
        ):
            reasons.append("source_format_mismatch")
        if not isinstance(source, dict):
            reasons.append("source_not_object")
        source_digest = _hash_json(source) if isinstance(source, dict) else None
        if source_digest is None:
            reasons.append("source_not_canonicalizable")
        reasons = list(dict.fromkeys(reasons))
        if reasons:
            return {
                "ok": False,
                "reasons": reasons,
                "profile_hash": profile_hash,
                "source_digest": source_digest,
            }

        action = {"action_type": profile["target_action_type"]}
        for rule in profile["rules"]:
            found = _at_pointer(source, rule["source_path"])
            if not found["found"]:
                reasons.append(found["reason"] + ":" + rule["source_path"])
                continue
            transformed = _apply_transform(found["value"], rule["transform"])
            if not transformed["ok"]:
                reasons.append(transformed["reason"] + ":" + rule["source_path"])
                continue
            action[rule["target_field"]] = transformed["value"]
        if reasons:
            return {
                "ok": False,
                "reasons": reasons,
                "profile_hash": profile_hash,
                "source_digest": source_digest,
            }

        computed = compute_caid(action, {"suite": suite, "definitions": definitions})
        if "caid" not in computed:
            return {
                "ok": False,
                "reasons": ["mapped_action:" + reason for reason in computed.get("refusals", ["invalid_mapped_action"])],
                "profile_hash": profile_hash,
                "source_digest": source_digest,
            }
        return {
            "ok": True,
            "action": action,
            "caid": computed["caid"],
            "digest": computed["digest"],
            "suite": suite,
            "profile_hash": profile_hash,
            "source_digest": source_digest,
        }
    except Exception:
        return {
            "ok": False,
            "reasons": ["unexpected_mapping_error"],
            "profile_hash": None,
            "source_digest": None,
        }


def compare_mapped_actions(left, right, *, definitions=None, suite="jcs-sha256"):
    def map_one(side):
        side = side if isinstance(side, dict) else {}
        return map_action(
            side.get("source"),
            profile=side.get("profile"),
            source_descriptor=side.get("source_descriptor"),
            expected_profile_hash=side.get("expected_profile_hash"),
            native_verified=side.get("native_verified"),
            definitions=definitions,
            suite=suite,
        )

    mapped_left = map_one(left)
    mapped_right = map_one(right)
    if not mapped_left["ok"] or not mapped_right["ok"]:
        reasons = []
        if not mapped_left["ok"]:
            reasons.extend("left:" + reason for reason in mapped_left["reasons"])
        if not mapped_right["ok"]:
            reasons.extend("right:" + reason for reason in mapped_right["reasons"])
        return {
            "verdict": INDETERMINATE,
            "reasons": reasons,
            "left": mapped_left,
            "right": mapped_right,
        }
    if mapped_left["action"]["action_type"] != mapped_right["action"]["action_type"]:
        return {
            "verdict": INDETERMINATE,
            "reasons": ["target_action_type_mismatch"],
            "left": mapped_left,
            "right": mapped_right,
        }
    equivalent = mapped_left["caid"] == mapped_right["caid"]
    return {
        "verdict": EQUIVALENT_UNDER_PROFILE if equivalent else NOT_EQUIVALENT,
        "reasons": [] if equivalent else ["material_projection_mismatch"],
        "left": mapped_left,
        "right": mapped_right,
    }
