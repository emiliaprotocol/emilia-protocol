# SPDX-License-Identifier: Apache-2.0
"""EP-OUTCOME-ATTESTATION-v1 and EP-OUTCOME-BINDING-v1.

Faithful Python port of packages/verify/effect-predicates.js and
packages/verify/outcome-binding.js. Comparison values remain strings, ordered
decimal predicates use string math, schemas are closed, and every refusal
returns one of the three protocol outcomes.
"""
from __future__ import annotations

import base64
import hashlib
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key

from . import canonicalize

OUTCOME_ATTESTATION_VERSION = "EP-OUTCOME-ATTESTATION-v1"
OUTCOME_ATTESTATION_DOMAIN = "EP-OUTCOME-ATTESTATION-v1\0"
OUTCOME_BINDING_VERSION = "EP-OUTCOME-BINDING-v1"
PREDICATE_OPS = ("eq", "lte", "gte", "range", "set_eq", "count_lte", "absent")
OUTCOME_BINDING_OUTCOMES = ("in_bounds", "divergent", "incomparable")
MAX_PREDICTED_EFFECTS = 64
MAX_OBSERVED_EFFECTS = 256
MAX_EFFECT_STRING_LENGTH = 512

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_NORMALIZED_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$", re.IGNORECASE)
_KEY_ID_RE = re.compile(r"^ep:executor-key:sha256:[0-9a-f]{64}$")
_DECIMAL_RE = re.compile(r"^(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?$")
_COUNT_RE = re.compile(r"^(0|[1-9][0-9]*)$")
_RFC3339_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d{1,9}))?(?:Z|([+-])(\d{2}):(\d{2}))$"
)
_TOP_KEYS = {
    "@version", "receipt_id", "receipt_digest", "action_hash", "consumption_nonce",
    "execution_id", "executor_id", "executed_at", "observed_effects",
    "observed_effects_digest", "proof",
}
_PROOF_KEYS = {"algorithm", "key_id", "public_key", "signature_b64u"}
_ENTRY_KEYS = {"effect_type", "target", "predicate"}
_OBSERVED_KEYS = {"effect_type", "target", "value", "values"}
_PREDICATE_KEYS = {
    "eq": {"op", "value"},
    "lte": {"op", "value"},
    "gte": {"op", "value"},
    "range": {"op", "min", "max"},
    "set_eq": {"op", "values"},
    "count_lte": {"op", "value"},
    "absent": {"op"},
}


def _digest(value: Any) -> str:
    encoded = canonicalize(value).encode("utf-8", "strict")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _safe_digest(value: Any) -> Optional[str]:
    try:
        return _digest(value)
    except Exception:
        return None


def _normalize_digest(value: Any) -> Optional[str]:
    if isinstance(value, str) and _NORMALIZED_DIGEST_RE.fullmatch(value):
        return value.lower()
    return None


def _too_long(value: Any) -> bool:
    return isinstance(value, str) and len(value) > MAX_EFFECT_STRING_LENGTH


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _split_decimal(value: Any) -> Optional[tuple[bool, str, str]]:
    if not isinstance(value, str):
        return None
    match = _DECIMAL_RE.fullmatch(value)
    if not match:
        return None
    negative = match.group(1) == "-"
    integer = match.group(2)
    fraction = (match.group(3) or "").rstrip("0")
    if integer == "0" and not fraction:
        negative = False
    return negative, integer, fraction


def is_decimal_string(value: Any) -> bool:
    """Return whether value is an exact canonical decimal string."""
    return _split_decimal(value) is not None


def compare_decimal_strings(left: Any, right: Any) -> Optional[int]:
    """Compare decimal strings without floats; return -1, 0, 1, or None."""
    a = _split_decimal(left)
    b = _split_decimal(right)
    if a is None or b is None:
        return None
    a_negative, a_integer, a_fraction = a
    b_negative, b_integer, b_fraction = b
    if a_negative != b_negative:
        return -1 if a_negative else 1
    if len(a_integer) != len(b_integer):
        magnitude = -1 if len(a_integer) < len(b_integer) else 1
    elif a_integer != b_integer:
        magnitude = -1 if a_integer < b_integer else 1
    else:
        width = max(len(a_fraction), len(b_fraction))
        a_padded = a_fraction.ljust(width, "0")
        b_padded = b_fraction.ljust(width, "0")
        magnitude = -1 if a_padded < b_padded else 1 if a_padded > b_padded else 0
    return -magnitude if a_negative else magnitude


def predicted_effects_digest(predicted_effects: Any) -> str:
    """Digest the exact signed predicted_effects array."""
    return _digest(predicted_effects)


def observed_effects_digest(observed_effects: Any) -> str:
    """Digest the exact executor-attested observed_effects array."""
    return _digest(observed_effects)


def trust_receipt_digest(receipt: Any) -> str:
    """Digest the exact Trust Receipt object referenced by an attestation."""
    return _digest(receipt)


def validate_predicted_effects(predicted: Any) -> dict:
    """Validate the closed signed-prediction schema."""
    reasons: list[str] = []
    if not isinstance(predicted, list) or not predicted:
        return {"ok": False, "reasons": ["predicted_effects must be a non-empty array"]}
    if len(predicted) > MAX_PREDICTED_EFFECTS:
        return {
            "ok": False,
            "reasons": [f"predicted_effects exceeds the {MAX_PREDICTED_EFFECTS}-entry limit"],
        }

    for index, entry in enumerate(predicted):
        at = f"predicted_effects[{index}]"
        if not isinstance(entry, dict):
            reasons.append(f"{at} is not an object")
            continue
        unknown = next((key for key in entry if key not in _ENTRY_KEYS), None)
        if unknown is not None:
            reasons.append(f'{at} has unknown member "{unknown}"')
            continue
        effect_type = entry.get("effect_type")
        if not isinstance(effect_type, str) or not effect_type or _too_long(effect_type):
            reasons.append(
                f"{at}.effect_type must be a non-empty string of at most "
                f"{MAX_EFFECT_STRING_LENGTH} characters"
            )
            continue
        target = entry.get("target")
        if not isinstance(target, str) or not target or _too_long(target):
            reasons.append(
                f"{at}.target must be a non-empty string of at most "
                f"{MAX_EFFECT_STRING_LENGTH} characters"
            )
            continue
        if "*" in target:
            reasons.append(
                f'{at}.target contains "*"; EP-OUTCOME-BINDING-v1 targets are '
                "literal identifiers, not patterns"
            )
            continue
        predicate = entry.get("predicate")
        if not isinstance(predicate, dict):
            reasons.append(f"{at}.predicate is not an object")
            continue
        op = predicate.get("op")
        if op not in PREDICATE_OPS:
            rendered = "undefined" if "op" not in predicate else str(op)
            reasons.append(f'{at}.predicate.op "{rendered}" is not a known op')
            continue
        unknown = next((key for key in predicate if key not in _PREDICATE_KEYS[op]), None)
        if unknown is not None:
            reasons.append(f'{at}.predicate (op {op}) has unknown member "{unknown}"')
            continue

        if op == "eq":
            value = predicate.get("value")
            if _is_number(value):
                reasons.append(
                    f"{at}.predicate.value is a number; comparison values MUST be "
                    "strings (canonicalization malleability)"
                )
            elif not isinstance(value, str) or _too_long(value):
                reasons.append(f"{at}.predicate.value must be a bounded string")
        elif op in ("lte", "gte"):
            value = predicate.get("value")
            if _is_number(value):
                reasons.append(
                    f"{at}.predicate.value is a number; comparison values MUST be "
                    "strings (canonicalization malleability)"
                )
            elif not isinstance(value, str) or _too_long(value) or not is_decimal_string(value):
                reasons.append(f"{at}.predicate.value must be a bounded decimal string")
        elif op == "range":
            malformed = False
            for field in ("min", "max"):
                value = predicate.get(field)
                if _is_number(value):
                    reasons.append(
                        f"{at}.predicate.{field} is a number; comparison values MUST "
                        "be strings (canonicalization malleability)"
                    )
                    malformed = True
                elif not isinstance(value, str) or _too_long(value) or not is_decimal_string(value):
                    reasons.append(f"{at}.predicate.{field} must be a bounded decimal string")
                    malformed = True
            if not malformed and compare_decimal_strings(predicate["min"], predicate["max"]) == 1:
                reasons.append(f"{at}.predicate range has min > max")
        elif op == "set_eq":
            values = predicate.get("values")
            if not isinstance(values, list) or len(values) > MAX_OBSERVED_EFFECTS:
                reasons.append(f"{at}.predicate.values must be a bounded array of strings")
            else:
                for value in values:
                    if _is_number(value):
                        reasons.append(
                            f"{at}.predicate.values contains a number; comparison values "
                            "MUST be strings (canonicalization malleability)"
                        )
                        break
                    if not isinstance(value, str) or _too_long(value):
                        reasons.append(
                            f"{at}.predicate.values must contain only bounded strings"
                        )
                        break
        elif op == "count_lte":
            value = predicate.get("value")
            if _is_number(value):
                reasons.append(
                    f"{at}.predicate.value is a number; comparison values MUST be "
                    "strings (canonicalization malleability)"
                )
            elif (
                not isinstance(value, str)
                or _too_long(value)
                or not _COUNT_RE.fullmatch(value)
            ):
                reasons.append(
                    f"{at}.predicate.value must be a bounded non-negative integer string"
                )
    return {"ok": not reasons, "reasons": reasons}


def _validate_observed_effects(observed: Any) -> dict:
    reasons: list[str] = []
    if not isinstance(observed, list):
        return {
            "ok": False,
            "reasons": ["observed_effects is missing or not an array (refusal, never a pass)"],
        }
    if len(observed) > MAX_OBSERVED_EFFECTS:
        return {
            "ok": False,
            "reasons": [f"observed_effects exceeds the {MAX_OBSERVED_EFFECTS}-entry limit"],
        }
    for index, entry in enumerate(observed):
        at = f"observed_effects[{index}]"
        if not isinstance(entry, dict):
            reasons.append(f"{at} is not an object")
            continue
        for member in entry:
            if member not in _OBSERVED_KEYS:
                reasons.append(f'{at} has unknown member "{member}"')
        effect_type = entry.get("effect_type")
        if not isinstance(effect_type, str) or not effect_type or _too_long(effect_type):
            reasons.append(f"{at}.effect_type must be a non-empty bounded string")
        target = entry.get("target")
        if (
            not isinstance(target, str)
            or not target
            or _too_long(target)
            or "*" in target
        ):
            reasons.append(f"{at}.target must be a bounded literal identifier")
        has_value = "value" in entry
        has_values = "values" in entry
        if has_value == has_values:
            reasons.append(f"{at} must carry exactly one of value or values")
        if has_value and _is_number(entry["value"]):
            reasons.append(f"{at}.value is a number; observed values MUST be strings")
        elif has_value and (
            not isinstance(entry["value"], str) or _too_long(entry["value"])
        ):
            reasons.append(f"{at}.value must be a bounded string")
        if has_values:
            values = entry["values"]
            if not isinstance(values, list) or len(values) > MAX_OBSERVED_EFFECTS:
                reasons.append(f"{at}.values must be a bounded array")
            else:
                for value in values:
                    if not isinstance(value, str) or _too_long(value):
                        reasons.append(f"{at}.values MUST be strings of bounded length")
                        break
    return {"ok": not reasons, "reasons": reasons}


def _set_sort(values: list[str]) -> list[str]:
    return sorted(set(values), key=lambda value: value.encode("utf-16-be", "surrogatepass"))


def _evaluate_entry(entry: dict, matches: list[dict]) -> tuple[str, Optional[str]]:
    predicate = entry["predicate"]
    op = predicate["op"]
    at = f'{entry["effect_type"]} on {entry["target"]}'
    if op == "absent":
        if not matches:
            return "in_bounds", None
        return "divergent", f"predicted absent for {at}, observed {len(matches)} effect(s)"
    if op == "count_lte":
        count = str(len(matches))
        if compare_decimal_strings(count, predicate["value"]) <= 0:
            return "in_bounds", None
        return (
            "divergent",
            f'predicted count <= {predicate["value"]} for {at}, observed {count}',
        )
    if not matches:
        return "incomparable", f"no observed effect for {at}"
    if len(matches) > 1:
        return "incomparable", f"ambiguous: {len(matches)} observed effects match {at}"
    observed = matches[0]
    if op == "set_eq":
        if not isinstance(observed.get("values"), list):
            return "incomparable", f"observed effect for {at} has no values array"
        if any(not isinstance(value, str) for value in observed["values"]):
            return (
                "incomparable",
                f"observed values for {at} contain a non-string (values MUST be strings)",
            )
        wanted = _set_sort(predicate["values"])
        got = _set_sort(observed["values"])
        if canonicalize(wanted) == canonicalize(got):
            return "in_bounds", None
        return (
            "divergent",
            f'predicted set_eq [{",".join(wanted)}] for {at}, observed [{",".join(got)}]',
        )

    value = observed.get("value")
    if _is_number(value):
        return (
            "incomparable",
            f"observed value for {at} is a number; values MUST be strings "
            "(canonicalization malleability)",
        )
    if not isinstance(value, str):
        return "incomparable", f"observed effect for {at} has no string value"
    if op == "eq":
        if value == predicate["value"]:
            return "in_bounds", None
        return (
            "divergent",
            f'predicted eq "{predicate["value"]}" for {at}, observed "{value}"',
        )
    if not is_decimal_string(value):
        return "incomparable", f'observed value "{value}" for {at} is not a decimal string'
    if op == "lte":
        if compare_decimal_strings(value, predicate["value"]) <= 0:
            return "in_bounds", None
        return "divergent", f'predicted <= {predicate["value"]} for {at}, observed {value}'
    if op == "gte":
        if compare_decimal_strings(value, predicate["value"]) >= 0:
            return "in_bounds", None
        return "divergent", f'predicted >= {predicate["value"]} for {at}, observed {value}'
    if compare_decimal_strings(value, predicate["min"]) < 0:
        return (
            "divergent",
            f'predicted range [{predicate["min"]}, {predicate["max"]}] for {at}, '
            f"observed {value} (below min)",
        )
    if compare_decimal_strings(value, predicate["max"]) > 0:
        return (
            "divergent",
            f'predicted range [{predicate["min"]}, {predicate["max"]}] for {at}, '
            f"observed {value} (above max)",
        )
    return "in_bounds", None


def evaluate_predicted_effects(predicted: Any, observed: Any) -> dict:
    """Evaluate signed predictions against executor observations."""
    structural = validate_predicted_effects(predicted)
    if not structural["ok"]:
        return {
            "outcome": "incomparable",
            "results": [],
            "reasons": [
                f"malformed predicted_effects: {reason}"
                for reason in structural["reasons"]
            ],
        }
    observed_structural = _validate_observed_effects(observed)
    if not observed_structural["ok"]:
        return {
            "outcome": "incomparable",
            "results": [],
            "reasons": [
                f"malformed observed_effects: {reason}"
                for reason in observed_structural["reasons"]
            ],
        }
    results = []
    for entry in predicted:
        matches = [
            item
            for item in observed
            if isinstance(item, dict)
            and item.get("effect_type") == entry["effect_type"]
            and item.get("target") == entry["target"]
        ]
        outcome, reason = _evaluate_entry(entry, matches)
        results.append(
            {
                "effect_type": entry["effect_type"],
                "target": entry["target"],
                "op": entry["predicate"]["op"],
                "outcome": outcome,
                "reason": reason,
            }
        )
    reasons = [item["reason"] for item in results if item["reason"] is not None]
    if any(item["outcome"] == "divergent" for item in results):
        outcome = "divergent"
    elif any(item["outcome"] == "incomparable" for item in results):
        outcome = "incomparable"
    else:
        outcome = "in_bounds"
    return {"outcome": outcome, "results": results, "reasons": reasons}


def _strict_instant_ms(value: Any) -> Optional[int]:
    if not isinstance(value, str):
        return None
    match = _RFC3339_RE.fullmatch(value)
    if not match:
        return None
    year, month, day, hour, minute, second = (int(match.group(i)) for i in range(1, 7))
    fraction = match.group(7) or ""
    sign, offset_hour, offset_minute = match.group(8), match.group(9), match.group(10)
    if offset_hour is not None and (int(offset_hour) > 23 or int(offset_minute) > 59):
        return None
    try:
        zone = timezone.utc
        if sign is not None:
            offset = timedelta(hours=int(offset_hour), minutes=int(offset_minute))
            zone = timezone(offset if sign == "+" else -offset)
        instant = datetime(year, month, day, hour, minute, second, tzinfo=zone)
        seconds = int(instant.timestamp())
    except (OverflowError, ValueError):
        return None
    milliseconds = int((fraction + "000")[:3])
    return seconds * 1000 + milliseconds


def _decode_b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _executor_key_id(public_key: str) -> str:
    return "ep:executor-key:sha256:" + hashlib.sha256(_decode_b64url(public_key)).hexdigest()


def _exact_keys(value: Any, allowed: set[str]) -> bool:
    return isinstance(value, dict) and all(key in allowed for key in value)


def _validate_attested_observed(observed: Any) -> dict:
    errors: list[str] = []
    if not isinstance(observed, list):
        return {"ok": False, "errors": ["observed_effects must be an array"]}
    if len(observed) > MAX_OBSERVED_EFFECTS:
        return {
            "ok": False,
            "errors": [f"observed_effects exceeds the {MAX_OBSERVED_EFFECTS}-entry limit"],
        }
    for index, entry in enumerate(observed):
        at = f"observed_effects[{index}]"
        if not _exact_keys(entry, _OBSERVED_KEYS):
            errors.append(f"{at} is not an exact observed-effect object")
            continue
        effect_type = entry.get("effect_type")
        if not isinstance(effect_type, str) or not effect_type or _too_long(effect_type):
            errors.append(f"{at}.effect_type is invalid")
        target = entry.get("target")
        if (
            not isinstance(target, str)
            or not target
            or _too_long(target)
            or "*" in target
        ):
            errors.append(f"{at}.target must be a bounded literal identifier")
        has_value = "value" in entry
        has_values = "values" in entry
        if has_value == has_values:
            errors.append(f"{at} must carry exactly one of value or values")
        if has_value and (
            not isinstance(entry["value"], str) or _too_long(entry["value"])
        ):
            errors.append(f"{at}.value must be a bounded string")
        if has_values:
            values = entry["values"]
            if (
                not isinstance(values, list)
                or len(values) > MAX_OBSERVED_EFFECTS
                or any(not isinstance(item, str) or _too_long(item) for item in values)
            ):
                errors.append(f"{at}.values must be a bounded array of bounded strings")
    return {"ok": not errors, "errors": errors}


def verify_outcome_attestation(attestation: Any, opts: Optional[dict] = None) -> dict:
    """Verify an executor attestation under a relying-party-pinned key."""
    opts = opts if isinstance(opts, dict) else {}
    executor_keys = opts.get("executorKeys")
    if not isinstance(executor_keys, dict):
        executor_keys = {}
    checks = {
        "structure": False,
        "observation_digest": False,
        "executor_key_pinned": False,
        "signature": False,
        "execution_time": False,
    }
    errors: list[str] = []

    def result() -> dict:
        return {"valid": all(checks.values()), "checks": checks, "errors": errors}

    proof = attestation.get("proof") if isinstance(attestation, dict) else None
    if (
        not _exact_keys(attestation, _TOP_KEYS)
        or attestation.get("@version") != OUTCOME_ATTESTATION_VERSION
        or not isinstance(attestation.get("receipt_id"), str)
        or not attestation.get("receipt_id")
        or _normalize_digest(attestation.get("receipt_digest")) is None
        or _normalize_digest(attestation.get("action_hash")) is None
        or not isinstance(attestation.get("consumption_nonce"), str)
        or not attestation.get("consumption_nonce")
        or not isinstance(attestation.get("execution_id"), str)
        or not attestation.get("execution_id")
        or not isinstance(attestation.get("executor_id"), str)
        or not attestation.get("executor_id")
        or not isinstance(attestation.get("observed_effects_digest"), str)
        or not _DIGEST_RE.fullmatch(attestation.get("observed_effects_digest", ""))
        or not _exact_keys(proof, _PROOF_KEYS)
        or proof.get("algorithm") != "Ed25519"
        or not isinstance(proof.get("key_id"), str)
        or not _KEY_ID_RE.fullmatch(proof.get("key_id", ""))
        or not isinstance(proof.get("public_key"), str)
        or not isinstance(proof.get("signature_b64u"), str)
    ):
        errors.append("malformed_outcome_attestation")
        return result()
    observed_validation = _validate_attested_observed(attestation.get("observed_effects"))
    if not observed_validation["ok"]:
        errors.extend(observed_validation["errors"])
        return result()
    checks["structure"] = True

    checks["observation_digest"] = (
        observed_effects_digest(attestation["observed_effects"])
        == attestation["observed_effects_digest"]
    )
    if not checks["observation_digest"]:
        errors.append("observed_effects_digest_mismatch")

    try:
        derived_key_id = _executor_key_id(proof["public_key"])
    except Exception:
        derived_key_id = None
    pin = executor_keys.get(attestation["executor_id"])
    checks["executor_key_pinned"] = (
        derived_key_id == proof["key_id"]
        and isinstance(pin, dict)
        and pin.get("public_key") == proof["public_key"]
        and ("key_id" not in pin or pin.get("key_id") == derived_key_id)
    )
    if not checks["executor_key_pinned"]:
        errors.append("executor_key_not_pinned")

    if checks["executor_key_pinned"]:
        try:
            key = load_der_public_key(_decode_b64url(pin["public_key"]))
            if not isinstance(key, Ed25519PublicKey):
                raise ValueError("not Ed25519")
            unsigned = {key_name: value for key_name, value in attestation.items() if key_name != "proof"}
            signing_bytes = (
                OUTCOME_ATTESTATION_DOMAIN + canonicalize(unsigned)
            ).encode("utf-8", "strict")
            key.verify(_decode_b64url(proof["signature_b64u"]), signing_bytes)
            checks["signature"] = True
        except Exception:
            checks["signature"] = False
    if not checks["signature"]:
        errors.append("executor_signature_invalid")

    executed_at = _strict_instant_ms(attestation.get("executed_at"))
    now = (
        int(time.time() * 1000)
        if "now" not in opts
        else _strict_instant_ms(opts.get("now"))
    )
    checks["execution_time"] = (
        executed_at is not None and now is not None and executed_at <= now
    )
    if not checks["execution_time"]:
        errors.append("execution_time_invalid_or_future")
    return result()


def _combine_evaluations(signed: dict, policy: Optional[dict]) -> dict:
    evaluations = [{"source": "signed_receipt", **signed}]
    if policy is not None:
        evaluations.append({"source": "relying_party_policy", **policy})
    if any(item["outcome"] == "divergent" for item in evaluations):
        outcome = "divergent"
    elif any(item["outcome"] == "incomparable" for item in evaluations):
        outcome = "incomparable"
    else:
        outcome = "in_bounds"
    reasons = [
        f'{item["source"]}: {reason}'
        for item in evaluations
        for reason in item["reasons"]
    ]
    return {
        "@version": OUTCOME_BINDING_VERSION,
        "outcome": outcome,
        "evaluations": evaluations,
        "reasons": reasons,
    }


def verify_outcome_binding_core(
    receipt: Any,
    attestation: Any,
    opts: Optional[dict],
    verify_receipt: Optional[Callable[[Any, dict], dict]],
) -> dict:
    """Compose Trust Receipt verification with exact outcome bindings."""
    opts = opts if isinstance(opts, dict) else {}
    checks = {
        "receipt_verified": False,
        "signed_predictions": False,
        "receipt_bound": False,
        "receipt_digest_bound": False,
        "action_bound": False,
        "consumption_bound": False,
        "attestation_verified": False,
    }
    errors: list[str] = []

    def exact_commitments() -> dict:
        receipt_value = receipt if isinstance(receipt, dict) else {}
        attestation_value = attestation if isinstance(attestation, dict) else {}
        consumption = receipt_value.get("consumption")
        proof = attestation_value.get("proof")
        return {
            "receipt_id": (
                receipt_value.get("receipt_id")
                if isinstance(receipt_value.get("receipt_id"), str) else None
            ),
            "attested_receipt_id": (
                attestation_value.get("receipt_id")
                if isinstance(attestation_value.get("receipt_id"), str) else None
            ),
            "receipt_digest": _safe_digest(receipt),
            "attested_receipt_digest": _normalize_digest(
                attestation_value.get("receipt_digest")
            ),
            "action_hash": _normalize_digest(receipt_value.get("action_hash")),
            "attested_action_hash": _normalize_digest(
                attestation_value.get("action_hash")
            ),
            "consumption_nonce": (
                consumption.get("nonce")
                if isinstance(consumption, dict)
                and isinstance(consumption.get("nonce"), str) else None
            ),
            "attested_consumption_nonce": (
                attestation_value.get("consumption_nonce")
                if isinstance(attestation_value.get("consumption_nonce"), str) else None
            ),
            "execution_id": (
                attestation_value.get("execution_id")
                if isinstance(attestation_value.get("execution_id"), str) else None
            ),
            "executor_id": (
                attestation_value.get("executor_id")
                if isinstance(attestation_value.get("executor_id"), str) else None
            ),
            "executor_key_id": (
                proof.get("key_id")
                if isinstance(proof, dict) and isinstance(proof.get("key_id"), str)
                else None
            ),
            "observed_effects_digest": _normalize_digest(
                attestation_value.get("observed_effects_digest")
            ),
        }

    def input_commitments() -> dict:
        policy_present = "policyPredictedEffects" in opts
        return {
            "receipt_digest": _safe_digest(receipt),
            "attestation_digest": _safe_digest(attestation),
            "policy_predictions_present": policy_present,
            "policy_predictions_digest": (
                _safe_digest(opts.get("policyPredictedEffects"))
                if policy_present
                else None
            ),
        }

    def refuse(reason: str) -> dict:
        errors.append(reason)
        outcome_binding = {
            "@version": OUTCOME_BINDING_VERSION,
            "outcome": "incomparable",
            "evaluations": [],
            "reasons": list(errors),
        }
        digest_input = {
            "input_commitments": input_commitments(),
            "exact_commitments": exact_commitments(),
            "valid": False,
            "verdict": outcome_binding["outcome"],
            "checks": checks,
            "errors": errors,
            "outcome_binding": outcome_binding,
        }
        return {
            "valid": False,
            "checks": checks,
            "errors": errors,
            "outcome_binding": outcome_binding,
            "result_digest": _digest(digest_input),
        }

    if not callable(verify_receipt):
        return refuse("receipt_verifier_required")
    try:
        receipt_result = verify_receipt(receipt, opts.get("receiptOptions") or {})
    except Exception:
        return refuse("receipt_verifier_failed")
    checks["receipt_verified"] = (
        isinstance(receipt_result, dict) and receipt_result.get("valid") is True
    )
    if not checks["receipt_verified"]:
        return refuse("receipt_verification_failed")

    action = receipt.get("action") if isinstance(receipt, dict) else None
    signed_predictions = action.get("predicted_effects") if isinstance(action, dict) else None
    bound_prediction_digest = (
        action.get("predicted_effects_digest") if isinstance(action, dict) else None
    )
    prediction_validation = validate_predicted_effects(signed_predictions)
    checks["signed_predictions"] = (
        prediction_validation["ok"]
        and _normalize_digest(bound_prediction_digest)
        == _normalize_digest(predicted_effects_digest(signed_predictions))
    )
    if not checks["signed_predictions"]:
        return refuse("signed_predictions_missing_or_mismatched")
    if (
        "policyPredictedEffects" in opts
        and not isinstance(opts.get("policyPredictedEffects"), list)
    ):
        return refuse("policy_predictions_present_but_not_array")
    if isinstance(opts.get("policyPredictedEffects"), list):
        policy_validation = validate_predicted_effects(
            opts["policyPredictedEffects"]
        )
        if not policy_validation["ok"]:
            errors.extend(
                f"relying_party_policy: {reason}"
                for reason in policy_validation["reasons"]
            )
            return refuse("policy_predictions_malformed")

    attestation_result = verify_outcome_attestation(
        attestation,
        {"executorKeys": opts.get("executorKeys") or {}, "now": opts.get("now")}
        if "now" in opts
        else {"executorKeys": opts.get("executorKeys") or {}},
    )
    checks["attestation_verified"] = attestation_result["valid"]
    if not checks["attestation_verified"]:
        errors.extend(attestation_result["errors"])
        return refuse("outcome_attestation_verification_failed")

    receipt_id = receipt.get("receipt_id") if isinstance(receipt, dict) else None
    receipt_action_hash = receipt.get("action_hash") if isinstance(receipt, dict) else None
    consumption = receipt.get("consumption") if isinstance(receipt, dict) else None
    checks["receipt_bound"] = attestation.get("receipt_id") == receipt_id
    checks["receipt_digest_bound"] = (
        _normalize_digest(attestation.get("receipt_digest"))
        == _normalize_digest(trust_receipt_digest(receipt))
    )
    checks["action_bound"] = (
        _normalize_digest(attestation.get("action_hash"))
        == _normalize_digest(receipt_action_hash)
    )
    checks["consumption_bound"] = (
        isinstance(consumption, dict)
        and isinstance(consumption.get("nonce"), str)
        and attestation.get("consumption_nonce") == consumption.get("nonce")
    )
    if not checks["receipt_bound"]:
        errors.append("receipt_id_mismatch")
    if not checks["receipt_digest_bound"]:
        errors.append("receipt_digest_mismatch")
    if not checks["action_bound"]:
        errors.append("action_hash_mismatch")
    if not checks["consumption_bound"]:
        errors.append("consumption_nonce_mismatch")
    if not all(
        checks[key]
        for key in ("receipt_bound", "receipt_digest_bound", "action_bound", "consumption_bound")
    ):
        return refuse("attestation_not_bound_to_verified_receipt")

    signed_evaluation = evaluate_predicted_effects(
        signed_predictions, attestation["observed_effects"]
    )
    policy_evaluation = (
        evaluate_predicted_effects(
            opts["policyPredictedEffects"], attestation["observed_effects"]
        )
        if isinstance(opts.get("policyPredictedEffects"), list)
        else None
    )
    outcome_binding = _combine_evaluations(signed_evaluation, policy_evaluation)
    result_errors = errors + outcome_binding["reasons"]
    valid = all(checks.values()) and outcome_binding["outcome"] == "in_bounds"
    digest_input = {
        "input_commitments": {
            **input_commitments(),
            "signed_predictions_digest": predicted_effects_digest(signed_predictions),
        },
        "exact_commitments": exact_commitments(),
        "valid": valid,
        "verdict": outcome_binding["outcome"],
        "checks": checks,
        "errors": result_errors,
        "outcome_binding": outcome_binding,
    }
    return {
        "valid": valid,
        "checks": checks,
        "errors": result_errors,
        "receipt_result": receipt_result,
        "attestation_result": attestation_result,
        "outcome_binding": outcome_binding,
        "result_digest": _digest(digest_input),
    }


def verify_outcome_binding(
    receipt: Any, attestation: Any, opts: Optional[dict] = None
) -> dict:
    """Verify the complete Trust Receipt plus Outcome Binding composition."""
    from . import verify_trust_receipt

    return verify_outcome_binding_core(
        receipt, attestation, opts, verify_trust_receipt
    )


__all__ = [
    "OUTCOME_ATTESTATION_VERSION",
    "OUTCOME_ATTESTATION_DOMAIN",
    "OUTCOME_BINDING_VERSION",
    "OUTCOME_BINDING_OUTCOMES",
    "PREDICATE_OPS",
    "MAX_PREDICTED_EFFECTS",
    "MAX_OBSERVED_EFFECTS",
    "MAX_EFFECT_STRING_LENGTH",
    "is_decimal_string",
    "compare_decimal_strings",
    "predicted_effects_digest",
    "observed_effects_digest",
    "trust_receipt_digest",
    "validate_predicted_effects",
    "evaluate_predicted_effects",
    "verify_outcome_attestation",
    "verify_outcome_binding_core",
    "verify_outcome_binding",
]
