# SPDX-License-Identifier: Apache-2.0
"""EP-AUTHORITY-DOC-PROOF-JOIN-v1.

Faithful same-team Python port of ``lib/authority/document-proof-join.js``.
The join establishes only that an Authority Proof signer is accepted through
an independently anchored Authority Document chain. Grant/action authorization,
delegation, and registry membership remain separate evaluations.
"""
from __future__ import annotations

import hashlib
import math
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key

from . import _b64url_decode, canonicalize

AUTHORITY_DOCUMENT_VERSION = "EP-AUTHORITY-DOC-v1"
AUTHORITY_PROOF_VERSION = "EP-AUTHORITY-PROOF-v1"
AUTHORITY_PROOF_DOMAIN = "EP-AUTHORITY-PROOF-v1\0"

_MAX_SAFE_INTEGER = 2**53 - 1
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PROOF_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$", re.IGNORECASE)
_ISSUER_KID_RE = re.compile(r"^ep:authority-issuer-key:sha256:[0-9a-f]{64}$")
_PROOF_KEY_ID_RE = re.compile(r"^ep:authority-registry-key:sha256:[0-9a-f]{64}$")
_RFC3339_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d{1,9}))?(?:Z|([+-])(\d{2}):(\d{2}))$"
)

_CHECK_NAMES = (
    "document_chain",
    "continuity",
    "document_anchor",
    "organization_binding",
    "proof_document_binding",
    "registry_issuer_binding",
    "issuer_key_resolved",
    "issuer_key_usage",
    "proof_signature",
    "proof_time_anchor",
    "registry_head",
    "epoch_fresh",
)


def _safe_integer(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER else None
    if isinstance(value, float) and math.isfinite(value) and value.is_integer():
        integer = int(value)
        return integer if -_MAX_SAFE_INTEGER <= integer <= _MAX_SAFE_INTEGER else None
    return None


def _instant_ns(value: Any) -> Optional[int]:
    """Parse the strict RFC 3339 instant grammar used by the JS authority code."""
    if not isinstance(value, str):
        return None
    match = _RFC3339_RE.fullmatch(value)
    if not match:
        return None
    year, month, day, hour, minute, second = (int(x) for x in match.groups()[:6])
    fraction, sign, offset_hour, offset_minute = match.groups()[6:]
    if offset_hour is not None and (int(offset_hour) > 23 or int(offset_minute) > 59):
        return None
    try:
        local = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        return None
    offset = timedelta()
    if sign is not None:
        offset = timedelta(hours=int(offset_hour), minutes=int(offset_minute))
        if sign == "-":
            offset = -offset
    utc = local - offset
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = utc - epoch
    whole_ns = (delta.days * 86400 + delta.seconds) * 1_000_000_000
    fractional_ns = int((fraction or "").ljust(9, "0") or "0")
    return whole_ns + fractional_ns


def _stable_identifier(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    # JSON Schema maxLength and this profile count Unicode code points.
    if len(value) > 512:
        return False
    return not any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value)


def _ed25519_key(public_key_b64u: Any) -> Optional[Tuple[Ed25519PublicKey, bytes]]:
    if not isinstance(public_key_b64u, str):
        return None
    try:
        der = _b64url_decode(public_key_b64u)
        key = load_der_public_key(der)
    except Exception:
        return None
    if not isinstance(key, Ed25519PublicKey):
        return None
    return key, der


def _verify_ed25519(data: bytes, public_key_b64u: Any, signature_b64u: Any) -> bool:
    if not isinstance(signature_b64u, str):
        return False
    loaded = _ed25519_key(public_key_b64u)
    if loaded is None:
        return False
    try:
        loaded[0].verify(_b64url_decode(signature_b64u), data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def authority_issuer_key_id(public_key_b64u: Any) -> Optional[str]:
    loaded = _ed25519_key(public_key_b64u)
    if loaded is None:
        return None
    return "ep:authority-issuer-key:sha256:" + hashlib.sha256(loaded[1]).hexdigest()


def authority_document_core_digest(document: Any) -> str:
    if not isinstance(document, dict):
        raise ValueError("authority document must be an object")
    core = {
        key: value
        for key, value in document.items()
        if key not in ("sig", "continuity_sig", "endorsements")
    }
    digest = hashlib.sha256(canonicalize(core).encode("utf-8")).hexdigest()
    return "sha256:" + digest


def _terminal_revocation_ns(documents: List[Dict[str, Any]], kid: str) -> Optional[int]:
    terminal: Optional[int] = None
    for document in documents:
        entries = document.get("issuer_keys") if isinstance(document, dict) else None
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("kid") != kid or "revoked_at" not in entry:
                continue
            candidate = _instant_ns(entry.get("revoked_at"))
            if candidate is not None and (terminal is None or candidate < terminal):
                terminal = candidate
    return terminal


def _verify_authority_chain(documents: Any) -> Dict[str, Any]:
    reasons: List[str] = []
    if not isinstance(documents, list) or not documents:
        return {"verified": False, "head": None, "breaks": [], "reasons": ["empty chain"]}
    if not all(isinstance(document, dict) for document in documents):
        return {
            "verified": False,
            "head": None,
            "breaks": [],
            "reasons": ["authority document is not an object"],
        }

    docs: List[Dict[str, Any]] = documents
    breaks: List[int] = []
    registry_identity_by_kid: Dict[str, Any] = {}
    first_org = docs[0].get("org") if isinstance(docs[0].get("org"), dict) else {}

    for index, document in enumerate(docs):
        if document.get("@version") != AUTHORITY_DOCUMENT_VERSION:
            return {"verified": False, "head": None, "breaks": breaks, "reasons": reasons + [f"doc {index}: bad version"]}
        if _safe_integer(document.get("seq")) != index:
            return {"verified": False, "head": None, "breaks": breaks, "reasons": reasons + [f"doc {index}: bad sequence"]}

        org = document.get("org")
        if not isinstance(org, dict) or not _stable_identifier(org.get("domain")):
            return {"verified": False, "head": None, "breaks": breaks, "reasons": reasons + [f"doc {index}: unstable organization"]}
        if "id" in org and not _stable_identifier(org.get("id")):
            return {"verified": False, "head": None, "breaks": breaks, "reasons": reasons + [f"doc {index}: unstable organization"]}
        if index > 0 and (org.get("domain") != first_org.get("domain") or org.get("id") != first_org.get("id")):
            return {"verified": False, "head": None, "breaks": breaks, "reasons": reasons + [f"doc {index}: organization changed"]}
        if _instant_ns(document.get("issued_at")) is None:
            return {"verified": False, "head": None, "breaks": breaks, "reasons": reasons + [f"doc {index}: invalid issued_at"]}
        if _ed25519_key(document.get("root_key")) is None:
            return {"verified": False, "head": None, "breaks": breaks, "reasons": reasons + [f"doc {index}: invalid root key"]}

        entries = document.get("issuer_keys")
        if not isinstance(entries, list):
            return {"verified": False, "head": None, "breaks": breaks, "reasons": reasons + [f"doc {index}: issuer_keys is not an array"]}
        kids = set()
        for entry in entries:
            if not isinstance(entry, dict):
                return {"verified": False, "head": None, "breaks": breaks, "reasons": reasons + [f"doc {index}: invalid issuer key"]}
            kid = entry.get("kid")
            if not isinstance(kid, str) or not kid or kid in kids:
                return {"verified": False, "head": None, "breaks": breaks, "reasons": reasons + [f"doc {index}: invalid issuer key id"]}
            kids.add(kid)
            valid_from = _instant_ns(entry.get("valid_from"))
            valid_to = _instant_ns(entry.get("valid_to"))
            revoked_at = _instant_ns(entry.get("revoked_at")) if "revoked_at" in entry else None
            if valid_from is None or valid_to is None or valid_from > valid_to \
                    or ("revoked_at" in entry and revoked_at is None):
                return {"verified": False, "head": None, "breaks": breaks, "reasons": reasons + [f"doc {index}: invalid issuer key window"]}
            if _ed25519_key(entry.get("key")) is None or authority_issuer_key_id(entry.get("key")) != kid:
                return {"verified": False, "head": None, "breaks": breaks, "reasons": reasons + [f"doc {index}: issuer key mismatch"]}
            if "registry_issuer_id" in entry and not _stable_identifier(entry.get("registry_issuer_id")):
                return {"verified": False, "head": None, "breaks": breaks, "reasons": reasons + [f"doc {index}: unstable registry issuer"]}
            registry_identity = entry.get("registry_issuer_id")
            if kid in registry_identity_by_kid and registry_identity_by_kid[kid] != registry_identity:
                return {"verified": False, "head": None, "breaks": breaks, "reasons": reasons + [f"doc {index}: registry issuer changed"]}
            registry_identity_by_kid[kid] = registry_identity
            if "usages" in entry:
                usages = entry.get("usages")
                if not isinstance(usages, list) or any(not _stable_identifier(usage) for usage in usages) \
                        or len(set(usages)) != len(usages):
                    return {"verified": False, "head": None, "breaks": breaks, "reasons": reasons + [f"doc {index}: invalid usages"]}

        core = {
            key: value
            for key, value in document.items()
            if key not in ("sig", "continuity_sig", "endorsements")
        }
        if not _verify_ed25519(
            canonicalize(core).encode("utf-8"),
            document.get("root_key"),
            document.get("sig"),
        ):
            return {"verified": False, "head": None, "breaks": breaks, "reasons": reasons + [f"doc {index}: self-signature invalid"]}

        if index == 0:
            if "prev_doc_digest" not in document or document.get("prev_doc_digest") is not None:
                return {"verified": False, "head": None, "breaks": breaks, "reasons": reasons + ["doc 0: unexpected prev digest"]}
            continue

        previous = docs[index - 1]
        if document.get("prev_doc_digest") != authority_document_core_digest(previous):
            return {"verified": False, "head": None, "breaks": breaks, "reasons": reasons + [f"doc {index}: prev digest mismatch"]}
        issued_at = _instant_ns(document.get("issued_at"))
        previous_issued_at = _instant_ns(previous.get("issued_at"))
        if issued_at is None or previous_issued_at is None or issued_at <= previous_issued_at:
            return {"verified": False, "head": None, "breaks": breaks, "reasons": reasons + [f"doc {index}: non-monotonic issued_at"]}

        continuity_keys = [previous.get("root_key")]
        for entry in previous.get("issuer_keys", []):
            usages = entry.get("usages")
            valid_from = _instant_ns(entry.get("valid_from"))
            valid_to = _instant_ns(entry.get("valid_to"))
            revoked_at = _terminal_revocation_ns(docs, entry.get("kid"))
            if isinstance(usages, list) and "authority_doc_rotation" in usages \
                    and valid_from is not None and valid_to is not None \
                    and valid_from <= issued_at <= valid_to \
                    and (revoked_at is None or issued_at < revoked_at):
                continuity_keys.append(entry.get("key"))
        continuity_data = authority_document_core_digest(document).encode("utf-8")
        continuity_ok = isinstance(document.get("continuity_sig"), str) and any(
            _verify_ed25519(continuity_data, key, document.get("continuity_sig"))
            for key in continuity_keys
        )
        if not continuity_ok:
            breaks.append(index)
            reasons.append(f"doc {index}: no valid continuity")

    return {"verified": True, "head": docs[-1], "breaks": breaks, "reasons": reasons}


def _resolve_issuer_key_at(documents: Any, kid: str, at_iso: Any) -> Optional[Dict[str, Any]]:
    at = _instant_ns(at_iso)
    if not isinstance(documents, list) or at is None:
        return None
    docs = [document for document in documents if isinstance(document, dict)]
    if len(docs) != len(documents):
        return None
    revoked_at = _terminal_revocation_ns(docs, kid)
    if revoked_at is not None and at >= revoked_at:
        return None

    effective_document = None
    for document in reversed(docs):
        issued_at = _instant_ns(document.get("issued_at"))
        if issued_at is not None and issued_at <= at:
            effective_document = document
            break
    if effective_document is None or not isinstance(effective_document.get("issuer_keys"), list):
        return None
    entry = next(
        (
            candidate
            for candidate in effective_document["issuer_keys"]
            if isinstance(candidate, dict) and candidate.get("kid") == kid
        ),
        None,
    )
    if entry is None:
        return None
    valid_from = _instant_ns(entry.get("valid_from"))
    valid_to = _instant_ns(entry.get("valid_to"))
    if valid_from is None or valid_to is None or at < valid_from or at > valid_to:
        return None
    return {
        "key": entry.get("key"),
        "usages": list(entry.get("usages")) if isinstance(entry.get("usages"), list) else [],
        "custody_class": entry.get("custody_class"),
        "registry_issuer_id": entry.get("registry_issuer_id"),
        "kid": entry.get("kid"),
        "doc_seq": effective_document.get("seq"),
    }


def _authority_proof_digest(proof: Any) -> str:
    if not isinstance(proof, dict):
        raise ValueError("authority proof must be an object")
    unsigned = {key: value for key, value in proof.items() if key != "signature"}
    signing_bytes = (AUTHORITY_PROOF_DOMAIN + canonicalize(unsigned)).encode("utf-8")
    return "sha256:" + hashlib.sha256(signing_bytes).hexdigest()


def _verify_authority_proof_signature(proof: Any) -> Dict[str, Any]:
    checks = {
        "version": isinstance(proof, dict) and proof.get("@type") == AUTHORITY_PROOF_VERSION,
        "proof_digest": False,
        "key_id": False,
        "signature": False,
    }

    def fail(reason: str, **extra: Any) -> Dict[str, Any]:
        return {"verified": False, "accepted": False, "checks": checks.copy(), "reason": reason, **extra}

    if not checks["version"]:
        return fail("unsupported_version")
    signature = proof.get("signature")
    if not isinstance(signature, dict) or signature.get("algorithm") != "Ed25519" \
            or not isinstance(signature.get("public_key"), str) \
            or not isinstance(signature.get("signature_b64u"), str) \
            or not isinstance(signature.get("proof_digest"), str) \
            or not _PROOF_DIGEST_RE.fullmatch(signature["proof_digest"]) \
            or not isinstance(signature.get("key_id"), str) \
            or not _PROOF_KEY_ID_RE.fullmatch(signature["key_id"]):
        return fail("signature_missing_or_malformed")
    try:
        proof_digest = _authority_proof_digest(proof)
    except Exception:
        return fail("proof_uncanonicalizable")
    checks["proof_digest"] = proof_digest == signature["proof_digest"]
    if not checks["proof_digest"]:
        return fail("proof_digest_mismatch", proof_digest=proof_digest)
    try:
        public_key_der = _b64url_decode(signature["public_key"])
    except Exception:
        public_key_der = b""
    derived_key_id = (
        "ep:authority-registry-key:sha256:" + hashlib.sha256(public_key_der).hexdigest()
        if public_key_der
        else ""
    )
    checks["key_id"] = signature["key_id"] == derived_key_id
    if not checks["key_id"]:
        return fail("key_id_mismatch", proof_digest=proof_digest)
    unsigned = {key: value for key, value in proof.items() if key != "signature"}
    checks["signature"] = _verify_ed25519(
        (AUTHORITY_PROOF_DOMAIN + canonicalize(unsigned)).encode("utf-8"),
        signature["public_key"],
        signature["signature_b64u"],
    )
    if not checks["signature"]:
        return fail("signature_invalid", proof_digest=proof_digest)
    return {
        "verified": True,
        "accepted": False,
        "checks": checks.copy(),
        "key_id": derived_key_id,
        "proof_digest": proof_digest,
    }


def verify_authority_proof_via_document(
    proof: Any,
    documents: Any,
    options: Any = None,
) -> Dict[str, Any]:
    """Verify an Authority Proof issuer through an Authority Document chain.

    ``options`` uses the wire-compatible JS names present in the shared
    conformance fixtures (for example ``expectedProofIssuedAt`` and
    ``expectRegistryHead``). The function is fail-closed and never raises.
    """
    opts = options if isinstance(options, dict) else {}
    checks = {name: False for name in _CHECK_NAMES}
    signature = _verify_authority_proof_signature(proof)
    checks["proof_signature"] = signature["verified"]

    def fail(reason: str, **extra: Any) -> Dict[str, Any]:
        return {
            "verified": bool(
                checks["proof_signature"] and checks["document_chain"] and checks["continuity"]
            ),
            "issuer_accepted": False,
            "accepted": False,
            "authority_evaluated": False,
            "delegation_evaluated": False,
            "checks": checks.copy(),
            "reason": reason,
            **extra,
        }

    try:
        chain = _verify_authority_chain(documents)
    except Exception:
        return fail("authority_document_chain_invalid")
    if not chain.get("verified") or not isinstance(chain.get("head"), dict):
        return fail("authority_document_chain_invalid")
    checks["document_chain"] = True
    docs: List[Dict[str, Any]] = documents
    try:
        document_head = authority_document_core_digest(chain["head"])
        bootstrap_digest = authority_document_core_digest(docs[0])
    except Exception:
        return fail("authority_document_chain_invalid")
    context = {"document_head": document_head, "bootstrap_digest": bootstrap_digest}

    if chain.get("breaks"):
        return fail("authority_document_continuity_break", **context)
    checks["continuity"] = True

    has_head_anchor = isinstance(opts.get("expectedDocumentHead"), str)
    has_bootstrap_anchor = isinstance(opts.get("expectedBootstrapDigest"), str)
    if not has_head_anchor and not has_bootstrap_anchor:
        return fail("authority_document_anchor_required", **context)
    if (has_head_anchor and opts["expectedDocumentHead"] != document_head) \
            or (has_bootstrap_anchor and opts["expectedBootstrapDigest"] != bootstrap_digest):
        return fail("authority_document_anchor_mismatch", **context)
    checks["document_anchor"] = True

    organization_id = opts.get("expectedOrganizationId")
    organization_domain = opts.get("expectedOrganizationDomain")
    if not _stable_identifier(organization_id) or not _stable_identifier(organization_domain) \
            or not isinstance(proof, dict) or proof.get("organization_id") != organization_id \
            or any(
                not isinstance(document.get("org"), dict)
                or document["org"].get("id") != organization_id
                or document["org"].get("domain") != organization_domain
                for document in docs
            ):
        return fail("authority_document_organization_mismatch", **context)
    checks["organization_binding"] = True

    expected_proof_time = opts.get("expectedProofIssuedAt")
    if not isinstance(expected_proof_time, str):
        return fail("authority_proof_time_anchor_required", **context)
    if _instant_ns(expected_proof_time) is None or _instant_ns(proof.get("issued_at")) is None:
        return fail("authority_proof_time_anchor_invalid", **context)
    if not isinstance(proof.get("issued_at"), str) or proof["issued_at"] != expected_proof_time:
        return fail("authority_proof_time_anchor_mismatch", **context)
    checks["proof_time_anchor"] = True

    binding = proof.get("authority_document")
    binding_seq = _safe_integer(binding.get("head_seq")) if isinstance(binding, dict) else None
    if not isinstance(binding, dict) or set(binding.keys()) != {"head_digest", "head_seq", "issuer_kid"} \
            or not isinstance(binding.get("head_digest"), str) \
            or not _DIGEST_RE.fullmatch(binding["head_digest"]) \
            or binding_seq is None or binding_seq < 0 or binding_seq >= len(docs) \
            or not isinstance(binding.get("issuer_kid"), str) \
            or not _ISSUER_KID_RE.fullmatch(binding["issuer_kid"]):
        return fail("authority_proof_document_binding_missing_or_malformed", **context)
    bound_document = docs[binding_seq]
    if authority_document_core_digest(bound_document) != binding["head_digest"]:
        return fail("authority_proof_document_head_mismatch", **context)
    checks["proof_document_binding"] = True

    registry_issuer_id = opts.get("expectedRegistryIssuerId")
    if not _stable_identifier(registry_issuer_id) \
            or not _stable_identifier(proof.get("registry_issuer_id")) \
            or proof.get("registry_issuer_id") != registry_issuer_id:
        return fail("authority_registry_issuer_mismatch", **context)
    bound_entry = next(
        (
            entry
            for entry in bound_document.get("issuer_keys", [])
            if isinstance(entry, dict) and entry.get("kid") == binding["issuer_kid"]
        ),
        None,
    )
    if bound_entry is None or bound_entry.get("registry_issuer_id") != registry_issuer_id:
        return fail("authority_registry_issuer_mismatch", **context)
    checks["registry_issuer_binding"] = True

    resolved = _resolve_issuer_key_at(docs, binding["issuer_kid"], expected_proof_time)
    proof_signature = proof.get("signature") if isinstance(proof.get("signature"), dict) else {}
    if resolved is None or resolved.get("kid") != binding["issuer_kid"] \
            or resolved.get("doc_seq") != binding_seq \
            or resolved.get("key") != bound_entry.get("key") \
            or resolved.get("key") != proof_signature.get("public_key") \
            or resolved.get("registry_issuer_id") != registry_issuer_id:
        return fail("authority_proof_key_unresolvable", **context)
    checks["issuer_key_resolved"] = True

    if "authority_proof_issuer" not in resolved.get("usages", []):
        return fail("authority_proof_key_wrong_usage", **context)
    checks["issuer_key_usage"] = True

    if not signature["verified"]:
        return fail(
            signature.get("reason", "authority_proof_invalid"),
            **context,
            proof_digest=signature.get("proof_digest"),
        )

    min_epoch = _safe_integer(opts.get("expectMinEpoch"))
    if not isinstance(opts.get("expectRegistryHead"), str) \
            or not _DIGEST_RE.fullmatch(opts["expectRegistryHead"]) \
            or min_epoch is None or min_epoch < 0:
        return fail(
            "registry_snapshot_pins_required",
            **context,
            proof_digest=signature.get("proof_digest"),
        )
    if proof.get("registry_head") != opts["expectRegistryHead"]:
        return fail("registry_head_mismatch", **context, proof_digest=signature.get("proof_digest"))
    checks["registry_head"] = True
    proof_epoch = _safe_integer(proof.get("registry_epoch"))
    if proof_epoch is None or proof_epoch < min_epoch:
        return fail("stale_registry", **context, proof_digest=signature.get("proof_digest"))
    checks["epoch_fresh"] = True

    return {
        "verified": True,
        "issuer_accepted": True,
        "accepted": True,
        "authority_evaluated": False,
        "delegation_evaluated": False,
        "checks": checks.copy(),
        "document_head": document_head,
        "proof_document_head": binding["head_digest"],
        "bootstrap_digest": bootstrap_digest,
        "registry_issuer_id": registry_issuer_id,
        "proof_digest": signature["proof_digest"],
        "key_id": binding["issuer_kid"],
        "limitations": [
            "Issuer acceptance is not a decision that the grant authorizes an action.",
            "Grant scope, limits, validity, revocation freshness, and delegation require separate evaluation.",
            "Authority-registry membership requires independently verified snapshot or inclusion evidence.",
        ],
    }


__all__ = [
    "AUTHORITY_DOCUMENT_VERSION",
    "AUTHORITY_PROOF_VERSION",
    "AUTHORITY_PROOF_DOMAIN",
    "authority_document_core_digest",
    "authority_issuer_key_id",
    "verify_authority_proof_via_document",
]
