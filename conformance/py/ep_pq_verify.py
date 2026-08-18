# SPDX-License-Identifier: Apache-2.0
"""EP hybrid post-quantum VERIFICATION, ported to Python for the conformance suite.

This module is a verification-only port of three EP profiles. It NEVER signs.
Issuance stays in JavaScript (packages/issue, packages/verify); a second signer
would be a second thing to keep byte-identical for no verifier benefit.

  EP-SIG-AGILITY-v1     packages/verify/src/pq-signature-agility.ts
                        per-artifact algorithm agility over unchanged canonical
                        bytes. Closed registry {Ed25519, ML-DSA-65}. The
                        algorithm is an explicit, verifier-checked field.

  EP-HYBRID-v1          packages/verify/src/pq-hybrid.ts
                        infrastructure envelope. BOTH signatures cover a
                        domain-separated signing input that includes the
                        algorithm set, so stripping or reordering an algorithm
                        changes what was signed. Carries the curve pin
                        (algorithm_key_mismatch) and the exact length pins
                        (signature_length_invalid).

  EP-RECEIPT-HYBRID-v1  packages/issue/src/hybrid-issuance.ts
                        issued receipts whose SIGNED MATERIAL commits to the
                        required algorithm set, verified by delegating to the
                        EP-SIG-AGILITY-v1 set verifier under policy hybrid_all.

The EP-REVOCATION-v2 set-proof pattern (packages/verify/src/revocation.ts) is
the same shape a third time: recompute the signed bytes from the REGISTERED
algorithm set rather than the set the document claims, then require one leg per
required algorithm. That recompute-from-registered rule is implemented here in
verify_hybrid_receipt and is the reason a narrowed set fails twice.

FAIL-CLOSED
  Every public verify function returns a structured refusal naming a reason.
  None of them raise on caller input: malformed messages, signatures, keys,
  envelopes, and receipts all produce a reason, never an exception and never a
  pass. Refusal names are the JS names, byte for byte.

ML-DSA BACKEND ("no backend is a refusal")
  This module ships with no post-quantum dependency, exactly as
  packages/verify does. The ML-DSA-65 leg is cryptographically live only when a
  backend is present, via caller injection or lazy discovery of an installed
  implementation. When no backend is available the result is
  pq_backend_unavailable. The check is NEVER skipped, and a valid classical leg
  NEVER carries an artifact on its own.

  Structural verification (shape, exact lengths, algorithm-set commitment,
  anti-stripping byte reconstruction, duplicate and unexpected algorithms) runs
  with or without a backend, because none of it needs one.
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
_PYTHON_VERIFY = os.path.join(_REPO_ROOT, "packages", "python-verify")
if _PYTHON_VERIFY not in sys.path:
    sys.path.insert(0, _PYTHON_VERIFY)

from emilia_verify import canonicalize, is_canonicalizable  # noqa: E402

from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import load_der_public_key  # noqa: E402

# ---------------------------------------------------------------------------
# Registry, sizes, and the named refusal vocabularies (mirrored exactly)
# ---------------------------------------------------------------------------

SIGNATURE_AGILITY_VERSION = "EP-SIG-AGILITY-v1"
HYBRID_ALG = "EP-HYBRID-v1"
HYBRID_DOMAIN = "emilia-protocol/pq-hybrid/v1"
HYBRID_RECEIPT_PROFILE = "EP-RECEIPT-HYBRID-v1"

AGILE_SIGNATURE_ALGORITHMS: Tuple[str, ...] = ("Ed25519", "ML-DSA-65")
HYBRID_SIGNATURE_ALGOS: Tuple[str, ...] = ("Ed25519", "ML-DSA-65")
HYBRID_RECEIPT_REQUIRED_ALGORITHMS: Tuple[str, ...] = ("Ed25519", "ML-DSA-65")

ED25519_SIGNATURE_BYTES = 64
ML_DSA_65_SIGNATURE_BYTES = 3309
ML_DSA_65_PUBLIC_KEY_BYTES = 1952
ML_DSA_65_SECRET_KEY_BYTES = 4032

AGILITY_REASONS = {
    "MALFORMED_INPUT": "malformed_input",
    "UNKNOWN_ALGORITHM": "unknown_algorithm",
    "UNKNOWN_POLICY": "unknown_policy",
    "MALFORMED_KEY": "malformed_key",
    "MALFORMED_SIGNATURE": "malformed_signature",
    "ALGORITHM_KEY_MISMATCH": "algorithm_key_mismatch",
    "SIGNATURE_INVALID": "signature_invalid",
    "PQ_BACKEND_UNAVAILABLE": "pq_backend_unavailable",
    "DUPLICATE_ALGORITHM": "duplicate_algorithm",
    "MISSING_REQUIRED_ALGORITHM": "missing_required_algorithm",
    "EMPTY_SIGNATURE_SET": "empty_signature_set",
}

HYBRID_REASONS = {
    "INVALID_INPUT": "invalid_input",
    "INVALID_ENVELOPE": "invalid_envelope",
    "ALGO_SET_MISMATCH": "algo_set_mismatch",
    "MISSING_SIGNATURE": "missing_signature",
    "MISSING_KEY": "missing_key",
    "ALGORITHM_KEY_MISMATCH": "algorithm_key_mismatch",
    "SIGNATURE_LENGTH_INVALID": "signature_length_invalid",
    "PUBLIC_KEY_LENGTH_INVALID": "public_key_length_invalid",
    "CLASSICAL_INVALID": "classical_signature_invalid",
    "PQ_INVALID": "pq_signature_invalid",
    "PQ_BACKEND_UNAVAILABLE": "pq_backend_unavailable",
}

HYBRID_RECEIPT_REASONS = {
    "MALFORMED_RECEIPT": "malformed_receipt",
    "MALFORMED_PAYLOAD": "malformed_payload",
    "UNKNOWN_PROFILE": "unknown_profile",
    "ALGORITHM_SET_MISMATCH": "algorithm_set_mismatch",
    "HYBRID_LEG_MISSING": "hybrid_leg_missing",
    "UNEXPECTED_ALGORITHM": "unexpected_algorithm",
    "DUPLICATE_ALGORITHM": "duplicate_algorithm",
    "MISSING_KEY": "missing_key",
    "SIGNATURE_INVALID": "signature_invalid",
    "PQ_BACKEND_UNAVAILABLE": "pq_backend_unavailable",
    "AGILITY_MODULE_UNAVAILABLE": "agility_module_unavailable",
}


# ---------------------------------------------------------------------------
# base64url decoding, in the two flavours the JS sources actually use
# ---------------------------------------------------------------------------

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_B64URL_VALUES = {c: i for i, c in enumerate(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)}


def node_base64url_decode(text: Any) -> Optional[bytes]:
    """Decode base64url the way node's Buffer.from(s, 'base64url') does.

    Node is LENIENT: characters outside the alphabet are ignored, padding is
    optional, and a trailing group of a single character contributes nothing.
    packages/verify/src/pq-hybrid.ts decodes signatures and keys this way, and
    it then pins the decoded LENGTH, so leniency here never widens acceptance;
    it only changes which named reason a malformed blob earns. Reproducing the
    exact leniency is what keeps the refusal names identical across languages.
    """
    if not isinstance(text, str):
        return None
    out = bytearray()
    acc = 0
    bits = 0
    for c in text:
        value = _B64URL_VALUES.get(c)
        if value is None:
            continue  # node ignores characters outside the alphabet, '=' included
        acc = (acc << 6) | value
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    # A trailing group of a single character carries 6 bits and contributes no
    # byte, which is exactly what the accumulator above does.
    return bytes(out)


def strict_base64url_decode(text: Any) -> Optional[bytes]:
    """The agility module's strict decoder: non-empty, alphabet-only, no padding.

    packages/verify/src/pq-signature-agility.ts gates on this regex before
    decoding, with the comment that lenient decoding would mask a tampering
    class. Anything the regex rejects is a malformed_signature / malformed_key,
    not a silently repaired value.
    """
    if not isinstance(text, str) or len(text) == 0 or not _B64URL_RE.match(text):
        return None
    return node_base64url_decode(text)


def _to_raw_key_bytes(key: Any) -> Optional[bytes]:
    if isinstance(key, (bytes, bytearray, memoryview)):
        return bytes(key)
    if isinstance(key, str):
        return strict_base64url_decode(key)
    return None


def _to_raw_bytes_lenient(key: Any) -> Optional[bytes]:
    """pq-hybrid.ts toRawBytes: raw bytes, or a non-empty base64url string."""
    if isinstance(key, (bytes, bytearray, memoryview)):
        return bytes(key)
    if isinstance(key, str) and len(key) > 0:
        return node_base64url_decode(key)
    return None


# ---------------------------------------------------------------------------
# Ed25519 key resolution, CURVE-PINNED
# ---------------------------------------------------------------------------

ALGORITHM_MISMATCH = "algorithm_mismatch"


def _load_public_key_der(der: bytes) -> Any:
    return load_der_public_key(der)


def to_ed25519_public_key_pinned(key: Any) -> Union[Ed25519PublicKey, str, None]:
    """pq-hybrid.ts toEd25519PublicKeyObject.

    Returns the key object for a well-formed Ed25519 public key, the sentinel
    ALGORITHM_MISMATCH for a well-formed public key of a DIFFERENT curve or type
    (Ed448, P-256, RSA), and None when the input is not a parseable public key
    at all. The distinction is load-bearing: the caller must refuse a curve
    mismatch by name rather than verifying under the attacker's own algorithm.
    """
    try:
        if isinstance(key, Ed25519PublicKey):
            return key
        if hasattr(key, "public_bytes") and not isinstance(key, (str, bytes, bytearray)):
            return ALGORITHM_MISMATCH
        if isinstance(key, str) and len(key) > 0:
            der = node_base64url_decode(key)
            if der is None:
                return None
            loaded = _load_public_key_der(der)
            return loaded if isinstance(loaded, Ed25519PublicKey) else ALGORITHM_MISMATCH
    except Exception:
        return None
    return None


def to_ed25519_public_key_or_none(key: Any) -> Optional[Ed25519PublicKey]:
    """pq-signature-agility.ts toEd25519PublicKeyObject.

    The agility module collapses "wrong curve" into "malformed key": it returns
    null for both, and the caller refuses with malformed_key either way. Kept
    separate from the pinned variant above so neither module's vocabulary is
    contaminated by the other's.
    """
    try:
        if isinstance(key, Ed25519PublicKey):
            return key
        if hasattr(key, "public_bytes") and not isinstance(key, (str, bytes, bytearray)):
            return None
        if isinstance(key, str):
            der = strict_base64url_decode(key)
            if der is None:
                return None
            loaded = _load_public_key_der(der)
            return loaded if isinstance(loaded, Ed25519PublicKey) else None
    except Exception:
        return None
    return None


def _ed25519_verify(public_key: Ed25519PublicKey, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# ML-DSA-65 backend resolution (lazy, fail-closed; absence is a refusal)
# ---------------------------------------------------------------------------

class MldsaBackend:
    """Minimal verify-only ML-DSA-65 backend surface.

    `verify(signature_bytes, message_bytes, public_key_bytes) -> bool`, argument
    order mirroring the JS backend contract so an injected backend written from
    the JS docs drops straight in.
    """

    def __init__(self, verify: Callable[[bytes, bytes, bytes], bool], name: str):
        self._verify = verify
        self.name = name

    def verify(self, signature_bytes: bytes, message_bytes: bytes, public_key_bytes: bytes) -> bool:
        try:
            return self._verify(bytes(signature_bytes), bytes(message_bytes), bytes(public_key_bytes)) is True
        except Exception:
            # A malformed signature or key refuses; it never throws upward and
            # it never passes.
            return False


def _backend_from_dilithium_py() -> Optional[MldsaBackend]:
    try:
        from dilithium_py.ml_dsa import ML_DSA_65  # type: ignore
    except Exception:
        return None

    def _verify(sig: bytes, msg: bytes, pk: bytes) -> bool:
        return ML_DSA_65.verify(pk, msg, sig) is True

    return MldsaBackend(_verify, "dilithium-py:ML_DSA_65")


def _backend_from_cryptography() -> Optional[MldsaBackend]:
    # cryptography exposes ML-DSA only when built against OpenSSL 3.5 or newer.
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa  # type: ignore
    except Exception:
        return None
    public_key_cls = getattr(mldsa, "MLDSA65PublicKey", None)
    if public_key_cls is None or not hasattr(public_key_cls, "from_public_bytes"):
        return None

    def _verify(sig: bytes, msg: bytes, pk: bytes) -> bool:
        key = public_key_cls.from_public_bytes(pk)
        try:
            key.verify(sig, msg)
            return True
        except Exception:
            return False

    try:
        # Prove the path is actually constructible before advertising it.
        public_key_cls.from_public_bytes(b"\x00" * ML_DSA_65_PUBLIC_KEY_BYTES)
    except Exception:
        return None
    return MldsaBackend(_verify, "cryptography:MLDSA65")


def load_default_mldsa_backend() -> Optional[MldsaBackend]:
    """Discover an installed ML-DSA-65 implementation. NEVER raises.

    Returns None when nothing is installed, so every caller refuses with
    pq_backend_unavailable rather than skipping the post-quantum leg.

    Neither candidate is a FIPS-validated module. dilithium-py is a pure-Python
    FIPS 204 implementation; cryptography's ML-DSA is OpenSSL's. This module
    makes no certification claim, only that the check ran against a real
    implementation or the artifact was refused.
    """
    for candidate in (_backend_from_cryptography, _backend_from_dilithium_py):
        try:
            backend = candidate()
        except Exception:
            backend = None
        if backend is not None:
            return backend
    return None


class _Options:
    """Normalized option bag mirroring the JS options objects.

    mldsa_backend       an explicit backend, or None to fall through
    mldsa_backend_loader a zero-arg callable returning a backend or None;
                        pass `lambda: None` to force the backend-absent path
    """

    __slots__ = ("mldsa_backend", "mldsa_backend_loader", "policy", "required_algorithms")

    def __init__(self, options: Optional[Dict[str, Any]]):
        options = options if isinstance(options, dict) else {}
        self.mldsa_backend = options.get("mldsa_backend")
        self.mldsa_backend_loader = options.get("mldsa_backend_loader")
        self.policy = options.get("policy")
        self.required_algorithms = options.get("required_algorithms")


def _resolve_backend(options: _Options) -> Optional[MldsaBackend]:
    backend = options.mldsa_backend
    if backend is not None:
        return backend if callable(getattr(backend, "verify", None)) else None
    loader = options.mldsa_backend_loader
    if not callable(loader):
        loader = load_default_mldsa_backend
    try:
        resolved = loader()
    except Exception:
        return None
    if resolved is None or not callable(getattr(resolved, "verify", None)):
        return None
    return resolved


# ---------------------------------------------------------------------------
# EP-SIG-AGILITY-v1: verify_agile_signature
# ---------------------------------------------------------------------------

def _is_known_algorithm(alg: Any) -> bool:
    return isinstance(alg, str) and alg in AGILE_SIGNATURE_ALGORITHMS


def _is_plain_object(value: Any) -> bool:
    return isinstance(value, dict)


def verify_agile_signature(
    message_bytes: Any,
    signature: Any,
    key: Any,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Verify ONE agile signature over canonical artifact bytes. Never raises.

    An unknown algorithm NEVER verifies: INDETERMINATE never authorizes.
    """
    opts = _Options(options)
    checks: Dict[str, Any] = {
        "algorithm_known": False,
        "key_wellformed": None,
        "signature_wellformed": None,
        "signature_valid": None,
    }
    base: Dict[str, Any] = {"alg": None, "key_id": None}

    def refuse(reason: str) -> Dict[str, Any]:
        return {"verified": False, "reason": reason, **base, "checks": checks}

    if not isinstance(message_bytes, (bytes, bytearray, memoryview)):
        return refuse(AGILITY_REASONS["MALFORMED_INPUT"])
    message_bytes = bytes(message_bytes)
    if not _is_plain_object(signature):
        return refuse(AGILITY_REASONS["MALFORMED_INPUT"])
    alg = signature.get("alg")
    if isinstance(alg, str):
        base["alg"] = alg
    if isinstance(signature.get("key_id"), str):
        base["key_id"] = signature["key_id"]

    # 1. Algorithm: closed registry, explicit field. Unknown refuses.
    if not _is_known_algorithm(alg):
        return refuse(AGILITY_REASONS["UNKNOWN_ALGORITHM"])
    checks["algorithm_known"] = True

    # 2. The key must be tagged with the SAME algorithm the signature declares.
    if not _is_plain_object(key) or key.get("alg") != alg:
        checks["key_wellformed"] = False
        return refuse(AGILITY_REASONS["ALGORITHM_KEY_MISMATCH"])

    # 3. Signature bytes: strict base64url, exact expected length.
    sig_bytes = strict_base64url_decode(signature.get("sig"))
    expected_len = ED25519_SIGNATURE_BYTES if alg == "Ed25519" else ML_DSA_65_SIGNATURE_BYTES
    if sig_bytes is None or len(sig_bytes) != expected_len:
        checks["signature_wellformed"] = False
        return refuse(AGILITY_REASONS["MALFORMED_SIGNATURE"])
    checks["signature_wellformed"] = True

    public_key = key.get("public_key")

    if alg == "Ed25519":
        key_object = to_ed25519_public_key_or_none(public_key)
        if key_object is None:
            checks["key_wellformed"] = False
            return refuse(AGILITY_REASONS["MALFORMED_KEY"])
        checks["key_wellformed"] = True
        ok = _ed25519_verify(key_object, message_bytes, sig_bytes)
        checks["signature_valid"] = ok is True
        if not checks["signature_valid"]:
            return refuse(AGILITY_REASONS["SIGNATURE_INVALID"])
        return {"verified": True, "reason": None, **base, "checks": checks}

    # ML-DSA-65
    pk = _to_raw_key_bytes(public_key)
    if pk is None or len(pk) != ML_DSA_65_PUBLIC_KEY_BYTES:
        checks["key_wellformed"] = False
        return refuse(AGILITY_REASONS["MALFORMED_KEY"])
    checks["key_wellformed"] = True
    backend = _resolve_backend(opts)
    if backend is None:
        # No backend is a REFUSAL, never a skipped check and never a pass.
        return refuse(AGILITY_REASONS["PQ_BACKEND_UNAVAILABLE"])
    ok = backend.verify(sig_bytes, message_bytes, pk) is True
    checks["signature_valid"] = ok
    if not ok:
        return refuse(AGILITY_REASONS["SIGNATURE_INVALID"])
    return {"verified": True, "reason": None, **base, "checks": checks}


def verify_agile_signature_set(
    message_bytes: Any,
    signatures: Any,
    keys: Any,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Verify a SET of agile signatures over the same message bytes. Never raises.

    policy 'hybrid_all' (default): verified is True only when every algorithm in
    required_algorithms (default: the FULL registry, which never narrows itself
    to what was presented) is present and every presented signature verifies.

    policy 'per_algorithm': the top-level verdict is ALWAYS None. Per-algorithm
    verdicts live in results and are never collapsed; None never authorizes.
    """
    opts = _Options(options)
    policy = "hybrid_all" if opts.policy is None else opts.policy

    def refuse(reason: str, results: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        return {"policy": policy, "verified": False, "reason": reason, "results": results or []}

    if policy not in ("hybrid_all", "per_algorithm"):
        return {"policy": policy, "verified": False,
                "reason": AGILITY_REASONS["UNKNOWN_POLICY"], "results": []}
    if not isinstance(message_bytes, (bytes, bytearray, memoryview)):
        return refuse(AGILITY_REASONS["MALFORMED_INPUT"])
    if not isinstance(signatures, list):
        return refuse(AGILITY_REASONS["MALFORMED_INPUT"])
    if len(signatures) == 0:
        return refuse(AGILITY_REASONS["EMPTY_SIGNATURE_SET"])
    if not isinstance(keys, list):
        return refuse(AGILITY_REASONS["MALFORMED_INPUT"])

    key_by_alg: Dict[str, Any] = {}
    for k in keys:
        if not _is_plain_object(k) or not isinstance(k.get("alg"), str):
            return refuse(AGILITY_REASONS["MALFORMED_KEY"])
        if k["alg"] in key_by_alg:
            return refuse(AGILITY_REASONS["DUPLICATE_ALGORITHM"])
        key_by_alg[k["alg"]] = k

    presented = set()
    for s in signatures:
        a = s.get("alg") if _is_plain_object(s) else None
        a = a if isinstance(a, str) else ""
        if a in presented:
            return refuse(AGILITY_REASONS["DUPLICATE_ALGORITHM"])
        presented.add(a)

    results: List[Dict[str, Any]] = []
    for s in signatures:
        alg = s.get("alg") if _is_plain_object(s) else None
        key = key_by_alg.get(alg) if isinstance(alg, str) else None
        results.append(verify_agile_signature(message_bytes, s, key, options))

    if policy == "per_algorithm":
        # Never collapse: verdicts stay per-algorithm; None never authorizes.
        return {"policy": policy, "verified": None, "reason": None, "results": results}

    required = opts.required_algorithms
    if not (isinstance(required, (list, tuple)) and len(required) > 0):
        required = AGILE_SIGNATURE_ALGORITHMS
    for alg in required:
        if alg not in presented:
            return refuse(AGILITY_REASONS["MISSING_REQUIRED_ALGORITHM"], results)

    first_failure = next((r for r in results if r.get("verified") is not True), None)
    if first_failure is not None:
        alg_label = first_failure.get("alg") or "unknown"
        return refuse(f"{alg_label}:{first_failure.get('reason')}", results)
    return {"policy": policy, "verified": True, "reason": None, "results": results}


# ---------------------------------------------------------------------------
# EP-HYBRID-v1: the anti-stripping envelope
# ---------------------------------------------------------------------------

def hybrid_signing_input(message_bytes: bytes, signature_algos: Sequence[str]) -> bytes:
    """The domain-separated bytes BOTH legs sign.

        UTF8(HYBRID_DOMAIN) || 0x00 || UTF8(JSON(signature_algos)) || 0x00 || message

    JSON never contains a raw 0x00, so label, algorithm set, and message stay
    unambiguous. The algorithm set being INSIDE these bytes is the anti-stripping
    property: removing or reordering an algorithm changes what was signed, so
    every remaining signature fails.
    """
    if not isinstance(message_bytes, (bytes, bytearray, memoryview)):
        raise TypeError("hybrid_signing_input: message_bytes must be bytes")
    if not (isinstance(signature_algos, (list, tuple)) and len(signature_algos) > 0
            and all(isinstance(a, str) and len(a) > 0 for a in signature_algos)):
        raise TypeError("hybrid_signing_input: signature_algos must be a non-empty string sequence")
    # JSON.stringify(array-of-ascii-strings) == json.dumps with compact separators.
    algos_json = json.dumps(list(signature_algos), separators=(",", ":"), ensure_ascii=False)
    return b"".join([
        HYBRID_DOMAIN.encode("utf-8"), b"\x00",
        algos_json.encode("utf-8"), b"\x00",
        bytes(message_bytes),
    ])


def _to_message_bytes(message: Any) -> Optional[bytes]:
    if isinstance(message, (bytes, bytearray, memoryview)):
        return bytes(message)
    if isinstance(message, str):
        return message.encode("utf-8")
    return None


def _algos_equal(presented: Any, registered: Sequence[str]) -> bool:
    return (isinstance(presented, list)
            and len(presented) == len(registered)
            and all(presented[i] == registered[i] for i in range(len(registered))))


def verify_hybrid(
    message: Any,
    envelope: Any,
    keys: Any,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Verify an EP-HYBRID-v1 envelope. Never raises.

    verified is True only when ALL of these hold:
      - well-formed envelope with alg 'EP-HYBRID-v1'
      - presented signature_algos EXACTLY equals ['Ed25519', 'ML-DSA-65'],
        order-sensitive (which both signatures also commit to, so tampering
        fails twice)
      - exactly one signature per committed algorithm, no extras, none missing
      - the Ed25519 key is curve-pinned and the ML-DSA-65 key length-pinned
      - both signature lengths pinned exactly, BEFORE any verify call
      - the Ed25519 signature valid over the committed signing input
      - the ML-DSA-65 signature valid over the committed signing input, checked
        by a REAL backend; with no backend the result is
        pq_backend_unavailable, never a skip and never a classical-only pass
    """
    opts = _Options(options)
    checks: Dict[str, Any] = {
        "envelope": False,
        "algo_set": False,
        "classical_signature": None,
        "pq_signature": None,
    }

    def refuse(reason: str) -> Dict[str, Any]:
        return {"verified": False, "reason": reason, "checks": checks}

    message_bytes = _to_message_bytes(message)
    if message_bytes is None:
        return refuse(HYBRID_REASONS["INVALID_INPUT"])

    # 1. Envelope shape.
    if not _is_plain_object(envelope):
        return refuse(HYBRID_REASONS["INVALID_ENVELOPE"])
    if envelope.get("alg") != HYBRID_ALG:
        return refuse(HYBRID_REASONS["INVALID_ENVELOPE"])
    sigs = envelope.get("sigs")
    if not _is_plain_object(sigs):
        return refuse(HYBRID_REASONS["INVALID_ENVELOPE"])
    checks["envelope"] = True

    # 2. Algorithm-set commitment: presented set must EXACTLY equal the
    #    registered set.
    signature_algos = envelope.get("signature_algos")
    if not _algos_equal(signature_algos, HYBRID_SIGNATURE_ALGOS):
        return refuse(HYBRID_REASONS["ALGO_SET_MISMATCH"])
    checks["algo_set"] = True

    # 3. Exactly one signature per committed algorithm; extras refuse.
    sig_keys = list(sigs.keys())
    if len(sig_keys) != len(HYBRID_SIGNATURE_ALGOS):
        return refuse(HYBRID_REASONS["MISSING_SIGNATURE"]
                      if len(sig_keys) < len(HYBRID_SIGNATURE_ALGOS)
                      else HYBRID_REASONS["INVALID_ENVELOPE"])
    for algo in HYBRID_SIGNATURE_ALGOS:
        value = sigs.get(algo)
        if not isinstance(value, str) or len(value) == 0:
            return refuse(HYBRID_REASONS["MISSING_SIGNATURE"])

    # 4. Key material. The classical key is CURVE-PINNED and the PQ key
    #    LENGTH-PINNED, so neither leg can be verified under a substituted
    #    algorithm.
    if not _is_plain_object(keys) or not keys.get("ed25519PublicKey") or not keys.get("mldsaPublicKey"):
        return refuse(HYBRID_REASONS["MISSING_KEY"])
    ed_key = to_ed25519_public_key_pinned(keys.get("ed25519PublicKey"))
    if ed_key == ALGORITHM_MISMATCH:
        return refuse(HYBRID_REASONS["ALGORITHM_KEY_MISMATCH"])
    if ed_key is None:
        return refuse(HYBRID_REASONS["MISSING_KEY"])
    pq_key = _to_raw_bytes_lenient(keys.get("mldsaPublicKey"))
    if pq_key is None or len(pq_key) == 0:
        return refuse(HYBRID_REASONS["MISSING_KEY"])
    if len(pq_key) != ML_DSA_65_PUBLIC_KEY_BYTES:
        return refuse(HYBRID_REASONS["PUBLIC_KEY_LENGTH_INVALID"])

    # Decode both signatures and pin their lengths BEFORE any verify call. A
    # relabeled Ed448 signature is 114 bytes, not 64; the length pin is the
    # second half of the anti-masquerade control, the curve pin above the first.
    ed_sig_bytes = node_base64url_decode(sigs["Ed25519"])
    if ed_sig_bytes is None or len(ed_sig_bytes) != ED25519_SIGNATURE_BYTES:
        return refuse(HYBRID_REASONS["SIGNATURE_LENGTH_INVALID"])
    pq_sig_bytes = node_base64url_decode(sigs["ML-DSA-65"])
    if pq_sig_bytes is None or len(pq_sig_bytes) != ML_DSA_65_SIGNATURE_BYTES:
        return refuse(HYBRID_REASONS["SIGNATURE_LENGTH_INVALID"])

    signing_input = hybrid_signing_input(message_bytes, signature_algos)

    # 5. Classical leg over the committed signing input.
    ed_ok = _ed25519_verify(ed_key, signing_input, ed_sig_bytes)
    checks["classical_signature"] = ed_ok is True
    if not checks["classical_signature"]:
        return refuse(HYBRID_REASONS["CLASSICAL_INVALID"])

    # 6. PQ leg. No backend means REFUSE. Never skip, never pass.
    backend = _resolve_backend(opts)
    if backend is None:
        return refuse(HYBRID_REASONS["PQ_BACKEND_UNAVAILABLE"])
    pq_ok = backend.verify(pq_sig_bytes, signing_input, pq_key) is True
    checks["pq_signature"] = pq_ok
    if not pq_ok:
        return refuse(HYBRID_REASONS["PQ_INVALID"])

    return {"verified": True, "reason": None, "checks": checks}


# ---------------------------------------------------------------------------
# EP-RECEIPT-HYBRID-v1: issued hybrid receipts
# ---------------------------------------------------------------------------

def _algorithm_set_matches_registered(algorithms: Any) -> bool:
    return (isinstance(algorithms, list)
            and len(algorithms) == len(HYBRID_RECEIPT_REQUIRED_ALGORITHMS)
            and all(algorithms[i] == HYBRID_RECEIPT_REQUIRED_ALGORITHMS[i]
                    for i in range(len(HYBRID_RECEIPT_REQUIRED_ALGORITHMS))))


def hybrid_signed_material(
    payload: Any,
    required_algorithms: Sequence[str] = HYBRID_RECEIPT_REQUIRED_ALGORITHMS,
) -> Dict[str, Any]:
    """The object every leg signs. The required algorithm set and the profile id
    are INSIDE it: that is the anti-stripping commitment."""
    if not _is_plain_object(payload):
        raise TypeError("hybrid_signed_material: payload must be a plain object")
    if not is_canonicalizable(payload):
        raise ValueError(
            "hybrid_signed_material: payload is outside the EP canonicalization profile; "
            "encode non-integer quantities as strings"
        )
    if not _algorithm_set_matches_registered(list(required_algorithms)):
        raise ValueError(
            f"hybrid_signed_material: refusing: {HYBRID_RECEIPT_REASONS['ALGORITHM_SET_MISMATCH']}"
        )
    return {
        "@version": HYBRID_RECEIPT_PROFILE,
        "payload": payload,
        "required_algorithms": list(required_algorithms),
    }


def hybrid_signed_bytes(
    payload: Any,
    required_algorithms: Sequence[str] = HYBRID_RECEIPT_REQUIRED_ALGORITHMS,
) -> bytes:
    """UTF-8 canonical bytes of hybrid_signed_material(). What every leg signs."""
    return canonicalize(hybrid_signed_material(payload, required_algorithms)).encode("utf-8")


def verify_hybrid_receipt(
    doc: Any,
    keys: Any,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Verify an EP-RECEIPT-HYBRID-v1 receipt. Never raises.

    The signed bytes are rebuilt from the REGISTERED algorithm set, never from
    the set the document claims: the document does not get to choose what it is
    checked against. That is why a narrowed set fails twice, structurally here
    and cryptographically in the set verifier.
    """
    checks: Dict[str, Any] = {
        "profile": False,
        "algorithm_set": None,
        "legs_present": None,
        "signatures_valid": None,
    }

    def refuse(reason: str, failed_algorithm: Any = None, set_result: Any = None) -> Dict[str, Any]:
        return {
            "verified": False,
            "reason": reason,
            "failed_algorithm": failed_algorithm,
            "checks": checks,
            "set_result": set_result,
        }

    # 1. Structure and profile marker.
    if not _is_plain_object(doc):
        return refuse(HYBRID_RECEIPT_REASONS["MALFORMED_RECEIPT"])
    if not is_canonicalizable(doc):
        return refuse(HYBRID_RECEIPT_REASONS["MALFORMED_RECEIPT"])
    if doc.get("@version") != HYBRID_RECEIPT_PROFILE:
        return refuse(HYBRID_RECEIPT_REASONS["UNKNOWN_PROFILE"])
    profile = doc.get("profile")
    if not _is_plain_object(profile):
        return refuse(HYBRID_RECEIPT_REASONS["MALFORMED_RECEIPT"])
    if profile.get("id") != HYBRID_RECEIPT_PROFILE:
        return refuse(HYBRID_RECEIPT_REASONS["UNKNOWN_PROFILE"])
    checks["profile"] = True

    # 2. Committed algorithm set, exact and order-sensitive.
    if not _algorithm_set_matches_registered(profile.get("required_algorithms")):
        checks["algorithm_set"] = False
        return refuse(HYBRID_RECEIPT_REASONS["ALGORITHM_SET_MISMATCH"])
    checks["algorithm_set"] = True

    # 3. Exactly one signature per required algorithm.
    signatures = doc.get("signatures")
    if not isinstance(signatures, list) or len(signatures) == 0:
        checks["legs_present"] = False
        return refuse(HYBRID_RECEIPT_REASONS["HYBRID_LEG_MISSING"])
    presented: List[str] = []
    for s in signatures:
        if not _is_plain_object(s) or not isinstance(s.get("alg"), str) or not isinstance(s.get("sig"), str):
            checks["legs_present"] = False
            return refuse(HYBRID_RECEIPT_REASONS["MALFORMED_RECEIPT"])
        if s["alg"] in presented:
            checks["legs_present"] = False
            return refuse(HYBRID_RECEIPT_REASONS["DUPLICATE_ALGORITHM"], s["alg"])
        presented.append(s["alg"])
    for alg in HYBRID_RECEIPT_REQUIRED_ALGORITHMS:
        if alg not in presented:
            checks["legs_present"] = False
            return refuse(HYBRID_RECEIPT_REASONS["HYBRID_LEG_MISSING"], alg)
    for alg in presented:
        if alg not in HYBRID_RECEIPT_REQUIRED_ALGORITHMS:
            checks["legs_present"] = False
            return refuse(HYBRID_RECEIPT_REASONS["UNEXPECTED_ALGORITHM"], alg)
    checks["legs_present"] = True

    # 4. Rebuild the bytes and delegate the set verdict.
    payload = doc.get("payload")
    if not _is_plain_object(payload) or not is_canonicalizable(payload):
        return refuse(HYBRID_RECEIPT_REASONS["MALFORMED_PAYLOAD"])
    if not _is_plain_object(keys) or not keys.get("ed25519PublicKey") or not keys.get("mldsaPublicKey"):
        return refuse(HYBRID_RECEIPT_REASONS["MISSING_KEY"])

    try:
        # The REGISTERED set, never profile.required_algorithms.
        message_bytes = hybrid_signed_bytes(payload, HYBRID_RECEIPT_REQUIRED_ALGORITHMS)
    except Exception:
        return refuse(HYBRID_RECEIPT_REASONS["MALFORMED_PAYLOAD"])

    verification_keys = [
        {"alg": "Ed25519", "public_key": keys["ed25519PublicKey"],
         **({"key_id": keys["ed25519KeyId"]} if keys.get("ed25519KeyId") else {})},
        {"alg": "ML-DSA-65", "public_key": keys["mldsaPublicKey"],
         **({"key_id": keys["mldsaKeyId"]} if keys.get("mldsaKeyId") else {})},
    ]

    set_options = dict(options or {})
    set_options["policy"] = "hybrid_all"
    set_options["required_algorithms"] = list(HYBRID_RECEIPT_REQUIRED_ALGORITHMS)
    try:
        set_result = verify_agile_signature_set(
            message_bytes, signatures, verification_keys, set_options
        )
    except Exception:
        # The set verifier documents that it never raises; if an injected
        # implementation does, that is still a refusal here, never a pass.
        checks["signatures_valid"] = False
        return refuse(HYBRID_RECEIPT_REASONS["SIGNATURE_INVALID"])

    if set_result.get("verified") is True:
        checks["signatures_valid"] = True
        return {"verified": True, "reason": None, "failed_algorithm": None,
                "checks": checks, "set_result": set_result}

    checks["signatures_valid"] = False
    results = set_result.get("results")
    failed = next((r for r in results if r.get("verified") is not True), None) if isinstance(results, list) else None
    failed_algorithm = failed.get("alg") if isinstance(failed, dict) else None

    raw_reason = str(set_result.get("reason") or "")
    if raw_reason == "missing_required_algorithm":
        return refuse(HYBRID_RECEIPT_REASONS["HYBRID_LEG_MISSING"], failed_algorithm, set_result)
    failed_reason = failed.get("reason") if isinstance(failed, dict) else None
    if raw_reason.endswith("pq_backend_unavailable") or failed_reason == "pq_backend_unavailable":
        return refuse(HYBRID_RECEIPT_REASONS["PQ_BACKEND_UNAVAILABLE"], failed_algorithm, set_result)
    if failed_reason in ("malformed_key", "algorithm_key_mismatch"):
        return refuse(HYBRID_RECEIPT_REASONS["MISSING_KEY"], failed_algorithm, set_result)
    return refuse(HYBRID_RECEIPT_REASONS["SIGNATURE_INVALID"], failed_algorithm, set_result)


__all__ = [
    "AGILE_SIGNATURE_ALGORITHMS",
    "AGILITY_REASONS",
    "ALGORITHM_MISMATCH",
    "ED25519_SIGNATURE_BYTES",
    "HYBRID_ALG",
    "HYBRID_DOMAIN",
    "HYBRID_REASONS",
    "HYBRID_RECEIPT_PROFILE",
    "HYBRID_RECEIPT_REASONS",
    "HYBRID_RECEIPT_REQUIRED_ALGORITHMS",
    "HYBRID_SIGNATURE_ALGOS",
    "ML_DSA_65_PUBLIC_KEY_BYTES",
    "ML_DSA_65_SECRET_KEY_BYTES",
    "ML_DSA_65_SIGNATURE_BYTES",
    "MldsaBackend",
    "SIGNATURE_AGILITY_VERSION",
    "hybrid_signed_bytes",
    "hybrid_signed_material",
    "hybrid_signing_input",
    "load_default_mldsa_backend",
    "node_base64url_decode",
    "strict_base64url_decode",
    "verify_agile_signature",
    "verify_agile_signature_set",
    "verify_hybrid",
    "verify_hybrid_receipt",
]
