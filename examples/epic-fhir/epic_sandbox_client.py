#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Secret-free Epic on FHIR R4 reference client for EMILIA receipts.

The client uses Epic's backend OAuth flow (client_credentials plus a
private_key_jwt assertion). Credentials are read from arguments or environment
variables and are never printed. The write command requires an explicit
``--confirm-write`` flag because it creates a DocumentReference in the selected
FHIR environment.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_TOKEN_URL = "https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token"
DEFAULT_FHIR_BASE = "https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4"
FHIR_ID = re.compile(r"^[A-Za-z0-9\-.]{1,64}$")


@dataclass(frozen=True)
class ClientConfig:
    client_id: str
    kid: str
    key_path: Path
    token_url: str = DEFAULT_TOKEN_URL
    fhir_base: str = DEFAULT_FHIR_BASE


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def validate_fhir_id(value: str, field: str) -> str:
    if not FHIR_ID.fullmatch(value):
        raise ValueError(f"{field} is not a valid FHIR id")
    return value


def token_summary(token_response: dict[str, Any]) -> dict[str, Any]:
    """Return only non-secret token metadata safe for console output."""
    return {
        "scope": token_response.get("scope", ""),
        "expires_in": token_response.get("expires_in"),
        "token_type": token_response.get("token_type", ""),
    }


def make_client_assertion(config: ClientConfig) -> str:
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError as exc:  # pragma: no cover - deployment dependency error
        raise RuntimeError("install the cryptography package") from exc

    key_bytes = config.key_path.read_bytes()
    key = serialization.load_pem_private_key(key_bytes, password=None)
    now = int(time.time())
    header = {"alg": "RS384", "typ": "JWT", "kid": config.kid}
    payload = {
        "iss": config.client_id,
        "sub": config.client_id,
        "aud": config.token_url,
        "jti": str(uuid.uuid4()),
        "nbf": now,
        "iat": now,
        "exp": now + 240,
    }
    signing_input = (
        b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64url(json.dumps(payload, separators=(",", ":")).encode())
    )
    signature = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA384())
    return signing_input + "." + b64url(signature)


def _read_json(request: urllib.request.Request) -> dict[str, Any]:
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
            result = json.loads(body) if body else {}
            result["_http_status"] = response.status
            location = response.headers.get("Location")
            if location:
                result["_location"] = location
            return result
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:800]
        raise RuntimeError(f"Epic FHIR request failed with HTTP {exc.code}: {detail}") from exc


def get_token(config: ClientConfig) -> dict[str, Any]:
    body = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": make_client_assertion(config),
        }
    ).encode()
    request = urllib.request.Request(
        config.token_url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    token = _read_json(request)
    if not token.get("access_token"):
        raise RuntimeError("Epic token response did not contain an access token")
    return token


def fhir_get(config: ClientConfig, token: str, path: str) -> dict[str, Any]:
    request = urllib.request.Request(
        f"{config.fhir_base.rstrip('/')}/{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/fhir+json",
        },
    )
    return _read_json(request)


def fhir_post(
    config: ClientConfig, token: str, path: str, resource: dict[str, Any]
) -> dict[str, Any]:
    request = urllib.request.Request(
        f"{config.fhir_base.rstrip('/')}/{path}",
        data=json.dumps(resource, separators=(",", ":")).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/fhir+json",
            "Accept": "application/fhir+json",
        },
    )
    return _read_json(request)


def build_document_reference(
    *, receipt_bytes: bytes, patient_id: str, encounter_id: str
) -> dict[str, Any]:
    """Build the Clinical Notes DocumentReference exercised in Epic's sandbox.

    The patient and encounter live in FHIR references. They are not copied into
    the receipt note. This function does not determine whether caller-supplied
    receipt bytes contain PHI; deployments must enforce that separately.
    """
    patient_id = validate_fhir_id(patient_id, "patient_id")
    encounter_id = validate_fhir_id(encounter_id, "encounter_id")
    note = (
        b"EMILIA PROTOCOL AUTHORIZATION EVIDENCE\n"
        b"Exact-action receipt; verify with relying-party-pinned keys.\n\n"
        + receipt_bytes
    )
    return {
        "resourceType": "DocumentReference",
        "status": "current",
        "docStatus": "final",
        "type": {
            "coding": [
                {
                    "system": "http://loinc.org",
                    "code": "11488-4",
                    "display": "Consult note",
                }
            ],
            "text": "EMILIA authorization evidence",
        },
        "category": [
            {
                "coding": [
                    {
                        "system": "http://hl7.org/fhir/us/core/CodeSystem/us-core-documentreference-category",
                        "code": "clinical-note",
                        "display": "Clinical Note",
                    }
                ]
            }
        ],
        "subject": {"reference": f"Patient/{patient_id}"},
        "context": {"encounter": [{"reference": f"Encounter/{encounter_id}"}]},
        "content": [
            {
                "attachment": {
                    "contentType": "text/plain",
                    "data": base64.b64encode(note).decode(),
                }
            }
        ],
    }


def document_id_from_response(response: dict[str, Any]) -> str | None:
    direct = response.get("id")
    if isinstance(direct, str) and FHIR_ID.fullmatch(direct):
        return direct
    location = response.get("_location", "")
    match = re.search(r"/DocumentReference/([A-Za-z0-9\-.]{1,64})(?:/|$)", location)
    return match.group(1) if match else None


def require_write_confirmation(args: argparse.Namespace) -> None:
    if not args.confirm_write:
        raise ValueError("file-receipt requires --confirm-write")


def config_from_args(args: argparse.Namespace) -> ClientConfig:
    client_id = args.client_id or os.environ.get("EPIC_FHIR_CLIENT_ID", "")
    kid = args.kid or os.environ.get("EPIC_FHIR_KID", "")
    key_path = args.key_path or os.environ.get("EPIC_FHIR_KEY_PATH", "")
    missing = [name for name, value in (("client id", client_id), ("kid", kid), ("key path", key_path)) if not value]
    if missing:
        raise ValueError("missing " + ", ".join(missing))
    path = Path(key_path).expanduser()
    if not path.is_file():
        raise ValueError("key path is not a file")
    return ClientConfig(
        client_id=client_id,
        kid=kid,
        key_path=path,
        token_url=args.token_url,
        fhir_base=args.fhir_base,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client-id")
    parser.add_argument("--kid")
    parser.add_argument("--key-path")
    parser.add_argument("--token-url", default=DEFAULT_TOKEN_URL)
    parser.add_argument("--fhir-base", default=DEFAULT_FHIR_BASE)
    commands = parser.add_subparsers(dest="command", required=True)

    check = commands.add_parser("check-patient", help="read one sandbox Patient")
    check.add_argument("--patient-id", required=True)

    read = commands.add_parser("read-document", help="read one DocumentReference")
    read.add_argument("--document-id", required=True)

    file = commands.add_parser("file-receipt", help="create and read back a DocumentReference")
    file.add_argument("--patient-id", required=True)
    file.add_argument("--encounter-id", required=True)
    file.add_argument("--receipt-file", required=True)
    file.add_argument("--confirm-write", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "file-receipt":
            require_write_confirmation(args)
        config = config_from_args(args)
        token_response = get_token(config)
        token = token_response["access_token"]
        print(json.dumps({"token": token_summary(token_response)}, sort_keys=True))

        if args.command == "check-patient":
            patient_id = validate_fhir_id(args.patient_id, "patient_id")
            patient = fhir_get(config, token, f"Patient/{patient_id}")
            print(json.dumps({"resourceType": patient.get("resourceType"), "id": patient.get("id")}, sort_keys=True))
            return 0

        if args.command == "read-document":
            document_id = validate_fhir_id(args.document_id, "document_id")
            document = fhir_get(config, token, f"DocumentReference/{document_id}")
            print(json.dumps({"resourceType": document.get("resourceType"), "id": document.get("id"), "status": document.get("status"), "docStatus": document.get("docStatus")}, sort_keys=True))
            return 0

        receipt_bytes = Path(args.receipt_file).read_bytes()
        document = build_document_reference(
            receipt_bytes=receipt_bytes,
            patient_id=args.patient_id,
            encounter_id=args.encounter_id,
        )
        created = fhir_post(config, token, "DocumentReference", document)
        document_id = document_id_from_response(created)
        print(json.dumps({"created": {"http_status": created.get("_http_status"), "resourceType": created.get("resourceType"), "id": document_id, "status": created.get("status"), "docStatus": created.get("docStatus")}}, sort_keys=True))
        if document_id:
            readback = fhir_get(config, token, f"DocumentReference/{validate_fhir_id(document_id, 'document_id')}")
            print(json.dumps({"readback": {"resourceType": readback.get("resourceType"), "id": readback.get("id"), "status": readback.get("status"), "docStatus": readback.get("docStatus")}}, sort_keys=True))
        return 0
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
