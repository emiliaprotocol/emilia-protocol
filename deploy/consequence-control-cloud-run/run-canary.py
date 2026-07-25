#!/usr/bin/env python3
"""Execute and sign the split consequence-control live canary."""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import datetime as dt
import errno
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterator


VERSION = "EP-CONSEQUENCE-CANARY-EVIDENCE-v1"
NORMAL_PROFILE = "github.issue.update.v1"
PROVIDER_RESPONSE_LOSS_PROFILE = "github.issue.update.indeterminate-smoke.v1"
ACTUATOR_RESPONSE_LOSS_PROFILE = (
    "github.issue.update.actuator-response-loss-smoke.v1"
)
OBSERVATION_SENTINEL = {"kind": "consequence-actuator-observation-v1"}
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_HTTP_BYTES = 2 * 1024 * 1024
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE = re.compile(
    r"^[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$"
)
IDENTIFIER = re.compile(r"^[A-Za-z0-9:_.@-]{3,256}$")
JWT = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


class CanaryError(ValueError):
    """A fail-closed canary refusal."""


def reject_duplicate_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CanaryError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def object_value(value: object, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CanaryError(f"{name} must be an object")
    return value


def exact_keys(value: object, expected: set[str], name: str) -> dict[str, Any]:
    result = object_value(value, name)
    actual = set(result)
    if actual != expected:
        raise CanaryError(
            f"{name} fields must be exactly {sorted(expected)!r}; "
            f"received {sorted(actual)!r}"
        )
    return result


def require_equal(value: object, expected: object, name: str) -> None:
    if value != expected:
        raise CanaryError(f"{name} must equal {expected!r}")


def require_identifier(value: object, name: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise CanaryError(f"{name} is invalid")
    return value


def require_digest(value: object, name: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise CanaryError(f"{name} must be a lowercase sha256 digest")
    return value


def read_bounded(path: Path, name: str, maximum: int = MAX_FILE_BYTES) -> bytes:
    try:
        size = path.stat().st_size
        if size > maximum:
            raise CanaryError(f"{name} is too large")
        return path.read_bytes()
    except OSError as error:
        raise CanaryError(f"{name} is unavailable") from error


def load_json_file(path: Path, name: str) -> object:
    raw = read_bounded(path, name)
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate_members,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CanaryError(f"{name} must be strict UTF-8 JSON") from error


def parse_config(raw: bytes) -> dict[str, str]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise CanaryError("config must be UTF-8") from error
    result: dict[str, str] = {}
    for number, raw in enumerate(lines, 1):
        if not raw or raw.startswith("#"):
            continue
        if "=" not in raw:
            raise CanaryError(f"invalid config line {number}")
        key, value = raw.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise CanaryError(f"invalid config key on line {number}")
        if key in result:
            raise CanaryError(f"duplicate config key on line {number}")
        if "\x00" in value or "\r" in value:
            raise CanaryError(f"invalid config value on line {number}")
        result[key] = value
    required = {
        "PROJECT_ID",
        "REGION",
        "RELEASE_ID",
        "ACTUATOR_SERVICE",
        "DECISION_SERVICE",
        "ACTUATOR_IMAGE",
        "DECISION_IMAGE",
        "GITHUB_OWNER",
        "GITHUB_REPO",
        "GITHUB_ISSUE_NUMBER",
        "CANARY_EVIDENCE_KEY_ID",
        "CANARY_EVIDENCE_PUBLIC_KEY_FILE",
        "CANARY_MAX_AGE_SEC",
    }
    missing = sorted(required - set(result))
    if missing:
        raise CanaryError(f"config is missing {missing!r}")
    for key in ("ACTUATOR_IMAGE", "DECISION_IMAGE"):
        if not IMAGE.fullmatch(result[key]):
            raise CanaryError(f"{key} is not digest pinned")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,20}", result["RELEASE_ID"]):
        raise CanaryError("RELEASE_ID is invalid")
    try:
        max_age = int(result["CANARY_MAX_AGE_SEC"])
    except ValueError as error:
        raise CanaryError("CANARY_MAX_AGE_SEC must be positive") from error
    if max_age <= 0:
        raise CanaryError("CANARY_MAX_AGE_SEC must be positive")
    return result


def read_pinned_config(path: Path) -> tuple[bytes, str]:
    expected = os.environ.get("DEPLOYMENT_CONFIG_SHA256", "")
    if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise CanaryError(
            "DEPLOYMENT_CONFIG_SHA256 must be injected by a protected source"
        )
    if not path.is_absolute():
        raise CanaryError("config path must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.EMLINK}:
            raise CanaryError(
                "config path must name a regular non-symlink file"
            ) from error
        raise CanaryError("config is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise CanaryError(
                "config path must name a single-link regular non-symlink file"
            )
        if metadata.st_uid not in {0, os.geteuid()}:
            raise CanaryError("config ownership is unsafe")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise CanaryError("config mode permits group or world writes")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_FILE_BYTES:
                raise CanaryError("config is too large")
            chunks.append(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    if not raw:
        raise CanaryError("config is empty")
    actual = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise CanaryError("deployment config differs from protected SHA-256")
    return raw, actual


def write_retained_config(directory: Path, raw: bytes) -> Path:
    snapshot = directory / "config.env"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
    )
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(snapshot, flags, 0o400)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return snapshot


@contextmanager
def retained_config(path: Path) -> Iterator[tuple[dict[str, str], Path]]:
    raw, _actual = read_pinned_config(path)
    config = parse_config(raw)
    with tempfile.TemporaryDirectory(prefix="emilia-canary-config-") as name:
        directory = Path(name)
        directory.chmod(0o700)
        snapshot = write_retained_config(directory, raw)
        yield config, snapshot


def secure_file(path: Path, name: str) -> Path:
    if not path.is_absolute():
        raise CanaryError(f"{name} must use an absolute path")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise CanaryError(f"{name} is unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise CanaryError(f"{name} must be a regular, non-symlink file")
    if metadata.st_uid != os.geteuid():
        raise CanaryError(f"{name} must be owned by the current user")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise CanaryError(f"{name} permissions must not grant group or other access")
    return path


def application_token(path: Path) -> str:
    checked = secure_file(path, "application token file")
    try:
        value = read_bounded(checked, "application token file", 16 * 1024).decode(
            "utf-8"
        )
    except UnicodeDecodeError as error:
        raise CanaryError("application token must be UTF-8") from error
    value = value.rstrip("\r\n")
    if (
        len(value) < 8
        or len(value) > 4096
        or any(character in value for character in "\r\n\x00")
    ):
        raise CanaryError("application token is invalid")
    return value


def private_key_file(path: Path, config: dict[str, str]) -> Path:
    checked = secure_file(path, "canary private key file")
    public_key = Path(config["CANARY_EVIDENCE_PUBLIC_KEY_FILE"])
    try:
        if checked.resolve(strict=True) == public_key.resolve(strict=True):
            raise CanaryError("canary private and public keys must be separate files")
    except OSError as error:
        raise CanaryError("pinned canary public key file is unavailable") from error
    lane = Path(__file__).resolve().parent
    try:
        checked.resolve(strict=True).relative_to(lane)
    except ValueError:
        pass
    else:
        raise CanaryError("canary private key file must remain outside the deployment lane")
    return checked


def validate_signing_key_pair(
    private_key: Path,
    public_key: Path,
) -> None:
    if not public_key.is_absolute() or not public_key.is_file():
        raise CanaryError("pinned canary public key file is unavailable")
    private_public = command(
        [
            "openssl",
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
        ],
        "canary private key validation",
        maximum=32 * 1024,
    ).stdout
    pinned_public = command(
        [
            "openssl",
            "pkey",
            "-pubin",
            "-in",
            str(public_key),
            "-pubout",
        ],
        "pinned canary public key validation",
        maximum=32 * 1024,
    ).stdout
    if (
        "-----BEGIN PUBLIC KEY-----" not in private_public
        or private_public != pinned_public
    ):
        raise CanaryError(
            "canary private key does not match the pinned public key"
        )


def validate_request(
    value: object,
    name: str,
    expected_profile: str,
    config: dict[str, str],
) -> dict[str, Any]:
    scenario = exact_keys(value, {"proposal_id", "request"}, name)
    proposal_id = require_identifier(scenario["proposal_id"], f"{name}.proposal_id")
    request = exact_keys(
        scenario["request"],
        {"proposal", "receipt", "evaluation", "evidence"},
        f"{name}.request",
    )
    proposal = object_value(request["proposal"], f"{name}.request.proposal")
    require_equal(
        proposal.get("proposal_id"),
        proposal_id,
        f"{name}.request.proposal.proposal_id",
    )
    require_equal(
        proposal.get("profile_id"),
        expected_profile,
        f"{name}.request.proposal.profile_id",
    )
    require_digest(
        proposal.get("aeb_action_digest"),
        f"{name}.request.proposal.aeb_action_digest",
    )
    action = exact_keys(
        proposal.get("action"),
        {"action_type", "owner", "repo", "issue_number", "title", "body"},
        f"{name}.request.proposal.action",
    )
    require_equal(
        action.get("action_type"),
        "github.issue.update.1",
        f"{name}.request.proposal.action.action_type",
    )
    require_equal(
        action.get("owner"),
        config["GITHUB_OWNER"],
        f"{name}.request.proposal.action.owner (must match GITHUB_OWNER)",
    )
    require_equal(
        action.get("repo"),
        config["GITHUB_REPO"],
        f"{name}.request.proposal.action.repo (must match GITHUB_REPO)",
    )
    try:
        issue_number = int(config["GITHUB_ISSUE_NUMBER"])
    except ValueError as error:
        raise CanaryError("GITHUB_ISSUE_NUMBER must be a positive integer") from error
    if issue_number <= 0:
        raise CanaryError("GITHUB_ISSUE_NUMBER must be a positive integer")
    require_equal(
        action.get("issue_number"),
        issue_number,
        f"{name}.request.proposal.action.issue_number "
        "(must match GITHUB_ISSUE_NUMBER)",
    )
    for field in ("title", "body"):
        if not isinstance(action.get(field), str) or not action[field]:
            raise CanaryError(
                f"{name}.request.proposal.action.{field} is invalid"
            )
    consequence = object_value(
        proposal.get("consequence"),
        f"{name}.request.proposal.consequence",
    )
    for field in (
        "tenant_id",
        "provider_id",
        "provider_account_id",
        "environment",
    ):
        require_identifier(
            consequence.get(field),
            f"{name}.request.proposal.consequence.{field}",
        )
    require_digest(
        consequence.get("request_digest"),
        f"{name}.request.proposal.consequence.request_digest",
    )
    object_value(request["receipt"], f"{name}.request.receipt")
    object_value(request["evaluation"], f"{name}.request.evaluation")
    evidence = exact_keys(
        request["evidence"],
        {"artifacts", "statuses"},
        f"{name}.request.evidence",
    )
    object_value(evidence["artifacts"], f"{name}.request.evidence.artifacts")
    object_value(evidence["statuses"], f"{name}.request.evidence.statuses")
    return scenario


def load_scenario(
    path: Path,
    config: dict[str, str],
) -> dict[str, dict[str, Any]]:
    root = exact_keys(
        load_json_file(path, "scenario"),
        {
            "exact_execution",
            "provider_response_loss",
            "actuator_response_loss",
        },
        "scenario",
    )
    return {
        "exact_execution": validate_request(
            root["exact_execution"],
            "scenario.exact_execution",
            NORMAL_PROFILE,
            config,
        ),
        "provider_response_loss": validate_request(
            root["provider_response_loss"],
            "scenario.provider_response_loss",
            PROVIDER_RESPONSE_LOSS_PROFILE,
            config,
        ),
        "actuator_response_loss": validate_request(
            root["actuator_response_loss"],
            "scenario.actuator_response_loss",
            ACTUATOR_RESPONSE_LOSS_PROFILE,
            config,
        ),
    }


def command(
    arguments: list[str],
    name: str,
    *,
    maximum: int = MAX_FILE_BYTES,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CanaryError(f"{name} is unavailable") from error
    if result.returncode != 0:
        raise CanaryError(f"{name} failed")
    if len(result.stdout.encode("utf-8")) > maximum:
        raise CanaryError(f"{name} output is too large")
    return result


def gcloud_json(arguments: list[str], name: str) -> dict[str, Any]:
    result = command(["gcloud", *arguments], name)
    try:
        value = json.loads(
            result.stdout,
            object_pairs_hook=reject_duplicate_members,
        )
    except json.JSONDecodeError as error:
        raise CanaryError(f"{name} did not return JSON") from error
    return object_value(value, name)


def describe_revision(
    config: dict[str, str],
    revision: str,
    service: str,
    image: str,
) -> None:
    value = gcloud_json(
        [
            "run",
            "revisions",
            "describe",
            revision,
            f"--project={config['PROJECT_ID']}",
            f"--region={config['REGION']}",
            "--format=json",
        ],
        f"live revision lookup for {revision}",
    )
    metadata = object_value(value.get("metadata"), f"{revision}.metadata")
    spec = object_value(value.get("spec"), f"{revision}.spec")
    require_equal(metadata.get("name"), revision, f"{revision}.metadata.name")
    labels = object_value(metadata.get("labels"), f"{revision}.metadata.labels")
    require_equal(
        labels.get("serving.knative.dev/service"),
        service,
        f"{revision}.service",
    )
    containers = spec.get("containers")
    if not isinstance(containers, list) or len(containers) != 1:
        raise CanaryError(f"{revision} must have exactly one container")
    container = object_value(containers[0], f"{revision}.container")
    require_equal(container.get("image"), image, f"{revision}.image")


def parsed_origin(value: object, name: str, allow_insecure_loopback: bool) -> str:
    if not isinstance(value, str):
        raise CanaryError(f"{name} is invalid")
    parsed = urllib.parse.urlsplit(value)
    loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or (parsed.scheme != "https" and not (
            allow_insecure_loopback and parsed.scheme == "http" and loopback
        ))
    ):
        raise CanaryError(f"{name} is not a safe service origin")
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, "", "", "")
    )


def resolve_decision_service(
    config: dict[str, str],
    allow_insecure_loopback: bool,
) -> tuple[str, str]:
    service = config["DECISION_SERVICE"]
    revision = f"{service}-{config['RELEASE_ID']}"
    tag = f"canary-{config['RELEASE_ID']}"
    value = gcloud_json(
        [
            "run",
            "services",
            "describe",
            service,
            f"--project={config['PROJECT_ID']}",
            f"--region={config['REGION']}",
            "--format=json",
        ],
        "decision service lookup",
    )
    metadata = object_value(value.get("metadata"), "decision service metadata")
    require_equal(metadata.get("name"), service, "decision service name")
    status = object_value(value.get("status"), "decision service status")
    audience = parsed_origin(status.get("url"), "decision service audience", False)
    traffic = status.get("traffic")
    if not isinstance(traffic, list):
        raise CanaryError("decision service traffic is unavailable")
    candidates = [
        entry
        for entry in traffic
        if isinstance(entry, dict)
        and entry.get("tag") == tag
        and entry.get("revisionName") == revision
    ]
    if len(candidates) != 1:
        raise CanaryError("exact decision canary tag/revision binding is unavailable")
    endpoint = parsed_origin(
        candidates[0].get("url"),
        "decision canary URL",
        allow_insecure_loopback,
    )
    return endpoint, audience


def preflight(config: dict[str, str], allow_insecure_loopback: bool) -> tuple[str, str]:
    actuator_revision = (
        f"{config['ACTUATOR_SERVICE']}-{config['RELEASE_ID']}"
    )
    decision_revision = (
        f"{config['DECISION_SERVICE']}-{config['RELEASE_ID']}"
    )
    describe_revision(
        config,
        actuator_revision,
        config["ACTUATOR_SERVICE"],
        config["ACTUATOR_IMAGE"],
    )
    describe_revision(
        config,
        decision_revision,
        config["DECISION_SERVICE"],
        config["DECISION_IMAGE"],
    )
    return resolve_decision_service(config, allow_insecure_loopback)


def google_identity_token(audience: str, service_account: str | None) -> str:
    arguments = [
        "gcloud",
        "auth",
        "print-identity-token",
        f"--audiences={audience}",
    ]
    if service_account:
        if not re.fullmatch(
            r"[a-z][a-z0-9-]{0,61}[a-z0-9]@"
            r"[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com",
            service_account,
        ):
            raise CanaryError("identity service account is invalid")
        arguments.append(f"--impersonate-service-account={service_account}")
    token = command(arguments, "Google identity token acquisition", maximum=32 * 1024)
    value = token.stdout.strip()
    if len(value) > 16 * 1024 or not JWT.fullmatch(value):
        raise CanaryError("Google identity token response is invalid")
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


class JsonClient:
    def __init__(
        self,
        origin: str,
        token: str,
        identity_token: str | None,
        timeout_seconds: int,
    ) -> None:
        self.origin = origin
        self.token = token
        self.identity_token = identity_token
        self.timeout_seconds = timeout_seconds
        self.opener = urllib.request.build_opener(NoRedirect)

    def post(self, path: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        payload = json.dumps(
            body,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
        if self.identity_token:
            headers["X-Serverless-Authorization"] = (
                f"Bearer {self.identity_token}"
            )
        request = urllib.request.Request(
            f"{self.origin}{path}",
            data=payload,
            headers=headers,
            method="POST",
        )
        try:
            response = self.opener.open(request, timeout=self.timeout_seconds)
        except urllib.error.HTTPError as error:
            response = error
        except (OSError, urllib.error.URLError) as error:
            raise CanaryError(f"HTTP request failed for {path}") from error
        try:
            status = response.status
            content_type = response.headers.get("content-type", "")
            announced = response.headers.get("content-length")
            if announced and int(announced) > MAX_HTTP_BYTES:
                raise CanaryError(f"HTTP response is too large for {path}")
            raw = response.read(MAX_HTTP_BYTES + 1)
        finally:
            response.close()
        if len(raw) > MAX_HTTP_BYTES:
            raise CanaryError(f"HTTP response is too large for {path}")
        if "application/json" not in content_type.lower():
            raise CanaryError(f"HTTP response is not JSON for {path}")
        try:
            value = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=reject_duplicate_members,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CanaryError(f"HTTP response is invalid JSON for {path}") from error
        return status, object_value(value, f"HTTP response for {path}")


def proposal_path(proposal_id: str, suffix: str) -> str:
    segment = urllib.parse.quote(proposal_id, safe=":_.@-")
    return f"/v1/proposals/{segment}/{suffix}"


def attempt_binding(
    value: object,
    name: str,
    *,
    full: bool,
) -> dict[str, Any]:
    attempt = object_value(value, name)
    fields = ["tenant_id", "attempt_id"]
    if full:
        fields = [
            "tenant_id",
            "provider_id",
            "provider_account_id",
            "environment",
            "attempt_id",
            "request_digest",
        ]
    for field in fields:
        if field == "request_digest":
            require_digest(attempt.get(field), f"{name}.{field}")
        else:
            require_identifier(attempt.get(field), f"{name}.{field}")
    return attempt


def assert_attempt_equal(
    left: dict[str, Any],
    right: dict[str, Any],
    name: str,
) -> None:
    for field in (
        "tenant_id",
        "provider_id",
        "provider_account_id",
        "environment",
        "attempt_id",
        "request_digest",
    ):
        require_equal(left.get(field), right.get(field), f"{name}.{field}")


def validate_exact_execution(
    status: int,
    body: dict[str, Any],
    request: dict[str, Any],
    config: dict[str, str],
) -> dict[str, Any]:
    require_equal(status, 200, "exact execution HTTP status")
    require_equal(body.get("status"), "completed", "exact execution status")
    result = object_value(body.get("result"), "exact execution result")
    require_equal(result.get("ok"), True, "exact execution result.ok")
    response_proposal = object_value(
        result.get("proposal"),
        "exact execution result.proposal",
    )
    require_equal(
        response_proposal,
        request["proposal"],
        "exact execution response proposal",
    )
    consequence = object_value(
        result.get("consequence"),
        "exact execution result.consequence",
    )
    require_equal(
        consequence.get("state"),
        "COMMITTED",
        "exact execution consequence.state",
    )
    attempt = attempt_binding(
        consequence.get("attempt"),
        "exact execution attempt",
        full=True,
    )
    effect = object_value(result.get("effect"), "exact execution result.effect")
    require_equal(
        effect.get("provider_status"),
        200,
        "exact execution provider_status",
    )
    reference = effect.get("provider_reference")
    expected_reference = (
        f"github:issue:{config['GITHUB_OWNER']}/"
        f"{config['GITHUB_REPO']}#{config['GITHUB_ISSUE_NUMBER']}"
    )
    require_equal(
        reference,
        expected_reference,
        "exact execution provider_reference",
    )
    observation = object_value(
        effect.get("actuator_observation"),
        "exact execution actuator observation",
    )
    payload = object_value(
        observation.get("payload"),
        "exact execution actuator observation payload",
    )
    action_digest = require_digest(
        payload.get("action_digest"),
        "exact execution observation action_digest",
    )
    require_equal(
        action_digest,
        response_proposal.get("aeb_action_digest"),
        "exact execution action_digest binding",
    )
    require_equal(
        payload.get("outcome"),
        "COMMITTED",
        "exact execution observation outcome",
    )
    require_equal(
        payload.get("attempt_id"),
        attempt["attempt_id"],
        "exact execution observation attempt_id",
    )
    require_equal(
        payload.get("provider_reference"),
        reference,
        "exact execution observation provider_reference",
    )
    return {
        "http_status": status,
        "outcome": payload["outcome"],
        "action_digest": action_digest,
        "attempt_id": attempt["attempt_id"],
        "provider_reference": reference,
    }


def validate_indeterminate_execution(
    status: int,
    body: dict[str, Any],
    request: dict[str, Any],
    name: str,
) -> dict[str, Any]:
    require_equal(status, 202, f"{name} HTTP status")
    require_equal(body.get("status"), "indeterminate", f"{name} status")
    require_equal(body.get("retry_allowed"), False, f"{name} retry_allowed")
    error = object_value(body.get("error"), f"{name} error")
    require_equal(
        error.get("code"),
        "provider_outcome_indeterminate",
        f"{name} error.code",
    )
    attempt = attempt_binding(body.get("attempt"), f"{name} attempt", full=False)
    proposal = object_value(request["proposal"], f"{name} proposal")
    consequence = object_value(
        proposal.get("consequence"),
        f"{name} proposal consequence",
    )
    require_equal(
        attempt.get("tenant_id"),
        consequence.get("tenant_id"),
        f"{name} attempt tenant binding",
    )
    return attempt


def lookup_attempt(
    client: JsonClient,
    scenario: dict[str, Any],
    expected_state: str,
    name: str,
) -> dict[str, Any]:
    proposal_id = scenario["proposal_id"]
    request = scenario["request"]
    status, body = client.post(
        proposal_path(proposal_id, "attempts/lookup"),
        {"proposal": request["proposal"]},
    )
    require_equal(status, 200, f"{name} attempt lookup HTTP status")
    require_equal(body.get("status"), "found", f"{name} attempt lookup status")
    require_equal(body.get("state"), expected_state, f"{name} attempt lookup state")
    attempt = attempt_binding(
        body.get("attempt"),
        f"{name} attempt lookup binding",
        full=True,
    )
    proposal_consequence = object_value(
        request["proposal"].get("consequence"),
        f"{name} proposal consequence",
    )
    for field in (
        "tenant_id",
        "provider_id",
        "provider_account_id",
        "environment",
        "request_digest",
    ):
        require_equal(
            attempt.get(field),
            proposal_consequence.get(field),
            f"{name} attempt lookup proposal binding.{field}",
        )
    return attempt


def validate_replay(
    status: int,
    body: dict[str, Any],
    expected_attempt: dict[str, Any],
    name: str,
) -> dict[str, Any]:
    require_equal(status, 409, f"{name} replay HTTP status")
    require_equal(body.get("status"), "refused", f"{name} replay status")
    result = object_value(body.get("result"), f"{name} replay result")
    require_equal(result.get("ok"), False, f"{name} replay result.ok")
    require_equal(
        result.get("reason"),
        "envelope_replayed",
        f"{name} replay reason (must be envelope_replayed)",
    )
    require_equal(result.get("invoked"), False, f"{name} replay invoked")
    consequence = object_value(
        result.get("consequence"),
        f"{name} replay consequence",
    )
    require_equal(
        consequence.get("state"),
        "INDETERMINATE",
        f"{name} replay consequence.state",
    )
    attempt = attempt_binding(
        consequence.get("attempt"),
        f"{name} replay attempt",
        full=True,
    )
    assert_attempt_equal(
        attempt,
        expected_attempt,
        f"{name} replay attempt binding",
    )
    return {
        "http_status": status,
        "reason": result["reason"],
        # One 202 effect-boundary entry plus this authenticated invoked=false
        # refusal proves exactly one provider invocation in this workflow.
        "provider_invocations": 1,
    }


def validate_unavailable_reconciliation(
    status: int,
    body: dict[str, Any],
) -> dict[str, Any]:
    require_equal(status, 503, "provider-response-loss reconciliation HTTP status")
    require_equal(
        body.get("status"),
        "refused",
        "provider-response-loss reconciliation status",
    )
    result = object_value(
        body.get("result"),
        "provider-response-loss reconciliation result",
    )
    require_equal(
        result.get("ok"),
        False,
        "provider-response-loss reconciliation result.ok",
    )
    require_equal(
        result.get("reason"),
        "provider_evidence_unavailable",
        "provider-response-loss reconciliation reason",
    )
    return {
        "http_status": status,
        "valid": False,
        "outcome": "INDETERMINATE",
        "reason": result["reason"],
        "terminalized": False,
        "reexecuted": False,
    }


def validate_committed_reconciliation(
    status: int,
    body: dict[str, Any],
    expected_attempt: dict[str, Any],
) -> dict[str, Any]:
    require_equal(status, 200, "actuator-response-loss reconciliation HTTP status")
    require_equal(
        body.get("status"),
        "reconciled",
        "actuator-response-loss reconciliation status",
    )
    result = object_value(
        body.get("result"),
        "actuator-response-loss reconciliation result",
    )
    require_equal(
        result.get("ok"),
        True,
        "actuator-response-loss reconciliation result.ok",
    )
    require_equal(
        result.get("state"),
        "COMMITTED",
        "actuator-response-loss reconciliation state",
    )
    require_equal(
        result.get("outcome"),
        "COMMITTED",
        "actuator-response-loss reconciliation outcome",
    )
    consequence = object_value(
        result.get("consequence"),
        "actuator-response-loss reconciliation consequence",
    )
    require_equal(
        consequence.get("state"),
        "COMMITTED",
        "actuator-response-loss reconciliation consequence.state",
    )
    attempt = attempt_binding(
        consequence.get("attempt"),
        "actuator-response-loss reconciliation attempt",
        full=True,
    )
    assert_attempt_equal(
        attempt,
        expected_attempt,
        "actuator-response-loss reconciliation attempt binding",
    )
    return {
        "http_status": status,
        "valid": result["ok"],
        "outcome": result["outcome"],
        "evidence_digest": require_digest(
            result.get("evidence_digest"),
            "actuator-response-loss reconciliation evidence_digest",
        ),
        "reexecuted": False,
    }


def run_workflow(
    client: JsonClient,
    scenario: dict[str, dict[str, Any]],
    config: dict[str, str],
) -> dict[str, Any]:
    exact = scenario["exact_execution"]
    exact_status, exact_body = client.post(
        proposal_path(exact["proposal_id"], "execute"),
        exact["request"],
    )
    exact_check = validate_exact_execution(
        exact_status,
        exact_body,
        exact["request"],
        config,
    )

    provider_loss = scenario["provider_response_loss"]
    provider_loss_status, provider_loss_body = client.post(
        proposal_path(provider_loss["proposal_id"], "execute"),
        provider_loss["request"],
    )
    provider_loss_attempt = validate_indeterminate_execution(
        provider_loss_status,
        provider_loss_body,
        provider_loss["request"],
        "provider response loss",
    )
    provider_loss_durable = lookup_attempt(
        client,
        provider_loss,
        "INDETERMINATE",
        "provider response loss",
    )
    require_equal(
        provider_loss_attempt.get("tenant_id"),
        provider_loss_durable.get("tenant_id"),
        "provider response loss durable tenant binding",
    )
    require_equal(
        provider_loss_attempt.get("attempt_id"),
        provider_loss_durable.get("attempt_id"),
        "provider response loss durable attempt binding",
    )
    provider_loss_replay_status, provider_loss_replay_body = client.post(
        proposal_path(provider_loss["proposal_id"], "execute"),
        provider_loss["request"],
    )
    provider_loss_replay = validate_replay(
        provider_loss_replay_status,
        provider_loss_replay_body,
        provider_loss_durable,
        "provider response loss",
    )
    provider_loss_after_replay = lookup_attempt(
        client,
        provider_loss,
        "INDETERMINATE",
        "provider response loss after replay",
    )
    assert_attempt_equal(
        provider_loss_after_replay,
        provider_loss_durable,
        "provider response loss post-replay durable attempt",
    )
    provider_loss_request = provider_loss["request"]
    provider_loss_reconciliation_request = {
        "proposal": provider_loss_request["proposal"],
        "evaluation": provider_loss_request["evaluation"],
        "attempt": provider_loss_durable,
        "provider_evidence": OBSERVATION_SENTINEL,
        "evidence": provider_loss_request["evidence"],
    }
    provider_loss_reconciliation_status, provider_loss_reconciliation_body = (
        client.post(
            proposal_path(provider_loss["proposal_id"], "reconcile"),
            provider_loss_reconciliation_request,
        )
    )
    provider_loss_reconciliation = validate_unavailable_reconciliation(
        provider_loss_reconciliation_status,
        provider_loss_reconciliation_body,
    )
    provider_loss_after_reconciliation = lookup_attempt(
        client,
        provider_loss,
        "INDETERMINATE",
        "provider response loss after unavailable reconciliation",
    )
    assert_attempt_equal(
        provider_loss_after_reconciliation,
        provider_loss_durable,
        "provider response loss post-reconciliation durable attempt",
    )

    actuator_loss = scenario["actuator_response_loss"]
    actuator_loss_status, actuator_loss_body = client.post(
        proposal_path(actuator_loss["proposal_id"], "execute"),
        actuator_loss["request"],
    )
    actuator_loss_attempt = validate_indeterminate_execution(
        actuator_loss_status,
        actuator_loss_body,
        actuator_loss["request"],
        "actuator response loss",
    )
    actuator_loss_durable = lookup_attempt(
        client,
        actuator_loss,
        "INDETERMINATE",
        "actuator response loss",
    )
    require_equal(
        actuator_loss_attempt.get("tenant_id"),
        actuator_loss_durable.get("tenant_id"),
        "actuator response loss durable tenant binding",
    )
    require_equal(
        actuator_loss_attempt.get("attempt_id"),
        actuator_loss_durable.get("attempt_id"),
        "actuator response loss durable attempt binding",
    )
    actuator_loss_replay_status, actuator_loss_replay_body = client.post(
        proposal_path(actuator_loss["proposal_id"], "execute"),
        actuator_loss["request"],
    )
    actuator_loss_replay = validate_replay(
        actuator_loss_replay_status,
        actuator_loss_replay_body,
        actuator_loss_durable,
        "actuator response loss",
    )
    actuator_loss_request = actuator_loss["request"]
    actuator_loss_reconciliation_request = {
        "proposal": actuator_loss_request["proposal"],
        "evaluation": actuator_loss_request["evaluation"],
        "attempt": actuator_loss_durable,
        "provider_evidence": OBSERVATION_SENTINEL,
        "evidence": actuator_loss_request["evidence"],
    }
    actuator_loss_reconciliation_status, actuator_loss_reconciliation_body = (
        client.post(
            proposal_path(actuator_loss["proposal_id"], "reconcile"),
            actuator_loss_reconciliation_request,
        )
    )
    actuator_loss_reconciliation = validate_committed_reconciliation(
        actuator_loss_reconciliation_status,
        actuator_loss_reconciliation_body,
        actuator_loss_durable,
    )
    actuator_loss_after_reconciliation = lookup_attempt(
        client,
        actuator_loss,
        "COMMITTED",
        "actuator response loss after reconciliation",
    )
    assert_attempt_equal(
        actuator_loss_after_reconciliation,
        actuator_loss_durable,
        "actuator response loss committed durable attempt",
    )

    return {
        "exact_execution": exact_check,
        "provider_response_loss": {
            "initial": {
                "http_status": provider_loss_status,
                "outcome": "INDETERMINATE",
                "effect_boundary_entered": True,
            },
            "replay": provider_loss_replay,
            "reconciliation": provider_loss_reconciliation,
            "durable_state": "INDETERMINATE",
        },
        "actuator_response_loss": {
            "initial": {
                "http_status": actuator_loss_status,
                "outcome": "INDETERMINATE",
                "effect_boundary_entered": True,
            },
            "replay": actuator_loss_replay,
            "reconciliation": actuator_loss_reconciliation,
            "durable_state": "COMMITTED",
        },
    }


def canonical_unsigned(evidence: dict[str, Any]) -> bytes:
    return json.dumps(
        evidence,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sign_evidence(
    evidence: dict[str, Any],
    private_key: Path,
    key_id: str,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="emilia-canary-sign-") as directory:
        root = Path(directory)
        payload = root / "payload.json"
        signature = root / "signature.bin"
        payload.write_bytes(canonical_unsigned(evidence))
        payload.chmod(0o600)
        command(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(private_key),
                "-rawin",
                "-in",
                str(payload),
                "-out",
                str(signature),
            ],
            "Ed25519 canary signing",
            maximum=32 * 1024,
        )
        try:
            signature_bytes = signature.read_bytes()
        except OSError as error:
            raise CanaryError("Ed25519 canary signature is unavailable") from error
    if len(signature_bytes) != 64:
        raise CanaryError("Ed25519 canary signature must be 64 bytes")
    return {
        **evidence,
        "signature": {
            "algorithm": "Ed25519",
            "key_id": key_id,
            "value": base64.urlsafe_b64encode(signature_bytes)
            .decode("ascii")
            .rstrip("="),
        },
    }


def write_verified_evidence(
    output: Path,
    evidence: dict[str, Any],
    config_path: Path,
    overwrite: bool,
) -> None:
    if not output.is_absolute():
        raise CanaryError("output must use an absolute path")
    if output.exists() and not overwrite:
        raise CanaryError("output already exists; use --overwrite to replace it")
    if not output.parent.is_dir():
        raise CanaryError("output directory is unavailable")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.",
        suffix=".tmp",
        dir=output.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(
                evidence,
                handle,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        verifier = Path(__file__).resolve().with_name("verify-canary.py")
        verification = subprocess.run(
            [
                sys.executable,
                str(verifier),
                "--config",
                str(config_path),
                "--evidence",
                str(temporary),
                "--live",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if verification.returncode != 0:
            detail = verification.stderr.strip()
            raise CanaryError(
                "signed evidence failed closed verification"
                + (f": {detail}" if detail else "")
            )
        os.replace(temporary, output)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def positive_integer(value: str, name: str, maximum: int) -> int:
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"{name} must be an integer") from error
    if number <= 0 or number > maximum:
        raise argparse.ArgumentTypeError(
            f"{name} must be between 1 and {maximum}"
        )
    return number


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Execute the exact consequence-control canary and write signed evidence"
        )
    )
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--scenario", required=True, type=Path)
    parser.add_argument("--application-token-file", required=True, type=Path)
    parser.add_argument("--private-key-file", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--use-google-id-token",
        action="store_true",
        help="obtain an ID token with gcloud for the canonical decision audience",
    )
    parser.add_argument(
        "--identity-service-account",
        help="optionally impersonate this service account for the Google ID token",
    )
    parser.add_argument(
        "--ttl-seconds",
        default=600,
        type=lambda value: positive_integer(value, "ttl-seconds", 3600),
    )
    parser.add_argument(
        "--timeout-seconds",
        default=30,
        type=lambda value: positive_integer(value, "timeout-seconds", 120),
    )
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument(
        "--allow-insecure-loopback",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        with retained_config(args.config) as (config, retained_config_path):
            maximum_age = int(config["CANARY_MAX_AGE_SEC"])
            if args.ttl_seconds > maximum_age:
                raise CanaryError(
                    "ttl-seconds exceeds the configured CANARY_MAX_AGE_SEC"
                )
            if args.identity_service_account and not args.use_google_id_token:
                raise CanaryError(
                    "--identity-service-account requires --use-google-id-token"
                )
            if args.output.exists() and not args.overwrite:
                raise CanaryError(
                    "output already exists; use --overwrite to replace it"
                )
            token = application_token(args.application_token_file)
            signing_key = private_key_file(args.private_key_file, config)
            validate_signing_key_pair(
                signing_key,
                Path(config["CANARY_EVIDENCE_PUBLIC_KEY_FILE"]),
            )
            scenario = load_scenario(args.scenario, config)

            decision_origin, audience = preflight(
                config,
                args.allow_insecure_loopback,
            )
            identity_token = (
                google_identity_token(audience, args.identity_service_account)
                if args.use_google_id_token
                else None
            )
            client = JsonClient(
                decision_origin,
                token,
                identity_token,
                args.timeout_seconds,
            )
            checks = run_workflow(client, scenario, config)

            observed_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
            expires_at = observed_at + dt.timedelta(seconds=args.ttl_seconds)
            unsigned = {
                "@version": VERSION,
                "project_id": config["PROJECT_ID"],
                "region": config["REGION"],
                "evidence_status": "observed",
                "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
                "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
                "nonce": f"canary_nonce_{secrets.token_urlsafe(24)}",
                "actuator_revision": (
                    f"{config['ACTUATOR_SERVICE']}-{config['RELEASE_ID']}"
                ),
                "decision_revision": (
                    f"{config['DECISION_SERVICE']}-{config['RELEASE_ID']}"
                ),
                "actuator_image": config["ACTUATOR_IMAGE"],
                "decision_image": config["DECISION_IMAGE"],
                "checks": checks,
            }
            signed = sign_evidence(
                unsigned,
                signing_key,
                config["CANARY_EVIDENCE_KEY_ID"],
            )
            write_verified_evidence(
                args.output,
                signed,
                retained_config_path,
                args.overwrite,
            )
    except (
        CanaryError,
        KeyError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        print(f"canary refused: {error}", file=sys.stderr)
        return 1
    print(f"signed canary evidence written: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
