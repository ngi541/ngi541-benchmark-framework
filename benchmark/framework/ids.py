from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone


SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
EXPERIMENT_ID_RE = re.compile(
    r"^[a-z0-9][a-z0-9-]*-"
    r"[a-z0-9][a-z0-9-]*-"
    r"\d{8}T\d{6}Z-"
    r"[a-f0-9]{6}$"
)
RUN_ID_RE = re.compile(r"^run-\d{4,}$")
PAIR_ID_RE = re.compile(r"^pair-\d{4,}$")


def validate_slug(value: str, field: str) -> str:
    if not SLUG_RE.fullmatch(value):
        raise ValueError(
            f"{field} must match {SLUG_RE.pattern!r}; got {value!r}"
        )
    return value


def utc_timestamp_for_id(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def utc_rfc3339(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_experiment_id(
    workload: str,
    environment: str,
    *,
    now: datetime | None = None,
    short_id: str | None = None,
) -> str:
    validate_slug(workload, "workload")
    validate_slug(environment, "environment")

    if short_id is None:
        short_id = secrets.token_hex(3)

    if not re.fullmatch(r"[a-f0-9]{6}", short_id):
        raise ValueError(
            "short_id must contain exactly six lowercase hexadecimal characters"
        )

    result = (
        f"{workload}-{environment}-"
        f"{utc_timestamp_for_id(now)}-{short_id}"
    )

    if not EXPERIMENT_ID_RE.fullmatch(result):
        raise ValueError(f"generated invalid experiment id: {result}")

    return result

def generate_portable_experiment_id(
    workload: str,
    scientific_identity_sha256: str,
    *,
    now: datetime | None = None,
    short_id: str | None = None,
) -> str:
    validate_slug(workload, "workload")

    if not re.fullmatch(r"[a-f0-9]{64}", scientific_identity_sha256):
        raise ValueError(
            "scientific_identity_sha256 must contain exactly 64 lowercase hexadecimal characters"
        )

    if short_id is None:
        short_id = secrets.token_hex(3)

    if not re.fullmatch(r"[a-f0-9]{6}", short_id):
        raise ValueError(
            "short_id must contain exactly six lowercase hexadecimal characters"
        )

    result = (
        f"{workload}-{scientific_identity_sha256[:12]}-"
        f"{utc_timestamp_for_id(now)}-{short_id}"
    )

    if not EXPERIMENT_ID_RE.fullmatch(result):
        raise ValueError(f"generated invalid portable experiment id: {result}")

    return result
