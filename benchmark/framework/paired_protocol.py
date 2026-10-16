from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from framework.ids import validate_slug
from framework.io_utils import FrameworkError, read_json


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def validate_paired_protocol(protocol: dict[str, Any]) -> None:
    if not isinstance(protocol, dict) or protocol.get("schema_version") != 1:
        raise FrameworkError("paired scientific protocol requires schema_version=1")

    metadata = protocol.get("protocol")
    if not isinstance(metadata, dict):
        raise FrameworkError("protocol metadata must be an object")
    name = metadata.get("name")
    if not isinstance(name, str):
        raise FrameworkError("protocol.name must be a string")
    validate_slug(name, "protocol.name")
    if not isinstance(metadata.get("claim_scope"), str) or not metadata["claim_scope"]:
        raise FrameworkError("protocol.claim_scope must be a non-empty string")

    if not isinstance(protocol.get("execution"), dict):
        raise FrameworkError("protocol.execution must be an object")
    if not isinstance(protocol.get("analysis"), dict):
        raise FrameworkError("protocol.analysis must be an object")


def load_paired_protocol(path: Path) -> dict[str, Any]:
    value = read_json(path)
    validate_paired_protocol(value)
    return value


def paired_protocol_sha256(protocol: dict[str, Any]) -> str:
    validate_paired_protocol(protocol)
    return hashlib.sha256(_canonical_json(protocol)).hexdigest()
