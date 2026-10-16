from __future__ import annotations

import hashlib
import json
from typing import Any

from framework.ids import validate_slug
from framework.io_utils import FrameworkError


SCIENTIFIC_REQUEST_KEYS = {
    "workload",
    "variants",
    "parameters",
    "conditions",
    "comparison",
    "scheduling",
    "measurement_control",
}

NON_SCIENTIFIC_REQUEST_KEYS = {
    "alias",
    "environment",
    "deployment",
}


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def scientific_identity_projection(
    request: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(request, dict):
        raise FrameworkError(
            "experiment request must be an object"
        )

    allowed = (
        SCIENTIFIC_REQUEST_KEYS
        | NON_SCIENTIFIC_REQUEST_KEYS
    )

    unknown = set(request).difference(
        allowed
    )
    if unknown:
        raise FrameworkError(
            "scientific identity cannot classify "
            "request field(s): "
            + ", ".join(sorted(unknown))
        )

    workload = request.get("workload")
    if not isinstance(workload, str):
        raise FrameworkError(
            "request.workload must be a string"
        )
    validate_slug(
        workload,
        "workload",
    )

    variants = request.get("variants")
    if (
        not isinstance(variants, list)
        or not variants
        or any(
            not isinstance(value, str)
            for value in variants
        )
    ):
        raise FrameworkError(
            "request.variants must be "
            "a non-empty string array"
        )

    parameters = request.get("parameters")
    if not isinstance(parameters, dict):
        raise FrameworkError(
            "request.parameters must be an object"
        )

    identity: dict[str, Any] = {
        "schema_version": 1,
        "workload": workload,
        "variants": list(variants),
        "parameters": dict(parameters),
    }

    for key in (
        "conditions",
        "comparison",
        "scheduling",
        "measurement_control",
    ):
        if key in request:
            identity[key] = request[key]

    return identity


def scientific_identity_sha256(
    request: dict[str, Any],
) -> str:
    identity = scientific_identity_projection(
        request
    )
    return hashlib.sha256(
        _canonical_json(identity)
    ).hexdigest()


def scientific_definition_id(
    request: dict[str, Any],
) -> str:
    identity = scientific_identity_projection(
        request
    )
    digest = hashlib.sha256(
        _canonical_json(identity)
    ).hexdigest()
    return (
        f"{identity['workload']}-"
        f"{digest[:12]}"
    )
