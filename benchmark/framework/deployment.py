from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from framework.io_utils import FrameworkError, read_json


SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")

CANONICAL_ROLES = (
    "dut",
    "loadgen",
)

ACCESS_MODES = {
    "local",
    "ssh",
}


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _require_slug(value: Any, field: str) -> str:
    if not isinstance(value, str) or not SLUG_RE.fullmatch(value):
        raise FrameworkError(
            f"{field} must be a lowercase slug"
        )
    return value


def normalize_deployment_definition(
    definition: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(definition, dict):
        raise FrameworkError(
            "deployment definition must be an object"
        )

    if definition.get("schema_version") != 1:
        raise FrameworkError(
            "deployment schema_version must be 1"
        )

    unknown_top = set(definition).difference(
        {
            "schema_version",
            "deployment",
            "nodes",
        }
    )
    if unknown_top:
        raise FrameworkError(
            "unsupported deployment field(s): "
            + ", ".join(sorted(unknown_top))
        )

    deployment = definition.get("deployment")
    if not isinstance(deployment, dict):
        raise FrameworkError(
            "deployment must be an object"
        )

    unknown_deployment = set(deployment).difference(
        {
            "name",
            "provider",
            "topology_class",
        }
    )
    if unknown_deployment:
        raise FrameworkError(
            "unsupported deployment metadata field(s): "
            + ", ".join(
                sorted(unknown_deployment)
            )
        )

    name = _require_slug(
        deployment.get("name"),
        "deployment.name",
    )
    provider = _require_slug(
        deployment.get("provider"),
        "deployment.provider",
    )
    topology_class = _require_slug(
        deployment.get("topology_class"),
        "deployment.topology_class",
    )

    nodes = definition.get("nodes")
    if not isinstance(nodes, dict) or not nodes:
        raise FrameworkError(
            "deployment.nodes must be a non-empty object"
        )

    normalized_nodes: dict[str, Any] = {}
    role_to_node: dict[str, str] = {}

    for node_name in sorted(nodes):
        _require_slug(
            node_name,
            "deployment node name",
        )

        node = nodes[node_name]
        if not isinstance(node, dict):
            raise FrameworkError(
                f"nodes.{node_name} must be an object"
            )

        unknown_node = set(node).difference(
            {
                "roles",
                "access",
                "data_address",
            }
        )
        if unknown_node:
            raise FrameworkError(
                f"unsupported nodes.{node_name} field(s): "
                + ", ".join(sorted(unknown_node))
            )

        roles = node.get("roles")
        if (
            not isinstance(roles, list)
            or not roles
            or any(
                not isinstance(role, str)
                for role in roles
            )
        ):
            raise FrameworkError(
                f"nodes.{node_name}.roles "
                "must be a non-empty string array"
            )

        if len(set(roles)) != len(roles):
            raise FrameworkError(
                f"nodes.{node_name}.roles "
                "must be unique"
            )

        unknown_roles = (
            set(roles)
            - set(CANONICAL_ROLES)
        )
        if unknown_roles:
            raise FrameworkError(
                f"unsupported nodes.{node_name} role(s): "
                + ", ".join(sorted(unknown_roles))
            )

        for role in roles:
            if role in role_to_node:
                raise FrameworkError(
                    f"canonical role {role!r} "
                    "must be assigned exactly once"
                )
            role_to_node[role] = node_name

        access = node.get("access")
        if not isinstance(access, dict):
            raise FrameworkError(
                f"nodes.{node_name}.access "
                "must be an object"
            )

        unknown_access = set(access).difference(
            {
                "mode",
                "target",
            }
        )
        if unknown_access:
            raise FrameworkError(
                f"unsupported nodes.{node_name}.access "
                "field(s): "
                + ", ".join(sorted(unknown_access))
            )

        mode = access.get("mode")
        if mode not in ACCESS_MODES:
            raise FrameworkError(
                f"nodes.{node_name}.access.mode "
                "must be local or ssh"
            )

        target = access.get("target")

        if mode == "local":
            if target is not None:
                raise FrameworkError(
                    f"nodes.{node_name}.access.target "
                    "is forbidden for local access"
                )
            normalized_access = {
                "mode": "local",
            }
        else:
            if (
                not isinstance(target, str)
                or not target.strip()
            ):
                raise FrameworkError(
                    f"nodes.{node_name}.access.target "
                    "is required for ssh access"
                )
            normalized_access = {
                "mode": "ssh",
                "target": target.strip(),
            }

        data_address = node.get(
            "data_address",
            "auto",
        )
        if (
            not isinstance(data_address, str)
            or not data_address.strip()
        ):
            raise FrameworkError(
                f"nodes.{node_name}.data_address "
                "must be a non-empty string"
            )

        normalized_nodes[node_name] = {
            "roles": list(roles),
            "access": normalized_access,
            "data_address":
                data_address.strip(),
        }

    missing_roles = (
        set(CANONICAL_ROLES)
        - set(role_to_node)
    )
    if missing_roles:
        raise FrameworkError(
            "deployment must assign canonical role(s): "
            + ", ".join(sorted(missing_roles))
        )

    return {
        "schema_version": 1,
        "deployment": {
            "name": name,
            "provider": provider,
            "topology_class":
                topology_class,
        },
        "nodes": normalized_nodes,
    }


def load_deployment_definition(
    path: Path,
) -> dict[str, Any]:
    if not path.is_file():
        raise FrameworkError(
            f"deployment definition not found: {path}"
        )

    value = read_json(path)
    return normalize_deployment_definition(
        value
    )


def deployment_role_map(
    definition: dict[str, Any],
) -> dict[str, str]:
    normalized = normalize_deployment_definition(
        definition
    )

    result: dict[str, str] = {}

    for node_name, node in (
        normalized["nodes"].items()
    ):
        for role in node["roles"]:
            result[role] = node_name

    return result


def deployment_definition_sha256(
    definition: dict[str, Any],
) -> str:
    normalized = normalize_deployment_definition(
        definition
    )
    return hashlib.sha256(
        _canonical_json(normalized)
    ).hexdigest()
