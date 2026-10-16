from __future__ import annotations

import os
import platform
import socket
import subprocess
from pathlib import Path
from typing import Any

from framework.ids import utc_rfc3339
from framework.io_utils import FrameworkError, atomic_write_json
from framework.deployment import normalize_deployment_definition


def _run_text(argv: list[str]) -> str | None:
    try:
        result = subprocess.run(
            argv,
            check=False,
            text=True,
            capture_output=True,
        )
    except OSError:
        return None

    if result.returncode != 0:
        return None

    return result.stdout.strip()


def _sysctl(name: str) -> str | None:
    return _run_text(["sysctl", "-n", name])


def _int_or_none(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value.strip())
    except ValueError:
        return None


def _linux_cpu_info() -> tuple[str | None, set[str]]:
    cpuinfo = Path("/proc/cpuinfo")
    if not cpuinfo.is_file():
        return None, set()

    model = None
    flags: set[str] = set()

    for line in cpuinfo.read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines():
        if ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]

        if model is None and key in {"model name", "Hardware", "Processor"}:
            model = value

        if key in {"flags", "Features"}:
            flags.update(value.lower().split())

    return model, flags


def _darwin_cpu_info() -> tuple[str | None, set[str]]:
    model = _sysctl("machdep.cpu.brand_string")
    flags: set[str] = set()

    for key in (
        "machdep.cpu.features",
        "machdep.cpu.leaf7_features",
        "machdep.cpu.extfeatures",
    ):
        value = _sysctl(key)
        if value:
            flags.update(value.lower().split())

    return model, flags


def _normalized_isa(flags: set[str]) -> dict[str, bool]:
    return {
        "aes": "aes" in flags,
        "pclmulqdq": "pclmulqdq" in flags or "pclmul" in flags,
        "avx2": "avx2" in flags,
        "avx512f": "avx512f" in flags,
        "vaes": "vaes" in flags,
        "vpclmulqdq": "vpclmulqdq" in flags,
        "neon": "neon" in flags or "asimd" in flags,
        "sha1": "sha1" in flags or "sha" in flags,
        "sha2": "sha2" in flags or "sha256" in flags,
    }


def collect_system() -> dict[str, Any]:
    uname = platform.uname()

    return {
        "schema_version": 1,
        "collected_at": utc_rfc3339(),
        "os": {
            "system": uname.system,
            "release": uname.release,
            "version": uname.version,
        },
        "kernel": {
            "name": uname.system,
            "release": uname.release,
        },
        "architecture": platform.machine(),
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
        },
    }


def collect_cpu() -> dict[str, Any]:
    system = platform.system()

    if system == "Darwin":
        model, flags = _darwin_cpu_info()
        logical = _int_or_none(_sysctl("hw.logicalcpu")) or os.cpu_count()
        physical = _int_or_none(_sysctl("hw.physicalcpu"))
        packages = _int_or_none(_sysctl("hw.packages"))
    elif system == "Linux":
        model, flags = _linux_cpu_info()
        logical = os.cpu_count()
        physical = None
        packages = None

        lscpu_json = _run_text(["lscpu", "-J"])
        if lscpu_json:
            try:
                import json
                data = json.loads(lscpu_json)
                fields = {
                    row["field"].rstrip(":"): row["data"]
                    for row in data.get("lscpu", [])
                    if "field" in row and "data" in row
                }
                sockets = _int_or_none(fields.get("Socket(s)"))
                cores_per_socket = _int_or_none(fields.get("Core(s) per socket"))
                if sockets is not None:
                    packages = sockets
                if sockets is not None and cores_per_socket is not None:
                    physical = sockets * cores_per_socket
            except (ValueError, TypeError, KeyError):
                pass
    else:
        model = platform.processor() or None
        flags = set()
        logical = os.cpu_count()
        physical = None
        packages = None

    return {
        "schema_version": 1,
        "model": model,
        "architecture": platform.machine(),
        "topology": {
            "logical_cpus": logical,
            "physical_cores": physical,
            "packages": packages,
        },
        "isa": _normalized_isa(flags),
        "raw_feature_count": len(flags),
    }


def collect_memory() -> dict[str, Any]:
    system = platform.system()
    total_bytes = None

    if system == "Darwin":
        total_bytes = _int_or_none(_sysctl("hw.memsize"))

    elif system == "Linux":
        meminfo = Path("/proc/meminfo")
        if meminfo.is_file():
            for line in meminfo.read_text(
                encoding="utf-8",
                errors="replace",
            ).splitlines():
                if line.startswith("MemTotal:"):
                    fields = line.split()
                    if len(fields) >= 2:
                        try:
                            total_bytes = int(fields[1]) * 1024
                        except ValueError:
                            pass
                    break

    return {
        "schema_version": 1,
        "total_bytes": total_bytes,
    }


def collect_network() -> dict[str, Any]:
    interfaces = []

    try:
        interfaces = [
            {
                "index": index,
                "name": name,
                "loopback": name in {"lo", "lo0"},
            }
            for index, name in socket.if_nameindex()
        ]
    except OSError:
        pass

    return {
        "schema_version": 1,
        "interfaces": interfaces,
    }


def prepare_local_environment(
    experiment_dir: Path,
) -> dict[str, Any]:
    nodes_root = experiment_dir / "environment" / "nodes"
    host_dir = nodes_root / "host"
    host_dir.mkdir(parents=True, exist_ok=True)

    adapter = {
        "schema_version": 1,
        "adapter": "local",
        "topology_class": "T0",
        "nodes": {
            "host": {
                "roles": [
                    "load-generator",
                    "dut",
                ]
            }
        },
    }

    atomic_write_json(
        experiment_dir / "environment" / "adapter.json",
        adapter,
    )
    atomic_write_json(host_dir / "system.json", collect_system())
    atomic_write_json(host_dir / "cpu.json", collect_cpu())
    atomic_write_json(host_dir / "memory.json", collect_memory())
    atomic_write_json(host_dir / "network.json", collect_network())

    return adapter


def prepare_deployment_environment(
    experiment_dir: Path,
    deployment: dict[str, Any],
) -> dict[str, Any]:
    definition = normalize_deployment_definition(deployment)
    metadata = definition["deployment"]

    if metadata["provider"] != "local":
        raise FrameworkError(
            "portable deployment provider is not implemented yet: "
            f"{metadata['provider']}"
        )

    nodes = definition["nodes"]
    if len(nodes) != 1:
        raise FrameworkError(
            "local portable deployment currently requires exactly one node"
        )

    node_name, node = next(iter(nodes.items()))
    if node["access"]["mode"] != "local":
        raise FrameworkError(
            "local portable deployment requires local access"
        )

    nodes_root = experiment_dir / "environment" / "nodes"
    node_dir = nodes_root / node_name
    node_dir.mkdir(parents=True, exist_ok=True)

    adapter = {
        "schema_version": 2,
        "adapter": "portable-deployment",
        "provider": metadata["provider"],
        "deployment_name": metadata["name"],
        "topology_class": metadata["topology_class"],
        "nodes": {
            node_name: {
                "roles": list(node["roles"]),
                "access": dict(node["access"]),
                "data_address": node["data_address"],
            }
        },
    }

    atomic_write_json(
        experiment_dir / "environment" / "adapter.json",
        adapter,
    )
    atomic_write_json(node_dir / "system.json", collect_system())
    atomic_write_json(node_dir / "cpu.json", collect_cpu())
    atomic_write_json(node_dir / "memory.json", collect_memory())
    atomic_write_json(node_dir / "network.json", collect_network())

    return adapter


def prepare_environment(
    experiment_dir: Path,
    environment_name: str | None = None,
    deployment: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if (environment_name is None) == (deployment is None):
        raise FrameworkError(
            "prepare_environment requires exactly one of environment_name or deployment"
        )

    if deployment is not None:
        return prepare_deployment_environment(
            experiment_dir,
            deployment,
        )

    if environment_name == "local":
        return prepare_local_environment(experiment_dir)

    raise FrameworkError(
        f"environment adapter is not implemented yet: {environment_name}"
    )
