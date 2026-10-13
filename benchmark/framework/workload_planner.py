from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from framework.dual_host_telemetry import (
    DarwinPowermetricsTelemetry,
    REMOTE_SAMPLER,
    _local_sample,
    definition_sha256 as telemetry_definition_sha256,
    integrate_power_energy_j,
    load_definition as load_telemetry_definition,
)
from framework.io_utils import FrameworkError, atomic_write_json, atomic_write_text
from framework.loadgen_runtime import (
    definition_sha256 as loadgen_definition_sha256,
    load_definition as load_loadgen_definition,
)
from framework.network_evidence import (
    definition_sha256 as network_evidence_definition_sha256,
    load_definition as load_network_evidence_definition,
)
from framework.network_qualification import SSHSession
from framework.scientific_corpus import (
    load_definition as load_corpus_definition,
    materialize_surrogate,
    run_scientific_corpus,
    stream_object_descriptor,
)
from framework.transport_security import (
    _generate_tls_material,
    _stop_server,
    _variant_environment,
    _write_remote_file_base64,
    definition_sha256 as transport_security_definition_sha256,
    load_definition as load_transport_security_definition,
    nginx_config,
)

SCHEMA_VERSION = 1
PLAN_SCHEMA_VERSION = 1


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _semantic_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _utc_id_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _slug(text: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    if not value:
        raise FrameworkError("qualification.name must contain an alphanumeric character")
    return value


def definition_sha256(definition: dict[str, Any]) -> str:
    return _semantic_sha256(definition)


def load_definition(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FrameworkError(f"workload planner config not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise FrameworkError(
            f"invalid workload planner JSON: line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    if not isinstance(value, dict):
        raise FrameworkError("workload planner definition must be a JSON object")
    validate_definition(value)
    return value


def _relative_path(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FrameworkError(f"{field} must be a non-empty relative path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise FrameworkError(f"{field} must be a portable repository-relative path")
    return value


def _positive_number(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)) or float(value) <= 0:
        raise FrameworkError(f"{field} must be a finite number > 0")
    return float(value)


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise FrameworkError(f"{field} must be an integer > 0")
    return value


def validate_definition(definition: dict[str, Any]) -> None:
    if definition.get("schema_version") != SCHEMA_VERSION:
        raise FrameworkError("workload planner schema_version must be 1")
    qualification = definition.get("qualification")
    if not isinstance(qualification, dict) or not isinstance(qualification.get("name"), str) or not qualification["name"].strip():
        raise FrameworkError("qualification.name must be a non-empty string")
    if qualification.get("claim_scope") != "stock-only-workload-planning-no-performance-claim":
        raise FrameworkError("qualification.claim_scope must be stock-only-workload-planning-no-performance-claim")

    inputs = definition.get("inputs")
    if not isinstance(inputs, dict):
        raise FrameworkError("inputs must be an object")
    for key in (
        "network_evidence_config",
        "loadgen_runtime_config",
        "scientific_corpus_config",
        "transport_security_config",
        "dual_host_telemetry_config",
    ):
        _relative_path(inputs.get(key), f"inputs.{key}")

    planning = definition.get("planning")
    if not isinstance(planning, dict):
        raise FrameworkError("planning must be an object")
    if planning.get("calibration_variant") != "stock":
        raise FrameworkError("planning.calibration_variant must be exactly 'stock'")
    fractions = planning.get("service_target_fractions")
    if fractions != [0.5, 0.8]:
        raise FrameworkError("planning.service_target_fractions must be exactly [0.5, 0.8]")
    workers = planning.get("worker_points")
    if workers != ["single", "physical-core-count"]:
        raise FrameworkError("planning.worker_points must be ['single', 'physical-core-count']")

    candidates = planning.get("concurrency_candidates")
    if not isinstance(candidates, list) or not candidates:
        raise FrameworkError("planning.concurrency_candidates must be a non-empty array")
    seen: set[tuple[int, int]] = set()
    previous_connections = 0
    for index, item in enumerate(candidates):
        if not isinstance(item, dict):
            raise FrameworkError(f"planning.concurrency_candidates[{index}] must be an object")
        c = _positive_int(item.get("connections"), f"planning.concurrency_candidates[{index}].connections")
        m = _positive_int(item.get("max_concurrent_streams_per_connection"), f"planning.concurrency_candidates[{index}].max_concurrent_streams_per_connection")
        pair = (c, m)
        if pair in seen:
            raise FrameworkError(f"duplicate concurrency candidate: {c}x{m}")
        seen.add(pair)
        if c < previous_connections:
            raise FrameworkError("concurrency candidates must be staged by non-decreasing connection count")
        previous_connections = c

    probe = planning.get("probe")
    if not isinstance(probe, dict):
        raise FrameworkError("planning.probe must be an object")
    _positive_number(probe.get("warmup_seconds"), "planning.probe.warmup_seconds")
    _positive_number(probe.get("measurement_seconds"), "planning.probe.measurement_seconds")
    _positive_number(probe.get("sample_interval_seconds"), "planning.probe.sample_interval_seconds")
    ratio = _positive_number(probe.get("achieved_target_ratio_min"), "planning.probe.achieved_target_ratio_min")
    if ratio > 1.0:
        raise FrameworkError("planning.probe.achieved_target_ratio_min must be <= 1")
    total = _positive_number(probe.get("loadgen_total_cpu_max_percent"), "planning.probe.loadgen_total_cpu_max_percent")
    core = _positive_number(probe.get("loadgen_core_cpu_max_percent"), "planning.probe.loadgen_core_cpu_max_percent")
    if total >= 100 or core > 100:
        raise FrameworkError("loadgen CPU headroom thresholds must be below/equal to 100")
    if probe.get("require_no_throttling") is not True:
        raise FrameworkError("planning.probe.require_no_throttling must be true")

    final = planning.get("final_measurement")
    if not isinstance(final, dict):
        raise FrameworkError("planning.final_measurement must be an object")
    _positive_number(final.get("warmup_seconds"), "planning.final_measurement.warmup_seconds")
    _positive_number(final.get("measurement_seconds"), "planning.final_measurement.measurement_seconds")

    hacc = planning.get("hacc_calibration")
    if not isinstance(hacc, dict):
        raise FrameworkError("planning.hacc_calibration must be an object")
    if hacc.get("selector") != "deterministic-bucket-sequence":
        raise FrameworkError("planning.hacc_calibration.selector must be deterministic-bucket-sequence")
    buckets = hacc.get("bucket_indices")
    if not isinstance(buckets, list) or not buckets:
        raise FrameworkError("planning.hacc_calibration.bucket_indices must be a non-empty array")
    for i, bucket in enumerate(buckets):
        if isinstance(bucket, bool) or not isinstance(bucket, int) or bucket < 0:
            raise FrameworkError(f"planning.hacc_calibration.bucket_indices[{i}] must be an integer >= 0")
    _positive_int(hacc.get("objects_per_bucket"), "planning.hacc_calibration.objects_per_bucket")
    max_bytes = hacc.get("max_materialized_bytes")
    _positive_int(max_bytes, "planning.hacc_calibration.max_materialized_bytes")


def derive_target_goodput_mbps(service_envelope_mbps: float, fraction: float) -> float:
    if service_envelope_mbps <= 0 or not 0 < fraction <= 1:
        raise FrameworkError("invalid service envelope or target fraction")
    return round(service_envelope_mbps * fraction, 6)


def fixed_object_rate_hz(target_goodput_mbps: float, object_bytes: int) -> float:
    if target_goodput_mbps <= 0 or object_bytes <= 0:
        raise FrameworkError("target_goodput_mbps and object_bytes must be > 0")
    return target_goodput_mbps * 1_000_000.0 / (8.0 * object_bytes)


def per_client_rps(target_goodput_mbps: float, object_bytes: int, connections: int) -> float:
    if connections <= 0:
        raise FrameworkError("connections must be > 0")
    return fixed_object_rate_hz(target_goodput_mbps, object_bytes) / connections


def _hacc_calibration_objects(manifest: dict[str, Any], spec: dict[str, Any]) -> list[dict[str, Any]]:
    objects = manifest.get("objects")
    if not isinstance(objects, list):
        raise FrameworkError("HACC manifest is missing objects")
    selected: list[dict[str, Any]] = []
    per_bucket = int(spec["objects_per_bucket"])
    for bucket_index in spec["bucket_indices"]:
        candidates = sorted(
            (obj for obj in objects if int(obj.get("bucket_index", -1)) == int(bucket_index)),
            key=lambda obj: (int(obj["sequence"]), str(obj["object_id"])),
        )
        if len(candidates) < per_bucket:
            raise FrameworkError(
                f"HACC calibration bucket {bucket_index} has only {len(candidates)} objects; {per_bucket} required"
            )
        selected.extend(candidates[:per_bucket])
    total = sum(int(obj["size_bytes"]) for obj in selected)
    if total > int(spec["max_materialized_bytes"]):
        raise FrameworkError(
            "HACC calibration selection exceeds max_materialized_bytes; "
            f"selected={total} limit={spec['max_materialized_bytes']}"
        )
    return selected


def build_hacc_timing_script(
    objects: list[dict[str, Any]],
    *,
    target_goodput_mbps: float,
    connections: int,
    duration_seconds: float,
    base_uri: str,
    object_paths: dict[str, str],
) -> str:
    if not objects:
        raise FrameworkError("HACC timing script requires at least one object")
    if target_goodput_mbps <= 0 or connections <= 0 or duration_seconds <= 0:
        raise FrameworkError("invalid HACC timing script parameters")
    per_client_bytes_per_second = target_goodput_mbps * 1_000_000.0 / 8.0 / connections
    if per_client_bytes_per_second <= 0:
        raise FrameworkError("invalid per-client byte rate")
    rows: list[str] = []
    offset_seconds = 0.0
    index = 0
    while offset_seconds < duration_seconds:
        obj = objects[index % len(objects)]
        object_id = str(obj["object_id"])
        path = object_paths[object_id]
        # h2load timing scripts use millisecond offsets with microsecond resolution.
        rows.append(f"{max(0.001, offset_seconds * 1000.0):.6f}\t{base_uri}/{path}")
        offset_seconds += int(obj["size_bytes"]) / per_client_bytes_per_second
        index += 1
        if index > 10_000_000:
            raise FrameworkError("HACC timing script generation exceeded safety bound")
    return "\n".join(rows) + "\n"


def parse_h2load_json(value: dict[str, Any], *, target_goodput_mbps: float) -> dict[str, Any]:
    try:
        measurements = value["measurements"]
        duration = float(measurements["duration"])
        requests = measurements["requests"]
        traffic = measurements["traffic"]
        data_bytes = int(traffic["data"])
        succeeded = int(requests["succeeded"])
        failed = int(requests["failed"])
        errored = int(requests["errored"])
        timeout = int(requests.get("timeout", 0))
    except (KeyError, TypeError, ValueError) as exc:
        raise FrameworkError(f"invalid h2load JSON result: {exc}") from exc
    if duration <= 0:
        raise FrameworkError("h2load JSON duration must be > 0")
    goodput = data_bytes * 8.0 / duration / 1_000_000.0
    ratio = goodput / target_goodput_mbps if target_goodput_mbps > 0 else None
    performance = measurements.get("performance") if isinstance(measurements.get("performance"), dict) else {}
    return {
        "duration_seconds": duration,
        "application_data_bytes": data_bytes,
        "application_goodput_mbps": goodput,
        "achieved_target_ratio": ratio,
        "requests_succeeded": succeeded,
        "requests_failed": failed,
        "requests_errored": errored,
        "requests_timeout": timeout,
        "request_per_second": measurements.get("request_per_second"),
        "bytes_per_second_total": measurements.get("bytes_per_second"),
        "udp_datagram": measurements.get("udp_datagram"),
        "performance": performance,
    }


def summarize_loadgen_telemetry(samples: list[dict[str, Any]]) -> dict[str, Any]:
    total_values: list[float] = []
    core_values: list[float] = []
    throttled = False
    process_values: list[float] = []
    rx_values: list[int] = []
    tx_values: list[int] = []
    udp_errors: list[int] = []
    for sample in samples:
        total = sample.get("cpu", {}).get("busy_percent")
        if isinstance(total, (int, float)) and not isinstance(total, bool):
            total_values.append(float(total))
        cores = sample.get("cpu", {}).get("per_core_busy_percent")
        if isinstance(cores, list):
            for value in cores:
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    core_values.append(float(value))
        if sample.get("thermal", {}).get("throttling_active") is True:
            throttled = True
        proc = sample.get("process")
        if isinstance(proc, dict) and isinstance(proc.get("cpu_seconds"), (int, float)):
            process_values.append(float(proc["cpu_seconds"]))
        net = sample.get("network")
        if isinstance(net, dict):
            if isinstance(net.get("rx_bytes"), int):
                rx_values.append(int(net["rx_bytes"]))
            if isinstance(net.get("tx_bytes"), int):
                tx_values.append(int(net["tx_bytes"]))
        ue = sample.get("udp", {}).get("in_errors")
        if isinstance(ue, int):
            udp_errors.append(ue)
    return {
        "max_total_cpu_busy_percent": max(total_values) if total_values else None,
        "max_single_core_busy_percent": max(core_values) if core_values else None,
        "firmware_throttling_active": throttled,
        "process_cpu_seconds_delta": max(process_values) - min(process_values) if len(process_values) >= 2 else None,
        "rx_bytes_delta": max(rx_values) - min(rx_values) if len(rx_values) >= 2 else None,
        "tx_bytes_delta": max(tx_values) - min(tx_values) if len(tx_values) >= 2 else None,
        "udp_in_errors_delta": max(udp_errors) - min(udp_errors) if len(udp_errors) >= 2 else None,
        "sample_count": len(samples),
    }


def summarize_dut_telemetry(samples: list[dict[str, Any]], application_data_bytes: int) -> dict[str, Any]:
    throttled = any(sample.get("thermal", {}).get("throttling_active") is True for sample in samples)
    cpu_values = [
        float(sample["process"]["cpu_seconds"])
        for sample in samples
        if isinstance(sample.get("process"), dict)
        and isinstance(sample["process"].get("cpu_seconds"), (int, float))
    ]
    process_delta = max(cpu_values) - min(cpu_values) if len(cpu_values) >= 2 else None
    gib = application_data_bytes / float(1024 ** 3) if application_data_bytes > 0 else 0.0
    energy = integrate_power_energy_j(samples)
    return {
        "throttling_active": throttled,
        "process_cpu_seconds_delta": process_delta,
        "process_cpu_seconds_per_gib": process_delta / gib if process_delta is not None and gib > 0 else None,
        "estimated_energy_j": energy,
        "estimated_energy_j_per_gib": energy / gib if energy is not None and gib > 0 else None,
        "sample_count": len(samples),
    }


def evaluate_probe(
    h2load: dict[str, Any],
    loadgen: dict[str, Any],
    dut: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    reasons: list[str] = []
    ratio = h2load.get("achieved_target_ratio")
    if not isinstance(ratio, (int, float)) or ratio < float(policy["achieved_target_ratio_min"]):
        reasons.append("target-goodput-not-sustained")
    if any(int(h2load.get(name, 0)) != 0 for name in ("requests_failed", "requests_errored", "requests_timeout")):
        reasons.append("http-request-failure")
    total = loadgen.get("max_total_cpu_busy_percent")
    if not isinstance(total, (int, float)):
        reasons.append("loadgen-total-cpu-unavailable")
    elif total >= float(policy["loadgen_total_cpu_max_percent"]):
        reasons.append("loadgen-total-cpu-headroom")
    core = loadgen.get("max_single_core_busy_percent")
    if not isinstance(core, (int, float)):
        reasons.append("loadgen-core-cpu-unavailable")
    elif core >= float(policy["loadgen_core_cpu_max_percent"]):
        reasons.append("loadgen-single-core-headroom")
    if policy.get("require_no_throttling") is True:
        if loadgen.get("firmware_throttling_active") is True:
            reasons.append("loadgen-firmware-throttling")
        if dut.get("throttling_active") is True:
            reasons.append("dut-throttling")
    return {"passed": not reasons, "reasons": reasons}


def select_first_passing_candidate(probes: list[dict[str, Any]]) -> dict[str, Any]:
    for probe in probes:
        if probe.get("evaluation", {}).get("passed") is True:
            return probe
    raise FrameworkError("no concurrency candidate satisfied target and load-generator headroom policy")


def _resolve_repo_path(repo_root: Path, value: str, field: str) -> Path:
    path = (repo_root / value).resolve()
    try:
        path.relative_to(repo_root.resolve())
    except ValueError as exc:
        raise FrameworkError(f"{field} escapes repository root: {value}") from exc
    return path


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        raise FrameworkError(f"unable to read {label}: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise FrameworkError(f"{label} must be a JSON object")
    return value


def _verify_artifact_inventory(root: Path) -> None:
    inventory = root / "artifacts.sha256"
    if not inventory.is_file():
        raise FrameworkError(f"missing artifact inventory: {inventory}")
    for line in inventory.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, rel = line.split("  ", 1)
        path = root / rel
        if not path.is_file() or _sha256_file(path) != expected:
            raise FrameworkError(f"artifact inventory verification failed: {root.name}/{rel}")


def _discover_latest(root: Path, definition_sha: str, id_field: str, *, require_inventory: bool = True) -> tuple[Path, dict[str, Any]]:
    matches: list[tuple[Path, dict[str, Any]]] = []
    if not root.is_dir():
        raise FrameworkError(f"qualification root not found: {root}")
    for child in sorted(p for p in root.iterdir() if p.is_dir()):
        path = child / "processed" / "summary.json"
        if not path.is_file():
            continue
        summary = _read_json(path, "qualification summary")
        if summary.get("status") != "COMPLETE" or summary.get("definition_sha256") != definition_sha:
            continue
        if summary.get(id_field) != child.name:
            continue
        if require_inventory:
            _verify_artifact_inventory(child)
        matches.append((child, summary))
    if not matches:
        raise FrameworkError(f"no COMPLETE qualification with definition SHA {definition_sha} in {root}")
    return matches[-1]


def _resolve_inputs(definition: dict[str, Any], repo_root: Path) -> dict[str, Any]:
    inputs = definition["inputs"]
    net_def = load_network_evidence_definition(_resolve_repo_path(repo_root, inputs["network_evidence_config"], "network evidence config"))
    net_root, net_summary = _discover_latest(
        repo_root / "qualifications" / "network-evidence",
        network_evidence_definition_sha256(net_def),
        "evidence_id",
    )
    envelope_path = net_root / "processed" / "network-envelope.json"
    envelope = _read_json(envelope_path, "network envelope")
    if envelope.get("direction_semantic") != "dut-to-loadgen":
        raise FrameworkError("workload planner requires DUT-to-loadgen network evidence")

    load_def = load_loadgen_definition(_resolve_repo_path(repo_root, inputs["loadgen_runtime_config"], "loadgen runtime config"))
    load_root, load_summary = _discover_latest(
        repo_root / "qualifications" / "loadgen-runtime",
        loadgen_definition_sha256(load_def),
        "runtime_id",
        require_inventory=False,
    )
    runtime = load_summary.get("runtime", {})
    if runtime.get("http3_capable") is not True or not isinstance(runtime.get("h2load"), dict) or runtime["h2load"].get("http3_capable") is not True:
        raise FrameworkError("resolved load-generator runtime is not HTTP/3 capable")

    sec_def = load_transport_security_definition(_resolve_repo_path(repo_root, inputs["transport_security_config"], "transport security config"))
    sec_root, sec_summary = _discover_latest(
        repo_root / "qualifications" / "transport-security",
        transport_security_definition_sha256(sec_def),
        "qualification_id",
    )
    gate = _read_json(sec_root / "processed" / "security-gate.json", "transport security gate")
    if gate.get("passed") is not True:
        raise FrameworkError("transport-security gate is not PASS")
    if {row.get("variant") for row in gate.get("variants", []) if row.get("passed") is True} != {"stock", "ngi541-direct"}:
        raise FrameworkError("transport-security gate must have PASS for stock and ngi541-direct")

    tel_def = load_telemetry_definition(_resolve_repo_path(repo_root, inputs["dual_host_telemetry_config"], "dual-host telemetry config"))
    tel_root, tel_summary = _discover_latest(
        repo_root / "qualifications" / "telemetry",
        telemetry_definition_sha256(tel_def),
        "qualification_id",
    )
    capabilities = tel_summary.get("capabilities", {})
    if not capabilities.get("dut", {}).get("process_tree") or not capabilities.get("loadgen", {}).get("per_core_cpu"):
        raise FrameworkError("dual-host telemetry qualification is missing required planner capabilities")

    corpus_def = load_corpus_definition(_resolve_repo_path(repo_root, inputs["scientific_corpus_config"], "scientific corpus config"))
    corpus_result = run_scientific_corpus(
        corpus_def,
        repo_root=repo_root,
        output_root=repo_root / "corpora" / "scientific",
    )
    corpus_root = corpus_result["root"]
    manifests: dict[str, dict[str, Any]] = {}
    for profile in corpus_result["summary"]["profiles"]:
        pid = profile["profile_id"]
        manifests[pid] = _read_json(
            corpus_root / "processed" / "profiles" / f"{pid}-v{profile['profile_version']}.corpus.json",
            f"{pid} corpus manifest",
        )

    topology = envelope.get("topology", {})
    local = topology.get("local", {})
    remote = topology.get("remote", {})
    if local.get("system") != "Darwin" or remote.get("system") != "Linux":
        raise FrameworkError("R6.5.3g currently expects Darwin DUT and Linux load generator")

    return {
        "network": {"root": net_root, "summary": net_summary, "envelope": envelope, "sha256": _sha256_file(envelope_path)},
        "loadgen": {"root": load_root, "summary": load_summary, "definition": load_def, "sha256": _sha256_file(load_root / "processed" / "summary.json")},
        "security": {"root": sec_root, "summary": sec_summary, "definition": sec_def, "gate": gate, "sha256": _sha256_file(sec_root / "processed" / "security-gate.json")},
        "telemetry": {"root": tel_root, "summary": tel_summary, "definition": tel_def, "sha256": _sha256_file(tel_root / "processed" / "summary.json")},
        "corpus": {"root": corpus_root, "summary": corpus_result["summary"], "definition": corpus_def, "manifests": manifests, "sha256": _sha256_file(corpus_root / "processed" / "summary.json")},
        "dut_address": local.get("address"),
        "dut_interface": local.get("interface"),
        "loadgen_address": remote.get("address"),
        "loadgen_interface": remote.get("interface"),
        "ssh_target": load_def["remote"]["ssh_target"],
    }


def _physical_core_count() -> int:
    if os.uname().sysname == "Darwin":
        result = subprocess.run(["/usr/sbin/sysctl", "-n", "hw.physicalcpu"], check=False, text=True, capture_output=True)
        if result.returncode == 0:
            try:
                return _positive_int(int(result.stdout.strip()), "hw.physicalcpu")
            except (ValueError, FrameworkError):
                pass
    count = os.cpu_count() or 1
    return max(1, int(count))


def _materialize_calibration_objects(
    manifests: dict[str, dict[str, Any]],
    hacc_spec: dict[str, Any],
    *,
    root: Path,
    chunk_bytes: int,
) -> dict[str, Any]:
    root.mkdir(parents=True, exist_ok=True)
    profiles: dict[str, Any] = {}

    for profile_id in ("clas12-event-stream", "lcls-detector-frame"):
        manifest = manifests[profile_id]
        obj = stream_object_descriptor(manifest, 0)
        rel = Path(profile_id) / f"{obj['object_id']}.bin"
        path = root / rel
        result = materialize_surrogate(
            path,
            seed_u64=int(obj["content_seed_u64_hex"], 16),
            size_bytes=int(obj["size_bytes"]),
            chunk_bytes=chunk_bytes,
        )
        profiles[profile_id] = {
            "kind": "fixed-object",
            "objects": [{**obj, "relative_path": rel.as_posix(), "sha256": result["sha256"]}],
            "object_size_bytes": int(obj["size_bytes"]),
        }

    hacc_manifest = manifests["hacc-multifile-dataset"]
    selected = _hacc_calibration_objects(hacc_manifest, hacc_spec)
    rows: list[dict[str, Any]] = []
    for obj in selected:
        rel = Path("hacc-multifile-dataset") / f"{obj['object_id']}.bin"
        path = root / rel
        result = materialize_surrogate(
            path,
            seed_u64=int(obj["content_seed_u64_hex"], 16),
            size_bytes=int(obj["size_bytes"]),
            chunk_bytes=chunk_bytes,
        )
        rows.append({**obj, "relative_path": rel.as_posix(), "sha256": result["sha256"]})
    profiles["hacc-multifile-dataset"] = {
        "kind": "heterogeneous-calibration-subset",
        "objects": rows,
        "selected_logical_bytes": sum(int(row["size_bytes"]) for row in rows),
        "selector": {
            "kind": hacc_spec["selector"],
            "bucket_indices": list(hacc_spec["bucket_indices"]),
            "objects_per_bucket": int(hacc_spec["objects_per_bucket"]),
        },
        "not_a_full_dataset_claim": True,
    }
    return profiles


def _threads_for(connections: int, loadgen_cpus: int) -> int:
    return max(1, min(connections, loadgen_cpus))


def _build_h2load_command(
    *,
    h2load_binary: str,
    server_name: str,
    host: str,
    port: int,
    cipher_suite: str,
    ca_path: str,
    connections: int,
    max_streams: int,
    threads: int,
    warmup_seconds: float,
    measurement_seconds: float,
    target_goodput_mbps: float,
    profile: dict[str, Any],
    result_path: str,
    timing_script_path: str | None,
) -> list[str]:
    command = [
        "env", f"SSL_CERT_FILE={ca_path}", h2load_binary,
        "--h3",
        "--tls13-ciphers", cipher_suite,
        "--connect-to", f"{host}:{port}",
        "--sni", server_name,
        "--output-file", result_path,
        "--duration", f"{measurement_seconds:g}s",
        "--warm-up-time", f"{warmup_seconds:g}s",
        "-c", str(connections),
        "-m", str(max_streams),
        "-t", str(threads),
    ]
    base_uri = f"https://{server_name}:{port}"
    if profile["kind"] == "fixed-object":
        obj = profile["objects"][0]
        rate = per_client_rps(target_goodput_mbps, int(obj["size_bytes"]), connections)
        command += ["--rps", f"{rate:.9f}", f"{base_uri}/{obj['relative_path']}"]
    else:
        if not timing_script_path:
            raise FrameworkError("HACC probe requires timing script path")
        command += ["--timing-script-file", timing_script_path]
    return command


def _parse_remote_jsonl(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise FrameworkError(f"invalid remote telemetry JSONL: {exc}") from exc
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _remote_probe_script(command: list[str], *, sampler_path: str, interface: str, sample_count: int, interval_seconds: float, prefix: str) -> str:
    cmd = shlex.join(command)
    return (
        "set +e; "
        f"{cmd} > {shlex.quote(prefix + '.stdout')} 2> {shlex.quote(prefix + '.stderr')} & "
        "pid=$!; "
        f"python3 {shlex.quote(sampler_path)} {shlex.quote(interface)} \"$pid\" {sample_count} {interval_seconds:g} > {shlex.quote(prefix + '.telemetry.jsonl')} 2> {shlex.quote(prefix + '.telemetry.stderr')}; "
        "sampler_rc=$?; "
        "wait \"$pid\"; rc=$?; "
        f"printf '%s\\n' \"$rc\" > {shlex.quote(prefix + '.rc')}; "
        f"printf '%s\\n' \"$sampler_rc\" > {shlex.quote(prefix + '.sampler.rc')}; "
        "exit 0"
    )


def _run_probe(
    *,
    ssh: SSHSession,
    pm: DarwinPowermetricsTelemetry,
    nginx_pid: int,
    dut_interface: str,
    loadgen_interface: str,
    remote_root: str,
    remote_sampler: str,
    command: list[str],
    probe_name: str,
    policy: dict[str, Any],
    warmup_seconds: float,
    measurement_seconds: float,
    sample_interval_seconds: float,
    target_goodput_mbps: float,
    raw_dir: Path,
) -> dict[str, Any]:
    duration_total = warmup_seconds + measurement_seconds
    sample_count = max(4, int(math.ceil(duration_total / sample_interval_seconds)))
    prefix = f"{remote_root}/{probe_name}"
    script = _remote_probe_script(
        command,
        sampler_path=remote_sampler,
        interface=loadgen_interface,
        sample_count=sample_count,
        interval_seconds=sample_interval_seconds,
        prefix=prefix,
    )

    local_samples: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(ssh.run, ["bash", "-lc", script], check=True, timeout=duration_total + 30)
        for index in range(sample_count):
            local_samples.append(_local_sample(index, dut_interface, nginx_pid, pm))
            if index + 1 < sample_count:
                time.sleep(sample_interval_seconds)
        future.result()

    def remote_text(suffix: str) -> str:
        result = ssh.run(["cat", prefix + suffix], check=False, timeout=10)
        return result.stdout if result.returncode == 0 else ""

    rc_text = remote_text(".rc").strip()
    sampler_rc_text = remote_text(".sampler.rc").strip()
    stdout = remote_text(".stdout")
    stderr = remote_text(".stderr")
    telemetry_text = remote_text(".telemetry.jsonl")
    telemetry_stderr = remote_text(".telemetry.stderr")
    result_text = remote_text(".result.json")

    probe_dir = raw_dir / probe_name
    probe_dir.mkdir(parents=True, exist_ok=True)
    atomic_write_text(probe_dir / "h2load.stdout.log", stdout)
    atomic_write_text(probe_dir / "h2load.stderr.log", stderr)
    atomic_write_text(probe_dir / "loadgen-telemetry.jsonl", telemetry_text)
    atomic_write_text(probe_dir / "loadgen-telemetry.stderr.log", telemetry_stderr)
    atomic_write_text(
        probe_dir / "dut-telemetry.jsonl",
        "".join(json.dumps(sample, sort_keys=True, separators=(",", ":")) + "\n" for sample in local_samples),
    )
    atomic_write_text(probe_dir / "command.txt", shlex.join(command) + "\n")

    try:
        rc = int(rc_text)
        sampler_rc = int(sampler_rc_text)
    except ValueError as exc:
        raise FrameworkError(f"unable to parse remote probe exit codes for {probe_name}") from exc
    if sampler_rc != 0:
        raise FrameworkError(f"remote telemetry sampler failed for {probe_name}: rc={sampler_rc}")
    if rc != 0:
        return {
            "probe_id": probe_name,
            "h2load_exit_code": rc,
            "evaluation": {"passed": False, "reasons": ["h2load-exit-nonzero"]},
        }
    try:
        result_json = json.loads(result_text)
    except json.JSONDecodeError as exc:
        raise FrameworkError(f"invalid h2load output JSON for {probe_name}: {exc}") from exc
    atomic_write_json(probe_dir / "h2load-result.json", result_json)
    remote_samples = _parse_remote_jsonl(telemetry_text)
    h2 = parse_h2load_json(result_json, target_goodput_mbps=target_goodput_mbps)
    loadgen = summarize_loadgen_telemetry(remote_samples)
    dut = summarize_dut_telemetry(local_samples, int(h2["application_data_bytes"]))
    evaluation = evaluate_probe(h2, loadgen, dut, policy)
    return {
        "probe_id": probe_name,
        "h2load_exit_code": rc,
        "h2load": h2,
        "loadgen": loadgen,
        "dut": dut,
        "evaluation": evaluation,
    }


def _artifact_hashes(root: Path) -> str:
    rows = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.name != "artifacts.sha256"):
        rows.append(f"{_sha256_file(path)}  {path.relative_to(root).as_posix()}")
    content = "\n".join(rows) + "\n"
    atomic_write_text(root / "artifacts.sha256", content)
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _find_reusable(output_root: Path, definition_sha: str, input_sha: str) -> tuple[Path, dict[str, Any]] | None:
    if not output_root.is_dir():
        return None
    for child in sorted((p for p in output_root.iterdir() if p.is_dir()), reverse=True):
        summary_path = child / "processed" / "summary.json"
        if not summary_path.is_file():
            continue
        summary = _read_json(summary_path, "workload planner summary")
        if summary.get("status") != "COMPLETE":
            continue
        if summary.get("definition_sha256") == definition_sha and summary.get("resolved_input_sha256") == input_sha:
            _verify_artifact_inventory(child)
            return child, summary
    return None


def run_workload_planner(definition: dict[str, Any], *, repo_root: Path, output_root: Path) -> dict[str, Any]:
    validate_definition(definition)
    resolved = _resolve_inputs(definition, repo_root)
    planning = definition["planning"]
    envelope_mbps = float(resolved["network"]["envelope"]["service_envelope_mbps"])
    if envelope_mbps <= 0:
        raise FrameworkError("network service envelope must be > 0")

    physical_cores = _physical_core_count()
    def_sha = definition_sha256(definition)

    stock_spec = resolved["security"]["definition"]["variants"]["stock"]
    stock_binary = _resolve_repo_path(repo_root, stock_spec["binary"], "stock binary")
    stock_sha = _sha256_file(stock_binary)
    if stock_sha != stock_spec["sha256"]:
        raise FrameworkError("stock NGINX binary SHA-256 no longer matches transport-security definition")

    runtime = resolved["loadgen"]["summary"]["runtime"]
    h2load_binary = runtime["h2load"]["binary"]
    h2load_sha = runtime["h2load"]["sha256"]

    # Environment identity includes capacities that influence the final deterministic plan.
    with SSHSession(resolved["ssh_target"], int(resolved["loadgen"]["definition"]["remote"].get("connect_timeout_seconds", 10))) as identity_ssh:
        cpu_result = identity_ssh.run(["python3", "-c", "import os; print(os.cpu_count() or 1)"], check=True)
        try:
            loadgen_cpus = max(1, int(cpu_result.stdout.strip().splitlines()[-1]))
        except (ValueError, IndexError) as exc:
            raise FrameworkError("unable to resolve load-generator CPU count") from exc
        hash_result = identity_ssh.run(["sha256sum", h2load_binary], check=True)
        if hash_result.stdout.strip().split()[0] != h2load_sha:
            raise FrameworkError("remote h2load SHA-256 no longer matches R6.5.3b evidence")

    input_identity = {
        "definition_sha256": def_sha,
        "network_envelope_sha256": resolved["network"]["sha256"],
        "loadgen_summary_sha256": resolved["loadgen"]["sha256"],
        "transport_security_sha256": resolved["security"]["sha256"],
        "telemetry_summary_sha256": resolved["telemetry"]["sha256"],
        "scientific_corpus_summary_sha256": resolved["corpus"]["sha256"],
        "stock_binary_sha256": stock_sha,
        "h2load_sha256": h2load_sha,
        "dut_physical_cores": physical_cores,
        "loadgen_logical_cpus": loadgen_cpus,
    }
    input_sha = _semantic_sha256(input_identity)
    reusable = _find_reusable(output_root, def_sha, input_sha)
    if reusable is not None:
        root, summary = reusable
        plan = _read_json(root / "processed" / "workload-plan.json", "workload plan")
        return {"root": root, "summary": summary, "plan": plan, "reused": True}

    qid = f"{_slug(definition['qualification']['name'])}-{_utc_id_timestamp()}-{input_sha[:6]}"
    root = output_root / qid
    raw_dir = root / "raw"
    processed_dir = root / "processed"
    inputs_dir = root / "inputs"
    for path in (raw_dir, processed_dir, inputs_dir):
        path.mkdir(parents=True, exist_ok=True)
    atomic_write_json(root / "definition.json", definition)
    atomic_write_json(inputs_dir / "resolved-inputs.json", input_identity)

    manifests = resolved["corpus"]["manifests"]
    chunk_bytes = int(resolved["corpus"]["definition"]["materialization"]["chunk_bytes"])
    with tempfile.TemporaryDirectory(prefix="ngi541-r653g-") as temp_name:
        temp = Path(temp_name)
        object_root = temp / "objects"
        calibration_profiles = _materialize_calibration_objects(
            manifests,
            planning["hacc_calibration"],
            root=object_root,
            chunk_bytes=chunk_bytes,
        )
        corpus_identity = {
            "schema_version": 1,
            "profiles": calibration_profiles,
            "corpus_id": resolved["corpus"]["summary"]["corpus_id"],
            "note": "HACC objects form a bounded deterministic planner-calibration subset, not a full HACC dataset claim.",
        }
        atomic_write_json(processed_dir / "calibration-corpus.json", corpus_identity)

        server_cfg = resolved["security"]["definition"]["server"]
        transport = resolved["security"]["definition"]["transport"]
        server_name = server_cfg["name"]
        host = str(resolved["dut_address"])
        port = int(server_cfg["port"])
        openssl = shutil.which("openssl") or "/usr/bin/openssl"
        tls = _generate_tls_material(openssl=openssl, root=temp / "tls", server_name=server_name, host=host)
        env = _variant_environment(stock_spec, repo_root)

        probe_records: list[dict[str, Any]] = []
        selected_conditions: list[dict[str, Any]] = []
        workers_resolved = [1, physical_cores]

        remote_timeout = int(resolved["loadgen"]["definition"]["remote"].get("connect_timeout_seconds", 10))
        with SSHSession(resolved["ssh_target"], remote_timeout) as ssh:
            remote_root = f"/tmp/{qid}"
            ssh.run(["bash", "-lc", f"rm -rf {shlex.quote(remote_root)} && mkdir -p {shlex.quote(remote_root)}"], check=True)
            remote_ca = f"{remote_root}/ca.crt"
            remote_sampler = f"{remote_root}/telemetry_sampler.py"
            _write_remote_file_base64(ssh, remote_ca, tls["ca_crt"].read_bytes())
            _write_remote_file_base64(ssh, remote_sampler, REMOTE_SAMPLER.encode("utf-8"))

            pm_raw = raw_dir / "dut-powermetrics.log"
            with DarwinPowermetricsTelemetry(float(planning["probe"]["sample_interval_seconds"]), pm_raw) as pm:
                for workers in workers_resolved:
                    server_runtime = temp / "server" / f"workers-{workers}"
                    for rel in ("conf", "html", "logs"):
                        (server_runtime / rel).mkdir(parents=True, exist_ok=True)
                    for profile in calibration_profiles.values():
                        for obj in profile["objects"]:
                            source = object_root / obj["relative_path"]
                            destination = server_runtime / "html" / obj["relative_path"]
                            destination.parent.mkdir(parents=True, exist_ok=True)
                            try:
                                os.link(source, destination)
                            except OSError:
                                shutil.copy2(source, destination)
                    shutil.copy2(tls["server_crt"], server_runtime / "conf" / "server.crt")
                    shutil.copy2(tls["server_key"], server_runtime / "conf" / "server.key")
                    config = nginx_config(
                        host=host,
                        port=port,
                        workers=workers,
                        worker_connections=int(server_cfg.get("worker_connections", 4096)),
                        cipher_suite=transport["cipher_suite"],
                    ).replace("server_name ngi541-dut.local;", f"server_name {server_name};")
                    atomic_write_text(server_runtime / "conf" / "nginx.conf", config)

                    test = subprocess.run(
                        [str(stock_binary), "-p", str(server_runtime) + os.sep, "-c", "conf/nginx.conf", "-t"],
                        env=env,
                        check=False,
                        text=True,
                        capture_output=True,
                    )
                    if test.returncode != 0:
                        raise FrameworkError(f"stock NGINX configuration test failed for workers={workers}: {test.stderr}")
                    stdout_handle = (raw_dir / f"nginx-workers-{workers}.stdout.log").open("wb")
                    stderr_handle = (raw_dir / f"nginx-workers-{workers}.stderr.log").open("wb")
                    process = subprocess.Popen(
                        [str(stock_binary), "-p", str(server_runtime) + os.sep, "-c", "conf/nginx.conf", "-g", "daemon off;"],
                        env=env,
                        stdout=stdout_handle,
                        stderr=stderr_handle,
                        start_new_session=True,
                    )
                    try:
                        deadline = time.monotonic() + int(server_cfg.get("startup_timeout_seconds", 15))
                        while time.monotonic() < deadline:
                            if process.poll() is not None:
                                raise FrameworkError(f"stock NGINX exited during planner startup for workers={workers}")
                            # UDP listener startup is asynchronous; a short stable alive window is sufficient before first probe.
                            time.sleep(0.25)
                            if time.monotonic() + 0.5 < deadline:
                                break

                        for profile_id in ("clas12-event-stream", "lcls-detector-frame", "hacc-multifile-dataset"):
                            profile = calibration_profiles[profile_id]
                            for fraction in planning["service_target_fractions"]:
                                target = derive_target_goodput_mbps(envelope_mbps, float(fraction))
                                condition_probes: list[dict[str, Any]] = []
                                for candidate_index, candidate in enumerate(planning["concurrency_candidates"]):
                                    connections = int(candidate["connections"])
                                    max_streams = int(candidate["max_concurrent_streams_per_connection"])
                                    threads = _threads_for(connections, loadgen_cpus)
                                    condition_key = f"w{workers}-{profile_id}-s{int(round(float(fraction)*100)):02d}"
                                    probe_name = f"{condition_key}-c{connections}-m{max_streams}"
                                    result_path = f"{remote_root}/{probe_name}.result.json"
                                    timing_path: str | None = None
                                    if profile["kind"] == "heterogeneous-calibration-subset":
                                        object_paths = {str(obj["object_id"]): str(obj["relative_path"]) for obj in profile["objects"]}
                                        script = build_hacc_timing_script(
                                            profile["objects"],
                                            target_goodput_mbps=target,
                                            connections=connections,
                                            duration_seconds=float(planning["probe"]["warmup_seconds"]) + float(planning["probe"]["measurement_seconds"]),
                                            base_uri=f"https://{server_name}:{port}",
                                            object_paths=object_paths,
                                        )
                                        timing_path = f"{remote_root}/{probe_name}.timing.tsv"
                                        _write_remote_file_base64(ssh, timing_path, script.encode("utf-8"))
                                    command = _build_h2load_command(
                                        h2load_binary=h2load_binary,
                                        server_name=server_name,
                                        host=host,
                                        port=port,
                                        cipher_suite=transport["cipher_suite"],
                                        ca_path=remote_ca,
                                        connections=connections,
                                        max_streams=max_streams,
                                        threads=threads,
                                        warmup_seconds=float(planning["probe"]["warmup_seconds"]),
                                        measurement_seconds=float(planning["probe"]["measurement_seconds"]),
                                        target_goodput_mbps=target,
                                        profile=profile,
                                        result_path=result_path,
                                        timing_script_path=timing_path,
                                    )
                                    probe = _run_probe(
                                        ssh=ssh,
                                        pm=pm,
                                        nginx_pid=process.pid,
                                        dut_interface=resolved["dut_interface"],
                                        loadgen_interface=resolved["loadgen_interface"],
                                        remote_root=remote_root,
                                        remote_sampler=remote_sampler,
                                        command=command,
                                        probe_name=probe_name,
                                        policy=planning["probe"],
                                        warmup_seconds=float(planning["probe"]["warmup_seconds"]),
                                        measurement_seconds=float(planning["probe"]["measurement_seconds"]),
                                        sample_interval_seconds=float(planning["probe"]["sample_interval_seconds"]),
                                        target_goodput_mbps=target,
                                        raw_dir=raw_dir,
                                    )
                                    probe.update({
                                        "worker_processes": workers,
                                        "profile_id": profile_id,
                                        "service_fraction": float(fraction),
                                        "target_goodput_mbps": target,
                                        "candidate_index": candidate_index,
                                        "connections": connections,
                                        "max_concurrent_streams_per_connection": max_streams,
                                        "threads": threads,
                                        "pacing": "per-client-rps" if profile["kind"] == "fixed-object" else "deterministic-byte-timing-script",
                                    })
                                    condition_probes.append(probe)
                                    probe_records.append(probe)
                                    if probe.get("evaluation", {}).get("passed") is True:
                                        break

                                selected = select_first_passing_candidate(condition_probes)
                                selected_conditions.append({
                                    "condition_id": f"w{workers}-{profile_id}-s{int(round(float(fraction)*100)):02d}",
                                    "profile_id": profile_id,
                                    "worker_processes": workers,
                                    "worker_semantic": "single" if workers == 1 else "physical-core-count",
                                    "service_fraction": float(fraction),
                                    "target_goodput_mbps": target,
                                    "selected_probe_id": selected["probe_id"],
                                    "client": {
                                        "connections": selected["connections"],
                                        "max_concurrent_streams_per_connection": selected["max_concurrent_streams_per_connection"],
                                        "threads": selected["threads"],
                                    },
                                    "pacing": selected["pacing"],
                                    "calibration_observed": {
                                        "application_goodput_mbps": selected.get("h2load", {}).get("application_goodput_mbps"),
                                        "achieved_target_ratio": selected.get("h2load", {}).get("achieved_target_ratio"),
                                        "loadgen_max_total_cpu_busy_percent": selected.get("loadgen", {}).get("max_total_cpu_busy_percent"),
                                        "loadgen_max_single_core_busy_percent": selected.get("loadgen", {}).get("max_single_core_busy_percent"),
                                    },
                                })
                    finally:
                        _stop_server(process)
                        stdout_handle.close()
                        stderr_handle.close()

            ssh.run(["bash", "-lc", f"rm -rf {shlex.quote(remote_root)}"], check=False)

    probe_document = {
        "schema_version": 1,
        "calibration_variant": "stock",
        "probes": probe_records,
    }
    atomic_write_json(processed_dir / "probe-results.json", probe_document)

    plan_identity = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "plan_name": "r6.5.3g-stock-only-scientific-http3-workload-plan",
        "claim_scope": "frozen-workload-plan-no-performance-claim",
        "calibration_variant": "stock",
        "resolved_input_sha256": input_sha,
        "network": {
            "evidence_id": resolved["network"]["summary"]["evidence_id"],
            "service_envelope_mbps": envelope_mbps,
            "direction": "dut-to-loadgen",
            "service_target_fractions": list(planning["service_target_fractions"]),
        },
        "transport": {
            "protocol": "http3-only",
            "tls_version": "1.3",
            "cipher_suite": resolved["security"]["gate"]["cipher_suite"],
            "allow_0rtt": False,
        },
        "environment": {
            "dut_physical_cores": physical_cores,
            "loadgen_logical_cpus": loadgen_cpus,
        },
        "scientific_corpus": {
            "corpus_id": resolved["corpus"]["summary"]["corpus_id"],
            "hacc_planner_coverage": calibration_profiles["hacc-multifile-dataset"]["selector"],
            "hacc_planner_coverage_is_not_full_dataset": True,
        },
        "measurement": {
            "warmup_seconds": float(planning["final_measurement"]["warmup_seconds"]),
            "measurement_seconds": float(planning["final_measurement"]["measurement_seconds"]),
            "qlog": "disabled-by-default-performance-run",
            "h2load_json_quic_metrics": "required",
        },
        "conditions": sorted(selected_conditions, key=lambda row: row["condition_id"]),
        "planner_policy": {
            "strategy": "first-passing-staged-concurrency",
            "achieved_target_ratio_min": float(planning["probe"]["achieved_target_ratio_min"]),
            "loadgen_total_cpu_max_percent": float(planning["probe"]["loadgen_total_cpu_max_percent"]),
            "loadgen_core_cpu_max_percent": float(planning["probe"]["loadgen_core_cpu_max_percent"]),
            "candidate_order": list(planning["concurrency_candidates"]),
            "candidate_variant_bias_prohibited": True,
        },
    }
    plan_id = f"r6-5-3g-workload-plan-{_semantic_sha256(plan_identity)[:12]}"
    plan = {**plan_identity, "plan_id": plan_id}
    plan["plan_sha256"] = _semantic_sha256(plan)
    atomic_write_json(processed_dir / "workload-plan.json", plan)

    summary = {
        "schema_version": 1,
        "qualification_id": qid,
        "definition_sha256": def_sha,
        "resolved_input_sha256": input_sha,
        "status": "COMPLETE",
        "claim_scope": definition["qualification"]["claim_scope"],
        "plan_id": plan_id,
        "plan_sha256": plan["plan_sha256"],
        "calibration_variant": "stock",
        "service_envelope_mbps": envelope_mbps,
        "condition_count": len(selected_conditions),
        "probe_count": len(probe_records),
        "network_evidence_id": resolved["network"]["summary"]["evidence_id"],
        "loadgen_runtime_id": resolved["loadgen"]["summary"]["runtime_id"],
        "transport_security_id": resolved["security"]["summary"]["qualification_id"],
        "telemetry_qualification_id": resolved["telemetry"]["summary"]["qualification_id"],
        "scientific_corpus_id": resolved["corpus"]["summary"]["corpus_id"],
    }
    atomic_write_json(processed_dir / "summary.json", summary)
    atomic_write_text(
        processed_dir / "SUMMARY.md",
        "# R6.5.3g stock-only workload planner\n\n"
        f"- Qualification: `{qid}`\n"
        f"- Plan: `{plan_id}`\n"
        f"- Service envelope: {envelope_mbps:g} Mbit/s\n"
        f"- Conditions: {len(selected_conditions)}\n"
        f"- Probes: {len(probe_records)}\n"
        "- Calibration variant: stock only\n"
        "- Candidate NGI541 datapath participated in tuning: no\n"
        "- Status: COMPLETE\n",
    )
    _artifact_hashes(root)
    return {"root": root, "summary": summary, "plan": plan, "reused": False}
