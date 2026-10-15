from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shlex
import shutil
import statistics
import subprocess
import tempfile
import threading
import time
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from framework.dual_host_telemetry import (
    DarwinPowermetricsTelemetry,
    REMOTE_SAMPLER,
    _darwin_interface,
    _darwin_power_source,
    _darwin_process_tree,
)
from framework.host_state import _darwin_thermal
from framework.final_freeze import (
    _load_pinned_context,
    definition_sha256 as final_freeze_definition_sha256,
    load_definition as load_final_freeze_definition,
)
from framework.io_utils import FrameworkError, atomic_write_json, atomic_write_text
from framework.network_qualification import SSHSession
from framework.scientific_corpus import materialize_surrogate, stream_object_descriptor
from framework.transport_security import _generate_tls_material, _stop_server, _variant_environment, _write_remote_file_base64, nginx_config
from framework.workload_planner import (
    _build_h2load_command,
    _hacc_calibration_objects,
    _parse_remote_jsonl,
    _sha256_file,
    build_hacc_timing_script,
    summarize_loadgen_telemetry,
)

SCHEMA_VERSION = 1
CLAIM_SCOPE = "controlled-paired-scientific-http3-performance-execution"
MEASUREMENT_PROTOCOL_REVISION = "r6.5.4.5"
VARIANTS = ["stock", "ngi541-direct"]


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _semantic_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def definition_sha256(definition: dict[str, Any]) -> str:
    return _semantic_sha256(definition)


def _utc_id_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _slug(value: str) -> str:
    text = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if not text:
        raise FrameworkError("experiment.name must contain an alphanumeric character")
    return text


def _relative_path(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise FrameworkError(f"{field} must be a non-empty relative path")
    p = Path(value)
    if p.is_absolute() or ".." in p.parts:
        raise FrameworkError(f"{field} must be a portable repository-relative path")
    return value


def validate_definition(definition: dict[str, Any]) -> None:
    if not isinstance(definition, dict) or definition.get("schema_version") != SCHEMA_VERSION:
        raise FrameworkError("R6.5.4 definition requires schema_version=1")
    exp = definition.get("experiment")
    if not isinstance(exp, dict) or not isinstance(exp.get("name"), str) or not exp["name"]:
        raise FrameworkError("experiment.name is required")
    if exp.get("claim_scope") != CLAIM_SCOPE:
        raise FrameworkError(f"experiment.claim_scope must be {CLAIM_SCOPE!r}")
    inputs = definition.get("inputs")
    if not isinstance(inputs, dict):
        raise FrameworkError("inputs must be an object")
    _relative_path(inputs.get("final_freeze_config"), "inputs.final_freeze_config")
    execution = definition.get("execution")
    if not isinstance(execution, dict):
        raise FrameworkError("execution must be an object")
    if execution.get("measurement_protocol_revision") != MEASUREMENT_PROTOCOL_REVISION:
        raise FrameworkError(
            f"execution.measurement_protocol_revision must be {MEASUREMENT_PROTOCOL_REVISION!r}"
        )
    if execution.get("repetitions") != 4:
        raise FrameworkError("execution.repetitions must be exactly 4 for the frozen local paired design")
    if execution.get("comparison") != "paired-balanced":
        raise FrameworkError("execution.comparison must be paired-balanced")
    if execution.get("condition_order") != "rotating-rounds":
        raise FrameworkError("execution.condition_order must be rotating-rounds")
    if execution.get("variant_order") != "balanced-by-condition-round":
        raise FrameworkError("execution.variant_order must be balanced-by-condition-round")
    interval = execution.get("sample_interval_seconds")
    if isinstance(interval, bool) or not isinstance(interval, (int, float)) or float(interval) <= 0:
        raise FrameworkError("execution.sample_interval_seconds must be > 0")
    controls = execution.get("server_controls")
    if not isinstance(controls, dict):
        raise FrameworkError("execution.server_controls must be an object")
    keepalive_requests = controls.get("keepalive_requests")
    if isinstance(keepalive_requests, bool) or not isinstance(keepalive_requests, int) or keepalive_requests < 2000:
        raise FrameworkError("execution.server_controls.keepalive_requests must be an integer >= 2000")

    if controls.get("require_prestart_udp_bindable") is not True:
        raise FrameworkError(
            "execution.server_controls.require_prestart_udp_bindable must be true"
        )

    if controls.get("remote_http3_readiness") != "pinned-curl-single-request":
        raise FrameworkError(
            "execution.server_controls.remote_http3_readiness must be "
            "'pinned-curl-single-request'"
        )

    for key in (
        "startup_readiness_timeout_seconds",
        "shutdown_release_timeout_seconds",
    ):
        value = controls.get(key)

        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or float(value) <= 0
        ):
            raise FrameworkError(
                f"execution.server_controls.{key} must be > 0"
            )

    stable_seconds = controls.get(
        "prestart_udp_stable_seconds"
    )

    if (
        isinstance(stable_seconds, bool)
        or not isinstance(
            stable_seconds,
            (int, float),
        )
        or float(stable_seconds) <= 0
    ):
        raise FrameworkError(
            "execution.server_controls."
            "prestart_udp_stable_seconds "
            "must be > 0"
        )

    quiescence_timeout = controls.get(
        "prestart_quiescence_timeout_seconds"
    )

    if (
        isinstance(quiescence_timeout, bool)
        or not isinstance(
            quiescence_timeout,
            (int, float),
        )
        or float(quiescence_timeout) <= 0
    ):
        raise FrameworkError(
            "execution.server_controls."
            "prestart_quiescence_timeout_seconds "
            "must be > 0"
        )

    if (
        float(quiescence_timeout)
        < float(stable_seconds)
    ):
        raise FrameworkError(
            "execution.server_controls."
            "prestart_quiescence_timeout_seconds "
            "must be >= "
            "prestart_udp_stable_seconds"
        )

    telemetry = execution.get("telemetry")
    if not isinstance(telemetry, dict):
        raise FrameworkError("execution.telemetry must be an object")
    if telemetry.get("dut_sampling") != "nonblocking-window-v2":
        raise FrameworkError("execution.telemetry.dut_sampling must be nonblocking-window-v2")

    if (
        telemetry.get("measurement_window_selection")
        != "strict-main-no-tolerance"
    ):
        raise FrameworkError(
            "execution.telemetry.measurement_window_selection "
            "must be 'strict-main-no-tolerance'"
        )

    guard_interval = telemetry.get("thermal_guard_interval_seconds")
    if isinstance(guard_interval, bool) or not isinstance(guard_interval, (int, float)) or float(guard_interval) <= 0:
        raise FrameworkError("execution.telemetry.thermal_guard_interval_seconds must be > 0")
    hacc = execution.get("hacc_execution")
    if hacc != {"mode": "repeat-frozen-planner-subset", "not_a_full_dataset_claim": True}:
        raise FrameworkError("execution.hacc_execution must freeze the planner subset and disclaim a full dataset claim")
    validity = execution.get("validity")
    if not isinstance(validity, dict):
        raise FrameworkError("execution.validity must be an object")
    if validity.get("require_zero_http_failures") is not True or validity.get("require_no_throttling") is not True:
        raise FrameworkError("R6.5.4 requires zero HTTP failures and no throttling")
    for key in ("loadgen_total_cpu_max_percent", "loadgen_core_cpu_max_percent"):
        value = validity.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not (0 < float(value) <= 100):
            raise FrameworkError(f"execution.validity.{key} must be in (0,100]")
    if execution.get("retry_policy") != "no-metric-dependent-retry":
        raise FrameworkError("execution.retry_policy must prohibit metric-dependent retry")
    if execution.get("outlier_policy") != "retain-all-valid-runs":
        raise FrameworkError("execution.outlier_policy must retain all valid runs")
    analysis = definition.get("analysis")
    if not isinstance(analysis, dict):
        raise FrameworkError("analysis must be an object")
    if analysis.get("pairing") != "within-condition-within-repetition":
        raise FrameworkError("analysis.pairing must be within-condition-within-repetition")
    if analysis.get("summary_statistic") != "median-paired-delta":
        raise FrameworkError("analysis.summary_statistic must be median-paired-delta")


def load_definition(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FrameworkError(f"R6.5.4 config not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise FrameworkError(f"invalid R6.5.4 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise FrameworkError("R6.5.4 definition must be an object")
    validate_definition(value)
    return value


def build_paired_schedule(plan: dict[str, Any], repetitions: int = 4) -> list[dict[str, Any]]:
    conditions = sorted(plan.get("conditions", []), key=lambda row: row["condition_id"])
    if len(conditions) != 12:
        raise FrameworkError("frozen workload plan must contain exactly 12 conditions")
    if repetitions != 4:
        raise FrameworkError("paired schedule repetitions must be exactly 4")
    runs: list[dict[str, Any]] = []
    seq = 0
    pair_seq = 0
    n = len(conditions)
    for repetition in range(1, repetitions + 1):
        offset = (repetition - 1) % n
        order = list(range(n))[offset:] + list(range(n))[:offset]
        for position, condition_index in enumerate(order, start=1):
            condition = conditions[condition_index]
            pair_seq += 1
            variants = list(VARIANTS)
            if ((repetition - 1) + condition_index) % 2 == 1:
                variants.reverse()
            pair_id = f"pair-{pair_seq:04d}"
            pair_order = "/".join(variants)
            for pair_position, variant in enumerate(variants, start=1):
                seq += 1
                runs.append({
                    "sequence": seq,
                    "run_id": f"run-{seq:04d}",
                    "pair_id": pair_id,
                    "pair_order": pair_order,
                    "pair_position": pair_position,
                    "variant": variant,
                    "repetition": repetition,
                    "condition_position_in_round": position,
                    "condition": condition,
                })
    return runs


def validate_balanced_schedule(runs: list[dict[str, Any]]) -> None:
    by_condition: dict[str, list[dict[str, Any]]] = {}
    for run in runs:
        by_condition.setdefault(run["condition"]["condition_id"], []).append(run)
    if len(by_condition) != 12:
        raise FrameworkError("paired schedule must cover 12 conditions")
    for condition_id, rows in by_condition.items():
        if len(rows) != 8:
            raise FrameworkError(f"condition {condition_id} must have 8 variant runs")
        pairs: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            pairs.setdefault(row["pair_id"], []).append(row)
        if len(pairs) != 4:
            raise FrameworkError(f"condition {condition_id} must have 4 pairs")
        orders = [sorted(pair_rows, key=lambda r: r["pair_position"])[0]["variant"] for pair_rows in pairs.values()]
        if orders.count("stock") != 2 or orders.count("ngi541-direct") != 2:
            raise FrameworkError(f"condition {condition_id} must have 2 stock-first and 2 NGI541-first pairs")
        for pair_rows in pairs.values():
            if sorted(row["variant"] for row in pair_rows) != sorted(VARIANTS):
                raise FrameworkError(f"condition {condition_id} pair does not contain both variants")


def _verify_artifacts(root: Path) -> None:
    inventory = root / "artifacts.sha256"
    if not inventory.is_file():
        raise FrameworkError(f"missing artifact inventory: {inventory}")
    for line in inventory.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, rel = line.split("  ", 1)
        path = root / rel
        if not path.is_file() or _sha256_file(path) != expected:
            raise FrameworkError(f"artifact inventory mismatch: {root.name}/{rel}")


def _discover_final_freeze(config_path: Path, repo_root: Path) -> tuple[Path, dict[str, Any], dict[str, Any], dict[str, Any]]:
    definition = load_final_freeze_definition(config_path)
    def_sha = final_freeze_definition_sha256(definition)
    root_base = repo_root / "qualifications" / "final-freeze"
    matches: list[Path] = []
    if root_base.is_dir():
        for child in sorted(p for p in root_base.iterdir() if p.is_dir()):
            summary_path = child / "processed" / "summary.json"
            if not summary_path.is_file():
                continue
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            if summary.get("status") == "COMPLETE" and (child / "state.json").is_file():
                state = json.loads((child / "state.json").read_text(encoding="utf-8"))
                if state.get("definition_sha256") == def_sha and state.get("state") == "COMPLETE":
                    matches.append(child)
    if not matches:
        raise FrameworkError("no COMPLETE R6.5.3h final freeze matches the configured definition")
    root = matches[-1]
    _verify_artifacts(root)
    manifest = json.loads((root / "processed" / "final-manifest.json").read_text(encoding="utf-8"))
    identity = dict(manifest)
    stated = identity.pop("freeze_sha256", None)
    if _semantic_sha256(identity) != stated:
        raise FrameworkError("R6.5.3h final manifest semantic SHA mismatch")
    contract = manifest.get("r6_5_4_execution_contract", {})
    required_true = (
        "same_frozen_plan_for_all_variants",
        "adaptive_replanning_prohibited",
        "candidate_variant_tuning_prohibited",
        "metric_dependent_retry_prohibited",
        "metric_dependent_outlier_deletion_prohibited",
    )
    if contract.get("variants") != VARIANTS or any(contract.get(key) is not True for key in required_true):
        raise FrameworkError("R6.5.3h execution contract is not compatible with R6.5.4")
    resolved = json.loads((root / "inputs" / "resolved-inputs.json").read_text(encoding="utf-8"))
    context = _load_pinned_context(resolved, repo_root)
    return root, manifest, resolved, context


def _materialize_frozen_profiles(context: dict[str, Any], *, root: Path) -> dict[str, Any]:
    corpus_root = context["roots"]["scientific_corpus"]
    planner_def = context["definitions"]["workload_planner"]
    corpus_def = context["definitions"]["scientific_corpus"]
    chunk_bytes = int(corpus_def["materialization"]["chunk_bytes"])
    manifests: dict[str, dict[str, Any]] = {}
    for name in ("clas12-event-stream", "lcls-detector-frame", "hacc-multifile-dataset"):
        filename = {
            "clas12-event-stream": "clas12-event-stream-v1.corpus.json",
            "lcls-detector-frame": "lcls-detector-frame-v1.corpus.json",
            "hacc-multifile-dataset": "hacc-multifile-dataset-v1.corpus.json",
        }[name]
        manifests[name] = json.loads((corpus_root / "processed" / "profiles" / filename).read_text(encoding="utf-8"))
    profiles: dict[str, Any] = {}
    root.mkdir(parents=True, exist_ok=True)
    for profile_id in ("clas12-event-stream", "lcls-detector-frame"):
        obj = stream_object_descriptor(manifests[profile_id], 0)
        rel = Path(profile_id) / f"{obj['object_id']}.bin"
        result = materialize_surrogate(root / rel, seed_u64=int(obj["content_seed_u64_hex"], 16), size_bytes=int(obj["size_bytes"]), chunk_bytes=chunk_bytes)
        profiles[profile_id] = {"kind": "fixed-object", "objects": [{**obj, "relative_path": rel.as_posix(), "sha256": result["sha256"]}], "object_size_bytes": int(obj["size_bytes"])}
    hacc_spec = planner_def["planning"]["hacc_calibration"]
    selected = _hacc_calibration_objects(manifests["hacc-multifile-dataset"], hacc_spec)
    hacc_rows = []
    for obj in selected:
        rel = Path("hacc-multifile-dataset") / f"{obj['object_id']}.bin"
        result = materialize_surrogate(root / rel, seed_u64=int(obj["content_seed_u64_hex"], 16), size_bytes=int(obj["size_bytes"]), chunk_bytes=chunk_bytes)
        hacc_rows.append({**obj, "relative_path": rel.as_posix(), "sha256": result["sha256"]})
    profiles["hacc-multifile-dataset"] = {
        "kind": "heterogeneous-calibration-subset",
        "objects": hacc_rows,
        "selected_logical_bytes": sum(int(row["size_bytes"]) for row in hacc_rows),
        "selector": {"kind": hacc_spec["selector"], "bucket_indices": list(hacc_spec["bucket_indices"]), "objects_per_bucket": int(hacc_spec["objects_per_bucket"])},
        "not_a_full_dataset_claim": True,
    }
    return profiles


class _DarwinThermalGuard:
    """Collect Darwin performance-limit state without blocking 1 Hz DUT samples."""

    def __init__(self, interval_seconds: float):
        self.interval_seconds = max(1.0, float(interval_seconds))
        self._lock = threading.Lock()
        self._latest: dict[str, Any] = {}
        self._ever_throttled = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _sample_once(self) -> None:
        value = _darwin_thermal(os.cpu_count() or 1, None)
        with self._lock:
            self._latest = dict(value)
            if value.get("throttling_active") is True:
                self._ever_throttled = True

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            self._sample_once()

    def start(self) -> None:
        self._sample_once()
        with self._lock:
            known = self._latest.get("throttling_active")
        if known is None:
            raise FrameworkError("DUT throttling telemetry is unavailable before measurement")
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            result = dict(self._latest)
            ever = self._ever_throttled
        if ever:
            result["throttling_active"] = True
            result["performance_limit_active"] = True
        return result

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=12.0)
            self._thread = None

    def __enter__(self) -> "_DarwinThermalGuard":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()


def _performance_local_sample(
    index: int,
    interface: str,
    pid: int,
    pm: DarwinPowermetricsTelemetry,
    thermal_guard: _DarwinThermalGuard,
) -> dict[str, Any]:
    """R6.5.4 DUT sample using nonblocking/cached thermal state.

    System-wide `top -l 1` and synchronous `pmset -g therm` are intentionally
    excluded from the hot sampling path.  The former is not an R6.5.4 validity
    input; the latter is collected by `_DarwinThermalGuard`.
    """
    power = pm.snapshot()
    thermal = thermal_guard.snapshot()
    load = os.getloadavg()
    return {
        "schema_version": 1,
        "host_role": "dut",
        "sample_index": index,
        "wall_time_ns": time.time_ns(),
        "monotonic_ns": time.monotonic_ns(),
        "cpu": {
            "busy_percent": None,
            "per_core_busy_percent": None,
            "average_frequency_mhz": power.get("average_frequency_mhz"),
        },
        "thermal": {
            "temperature_c": power.get("temperature_c"),
            "thermal_pressure": power.get("thermal_pressure"),
            "fan_rpm": power.get("fan_rpm"),
            "throttling_active": thermal.get("throttling_active"),
            "performance_limit_active": thermal.get("performance_limit_active"),
            "cpu_speed_limit_percent": thermal.get("cpu_speed_limit_percent"),
            "sample_age_seconds": power.get("sample_age_seconds"),
        },
        "power": {
            "package_power_w_estimate": power.get("package_power_w_estimate"),
            "cpu_power_w_estimate": power.get("cpu_power_w_estimate"),
            "source": power.get("package_power_source"),
            "estimated": power.get("package_power_w_estimate") is not None,
            "sample_age_seconds": power.get("sample_age_seconds"),
        },
        "load": {"load_1m": load[0], "load_5m": load[1], "load_15m": load[2]},
        "network": _darwin_interface(interface),
        "udp": {"in_errors": None},
        "process": _darwin_process_tree(pid),
    }


def _window_samples(
    samples: list[dict[str, Any]],
    *,
    start_ns: int,
    end_ns: int,
    tolerance_ns: int = 0,
) -> list[dict[str, Any]]:
    return [
        row for row in samples
        if isinstance(row.get("monotonic_ns"), int)
        and start_ns - tolerance_ns <= int(row["monotonic_ns"]) <= end_ns + tolerance_ns
    ]


def _numeric_points(samples: list[dict[str, Any]], *path: str) -> list[tuple[int, float]]:
    points: list[tuple[int, float]] = []
    for sample in samples:
        stamp = sample.get("monotonic_ns")
        current: Any = sample
        for key in path:
            if not isinstance(current, dict):
                current = None
                break
            current = current.get(key)
        if isinstance(stamp, int) and isinstance(current, (int, float)) and not isinstance(current, bool):
            points.append((stamp, float(current)))
    return sorted(points)


def _interpolated_value(points: list[tuple[int, float]], stamp_ns: int) -> float | None:
    if not points or stamp_ns < points[0][0] or stamp_ns > points[-1][0]:
        return None
    for index, (stamp, value) in enumerate(points):
        if stamp == stamp_ns:
            return value
        if stamp > stamp_ns:
            p0, p1 = points[index - 1], (stamp, value)
            span = p1[0] - p0[0]
            if span <= 0:
                return None
            fraction = (stamp_ns - p0[0]) / span
            return p0[1] + (p1[1] - p0[1]) * fraction
    return points[-1][1]


def _integrate_points_window(points: list[tuple[int, float]], start_ns: int, end_ns: int) -> float | None:
    if end_ns <= start_ns:
        return None
    start_value = _interpolated_value(points, start_ns)
    end_value = _interpolated_value(points, end_ns)
    if start_value is None or end_value is None:
        return None
    clipped = [(start_ns, start_value)]
    clipped.extend((stamp, value) for stamp, value in points if start_ns < stamp < end_ns)
    clipped.append((end_ns, end_value))
    energy = 0.0
    for (t0, p0), (t1, p1) in zip(clipped, clipped[1:]):
        energy += ((p0 + p1) / 2.0) * ((t1 - t0) / 1e9)
    return energy


def _summarize_dut_exact_window(
    samples: list[dict[str, Any]],
    *,
    application_data_bytes: int,
    start_ns: int,
    end_ns: int,
) -> dict[str, Any]:
    process_points = _numeric_points(samples, "process", "cpu_seconds")
    power_points = _numeric_points(samples, "power", "package_power_w_estimate")
    process_start = _interpolated_value(process_points, start_ns)
    process_end = _interpolated_value(process_points, end_ns)
    process_delta = None
    if process_start is not None and process_end is not None:
        process_delta = max(0.0, process_end - process_start)
    energy = _integrate_points_window(power_points, start_ns, end_ns)
    gib = application_data_bytes / float(1024 ** 3) if application_data_bytes > 0 else 0.0
    in_window = _window_samples(samples, start_ns=start_ns, end_ns=end_ns, tolerance_ns=0)
    throttled = any(row.get("thermal", {}).get("throttling_active") is True for row in in_window)
    return {
        "throttling_active": throttled,
        "process_cpu_seconds_delta": process_delta,
        "process_cpu_seconds_per_gib": process_delta / gib if process_delta is not None and gib > 0 else None,
        "estimated_energy_j": energy,
        "estimated_energy_j_per_gib": energy / gib if energy is not None and gib > 0 else None,
        "sample_count": len(in_window),
        "window_seconds": (end_ns - start_ns) / 1e9,
        "boundary_covered": bool(
            process_points
            and process_points[0][0] <= start_ns
            and process_points[-1][0] >= end_ns
        ),
    }


def _parse_scientific_h2load_result(
    value: dict[str, Any],
    *,
    target_goodput_mbps: float,
    measurement_seconds: float,
    profile: dict[str, Any],
    hacc_main_sizes: list[int] | None = None,
) -> dict[str, Any]:
    # profile/hacc_main_sizes remain in the interface because the caller
    # freezes them, but byte accounting is now performed directly by the
    # patched h2load main-phase DATA counter.
    _ = profile
    _ = hacc_main_sizes

    try:
        measurements = value["measurements"]
        requests = measurements["requests"]
        statuses = measurements["status_codes"]
        traffic = measurements["traffic"]

        started = int(requests["started"])
        done = int(requests["done"])
        failed = int(requests["failed"])
        errored = int(requests["errored"])
        timeout = int(requests.get("timeout", 0))
        succeeded_reported = int(requests["succeeded"])

        status_2xx = int(statuses.get("2xx", 0))
        status_3xx = int(statuses.get("3xx", 0))
        status_4xx = int(statuses.get("4xx", 0))
        status_5xx = int(statuses.get("5xx", 0))

        main_body_bytes = int(traffic["data"])
        raw_total_bytes = int(traffic["total"])
    except (KeyError, TypeError, ValueError) as exc:
        raise FrameworkError(
            f"invalid h2load JSON result: {exc}"
        ) from exc

    if measurement_seconds <= 0:
        raise FrameworkError(
            "measurement_seconds must be > 0"
        )

    successful_statuses = status_2xx + status_3xx

    inflight_at_cutoff = max(
        0,
        started - done,
    )

    completed_failures = max(
        0,
        done - succeeded_reported,
    )

    phase_boundary_excess_successes = max(
        0,
        successful_statuses - started,
    )

    completion_excess = max(
        0,
        done - started,
    )

    succeeded_over_status = max(
        0,
        succeeded_reported - successful_statuses,
    )

    status_ahead_of_completed = max(
        0,
        successful_statuses - succeeded_reported,
    )

    unexplained_status_ahead = max(
        0,
        status_ahead_of_completed - inflight_at_cutoff,
    )

    reported_success_mismatch = (
        succeeded_reported != successful_statuses
    )

    inferred_unissued_failure_accounting = (
        (failed != 0 or errored != 0)
        and completed_failures == 0
    )

    accounting_anomaly = any((
        phase_boundary_excess_successes,
        completion_excess,
        succeeded_over_status,
        unexplained_status_ahead,
    ))

    application_data_bytes = main_body_bytes

    goodput = (
        application_data_bytes
        * 8.0
        / measurement_seconds
        / 1_000_000.0
    )

    ratio = (
        goodput / target_goodput_mbps
        if target_goodput_mbps > 0
        else None
    )

    performance = (
        measurements.get("performance")
        if isinstance(measurements.get("performance"), dict)
        else {}
    )

    return {
        "duration_seconds_total":
            float(measurements.get("duration", 0.0)),
        "measurement_seconds":
            measurement_seconds,

        "application_data_bytes":
            application_data_bytes,
        "application_goodput_mbps":
            goodput,
        "achieved_target_ratio":
            ratio,
        "scientific_byte_accounting":
            "h2load-main-phase-body-bytes",

        "requests_started":
            started,
        "requests_done":
            done,
        "requests_succeeded":
            successful_statuses,
        "requests_succeeded_reported":
            succeeded_reported,
        "requests_failed":
            failed,
        "requests_errored":
            errored,
        "requests_timeout":
            timeout,

        "requests_inflight_at_cutoff":
            inflight_at_cutoff,
        "requests_completed_failures":
            completed_failures,

        "status_2xx":
            status_2xx,
        "status_3xx":
            status_3xx,
        "status_4xx":
            status_4xx,
        "status_5xx":
            status_5xx,

        "h2load_accounting_anomaly":
            accounting_anomaly,
        "h2load_phase_boundary_excess_successes":
            phase_boundary_excess_successes,
        "h2load_completion_excess":
            completion_excess,
        "h2load_unexplained_status_ahead":
            unexplained_status_ahead,
        "h2load_reported_success_mismatch":
            reported_success_mismatch,
        "h2load_inferred_unissued_failure_accounting":
            inferred_unissued_failure_accounting,

        "raw_traffic_data_bytes":
            main_body_bytes,
        "raw_traffic_total_bytes":
            raw_total_bytes,

        "request_per_second":
            measurements.get("request_per_second"),
        "bytes_per_second_total":
            measurements.get("bytes_per_second"),
        "udp_datagram":
            measurements.get("udp_datagram"),
        "performance":
            performance,
    }


def _hacc_main_window_sizes(
    profile: dict[str, Any],
    *,
    target_goodput_mbps: float,
    connections: int,
    warmup_seconds: float,
    measurement_seconds: float,
) -> list[int]:
    if connections != 1:
        raise FrameworkError("R6.5.4 local HACC exact accounting requires the frozen one-client plan")
    objects = profile["objects"]
    per_client_bytes_per_second = target_goodput_mbps * 1_000_000.0 / 8.0 / connections
    if per_client_bytes_per_second <= 0:
        raise FrameworkError("HACC target byte rate must be > 0")
    sizes: list[int] = []
    offset_seconds = 0.000001
    index = 0
    end_seconds = warmup_seconds + measurement_seconds
    while offset_seconds < end_seconds:
        obj = objects[index % len(objects)]
        size = int(obj["size_bytes"])
        if warmup_seconds <= offset_seconds < end_seconds:
            sizes.append(size)
        offset_seconds += size / per_client_bytes_per_second
        index += 1
        if index > 10_000_000:
            raise FrameworkError("HACC main-window accounting exceeded safety bound")
    return sizes


def _required_keepalive_requests(
    profile: dict[str, Any],
    *,
    target_goodput_mbps: float,
    connections: int,
    warmup_seconds: float,
    measurement_seconds: float,
) -> int:
    total_seconds = warmup_seconds + measurement_seconds
    if profile["kind"] == "fixed-object":
        aggregate_rps = target_goodput_mbps * 1_000_000.0 / 8.0 / int(profile["object_size_bytes"])
        per_client = aggregate_rps / connections
        return int(math.ceil(per_client * total_seconds)) + 16
    sizes = _hacc_main_window_sizes(
        profile,
        target_goodput_mbps=target_goodput_mbps,
        connections=connections,
        warmup_seconds=0.0,
        measurement_seconds=total_seconds,
    )
    return len(sizes) + 16

def _measurement_slice(samples: list[dict[str, Any]], warmup_seconds: float) -> list[dict[str, Any]]:
    if not samples:
        return []
    start = samples[0].get("monotonic_ns")
    if not isinstance(start, int):
        # Deterministic fallback for unit fixtures without clocks.
        index = min(len(samples) - 1, max(0, int(math.ceil(warmup_seconds))))
        return samples[index:]
    threshold = start + int(warmup_seconds * 1_000_000_000)
    rows = [row for row in samples if isinstance(row.get("monotonic_ns"), int) and int(row["monotonic_ns"]) >= threshold]
    return rows if len(rows) >= 2 else samples[-2:]


def telemetry_integrity_reasons(local_samples: list[dict[str, Any]], remote_samples: list[dict[str, Any]]) -> list[str]:
    reasons: list[str] = []
    if len(local_samples) < 2 or len(remote_samples) < 2:
        return ["telemetry-window-too-short"]
    if any(sample.get("process") is None for sample in local_samples):
        reasons.append("dut-process-telemetry-incomplete")
    if any(sample.get("thermal", {}).get("throttling_active") is None for sample in local_samples):
        reasons.append("dut-throttling-telemetry-incomplete")
    if any(sample.get("thermal", {}).get("temperature_c") is None for sample in local_samples):
        reasons.append("dut-temperature-telemetry-incomplete")
    usable_remote_cpu = [sample for sample in remote_samples if isinstance(sample.get("cpu", {}).get("busy_percent"), (int, float))]
    if len(usable_remote_cpu) < max(1, len(remote_samples) - 1):
        reasons.append("loadgen-cpu-telemetry-incomplete")
    if any(not isinstance(sample.get("cpu", {}).get("per_core_busy_percent"), list) for sample in remote_samples):
        reasons.append("loadgen-per-core-telemetry-incomplete")
    if any(sample.get("thermal", {}).get("throttling_active") is None for sample in remote_samples):
        reasons.append("loadgen-throttling-telemetry-incomplete")
    if any(sample.get("thermal", {}).get("temperature_c") is None for sample in remote_samples):
        reasons.append("loadgen-temperature-telemetry-incomplete")
    if any(sample.get("process") is None for sample in remote_samples):
        reasons.append("loadgen-process-telemetry-incomplete")
    if any(sample.get("udp", {}).get("in_errors") is None for sample in remote_samples):
        reasons.append("loadgen-udp-telemetry-incomplete")
    return sorted(set(reasons))

def _udp_bind_probe(
    host: str,
    port: int,
) -> dict[str, Any]:
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
    )

    try:
        sock.bind(
            (
                host,
                port,
            )
        )

        return {
            "bindable": True,
            "host": host,
            "port": port,
            "errno": None,
            "error": None,
        }

    except OSError as exc:
        return {
            "bindable": False,
            "host": host,
            "port": port,
            "errno": exc.errno,
            "error": str(exc),
        }

    finally:
        sock.close()


def _wait_udp_bindable(
    host: str,
    port: int,
    *,
    timeout_seconds: float,
    poll_interval_seconds: float = 0.1,
) -> dict[str, Any]:
    started = time.monotonic()
    attempts = 0

    while True:
        attempts += 1

        probe = _udp_bind_probe(
            host,
            port,
        )

        elapsed = (
            time.monotonic()
            - started
        )

        if probe["bindable"]:
            return {
                **probe,
                "released": True,
                "attempts": attempts,
                "elapsed_seconds": elapsed,
            }

        if elapsed >= timeout_seconds:
            return {
                **probe,
                "released": False,
                "attempts": attempts,
                "elapsed_seconds": elapsed,
            }

        time.sleep(
            poll_interval_seconds
        )


def _wait_udp_stably_bindable(
    host: str,
    port: int,
    *,
    timeout_seconds: float,
    stable_seconds: float,
    poll_interval_seconds: float = 0.1,
) -> dict[str, Any]:
    started = time.monotonic()
    stable_started: float | None = None
    attempts = 0

    while True:
        attempts += 1

        probe = _udp_bind_probe(
            host,
            port,
        )

        now = time.monotonic()

        elapsed = (
            now
            - started
        )

        if probe["bindable"]:
            if stable_started is None:
                stable_started = now

            stable_elapsed = (
                now
                - stable_started
            )

            if stable_elapsed >= stable_seconds:
                return {
                    **probe,
                    "stable_bindable": True,
                    "attempts": attempts,
                    "elapsed_seconds": elapsed,
                    "stable_required_seconds":
                        stable_seconds,
                    "stable_observed_seconds":
                        stable_elapsed,
                }

        else:
            stable_started = None
            stable_elapsed = 0.0

        if elapsed >= timeout_seconds:
            return {
                **probe,
                "stable_bindable": False,
                "attempts": attempts,
                "elapsed_seconds": elapsed,
                "stable_required_seconds":
                    stable_seconds,
                "stable_observed_seconds":
                    (
                        0.0
                        if stable_started is None
                        else now - stable_started
                    ),
            }

        time.sleep(
            poll_interval_seconds
        )


def _remote_http3_readiness(
    *,
    ssh: SSHSession,
    process: subprocess.Popen[Any],
    curl_binary: str,
    server_name: str,
    host: str,
    port: int,
    ca_path: str,
    cipher_suite: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    started = time.monotonic()
    attempts: list[dict[str, Any]] = []

    command = [
        curl_binary,
        "--http3-only",
        "--tls13-ciphers",
        cipher_suite,
        "--connect-to",
        (
            f"{server_name}:{port}:"
            f"{host}:{port}"
        ),
        "--cacert",
        ca_path,
        "--silent",
        "--show-error",
        "--fail",
        "--output",
        "/dev/null",
        "--connect-timeout",
        "1",
        "--max-time",
        "2",
        (
            f"https://{server_name}:{port}/"
            "__ngi541_ready.txt"
        ),
    ]

    while True:
        exit_code = process.poll()

        if exit_code is not None:
            return {
                "passed": False,
                "reason": "server-exited-before-readiness",
                "server_exit_code": exit_code,
                "attempts": attempts,
                "elapsed_seconds": (
                    time.monotonic()
                    - started
                ),
            }

        result = ssh.run(
            command,
            check=False,
            timeout=3,
        )

        attempts.append({
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        })

        if result.returncode == 0:
            return {
                "passed": True,
                "reason": None,
                "server_exit_code": None,
                "attempts": attempts,
                "elapsed_seconds": (
                    time.monotonic()
                    - started
                ),
            }

        elapsed = (
            time.monotonic()
            - started
        )

        if elapsed >= timeout_seconds:
            return {
                "passed": False,
                "reason": "remote-http3-readiness-timeout",
                "server_exit_code": process.poll(),
                "attempts": attempts,
                "elapsed_seconds": elapsed,
            }

        time.sleep(0.25)

def evaluate_measurement_validity(h2: dict[str, Any], loadgen: dict[str, Any], dut: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    started = int(
        h2.get(
            "requests_started",
            0,
        )
    )

    application_data_bytes = int(
        h2.get(
            "application_data_bytes",
            0,
        )
    )

    if started <= 0:
        reasons.append(
            "no-measurement-traffic"
        )

    if application_data_bytes <= 0:
        reasons.append(
            "no-application-data"
        )
    if policy.get("require_zero_http_failures") is True:
        if int(h2.get("requests_timeout", 0)) != 0:
            reasons.append(
                "http-request-timeout"
            )

        if (
            int(h2.get("status_4xx", 0)) != 0
            or int(h2.get("status_5xx", 0)) != 0
        ):
            reasons.append(
                "http-status-failure"
            )

        if int(
            h2.get(
                "requests_completed_failures",
                0,
            )
        ) != 0:
            reasons.append(
                "http-request-failure"
            )

        phase_boundary_excess = int(
            h2.get(
                "h2load_phase_boundary_excess_successes",
                max(
                    0,
                    int(h2.get("requests_succeeded", 0))
                    - int(h2.get("requests_started", 0)),
                ),
            )
        )

        if phase_boundary_excess != 0:
            reasons.append(
                "h2load-phase-boundary-accounting"
            )

        if (
            h2.get("h2load_accounting_anomaly") is True
            and phase_boundary_excess == 0
        ):
            reasons.append(
                "h2load-accounting-anomaly"
            )

    total = loadgen.get("max_total_cpu_busy_percent")
    core = loadgen.get("max_single_core_busy_percent")
    if not isinstance(total, (int, float)):
        reasons.append("loadgen-total-cpu-unavailable")
    elif float(total) >= float(policy["loadgen_total_cpu_max_percent"]):
        reasons.append("loadgen-total-cpu-headroom")
    if not isinstance(core, (int, float)):
        reasons.append("loadgen-core-cpu-unavailable")
    elif float(core) >= float(policy["loadgen_core_cpu_max_percent"]):
        reasons.append("loadgen-single-core-headroom")
    if policy.get("require_no_throttling") is True:
        if loadgen.get("firmware_throttling_active") is True:
            reasons.append("loadgen-firmware-throttling")
        if dut.get("throttling_active") is True:
            reasons.append("dut-throttling")
    # Deliberately do NOT gate on achieved_target_ratio. A slower candidate is a
    # performance result after plan freeze, not a reason to retry or discard.
    return {"valid": not reasons, "reasons": reasons}


def _remote_run_script(command: list[str], sampler_path: str, interface: str, sample_count: int, interval: float, prefix: str) -> str:
    cmd = shlex.join(command)
    return (
        "set +e; "
        f"{cmd} > {shlex.quote(prefix + '.stdout')} 2> {shlex.quote(prefix + '.stderr')} & pid=$!; "
        f"python3 {shlex.quote(sampler_path)} {shlex.quote(interface)} \"$pid\" {sample_count} {interval:g} > {shlex.quote(prefix + '.telemetry.jsonl')} 2> {shlex.quote(prefix + '.telemetry.stderr')}; sampler_rc=$?; "
        "wait \"$pid\"; rc=$?; "
        f"printf '%s\\n' \"$rc\" > {shlex.quote(prefix + '.rc')}; printf '%s\\n' \"$sampler_rc\" > {shlex.quote(prefix + '.sampler.rc')}; exit 0"
    )


def _run_measurement(
    *,
    ssh: SSHSession,
    pm: DarwinPowermetricsTelemetry,
    nginx_pid: int,
    dut_interface: str,
    loadgen_interface: str,
    remote_sampler: str,
    command: list[str],
    run_id: str,
    warmup_seconds: float,
    measurement_seconds: float,
    interval: float,
    target_goodput_mbps: float,
    validity_policy: dict[str, Any],
    raw_dir: Path,
    profile: dict[str, Any],
    hacc_main_sizes: list[int] | None,
    thermal_guard_interval_seconds: float,
) -> dict[str, Any]:
    total_duration = warmup_seconds + measurement_seconds
    sample_count = max(4, int(math.ceil(total_duration / interval)))
    prefix = f"/tmp/ngi541-r654/{run_id}"
    script = _remote_run_script(command, remote_sampler, loadgen_interface, sample_count, interval, prefix)
    local_samples: list[dict[str, Any]] = []

    # Anchor the local measurement window immediately before dispatching the
    # remote command.  On this LAN the dispatch uncertainty is sub-second and,
    # unlike the old fixed-count sampler, cannot stretch the DUT window beyond
    # the actual h2load process lifetime.
    with _DarwinThermalGuard(thermal_guard_interval_seconds) as thermal_guard:
        launch_ns = time.monotonic_ns()
        next_sample_ns = launch_ns
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(ssh.run, ["bash", "-lc", script], check=True, timeout=total_duration + 45)
            idx = 0
            while not future.done():
                now_ns = time.monotonic_ns()
                if now_ns < next_sample_ns:
                    time.sleep(min((next_sample_ns - now_ns) / 1e9, 0.05))
                    continue
                local_samples.append(
                    _performance_local_sample(idx, dut_interface, nginx_pid, pm, thermal_guard)
                )
                idx += 1
                next_sample_ns = launch_ns + int(idx * interval * 1e9)
            future.result()
            # One post-completion sample is required so cumulative process CPU
            # and power can bracket/interpolate the exact main-window end.
            local_samples.append(
                _performance_local_sample(idx, dut_interface, nginx_pid, pm, thermal_guard)
            )

    def remote_text(suffix: str) -> str:
        result = ssh.run(["cat", prefix + suffix], check=False, timeout=10)
        return result.stdout if result.returncode == 0 else ""

    run_raw = raw_dir / run_id
    run_raw.mkdir(parents=True, exist_ok=True)
    stdout, stderr = remote_text(".stdout"), remote_text(".stderr")
    telemetry_text, telemetry_stderr = remote_text(".telemetry.jsonl"), remote_text(".telemetry.stderr")
    result_text = remote_text(".result.json")
    atomic_write_text(run_raw / "h2load.stdout.log", stdout)
    atomic_write_text(run_raw / "h2load.stderr.log", stderr)
    atomic_write_text(run_raw / "loadgen-telemetry.jsonl", telemetry_text)
    atomic_write_text(run_raw / "loadgen-telemetry.stderr.log", telemetry_stderr)
    atomic_write_text(run_raw / "dut-telemetry.jsonl", "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in local_samples))
    atomic_write_text(run_raw / "command.txt", shlex.join(command) + "\n")
    try:
        rc = int(remote_text(".rc").strip())
        sampler_rc = int(remote_text(".sampler.rc").strip())
    except ValueError as exc:
        raise FrameworkError(f"unable to parse remote exit codes for {run_id}") from exc
    if sampler_rc != 0:
        raise FrameworkError(f"remote telemetry sampler failed for {run_id}: rc={sampler_rc}")
    if rc != 0:
        raise FrameworkError(f"h2load failed for {run_id}: rc={rc}; no automatic retry is permitted")
    try:
        result_json = json.loads(result_text)
    except json.JSONDecodeError as exc:
        raise FrameworkError(f"invalid h2load JSON for {run_id}: {exc}") from exc
    atomic_write_json(run_raw / "h2load-result.json", result_json)

    remote_all = _parse_remote_jsonl(telemetry_text)
    main_start_ns = launch_ns + int(warmup_seconds * 1e9)
    main_end_ns = launch_ns + int(total_duration * 1e9)

    # R6.5.4.5 integrity and load-generator summaries use only samples whose
    # timestamps are inside the declared MAIN interval.  Warm-up and
    # post-completion samples must never affect validity or load-generator CPU
    # metrics.
    local_measurement = _window_samples(
        local_samples,
        start_ns=main_start_ns,
        end_ns=main_end_ns,
    )

    # Remote monotonic clocks are independent of the DUT.  The first Pi sample
    # is the remote launch anchor.  Selection is deliberately strict:
    # [MAIN start, MAIN end], with no tolerance on either boundary.
    remote_measurement: list[dict[str, Any]] = []

    if (
        remote_all
        and isinstance(
            remote_all[0].get("monotonic_ns"),
            int,
        )
    ):
        remote_start_ns = int(
            remote_all[0]["monotonic_ns"]
        )

        remote_measurement = _window_samples(
            remote_all,
            start_ns=(
                remote_start_ns
                + int(warmup_seconds * 1e9)
            ),
            end_ns=(
                remote_start_ns
                + int(total_duration * 1e9)
            ),
        )

    h2 = _parse_scientific_h2load_result(
        result_json,
        target_goodput_mbps=target_goodput_mbps,
        measurement_seconds=measurement_seconds,
        profile=profile,
        hacc_main_sizes=hacc_main_sizes,
    )
    loadgen = summarize_loadgen_telemetry(remote_measurement)
    dut = _summarize_dut_exact_window(
        local_samples,
        application_data_bytes=int(h2["application_data_bytes"]),
        start_ns=main_start_ns,
        end_ns=main_end_ns,
    )
    validity = evaluate_measurement_validity(h2, loadgen, dut, validity_policy)
    integrity = telemetry_integrity_reasons(local_measurement, remote_measurement)
    if dut.get("boundary_covered") is not True:
        integrity.append("dut-exact-window-boundary-uncovered")
    if integrity:
        validity = {"valid": False, "reasons": sorted(set(validity["reasons"] + integrity))}

    first_local = local_samples[0].get("monotonic_ns") if local_samples else None
    last_local = local_samples[-1].get("monotonic_ns") if local_samples else None
    local_span = None
    if isinstance(first_local, int) and isinstance(last_local, int):
        local_span = (last_local - first_local) / 1e9
    return {
        "h2load": h2,
        "loadgen": loadgen,
        "dut": dut,
        "validity": validity,
        "telemetry_window": {
            "warmup_seconds": warmup_seconds,
            "measurement_seconds": measurement_seconds,
            "dut_samples": len(local_measurement),
            "loadgen_samples": len(remote_measurement),
            "dut_sampling_span_seconds": local_span,
            "dut_sampling_protocol": "nonblocking-window-v2",
            "measurement_window_selection": "strict-main-no-tolerance",
            "dut_exact_window_boundary_covered": dut.get("boundary_covered"),
        },
    }


def paired_delta_percent(stock: float, ngi: float, *, higher_is_better: bool) -> float:
    if stock == 0:
        raise FrameworkError("cannot compute paired percent delta with zero stock baseline")
    if higher_is_better:
        return (ngi - stock) / stock * 100.0
    return (stock - ngi) / stock * 100.0


def analyze_paired_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    pairs: dict[tuple[str, int], dict[str, dict[str, Any]]] = {}
    for row in results:
        key = (row["condition_id"], int(row["repetition"]))
        pairs.setdefault(key, {})[row["variant"]] = row
    pair_rows: list[dict[str, Any]] = []
    by_condition: dict[str, list[dict[str, Any]]] = {}
    for (condition_id, repetition), variants in sorted(pairs.items()):
        if set(variants) != set(VARIANTS):
            raise FrameworkError(f"incomplete pair for {condition_id} repetition {repetition}")
        stock, ngi = variants["stock"], variants["ngi541-direct"]
        metric_defs = [
            ("application_goodput_mbps", True),
            ("dut_process_cpu_seconds_per_gib", False),
            ("dut_estimated_energy_j_per_gib", False),
        ]
        deltas: dict[str, float | None] = {}
        for metric, higher in metric_defs:
            sv, nv = stock["metrics"].get(metric), ngi["metrics"].get(metric)
            if isinstance(sv, (int, float)) and isinstance(nv, (int, float)) and float(sv) != 0.0:
                deltas[metric] = paired_delta_percent(float(sv), float(nv), higher_is_better=higher)
            else:
                deltas[metric] = None
        first_variant = stock["pair_order"].split("/")[0]
        pair = {"condition_id": condition_id, "repetition": repetition, "pair_id": stock["pair_id"], "first_variant": first_variant, "delta_percent_positive_favors_ngi541": deltas}
        pair_rows.append(pair)
        by_condition.setdefault(condition_id, []).append(pair)
    summaries = []
    for condition_id, rows in sorted(by_condition.items()):
        metrics: dict[str, Any] = {}
        for metric in ("application_goodput_mbps", "dut_process_cpu_seconds_per_gib", "dut_estimated_energy_j_per_gib"):
            vals = [row["delta_percent_positive_favors_ngi541"][metric] for row in rows if isinstance(row["delta_percent_positive_favors_ngi541"][metric], (int, float))]
            metrics[metric] = {
                "pair_count": len(vals),
                "median_delta_percent": statistics.median(vals) if vals else None,
                "ngi541_pair_wins": sum(1 for value in vals if value > 0),
                "stock_pair_wins": sum(1 for value in vals if value < 0),
                "ties": sum(1 for value in vals if value == 0),
            }
        summaries.append({"condition_id": condition_id, "metrics": metrics})
    return {"schema_version": 1, "pair_count": len(pair_rows), "pairs": pair_rows, "conditions": summaries, "outlier_deletion": "none", "interpretation": "positive paired delta favors ngi541-direct"}


def _write_inventory(root: Path) -> str:
    rows = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.name != "artifacts.sha256"):
        rows.append(f"{_sha256_file(path)}  {path.relative_to(root).as_posix()}")
    content = "\n".join(rows) + "\n"
    atomic_write_text(root / "artifacts.sha256", content)
    return hashlib.sha256(content.encode("utf-8")).hexdigest()




def _find_incomplete_execution(output_root: Path, definition_sha: str, input_sha: str) -> Path | None:
    if not output_root.is_dir():
        return None
    matches: list[Path] = []
    for child in sorted((p for p in output_root.iterdir() if p.is_dir()), reverse=True):
        definition_path = child / "definition.json"
        inputs_path = child / "inputs" / "frozen-inputs.json"
        summary_path = child / "processed" / "summary.json"
        if not definition_path.is_file() or not inputs_path.is_file():
            continue
        try:
            frozen_definition = json.loads(definition_path.read_text(encoding="utf-8"))
            frozen_inputs = json.loads(inputs_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if definition_sha256(frozen_definition) != definition_sha or frozen_inputs.get("resolved_execution_input_sha256") != input_sha:
            continue
        if summary_path.is_file():
            try:
                if json.loads(summary_path.read_text(encoding="utf-8")).get("status") == "COMPLETE":
                    continue
            except json.JSONDecodeError:
                pass
        matches.append(child)
    if len(matches) > 1:
        raise FrameworkError("multiple incomplete R6.5.4 executions match the same frozen inputs")
    return matches[0] if matches else None


def _load_completed_run(root: Path, run_id: str) -> dict[str, Any] | None:
    path = root / "raw" / run_id / "run-result.json"
    if not path.is_file():
        return None
    try:
        row = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise FrameworkError(f"existing run result is malformed: {run_id}") from exc
    if row.get("run_id") != run_id:
        raise FrameworkError(f"existing run result identity mismatch: {run_id}")
    if row.get("validity", {}).get("valid") is not True:
        raise FrameworkError(f"existing run {run_id} is invalid; R6.5.4 prohibits result-dependent retry")
    return row

def run_paired_execution(definition: dict[str, Any], *, repo_root: Path, output_root: Path) -> dict[str, Any]:
    validate_definition(definition)
    freeze_config = (repo_root / definition["inputs"]["final_freeze_config"]).resolve()
    freeze_root, freeze_manifest, frozen_inputs, context = _discover_final_freeze(freeze_config, repo_root)
    plan_root = context["roots"]["workload_planner"]
    plan = json.loads((plan_root / "processed" / "workload-plan.json").read_text(encoding="utf-8"))
    contract = freeze_manifest["r6_5_4_execution_contract"]
    if plan.get("plan_id") != contract.get("workload_plan_id") or plan.get("plan_sha256") != contract.get("workload_plan_sha256"):
        raise FrameworkError("workload plan no longer matches the R6.5.3h frozen execution contract")
    schedule = build_paired_schedule(plan, int(definition["execution"]["repetitions"]))
    validate_balanced_schedule(schedule)
    identity = {
        "definition_sha256": definition_sha256(definition),
        "freeze_id": freeze_root.name,
        "freeze_sha256": freeze_manifest["freeze_sha256"],
        "workload_plan_id": plan["plan_id"],
        "workload_plan_sha256": plan["plan_sha256"],
        "schedule_sha256": _semantic_sha256(schedule),
    }
    input_sha = _semantic_sha256(identity)
    identity["resolved_execution_input_sha256"] = input_sha
    output_root.mkdir(parents=True, exist_ok=True)
    incomplete = _find_incomplete_execution(output_root, definition_sha256(definition), input_sha)
    resumed = incomplete is not None
    if incomplete is not None:
        root = incomplete
        experiment_id = root.name
    else:
        experiment_id = f"{_slug(definition['experiment']['name'])}-{_utc_id_timestamp()}-{input_sha[:6]}"
        root = output_root / experiment_id
    raw_dir, processed_dir, inputs_dir = root / "raw", root / "processed", root / "inputs"
    for p in (raw_dir, processed_dir, inputs_dir):
        p.mkdir(parents=True, exist_ok=True)
    if not (root / "definition.json").is_file():
        atomic_write_json(root / "definition.json", definition)
    if not (inputs_dir / "frozen-inputs.json").is_file():
        atomic_write_json(inputs_dir / "frozen-inputs.json", identity)
    if not (processed_dir / "schedule.json").is_file():
        atomic_write_json(processed_dir / "schedule.json", {"schema_version": 1, "run_count": len(schedule), "pair_count": len(schedule)//2, "runs": schedule})

    network = json.loads((context["roots"]["network_evidence"] / "processed" / "network-envelope.json").read_text(encoding="utf-8"))
    topology = network["topology"]
    dut_interface = topology["local"]["interface"]
    loadgen_interface = topology["remote"]["interface"]
    loadgen_def = context["definitions"]["loadgen_runtime"]
    loadgen_summary = json.loads((context["roots"]["loadgen_runtime"] / "processed" / "summary.json").read_text(encoding="utf-8"))
    ssh_target = loadgen_def["remote"]["ssh_target"]
    h2load_binary = loadgen_summary["runtime"]["h2load"]["binary"]
    h2load_sha = loadgen_summary["runtime"]["h2load"]["sha256"]
    curl_binary = loadgen_summary["runtime"]["curl_binary"]
    curl_sha = loadgen_summary["runtime"]["curl_sha256"]
    security_def = context["definitions"]["transport_security"]
    planner_def = context["definitions"]["workload_planner"]
    server_cfg = security_def["server"]
    transport = security_def["transport"]
    host = str(topology["local"]["address"])
    server_name = server_cfg["name"]
    port = int(server_cfg["port"])
    warmup = float(plan["measurement"]["warmup_seconds"])
    measurement = float(plan["measurement"]["measurement_seconds"])
    interval = float(definition["execution"]["sample_interval_seconds"])
    keepalive_requests = int(definition["execution"]["server_controls"]["keepalive_requests"])
    thermal_guard_interval = float(definition["execution"]["telemetry"]["thermal_guard_interval_seconds"])

    telemetry_definition = context["definitions"]["dual_host_telemetry"]
    if telemetry_definition.get("dut", {}).get("require_ac_power") is True:
        power_source = _darwin_power_source()
        if power_source != "ac":
            raise FrameworkError(f"R6.5.4 DUT must remain on AC power; current source={power_source}")

    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="ngi541-r654-") as temp_name:
        temp = Path(temp_name)
        profiles = _materialize_frozen_profiles(context, root=temp / "objects")
        # Global, variant-independent protocol preflight.  The configured NGINX
        # request-per-connection cap must exceed the maximum number of requests
        # any frozen client can schedule across warm-up + measurement.
        keepalive_requirements: dict[str, int] = {}
        for condition in plan["conditions"]:
            client = condition["client"]
            required = _required_keepalive_requests(
                profiles[condition["profile_id"]],
                target_goodput_mbps=float(condition["target_goodput_mbps"]),
                connections=int(client["connections"]),
                warmup_seconds=warmup,
                measurement_seconds=measurement,
            )
            keepalive_requirements[condition["condition_id"]] = required
            if keepalive_requests < required:
                raise FrameworkError(
                    f"server keepalive_requests={keepalive_requests} is below frozen requirement "
                    f"{required} for {condition['condition_id']}"
                )
        openssl = shutil.which("openssl") or "/usr/bin/openssl"
        tls = _generate_tls_material(openssl=openssl, root=temp / "tls", server_name=server_name, host=host)
        remote_timeout = int(loadgen_def["remote"].get("connect_timeout_seconds", 10))
        with SSHSession(ssh_target, remote_timeout) as ssh:
            check = ssh.run(
                ["sha256sum", h2load_binary],
                check=True,
            )

            if check.stdout.strip().split()[0] != h2load_sha:
                raise FrameworkError(
                    "remote h2load SHA-256 changed after final freeze"
                )

            check = ssh.run(
                ["sha256sum", curl_binary],
                check=True,
            )

            if check.stdout.strip().split()[0] != curl_sha:
                raise FrameworkError(
                    "remote curl SHA-256 changed after final freeze"
                )

            ssh.run(
                [
                    "bash",
                    "-lc",
                    "rm -rf /tmp/ngi541-r654 && "
                    "mkdir -p /tmp/ngi541-r654",
                ],
                check=True,
            )
            remote_ca = "/tmp/ngi541-r654/ca.crt"
            remote_sampler = "/tmp/ngi541-r654/telemetry_sampler.py"
            _write_remote_file_base64(ssh, remote_ca, tls["ca_crt"].read_bytes())
            _write_remote_file_base64(ssh, remote_sampler, REMOTE_SAMPLER.encode("utf-8"))
            with DarwinPowermetricsTelemetry(interval, raw_dir / "dut-powermetrics.log") as pm:
                for scheduled in schedule:
                    condition = scheduled["condition"]
                    variant = scheduled["variant"]
                    run_id = scheduled["run_id"]
                    completed = _load_completed_run(root, run_id)
                    if completed is not None:
                        results.append(completed)
                        continue
                    variant_spec = security_def["variants"][variant]
                    binary = (repo_root / variant_spec["binary"]).resolve()
                    if _sha256_file(binary) != variant_spec["sha256"]:
                        raise FrameworkError(f"{variant} NGINX binary SHA-256 changed after final freeze")
                    env = _variant_environment(variant_spec, repo_root)
                    runtime = temp / "server" / run_id
                    for rel in ("conf", "html", "logs"):
                        (runtime / rel).mkdir(parents=True, exist_ok=True)
                    profile = profiles[condition["profile_id"]]
                    for obj in profile["objects"]:
                        source = temp / "objects" / obj["relative_path"]
                        dest = runtime / "html" / obj["relative_path"]
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        try:
                            os.link(source, dest)
                        except OSError:
                            shutil.copy2(source, dest)
                    shutil.copy2(
                        tls["server_crt"],
                        runtime / "conf" / "server.crt",
                    )

                    shutil.copy2(
                        tls["server_key"],
                        runtime / "conf" / "server.key",
                    )

                    atomic_write_text(
                        runtime / "html" / "__ngi541_ready.txt",
                        "ngi541-ready\n",
                    )

                    cfg = nginx_config(
                        host=host,
                        port=port,
                        workers=int(condition["worker_processes"]),
                        worker_connections=int(
                            server_cfg.get("worker_connections", 4096)
                        ),
                        cipher_suite=transport["cipher_suite"],
                    ).replace(
                        "server_name ngi541-dut.local;",
                        f"server_name {server_name};",
                    )
                    marker = "        http3 on;"
                    if marker not in cfg:
                        raise FrameworkError(
                            "unable to inject R6.5.4.5 "
                            "keepalive_requests into NGINX config"
                        )
                    cfg = cfg.replace(marker, f"        keepalive_requests {keepalive_requests};\n\n{marker}", 1)
                    atomic_write_text(runtime / "conf" / "nginx.conf", cfg)
                    test = subprocess.run([str(binary), "-p", str(runtime) + os.sep, "-c", "conf/nginx.conf", "-t"], env=env, check=False, text=True, capture_output=True)
                    if test.returncode != 0:
                        raise FrameworkError(f"{variant} NGINX config test failed for {run_id}: {test.stderr}")
                    run_raw = raw_dir / run_id
                    run_raw.mkdir(
                        parents=True,
                        exist_ok=True,
                    )

                    prestart = _wait_udp_stably_bindable(
                        host,
                        port,
                        timeout_seconds=float(
                            definition["execution"]
                            ["server_controls"]
                            ["prestart_quiescence_timeout_seconds"]
                        ),
                        stable_seconds=float(
                            definition["execution"]
                            ["server_controls"]
                            ["prestart_udp_stable_seconds"]
                        ),
                    )

                    atomic_write_json(
                        run_raw / "server-prestart-port.json",
                        prestart,
                    )

                    if prestart["stable_bindable"] is not True:
                        raise FrameworkError(
                            f"UDP endpoint {host}:{port} "
                            f"did not reach stable pre-start "
                            f"quiescence before {run_id}: "
                            f"{prestart}"
                        )

                    out_handle = (
                        raw_dir / f"{run_id}-nginx.stdout.log"
                    ).open(
                        "w",
                        encoding="utf-8",
                    )

                    err_handle = (
                        raw_dir / f"{run_id}-nginx.stderr.log"
                    ).open(
                        "w",
                        encoding="utf-8",
                    )

                    process = subprocess.Popen(
                        [
                            str(binary),
                            "-p",
                            str(runtime) + os.sep,
                            "-c",
                            "conf/nginx.conf",
                            "-g",
                            "daemon off;",
                        ],
                        env=env,
                        stdout=out_handle,
                        stderr=err_handle,
                        start_new_session=True,
                    )

                    release: dict[str, Any] | None = None

                    try:
                        readiness = _remote_http3_readiness(
                            ssh=ssh,
                            process=process,
                            curl_binary=curl_binary,
                            server_name=server_name,
                            host=host,
                            port=port,
                            ca_path=remote_ca,
                            cipher_suite=transport["cipher_suite"],
                            timeout_seconds=float(
                                definition["execution"]
                                ["server_controls"]
                                ["startup_readiness_timeout_seconds"]
                            ),
                        )

                        atomic_write_json(
                            run_raw / "server-readiness.json",
                            readiness,
                        )

                        if readiness["passed"] is not True:
                            raise FrameworkError(
                                f"{variant} NGINX failed HTTP/3 "
                                f"readiness for {run_id}: "
                                f"{readiness['reason']}"
                            )

                        client = condition["client"]
                        result_path = f"/tmp/ngi541-r654/{run_id}.result.json"
                        timing_path = None
                        hacc_main_sizes = None
                        if profile["kind"] != "fixed-object":
                            object_paths = {str(obj["object_id"]): str(obj["relative_path"]) for obj in profile["objects"]}
                            script = build_hacc_timing_script(profile["objects"], target_goodput_mbps=float(condition["target_goodput_mbps"]), connections=int(client["connections"]), duration_seconds=warmup + measurement, base_uri=f"https://{server_name}:{port}", object_paths=object_paths)
                            timing_path = f"/tmp/ngi541-r654/{run_id}.timing.tsv"
                            _write_remote_file_base64(ssh, timing_path, script.encode("utf-8"))
                            hacc_main_sizes = _hacc_main_window_sizes(
                                profile,
                                target_goodput_mbps=float(condition["target_goodput_mbps"]),
                                connections=int(client["connections"]),
                                warmup_seconds=warmup,
                                measurement_seconds=measurement,
                            )
                        command = _build_h2load_command(h2load_binary=h2load_binary, server_name=server_name, host=host, port=port, cipher_suite=transport["cipher_suite"], ca_path=remote_ca, connections=int(client["connections"]), max_streams=int(client["max_concurrent_streams_per_connection"]), threads=int(client["threads"]), warmup_seconds=warmup, measurement_seconds=measurement, target_goodput_mbps=float(condition["target_goodput_mbps"]), profile=profile, result_path=result_path, timing_script_path=timing_path)
                        measurement_result = _run_measurement(
                            ssh=ssh, pm=pm, nginx_pid=process.pid, dut_interface=dut_interface,
                            loadgen_interface=loadgen_interface, remote_sampler=remote_sampler, command=command,
                            run_id=run_id, warmup_seconds=warmup, measurement_seconds=measurement, interval=interval,
                            target_goodput_mbps=float(condition["target_goodput_mbps"]),
                            validity_policy=definition["execution"]["validity"], raw_dir=raw_dir,
                            profile=profile, hacc_main_sizes=hacc_main_sizes,
                            thermal_guard_interval_seconds=thermal_guard_interval,
                        )
                        h2, dut, loadgen = measurement_result["h2load"], measurement_result["dut"], measurement_result["loadgen"]
                        row = {
                            "schema_version": 1,
                            "measurement_protocol_revision": MEASUREMENT_PROTOCOL_REVISION,
                            "run_id": run_id,
                            "sequence": scheduled["sequence"],
                            "pair_id": scheduled["pair_id"],
                            "pair_order": scheduled["pair_order"],
                            "pair_position": scheduled["pair_position"],
                            "repetition": scheduled["repetition"],
                            "condition_id": condition["condition_id"],
                            "variant": variant,
                            "metrics": {
                                "application_goodput_mbps": h2.get("application_goodput_mbps"),
                                "achieved_target_ratio": h2.get("achieved_target_ratio"),
                                "dut_process_cpu_seconds_per_gib": dut.get("process_cpu_seconds_per_gib"),
                                "dut_estimated_energy_j_per_gib": dut.get("estimated_energy_j_per_gib"),
                                "loadgen_max_total_cpu_busy_percent": loadgen.get("max_total_cpu_busy_percent"),
                                "loadgen_max_single_core_busy_percent": loadgen.get("max_single_core_busy_percent"),
                                "udp_in_errors_delta": loadgen.get("udp_in_errors_delta"),
                            },
                            "diagnostics": {
                                "scientific_byte_accounting": h2.get("scientific_byte_accounting"),
                                "h2load_accounting_anomaly": h2.get("h2load_accounting_anomaly"),
                                "requests_started": h2.get("requests_started"),
                                "successful_http_statuses": h2.get("requests_succeeded"),
                                "raw_traffic_data_bytes": h2.get("raw_traffic_data_bytes"),
                                "main_wire_bytes": h2.get("main_wire_bytes"),
                                "required_keepalive_requests": keepalive_requirements[condition["condition_id"]],
                                "configured_keepalive_requests": keepalive_requests,
                            },
                            "validity": measurement_result["validity"],
                            "telemetry_window": measurement_result["telemetry_window"],
                        }
                        atomic_write_json(raw_dir / run_id / "run-result.json", row)
                        results.append(row)
                        if row["validity"]["valid"] is not True:
                            raise FrameworkError(f"run {run_id} failed frozen validity gates: {row['validity']['reasons']}; no automatic retry is permitted")
                    finally:
                        _stop_server(process)

                        out_handle.close()
                        err_handle.close()

                        release = _wait_udp_bindable(
                            host,
                            port,
                            timeout_seconds=float(
                                definition["execution"]
                                ["server_controls"]
                                ["shutdown_release_timeout_seconds"]
                            ),
                        )

                        atomic_write_json(
                            run_raw / "server-release.json",
                            release,
                        )

                    if (
                        release is None
                        or release["released"] is not True
                    ):
                        raise FrameworkError(
                            f"UDP endpoint {host}:{port} "
                            f"was not released after {run_id}: "
                            f"{release}"
                        )

            ssh.run(
                [
                    "bash",
                    "-lc",
                    "rm -rf /tmp/ngi541-r654",
                ],
                check=False,
            )

    results.sort(key=lambda row: int(row["sequence"]))
    atomic_write_json(processed_dir / "run-results.json", {"schema_version": 1, "run_count": len(results), "runs": results})
    analysis = analyze_paired_results(results)
    atomic_write_json(processed_dir / "paired-analysis.json", analysis)
    summary = {
        "schema_version": 1,
        "experiment_id": experiment_id,
        "status": "COMPLETE",
        "measurement_protocol_revision": MEASUREMENT_PROTOCOL_REVISION,
        "server_keepalive_requests": keepalive_requests,
        "prestart_udp_stable_seconds": float(
            definition["execution"]
            ["server_controls"]
            ["prestart_udp_stable_seconds"]
        ),
        "prestart_quiescence_timeout_seconds": float(
            definition["execution"]
            ["server_controls"]
            ["prestart_quiescence_timeout_seconds"]
        ),
        "startup_readiness_timeout_seconds": float(
            definition["execution"]
            ["server_controls"]
            ["startup_readiness_timeout_seconds"]
        ),
        "shutdown_release_timeout_seconds": float(
            definition["execution"]
            ["server_controls"]
            ["shutdown_release_timeout_seconds"]
        ),
        "scientific_byte_accounting": "h2load-main-phase-body-bytes",
        "measurement_window_selection": "strict-main-no-tolerance",
        "claim_scope": CLAIM_SCOPE,
        "freeze_id": freeze_root.name,
        "freeze_sha256": freeze_manifest["freeze_sha256"],
        "workload_plan_id": plan["plan_id"],
        "workload_plan_sha256": plan["plan_sha256"],
        "condition_count": 12,
        "pair_count": len(schedule) // 2,
        "run_count": len(results),
        "repetitions": 4,
        "variants": VARIANTS,
        "adaptive_replanning": "prohibited",
        "metric_dependent_retry": "prohibited",
        "outlier_deletion": "none",
        "hacc_scope": "repeated-frozen-planner-subset-not-full-dataset",
        "resumed": resumed,
    }
    atomic_write_json(processed_dir / "summary.json", summary)
    atomic_write_text(processed_dir / "SUMMARY.md", f"# R6.5.4.5 controlled paired scientific execution\n\n- Experiment: `{experiment_id}`\n- Final freeze: `{freeze_root.name}`\n- Workload plan: `{plan['plan_id']}`\n- Conditions: 12\n- Repetitions: 4 paired repetitions per condition\n- Pairs: {len(schedule)//2}\n- Variant runs: {len(results)}\n- Measurement protocol: `{MEASUREMENT_PROTOCOL_REVISION}`\n- NGINX `keepalive_requests`: {keepalive_requests}\n- Scientific byte accounting: main-window frozen scientific bytes\n- DUT telemetry: nonblocking window with exact-boundary CPU/energy integration\n- Adaptive replanning: prohibited\n- Metric-dependent retry: prohibited\n- Outlier deletion: none\n- HACC local scope: repeated frozen planner subset, not full-dataset transfer\n- Status: COMPLETE\n")
    _write_inventory(root)
    return {"root": root, "summary": summary, "analysis": analysis}
