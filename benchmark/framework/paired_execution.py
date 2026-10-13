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
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from framework.dual_host_telemetry import DarwinPowermetricsTelemetry, REMOTE_SAMPLER, _darwin_power_source, _local_sample
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
    parse_h2load_json,
    summarize_dut_telemetry,
    summarize_loadgen_telemetry,
)

SCHEMA_VERSION = 1
CLAIM_SCOPE = "controlled-paired-scientific-http3-performance-execution"
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


def evaluate_measurement_validity(h2: dict[str, Any], loadgen: dict[str, Any], dut: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    if policy.get("require_zero_http_failures") is True:
        if any(int(h2.get(key, 0)) != 0 for key in ("requests_failed", "requests_errored", "requests_timeout")):
            reasons.append("http-request-failure")
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


def _run_measurement(*, ssh: SSHSession, pm: DarwinPowermetricsTelemetry, nginx_pid: int, dut_interface: str, loadgen_interface: str, remote_sampler: str, command: list[str], run_id: str, warmup_seconds: float, measurement_seconds: float, interval: float, target_goodput_mbps: float, validity_policy: dict[str, Any], raw_dir: Path) -> dict[str, Any]:
    total_duration = warmup_seconds + measurement_seconds
    sample_count = max(4, int(math.ceil(total_duration / interval)))
    prefix = f"/tmp/ngi541-r654/{run_id}"
    script = _remote_run_script(command, remote_sampler, loadgen_interface, sample_count, interval, prefix)
    local_samples: list[dict[str, Any]] = []
    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(ssh.run, ["bash", "-lc", script], check=True, timeout=total_duration + 45)
        for idx in range(sample_count):
            local_samples.append(_local_sample(idx, dut_interface, nginx_pid, pm))
            target = start + (idx + 1) * interval
            if idx + 1 < sample_count and target > time.monotonic():
                time.sleep(target - time.monotonic())
        future.result()

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
    local_measurement = _measurement_slice(local_samples, warmup_seconds)
    remote_measurement = _measurement_slice(remote_all, warmup_seconds)
    h2 = parse_h2load_json(result_json, target_goodput_mbps=target_goodput_mbps)
    loadgen = summarize_loadgen_telemetry(remote_measurement)
    dut = summarize_dut_telemetry(local_measurement, int(h2["application_data_bytes"]))
    validity = evaluate_measurement_validity(h2, loadgen, dut, validity_policy)
    integrity = telemetry_integrity_reasons(local_measurement, remote_measurement)
    if integrity:
        validity = {"valid": False, "reasons": sorted(set(validity["reasons"] + integrity))}
    return {"h2load": h2, "loadgen": loadgen, "dut": dut, "validity": validity, "telemetry_window": {"warmup_seconds": warmup_seconds, "measurement_seconds": measurement_seconds, "dut_samples": len(local_measurement), "loadgen_samples": len(remote_measurement)}}


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

    telemetry_definition = context["definitions"]["dual_host_telemetry"]
    if telemetry_definition.get("dut", {}).get("require_ac_power") is True:
        power_source = _darwin_power_source()
        if power_source != "ac":
            raise FrameworkError(f"R6.5.4 DUT must remain on AC power; current source={power_source}")

    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="ngi541-r654-") as temp_name:
        temp = Path(temp_name)
        profiles = _materialize_frozen_profiles(context, root=temp / "objects")
        openssl = shutil.which("openssl") or "/usr/bin/openssl"
        tls = _generate_tls_material(openssl=openssl, root=temp / "tls", server_name=server_name, host=host)
        remote_timeout = int(loadgen_def["remote"].get("connect_timeout_seconds", 10))
        with SSHSession(ssh_target, remote_timeout) as ssh:
            check = ssh.run(["sha256sum", h2load_binary], check=True)
            if check.stdout.strip().split()[0] != h2load_sha:
                raise FrameworkError("remote h2load SHA-256 changed after final freeze")
            ssh.run(["bash", "-lc", "rm -rf /tmp/ngi541-r654 && mkdir -p /tmp/ngi541-r654"], check=True)
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
                    shutil.copy2(tls["server_crt"], runtime / "conf" / "server.crt")
                    shutil.copy2(tls["server_key"], runtime / "conf" / "server.key")
                    cfg = nginx_config(host=host, port=port, workers=int(condition["worker_processes"]), worker_connections=int(server_cfg.get("worker_connections", 4096)), cipher_suite=transport["cipher_suite"]).replace("server_name ngi541-dut.local;", f"server_name {server_name};")
                    atomic_write_text(runtime / "conf" / "nginx.conf", cfg)
                    test = subprocess.run([str(binary), "-p", str(runtime) + os.sep, "-c", "conf/nginx.conf", "-t"], env=env, check=False, text=True, capture_output=True)
                    if test.returncode != 0:
                        raise FrameworkError(f"{variant} NGINX config test failed for {run_id}: {test.stderr}")
                    out_handle = (raw_dir / f"{run_id}-nginx.stdout.log").open("w", encoding="utf-8")
                    err_handle = (raw_dir / f"{run_id}-nginx.stderr.log").open("w", encoding="utf-8")
                    process = subprocess.Popen([str(binary), "-p", str(runtime) + os.sep, "-c", "conf/nginx.conf", "-g", "daemon off;"], env=env, stdout=out_handle, stderr=err_handle, start_new_session=True)
                    try:
                        time.sleep(0.5)
                        if process.poll() is not None:
                            raise FrameworkError(f"{variant} NGINX exited during startup for {run_id}")
                        client = condition["client"]
                        result_path = f"/tmp/ngi541-r654/{run_id}.result.json"
                        timing_path = None
                        if profile["kind"] != "fixed-object":
                            object_paths = {str(obj["object_id"]): str(obj["relative_path"]) for obj in profile["objects"]}
                            script = build_hacc_timing_script(profile["objects"], target_goodput_mbps=float(condition["target_goodput_mbps"]), connections=int(client["connections"]), duration_seconds=warmup + measurement, base_uri=f"https://{server_name}:{port}", object_paths=object_paths)
                            timing_path = f"/tmp/ngi541-r654/{run_id}.timing.tsv"
                            _write_remote_file_base64(ssh, timing_path, script.encode("utf-8"))
                        command = _build_h2load_command(h2load_binary=h2load_binary, server_name=server_name, host=host, port=port, cipher_suite=transport["cipher_suite"], ca_path=remote_ca, connections=int(client["connections"]), max_streams=int(client["max_concurrent_streams_per_connection"]), threads=int(client["threads"]), warmup_seconds=warmup, measurement_seconds=measurement, target_goodput_mbps=float(condition["target_goodput_mbps"]), profile=profile, result_path=result_path, timing_script_path=timing_path)
                        measurement_result = _run_measurement(ssh=ssh, pm=pm, nginx_pid=process.pid, dut_interface=dut_interface, loadgen_interface=loadgen_interface, remote_sampler=remote_sampler, command=command, run_id=run_id, warmup_seconds=warmup, measurement_seconds=measurement, interval=interval, target_goodput_mbps=float(condition["target_goodput_mbps"]), validity_policy=definition["execution"]["validity"], raw_dir=raw_dir)
                        h2, dut, loadgen = measurement_result["h2load"], measurement_result["dut"], measurement_result["loadgen"]
                        row = {
                            "schema_version": 1,
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
                            "validity": measurement_result["validity"],
                            "telemetry_window": measurement_result["telemetry_window"],
                        }
                        atomic_write_json(raw_dir / run_id / "run-result.json", row)
                        results.append(row)
                        if row["validity"]["valid"] is not True:
                            raise FrameworkError(f"run {run_id} failed frozen validity gates: {row['validity']['reasons']}; no automatic retry is permitted")
                    finally:
                        _stop_server(process)
                        out_handle.close(); err_handle.close()
            ssh.run(["bash", "-lc", "rm -rf /tmp/ngi541-r654"], check=False)

    results.sort(key=lambda row: int(row["sequence"]))
    atomic_write_json(processed_dir / "run-results.json", {"schema_version": 1, "run_count": len(results), "runs": results})
    analysis = analyze_paired_results(results)
    atomic_write_json(processed_dir / "paired-analysis.json", analysis)
    summary = {
        "schema_version": 1,
        "experiment_id": experiment_id,
        "status": "COMPLETE",
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
    atomic_write_text(processed_dir / "SUMMARY.md", f"# R6.5.4 controlled paired scientific execution\n\n- Experiment: `{experiment_id}`\n- Final freeze: `{freeze_root.name}`\n- Workload plan: `{plan['plan_id']}`\n- Conditions: 12\n- Repetitions: 4 paired repetitions per condition\n- Pairs: {len(schedule)//2}\n- Variant runs: {len(results)}\n- Adaptive replanning: prohibited\n- Metric-dependent retry: prohibited\n- Outlier deletion: none\n- HACC local scope: repeated frozen planner subset, not full-dataset transfer\n- Status: COMPLETE\n")
    _write_inventory(root)
    return {"root": root, "summary": summary, "analysis": analysis}
