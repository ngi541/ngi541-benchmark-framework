from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import statistics
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable
from xml.sax.saxutils import escape

from framework.host_state import normalize_measurement_control
from framework.io_utils import (
    FrameworkError,
    atomic_write_json,
    atomic_write_text,
    read_json,
)
from framework.provenance import git_source_info, sha256_file


PRIMARY_METRIC = "requests_per_second"
ANALYSIS_SCHEMA_VERSION = 1


def _attempt_number(path: Path) -> int:
    name = path.parent.name
    if not name.startswith("attempt-"):
        raise FrameworkError(f"invalid attempt directory: {path.parent}")
    try:
        number = int(name.split("-", 1)[1])
    except (IndexError, ValueError) as exc:
        raise FrameworkError(f"invalid attempt directory: {path.parent}") from exc
    if number < 1:
        raise FrameworkError(f"invalid attempt number: {number}")
    return number


def _measurement_paths(experiment_dir: Path, run_id: str) -> list[Path]:
    run_dir = experiment_dir / "raw" / "runs" / run_id
    paths = list(run_dir.glob("attempt-*/measurement.json")) if run_dir.is_dir() else []
    return sorted(paths, key=_attempt_number)


def _first_valid_measurement(
    experiment_dir: Path,
    scheduled_run: dict[str, Any],
) -> tuple[dict[str, Any], Path, dict[str, Any]]:
    paths = _measurement_paths(experiment_dir, scheduled_run["run_id"])
    if not paths:
        raise FrameworkError(
            f"analysis missing measurements for {scheduled_run['run_id']}"
        )

    selected: tuple[dict[str, Any], Path] | None = None
    earlier_invalid = 0

    for path in paths:
        measurement = read_json(path)
        if measurement.get("execution", {}).get("valid") is True:
            selected = (measurement, path)
            break
        earlier_invalid += 1

    if selected is None:
        raise FrameworkError(
            f"analysis found no valid attempt for {scheduled_run['run_id']}"
        )

    measurement, path = selected
    attempt_number = _attempt_number(path)
    _validate_selected_measurement(measurement, scheduled_run, attempt_number)

    later_attempts = sum(
        1 for candidate in paths if _attempt_number(candidate) > attempt_number
    )

    selection = {
        "run_id": scheduled_run["run_id"],
        "selected_attempt": attempt_number,
        "selected_path": str(path.relative_to(experiment_dir)),
        "earlier_invalid_attempts": earlier_invalid,
        "later_attempts_ignored": later_attempts,
        "rule": "first-valid-attempt-by-attempt-number",
    }
    return measurement, path, selection


def _finite_number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise FrameworkError(f"{name} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise FrameworkError(f"{name} must be finite")
    return result


def _validate_selected_measurement(
    measurement: dict[str, Any],
    scheduled_run: dict[str, Any],
    attempt_number: int,
) -> None:
    run_id = scheduled_run["run_id"]

    if measurement.get("run_id") != run_id:
        raise FrameworkError(f"measurement run_id mismatch for {run_id}")
    if measurement.get("variant") != scheduled_run["variant"]:
        raise FrameworkError(f"measurement variant mismatch for {run_id}")
    if measurement.get("pair_id") != scheduled_run.get("pair_id"):
        raise FrameworkError(f"measurement pair_id mismatch for {run_id}")
    if measurement.get("attempt") != attempt_number:
        raise FrameworkError(f"measurement attempt mismatch for {run_id}")
    if measurement.get("execution", {}).get("valid") is not True:
        raise FrameworkError(f"selected measurement is not valid for {run_id}")
    if measurement.get("execution", {}).get("exit_code") != 0:
        raise FrameworkError(f"valid measurement has non-zero exit code for {run_id}")
    if measurement.get("observations", {}).get("completed_count_known") is not True:
        raise FrameworkError(f"completed request count is unknown for {run_id}")

    requests = measurement.get("requests", {})
    planned = requests.get("planned")
    completed = requests.get("completed")
    if not isinstance(planned, int) or planned <= 0:
        raise FrameworkError(f"invalid planned request count for {run_id}")
    if completed != planned:
        raise FrameworkError(f"incomplete valid measurement for {run_id}")

    elapsed_ns = measurement.get("timing", {}).get("elapsed_ns")
    if not isinstance(elapsed_ns, int) or elapsed_ns <= 0:
        raise FrameworkError(f"invalid elapsed_ns for {run_id}")

    metric = _finite_number(
        measurement.get("metrics", {}).get(PRIMARY_METRIC),
        f"{run_id}.{PRIMARY_METRIC}",
    )
    if metric <= 0:
        raise FrameworkError(f"{run_id}.{PRIMARY_METRIC} must be > 0")


def _condition_key(parameters: dict[str, Any]) -> str:
    return json.dumps(
        parameters,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _condition_catalog(schedule: dict[str, Any]) -> tuple[list[str], dict[str, dict[str, Any]]]:
    order: list[str] = []
    catalog: dict[str, dict[str, Any]] = {}
    for run in schedule["runs"]:
        parameters = dict(run.get("parameters") or {})
        key = _condition_key(parameters)
        if key not in catalog:
            condition_id = f"condition-{len(order) + 1:04d}"
            order.append(key)
            catalog[key] = {
                "condition_id": condition_id,
                "parameters": parameters,
            }
    return order, catalog


def _sample_stddev(values: list[float]) -> float | None:
    return statistics.stdev(values) if len(values) >= 2 else None


def _variant_statistics(values: list[float]) -> dict[str, Any]:
    if not values:
        raise FrameworkError("cannot summarize empty metric series")
    mean = statistics.fmean(values)
    stddev = _sample_stddev(values)
    cv = None
    if stddev is not None and mean != 0:
        cv = stddev / mean * 100.0
    return {
        "n": len(values),
        "mean": mean,
        "median": statistics.median(values),
        "min": min(values),
        "max": max(values),
        "sample_standard_deviation": stddev,
        "coefficient_of_variation_percent": cv,
    }


def _paired_statistics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    deltas = [float(row["delta_percent"]) for row in rows]
    ratios = [float(row["ratio"]) for row in rows]
    if not deltas:
        return {
            "n_pairs": 0,
            "mean_delta_percent": None,
            "median_delta_percent": None,
            "min_delta_percent": None,
            "max_delta_percent": None,
            "sample_standard_deviation_percent": None,
            "geometric_mean_ratio": None,
            "geometric_mean_delta_percent": None,
            "wins": 0,
            "losses": 0,
            "ties": 0,
        }

    geomean_ratio = None
    if all(ratio > 0 for ratio in ratios):
        geomean_ratio = math.exp(statistics.fmean(math.log(r) for r in ratios))

    return {
        "n_pairs": len(rows),
        "mean_delta_percent": statistics.fmean(deltas),
        "median_delta_percent": statistics.median(deltas),
        "min_delta_percent": min(deltas),
        "max_delta_percent": max(deltas),
        "sample_standard_deviation_percent": _sample_stddev(deltas),
        "geometric_mean_ratio": geomean_ratio,
        "geometric_mean_delta_percent": (
            (geomean_ratio - 1.0) * 100.0 if geomean_ratio is not None else None
        ),
        "wins": sum(1 for row in rows if row["winner"] == "candidate"),
        "losses": sum(1 for row in rows if row["winner"] == "baseline"),
        "ties": sum(1 for row in rows if row["winner"] == "tie"),
    }


def _csv_value(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    return value


def _csv_text(fieldnames: list[str], rows: Iterable[dict[str, Any]]) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=fieldnames,
        lineterminator="\n",
        extrasaction="raise",
    )
    writer.writeheader()
    for row in rows:
        writer.writerow({name: _csv_value(row.get(name)) for name in fieldnames})
    return buffer.getvalue()


def _parameter_names(schedule: dict[str, Any]) -> list[str]:
    names: set[str] = set()
    for run in schedule["runs"]:
        names.update((run.get("parameters") or {}).keys())
    return sorted(names)


def _normalize_runs(
    experiment_dir: Path,
    schedule: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    selections: list[dict[str, Any]] = []

    for run in schedule["runs"]:
        measurement, _, selection = _first_valid_measurement(
            experiment_dir,
            run,
        )
        selections.append(selection)
        metric = float(measurement["metrics"][PRIMARY_METRIC])
        timing = measurement.get("timing") or {}
        phases = measurement.get("phases") or {}
        row: dict[str, Any] = {
            "experiment_id": experiment_dir.name,
            "sequence": run["sequence"],
            "run_id": run["run_id"],
            "pair_id": run.get("pair_id"),
            "variant": run["variant"],
            "repetition": run.get("repetition"),
            "repetition_round": run.get("repetition_round", run.get("repetition")),
            "condition_id": run.get("condition_id"),
            "condition_position_in_round": run.get("condition_position_in_round"),
            "pair_position": run.get("pair_position"),
            "pair_order": run.get("pair_order"),
            "attempt": measurement["attempt"],
            "attempt_started_at": timing.get("attempt_started_at")
                or measurement.get("observations", {}).get("attempt_started_at"),
            "measured_started_at": timing.get("started_at"),
            "measured_finished_at": timing.get("finished_at"),
            "attempt_elapsed_ns": timing.get("attempt_elapsed_ns"),
            "planned_requests": measurement["requests"]["planned"],
            "completed_requests": measurement["requests"]["completed"],
            "elapsed_ns": timing["elapsed_ns"],
            PRIMARY_METRIC: metric,
        }
        for phase_name, elapsed in sorted(phases.items()):
            row[f"phase_{phase_name}"] = elapsed
        row.update(run.get("parameters") or {})
        rows.append(row)

    return rows, selections

def _build_variant_summary(
    rows: list[dict[str, Any]],
    condition_order: list[str],
    condition_catalog: dict[str, dict[str, Any]],
    variants: list[str],
    parameter_names: list[str],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    grouped: dict[tuple[str, str], list[float]] = defaultdict(list)
    for row in rows:
        parameters = {name: row[name] for name in parameter_names}
        grouped[(_condition_key(parameters), row["variant"])].append(
            float(row[PRIMARY_METRIC])
        )

    csv_rows: list[dict[str, Any]] = []
    json_conditions: dict[str, Any] = {}
    for key in condition_order:
        condition = condition_catalog[key]
        condition_id = condition["condition_id"]
        json_conditions[condition_id] = {
            "parameters": condition["parameters"],
            "variants": {},
        }
        for variant in variants:
            values = grouped.get((key, variant), [])
            if not values:
                continue
            stats = _variant_statistics(values)
            json_conditions[condition_id]["variants"][variant] = stats
            csv_row = {
                "condition_id": condition_id,
                **condition["parameters"],
                "variant": variant,
                **stats,
            }
            csv_rows.append(csv_row)
    return csv_rows, json_conditions


def _parse_rfc3339(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _build_pairs(
    rows: list[dict[str, Any]],
    schedule: dict[str, Any],
    condition_catalog: dict[str, dict[str, Any]],
    variants: list[str],
    parameter_names: list[str],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if schedule.get("comparison_mode") != "paired-balanced" or len(variants) != 2:
        return [], {}

    baseline, candidate = variants
    by_pair: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in rows:
        pair_id = row.get("pair_id")
        if pair_id is None:
            raise FrameworkError("paired-balanced run is missing pair_id")
        by_pair[pair_id][row["variant"]] = row

    pair_rows: list[dict[str, Any]] = []
    by_condition: dict[str, list[dict[str, Any]]] = defaultdict(list)

    earliest = None
    for row in rows:
        dt = _parse_rfc3339(row.get("attempt_started_at"))
        if dt is not None and (earliest is None or dt < earliest):
            earliest = dt

    for pair_id in sorted(by_pair):
        pair = by_pair[pair_id]
        if set(pair) != {baseline, candidate}:
            raise FrameworkError(
                f"pair {pair_id} does not contain exactly {baseline} and {candidate}"
            )
        base_row = pair[baseline]
        cand_row = pair[candidate]
        base_params = {name: base_row[name] for name in parameter_names}
        cand_params = {name: cand_row[name] for name in parameter_names}
        if base_params != cand_params:
            raise FrameworkError(f"pair {pair_id} parameter mismatch")
        if base_row.get("repetition") != cand_row.get("repetition"):
            raise FrameworkError(f"pair {pair_id} repetition mismatch")

        key = _condition_key(base_params)
        if key not in condition_catalog:
            raise FrameworkError(f"pair {pair_id} has unknown condition")

        first_row, second_row = sorted(
            (base_row, cand_row),
            key=lambda row: int(row["sequence"]),
        )
        baseline_value = float(base_row[PRIMARY_METRIC])
        candidate_value = float(cand_row[PRIMARY_METRIC])
        if baseline_value <= 0:
            raise FrameworkError(f"pair {pair_id} baseline metric must be > 0")
        ratio = candidate_value / baseline_value
        delta = (ratio - 1.0) * 100.0
        winner = "tie"
        if delta > 0:
            winner = "candidate"
        elif delta < 0:
            winner = "baseline"

        pair_started = _parse_rfc3339(first_row.get("attempt_started_at"))
        pair_finished = _parse_rfc3339(second_row.get("measured_finished_at"))
        elapsed_from_start = None
        if pair_started is not None and earliest is not None:
            elapsed_from_start = (pair_started - earliest).total_seconds()

        result = {
            "condition_id": condition_catalog[key]["condition_id"],
            **base_params,
            "pair_id": pair_id,
            "repetition": base_row.get("repetition"),
            "repetition_round": base_row.get("repetition_round"),
            "condition_position_in_round": base_row.get("condition_position_in_round"),
            "first_sequence": first_row["sequence"],
            "first_variant": first_row["variant"],
            "second_variant": second_row["variant"],
            "pair_started_at": first_row.get("attempt_started_at"),
            "pair_finished_at": second_row.get("measured_finished_at"),
            "elapsed_since_campaign_start_seconds": elapsed_from_start,
            "baseline_variant": baseline,
            "candidate_variant": candidate,
            "baseline_requests_per_second": baseline_value,
            "candidate_requests_per_second": candidate_value,
            "ratio": ratio,
            "delta_percent": delta,
            "winner": winner,
        }
        pair_rows.append(result)
        by_condition[key].append(result)

    paired_json: dict[str, Any] = {}
    for key, group in by_condition.items():
        condition_id = condition_catalog[key]["condition_id"]
        paired_json[condition_id] = {
            "parameters": condition_catalog[key]["parameters"],
            "baseline_variant": baseline,
            "candidate_variant": candidate,
            **_paired_statistics(group),
        }
    return pair_rows, paired_json


def _order_effect_statistics(
    pair_rows: list[dict[str, Any]],
    *,
    warning_pp: float,
    strong_warning_pp: float,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in pair_rows:
        grouped[row["condition_id"]].append(row)

    csv_rows: list[dict[str, Any]] = []
    summary: dict[str, Any] = {}
    for condition_id in sorted(grouped):
        rows = grouped[condition_id]
        first_groups: dict[str, list[float]] = defaultdict(list)
        for row in rows:
            first_groups[row["first_variant"]].append(float(row["delta_percent"]))

        group_summary: dict[str, Any] = {}
        for variant, values in sorted(first_groups.items()):
            group_summary[variant] = {
                "n": len(values),
                "mean_delta_percent": statistics.fmean(values),
                "median_delta_percent": statistics.median(values),
            }

        variants = sorted(first_groups)
        signed_gap = None
        absolute_gap = None
        if len(variants) == 2:
            signed_gap = (
                group_summary[variants[0]]["median_delta_percent"]
                - group_summary[variants[1]]["median_delta_percent"]
            )
            absolute_gap = abs(signed_gap)

        level = "unavailable"
        if absolute_gap is not None:
            if absolute_gap >= strong_warning_pp:
                level = "strongly-order-sensitive"
            elif absolute_gap >= warning_pp:
                level = "order-sensitive"
            else:
                level = "stable"

        summary[condition_id] = {
            "first_variant_groups": group_summary,
            "median_gap_percentage_points": signed_gap,
            "absolute_median_gap_percentage_points": absolute_gap,
            "warning_level": level,
            "warning_threshold_pp": warning_pp,
            "strong_warning_threshold_pp": strong_warning_pp,
        }
        csv_rows.append({
            "condition_id": condition_id,
            "first_variant_a": variants[0] if len(variants) >= 1 else None,
            "first_variant_a_n": group_summary.get(variants[0], {}).get("n") if variants else None,
            "first_variant_a_median_delta_percent": group_summary.get(variants[0], {}).get("median_delta_percent") if variants else None,
            "first_variant_b": variants[1] if len(variants) >= 2 else None,
            "first_variant_b_n": group_summary.get(variants[1], {}).get("n") if len(variants) >= 2 else None,
            "first_variant_b_median_delta_percent": group_summary.get(variants[1], {}).get("median_delta_percent") if len(variants) >= 2 else None,
            "median_gap_percentage_points": signed_gap,
            "absolute_median_gap_percentage_points": absolute_gap,
            "warning_level": level,
        })
    return csv_rows, summary


def _phase_timing_summary(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    phase_names = sorted({
        key.removeprefix("phase_")
        for row in rows
        for key in row
        if key.startswith("phase_") and isinstance(row.get(key), (int, float))
    })
    csv_rows: list[dict[str, Any]] = []
    summary: dict[str, Any] = {}
    for phase in phase_names:
        values = [
            float(row[f"phase_{phase}"])
            for row in rows
            if isinstance(row.get(f"phase_{phase}"), (int, float))
        ]
        if not values:
            continue
        stats = _variant_statistics(values)
        summary[phase] = stats
        csv_rows.append({"phase": phase, **stats})
    return csv_rows, summary


def _host_calibration_rows(experiment_dir: Path) -> list[dict[str, Any]]:
    root = experiment_dir / "raw" / "host-calibration"
    if not root.is_dir():
        return []
    rows: list[dict[str, Any]] = []
    for path in sorted(root.glob("session-*.json")):
        record = read_json(path)
        cpu = record.get("cpu_busy_percent") or {}
        temp = record.get("temperature_c") or {}
        rows.append({
            "session_id": record.get("session_id") or path.stem,
            "started_at": record.get("started_at"),
            "finished_at": record.get("finished_at"),
            "algorithm": record.get("algorithm"),
            "samples_requested": record.get("samples_requested"),
            "samples_collected": record.get("samples_collected"),
            "sample_interval_seconds": record.get("sample_interval_seconds"),
            "cpu_busy_min_percent": cpu.get("min"),
            "cpu_busy_median_percent": cpu.get("median"),
            "cpu_busy_mean_percent": cpu.get("mean"),
            "cpu_busy_max_percent": cpu.get("max"),
            "cpu_busy_upper_quantile": cpu.get("upper_quantile"),
            "cpu_busy_upper_limit_percent": cpu.get("upper_limit"),
            "temperature_min_c": temp.get("min"),
            "temperature_median_c": temp.get("median"),
            "temperature_max_c": temp.get("max"),
        })
    return rows


def _host_state_rows(experiment_dir: Path) -> list[dict[str, Any]]:
    path = experiment_dir / "raw" / "host-state.jsonl"
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise FrameworkError(f"invalid host-state.jsonl line {line_number}") from exc
        rows.append({
            "captured_at": record.get("captured_at"),
            "phase": record.get("phase"),
            "run_id": record.get("run_id"),
            "pair_id": record.get("pair_id"),
            "variant": record.get("variant"),
            "condition_id": record.get("condition_id"),
            "repetition": record.get("repetition"),
            "sequence": record.get("sequence"),
            "host_calibration_id": record.get("host_calibration_id"),
            "temperature_c": (record.get("temperature") or {}).get("temperature_c"),
            "thermal_state": (record.get("thermal") or {}).get("thermal_state"),
            "thermal_pressure": (record.get("thermal") or {}).get("thermal_pressure"),
            "throttling_active": (record.get("thermal") or {}).get("throttling_active"),
            "cpu_speed_limit_percent": (record.get("thermal") or {}).get("cpu_speed_limit_percent"),
            "cpu_available_cpus": (record.get("thermal") or {}).get("cpu_available_cpus"),
            "power_source": (record.get("power") or {}).get("source"),
            "cpu_busy_percent": (record.get("load") or {}).get("cpu_busy_percent"),
            "load_1m": (record.get("load") or {}).get("load_1m"),
            "load_1m_per_logical_cpu": (record.get("load") or {}).get("load_1m_per_logical_cpu"),
            "ready": (record.get("readiness") or {}).get("ready"),
            "consecutive_ready_samples": (record.get("readiness") or {}).get("consecutive_ready_samples"),
            "required_consecutive_ready_samples": (record.get("readiness") or {}).get("required_consecutive_ready_samples"),
            "readiness_reasons": (record.get("readiness") or {}).get("reasons"),
        })
    return rows

def _svg_document(width: int, height: int, body: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
        f'height="{height}" viewBox="0 0 {width} {height}">\n'
        '<rect x="0" y="0" width="100%" height="100%" fill="white"/>\n'
        f'{body}'
        '</svg>\n'
    )


def _svg_text(
    x: float,
    y: float,
    text: str,
    *,
    size: int = 12,
    anchor: str = "start",
    weight: str = "normal",
    fill: str = "#111111",
    rotate: float | None = None,
) -> str:
    transform = ""
    if rotate is not None:
        transform = f' transform="rotate({rotate:.2f} {x:.2f} {y:.2f})"'
    return (
        f'<text x="{x:.2f}" y="{y:.2f}" font-family="Arial, Helvetica, sans-serif" '
        f'font-size="{size}" font-weight="{weight}" text-anchor="{anchor}" '
        f'fill="{fill}"{transform}>{escape(text)}</text>\n'
    )


def _svg_multiline_text(
    x: float,
    y: float,
    lines: list[str],
    *,
    size: int = 12,
    anchor: str = "middle",
    weight: str = "normal",
    fill: str = "#111111",
    line_height: float = 1.18,
) -> str:
    if not lines:
        return ""
    parts = [
        f'<text x="{x:.2f}" y="{y:.2f}" font-family="Arial, Helvetica, sans-serif" '
        f'font-size="{size}" font-weight="{weight}" text-anchor="{anchor}" fill="{fill}">\n'
    ]
    for index, line in enumerate(lines):
        dy = "0" if index == 0 else f"{line_height:.2f}em"
        parts.append(
            f'<tspan x="{x:.2f}" dy="{dy}">{escape(line)}</tspan>\n'
        )
    parts.append('</text>\n')
    return "".join(parts)


def _display_variant(variant: str) -> str:
    known = {
        "stock": "Stock OpenSSL",
        "ngi541-direct": "NGI541 direct",
    }
    return known.get(variant, variant.replace("-", " "))


def _format_payload_bytes(value: Any) -> str:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return str(value)
    if number > 0 and number % (1024 * 1024) == 0:
        return f"{number // (1024 * 1024)} MiB"
    if number > 0 and number % 1024 == 0:
        return f"{number // 1024} KiB"
    return f"{number} B"


def _condition_label(parameters: dict[str, Any]) -> list[str]:
    payload = _format_payload_bytes(parameters.get("payload_bytes", "?"))
    workers = parameters.get("workers", "?")
    clients = parameters.get("clients", "?")
    return [payload, f"{workers}w/{clients}c"]


def _nice_ceiling(value: float) -> float:
    if value <= 0:
        return 1.0
    exponent = math.floor(math.log10(value))
    scale = 10.0 ** exponent
    fraction = value / scale
    if fraction <= 1.0:
        nice = 1.0
    elif fraction <= 1.2:
        nice = 1.2
    elif fraction <= 1.5:
        nice = 1.5
    elif fraction <= 2.0:
        nice = 2.0
    elif fraction <= 2.5:
        nice = 2.5
    elif fraction <= 5.0:
        nice = 5.0
    elif fraction <= 7.5:
        nice = 7.5
    else:
        nice = 10.0
    return nice * scale


def _variant_fill(index: int) -> str:
    palette = ["#2F6FA3", "#E98B2A", "#5B8C5A", "#8C6BB1"]
    return palette[index % len(palette)]


def _requests_svg(
    variant_summary: dict[str, Any],
    condition_order: list[str],
    condition_catalog: dict[str, dict[str, Any]],
    variants: list[str],
) -> str:
    width, height = 1180, 660
    left, right, top, bottom = 105.0, 45.0, 100.0, 135.0
    plot_w = width - left - right
    plot_h = height - top - bottom

    conditions: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    values: list[float] = []
    for key in condition_order:
        cid = condition_catalog[key]["condition_id"]
        summary = variant_summary.get(cid, {})
        parameters = condition_catalog[key]["parameters"]
        conditions.append((cid, parameters, summary))
        for variant in variants:
            stats = summary.get("variants", {}).get(variant)
            if stats:
                values.append(float(stats["median"]))

    if not values:
        body = _svg_text(60, 40, "NGINX HTTP/3 throughput", size=22, weight="bold")
        body += _svg_text(width / 2, height / 2, "No analyzed measurements", anchor="middle")
        return _svg_document(width, height, body)

    y_max = _nice_ceiling(max(values) * 1.12)
    tick_count = 5
    group_count = max(1, len(conditions))
    group_step = plot_w / group_count
    group_inner = min(group_step * 0.70, 260.0)
    bar_gap = 8.0
    bar_count = max(1, len(variants))
    bar_width = min(92.0, (group_inner - bar_gap * (bar_count - 1)) / bar_count)
    cluster_width = bar_width * bar_count + bar_gap * (bar_count - 1)

    body = _svg_text(left, 38, "NGINX HTTP/3 throughput", size=24, weight="bold")
    body += _svg_text(
        left,
        67,
        "Median completed HTTP/3 requests/s by workload condition",
        size=13,
        fill="#555555",
    )

    # Plot frame and horizontal grid.
    baseline_y = top + plot_h
    for tick in range(tick_count + 1):
        value = y_max * tick / tick_count
        y = baseline_y - plot_h * tick / tick_count
        body += (
            f'<line x1="{left:.2f}" y1="{y:.2f}" x2="{left + plot_w:.2f}" y2="{y:.2f}" '
            'stroke="#D8D8D8" stroke-width="1"/>\n'
        )
        body += _svg_text(left - 12, y + 4, f"{value:,.0f}", size=11, anchor="end", fill="#333333")

    body += (
        f'<line x1="{left:.2f}" y1="{top:.2f}" x2="{left:.2f}" y2="{baseline_y:.2f}" '
        'stroke="#222222" stroke-width="1.4"/>\n'
    )
    body += (
        f'<line x1="{left:.2f}" y1="{baseline_y:.2f}" x2="{left + plot_w:.2f}" y2="{baseline_y:.2f}" '
        'stroke="#222222" stroke-width="1.4"/>\n'
    )

    # Grouped bars.
    for condition_index, (cid, parameters, summary) in enumerate(conditions):
        center = left + group_step * (condition_index + 0.5)
        cluster_left = center - cluster_width / 2
        for variant_index, variant in enumerate(variants):
            stats = summary.get("variants", {}).get(variant)
            if not stats:
                continue
            value = float(stats["median"])
            x = cluster_left + variant_index * (bar_width + bar_gap)
            bar_h = (value / y_max) * plot_h
            y = baseline_y - bar_h
            fill = _variant_fill(variant_index)
            body += (
                f'<rect x="{x:.2f}" y="{y:.2f}" width="{bar_width:.2f}" height="{bar_h:.2f}" '
                f'rx="2" fill="{fill}"/>\n'
            )
            label_y = max(top + 14, y - 8)
            body += _svg_text(
                x + bar_width / 2,
                label_y,
                f"{value:,.1f}",
                size=11,
                anchor="middle",
                weight="bold",
                fill="#222222",
            )

        label_lines = _condition_label(parameters)
        body += _svg_multiline_text(
            center,
            baseline_y + 28,
            label_lines,
            size=12,
            anchor="middle",
            weight="bold",
        )
        body += _svg_text(
            center,
            baseline_y + 64,
            cid,
            size=9,
            anchor="middle",
            fill="#777777",
        )

    # Legend.
    legend_x = left + 10
    legend_y = 88
    for index, variant in enumerate(variants):
        x = legend_x + index * 185
        fill = _variant_fill(index)
        body += f'<rect x="{x:.2f}" y="{legend_y - 11:.2f}" width="16" height="12" rx="1" fill="{fill}"/>\n'
        body += _svg_text(x + 24, legend_y, _display_variant(variant), size=11, fill="#222222")

    body += _svg_text(
        28,
        top + plot_h / 2,
        "Completed HTTP/3 requests/s",
        size=13,
        anchor="middle",
        weight="bold",
        rotate=-90,
    )
    body += _svg_text(
        left + plot_w / 2,
        height - 24,
        "Workload configuration",
        size=13,
        anchor="middle",
        weight="bold",
    )
    return _svg_document(width, height, body)


def _delta_axis(values: list[float]) -> tuple[float, float, list[float]]:
    low = min(values)
    high = max(values)
    if low >= 0:
        upper = _nice_ceiling(max(1.0, high * 1.12))
        lower = 0.0
    elif high <= 0:
        lower = -_nice_ceiling(max(1.0, abs(low) * 1.12))
        upper = 0.0
    else:
        bound = _nice_ceiling(max(abs(low), abs(high)) * 1.12)
        lower, upper = -bound, bound
    step = (upper - lower) / 5.0
    ticks = [lower + step * i for i in range(6)]
    return lower, upper, ticks


def _paired_svg(pair_rows: list[dict[str, Any]]) -> str:
    width, height = 1180, 660
    if not pair_rows:
        body = _svg_text(60, 40, "NGI541 relative throughput delta", size=24, weight="bold")
        body += _svg_text(width / 2, height / 2, "Paired comparison not applicable", anchor="middle")
        return _svg_document(width, height, body)

    left, right, top, bottom = 105.0, 45.0, 100.0, 135.0
    plot_w = width - left - right
    plot_h = height - top - bottom

    by_condition: dict[str, list[dict[str, Any]]] = defaultdict(list)
    condition_parameters: dict[str, dict[str, Any]] = {}
    condition_order: list[str] = []
    for row in pair_rows:
        cid = str(row["condition_id"])
        if cid not in by_condition:
            condition_order.append(cid)
        by_condition[cid].append(row)
        condition_parameters[cid] = {
            key: value
            for key, value in row.items()
            if key not in {
                "condition_id", "pair_id", "repetition", "baseline_variant",
                "candidate_variant", "baseline_requests_per_second",
                "candidate_requests_per_second", "ratio", "delta_percent", "winner",
            }
        }

    medians = [
        float(statistics.median(float(row["delta_percent"]) for row in by_condition[cid]))
        for cid in condition_order
    ]
    all_values = [float(row["delta_percent"]) for row in pair_rows]
    y_min, y_max, ticks = _delta_axis(all_values + medians)

    def y_pos(value: float) -> float:
        if y_max == y_min:
            return top + plot_h / 2
        return top + (y_max - value) / (y_max - y_min) * plot_h

    zero_y = y_pos(0.0)
    group_count = max(1, len(condition_order))
    group_step = plot_w / group_count
    bar_width = min(125.0, group_step * 0.52)

    body = _svg_text(left, 38, "NGI541 relative throughput delta", size=24, weight="bold")
    body += _svg_text(
        left,
        67,
        "Median paired delta vs Stock OpenSSL; positive values favor NGI541",
        size=13,
        fill="#555555",
    )

    for value in ticks:
        y = y_pos(value)
        line_color = "#222222" if abs(value) < 1e-12 else "#D8D8D8"
        line_width = "1.5" if abs(value) < 1e-12 else "1"
        body += (
            f'<line x1="{left:.2f}" y1="{y:.2f}" x2="{left + plot_w:.2f}" y2="{y:.2f}" '
            f'stroke="{line_color}" stroke-width="{line_width}"/>\n'
        )
        body += _svg_text(left - 12, y + 4, f"{value:+.1f}%", size=11, anchor="end", fill="#333333")

    body += (
        f'<line x1="{left:.2f}" y1="{top:.2f}" x2="{left:.2f}" y2="{top + plot_h:.2f}" '
        'stroke="#222222" stroke-width="1.4"/>\n'
    )

    for index, cid in enumerate(condition_order):
        rows = by_condition[cid]
        values = [float(row["delta_percent"]) for row in rows]
        median = float(statistics.median(values))
        center = left + group_step * (index + 0.5)
        y_med = y_pos(median)
        rect_y = min(zero_y, y_med)
        rect_h = max(1.0, abs(zero_y - y_med))

        body += (
            f'<rect x="{center - bar_width / 2:.2f}" y="{rect_y:.2f}" '
            f'width="{bar_width:.2f}" height="{rect_h:.2f}" rx="2" fill="#2F6FA3"/>\n'
        )

        # Min/max range and individual pair samples provide distribution context.
        minimum = min(values)
        maximum = max(values)
        y_lo = y_pos(minimum)
        y_hi = y_pos(maximum)
        if len(values) > 1:
            body += (
                f'<line x1="{center:.2f}" y1="{y_hi:.2f}" x2="{center:.2f}" y2="{y_lo:.2f}" '
                'stroke="#222222" stroke-width="1.4"/>\n'
            )
            body += (
                f'<line x1="{center - 8:.2f}" y1="{y_hi:.2f}" x2="{center + 8:.2f}" y2="{y_hi:.2f}" '
                'stroke="#222222" stroke-width="1.4"/>\n'
            )
            body += (
                f'<line x1="{center - 8:.2f}" y1="{y_lo:.2f}" x2="{center + 8:.2f}" y2="{y_lo:.2f}" '
                'stroke="#222222" stroke-width="1.4"/>\n'
            )

        if len(values) <= 12:
            if len(values) == 1:
                offsets = [0.0]
            else:
                spread = min(38.0, bar_width * 0.55)
                offsets = [
                    -spread / 2 + spread * i / (len(values) - 1)
                    for i in range(len(values))
                ]
            for offset, value in zip(offsets, values):
                body += (
                    f'<circle cx="{center + offset:.2f}" cy="{y_pos(value):.2f}" r="3.4" '
                    'fill="white" stroke="#222222" stroke-width="1.2"/>\n'
                )

        label_y = y_med - 10 if median >= 0 else y_med + 22
        body += _svg_text(
            center,
            label_y,
            f"{median:+.2f}%",
            size=12,
            anchor="middle",
            weight="bold",
        )
        body += _svg_multiline_text(
            center,
            top + plot_h + 28,
            _condition_label(condition_parameters[cid]),
            size=12,
            weight="bold",
        )
        body += _svg_text(
            center,
            top + plot_h + 64,
            f"{cid} · n={len(values)}",
            size=9,
            anchor="middle",
            fill="#777777",
        )

    body += _svg_text(
        28,
        top + plot_h / 2,
        "NGI541 median throughput delta (%)",
        size=13,
        anchor="middle",
        weight="bold",
        rotate=-90,
    )
    body += _svg_text(
        left + plot_w / 2,
        height - 24,
        "Workload configuration",
        size=13,
        anchor="middle",
        weight="bold",
    )
    return _svg_document(width, height, body)

def _results_readme(
    experiment_id: str,
    variants: list[str],
    variant_summary: dict[str, Any],
    paired_summary: dict[str, Any],
) -> str:
    lines = [
        f"# Analysis — {experiment_id}",
        "",
        "This directory is generated deterministically from the experiment's raw `measurement.json` files.",
        "Attempt selection is fixed before metric inspection: the first attempt with `execution.valid=true` is selected for every scheduled run.",
        "",
        f"Primary metric: `{PRIMARY_METRIC}`.",
        "Sample standard deviation and coefficient of variation are reported only when `n >= 2`.",
        "",
        "## Variant summaries",
        "",
    ]

    for condition_id in sorted(variant_summary):
        condition = variant_summary[condition_id]
        lines.append(f"### {condition_id}")
        params = json.dumps(condition["parameters"], sort_keys=True, ensure_ascii=False)
        lines.append("")
        lines.append(f"Parameters: `{params}`")
        lines.append("")
        for variant in variants:
            stats = condition["variants"].get(variant)
            if not stats:
                continue
            lines.append(
                f"- `{variant}`: n={stats['n']}, median={stats['median']:.6f}, mean={stats['mean']:.6f} requests/s"
            )
        lines.append("")

    if paired_summary:
        lines.extend(["## Paired comparison", ""])
        for condition_id in sorted(paired_summary):
            stats = paired_summary[condition_id]
            lines.append(
                f"- `{condition_id}`: {stats['candidate_variant']} vs {stats['baseline_variant']}, "
                f"n={stats['n_pairs']}, median delta={stats['median_delta_percent']:+.6f}%, "
                f"wins/losses/ties={stats['wins']}/{stats['losses']}/{stats['ties']}"
            )
        lines.append("")

    lines.extend([
        "## Artifacts",
        "",
        "- `selection.json` — deterministic attempt selection record.",
        "- `runs.csv` — one normalized row per scheduled run.",
        "- `summary.csv` — per-condition, per-variant statistics.",
        "- `pairs.csv` — paired A/B rows when applicable.",
        "- `statistics.json` — structured statistics and analysis policy.",
        "- `analysis-provenance.json` — analysis implementation Git identity.",
        "- `artifacts.sha256` — SHA-256 inventory of generated analysis outputs.",
        "- `../figures/requests-per-second.svg` — median throughput plot.",
        "- `../figures/paired-delta.svg` — paired delta plot.",
        "",
    ])
    return "\n".join(lines)


def _analysis_provenance(experiment_dir: Path) -> dict[str, Any]:
    repo_root = experiment_dir.parents[1]
    source = git_source_info("ngi541-nginx", repo_root, repo_root)
    return {
        "schema_version": 1,
        "implementation": "benchmark/framework/analysis.py",
        "repository": source["name"],
        "commit": source["commit"],
        "describe": source.get("describe"),
        "tracked_dirty": bool(source.get("tracked_dirty")),
        "tracked_diff_sha256": source.get("tracked_diff_sha256"),
        "selection_policy": "first-valid-attempt-by-attempt-number",
        "primary_metric": PRIMARY_METRIC,
    }


def _write_artifact_hashes(experiment_dir: Path, relative_paths: list[str]) -> None:
    lines = []
    for rel in sorted(relative_paths):
        digest = sha256_file(experiment_dir / rel)
        lines.append(f"{digest}  {rel}")
    atomic_write_text(
        experiment_dir / "processed" / "artifacts.sha256",
        "\n".join(lines) + "\n",
    )


def analyze_experiment(experiment_dir: Path) -> dict[str, Any]:
    schedule = read_json(experiment_dir / "execution" / "schedule.json")
    resolved = read_json(experiment_dir / "config" / "resolved.json")
    variants = list(resolved["variants"])

    rows, selections = _normalize_runs(experiment_dir, schedule)
    condition_order, condition_catalog = _condition_catalog(schedule)
    parameter_names = _parameter_names(schedule)

    summary_rows, variant_summary = _build_variant_summary(
        rows,
        condition_order,
        condition_catalog,
        variants,
        parameter_names,
    )
    pair_rows, paired_summary = _build_pairs(
        rows,
        schedule,
        condition_catalog,
        variants,
        parameter_names,
    )

    control = normalize_measurement_control(resolved.get("measurement_control"))
    order_rows, order_summary = _order_effect_statistics(
        pair_rows,
        warning_pp=control["analysis"]["order_effect_warning_pp"],
        strong_warning_pp=control["analysis"]["order_effect_strong_warning_pp"],
    )
    phase_rows, phase_summary = _phase_timing_summary(rows)
    host_rows = _host_state_rows(experiment_dir)
    host_calibration_rows = _host_calibration_rows(experiment_dir)

    selection_doc = {
        "schema_version": ANALYSIS_SCHEMA_VERSION,
        "experiment_id": experiment_dir.name,
        "policy": {
            "validity_predicate": "execution.valid == true",
            "selection": "lowest attempt number satisfying validity predicate",
            "metric_independent": True,
            "later_valid_attempts": "ignored",
        },
        "runs": selections,
    }
    atomic_write_json(experiment_dir / "processed" / "selection.json", selection_doc)

    phase_fields = sorted({
        key for row in rows for key in row if key.startswith("phase_")
    })
    run_fields = [
        "experiment_id", "sequence", "run_id", "pair_id", "variant",
        "repetition", "repetition_round", "condition_id",
        "condition_position_in_round", "pair_position", "pair_order",
        "attempt", "attempt_started_at", "measured_started_at",
        "measured_finished_at", "attempt_elapsed_ns", *parameter_names,
        "planned_requests", "completed_requests", "elapsed_ns",
        *phase_fields, PRIMARY_METRIC,
    ]
    atomic_write_text(
        experiment_dir / "processed" / "runs.csv",
        _csv_text(run_fields, rows),
    )

    summary_fields = [
        "condition_id", *parameter_names, "variant", "n", "mean", "median",
        "min", "max", "sample_standard_deviation",
        "coefficient_of_variation_percent",
    ]
    atomic_write_text(
        experiment_dir / "processed" / "summary.csv",
        _csv_text(summary_fields, summary_rows),
    )

    pair_fields = [
        "condition_id", *parameter_names, "pair_id", "repetition",
        "repetition_round", "condition_position_in_round", "first_sequence",
        "first_variant", "second_variant", "pair_started_at", "pair_finished_at",
        "elapsed_since_campaign_start_seconds",
        "baseline_variant", "candidate_variant",
        "baseline_requests_per_second", "candidate_requests_per_second",
        "ratio", "delta_percent", "winner",
    ]
    atomic_write_text(
        experiment_dir / "processed" / "pairs.csv",
        _csv_text(pair_fields, pair_rows),
    )

    order_fields = [
        "condition_id", "first_variant_a", "first_variant_a_n",
        "first_variant_a_median_delta_percent", "first_variant_b",
        "first_variant_b_n", "first_variant_b_median_delta_percent",
        "median_gap_percentage_points", "absolute_median_gap_percentage_points",
        "warning_level",
    ]
    atomic_write_text(
        experiment_dir / "processed" / "order-effects.csv",
        _csv_text(order_fields, order_rows),
    )

    phase_fields_csv = [
        "phase", "n", "mean", "median", "min", "max",
        "sample_standard_deviation", "coefficient_of_variation_percent",
    ]
    atomic_write_text(
        experiment_dir / "processed" / "phase-timing.csv",
        _csv_text(phase_fields_csv, phase_rows),
    )

    host_calibration_fields = [
        "session_id", "started_at", "finished_at", "algorithm",
        "samples_requested", "samples_collected", "sample_interval_seconds",
        "cpu_busy_min_percent", "cpu_busy_median_percent", "cpu_busy_mean_percent",
        "cpu_busy_max_percent", "cpu_busy_upper_quantile",
        "cpu_busy_upper_limit_percent", "temperature_min_c",
        "temperature_median_c", "temperature_max_c",
    ]
    atomic_write_text(
        experiment_dir / "processed" / "host-calibration.csv",
        _csv_text(host_calibration_fields, host_calibration_rows),
    )

    host_fields = [
        "captured_at", "phase", "run_id", "pair_id", "variant",
        "condition_id", "repetition", "sequence", "host_calibration_id", "temperature_c",
        "thermal_state", "thermal_pressure", "throttling_active", "cpu_speed_limit_percent",
        "cpu_available_cpus", "power_source", "cpu_busy_percent", "load_1m",
        "load_1m_per_logical_cpu", "ready", "consecutive_ready_samples",
        "required_consecutive_ready_samples", "readiness_reasons",
    ]
    atomic_write_text(
        experiment_dir / "processed" / "host-state.csv",
        _csv_text(host_fields, host_rows),
    )

    statistics_doc = {
        "schema_version": ANALYSIS_SCHEMA_VERSION,
        "experiment_id": experiment_dir.name,
        "primary_metric": PRIMARY_METRIC,
        "analysis_policy": {
            "attempt_selection": "first-valid-attempt-by-attempt-number",
            "standard_deviation": "sample (n-1); null when n < 2",
            "coefficient_of_variation": "sample_standard_deviation / mean * 100; null when unavailable",
            "paired_baseline_variant": variants[0] if variants else None,
            "paired_candidate_variant": variants[1] if len(variants) == 2 else None,
            "paired_delta": "(candidate / baseline - 1) * 100",
            "geometric_mean_ratio": "exp(mean(log(candidate / baseline))); positive ratios only",
        },
        "conditions": variant_summary,
        "paired": paired_summary,
        "order_effect": order_summary,
        "phase_timing_ns": phase_summary,
        "measurement_control": control,
        "host_calibration": host_calibration_rows,
    }
    atomic_write_json(
        experiment_dir / "processed" / "statistics.json",
        statistics_doc,
    )

    provenance_doc = _analysis_provenance(experiment_dir)
    atomic_write_json(
        experiment_dir / "processed" / "analysis-provenance.json",
        provenance_doc,
    )

    atomic_write_text(
        experiment_dir / "figures" / "requests-per-second.svg",
        _requests_svg(
            variant_summary,
            condition_order,
            condition_catalog,
            variants,
        ),
    )
    atomic_write_text(
        experiment_dir / "figures" / "paired-delta.svg",
        _paired_svg(pair_rows),
    )
    atomic_write_text(
        experiment_dir / "processed" / "README.md",
        _results_readme(
            experiment_dir.name,
            variants,
            variant_summary,
            paired_summary,
        ),
    )

    generated = [
        "processed/selection.json",
        "processed/runs.csv",
        "processed/summary.csv",
        "processed/pairs.csv",
        "processed/order-effects.csv",
        "processed/phase-timing.csv",
        "processed/host-state.csv",
        "processed/host-calibration.csv",
        "processed/statistics.json",
        "processed/analysis-provenance.json",
        "processed/README.md",
        "figures/requests-per-second.svg",
        "figures/paired-delta.svg",
    ]
    _write_artifact_hashes(experiment_dir, generated)

    return {
        "selected_runs": len(rows),
        "conditions": len(condition_order),
        "pairs": len(pair_rows),
        "variants": variants,
        "analysis_provenance": provenance_doc,
    }


def validate_analysis_outputs(experiment_dir: Path) -> list[str]:
    errors: list[str] = []
    required = [
        "processed/selection.json",
        "processed/runs.csv",
        "processed/summary.csv",
        "processed/pairs.csv",
        "processed/order-effects.csv",
        "processed/phase-timing.csv",
        "processed/host-state.csv",
        "processed/host-calibration.csv",
        "processed/statistics.json",
        "processed/analysis-provenance.json",
        "processed/README.md",
        "processed/artifacts.sha256",
        "figures/requests-per-second.svg",
        "figures/paired-delta.svg",
    ]
    for rel in required:
        if not (experiment_dir / rel).is_file():
            errors.append(f"analysis output missing file: {rel}")

    stats_path = experiment_dir / "processed" / "statistics.json"
    if stats_path.is_file():
        try:
            stats = read_json(stats_path)
            if stats.get("experiment_id") != experiment_dir.name:
                errors.append("statistics.json experiment_id does not match directory")
            if stats.get("primary_metric") != PRIMARY_METRIC:
                errors.append("statistics.json primary_metric is unexpected")
        except FrameworkError as exc:
            errors.append(str(exc))

    hashes_path = experiment_dir / "processed" / "artifacts.sha256"
    if hashes_path.is_file():
        for line in hashes_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                expected, rel = line.split("  ", 1)
            except ValueError:
                errors.append("invalid processed/artifacts.sha256 line")
                continue
            path = experiment_dir / rel
            if not path.is_file():
                errors.append(f"hashed analysis artifact missing: {rel}")
                continue
            actual = sha256_file(path)
            if actual != expected:
                errors.append(f"analysis artifact hash mismatch: {rel}")

    return errors
