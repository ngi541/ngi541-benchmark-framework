from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from framework.analysis import validate_analysis_outputs
from framework.ids import (
    EXPERIMENT_ID_RE,
    PAIR_ID_RE,
    RUN_ID_RE,
    SLUG_RE,
)
from framework.io_utils import FrameworkError, read_json
from framework.host_state import normalize_measurement_control
from framework.deployment import normalize_deployment_definition


COMMON_DIRS = (
    "config",
    "environment",
    "environment/nodes",
    "provenance",
    "execution",
    "raw",
    "raw/runs",
    "processed",
    "figures",
    "logs",
)

SEALED_STATES = {
    "READY",
    "RUNNING",
    "ANALYZING",
    "COMPLETE",
    "ABORTED",
}


def validate_request(request: dict[str, Any]) -> None:
    required = {"workload", "variants", "parameters"}
    missing = required.difference(request)
    if missing:
        raise FrameworkError(
            f"request is missing required fields: {', '.join(sorted(missing))}"
        )

    if not SLUG_RE.fullmatch(str(request["workload"])):
        raise FrameworkError("invalid workload identifier")

    has_environment = "environment" in request
    has_deployment = "deployment" in request

    if has_environment == has_deployment:
        raise FrameworkError(
            "request must contain exactly one of environment or deployment"
        )

    if has_environment:
        if not SLUG_RE.fullmatch(str(request["environment"])):
            raise FrameworkError("invalid environment identifier")
    else:
        normalize_deployment_definition(request["deployment"])

    variants = request["variants"]
    if not isinstance(variants, list) or not variants:
        raise FrameworkError("variants must be a non-empty array")

    for variant in variants:
        if not isinstance(variant, str) or not SLUG_RE.fullmatch(variant):
            raise FrameworkError(f"invalid variant identifier: {variant!r}")

    if not isinstance(request["parameters"], dict):
        raise FrameworkError("parameters must be an object")

    scheduling = request.get("scheduling")
    if scheduling is not None:
        if not isinstance(scheduling, dict):
            raise FrameworkError("scheduling must be an object")
        if scheduling.get("condition_order", "condition-major") not in {"condition-major", "rotating-rounds"}:
            raise FrameworkError("unsupported scheduling.condition_order")
        if scheduling.get("variant_order", "pair-sequence") not in {"pair-sequence", "alternate-by-repetition", "balanced-by-condition-round"}:
            raise FrameworkError("unsupported scheduling.variant_order")

    if request.get("measurement_control") is not None:
        normalize_measurement_control(request["measurement_control"])

    conditions = request.get("conditions")
    if conditions is not None:
        if not isinstance(conditions, list) or not conditions:
            raise FrameworkError("conditions must be a non-empty array")

        fixed_names = set(request["parameters"]) - {"repetitions"}
        expected_keys = None
        seen = set()

        for index, condition in enumerate(conditions):
            if not isinstance(condition, dict) or not condition:
                raise FrameworkError(
                    f"conditions[{index}] must be a non-empty object"
                )

            overlap = fixed_names.intersection(condition)
            if overlap:
                raise FrameworkError(
                    "condition parameters must not overlap fixed parameters: "
                    + ", ".join(sorted(overlap))
                )

            keys = frozenset(condition)
            if expected_keys is None:
                expected_keys = keys
            elif keys != expected_keys:
                raise FrameworkError(
                    "all explicit conditions must use the same parameter keys"
                )

            for name, value in condition.items():
                if isinstance(value, (list, dict)):
                    raise FrameworkError(
                        f"conditions[{index}].{name} must be scalar"
                    )

            identity = json.dumps(
                condition,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            if identity in seen:
                raise FrameworkError(
                    f"duplicate explicit condition at index {index}"
                )
            seen.add(identity)


def _validate_schedule(
    schedule: dict[str, Any],
    experiment_id: str,
    errors: list[str],
) -> None:
    if schedule.get("experiment_id") != experiment_id:
        errors.append(
            "schedule.json experiment_id does not match directory name"
        )

    runs = schedule.get("runs")
    if not isinstance(runs, list) or not runs:
        errors.append("schedule.json runs must be a non-empty array")
        return

    seen_run_ids: set[str] = set()
    expected_sequence = 1

    for run in runs:
        run_id = run.get("run_id")
        if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
            errors.append(f"invalid run_id: {run_id!r}")
        elif run_id in seen_run_ids:
            errors.append(f"duplicate run_id: {run_id}")
        else:
            seen_run_ids.add(run_id)

        if run.get("sequence") != expected_sequence:
            errors.append(
                f"unexpected sequence for {run_id}: "
                f"expected {expected_sequence}, got {run.get('sequence')}"
            )
        expected_sequence += 1

        pair_id = run.get("pair_id")
        if pair_id is not None and (
            not isinstance(pair_id, str)
            or not PAIR_ID_RE.fullmatch(pair_id)
        ):
            errors.append(f"invalid pair_id: {pair_id!r}")


def validate_experiment(experiment_dir: Path) -> list[str]:
    errors: list[str] = []
    experiment_id = experiment_dir.name

    if not EXPERIMENT_ID_RE.fullmatch(experiment_id):
        errors.append(f"invalid experiment directory name: {experiment_id}")

    for rel in COMMON_DIRS:
        if not (experiment_dir / rel).is_dir():
            errors.append(f"missing directory: {rel}")

    try:
        request = read_json(experiment_dir / "config" / "request.json")
        validate_request(request)
    except FrameworkError as exc:
        errors.append(str(exc))

    campaign_path = experiment_dir / "config" / "campaign.json"
    if campaign_path.is_file():
        try:
            campaign = read_json(campaign_path)
            definition = campaign.get("definition")
            expected = campaign.get("definition_sha256")
            if not isinstance(definition, dict) or not isinstance(expected, str):
                errors.append("config/campaign.json has invalid definition metadata")
            else:
                encoded = json.dumps(
                    definition,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
                actual = hashlib.sha256(encoded).hexdigest()
                if actual != expected:
                    errors.append("config/campaign.json definition SHA-256 mismatch")
        except FrameworkError as exc:
            errors.append(str(exc))

    state = None
    try:
        state = read_json(experiment_dir / "state.json")
        if state.get("experiment_id") != experiment_id:
            errors.append(
                "state.json experiment_id does not match directory name"
            )
        if state.get("schema_version") != 1:
            errors.append("state.json schema_version must be 1")
    except FrameworkError as exc:
        errors.append(str(exc))

    schedule_path = experiment_dir / "execution" / "schedule.json"
    if schedule_path.exists():
        try:
            _validate_schedule(
                read_json(schedule_path),
                experiment_id,
                errors,
            )
        except FrameworkError as exc:
            errors.append(str(exc))

    if state and state.get("state") in SEALED_STATES:
        required_files = (
            "manifest.json",
            "config/resolved.json",
            "environment/adapter.json",
            "provenance/sources.json",
            "provenance/dependencies.json",
            "provenance/build.json",
            "provenance/binaries.sha256",
            "provenance/runtime-bindings.json",
            "provenance/preflight.json",
            "execution/schedule.json",
            "execution/workload/manifest.json",
            "execution/workload/preflight.json",
        )

        for rel in required_files:
            if not (experiment_dir / rel).is_file():
                errors.append(f"sealed experiment missing file: {rel}")

        for preflight_rel in (
            "provenance/preflight.json",
            "execution/workload/preflight.json",
        ):
            path = experiment_dir / preflight_rel
            if path.is_file():
                try:
                    preflight = read_json(path)
                    if not preflight.get("passed"):
                        errors.append(
                            f"sealed experiment has non-passing {preflight_rel}"
                        )
                except FrameworkError as exc:
                    errors.append(str(exc))

        manifest_path = experiment_dir / "manifest.json"
        if manifest_path.is_file():
            try:
                manifest = read_json(manifest_path)
                if (
                    manifest.get("experiment", {}).get("id")
                    != experiment_id
                ):
                    errors.append(
                        "manifest.json experiment id does not match directory"
                    )
            except FrameworkError as exc:
                errors.append(str(exc))

    if state and state.get("state") in {"ANALYZING", "COMPLETE"}:
        try:
            resolved = read_json(experiment_dir / "config" / "resolved.json")
            control = normalize_measurement_control(resolved.get("measurement_control"))
            if control["host_state"]["enabled"]:
                if not (experiment_dir / "raw" / "host-state.jsonl").is_file():
                    errors.append("controlled execution missing raw/host-state.jsonl")
            if control["calibration"]["enabled"]:
                calibration_files = sorted(
                    (experiment_dir / "raw" / "host-calibration").glob("session-*.json")
                )
                if not calibration_files:
                    errors.append("controlled execution missing host calibration record")
                else:
                    for calibration_path in calibration_files:
                        try:
                            calibration = read_json(calibration_path)
                            cpu = calibration.get("cpu_busy_percent") or {}
                            if not isinstance(cpu.get("upper_limit"), (int, float)):
                                errors.append(
                                    f"invalid host calibration envelope: {calibration_path.name}"
                                )
                        except FrameworkError as exc:
                            errors.append(str(exc))
        except FrameworkError as exc:
            errors.append(str(exc))

        schedule = None
        try:
            schedule = read_json(
                experiment_dir / "execution" / "schedule.json"
            )
        except FrameworkError as exc:
            errors.append(str(exc))

        if schedule:
            for run in schedule["runs"]:
                run_dir = (
                    experiment_dir
                    / "raw"
                    / "runs"
                    / run["run_id"]
                )
                valid = False

                if run_dir.is_dir():
                    for measurement_path in run_dir.glob(
                        "attempt-*/measurement.json"
                    ):
                        try:
                            measurement = read_json(measurement_path)
                            if measurement.get(
                                "execution", {}
                            ).get("valid") is True:
                                valid = True
                                break
                        except FrameworkError:
                            pass

                if not valid:
                    errors.append(
                        f"completed execution missing valid measurement: "
                        f"{run['run_id']}"
                    )

    if state and state.get("state") == "COMPLETE":
        errors.extend(validate_analysis_outputs(experiment_dir))

    return errors
