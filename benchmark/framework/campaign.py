from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from framework.io_utils import FrameworkError, read_json
from framework.host_state import normalize_measurement_control
from framework.provenance import sha256_file
from framework.validation import validate_request


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def campaign_definition_sha256(definition: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(definition)).hexdigest()


def _relative_repo_path(path: Path, repo_root: Path) -> str | None:
    try:
        return str(path.resolve().relative_to(repo_root.resolve()))
    except ValueError:
        return None


def resolve_campaign_config_path(text: str, repo_root: Path) -> Path:
    candidate = Path(text).expanduser()
    if candidate.is_absolute():
        path = candidate
    else:
        cwd_candidate = Path.cwd() / candidate
        repo_candidate = repo_root / candidate
        path = cwd_candidate if cwd_candidate.is_file() else repo_candidate

    path = path.resolve()
    if not path.is_file():
        raise FrameworkError(f"campaign config not found: {text}")
    return path


def _validate_artifact_record(record: Any, label: str) -> None:
    if not isinstance(record, dict):
        raise FrameworkError(f"{label} must be an object")
    path = record.get("path")
    digest = record.get("sha256")
    if not isinstance(path, str) or not path:
        raise FrameworkError(f"{label}.path must be a non-empty string")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise FrameworkError(f"{label}.sha256 must be a lowercase SHA-256 hex digest")


def _validate_campaign_definition(definition: dict[str, Any]) -> None:
    if definition.get("schema_version") != 1:
        raise FrameworkError("campaign schema_version must be 1")

    campaign = definition.get("campaign")
    if not isinstance(campaign, dict):
        raise FrameworkError("campaign must be an object")
    name = campaign.get("name")
    if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", name):
        raise FrameworkError("campaign.name must be a lowercase slug")

    experiment = definition.get("experiment")
    if not isinstance(experiment, dict):
        raise FrameworkError("experiment must be an object")

    repetitions = experiment.get("repetitions", 1)
    if not isinstance(repetitions, int) or isinstance(repetitions, bool) or repetitions < 1:
        raise FrameworkError("experiment.repetitions must be a positive integer")

    parameters = experiment.get("parameters", {})
    if not isinstance(parameters, dict):
        raise FrameworkError("experiment.parameters must be an object")
    if "repetitions" in parameters:
        raise FrameworkError("use experiment.repetitions, not parameters.repetitions")

    scheduling = experiment.get("scheduling")
    if scheduling is not None:
        if not isinstance(scheduling, dict):
            raise FrameworkError("experiment.scheduling must be an object")
        condition_order = scheduling.get("condition_order", "condition-major")
        variant_order = scheduling.get("variant_order", "pair-sequence")
        if condition_order not in {"condition-major", "rotating-rounds"}:
            raise FrameworkError("unsupported experiment.scheduling.condition_order")
        if variant_order not in {"pair-sequence", "alternate-by-repetition", "balanced-by-condition-round"}:
            raise FrameworkError("unsupported experiment.scheduling.variant_order")

    measurement_control = experiment.get("measurement_control")
    if measurement_control is not None:
        normalize_measurement_control(measurement_control)

    conditions = experiment.get("conditions")
    if not isinstance(conditions, list) or not conditions:
        raise FrameworkError("experiment.conditions must be a non-empty array")

    keyset: set[str] | None = None
    seen: set[bytes] = set()
    parameter_names = set(parameters)
    for index, condition in enumerate(conditions, start=1):
        if not isinstance(condition, dict) or not condition:
            raise FrameworkError(f"experiment.conditions[{index - 1}] must be a non-empty object")
        overlap = parameter_names.intersection(condition)
        if overlap:
            raise FrameworkError(
                "condition parameters must not overlap fixed parameters: "
                + ", ".join(sorted(overlap))
            )
        current_keys = set(condition)
        if keyset is None:
            keyset = current_keys
        elif current_keys != keyset:
            raise FrameworkError("all explicit conditions must use the same parameter keys")
        for key, value in condition.items():
            if isinstance(value, (list, dict)):
                raise FrameworkError(
                    f"explicit condition value {key!r} must be scalar, not {type(value).__name__}"
                )
        encoded = _canonical_json(condition)
        if encoded in seen:
            raise FrameworkError(f"duplicate explicit condition at index {index - 1}")
        seen.add(encoded)

    preparation = definition.get("preparation")
    if not isinstance(preparation, dict):
        raise FrameworkError("preparation must be an object")

    variants = experiment.get("variants")
    if not isinstance(variants, list) or not variants:
        raise FrameworkError("experiment.variants must be a non-empty array")

    binaries = preparation.get("binaries")
    if not isinstance(binaries, dict):
        raise FrameworkError("preparation.binaries must be an object")
    if set(binaries) != set(variants):
        raise FrameworkError("preparation.binaries must contain exactly one entry for every variant")
    for variant, record in binaries.items():
        _validate_artifact_record(record, f"preparation.binaries.{variant}")

    libraries = preparation.get("runtime_libraries", {})
    if not isinstance(libraries, dict):
        raise FrameworkError("preparation.runtime_libraries must be an object")
    unknown = set(libraries).difference(variants)
    if unknown:
        raise FrameworkError(
            "runtime library references unknown variants: " + ", ".join(sorted(unknown))
        )
    for variant, records in libraries.items():
        if not isinstance(records, list):
            raise FrameworkError(f"preparation.runtime_libraries.{variant} must be an array")
        for index, record in enumerate(records):
            _validate_artifact_record(
                record,
                f"preparation.runtime_libraries.{variant}[{index}]",
            )

    source_requirements = preparation.get("source_requirements", {})
    if not isinstance(source_requirements, dict):
        raise FrameworkError("preparation.source_requirements must be an object")
    for name, requirement in source_requirements.items():
        if not isinstance(requirement, dict):
            raise FrameworkError(f"source requirement {name!r} must be an object")
        if not isinstance(requirement.get("path"), str):
            raise FrameworkError(f"source requirement {name!r}.path must be a string")
        commit = requirement.get("commit")
        if commit is not None and (not isinstance(commit, str) or not commit):
            raise FrameworkError(f"source requirement {name!r}.commit must be a string")
        tracked_clean = requirement.get("tracked_clean", False)
        if not isinstance(tracked_clean, bool):
            raise FrameworkError(f"source requirement {name!r}.tracked_clean must be boolean")

    request = request_from_campaign(definition)
    validate_request(request)


def load_campaign_definition(path: Path, repo_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    definition = read_json(path)
    if not isinstance(definition, dict):
        raise FrameworkError("campaign config root must be an object")
    _validate_campaign_definition(definition)

    raw_sha = sha256_file(path)
    canonical_sha = campaign_definition_sha256(definition)
    source_path = _relative_repo_path(path, repo_root)
    record = {
        "schema_version": 1,
        "campaign_name": definition["campaign"]["name"],
        "definition_sha256": canonical_sha,
        "source": {
            "path": source_path,
            "basename": path.name,
            "sha256": raw_sha,
        },
        "definition": definition,
    }
    return definition, record


def request_from_campaign(definition: dict[str, Any]) -> dict[str, Any]:
    experiment = definition["experiment"]
    parameters = dict(experiment.get("parameters") or {})
    parameters["repetitions"] = experiment.get("repetitions", 1)
    request: dict[str, Any] = {
        "workload": experiment["workload"],
        "environment": experiment["environment"],
        "variants": list(experiment["variants"]),
        "parameters": parameters,
        "conditions": [dict(row) for row in experiment["conditions"]],
    }
    comparison = experiment.get("comparison")
    if comparison is not None:
        request["comparison"] = dict(comparison)
    scheduling = experiment.get("scheduling")
    if scheduling is not None:
        request["scheduling"] = dict(scheduling)
    measurement_control = experiment.get("measurement_control")
    if measurement_control is not None:
        request["measurement_control"] = normalize_measurement_control(measurement_control)
    alias = experiment.get("alias") or definition["campaign"].get("alias")
    if alias is not None:
        request["alias"] = alias
    return request


def _resolve_repo_artifact(path_text: str, repo_root: Path) -> Path:
    path = Path(path_text).expanduser()
    if not path.is_absolute():
        path = repo_root / path
    return path.resolve()


def _verify_artifact(record: dict[str, Any], repo_root: Path, label: str) -> Path:
    path = _resolve_repo_artifact(record["path"], repo_root)
    if not path.is_file():
        raise FrameworkError(f"campaign artifact is missing for {label}: {path}")
    actual = sha256_file(path)
    if actual != record["sha256"]:
        raise FrameworkError(
            f"campaign artifact SHA-256 mismatch for {label}: "
            f"expected {record['sha256']}, got {actual}"
        )
    return path


def preparation_specs(definition: dict[str, Any], repo_root: Path) -> dict[str, list[str]]:
    preparation = definition["preparation"]
    binary_specs: list[str] = []
    library_specs: list[str] = []

    for variant, record in preparation["binaries"].items():
        path = _verify_artifact(record, repo_root, f"binary {variant}")
        binary_specs.append(f"{variant}={path}")

    for variant, records in preparation.get("runtime_libraries", {}).items():
        for index, record in enumerate(records):
            path = _verify_artifact(
                record,
                repo_root,
                f"runtime library {variant}[{index}]",
            )
            library_specs.append(f"{variant}={path}")

    source_specs: list[str] = []
    for item in preparation.get("sources", []):
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("path"), str):
            raise FrameworkError("preparation.sources entries require name and path")
        path = _resolve_repo_artifact(item["path"], repo_root)
        source_specs.append(f"{item['name']}={path}")

    preflight_specs: list[str] = []
    for item in preparation.get("preflight", []):
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("command"), str):
            raise FrameworkError("preparation.preflight entries require name and command")
        preflight_specs.append(f"{item['name']}={item['command']}")

    return {
        "binary": binary_specs,
        "runtime_library": library_specs,
        "source": source_specs,
        "preflight": preflight_specs,
    }


def verify_source_requirements(definition: dict[str, Any], repo_root: Path) -> None:
    requirements = definition["preparation"].get("source_requirements", {})
    for name, requirement in requirements.items():
        path = Path(requirement["path"]).expanduser()
        if not path.is_absolute():
            path = repo_root / path
        path = path.resolve()
        if not path.is_dir():
            raise FrameworkError(f"required source {name!r} is missing: {path}")

        def git(*argv: str) -> str:
            result = subprocess.run(
                ["git", "-C", str(path), *argv],
                check=False,
                text=True,
                capture_output=True,
            )
            if result.returncode != 0:
                raise FrameworkError(
                    f"unable to inspect required source {name!r}: {result.stderr.strip()}"
                )
            return result.stdout.strip()

        expected_commit = requirement.get("commit")
        if expected_commit is not None:
            actual_commit = git("rev-parse", "HEAD")
            if actual_commit != expected_commit:
                raise FrameworkError(
                    f"required source {name!r} commit mismatch: "
                    f"expected {expected_commit}, got {actual_commit}"
                )

        if requirement.get("tracked_clean", False):
            status = git("status", "--porcelain", "--untracked-files=no")
            if status:
                raise FrameworkError(f"required source {name!r} has tracked changes")


def campaign_record_matches(experiment_dir: Path, definition_sha256: str) -> bool:
    path = experiment_dir / "config" / "campaign.json"
    if not path.is_file():
        return False
    try:
        record = read_json(path)
    except FrameworkError:
        return False
    return record.get("definition_sha256") == definition_sha256


def discover_campaign_instances(
    experiments_root: Path,
    *,
    campaign_name: str,
    definition_sha256: str,
) -> dict[str, list[Path]]:
    exact_incomplete: list[Path] = []
    exact_complete: list[Path] = []
    name_drift_incomplete: list[Path] = []

    if not experiments_root.is_dir():
        return {
            "exact_incomplete": [],
            "exact_complete": [],
            "name_drift_incomplete": [],
        }

    for experiment_dir in sorted(experiments_root.iterdir()):
        if not experiment_dir.is_dir():
            continue
        campaign_path = experiment_dir / "config" / "campaign.json"
        state_path = experiment_dir / "state.json"
        if not campaign_path.is_file() or not state_path.is_file():
            continue
        try:
            record = read_json(campaign_path)
            state = read_json(state_path).get("state")
        except FrameworkError:
            continue
        if record.get("campaign_name") != campaign_name:
            continue
        exact = record.get("definition_sha256") == definition_sha256
        if exact and state == "COMPLETE":
            exact_complete.append(experiment_dir)
        elif exact:
            exact_incomplete.append(experiment_dir)
        elif state != "COMPLETE":
            name_drift_incomplete.append(experiment_dir)

    return {
        "exact_incomplete": exact_incomplete,
        "exact_complete": exact_complete,
        "name_drift_incomplete": name_drift_incomplete,
    }


def preparation_complete(experiment_dir: Path) -> bool:
    required = (
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
    if not all((experiment_dir / rel).is_file() for rel in required):
        return False
    try:
        generic = read_json(experiment_dir / "provenance" / "preflight.json")
        workload = read_json(experiment_dir / "execution" / "workload" / "preflight.json")
    except FrameworkError:
        return False
    return bool(generic.get("passed")) and bool(workload.get("passed"))


def next_campaign_stage(experiment_dir: Path) -> str:
    state = read_json(experiment_dir / "state.json")
    lifecycle = state.get("state")

    if lifecycle == "PREPARING":
        if not (experiment_dir / "execution" / "schedule.json").is_file():
            return "plan"
        return "seal" if preparation_complete(experiment_dir) else "prepare"

    if lifecycle == "FAILED":
        stage = (state.get("failure") or {}).get("stage")
        if stage == "preparing":
            return "prepare"
        if stage == "running":
            return "execute"
        if stage == "analyzing":
            return "analyze"
        raise FrameworkError(f"cannot resume FAILED campaign with unknown failure stage: {stage!r}")

    mapping = {
        "READY": "execute",
        "RUNNING": "execute",
        "ABORTED": "execute",
        "ANALYZING": "analyze",
        "COMPLETE": "complete",
    }
    if lifecycle in mapping:
        return mapping[lifecycle]
    raise FrameworkError(f"campaign cannot continue from lifecycle state: {lifecycle!r}")


def verify_active_framework_identity(experiment_dir: Path, repo_root: Path) -> None:
    manifest_path = experiment_dir / "manifest.json"
    if not manifest_path.is_file():
        return
    manifest = read_json(manifest_path)
    expected = (manifest.get("framework") or {}).get("commit")
    if not expected:
        raise FrameworkError("sealed manifest is missing framework commit")

    result = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise FrameworkError(
            "unable to inspect current framework commit: "
            + result.stderr.strip()
        )
    actual = result.stdout.strip()
    if actual != expected:
        raise FrameworkError(
            "refusing to resume sealed campaign with a different framework "
            f"commit: sealed={expected}, current={actual}"
        )
