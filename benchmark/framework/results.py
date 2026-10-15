from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import math
import re
import statistics
import subprocess
import tarfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from framework.io_utils import (
    FrameworkError,
    atomic_write_json,
    atomic_write_text,
    read_json,
)
from framework.paired_execution import analyze_paired_results


RESULT_SCHEMA_VERSION = 1
SUPPORTED_PROTOCOL = "r6.5.4.5"
EXECUTION_TAG = "r6.5.4.5-execution"

EXPECTED_RUNS = 96
EXPECTED_PAIRS = 48
EXPECTED_CONDITIONS = 12
EXPECTED_REPETITIONS = 4

VARIANTS = ("stock", "ngi541-direct")

METRICS = (
    "application_goodput_mbps",
    "dut_process_cpu_seconds_per_gib",
    "dut_estimated_energy_j_per_gib",
)


def _must(condition: bool, message: str) -> None:
    if not condition:
        raise FrameworkError(message)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def _semantic_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return hashlib.sha256(payload).hexdigest()


def _json_text(value: Any) -> str:
    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n"
    )


def _manifest_yaml_text(value: Any) -> str:
    # JSON is a valid YAML 1.2 document.
    #
    # Using this strict subset avoids adding PyYAML as a runtime
    # dependency and gives deterministic serialization.
    return _json_text(value)


def _resolve_under_repo(
    path: Path,
    repo_root: Path,
    label: str,
) -> Path:
    candidate = path.expanduser()

    if not candidate.is_absolute():
        cwd_candidate = (Path.cwd() / candidate).resolve()
        repo_candidate = (repo_root / candidate).resolve()

        candidate = (
            cwd_candidate
            if cwd_candidate.exists()
            else repo_candidate
        )
    else:
        candidate = candidate.resolve()

    try:
        candidate.relative_to(repo_root.resolve())
    except ValueError as exc:
        raise FrameworkError(
            f"{label} must be inside repository root: "
            f"{candidate}"
        ) from exc

    return candidate


def _verify_inventory(
    root: Path,
    *,
    allowed_unrecorded: set[str] | None = None,
) -> dict[str, Any]:
    inventory = root / "artifacts.sha256"

    _must(
        inventory.is_file(),
        f"missing artifact inventory: {inventory}",
    )

    recorded: dict[str, str] = {}

    for number, raw in enumerate(
        inventory.read_text(
            encoding="utf-8"
        ).splitlines(),
        start=1,
    ):
        if not raw.strip():
            continue

        try:
            sha256, relative = raw.split("  ", 1)
        except ValueError as exc:
            raise FrameworkError(
                f"malformed inventory line "
                f"{number}: {inventory}"
            ) from exc

        _must(
            bool(
                re.fullmatch(
                    r"[0-9a-f]{64}",
                    sha256,
                )
            ),
            f"invalid SHA in "
            f"{inventory}:{number}",
        )

        relative_path = Path(relative)

        _must(
            not relative_path.is_absolute()
            and ".." not in relative_path.parts,
            f"unsafe inventory path: {relative}",
        )

        _must(
            relative not in recorded,
            f"duplicate inventory path: "
            f"{relative}",
        )

        recorded[relative] = sha256

    recorded_set = set(recorded)

    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if (
            path.is_file()
            and path.name
            != "artifacts.sha256"
        )
    }

    missing = sorted(
        recorded_set - actual
    )

    _must(
        not missing,
        "artifact inventory is missing "
        "recorded files: "
        + ", ".join(missing),
    )

    allowed = set(
        allowed_unrecorded
        or set()
    )

    unrecorded = sorted(
        actual - recorded_set
    )

    unexpected = sorted(
        set(unrecorded) - allowed
    )

    _must(
        not unexpected,
        "artifact inventory has "
        "unexpected unrecorded files: "
        + ", ".join(unexpected),
    )

    for relative, expected in recorded.items():
        path = root / relative

        _must(
            _sha256_file(path) == expected,
            f"artifact SHA mismatch: {path}",
        )

    return {
        "semantics":
            (
                "recorded-files-sha256-with-"
                "explicit-unrecorded-allowlist"
                if allowed
                else "exact-file-set-sha256"
            ),
        "recorded_entry_count":
            len(recorded),
        "unrecorded_files":
            unrecorded,
        "allowed_unrecorded_files":
            sorted(allowed),
        "inventory_sha256":
            _sha256_file(inventory),
    }



def _read_jsonl(
    path: Path,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as handle:

        for number, raw in enumerate(
            handle,
            start=1,
        ):
            line = raw.strip()

            if not line:
                continue

            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise FrameworkError(
                    f"invalid JSONL in "
                    f"{path}:{number}: "
                    f"{exc}"
                ) from exc

            _must(
                isinstance(value, dict),
                f"JSONL row must be "
                f"an object: "
                f"{path}:{number}",
            )

            result.append(value)

    return result


def _strict_nominal_loadgen_samples(
    path: Path,
    *,
    warmup_seconds: float,
    measurement_seconds: float,
) -> list[dict[str, Any]]:

    rows = _read_jsonl(path)

    _must(
        bool(rows),
        f"empty loadgen telemetry: {path}",
    )

    first_monotonic_ns = rows[0].get(
        "monotonic_ns"
    )

    _must(
        isinstance(first_monotonic_ns, int),
        "loadgen telemetry is missing "
        f"the first-sample monotonic anchor: {path}",
    )

    start_ns = (
        int(first_monotonic_ns)
        + int(
            float(warmup_seconds)
            * 1_000_000_000
        )
    )

    end_ns = (
        int(first_monotonic_ns)
        + int(
            (
                float(warmup_seconds)
                + float(measurement_seconds)
            )
            * 1_000_000_000
        )
    )

    selected = [
        row
        for row in rows
        if (
            isinstance(
                row.get("monotonic_ns"),
                int,
            )
            and start_ns
            <= int(row["monotonic_ns"])
            < end_ns
        )
    ]

    _must(
        len(selected) >= 2,
        "strict nominal remote MAIN "
        f"contains fewer than two samples: {path}",
    )

    return selected


def _attempt_count(
    value: Any,
) -> int:
    if isinstance(value, list):
        return len(value)

    if (
        isinstance(value, int)
        and not isinstance(value, bool)
    ):
        return value

    if isinstance(value, float):
        _must(
            value.is_integer(),
            "non-integral lifecycle attempt count",
        )
        return int(value)

    if value is None:
        return 0

    raise FrameworkError(
        "unsupported lifecycle attempts shape: "
        f"{type(value).__name__}"
    )


def _timestamp_from_id(
    value: str,
) -> str:
    match = re.search(
        r"(\d{8}T\d{6}Z)",
        value,
    )

    if match is None:
        raise FrameworkError(
            "unable to derive timestamp "
            f"from identifier: {value}"
        )

    return match.group(1)


def _result_id(
    summary: dict[str, Any],
    frozen: dict[str, Any],
) -> str:
    protocol = str(
        summary[
            "measurement_protocol_revision"
        ]
    ).replace(".", "-")

    timestamp = _timestamp_from_id(
        str(summary["experiment_id"])
    )

    input_sha = str(
        frozen[
            "resolved_execution_input_sha256"
        ]
    )

    _must(
        bool(
            re.fullmatch(
                r"[0-9a-f]{64}",
                input_sha,
            )
        ),
        "invalid resolved execution "
        "input SHA",
    )

    return (
        f"{protocol}-"
        f"http3-paired-result-"
        f"{timestamp}-"
        f"{input_sha[:6]}"
    )


def _run_git(
    repo_root: Path,
    *args: str,
    required: bool = True,
) -> str | None:
    result = subprocess.run(
        [
            "git",
            *args,
        ],
        cwd=repo_root,
        check=False,
        text=True,
        capture_output=True,
    )

    if result.returncode != 0:
        if required:
            raise FrameworkError(
                "git "
                + " ".join(args)
                + " failed: "
                + (
                    result.stderr
                    or result.stdout
                ).strip()
            )

        return None

    return result.stdout.strip()


def _generator_source(
    repo_root: Path,
) -> dict[str, Any]:
    commit = _run_git(
        repo_root,
        "rev-parse",
        "HEAD",
    )

    _must(
        bool(
            commit
            and re.fullmatch(
                r"[0-9a-f]{40,64}",
                commit,
            )
        ),
        "invalid result-generator commit",
    )

    tracked_status = _run_git(
        repo_root,
        "status",
        "--porcelain",
        "--untracked-files=no",
    )

    _must(
        tracked_status == "",
        "tracked worktree must be clean "
        "before publication artifact generation",
    )

    return {
        "repository": "ngi541-nginx",
        "commit": commit,
        "tracked_worktree_clean": True,
        "module": "benchmark/framework/results.py",
    }


def _execution_source(
    repo_root: Path,
) -> dict[str, Any]:
    commit = _run_git(
        repo_root,
        "rev-parse",
        f"{EXECUTION_TAG}^{{commit}}",
    )

    _must(
        bool(
            commit
            and re.fullmatch(
                r"[0-9a-f]{40,64}",
                commit,
            )
        ),
        "invalid execution tag commit",
    )

    remote = _run_git(
        repo_root,
        "remote",
        "get-url",
        "origin",
        required=False,
    )

    return {
        "repository": "ngi541-nginx",
        "execution_tag": EXECUTION_TAG,
        "execution_commit": commit,
        "remote": remote,
        "relationship":
            "post-execution archival commit "
            "of the exact qualified "
            "implementation",
    }


def _validate_h2load_raw(
    run_root: Path,
    row: dict[str, Any],
) -> None:
    path = (
        run_root
        / "h2load-result.json"
    )

    _must(
        path.is_file(),
        f"missing h2load result: {path}",
    )

    value = read_json(path)

    measurements = (
        value.get("measurements")
        if isinstance(value, dict)
        else None
    )

    _must(
        isinstance(
            measurements,
            dict,
        ),
        f"invalid h2load result "
        f"structure: {path}",
    )

    requests = measurements.get(
        "requests"
    )

    _must(
        isinstance(
            requests,
            dict,
        ),
        f"missing h2load request "
        f"accounting: {path}",
    )

    for field in (
        "failed",
        "errored",
    ):
        _must(
            int(
                requests.get(
                    field,
                    0,
                )
            )
            == 0,
            f"h2load {field} != 0 "
            f"for {row['run_id']}",
        )

    _must(
        int(
            requests.get(
                "timeout",
                0,
            )
        )
        == 0,
        "h2load timeout != 0 "
        f"for {row['run_id']}",
    )


def _validate_campaign(
    experiment_root: Path,
) -> dict[str, Any]:

    inventory = _verify_inventory(
        experiment_root
    )

    required = (
        "definition.json",
        "inputs/frozen-inputs.json",
        "processed/schedule.json",
        "processed/run-results.json",
        "processed/paired-analysis.json",
        "processed/summary.json",
    )

    for relative in required:
        _must(
            (
                experiment_root
                / relative
            ).is_file(),
            "missing campaign artifact: "
            f"{relative}",
        )

    definition = read_json(
        experiment_root
        / "definition.json"
    )

    frozen = read_json(
        experiment_root
        / "inputs"
        / "frozen-inputs.json"
    )

    schedule_document = read_json(
        experiment_root
        / "processed"
        / "schedule.json"
    )

    run_document = read_json(
        experiment_root
        / "processed"
        / "run-results.json"
    )

    analysis = read_json(
        experiment_root
        / "processed"
        / "paired-analysis.json"
    )

    summary = read_json(
        experiment_root
        / "processed"
        / "summary.json"
    )

    _must(
        summary.get("status")
        == "COMPLETE",
        "source campaign "
        "is not COMPLETE",
    )

    _must(
        summary.get(
            "measurement_protocol_revision"
        )
        == SUPPORTED_PROTOCOL,
        "unsupported measurement protocol",
    )

    _must(
        summary.get(
            "experiment_id"
        )
        == experiment_root.name,
        "source experiment "
        "identity mismatch",
    )

    _must(
        summary.get("run_count")
        == EXPECTED_RUNS,
        "source campaign "
        "run count mismatch",
    )

    _must(
        summary.get("pair_count")
        == EXPECTED_PAIRS,
        "source campaign "
        "pair count mismatch",
    )

    _must(
        summary.get(
            "condition_count"
        )
        == EXPECTED_CONDITIONS,
        "source condition "
        "count mismatch",
    )

    _must(
        summary.get("repetitions")
        == EXPECTED_REPETITIONS,
        "source repetition "
        "count mismatch",
    )

    _must(
        summary.get("variants")
        == list(VARIANTS),
        "source variants mismatch",
    )

    _must(
        summary.get(
            "adaptive_replanning"
        )
        == "prohibited",
        "adaptive replanning "
        "policy mismatch",
    )

    _must(
        summary.get(
            "metric_dependent_retry"
        )
        == "prohibited",
        "retry policy mismatch",
    )

    _must(
        summary.get(
            "outlier_deletion"
        )
        == "none",
        "outlier policy mismatch",
    )

    _must(
        summary.get(
            "measurement_window_selection"
        )
        == "strict-main-no-tolerance",
        "MAIN selection policy mismatch",
    )

    _must(
        summary.get(
            "scientific_byte_accounting"
        )
        == "h2load-main-phase-body-bytes",
        "scientific byte "
        "accounting mismatch",
    )

    _must(
        summary.get("resumed")
        is False,
        "accepted publication campaign "
        "must not be resumed",
    )

    _must(
        _semantic_sha256(
            definition
        )
        == frozen.get(
            "definition_sha256"
        ),
        "definition semantic "
        "SHA mismatch",
    )

    schedule = (
        schedule_document.get(
            "runs"
        )
    )

    _must(
        isinstance(
            schedule,
            list,
        )
        and len(schedule)
        == EXPECTED_RUNS,
        "schedule run "
        "count mismatch",
    )

    _must(
        _semantic_sha256(
            schedule
        )
        == frozen.get(
            "schedule_sha256"
        ),
        "schedule semantic "
        "SHA mismatch",
    )

    _must(
        summary.get(
            "freeze_sha256"
        )
        == frozen.get(
            "freeze_sha256"
        ),
        "freeze SHA linkage mismatch",
    )

    _must(
        summary.get(
            "workload_plan_sha256"
        )
        == frozen.get(
            "workload_plan_sha256"
        ),
        "workload-plan SHA "
        "linkage mismatch",
    )

    runs = run_document.get(
        "runs"
    )

    _must(
        run_document.get(
            "run_count"
        )
        == EXPECTED_RUNS,
        "processed run-results "
        "count mismatch",
    )

    _must(
        isinstance(
            runs,
            list,
        )
        and len(runs)
        == EXPECTED_RUNS,
        "processed runs malformed",
    )

    _must(
        [
            int(row["sequence"])
            for row in runs
        ]
        == list(
            range(
                1,
                EXPECTED_RUNS + 1,
            )
        ),
        "run sequence is not "
        "exact 1..96",
    )

    _must(
        len(
            {
                row["run_id"]
                for row in runs
            }
        )
        == EXPECTED_RUNS,
        "duplicate run_id",
    )

    _must(
        Counter(
            row["variant"]
            for row in runs
        )
        == Counter(
            {
                "stock": 48,
                "ngi541-direct": 48,
            }
        ),
        "variant balance mismatch",
    )

    condition_counts = Counter(
        row["condition_id"]
        for row in runs
    )

    _must(
        len(condition_counts)
        == EXPECTED_CONDITIONS,
        "condition cardinality mismatch",
    )

    _must(
        set(
            condition_counts.values()
        )
        == {8},
        "each condition must "
        "contain 8 runs",
    )

    pairs: dict[
        str,
        list[dict[str, Any]],
    ] = defaultdict(list)

    for row in runs:
        pairs[
            str(row["pair_id"])
        ].append(row)

    _must(
        len(pairs)
        == EXPECTED_PAIRS,
        "pair cardinality mismatch",
    )

    first_by_condition: dict[
        str,
        Counter[str],
    ] = defaultdict(Counter)

    for pair_id, pair_rows in pairs.items():
        _must(
            len(pair_rows) == 2,
            f"{pair_id} does not "
            "contain two runs",
        )

        _must(
            {
                row["variant"]
                for row in pair_rows
            }
            == set(VARIANTS),
            f"{pair_id} "
            "variant mismatch",
        )

        _must(
            len(
                {
                    row["condition_id"]
                    for row in pair_rows
                }
            )
            == 1,
            f"{pair_id} "
            "condition mismatch",
        )

        _must(
            len(
                {
                    int(
                        row["repetition"]
                    )
                    for row in pair_rows
                }
            )
            == 1,
            f"{pair_id} "
            "repetition mismatch",
        )

        order = str(
            pair_rows[0]["pair_order"]
        ).split("/")

        _must(
            order
            in (
                [
                    "stock",
                    "ngi541-direct",
                ],
                [
                    "ngi541-direct",
                    "stock",
                ],
            ),
            f"{pair_id} "
            "pair order invalid",
        )

        first_by_condition[
            pair_rows[0][
                "condition_id"
            ]
        ][order[0]] += 1

    for (
        condition_id,
        counts,
    ) in first_by_condition.items():

        _must(
            counts
            == Counter(
                {
                    "stock": 2,
                    "ngi541-direct": 2,
                }
            ),
            "pair-order balance "
            f"mismatch: {condition_id}",
        )

    udp_rows: list[
        dict[str, Any]
    ] = []

    multi_readiness: list[str] = []
    multi_release: list[str] = []

    for row in runs:
        run_id = str(
            row["run_id"]
        )

        raw_root = (
            experiment_root
            / "raw"
            / run_id
        )

        raw_result = read_json(
            raw_root
            / "run-result.json"
        )

        _must(
            raw_result == row,
            "raw/processed run-result "
            f"mismatch: {run_id}",
        )

        validity = row.get(
            "validity",
            {},
        )

        _must(
            validity.get("valid")
            is True
            and validity.get(
                "reasons"
            )
            == [],
            "frozen validity failed: "
            f"{run_id}",
        )

        metrics = row.get(
            "metrics",
            {},
        )

        for metric in METRICS:
            _must(
                isinstance(
                    metrics.get(metric),
                    (
                        int,
                        float,
                    ),
                ),
                "missing primary metric "
                f"{metric}: {run_id}",
            )

        _must(
            float(
                metrics[
                    "application_goodput_mbps"
                ]
            )
            > 0.0,
            "zero application goodput: "
            f"{run_id}",
        )

        diagnostics = row.get(
            "diagnostics",
            {},
        )

        _must(
            diagnostics.get(
                "scientific_byte_accounting"
            )
            == (
                "h2load-main-phase-"
                "body-bytes"
            ),
            "byte accounting mismatch: "
            f"{run_id}",
        )

        _must(
            diagnostics.get(
                "h2load_accounting_anomaly"
            )
            is False,
            "h2load accounting anomaly: "
            f"{run_id}",
        )

        _must(
            int(
                diagnostics.get(
                    "requests_started"
                )
                or 0
            )
            > 0,
            "zero-traffic run: "
            f"{run_id}",
        )

        telemetry = row.get(
            "telemetry_window",
            {},
        )

        _must(
            telemetry.get(
                "measurement_window_selection"
            )
            == "strict-main-no-tolerance",
            "telemetry selection "
            f"mismatch: {run_id}",
        )

        _must(
            float(
                telemetry.get(
                    "warmup_seconds"
                )
            )
            == 5.0,
            "warmup mismatch: "
            f"{run_id}",
        )

        _must(
            float(
                telemetry.get(
                    "measurement_seconds"
                )
            )
            == 20.0,
            "MAIN duration mismatch: "
            f"{run_id}",
        )

        _must(
            telemetry.get(
                "dut_exact_window_boundary_covered"
            )
            is True,
            "DUT exact-window boundary "
            f"missing: {run_id}",
        )

        _must(
            int(
                telemetry.get(
                    "dut_samples"
                )
                or 0
            )
            >= 2,
            "insufficient DUT telemetry: "
            f"{run_id}",
        )

        _must(
            int(
                telemetry.get(
                    "loadgen_samples"
                )
                or 0
            )
            >= 2,
            "insufficient loadgen telemetry: "
            f"{run_id}",
        )

        _validate_h2load_raw(
            raw_root,
            row,
        )

        prestart = read_json(
            raw_root
            / "server-prestart-port.json"
        )

        readiness = read_json(
            raw_root
            / "server-readiness.json"
        )

        release = read_json(
            raw_root
            / "server-release.json"
        )

        _must(
            prestart.get(
                "stable_bindable",
                prestart.get(
                    "bindable"
                ),
            )
            is True,
            "prestart lifecycle failed: "
            f"{run_id}",
        )

        _must(
            readiness.get("passed")
            is True,
            "server readiness failed: "
            f"{run_id}",
        )

        _must(
            release.get("released")
            is True,
            "server release failed: "
            f"{run_id}",
        )

        if _attempt_count(
            readiness.get("attempts")
        ) > 1:
            multi_readiness.append(
                run_id
            )

        if _attempt_count(
            release.get("attempts")
        ) > 1:
            multi_release.append(
                run_id
            )

        warmup = float(
            telemetry[
                "warmup_seconds"
            ]
        )

        main = float(
            telemetry[
                "measurement_seconds"
            ]
        )

        loadgen_samples = (
            _strict_nominal_loadgen_samples(
                raw_root
                / "loadgen-telemetry.jsonl",
                warmup_seconds=warmup,
                measurement_seconds=main,
            )
        )

        _must(
            len(loadgen_samples)
            == int(
                telemetry[
                    "loadgen_samples"
                ]
            ),
            "strict loadgen sample "
            f"count mismatch: {run_id}",
        )

        dut_rows = _read_jsonl(
            raw_root
            / "dut-telemetry.jsonl"
        )

        _must(
            len(dut_rows)
            >= int(
                telemetry[
                    "dut_samples"
                ]
            ),
            "DUT telemetry raw data "
            f"incomplete: {run_id}",
        )

        udp_first = (
            loadgen_samples[0]
            .get(
                "udp",
                {},
            )
            .get(
                "in_errors"
            )
        )

        udp_last = (
            loadgen_samples[-1]
            .get(
                "udp",
                {},
            )
            .get(
                "in_errors"
            )
        )

        _must(
            isinstance(
                udp_first,
                (
                    int,
                    float,
                ),
            )
            and isinstance(
                udp_last,
                (
                    int,
                    float,
                ),
            ),
            "missing UDP counters: "
            f"{run_id}",
        )

        udp_delta = (
            float(udp_last)
            - float(udp_first)
        )

        stated_udp = metrics.get(
            "udp_in_errors_delta"
        )

        _must(
            isinstance(
                stated_udp,
                (
                    int,
                    float,
                ),
            )
            and math.isclose(
                float(stated_udp),
                udp_delta,
                rel_tol=0.0,
                abs_tol=1e-12,
            ),
            "UDP delta mismatch: "
            f"{run_id}",
        )

        network_first = (
            loadgen_samples[0]
            .get(
                "network",
                {},
            )
        )

        network_last = (
            loadgen_samples[-1]
            .get(
                "network",
                {},
            )
        )

        rx_packets_delta = (
            int(
                network_last.get(
                    "rx_packets",
                    0,
                )
            )
            - int(
                network_first.get(
                    "rx_packets",
                    0,
                )
            )
        )

        rx_errors_delta = (
            int(
                network_last.get(
                    "rx_errors",
                    0,
                )
            )
            - int(
                network_first.get(
                    "rx_errors",
                    0,
                )
            )
        )

        rx_dropped_delta = (
            int(
                network_last.get(
                    "rx_dropped",
                    0,
                )
            )
            - int(
                network_first.get(
                    "rx_dropped",
                    0,
                )
            )
        )

        if udp_delta > 0:
            udp_rows.append(
                {
                    "run_id":
                        run_id,
                    "variant":
                        row["variant"],
                    "condition_id":
                        row[
                            "condition_id"
                        ],
                    "udp_in_errors_delta":
                        udp_delta,
                    "rx_packets_delta":
                        rx_packets_delta,
                    "udp_errors_per_million_rx_packets":
                        (
                            udp_delta
                            / rx_packets_delta
                            * 1_000_000.0
                            if rx_packets_delta
                            > 0
                            else None
                        ),
                    "nic_rx_errors_delta":
                        rx_errors_delta,
                    "nic_rx_dropped_delta":
                        rx_dropped_delta,
                }
            )

    fresh_analysis = (
        analyze_paired_results(
            runs
        )
    )

    _must(
        fresh_analysis == analysis,
        "paired-analysis.json differs "
        "from fresh recomputation",
    )

    _must(
        analysis.get(
            "pair_count"
        )
        == EXPECTED_PAIRS,
        "paired analysis "
        "pair count mismatch",
    )

    _must(
        analysis.get(
            "outlier_deletion"
        )
        == "none",
        "paired analysis "
        "outlier policy mismatch",
    )

    udp_summary = {
        "classification":
            "diagnostic-not-frozen-validity-gate",
        "affected_runs":
            len(udp_rows),
        "total_delta":
            sum(
                float(
                    row[
                        "udp_in_errors_delta"
                    ]
                )
                for row in udp_rows
            ),
        "max_delta":
            max(
                (
                    float(
                        row[
                            "udp_in_errors_delta"
                        ]
                    )
                    for row
                    in udp_rows
                ),
                default=0.0,
            ),
        "by_variant":
            dict(
                Counter(
                    row["variant"]
                    for row
                    in udp_rows
                )
            ),
        "conditions":
            sorted(
                {
                    row[
                        "condition_id"
                    ]
                    for row
                    in udp_rows
                }
            ),
        "nic_rx_errors_delta_total":
            sum(
                int(
                    row[
                        "nic_rx_errors_delta"
                    ]
                )
                for row
                in udp_rows
            ),
        "nic_rx_dropped_delta_total":
            sum(
                int(
                    row[
                        "nic_rx_dropped_delta"
                    ]
                )
                for row
                in udp_rows
            ),
        "runs":
            udp_rows,
    }

    return {
        "definition":
            definition,
        "frozen":
            frozen,
        "schedule":
            schedule_document,
        "runs":
            runs,
        "analysis":
            analysis,
        "summary":
            summary,
        "source_inventory":
            inventory,
        "udp":
            udp_summary,
        "performance_lifecycle": {
            "runs_passed":
                EXPECTED_RUNS,
            "multi_readiness":
                multi_readiness,
            "multi_release":
                multi_release,
        },
    }


def _select_lifecycle_qualification(
    repo_root: Path,
    *,
    campaign_summary: dict[str, Any],
    frozen: dict[str, Any],
) -> tuple[
    Path,
    dict[str, Any],
]:
    base = (
        repo_root
        / "qualifications"
        / "server-lifecycle"
    )

    _must(
        base.is_dir(),
        "server-lifecycle qualification "
        "root is missing",
    )

    campaign_timestamp = (
        _timestamp_from_id(
            str(
                campaign_summary[
                    "experiment_id"
                ]
            )
        )
    )

    matches: list[
        tuple[
            str,
            Path,
            dict[str, Any],
        ]
    ] = []

    for child in sorted(
        path
        for path in base.iterdir()
        if path.is_dir()
    ):
        summary_path = (
            child
            / "processed"
            / "summary.json"
        )

        if not summary_path.is_file():
            continue

        try:
            summary = read_json(
                summary_path
            )
            timestamp = (
                _timestamp_from_id(
                    child.name
                )
            )
        except FrameworkError:
            continue

        if timestamp > campaign_timestamp:
            continue

        if (
            summary.get("status")
            != "COMPLETE"
        ):
            continue

        if (
            summary.get(
                "measurement_protocol_revision"
            )
            != campaign_summary.get(
                "measurement_protocol_revision"
            )
        ):
            continue

        if (
            summary.get(
                "paired_definition_sha256"
            )
            != frozen.get(
                "definition_sha256"
            )
        ):
            continue

        if (
            summary.get(
                "final_freeze_sha256"
            )
            != campaign_summary.get(
                "freeze_sha256"
            )
        ):
            continue

        if not (
            summary.get(
                "cycles_planned"
            )
            == 64
            and summary.get(
                "cycles_passed"
            )
            == 64
            and summary.get(
                "cycles_failed"
            )
            == 0
            and summary.get(
                "stock_cycles"
            )
            == 32
            and summary.get(
                "ngi541_direct_cycles"
            )
            == 32
            and summary.get(
                "worker_1_cycles"
            )
            == 32
            and summary.get(
                "worker_4_cycles"
            )
            == 32
        ):
            continue

        results = summary.get(
            "results"
        )

        if not (
            isinstance(
                results,
                list,
            )
            and len(results) == 64
            and all(
                row.get("passed")
                is True
                for row in results
            )
        ):
            continue

        matches.append(
            (
                timestamp,
                child,
                summary,
            )
        )

    _must(
        bool(matches),
        "no COMPLETE 64-cycle lifecycle "
        "qualification matches "
        "the campaign",
    )

    matches.sort(
        key=lambda item: (
            item[0],
            item[1].name,
        )
    )

    _, root, summary = matches[-1]

    return root, summary


def _resolve_evidence_roots(
    repo_root: Path,
    *,
    experiment_root: Path,
    campaign_summary: dict[str, Any],
    lifecycle_root: Path,
) -> tuple[
    Path,
    list[Path],
    dict[str, Any],
]:

    freeze_root = (
        repo_root
        / "qualifications"
        / "final-freeze"
        / str(
            campaign_summary[
                "freeze_id"
            ]
        )
    )

    _must(
        freeze_root.is_dir(),
        "final freeze root "
        f"is missing: {freeze_root}",
    )

    freeze_inventory = _verify_inventory(
        freeze_root,
        allowed_unrecorded={
            "state.json",
        },
    )

    state = read_json(
        freeze_root
        / "state.json"
    )

    _must(
        state.get("state")
        == "COMPLETE",
        "final-freeze historical "
        "state is not COMPLETE",
    )

    freeze_definition = read_json(
        freeze_root
        / "definition.json"
    )

    if isinstance(
        state.get(
            "definition_sha256"
        ),
        str,
    ):
        _must(
            state[
                "definition_sha256"
            ]
            == _semantic_sha256(
                freeze_definition
            ),
            "final-freeze state "
            "definition SHA mismatch",
        )

    manifest = read_json(
        freeze_root
        / "processed"
        / "final-manifest.json"
    )

    identity = dict(manifest)

    stated_sha = identity.pop(
        "freeze_sha256",
        None,
    )

    _must(
        _semantic_sha256(
            identity
        )
        == stated_sha,
        "final-freeze semantic "
        "SHA mismatch",
    )

    _must(
        stated_sha
        == campaign_summary.get(
            "freeze_sha256"
        ),
        "campaign/final-freeze "
        "SHA mismatch",
    )

    resolved = read_json(
        freeze_root
        / "inputs"
        / "resolved-inputs.json"
    )

    artifacts = resolved.get(
        "artifacts"
    )

    _must(
        isinstance(
            artifacts,
            dict,
        ),
        "final-freeze resolved "
        "inputs are malformed",
    )

    roots: list[Path] = [
        experiment_root,
        freeze_root,
        lifecycle_root,
    ]

    input_records: dict[
        str,
        Any,
    ] = {}

    for (
        name,
        record,
    ) in sorted(
        artifacts.items()
    ):
        _must(
            isinstance(
                record,
                dict,
            ),
            "malformed final-freeze "
            f"input record: {name}",
        )

        root_relative = record.get(
            "root"
        )

        _must(
            isinstance(
                root_relative,
                str,
            ),
            "missing final-freeze "
            f"root path: {name}",
        )

        root = (
            repo_root
            / root_relative
        ).resolve()

        try:
            root.relative_to(
                repo_root.resolve()
            )
        except ValueError as exc:
            raise FrameworkError(
                "final-freeze input "
                "escapes repository: "
                f"{name}"
            ) from exc

        _must(
            root.is_dir(),
            "final-freeze input root "
            f"missing: {name}: {root}",
        )

        summary_path = (
            root
            / "processed"
            / "summary.json"
        )

        _must(
            summary_path.is_file(),
            "final-freeze input summary "
            f"missing: {name}",
        )

        if isinstance(
            record.get(
                "summary_sha256"
            ),
            str,
        ):
            _must(
                _sha256_file(
                    summary_path
                )
                == record[
                    "summary_sha256"
                ],
                "final-freeze input "
                "summary SHA mismatch: "
                f"{name}",
            )

        inventory_sha = record.get(
            "artifact_inventory_sha256"
        )

        if isinstance(
            inventory_sha,
            str,
        ):
            inventory_path = (
                root
                / "artifacts.sha256"
            )

            _must(
                inventory_path.is_file(),
                "final-freeze input "
                "inventory missing: "
                f"{name}",
            )

            _must(
                _sha256_file(
                    inventory_path
                )
                == inventory_sha,
                "final-freeze input "
                "inventory SHA mismatch: "
                f"{name}",
            )

        roots.append(root)
        input_records[name] = record

    unique: dict[
        Path,
        Path,
    ] = {}

    for root in roots:
        unique[
            root.resolve()
        ] = root.resolve()

    evidence_roots = sorted(
        unique.values(),
        key=lambda path:
            path.relative_to(
                repo_root
            ).as_posix(),
    )

    return (
        freeze_root,
        evidence_roots,
        {
            "final_freeze_manifest":
                manifest,
            "final_freeze_resolved_inputs":
                resolved,
            "final_freeze_inventory":
                freeze_inventory,
            "input_records":
                input_records,
        },
    )


def _metric_summary(
    analysis: dict[str, Any],
) -> dict[str, Any]:

    result: dict[
        str,
        Any,
    ] = {}

    pairs = analysis[
        "pairs"
    ]

    for metric in METRICS:
        values = [
            float(
                row[
                    "delta_percent_positive_favors_ngi541"
                ][metric]
            )
            for row in pairs
            if isinstance(
                row[
                    "delta_percent_positive_favors_ngi541"
                ].get(metric),
                (
                    int,
                    float,
                ),
            )
        ]

        _must(
            len(values)
            == EXPECTED_PAIRS,
            "paired metric "
            f"is incomplete: {metric}",
        )

        result[metric] = {
            "pair_count":
                len(values),
            "median_delta_percent":
                statistics.median(
                    values
                ),
            "mean_delta_percent":
                statistics.fmean(
                    values
                ),
            "min_delta_percent":
                min(values),
            "max_delta_percent":
                max(values),
            "ngi541_pair_wins":
                sum(
                    1
                    for value
                    in values
                    if value > 0
                ),
            "stock_pair_wins":
                sum(
                    1
                    for value
                    in values
                    if value < 0
                ),
            "ties":
                sum(
                    1
                    for value
                    in values
                    if value == 0
                ),
        }

    return result


def _condition_rows(
    runs: list[dict[str, Any]],
    analysis: dict[str, Any],
) -> list[dict[str, Any]]:

    paired = {
        row["condition_id"]:
            row["metrics"]
        for row
        in analysis["conditions"]
    }

    grouped: dict[
        tuple[str, str],
        list[dict[str, Any]],
    ] = defaultdict(list)

    for row in runs:
        grouped[
            (
                row["condition_id"],
                row["variant"],
            )
        ].append(row)

    output: list[
        dict[str, Any]
    ] = []

    for condition_id in sorted(
        {
            row["condition_id"]
            for row in runs
        }
    ):
        record: dict[
            str,
            Any,
        ] = {
            "condition_id":
                condition_id,
        }

        for metric in METRICS:
            for variant in VARIANTS:
                values = [
                    float(
                        row["metrics"][
                            metric
                        ]
                    )
                    for row
                    in grouped[
                        (
                            condition_id,
                            variant,
                        )
                    ]
                ]

                record[
                    f"{variant}_"
                    f"{metric}_median"
                ] = statistics.median(
                    values
                )

            stats = paired[
                condition_id
            ][metric]

            record[
                f"{metric}_paired_"
                "median_delta_percent"
            ] = stats[
                "median_delta_percent"
            ]

            record[
                f"{metric}_"
                "ngi541_pair_wins"
            ] = stats[
                "ngi541_pair_wins"
            ]

            record[
                f"{metric}_"
                "stock_pair_wins"
            ] = stats[
                "stock_pair_wins"
            ]

            record[
                f"{metric}_ties"
            ] = stats[
                "ties"
            ]

        output.append(record)

    return output


def _run_rows(
    runs: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    output: list[
        dict[str, Any]
    ] = []

    for row in runs:
        metrics = row["metrics"]

        output.append(
            {
                "sequence":
                    row["sequence"],
                "run_id":
                    row["run_id"],
                "pair_id":
                    row["pair_id"],
                "repetition":
                    row["repetition"],
                "condition_id":
                    row[
                        "condition_id"
                    ],
                "variant":
                    row["variant"],
                "pair_order":
                    row["pair_order"],
                "application_goodput_mbps":
                    metrics[
                        "application_goodput_mbps"
                    ],
                "achieved_target_ratio":
                    metrics[
                        "achieved_target_ratio"
                    ],
                "dut_process_cpu_seconds_per_gib":
                    metrics[
                        "dut_process_cpu_seconds_per_gib"
                    ],
                "dut_estimated_energy_j_per_gib":
                    metrics[
                        "dut_estimated_energy_j_per_gib"
                    ],
                "loadgen_max_total_cpu_busy_percent":
                    metrics[
                        "loadgen_max_total_cpu_busy_percent"
                    ],
                "loadgen_max_single_core_busy_percent":
                    metrics[
                        "loadgen_max_single_core_busy_percent"
                    ],
                "udp_in_errors_delta":
                    metrics[
                        "udp_in_errors_delta"
                    ],
            }
        )

    return output


def _pair_rows(
    analysis: dict[str, Any],
) -> list[dict[str, Any]]:

    output: list[
        dict[str, Any]
    ] = []

    for pair in analysis[
        "pairs"
    ]:
        deltas = pair[
            "delta_percent_positive_favors_ngi541"
        ]

        output.append(
            {
                "pair_id":
                    pair["pair_id"],
                "condition_id":
                    pair[
                        "condition_id"
                    ],
                "repetition":
                    pair[
                        "repetition"
                    ],
                "first_variant":
                    pair[
                        "first_variant"
                    ],
                "application_goodput_delta_percent":
                    deltas[
                        "application_goodput_mbps"
                    ],
                "dut_process_cpu_seconds_per_gib_delta_percent":
                    deltas[
                        "dut_process_cpu_seconds_per_gib"
                    ],
                "dut_estimated_energy_j_per_gib_delta_percent":
                    deltas[
                        "dut_estimated_energy_j_per_gib"
                    ],
            }
        )

    return output


def _csv_text(
    rows: list[dict[str, Any]],
) -> str:
    if not rows:
        return ""

    fieldnames = list(
        rows[0].keys()
    )

    buffer = io.StringIO(
        newline=""
    )

    writer = csv.DictWriter(
        buffer,
        fieldnames=fieldnames,
        lineterminator="\n",
    )

    writer.writeheader()

    for row in rows:
        writer.writerow(row)

    return buffer.getvalue()


def _svg_delta_plot(
    metric: str,
    analysis: dict[str, Any],
) -> str:

    values = [
        float(
            pair[
                "delta_percent_positive_favors_ngi541"
            ][metric]
        )
        for pair
        in analysis["pairs"]
    ]

    width = 900
    height = 420

    left = 70
    right = 20
    top = 35
    bottom = 55

    inner_width = (
        width
        - left
        - right
    )

    inner_height = (
        height
        - top
        - bottom
    )

    low = min(
        min(values),
        0.0,
    )

    high = max(
        max(values),
        0.0,
    )

    if math.isclose(
        low,
        high,
    ):
        low -= 1.0
        high += 1.0

    padding = (
        high - low
    ) * 0.08

    low -= padding
    high += padding

    def x_position(
        index: int,
    ) -> float:
        return (
            left
            + (
                index - 1
            )
            / max(
                1,
                len(values) - 1,
            )
            * inner_width
        )

    def y_position(
        value: float,
    ) -> float:
        return (
            top
            + (
                high - value
            )
            / (
                high - low
            )
            * inner_height
        )

    circles = "\n".join(
        (
            '<circle '
            f'cx="{x_position(index):.2f}" '
            f'cy="{y_position(value):.2f}" '
            'r="3" />'
        )
        for index, value
        in enumerate(
            values,
            start=1,
        )
    )

    zero = y_position(
        0.0
    )

    title = metric.replace(
        "_",
        " ",
    )

    return (
        '<?xml version="1.0" '
        'encoding="UTF-8"?>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'width="{width}" '
        f'height="{height}" '
        f'viewBox="0 0 {width} {height}">\n'
        '<rect width="100%" '
        'height="100%" '
        'fill="white"/>\n'
        '<g stroke="black" '
        'fill="none" '
        'stroke-width="1">\n'
        f'<line x1="{left}" '
        f'y1="{top}" '
        f'x2="{left}" '
        f'y2="{height-bottom}"/>\n'
        f'<line x1="{left}" '
        f'y1="{zero:.2f}" '
        f'x2="{width-right}" '
        f'y2="{zero:.2f}" '
        'stroke-dasharray="5 5"/>\n'
        '</g>\n'
        '<g fill="black">\n'
        f'<text x="{width/2:.0f}" '
        'y="22" '
        'text-anchor="middle" '
        'font-family="sans-serif" '
        'font-size="14">'
        f'{title}: paired delta '
        '(positive favors ngi541-direct)'
        '</text>\n'
        f'<text x="{width/2:.0f}" '
        f'y="{height-12}" '
        'text-anchor="middle" '
        'font-family="sans-serif" '
        'font-size="12">'
        'pair index'
        '</text>\n'
        f'{circles}\n'
        '</g>\n'
        '</svg>\n'
    )


def _deterministic_tar_gz(
    path: Path,
    entries: Iterable[
        tuple[
            Path,
            str,
        ]
    ],
) -> None:

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "wb"
    ) as raw:

        with gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=raw,
            compresslevel=9,
            mtime=0,
        ) as gzip_file:

            with tarfile.open(
                fileobj=gzip_file,
                mode="w",
                format=tarfile.PAX_FORMAT,
            ) as archive:

                seen: set[str] = set()

                for (
                    source,
                    archive_name,
                ) in sorted(
                    entries,
                    key=lambda item:
                        item[1],
                ):
                    _must(
                        archive_name
                        not in seen,
                        "duplicate tar path: "
                        f"{archive_name}",
                    )

                    seen.add(
                        archive_name
                    )

                    data = source.read_bytes()

                    info = tarfile.TarInfo(
                        archive_name
                    )

                    info.size = len(data)
                    info.mode = 0o644
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.mtime = 0

                    archive.addfile(
                        info,
                        io.BytesIO(data),
                    )


def _tree_entries(
    root: Path,
    archive_prefix: str = "",
) -> list[
    tuple[
        Path,
        str,
    ]
]:
    result = []

    for path in sorted(
        candidate
        for candidate
        in root.rglob("*")
        if candidate.is_file()
    ):
        relative = (
            path.relative_to(
                root
            ).as_posix()
        )

        if archive_prefix:
            archive_name = (
                archive_prefix.rstrip("/")
                + "/"
                + relative
            )
        else:
            archive_name = relative

        result.append(
            (
                path,
                archive_name,
            )
        )

    return result


def _write_inventory(
    root: Path,
) -> dict[str, Any]:

    rows = []

    for path in sorted(
        candidate
        for candidate
        in root.rglob("*")
        if (
            candidate.is_file()
            and candidate.name
            != "artifacts.sha256"
        )
    ):
        rows.append(
            f"{_sha256_file(path)}  "
            f"{path.relative_to(root).as_posix()}"
        )

    content = (
        "\n".join(rows)
        + "\n"
    )

    atomic_write_text(
        root
        / "artifacts.sha256",
        content,
    )

    return {
        "entry_count":
            len(rows),
        "inventory_sha256":
            _sha256_file(
                root
                / "artifacts.sha256"
            ),
    }


def _methodology_md(
    result_id: str,
    campaign: dict[str, Any],
    lifecycle: dict[str, Any],
) -> str:

    summary = campaign[
        "summary"
    ]

    return f"""# Methodology

Result artifact: `{result_id}`

- Source campaign: `{summary['experiment_id']}`
- Measurement protocol: `{summary['measurement_protocol_revision']}`
- Transport: HTTP/3
- Experimental design: {summary['condition_count']} conditions × {summary['repetitions']} paired repetitions
- Variant runs: {summary['run_count']}
- Warmup / MAIN: 5 s / 20 s
- MAIN telemetry selection: `strict-main-no-tolerance`
- Scientific byte accounting: `h2load-main-phase-body-bytes`
- Adaptive replanning: prohibited
- Metric-dependent retry: prohibited
- Outlier deletion: none
- Accepted lifecycle qualification: `{lifecycle['qualification_id']}` ({lifecycle['cycles_passed']}/{lifecycle['cycles_planned']} PASS)

The workload, transport-security, telemetry, network-evidence,
scientific-corpus, load-generator and workload-planner inputs are preserved
through the final-freeze dependency closure in the evidence archive.

Historical host names remain only in immutable provenance identifiers.  The
publication artifact itself uses semantic `dut` and `loadgen` roles and does
not encode Mac/Pi in its result identity.

The result generator does not infer historical firewall state from the current
host.  Host firewall control is therefore not promoted to a machine-rederived
performance claim.
"""


def _results_md(
    result_id: str,
    overall: dict[str, Any],
    udp: dict[str, Any],
) -> str:

    goodput = overall[
        "application_goodput_mbps"
    ]

    cpu = overall[
        "dut_process_cpu_seconds_per_gib"
    ]

    energy = overall[
        "dut_estimated_energy_j_per_gib"
    ]

    return f"""# Results

Result artifact: `{result_id}`

| Metric | Median paired delta | NGI541 wins | Stock wins | Ties |
| --- | ---: | ---: | ---: | ---: |
| Application goodput | {goodput['median_delta_percent']:+.6f}% | {goodput['ngi541_pair_wins']} | {goodput['stock_pair_wins']} | {goodput['ties']} |
| DUT process CPU s/GiB | {cpu['median_delta_percent']:+.6f}% | {cpu['ngi541_pair_wins']} | {cpu['stock_pair_wins']} | {cpu['ties']} |
| Estimated energy J/GiB | {energy['median_delta_percent']:+.6f}% | {energy['ngi541_pair_wins']} | {energy['stock_pair_wins']} | {energy['ties']} |

Positive paired delta favors `ngi541-direct`.

## Interpretation

The strongest controlled-environment result is CPU efficiency: median paired
improvement of {cpu['median_delta_percent']:+.6f}% with
{cpu['ngi541_pair_wins']}/{cpu['pair_count']} pairs favoring
`ngi541-direct`.

Goodput is service-target limited and does not support a general throughput
improvement claim.  Energy is mixed and does not support an energy-efficiency
claim.

UDP `InErrors` are retained as diagnostics, not as a post-hoc validity gate:
{udp['affected_runs']} affected runs, maximum delta {udp['max_delta']:g},
stock/direct balance
{udp['by_variant'].get('stock', 0)}/{udp['by_variant'].get('ngi541-direct', 0)}.
"""


def _publication_readme(
    result_id: str,
) -> str:

    return f"""# NGI541 scientific result artifact

Artifact: `{result_id}`

Files:

- `results.tar.gz` — compact result, tables, figures, methodology, integrity and provenance.
- `evidence.tar.gz` — source experiment plus the frozen qualification/evidence dependency closure.
- `SHA256SUMS` — SHA-256 checksums for the two archives.

`manifest.yaml` at the artifact root is the canonical contract.  It is emitted
as YAML-1.2-compatible JSON so publication generation requires no PyYAML
dependency.
"""


def _existing_result(
    root: Path,
    source_experiment_id: str,
) -> dict[str, Any]:

    _verify_inventory(root)

    provenance = read_json(
        root
        / "provenance.json"
    )

    _must(
        provenance.get(
            "source_experiment",
            {},
        ).get("id")
        == source_experiment_id,
        "existing result artifact "
        "source mismatch",
    )

    manifest = json.loads(
        (
            root
            / "manifest.yaml"
        ).read_text(
            encoding="utf-8"
        )
    )

    _must(
        manifest.get(
            "artifact",
            {},
        ).get("state")
        == "COMPLETE",
        "existing result artifact "
        "is not COMPLETE",
    )

    return {
        "root":
            root,
        "manifest":
            manifest,
        "results":
            read_json(
                root
                / "results.json"
            ),
        "integrity":
            read_json(
                root
                / "integrity.json"
            ),
        "provenance":
            provenance,
        "reused":
            True,
    }


def build_results_artifact(
    experiment: Path,
    *,
    repo_root: Path,
    output_root: Path,
) -> dict[str, Any]:

    experiment_root = (
        _resolve_under_repo(
            experiment,
            repo_root,
            "source experiment",
        )
    )

    _must(
        experiment_root.is_dir(),
        "source experiment "
        "does not exist: "
        f"{experiment_root}",
    )

    campaign = _validate_campaign(
        experiment_root
    )

    summary = campaign[
        "summary"
    ]

    frozen = campaign[
        "frozen"
    ]

    result_id = _result_id(
        summary,
        frozen,
    )

    (
        lifecycle_root,
        lifecycle,
    ) = _select_lifecycle_qualification(
        repo_root,
        campaign_summary=summary,
        frozen=frozen,
    )

    (
        freeze_root,
        evidence_roots,
        freeze_context,
    ) = _resolve_evidence_roots(
        repo_root,
        experiment_root=experiment_root,
        campaign_summary=summary,
        lifecycle_root=lifecycle_root,
    )

    output_root.mkdir(
        parents=True,
        exist_ok=True,
    )

    root = (
        output_root
        / result_id
    )

    if root.exists():
        return _existing_result(
            root,
            str(
                summary[
                    "experiment_id"
                ]
            ),
        )

    temp = (
        output_root
        / f".{result_id}.tmp"
    )

    _must(
        not temp.exists(),
        "stale temporary result "
        f"artifact exists: {temp}",
    )

    temp.mkdir(
        parents=True
    )

    for relative in (
        "tables",
        "figures",
        "report",
        "publication",
    ):
        (
            temp
            / relative
        ).mkdir(
            parents=True,
            exist_ok=True,
        )

    overall = _metric_summary(
        campaign["analysis"]
    )

    condition_rows = (
        _condition_rows(
            campaign["runs"],
            campaign["analysis"],
        )
    )

    run_rows = _run_rows(
        campaign["runs"]
    )

    pair_rows = _pair_rows(
        campaign["analysis"]
    )

    execution_source = (
        _execution_source(
            repo_root
        )
    )

    generator_source = (
        _generator_source(
            repo_root
        )
    )

    results = {
        "schema_version":
            RESULT_SCHEMA_VERSION,
        "artifact_id":
            result_id,
        "source_experiment_id":
            summary[
                "experiment_id"
            ],
        "measurement_protocol_revision":
            summary[
                "measurement_protocol_revision"
            ],
        "design": {
            "conditions":
                summary[
                    "condition_count"
                ],
            "repetitions":
                summary[
                    "repetitions"
                ],
            "pairs":
                summary[
                    "pair_count"
                ],
            "runs":
                summary[
                    "run_count"
                ],
            "variants":
                summary[
                    "variants"
                ],
        },
        "overall_paired_metrics":
            overall,
        "condition_paired_metrics":
            campaign[
                "analysis"
            ][
                "conditions"
            ],
        "claims": {
            "permitted": [
                {
                    "scope":
                        "controlled-environment",
                    "metric":
                        "dut_process_cpu_seconds_per_gib",
                    "statement":
                        (
                            "ngi541-direct showed "
                            "lower DUT process CPU "
                            "seconds per GiB for "
                            "the accepted paired "
                            "campaign"
                        ),
                    "median_paired_improvement_percent":
                        overall[
                            "dut_process_cpu_seconds_per_gib"
                        ][
                            "median_delta_percent"
                        ],
                    "ngi541_pair_wins":
                        overall[
                            "dut_process_cpu_seconds_per_gib"
                        ][
                            "ngi541_pair_wins"
                        ],
                    "pair_count":
                        EXPECTED_PAIRS,
                }
            ],
            "not_supported": [
                "universal-hardware-generalization",
                "general-throughput-improvement",
                "energy-efficiency-improvement",
                "full-hacc-dataset-execution",
            ],
        },
    }

    provenance = {
        "schema_version":
            RESULT_SCHEMA_VERSION,
        "artifact_id":
            result_id,
        "source_experiment": {
            "id":
                summary[
                    "experiment_id"
                ],
            "path":
                experiment_root
                .relative_to(
                    repo_root
                )
                .as_posix(),
            "inventory_sha256":
                campaign[
                    "source_inventory"
                ][
                    "inventory_sha256"
                ],
            "resolved_execution_input_sha256":
                frozen[
                    "resolved_execution_input_sha256"
                ],
        },
        "execution_software":
            execution_source,
        "generator_software":
            generator_source,
        "final_freeze": {
            "id":
                summary[
                    "freeze_id"
                ],
            "path":
                freeze_root
                .relative_to(
                    repo_root
                )
                .as_posix(),
            "sha256":
                summary[
                    "freeze_sha256"
                ],
            "historical_inventory":
                freeze_context[
                    "final_freeze_inventory"
                ],
        },
        "workload_plan": {
            "id":
                summary[
                    "workload_plan_id"
                ],
            "sha256":
                summary[
                    "workload_plan_sha256"
                ],
        },
        "lifecycle_qualification": {
            "id":
                lifecycle[
                    "qualification_id"
                ],
            "path":
                lifecycle_root
                .relative_to(
                    repo_root
                )
                .as_posix(),
            "summary_sha256":
                _sha256_file(
                    lifecycle_root
                    / "processed"
                    / "summary.json"
                ),
            "cycles_passed":
                lifecycle[
                    "cycles_passed"
                ],
            "cycles_planned":
                lifecycle[
                    "cycles_planned"
                ],
        },
        "evidence_roots": [
            path
            .relative_to(
                repo_root
            )
            .as_posix()
            for path
            in evidence_roots
        ],
        "final_freeze_inputs":
            freeze_context[
                "input_records"
            ],
    }

    integrity = {
        "schema_version":
            RESULT_SCHEMA_VERSION,
        "artifact_id":
            result_id,
        "status":
            "PASS",
        "checks": {
            "source_inventory": {
                "status":
                    "PASS",
                **campaign[
                    "source_inventory"
                ],
            },
            "final_freeze_historical_inventory": {
                "status":
                    "PASS",
                **freeze_context[
                    "final_freeze_inventory"
                ],
            },
            "campaign_structure": {
                "status":
                    "PASS",
                "runs":
                    EXPECTED_RUNS,
                "pairs":
                    EXPECTED_PAIRS,
                "conditions":
                    EXPECTED_CONDITIONS,
                "repetitions":
                    EXPECTED_REPETITIONS,
                "variant_balance":
                    "48/48",
                "pair_order_balance":
                    (
                        "2 stock-first + "
                        "2 ngi541-direct-first "
                        "per condition"
                    ),
            },
            "frozen_validity": {
                "status":
                    "PASS",
                "valid_runs":
                    EXPECTED_RUNS,
                "invalid_runs":
                    0,
                "zero_traffic_runs":
                    0,
                "accounting_anomalies":
                    0,
                "energy_missing_runs":
                    0,
            },
            "paired_analysis_recomputation": {
                "status":
                    "PASS",
                "pairs_retained":
                    EXPECTED_PAIRS,
                "outlier_deletion":
                    "none",
            },
            "performance_lifecycle": {
                "status":
                    "PASS",
                **campaign[
                    "performance_lifecycle"
                ],
            },
            "lifecycle_qualification": {
                "status":
                    "PASS",
                "qualification_id":
                    lifecycle[
                        "qualification_id"
                    ],
                "cycles":
                    "64/64",
            },
        },
        "udp_diagnostic":
            campaign["udp"],
    }

    manifest = {
        "schema_version":
            RESULT_SCHEMA_VERSION,
        "artifact": {
            "id":
                result_id,
            "type":
                "scientific-performance-result",
            "state":
                "COMPLETE",
        },
        "source": {
            "experiment_id":
                summary[
                    "experiment_id"
                ],
            "measurement_protocol_revision":
                summary[
                    "measurement_protocol_revision"
                ],
            "execution_tag":
                EXECUTION_TAG,
            "execution_commit":
                execution_source[
                    "execution_commit"
                ],
            "generator_commit":
                generator_source[
                    "commit"
                ],
        },
        "roles": {
            "dut": {
                "semantic_role":
                    "device-under-test",
            },
            "loadgen": {
                "semantic_role":
                    "load-generator",
            },
        },
        "protocol": {
            "transport":
                "HTTP/3",
            "tls":
                "1.3",
            "cipher":
                "TLS_AES_128_GCM_SHA256",
        },
        "design":
            results["design"],
        "integrity": {
            "status":
                "PASS",
            "valid_runs":
                EXPECTED_RUNS,
            "complete_pairs":
                EXPECTED_PAIRS,
            "metric_dependent_retry":
                "prohibited",
            "outlier_deletion":
                "none",
        },
        "primary_result": {
            "metric":
                "dut_process_cpu_seconds_per_gib",
            **overall[
                "dut_process_cpu_seconds_per_gib"
            ],
        },
        "claims":
            results["claims"],
        "publication": {
            "results_archive":
                "publication/results.tar.gz",
            "evidence_archive":
                "publication/evidence.tar.gz",
            "checksums":
                "publication/SHA256SUMS",
        },
    }

    atomic_write_json(
        temp
        / "results.json",
        results,
    )

    atomic_write_json(
        temp
        / "integrity.json",
        integrity,
    )

    atomic_write_json(
        temp
        / "provenance.json",
        provenance,
    )

    atomic_write_text(
        temp
        / "manifest.yaml",
        _manifest_yaml_text(
            manifest
        ),
    )

    atomic_write_text(
        temp
        / "tables"
        / "condition-summary.csv",
        _csv_text(
            condition_rows
        ),
    )

    atomic_write_text(
        temp
        / "tables"
        / "pair-results.csv",
        _csv_text(
            pair_rows
        ),
    )

    atomic_write_text(
        temp
        / "tables"
        / "run-results.csv",
        _csv_text(
            run_rows
        ),
    )

    atomic_write_text(
        temp
        / "figures"
        / "goodput-delta.svg",
        _svg_delta_plot(
            "application_goodput_mbps",
            campaign[
                "analysis"
            ],
        ),
    )

    atomic_write_text(
        temp
        / "figures"
        / "paired-cpu-delta.svg",
        _svg_delta_plot(
            "dut_process_cpu_seconds_per_gib",
            campaign[
                "analysis"
            ],
        ),
    )

    atomic_write_text(
        temp
        / "figures"
        / "energy-delta.svg",
        _svg_delta_plot(
            "dut_estimated_energy_j_per_gib",
            campaign[
                "analysis"
            ],
        ),
    )

    atomic_write_text(
        temp
        / "report"
        / "methodology.md",
        _methodology_md(
            result_id,
            campaign,
            lifecycle,
        ),
    )

    atomic_write_text(
        temp
        / "report"
        / "results.md",
        _results_md(
            result_id,
            overall,
            campaign["udp"],
        ),
    )

    atomic_write_text(
        temp
        / "publication"
        / "README.md",
        _publication_readme(
            result_id
        ),
    )

    compact_files = [
        temp
        / "manifest.yaml",
        temp
        / "results.json",
        temp
        / "integrity.json",
        temp
        / "provenance.json",
        temp
        / "publication"
        / "README.md",
    ]

    compact_files.extend(
        sorted(
            (
                temp
                / "tables"
            ).glob("*")
        )
    )

    compact_files.extend(
        sorted(
            (
                temp
                / "figures"
            ).glob("*")
        )
    )

    compact_files.extend(
        sorted(
            (
                temp
                / "report"
            ).glob("*")
        )
    )

    _deterministic_tar_gz(
        temp
        / "publication"
        / "results.tar.gz",
        [
            (
                path,
                path
                .relative_to(
                    temp
                )
                .as_posix(),
            )
            for path
            in compact_files
        ],
    )

    evidence_entries: list[
        tuple[
            Path,
            str,
        ]
    ] = []

    for evidence_root in evidence_roots:
        prefix = (
            evidence_root
            .relative_to(
                repo_root
            )
            .as_posix()
        )

        evidence_entries.extend(
            _tree_entries(
                evidence_root,
                prefix,
            )
        )

    _deterministic_tar_gz(
        temp
        / "publication"
        / "evidence.tar.gz",
        evidence_entries,
    )

    results_archive_sha = (
        _sha256_file(
            temp
            / "publication"
            / "results.tar.gz"
        )
    )

    evidence_archive_sha = (
        _sha256_file(
            temp
            / "publication"
            / "evidence.tar.gz"
        )
    )

    atomic_write_text(
        temp
        / "publication"
        / "SHA256SUMS",
        (
            f"{results_archive_sha}  "
            "results.tar.gz\n"
            f"{evidence_archive_sha}  "
            "evidence.tar.gz\n"
        ),
    )

    _write_inventory(
        temp
    )

    temp.rename(root)

    return {
        "root":
            root,
        "manifest":
            manifest,
        "results":
            results,
        "integrity":
            integrity,
        "provenance":
            provenance,
        "reused":
            False,
    }
