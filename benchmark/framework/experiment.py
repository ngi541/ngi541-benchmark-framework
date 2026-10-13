#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
BENCHMARK_DIR = SCRIPT_DIR.parent
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))

from framework.analysis import analyze_experiment, validate_analysis_outputs
from framework.campaign import (
    campaign_record_matches,
    discover_campaign_instances,
    load_campaign_definition,
    next_campaign_stage,
    preparation_specs,
    request_from_campaign,
    resolve_campaign_config_path,
    verify_source_requirements,
    verify_active_framework_identity,
)
from framework.environment import prepare_environment
from framework.host_state import (
    calibrate_host_state,
    host_state_session,
    normalize_measurement_control,
    validate_host_state_capabilities,
    wait_until_ready,
)
from framework.ids import (
    generate_experiment_id,
    utc_rfc3339,
    validate_slug,
)
from framework.io_utils import (
    FrameworkError,
    append_log,
    atomic_write_json,
    atomic_write_text,
    read_json,
    write_immutable_json,
)
from framework.lifecycle import (
    initial_state,
    load_state,
    transition,
    update_run_counts,
)
from framework.manifest import build_manifest
from framework.network_qualification import (
    load_network_qualification_definition,
    run_network_qualification,
)
from framework.network_evidence import (
    load_definition as load_network_evidence_definition,
    run_network_evidence,
)
from framework.loadgen_runtime import (
    load_definition as load_loadgen_runtime_definition,
    run_loadgen_runtime,
)
from framework.scientific_corpus import (
    load_definition as load_scientific_corpus_definition,
    run_scientific_corpus,
)
from framework.transport_security import (
    load_definition as load_transport_security_definition,
    run_transport_security,
)
from framework.dual_host_telemetry import (
    load_definition as load_dual_host_telemetry_definition,
    run_dual_host_telemetry,
)
from framework.provenance import (
    discover_dependencies,
    discover_sources,
    record_binaries,
    record_build,
    record_runtime_bindings,
    run_preflight,
)
from framework.readme import generate_prepared_readme
from framework.schedule import build_schedule, resolve_common_request
from framework.validation import (
    COMMON_DIRS,
    validate_experiment,
    validate_request,
)
from framework.workloads import (
    execute_workload,
    prepare_workload,
    resolve_workload_config,
)


REPO_ROOT = SCRIPT_DIR.parents[1]
EXPERIMENTS_ROOT = REPO_ROOT / "experiments"


def parse_parameter(text: str) -> tuple[str, Any]:
    if "=" not in text:
        raise argparse.ArgumentTypeError(
            "--param must use NAME=VALUE syntax"
        )

    name, raw = text.split("=", 1)
    name = name.strip()

    if not name:
        raise argparse.ArgumentTypeError("parameter name must not be empty")

    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        value = raw

    return name, value


def experiment_dir(experiment_id: str) -> Path:
    return EXPERIMENTS_ROOT / experiment_id


def ensure_experiment_exists(experiment_id: str) -> Path:
    path = experiment_dir(experiment_id)
    if not path.is_dir():
        raise FrameworkError(f"experiment not found: {experiment_id}")
    return path


def _create_experiment_from_request(
    request: dict[str, Any],
    *,
    campaign_record: dict[str, Any] | None = None,
) -> tuple[str, Path]:
    validate_request(request)

    experiment_id = generate_experiment_id(
        request["workload"],
        request["environment"],
    )
    path = experiment_dir(experiment_id)

    if path.exists():
        raise FrameworkError(
            f"refusing to overwrite existing experiment directory: {path}"
        )

    path.mkdir(parents=True)

    for rel in COMMON_DIRS:
        (path / rel).mkdir(parents=True, exist_ok=True)

    write_immutable_json(path / "config" / "request.json", request)
    if campaign_record is not None:
        write_immutable_json(
            path / "config" / "campaign.json",
            campaign_record,
        )

    atomic_write_json(path / "state.json", initial_state(experiment_id))

    append_log(
        path / "logs" / "framework.log",
        f"{utc_rfc3339()} experiment created id={experiment_id}",
    )

    transition(path, "PREPARING")
    return experiment_id, path


def command_create(args: argparse.Namespace) -> int:
    workload = validate_slug(args.workload, "workload")
    environment = validate_slug(args.environment, "environment")

    variants = [
        validate_slug(variant, "variant")
        for variant in args.variant
    ]

    parameters: dict[str, Any] = {}
    for name, value in args.param:
        if name in parameters:
            raise FrameworkError(f"duplicate parameter: {name}")
        parameters[name] = value

    if "repetitions" in parameters:
        raise FrameworkError(
            "use --repetitions instead of --param repetitions=..."
        )
    parameters["repetitions"] = args.repetitions

    comparison: dict[str, Any] = {}
    if args.comparison_mode is not None:
        comparison["mode"] = args.comparison_mode
    if args.random_seed is not None:
        comparison["random_seed"] = args.random_seed

    request: dict[str, Any] = {
        "workload": workload,
        "environment": environment,
        "variants": variants,
        "parameters": parameters,
    }

    if comparison:
        request["comparison"] = comparison

    if args.alias is not None:
        request["alias"] = args.alias

    experiment_id, path = _create_experiment_from_request(request)
    print(experiment_id)
    print(path)
    return 0


def command_plan(args: argparse.Namespace) -> int:
    path = ensure_experiment_exists(args.experiment_id)
    state = load_state(path)

    if state["state"] != "PREPARING":
        raise FrameworkError(
            "plan requires PREPARING state; "
            f"current state is {state['state']}"
        )

    request = read_json(path / "config" / "request.json")
    validate_request(request)

    resolved = resolve_common_request(request)
    resolved = resolve_workload_config(request, resolved)
    schedule = build_schedule(args.experiment_id, resolved)

    write_immutable_json(
        path / "config" / "resolved.json",
        resolved,
    )
    write_immutable_json(
        path / "execution" / "schedule.json",
        schedule,
    )

    update_run_counts(path, planned=len(schedule["runs"]))

    append_log(
        path / "logs" / "framework.log",
        f"{utc_rfc3339()} execution plan generated "
        f"runs={len(schedule['runs'])} "
        f"mode={schedule['comparison_mode']}",
    )

    print(f"experiment: {args.experiment_id}")
    print(f"runs:       {len(schedule['runs'])}")
    print(f"mode:       {schedule['comparison_mode']}")
    return 0


def _ensure_preparing(path: Path) -> None:
    state = load_state(path)

    if state["state"] == "FAILED":
        if state.get("failure", {}).get("stage") != "preparing":
            raise FrameworkError(
                "prepare can resume only a FAILED preparation; "
                "this experiment failed during another stage"
            )
        transition(path, "PREPARING")
        return

    if state["state"] != "PREPARING":
        raise FrameworkError(
            "prepare requires PREPARING or preparation-FAILED state; "
            f"current state is {state['state']}"
        )


def command_prepare(args: argparse.Namespace) -> int:
    path = ensure_experiment_exists(args.experiment_id)
    _ensure_preparing(path)

    if not (path / "config" / "resolved.json").is_file():
        raise FrameworkError(
            "experiment must be planned before prepare"
        )

    if not (path / "execution" / "schedule.json").is_file():
        raise FrameworkError(
            "execution schedule is missing; run plan first"
        )

    request = read_json(path / "config" / "request.json")
    resolved = read_json(path / "config" / "resolved.json")

    try:
        adapter = prepare_environment(
            path,
            request["environment"],
        )

        sources = discover_sources(
            REPO_ROOT,
            args.source,
        )
        dependencies = discover_dependencies(REPO_ROOT)

        binaries = record_binaries(
            REPO_ROOT,
            args.binary,
            path / "provenance" / "binaries.sha256",
        )

        runtime_bindings = record_runtime_bindings(
            REPO_ROOT,
            resolved["variants"],
            binaries,
            args.runtime_library,
        )

        atomic_write_json(
            path / "provenance" / "runtime-bindings.json",
            runtime_bindings,
        )

        build = record_build(
            binaries,
            runtime_bindings,
        )

        atomic_write_json(
            path / "provenance" / "sources.json",
            sources,
        )
        atomic_write_json(
            path / "provenance" / "dependencies.json",
            dependencies,
        )
        atomic_write_json(
            path / "provenance" / "build.json",
            build,
        )

        prepare_workload(
            path,
            resolved,
            dependencies,
            runtime_bindings,
        )

        preflight = run_preflight(
            path,
            REPO_ROOT,
            args.preflight,
        )

        atomic_write_json(
            path / "provenance" / "preflight.json",
            preflight,
        )

        if not preflight["passed"]:
            raise FrameworkError(
                "one or more preparation preflight checks failed"
            )

    except Exception as exc:
        state = load_state(path)
        if state["state"] == "PREPARING":
            transition(
                path,
                "FAILED",
                failure={
                    "stage": "preparing",
                    "message": str(exc),
                    "run_id": None,
                },
            )
        raise

    append_log(
        path / "logs" / "framework.log",
        f"{utc_rfc3339()} preparation artifacts collected "
        f"adapter={adapter['adapter']} "
        f"sources={len(sources['sources'])} "
        f"binaries={len(binaries['artifacts'])}",
    )

    print(f"experiment: {args.experiment_id}")
    print(f"environment: {adapter['adapter']}")
    print(f"sources:     {len(sources['sources'])}")
    print(f"binaries:    {len(binaries['artifacts'])}")
    print("workload:    PASS")
    print("preflight:   PASS")
    print("state:       PREPARING")
    return 0


def command_seal(args: argparse.Namespace) -> int:
    path = ensure_experiment_exists(args.experiment_id)
    state = load_state(path)

    if state["state"] != "PREPARING":
        raise FrameworkError(
            "seal requires PREPARING state; "
            f"current state is {state['state']}"
        )

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

    missing = [
        rel
        for rel in required
        if not (path / rel).is_file()
    ]
    if missing:
        raise FrameworkError(
            "cannot seal experiment; missing preparation artifacts: "
            + ", ".join(missing)
        )

    preflight = read_json(path / "provenance" / "preflight.json")
    workload_preflight = read_json(
        path / "execution" / "workload" / "preflight.json"
    )

    if not preflight.get("passed"):
        raise FrameworkError(
            "cannot seal experiment with failed generic preflight"
        )
    if not workload_preflight.get("passed"):
        raise FrameworkError(
            "cannot seal experiment with failed workload preflight"
        )

    manifest = build_manifest(path)
    write_immutable_json(path / "manifest.json", manifest)

    transition(path, "READY")

    atomic_write_text(
        path / "README.md",
        generate_prepared_readme(path),
    )

    errors = validate_experiment(path)
    if errors:
        raise FrameworkError(
            "sealed experiment failed validation: "
            + "; ".join(errors)
        )

    append_log(
        path / "logs" / "framework.log",
        f"{utc_rfc3339()} manifest sealed; experiment READY",
    )

    print(f"experiment: {args.experiment_id}")
    print("state:      READY")
    print("manifest:   manifest.json")
    return 0


def command_execute(args: argparse.Namespace) -> int:
    path = ensure_experiment_exists(args.experiment_id)

    try:
        execute_workload(path)
    except KeyboardInterrupt:
        print("ABORTED: execution interrupted", file=sys.stderr)
        return 130

    state = load_state(path)
    print(f"experiment: {args.experiment_id}")
    print(f"state:      {state['state']}")
    print(
        "runs:       "
        f"planned={state['runs']['planned']} "
        f"completed={state['runs']['completed']} "
        f"failed={state['runs']['failed']} "
        f"skipped={state['runs']['skipped']}"
    )
    return 0


def command_analyze(args: argparse.Namespace) -> int:
    path = ensure_experiment_exists(args.experiment_id)
    state = load_state(path)

    if state["state"] == "FAILED":
        if state.get("failure", {}).get("stage") != "analyzing":
            raise FrameworkError(
                "analyze can resume only a FAILED analysis; "
                "this experiment failed during another stage"
            )
        transition(path, "ANALYZING")
    elif state["state"] != "ANALYZING":
        raise FrameworkError(
            "analyze requires ANALYZING or analysis-FAILED state; "
            f"current state is {state['state']}"
        )

    try:
        result = analyze_experiment(path)

        errors = validate_analysis_outputs(path)
        if errors:
            raise FrameworkError(
                "generated analysis outputs failed validation: "
                + "; ".join(errors)
            )

        common_errors = validate_experiment(path)
        if common_errors:
            raise FrameworkError(
                "experiment failed validation before completion: "
                + "; ".join(common_errors)
            )

        transition(path, "COMPLETE")

        final_errors = validate_experiment(path)
        if final_errors:
            raise FrameworkError(
                "completed experiment failed validation: "
                + "; ".join(final_errors)
            )

    except Exception as exc:
        current = load_state(path)
        if current["state"] == "ANALYZING":
            transition(
                path,
                "FAILED",
                failure={
                    "stage": "analyzing",
                    "message": str(exc),
                    "run_id": None,
                },
            )
        raise

    append_log(
        path / "logs" / "framework.log",
        f"{utc_rfc3339()} deterministic analysis complete "
        f"selected_runs={result['selected_runs']} "
        f"conditions={result['conditions']} pairs={result['pairs']}",
    )

    print(f"experiment: {args.experiment_id}")
    print("state:      COMPLETE")
    print(f"runs:       analyzed={result['selected_runs']}")
    print(f"conditions: {result['conditions']}")
    print(f"pairs:      {result['pairs']}")
    print("results:    processed/statistics.json")
    return 0



def _campaign_prepare_namespace(
    experiment_id: str,
    specs: dict[str, list[str]],
) -> argparse.Namespace:
    return argparse.Namespace(
        experiment_id=experiment_id,
        source=specs["source"],
        binary=specs["binary"],
        runtime_library=specs["runtime_library"],
        preflight=specs["preflight"],
    )


def _select_campaign_experiment(
    args: argparse.Namespace,
    definition: dict[str, Any],
    campaign_record: dict[str, Any],
) -> tuple[str, Path, bool]:
    definition_sha = campaign_record["definition_sha256"]
    campaign_name = campaign_record["campaign_name"]

    if args.experiment_id is not None:
        path = ensure_experiment_exists(args.experiment_id)
        if not campaign_record_matches(path, definition_sha):
            raise FrameworkError(
                "--experiment-id does not reference an experiment created "
                "from this campaign definition"
            )
        return args.experiment_id, path, False

    instances = discover_campaign_instances(
        EXPERIMENTS_ROOT,
        campaign_name=campaign_name,
        definition_sha256=definition_sha,
    )

    if not args.new:
        incomplete = instances["exact_incomplete"]
        if len(incomplete) > 1:
            ids = ", ".join(path.name for path in incomplete)
            raise FrameworkError(
                "multiple incomplete experiments match this campaign; "
                f"use --experiment-id to select one: {ids}"
            )
        if len(incomplete) == 1:
            path = incomplete[0]
            return path.name, path, False

        drift = instances["name_drift_incomplete"]
        if drift:
            ids = ", ".join(path.name for path in drift)
            raise FrameworkError(
                "an incomplete experiment exists for the same campaign name "
                "but the config definition changed; resume it with the original "
                f"config or use --new intentionally: {ids}"
            )

        complete = instances["exact_complete"]
        if complete:
            path = complete[-1]
            return path.name, path, False

    request = request_from_campaign(definition)
    experiment_id, path = _create_experiment_from_request(
        request,
        campaign_record=campaign_record,
    )
    return experiment_id, path, True


def command_campaign(args: argparse.Namespace) -> int:
    config_path = resolve_campaign_config_path(args.config, REPO_ROOT)
    definition, campaign_record = load_campaign_definition(
        config_path,
        REPO_ROOT,
    )

    experiment_id, path, created = _select_campaign_experiment(
        args,
        definition,
        campaign_record,
    )

    print(f"campaign:   {campaign_record['campaign_name']}")
    print(f"config:     {campaign_record['source']['path'] or campaign_record['source']['basename']}")
    print(f"config-sha: {campaign_record['definition_sha256']}")
    print(f"experiment: {experiment_id}")
    print(f"mode:       {'created' if created else 'resume'}")

    try:
        while True:
            stage = next_campaign_stage(path)
            state = load_state(path)
            print(f"campaign-stage: {stage} (state={state['state']})")

            if stage == "complete":
                result = command_validate(
                    argparse.Namespace(experiment_id=experiment_id)
                )
                if result != 0:
                    return result
                final = load_state(path)
                print(f"campaign:   COMPLETE")
                print(
                    "runs:       "
                    f"planned={final['runs']['planned']} "
                    f"completed={final['runs']['completed']} "
                    f"failed={final['runs']['failed']} "
                    f"skipped={final['runs']['skipped']}"
                )
                print(f"results:    experiments/{experiment_id}/processed/statistics.json")
                return 0

            verify_source_requirements(definition, REPO_ROOT)

            if state["state"] in {"READY", "RUNNING", "ABORTED", "ANALYZING"} or (
                state["state"] == "FAILED"
                and (state.get("failure") or {}).get("stage") in {"running", "analyzing"}
            ):
                verify_active_framework_identity(path, REPO_ROOT)

            prepare_args = None
            if stage in {"prepare", "execute"}:
                specs = preparation_specs(definition, REPO_ROOT)
                prepare_args = _campaign_prepare_namespace(
                    experiment_id,
                    specs,
                )

            if stage == "plan":
                command_plan(argparse.Namespace(experiment_id=experiment_id))
                continue

            if stage == "prepare":
                command_prepare(prepare_args)
                continue

            if stage == "seal":
                command_seal(argparse.Namespace(experiment_id=experiment_id))
                result = command_validate(
                    argparse.Namespace(experiment_id=experiment_id)
                )
                if result != 0:
                    return result
                continue

            if stage == "execute":
                lifecycle = state["state"]
                if lifecycle == "READY":
                    result = command_validate(
                        argparse.Namespace(experiment_id=experiment_id)
                    )
                    if result != 0:
                        return result
                result = command_execute(
                    argparse.Namespace(experiment_id=experiment_id)
                )
                if result != 0:
                    if result == 130:
                        print(
                            "resume:     rerun the same campaign --config command",
                            file=sys.stderr,
                        )
                    return result

                after = load_state(path)["state"]
                if after == "ANALYZING":
                    result = command_validate(
                        argparse.Namespace(experiment_id=experiment_id)
                    )
                    if result != 0:
                        return result
                continue

            if stage == "analyze":
                result = command_validate(
                    argparse.Namespace(experiment_id=experiment_id)
                )
                if result != 0:
                    return result
                command_analyze(argparse.Namespace(experiment_id=experiment_id))
                continue

            raise FrameworkError(f"unsupported campaign stage: {stage}")

    except KeyboardInterrupt:
        current = load_state(path)
        print(
            f"INTERRUPTED: campaign {experiment_id} stopped in state "
            f"{current['state']}; rerun the same campaign command to resume",
            file=sys.stderr,
        )
        return 130

def command_host_check(args: argparse.Namespace) -> int:
    config_path = resolve_campaign_config_path(args.config, REPO_ROOT)
    definition, _ = load_campaign_definition(config_path, REPO_ROOT)
    control = normalize_measurement_control(
        definition["experiment"].get("measurement_control")
    )

    calibration_snapshots: list[dict[str, Any]] = []
    readiness_snapshots: list[dict[str, Any]] = []

    try:
        with host_state_session(control) as host_session:
            capabilities = validate_host_state_capabilities(
                control, session=host_session
            )
            snapshot = capabilities.get("snapshot")
            if not capabilities["passed"]:
                calibration = None
                result = capabilities.get("static_readiness_at_preflight") or {
                    "ready": False,
                    "reasons": ["host-state-capabilities-failed"],
                    "fatal": True,
                }
            else:
                calibration = calibrate_host_state(
                    control,
                    session=host_session,
                    on_snapshot=calibration_snapshots.append,
                )
                final_snapshot, readiness_count, _ = wait_until_ready(
                    control,
                    calibration=calibration,
                    session=host_session,
                    on_snapshot=readiness_snapshots.append,
                )
                snapshot = final_snapshot
                result = final_snapshot["readiness"]
                result = dict(result)
                result["samples"] = readiness_count
    except FrameworkError as exc:
        capabilities = locals().get("capabilities") or {
            "schema_version": 2,
            "passed": False,
            "errors": [str(exc)],
            "snapshot": None,
        }
        calibration = locals().get("calibration")
        snapshot = capabilities.get("snapshot")
        result = {
            "ready": False,
            "reasons": [str(exc)],
            "fatal": True,
        }

    document = {
        "schema_version": 2,
        "config": str(config_path),
        "capabilities": capabilities,
        "calibration": calibration,
        "readiness": result,
    }
    if args.json:
        print(json.dumps(document, indent=2, sort_keys=True))
    else:
        temperature = ((snapshot or {}).get("temperature") or {}).get("temperature_c")
        thermal = ((snapshot or {}).get("thermal") or {})
        power = ((snapshot or {}).get("power") or {})
        load = ((snapshot or {}).get("load") or {})
        print(f"capabilities: {'PASS' if capabilities['passed'] else 'FAIL'}")
        print(f"provider:     {(snapshot or {}).get('provider', 'disabled')}")
        print(f"temperature:  {temperature if temperature is not None else 'unavailable'}")
        print(f"power:        {power.get('source', 'unknown')}")
        print(f"thermal:      {thermal.get('thermal_state', 'unknown')}")
        print(f"throttling:   {thermal.get('throttling_active')}")
        print(f"cpu-busy:     {load.get('cpu_busy_percent')}")
        if calibration and calibration.get("enabled"):
            busy = calibration.get("cpu_busy_percent") or {}
            quantile = busy.get("upper_quantile")
            q_label = int(round(float(quantile) * 100)) if isinstance(quantile, (int, float)) else None
            print(f"calibration:  PASS ({calibration.get('samples_collected')}/{calibration.get('samples_requested')} samples)")
            print(f"cpu-baseline: median={busy.get('median'):.1f}% q{q_label}={busy.get('upper_limit'):.1f}%")
        elif calibration is not None:
            print("calibration:  disabled")
        print(f"readiness:    {'PASS' if result.get('ready') else 'BLOCKED'}")
        streak = result.get("consecutive_ready_samples")
        required = result.get("required_consecutive_ready_samples")
        if streak is not None and required is not None:
            print(f"ready-streak: {streak}/{required}")
        if result.get("reasons"):
            print("reasons:      " + ", ".join(result["reasons"]))
        for error in capabilities.get("errors", []):
            print("error:        " + error)
    return 0 if capabilities["passed"] and result.get("ready") else 1



def command_network_qualify(args: argparse.Namespace) -> int:
    config_path = Path(args.config).expanduser()
    if not config_path.is_absolute():
        cwd_candidate = (Path.cwd() / config_path).resolve()
        repo_candidate = (REPO_ROOT / config_path).resolve()
        config_path = cwd_candidate if cwd_candidate.is_file() else repo_candidate
    else:
        config_path = config_path.resolve()

    definition = load_network_qualification_definition(config_path)
    output_root = REPO_ROOT / "qualifications" / "network"
    result = run_network_qualification(
        definition,
        config_path=config_path,
        output_root=output_root,
        repo_root=REPO_ROOT,
        bootstrap=args.bootstrap,
    )
    summary = result["summary"]
    topo = summary["topology"]
    refs = summary["references"]

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    print(f"network-qualification: {summary['qualification_id']}")
    print(f"topology:              {topo['classification']}")
    print(
        "local:                 "
        f"{topo['local'].get('address')} via {topo['local'].get('interface')} "
        f"({topo['local'].get('hardware_port') or 'unknown'})"
    )
    print(
        "remote:                "
        f"{topo['remote'].get('address')} via {topo['remote'].get('interface')} "
        f"({topo['remote'].get('speed_mbps') or 'unknown'} Mb/s)"
    )
    if summary['ping'].get('enabled'):
        print(
            "ping local->remote:  "
            f"avg={summary['ping']['local_to_remote'].get('rtt_avg_ms')} ms "
            f"loss={summary['ping']['local_to_remote'].get('packet_loss_percent')}%"
        )
        print(
            "ping remote->local:  "
            f"avg={summary['ping']['remote_to_local'].get('rtt_avg_ms')} ms "
            f"loss={summary['ping']['remote_to_local'].get('packet_loss_percent')}%"
        )
    print(
        "tcp local->remote:      "
        f"{refs['tcp']['local-to-remote'].get('best_throughput_mbps')} Mb/s"
    )
    print(
        "tcp remote->local:      "
        f"{refs['tcp']['remote-to-local'].get('best_throughput_mbps')} Mb/s"
    )
    print(
        "udp local->remote ref:  "
        f"{refs['udp']['local-to-remote'].get('highest_requested_mbps')} Mb/s"
    )
    print(
        "udp remote->local ref:  "
        f"{refs['udp']['remote-to-local'].get('highest_requested_mbps')} Mb/s"
    )
    print("status:                 COMPLETE")
    print(f"results:                {result['root'].relative_to(REPO_ROOT)}/processed/summary.json")
    return 0

def command_network_evidence(args: argparse.Namespace) -> int:
    config_path = Path(args.config).expanduser()
    if not config_path.is_absolute():
        cwd_candidate = (Path.cwd() / config_path).resolve()
        repo_candidate = (REPO_ROOT / config_path).resolve()
        config_path = cwd_candidate if cwd_candidate.is_file() else repo_candidate
    else:
        config_path = config_path.resolve()

    definition = load_network_evidence_definition(config_path)
    output_root = REPO_ROOT / "qualifications" / "network-evidence"
    result = run_network_evidence(
        definition,
        repo_root=REPO_ROOT,
        output_root=output_root,
        bootstrap=args.bootstrap,
    )
    summary = result["summary"]
    envelope = result["envelope"]

    if args.json:
        print(json.dumps(envelope, indent=2, sort_keys=True))
        return 0

    print(f"network-evidence:       {summary['evidence_id']}")
    print(f"observations:           {summary['selected_observations']}")
    print(f"collected-now:          {summary['collected_observations']}")
    print(f"topology:               {envelope['topology']['topology_classification']}")
    print(f"direction:              {envelope['direction_transport']} (DUT -> loadgen)")
    print(f"tcp floor:              {envelope['floors']['tcp_capacity_mbps']} Mb/s")
    print(f"udp safe requested:     {envelope['floors']['udp_safe_requested_mbps']} Mb/s")
    print(f"udp safe achieved:      {envelope['floors']['udp_safe_achieved_mbps']} Mb/s")
    print(f"service envelope:       {envelope['service_envelope_mbps']} Mb/s")
    print(f"limiting reference:     {envelope['limiting_reference']}")
    print("status:                 COMPLETE")
    print(
        "results:                "
        f"{result['root'].relative_to(REPO_ROOT)}/processed/network-envelope.json"
    )
    return 0


def command_loadgen_runtime(args: argparse.Namespace) -> int:
    config_path = Path(args.config).expanduser()
    if not config_path.is_absolute():
        cwd_candidate = (Path.cwd() / config_path).resolve()
        repo_candidate = (REPO_ROOT / config_path).resolve()
        config_path = cwd_candidate if cwd_candidate.is_file() else repo_candidate
    else:
        config_path = config_path.resolve()

    definition = load_loadgen_runtime_definition(config_path)
    output_root = REPO_ROOT / "qualifications" / "loadgen-runtime"
    result = run_loadgen_runtime(
        definition,
        config_path=config_path,
        output_root=output_root,
        bootstrap=args.bootstrap,
    )
    summary = result["summary"]
    runtime = summary["runtime"]

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    print(f"loadgen-runtime: {summary['runtime_id']}")
    print(f"remote:          {summary['remote']['ssh_target']}")
    print(f"architecture:    {summary['remote']['architecture']}")
    print(f"curl:            {runtime['curl_binary']}")
    print(f"curl-sha256:     {runtime['curl_sha256']}")
    print(f"http3:           {'PASS' if runtime['http3_capable'] else 'FAIL'}")
    if runtime.get("h2load"):
        h2load = runtime["h2load"]
        print(f"h2load:          {h2load['binary']}")
        print(f"h2load-sha256:   {h2load['sha256']}")
        print(f"h2load-http3:    {'PASS' if h2load['http3_capable'] else 'FAIL'}")
        print(f"h2load-json:     {'PASS' if h2load['json_output_capable'] else 'FAIL'}")
    print("status:          COMPLETE")
    print(f"results:         {result['root'].relative_to(REPO_ROOT)}/processed/summary.json")
    return 0


def command_scientific_corpus(args: argparse.Namespace) -> int:
    config_path = Path(args.config).expanduser()
    if not config_path.is_absolute():
        cwd_candidate = (Path.cwd() / config_path).resolve()
        repo_candidate = (REPO_ROOT / config_path).resolve()
        config_path = cwd_candidate if cwd_candidate.is_file() else repo_candidate
    else:
        config_path = config_path.resolve()

    definition = load_scientific_corpus_definition(config_path)
    output_root = REPO_ROOT / "corpora" / "scientific"
    result = run_scientific_corpus(
        definition,
        repo_root=REPO_ROOT,
        output_root=output_root,
    )
    summary = result["summary"]

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    print(f"scientific-corpus:      {summary['corpus_id']}")
    print(f"profiles:               {summary['profile_count']}")
    for profile in summary["profiles"]:
        print(
            "profile:                "
            f"{profile['profile_id']} v{profile['profile_version']} "
            f"({profile['corpus_kind']})"
        )
    hacc = summary.get("hacc")
    if hacc:
        print(f"hacc logical objects:   {hacc['logical_objects']}")
        print(f"hacc logical bytes:     {hacc['logical_bytes']}")
        print(
            "hacc coverage:          "
            + ", ".join(hacc["coverage_modes"])
        )
    print(f"reused:                 {'yes' if result['reused'] else 'no'}")
    print("status:                 COMPLETE")
    print(
        "results:                "
        f"{result['root'].relative_to(REPO_ROOT)}/processed/summary.json"
    )
    return 0


def command_transport_security(args: argparse.Namespace) -> int:
    config_path = Path(args.config).expanduser()
    if not config_path.is_absolute():
        cwd_candidate = (Path.cwd() / config_path).resolve()
        repo_candidate = (REPO_ROOT / config_path).resolve()
        config_path = cwd_candidate if cwd_candidate.is_file() else repo_candidate
    else:
        config_path = config_path.resolve()

    definition = load_transport_security_definition(config_path)
    output_root = REPO_ROOT / "qualifications" / "transport-security"
    result = run_transport_security(
        definition,
        repo_root=REPO_ROOT,
        output_root=output_root,
    )
    summary = result["summary"]
    gate = result["security_gate"]

    if args.json:
        print(json.dumps(gate, indent=2, sort_keys=True))
        return 0

    print(f"transport-security:     {summary['qualification_id']}")
    print(f"network-evidence:      {summary['network_evidence_id']}")
    print(f"loadgen-runtime:       {summary['loadgen_runtime_id']}")
    print(f"scientific-corpus:     {summary['scientific_corpus_id']}")
    print("transport:             HTTP/3 only")
    print("TLS:                   1.3")
    print(f"cipher:                {gate['cipher_suite']}")
    print("peer-verification:     PASS")
    for variant in gate["variants"]:
        print(f"variant {variant['variant']}:       {'PASS' if variant['passed'] else 'FAIL'}")
    print(f"status:                {summary['status']}")
    print("results:               " + str(result["root"].relative_to(REPO_ROOT) / "processed" / "security-gate.json"))
    return 0


def command_dual_host_telemetry(args: argparse.Namespace) -> int:
    config_path = Path(args.config).expanduser()
    if not config_path.is_absolute():
        cwd_candidate = (Path.cwd() / config_path).resolve()
        repo_candidate = (REPO_ROOT / config_path).resolve()
        config_path = cwd_candidate if cwd_candidate.is_file() else repo_candidate
    else:
        config_path = config_path.resolve()

    definition = load_dual_host_telemetry_definition(config_path)
    output_root = REPO_ROOT / "qualifications" / "telemetry"
    result = run_dual_host_telemetry(definition, repo_root=REPO_ROOT, output_root=output_root)
    summary = result["summary"]

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    print(f"dual-host-telemetry:    {summary['qualification_id']}")
    print(f"network-evidence:      {summary['network_evidence_id']}")
    print(f"loadgen-runtime:       {summary['loadgen_runtime_id']}")
    print(f"transport-security:    {summary['transport_security_id']}")
    print(f"samples/host:          {summary['samples_per_host']}")
    print(f"sample interval:       {summary['interval_seconds']} s")
    print(f"DUT package power:     {'available (estimated)' if summary['dut_estimated_power']['available'] else 'unavailable'}")
    print("loadgen package power: unavailable without external sensor")
    print(f"status:                {summary['status']}")
    print("results:               " + str(result["root"].relative_to(REPO_ROOT) / "processed" / "summary.json"))
    return 0


def command_status(args: argparse.Namespace) -> int:
    path = ensure_experiment_exists(args.experiment_id)
    state = read_json(path / "state.json")

    if args.json:
        print(json.dumps(state, indent=2, sort_keys=True))
        return 0

    runs = state.get("runs", {})
    print(f"experiment: {args.experiment_id}")
    print(f"state:      {state.get('state')}")
    print(
        "runs:       "
        f"planned={runs.get('planned', 0)} "
        f"completed={runs.get('completed', 0)} "
        f"failed={runs.get('failed', 0)} "
        f"skipped={runs.get('skipped', 0)}"
    )

    failure = state.get("failure")
    if failure:
        print(
            f"failure:    "
            f"{failure.get('stage')}: {failure.get('message')}"
        )

    return 0


def command_validate(args: argparse.Namespace) -> int:
    path = ensure_experiment_exists(args.experiment_id)
    errors = validate_experiment(path)

    if errors:
        print("FAIL: experiment validation", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(f"PASS: experiment validation: {args.experiment_id}")
    return 0


def command_attempt(args: argparse.Namespace) -> int:
    path = ensure_experiment_exists(args.experiment_id)
    state = load_state(path)

    if state["state"] not in {"READY", "RUNNING"}:
        raise FrameworkError(
            "attempt allocation requires READY or RUNNING state; "
            f"current state is {state['state']}"
        )

    schedule = read_json(path / "execution" / "schedule.json")

    run_ids = {run["run_id"] for run in schedule["runs"]}
    if args.run_id not in run_ids:
        raise FrameworkError(
            f"run id is not present in execution schedule: {args.run_id}"
        )

    run_dir = path / "raw" / "runs" / args.run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    existing = []
    for child in run_dir.iterdir():
        if child.is_dir() and child.name.startswith("attempt-"):
            try:
                existing.append(int(child.name.split("-", 1)[1]))
            except (IndexError, ValueError):
                continue

    next_number = max(existing, default=0) + 1
    attempt_dir = run_dir / f"attempt-{next_number:02d}"
    attempt_dir.mkdir()

    print(attempt_dir)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="experiment",
        description="NGI541 portable experiment framework core",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser(
        "create",
        help="create a new experiment and enter PREPARING state",
    )
    create.add_argument("--workload", required=True)
    create.add_argument("--environment", required=True)
    create.add_argument(
        "--variant",
        action="append",
        required=True,
        help="repeat for each variant",
    )
    create.add_argument(
        "--param",
        action="append",
        type=parse_parameter,
        default=[],
        metavar="NAME=VALUE",
        help=(
            "workload parameter; VALUE is parsed as JSON when possible "
            "(example: --param 'payload_bytes=[1024,16384]')"
        ),
    )
    create.add_argument("--repetitions", type=int, default=1)
    create.add_argument(
        "--comparison-mode",
        choices=["single", "fixed", "paired-balanced", "randomized"],
    )
    create.add_argument("--random-seed", type=int)
    create.add_argument("--alias")
    create.set_defaults(func=command_create)

    plan = subparsers.add_parser(
        "plan",
        help="resolve workload configuration and generate immutable schedule",
    )
    plan.add_argument("experiment_id")
    plan.set_defaults(func=command_plan)

    prepare = subparsers.add_parser(
        "prepare",
        help="collect environment/provenance and prepare workload inputs",
    )
    prepare.add_argument("experiment_id")
    prepare.add_argument(
        "--source",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="additional Git source to record",
    )
    prepare.add_argument(
        "--binary",
        action="append",
        default=[],
        metavar="VARIANT=PATH",
        help=(
            "runtime executable for a variant; every experiment variant "
            "must have exactly one binding"
        ),
    )
    prepare.add_argument(
        "--runtime-library",
        action="append",
        default=[],
        metavar="VARIANT=PATH",
        help=(
            "runtime shared library for a variant; repeat when several "
            "library files must be staged"
        ),
    )
    prepare.add_argument(
        "--preflight",
        action="append",
        default=[],
        metavar="NAME=COMMAND",
        help="additional preparation/preflight command",
    )
    prepare.set_defaults(func=command_prepare)

    seal = subparsers.add_parser(
        "seal",
        help="create immutable manifest and transition PREPARING -> READY",
    )
    seal.add_argument("experiment_id")
    seal.set_defaults(func=command_seal)

    execute = subparsers.add_parser(
        "execute",
        help="execute or resume the immutable workload schedule",
    )
    execute.add_argument("experiment_id")
    execute.set_defaults(func=command_execute)

    analyze = subparsers.add_parser(
        "analyze",
        help="analyze frozen raw measurements and complete the experiment",
    )
    analyze.add_argument("experiment_id")
    analyze.set_defaults(func=command_analyze)

    campaign = subparsers.add_parser(
        "campaign",
        help=(
            "run or resume a config-driven campaign through create, plan, "
            "prepare, seal, execute, and analyze"
        ),
    )
    campaign.add_argument(
        "--config",
        required=True,
        help="versioned campaign JSON definition",
    )
    campaign.add_argument(
        "--experiment-id",
        help="resume a specific experiment created from this config",
    )
    campaign.add_argument(
        "--new",
        action="store_true",
        help="create a new campaign instance even if a matching one exists",
    )
    campaign.set_defaults(func=command_campaign)

    host_check = subparsers.add_parser(
        "host-check",
        help="inspect measurement-control host telemetry and readiness",
    )
    host_check.add_argument(
        "--config",
        required=True,
        help="campaign JSON whose measurement-control policy should be checked",
    )
    host_check.add_argument("--json", action="store_true")
    host_check.set_defaults(func=command_host_check)


    network_qualify = subparsers.add_parser(
        "network-qualify",
        help="qualify a local/remote network path with ping and iperf3",
    )
    network_qualify.add_argument(
        "--config",
        required=True,
        help="versioned network qualification JSON definition",
    )
    network_qualify.add_argument(
        "--bootstrap",
        action="store_true",
        help="install missing iperf3 dependencies on supported endpoints",
    )
    network_qualify.add_argument("--json", action="store_true")
    network_qualify.set_defaults(func=command_network_qualify)

    network_evidence = subparsers.add_parser(
        "network-evidence",
        help="resolve compatible network qualifications and derive a deterministic service envelope",
    )
    network_evidence.add_argument(
        "--config",
        required=True,
        help="versioned network-evidence JSON definition",
    )
    network_evidence.add_argument(
        "--bootstrap",
        action="store_true",
        help="allow missing auto-collected network qualifications to bootstrap iperf3",
    )
    network_evidence.add_argument("--json", action="store_true")
    network_evidence.set_defaults(func=command_network_evidence)

    loadgen_runtime = subparsers.add_parser(
        "loadgen-runtime",
        help="provision and qualify a pinned HTTP/3 curl runtime on a remote load generator",
    )
    loadgen_runtime.add_argument(
        "--config",
        required=True,
        help="versioned load-generator runtime JSON definition",
    )
    loadgen_runtime.add_argument(
        "--bootstrap",
        action="store_true",
        help="install missing build dependencies on the supported remote host",
    )
    loadgen_runtime.add_argument("--json", action="store_true")
    loadgen_runtime.set_defaults(func=command_loadgen_runtime)

    scientific_corpus = subparsers.add_parser(
        "scientific-corpus",
        help="generate deterministic scientific corpus manifests and coverage contracts",
    )
    scientific_corpus.add_argument(
        "--config",
        required=True,
        help="versioned scientific corpus JSON definition",
    )
    scientific_corpus.add_argument("--json", action="store_true")
    scientific_corpus.set_defaults(func=command_scientific_corpus)

    transport_security = subparsers.add_parser(
        "transport-security",
        help="verify remote HTTP/3/TLS security and functional scientific-object transport for stock and NGI541",
    )
    transport_security.add_argument(
        "--config",
        required=True,
        help="versioned transport-security qualification JSON definition",
    )
    transport_security.add_argument("--json", action="store_true")
    transport_security.set_defaults(func=command_transport_security)

    dual_host_telemetry = subparsers.add_parser(
        "dual-host-telemetry",
        help="qualify normalized telemetry providers on the Darwin DUT and Linux SSH load generator",
    )
    dual_host_telemetry.add_argument(
        "--config",
        required=True,
        help="versioned dual-host telemetry qualification JSON definition",
    )
    dual_host_telemetry.add_argument("--json", action="store_true")
    dual_host_telemetry.set_defaults(func=command_dual_host_telemetry)

    status = subparsers.add_parser(
        "status",
        help="show experiment lifecycle state",
    )
    status.add_argument("experiment_id")
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=command_status)

    validate = subparsers.add_parser(
        "validate",
        help="validate the common experiment structure",
    )
    validate.add_argument("experiment_id")
    validate.set_defaults(func=command_validate)

    attempt = subparsers.add_parser(
        "allocate-attempt",
        help="allocate a new append-only attempt directory for a scheduled run",
    )
    attempt.add_argument("experiment_id")
    attempt.add_argument("run_id")
    attempt.set_defaults(func=command_attempt)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if getattr(args, "repetitions", 1) < 1:
        parser.error("--repetitions must be >= 1")

    if getattr(args, "new", False) and getattr(args, "experiment_id", None):
        parser.error("--new and --experiment-id are mutually exclusive")

    try:
        return args.func(args)
    except (FrameworkError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
