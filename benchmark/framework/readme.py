from __future__ import annotations

from pathlib import Path

from framework.io_utils import read_json


def generate_prepared_readme(experiment_dir: Path) -> str:
    manifest = read_json(experiment_dir / "manifest.json")
    schedule = read_json(experiment_dir / "execution" / "schedule.json")
    preflight = read_json(experiment_dir / "provenance" / "preflight.json")
    workload = read_json(
        experiment_dir / "execution" / "workload" / "manifest.json"
    )

    exp = manifest["experiment"]
    topology = manifest["topology"]
    variants = []

    for run in schedule["runs"]:
        variant = run["variant"]
        if variant not in variants:
            variants.append(variant)

    dirty_sources = [
        name
        for name, dirty in manifest
        .get("extensions", {})
        .get("source_dirty", {})
        .items()
        if dirty
    ]

    untracked_sources = [
        name
        for name, present in manifest
        .get("extensions", {})
        .get("source_untracked_present", {})
        .items()
        if present
    ]

    dirty_note = ", ".join(dirty_sources) if dirty_sources else "none"
    untracked_note = (
        ", ".join(untracked_sources)
        if untracked_sources else "none"
    )

    if "environment" in exp:
        placement_line = f"environment: {exp['environment']}"
    else:
        deployment = manifest.get("deployment", {})
        placement_line = (
            "deployment: "
            f"{deployment.get('provider', 'unknown')}/"
            f"{deployment.get('name', 'unknown')}"
        )

    return f"""# {exp["id"]}

Generated NGI541 experiment record.

## Preparation status

```text
state: READY
workload: {exp["workload"]}
{placement_line}
topology: {topology["class"]}
planned runs: {len(schedule["runs"])}
comparison mode: {schedule["comparison_mode"]}
variants: {", ".join(variants)}
preflight: {"PASS" if preflight["passed"] else "FAIL"}
tracked-dirty sources: {dirty_note}
sources with untracked files: {untracked_note}
```

## HTTP/3 workload

```text
transport: {workload["transport"]}
application protocol: {workload["application_protocol"]}
cipher suite: {workload["cipher_suite"]}
endpoint: {workload["server"]["host"]}:{workload["server"]["port"]}
```

## Canonical records

```text
manifest.json
config/request.json
config/resolved.json
environment/
provenance/
execution/schedule.json
execution/workload/
state.json
```

Measured runs are appended below:

```text
raw/runs/
```

Each attempt preserves `measurement.json`, client logs, server logs, and the generated NGINX configuration.

Processed outputs and figures are derived artifacts and are generated after measured execution.

This README is generated from experiment metadata and may be regenerated.
"""
