from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from framework.dual_host_telemetry import (
    definition_sha256 as telemetry_definition_sha256,
    load_definition as load_telemetry_definition,
)
from framework.io_utils import (
    FrameworkError,
    atomic_write_json,
    atomic_write_text,
    read_json,
    write_immutable_json,
)
from framework.loadgen_runtime import (
    definition_sha256 as loadgen_definition_sha256,
    load_definition as load_loadgen_definition,
)
from framework.network_evidence import (
    definition_sha256 as network_definition_sha256,
    load_definition as load_network_definition,
)
from framework.scientific_corpus import (
    definition_sha256 as corpus_definition_sha256,
    load_definition as load_corpus_definition,
)
from framework.transport_security import (
    definition_sha256 as security_definition_sha256,
    load_definition as load_security_definition,
)
from framework.workload_planner import (
    definition_sha256 as planner_definition_sha256,
    load_definition as load_planner_definition,
)

SCHEMA_VERSION = 1
CLAIM_SCOPE = "r6.5.3-final-freeze-no-performance-claim"
SELECTION_POLICY = "latest-compatible"

# This sequence is intentionally the frozen R6.5.3 lifecycle contract.  It is a
# validation/freeze lifecycle; the underlying evidence artifacts were produced
# by R6.5.3a-g in their own dependency order.
LIFECYCLE_STATES = [
    "CREATED",
    "INPUTS_RESOLVING",
    "INPUTS_FROZEN",
    "PROFILES_VALIDATED",
    "RUNTIME_READY",
    "SECURITY_VERIFIED",
    "NETWORK_ENVELOPE_FROZEN",
    "CORPUS_READY",
    "TELEMETRY_READY",
    "STOCK_PROBING",
    "PLAN_DERIVED",
    "PLAN_FROZEN",
    "VALIDATED",
    "COMPLETE",
]
ACTIVE_STATES = set(LIFECYCLE_STATES[:-1])

_INPUT_SPECS = {
    "network_evidence": {
        "config_key": "network_evidence_config",
        "root": Path("qualifications/network-evidence"),
        "id_field": "evidence_id",
        "definition_loader": load_network_definition,
        "definition_sha": network_definition_sha256,
        "inventory_required": True,
        "canonical": ["processed/summary.json", "processed/network-envelope.json"],
    },
    "loadgen_runtime": {
        "config_key": "loadgen_runtime_config",
        "root": Path("qualifications/loadgen-runtime"),
        "id_field": "runtime_id",
        "definition_loader": load_loadgen_definition,
        "definition_sha": loadgen_definition_sha256,
        "inventory_required": False,
        "canonical": ["processed/summary.json"],
    },
    "scientific_corpus": {
        "config_key": "scientific_corpus_config",
        "root": Path("corpora/scientific"),
        "id_field": "corpus_id",
        "definition_loader": load_corpus_definition,
        "definition_sha": corpus_definition_sha256,
        "inventory_required": True,
        "canonical": [
            "processed/summary.json",
            "processed/registry.json",
            "processed/coverage-contract.json",
        ],
    },
    "transport_security": {
        "config_key": "transport_security_config",
        "root": Path("qualifications/transport-security"),
        "id_field": "qualification_id",
        "definition_loader": load_security_definition,
        "definition_sha": security_definition_sha256,
        "inventory_required": True,
        "canonical": ["processed/summary.json", "processed/security-gate.json"],
    },
    "dual_host_telemetry": {
        "config_key": "dual_host_telemetry_config",
        "root": Path("qualifications/telemetry"),
        "id_field": "qualification_id",
        "definition_loader": load_telemetry_definition,
        "definition_sha": telemetry_definition_sha256,
        "inventory_required": True,
        "canonical": ["processed/summary.json", "processed/capabilities.json"],
    },
    "workload_planner": {
        "config_key": "workload_planner_config",
        "root": Path("qualifications/workload-planner"),
        "id_field": "qualification_id",
        "definition_loader": load_planner_definition,
        "definition_sha": planner_definition_sha256,
        "inventory_required": True,
        "canonical": ["processed/summary.json", "processed/workload-plan.json"],
    },
}


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _semantic_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _utc_rfc3339() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _utc_id_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    if not slug:
        raise FrameworkError("freeze.name must contain at least one alphanumeric character")
    return slug


def definition_sha256(definition: dict[str, Any]) -> str:
    return _semantic_sha256(definition)


def validate_definition(definition: dict[str, Any]) -> None:
    if not isinstance(definition, dict) or definition.get("schema_version") != SCHEMA_VERSION:
        raise FrameworkError("R6.5.3h definition requires schema_version=1")

    freeze = definition.get("freeze")
    if not isinstance(freeze, dict) or not isinstance(freeze.get("name"), str):
        raise FrameworkError("freeze.name is required")
    if freeze.get("claim_scope") != CLAIM_SCOPE:
        raise FrameworkError(f"freeze.claim_scope must be {CLAIM_SCOPE!r}")

    inputs = definition.get("inputs")
    if not isinstance(inputs, dict):
        raise FrameworkError("inputs must be an object")
    for spec in _INPUT_SPECS.values():
        key = spec["config_key"]
        value = inputs.get(key)
        if not isinstance(value, str) or not value:
            raise FrameworkError(f"inputs.{key} is required")
        path = Path(value)
        if path.is_absolute() or ".." in path.parts:
            raise FrameworkError(f"inputs.{key} must be a portable repo-relative path")

    policy = definition.get("policy")
    if not isinstance(policy, dict):
        raise FrameworkError("policy must be an object")
    if policy.get("selection") != SELECTION_POLICY:
        raise FrameworkError(f"policy.selection must be {SELECTION_POLICY!r}")
    if policy.get("resume") != "resume-from-last-completed-phase":
        raise FrameworkError("policy.resume must be 'resume-from-last-completed-phase'")
    if policy.get("reuse_complete_if_inputs_identical") is not True:
        raise FrameworkError("policy.reuse_complete_if_inputs_identical must be true")

    requirements = definition.get("requirements")
    if not isinstance(requirements, dict):
        raise FrameworkError("requirements must be an object")

    profiles = requirements.get("profiles")
    if profiles != [
        "clas12-event-stream",
        "lcls-detector-frame",
        "hacc-multifile-dataset",
    ]:
        raise FrameworkError("requirements.profiles must pin the three canonical scientific profiles")

    variants = requirements.get("variants")
    if variants != ["stock", "ngi541-direct"]:
        raise FrameworkError("requirements.variants must be ['stock', 'ngi541-direct']")

    transport = requirements.get("transport")
    expected_transport = {
        "protocol": "http3-only",
        "tls_version": "1.3",
        "cipher_suite": "TLS_AES_128_GCM_SHA256",
        "verify_peer": True,
        "allow_0rtt": False,
    }
    if transport != expected_transport:
        raise FrameworkError("requirements.transport must pin the frozen HTTP/3/TLS contract")

    network = requirements.get("network")
    if not isinstance(network, dict):
        raise FrameworkError("requirements.network must be an object")
    if network.get("direction") != "dut-to-loadgen":
        raise FrameworkError("requirements.network.direction must be 'dut-to-loadgen'")
    minimum = network.get("minimum_observations")
    if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 3:
        raise FrameworkError("requirements.network.minimum_observations must be >= 3")

    plan = requirements.get("plan")
    if not isinstance(plan, dict):
        raise FrameworkError("requirements.plan must be an object")
    if plan.get("condition_count") != 12:
        raise FrameworkError("requirements.plan.condition_count must be 12")
    if plan.get("service_target_fractions") != [0.5, 0.8]:
        raise FrameworkError("requirements.plan.service_target_fractions must be [0.5, 0.8]")
    if plan.get("worker_semantics") != ["single", "physical-core-count"]:
        raise FrameworkError("requirements.plan.worker_semantics must pin the two worker semantics")
    if plan.get("calibration_variant") != "stock":
        raise FrameworkError("requirements.plan.calibration_variant must be 'stock'")
    if plan.get("candidate_variant_bias_prohibited") is not True:
        raise FrameworkError("requirements.plan.candidate_variant_bias_prohibited must be true")


def load_definition(path: Path) -> dict[str, Any]:
    definition = read_json(path)
    validate_definition(definition)
    return definition


def _resolve_repo_path(repo_root: Path, relative: str, label: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise FrameworkError(f"{label} must be a repo-relative path")
    resolved = (repo_root / path).resolve()
    try:
        resolved.relative_to(repo_root.resolve())
    except ValueError as exc:
        raise FrameworkError(f"{label} escapes repository root") from exc
    if not resolved.is_file():
        raise FrameworkError(f"missing {label}: {relative}")
    return resolved


def _verify_artifact_inventory(root: Path) -> str:
    inventory = root / "artifacts.sha256"
    if not inventory.is_file():
        raise FrameworkError(f"missing artifacts.sha256: {root}")
    text = inventory.read_text(encoding="utf-8")
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        parts = line.split(None, 1)
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            raise FrameworkError(f"invalid artifacts.sha256 line {line_number} in {root.name}")
        expected, relative = parts
        relative = relative.strip()
        rel_path = Path(relative)
        if rel_path.is_absolute() or ".." in rel_path.parts:
            raise FrameworkError(f"unsafe artifact path in {root.name}: {relative}")
        path = root / rel_path
        if not path.is_file():
            raise FrameworkError(f"missing artifact listed by {root.name}: {relative}")
        actual = _sha256_file(path)
        if actual != expected:
            raise FrameworkError(f"artifact hash mismatch in {root.name}: {relative}")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _artifact_record(
    *,
    repo_root: Path,
    root: Path,
    summary: dict[str, Any],
    definition_sha: str,
    id_field: str,
    inventory_required: bool,
    canonical: list[str],
) -> dict[str, Any]:
    artifact_id = summary.get(id_field)
    if artifact_id != root.name:
        raise FrameworkError(f"artifact id/root mismatch for {root}")
    if summary.get("status") != "COMPLETE":
        raise FrameworkError(f"artifact is not COMPLETE: {root.name}")
    if summary.get("definition_sha256") != definition_sha:
        raise FrameworkError(f"artifact definition SHA mismatch: {root.name}")

    inventory_sha: str | None = None
    if inventory_required:
        inventory_sha = _verify_artifact_inventory(root)
    elif (root / "artifacts.sha256").is_file():
        inventory_sha = _verify_artifact_inventory(root)

    canonical_files: dict[str, str] = {}
    for relative in canonical:
        path = root / relative
        if not path.is_file():
            raise FrameworkError(f"missing canonical artifact {relative} in {root.name}")
        canonical_files[relative] = _sha256_file(path)

    return {
        "artifact_id": artifact_id,
        "root": root.relative_to(repo_root).as_posix(),
        "definition_sha256": definition_sha,
        "summary_sha256": canonical_files["processed/summary.json"],
        "artifact_inventory_sha256": inventory_sha,
        "canonical_files": canonical_files,
    }


def _discover_latest_artifact(
    *,
    repo_root: Path,
    definition_path: Path,
    spec: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], Path]:
    definition = spec["definition_loader"](definition_path)
    def_sha = spec["definition_sha"](definition)
    parent = repo_root / spec["root"]
    matches: list[tuple[Path, dict[str, Any]]] = []
    if parent.is_dir():
        for child in sorted((p for p in parent.iterdir() if p.is_dir()), reverse=True):
            summary_path = child / "processed" / "summary.json"
            if not summary_path.is_file():
                continue
            summary = read_json(summary_path)
            if summary.get("status") != "COMPLETE":
                continue
            if summary.get("definition_sha256") != def_sha:
                continue
            if summary.get(spec["id_field"]) != child.name:
                continue
            matches.append((child, summary))
    if not matches:
        raise FrameworkError(
            f"no COMPLETE {spec['root'].name} artifact with definition SHA {def_sha}"
        )
    root, summary = matches[0]
    record = _artifact_record(
        repo_root=repo_root,
        root=root,
        summary=summary,
        definition_sha=def_sha,
        id_field=spec["id_field"],
        inventory_required=bool(spec["inventory_required"]),
        canonical=list(spec["canonical"]),
    )
    record["definition_config"] = definition_path.relative_to(repo_root).as_posix()
    record["definition_config_sha256"] = _sha256_file(definition_path)
    return record, definition, root


def resolve_inputs(definition: dict[str, Any], repo_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    validate_definition(definition)
    records: dict[str, Any] = {}
    definitions: dict[str, Any] = {}
    roots: dict[str, Path] = {}

    for name, spec in _INPUT_SPECS.items():
        config_path = _resolve_repo_path(
            repo_root,
            definition["inputs"][spec["config_key"]],
            f"{name} config",
        )
        record, sub_definition, root = _discover_latest_artifact(
            repo_root=repo_root,
            definition_path=config_path,
            spec=spec,
        )
        records[name] = record
        definitions[name] = sub_definition
        roots[name] = root

    identity = {
        "schema_version": 1,
        "selection_policy": SELECTION_POLICY,
        "artifacts": records,
    }
    input_sha = _semantic_sha256(identity)
    resolved = {**identity, "resolved_input_sha256": input_sha}
    context = {"definitions": definitions, "roots": roots}
    return resolved, context


def _load_pinned_context(resolved: dict[str, Any], repo_root: Path) -> dict[str, Any]:
    context: dict[str, Any] = {"definitions": {}, "roots": {}}
    artifacts = resolved.get("artifacts")
    if not isinstance(artifacts, dict):
        raise FrameworkError("pinned resolved-inputs.json is malformed")

    for name, spec in _INPUT_SPECS.items():
        record = artifacts.get(name)
        if not isinstance(record, dict):
            raise FrameworkError(f"pinned input missing artifact: {name}")
        config_rel = record.get("definition_config")
        root_rel = record.get("root")
        if not isinstance(config_rel, str) or not isinstance(root_rel, str):
            raise FrameworkError(f"pinned input paths are malformed: {name}")
        config = _resolve_repo_path(repo_root, config_rel, f"{name} config")
        if _sha256_file(config) != record.get("definition_config_sha256"):
            raise FrameworkError(f"pinned definition config changed after INPUTS_FROZEN: {name}")
        sub_definition = spec["definition_loader"](config)
        def_sha = spec["definition_sha"](sub_definition)
        if def_sha != record.get("definition_sha256"):
            raise FrameworkError(f"pinned definition SHA changed after INPUTS_FROZEN: {name}")
        root = (repo_root / root_rel).resolve()
        try:
            root.relative_to(repo_root.resolve())
        except ValueError as exc:
            raise FrameworkError(f"pinned artifact root escapes repository: {name}") from exc
        summary_path = root / "processed" / "summary.json"
        if not summary_path.is_file():
            raise FrameworkError(f"pinned artifact disappeared: {name}")
        summary = read_json(summary_path)
        actual = _artifact_record(
            repo_root=repo_root,
            root=root,
            summary=summary,
            definition_sha=def_sha,
            id_field=spec["id_field"],
            inventory_required=bool(spec["inventory_required"]),
            canonical=list(spec["canonical"]),
        )
        for key in (
            "artifact_id",
            "root",
            "definition_sha256",
            "summary_sha256",
            "artifact_inventory_sha256",
            "canonical_files",
        ):
            if actual.get(key) != record.get(key):
                raise FrameworkError(f"pinned artifact changed after INPUTS_FROZEN: {name}.{key}")
        context["definitions"][name] = sub_definition
        context["roots"][name] = root

    identity = {
        "schema_version": 1,
        "selection_policy": resolved.get("selection_policy"),
        "artifacts": artifacts,
    }
    if _semantic_sha256(identity) != resolved.get("resolved_input_sha256"):
        raise FrameworkError("pinned resolved-input identity SHA mismatch")
    return context


def _read_canonical(context: dict[str, Any], name: str, relative: str) -> dict[str, Any]:
    return read_json(context["roots"][name] / relative)


def validate_profiles(definition: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    summary = _read_canonical(context, "scientific_corpus", "processed/summary.json")
    registry = _read_canonical(context, "scientific_corpus", "processed/registry.json")
    required = definition["requirements"]["profiles"]
    observed = [row.get("profile_id") for row in registry.get("profiles", [])]
    if sorted(observed) != sorted(required) or len(observed) != len(required):
        raise FrameworkError("scientific corpus registry does not contain exactly the required profiles")
    if summary.get("profile_count") != len(required):
        raise FrameworkError("scientific corpus profile count mismatch")
    registry_identity = deepcopy(registry)
    registry_stated_sha = registry_identity.pop("corpus_registry_sha256", None)
    if _semantic_sha256(registry_identity) != registry_stated_sha:
        raise FrameworkError("scientific corpus registry semantic SHA mismatch")
    if summary.get("corpus_registry_sha256") != registry_stated_sha:
        raise FrameworkError("scientific corpus registry SHA linkage mismatch")
    for row in registry.get("profiles", []):
        if not isinstance(row.get("profile_sha256"), str) or len(row["profile_sha256"]) != 64:
            raise FrameworkError("scientific profile SHA is missing or invalid")
        if not isinstance(row.get("corpus_sha256"), str) or len(row["corpus_sha256"]) != 64:
            raise FrameworkError("scientific corpus SHA is missing or invalid")
    return {
        "profile_count": len(required),
        "profiles": sorted(observed),
        "corpus_registry_sha256": registry["corpus_registry_sha256"],
    }


def validate_runtime(context: dict[str, Any]) -> dict[str, Any]:
    summary = _read_canonical(context, "loadgen_runtime", "processed/summary.json")
    runtime = summary.get("runtime")
    if not isinstance(runtime, dict) or runtime.get("http3_capable") is not True:
        raise FrameworkError("load-generator curl HTTP/3 capability is not frozen PASS")
    h2load = runtime.get("h2load")
    if not isinstance(h2load, dict):
        raise FrameworkError("load-generator h2load evidence is missing")
    for key in (
        "http3_capable",
        "json_output_capable",
        "timing_script_capable",
        "rps_capable",
        "connections_streams_capable",
    ):
        if h2load.get(key) is not True:
            raise FrameworkError(f"load-generator h2load capability is not PASS: {key}")
    for key in ("curl_sha256",):
        value = runtime.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise FrameworkError(f"load-generator runtime {key} is invalid")
    if not isinstance(h2load.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", h2load["sha256"]):
        raise FrameworkError("h2load SHA-256 is invalid")
    return {
        "runtime_id": summary["runtime_id"],
        "architecture": summary.get("remote", {}).get("architecture"),
        "curl_sha256": runtime["curl_sha256"],
        "h2load_sha256": h2load["sha256"],
    }


def validate_security(definition: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    summary = _read_canonical(context, "transport_security", "processed/summary.json")
    gate = _read_canonical(context, "transport_security", "processed/security-gate.json")
    req = definition["requirements"]["transport"]
    if gate.get("passed") is not True:
        raise FrameworkError("transport security gate did not pass")
    if gate.get("protocol") != req["protocol"]:
        raise FrameworkError("transport protocol mismatch in security gate")
    if gate.get("tls_version") != req["tls_version"]:
        raise FrameworkError("TLS version mismatch in security gate")
    if gate.get("cipher_suite") != req["cipher_suite"]:
        raise FrameworkError("TLS cipher mismatch in security gate")
    if gate.get("peer_verification") != "required-and-verified-by-curl":
        raise FrameworkError("peer verification is not frozen PASS")
    if gate.get("zero_rtt") != "disabled":
        raise FrameworkError("0-RTT must be disabled")
    if gate.get("http_fallback") != "prohibited":
        raise FrameworkError("HTTP fallback must be prohibited")
    variants = gate.get("variants")
    if not isinstance(variants, list):
        raise FrameworkError("transport security variant evidence is missing")
    observed_names = [row.get("variant") for row in variants]
    if observed_names != definition["requirements"]["variants"]:
        raise FrameworkError("transport security variants do not match frozen requirements")
    if any(row.get("passed") is not True for row in variants):
        raise FrameworkError("one or more transport-security variants failed")
    gate_identity = deepcopy(gate)
    gate_stated_sha = gate_identity.pop("security_gate_sha256", None)
    if _semantic_sha256(gate_identity) != gate_stated_sha:
        raise FrameworkError("security-gate semantic SHA mismatch")
    if summary.get("security_gate_sha256") != gate_stated_sha:
        raise FrameworkError("security-gate SHA linkage mismatch")

    net = _read_canonical(context, "network_evidence", "processed/summary.json")
    load = _read_canonical(context, "loadgen_runtime", "processed/summary.json")
    corpus = _read_canonical(context, "scientific_corpus", "processed/summary.json")
    if summary.get("network_evidence_id") != net.get("evidence_id"):
        raise FrameworkError("transport-security network evidence linkage mismatch")
    if summary.get("loadgen_runtime_id") != load.get("runtime_id"):
        raise FrameworkError("transport-security loadgen runtime linkage mismatch")
    if summary.get("scientific_corpus_id") != corpus.get("corpus_id"):
        raise FrameworkError("transport-security scientific corpus linkage mismatch")
    return {
        "qualification_id": summary["qualification_id"],
        "security_gate_sha256": gate["security_gate_sha256"],
        "variants": observed_names,
        "cipher_suite": gate["cipher_suite"],
    }


def validate_network(definition: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    summary = _read_canonical(context, "network_evidence", "processed/summary.json")
    envelope = _read_canonical(context, "network_evidence", "processed/network-envelope.json")
    req = definition["requirements"]["network"]
    if envelope.get("direction_semantic") != req["direction"]:
        raise FrameworkError("network envelope semantic direction mismatch")
    if envelope.get("observation_count", 0) < req["minimum_observations"]:
        raise FrameworkError("network envelope has fewer observations than required")
    if envelope.get("aggregation") != "minimum":
        raise FrameworkError("network envelope aggregation must be minimum")
    service = envelope.get("service_envelope_mbps")
    if not isinstance(service, (int, float)) or isinstance(service, bool) or service <= 0:
        raise FrameworkError("network service envelope must be positive")
    identity = deepcopy(envelope)
    stated_sha = identity.pop("envelope_sha256", None)
    if _semantic_sha256(identity) != stated_sha:
        raise FrameworkError("network envelope semantic SHA mismatch")
    if summary.get("envelope_sha256") != stated_sha:
        raise FrameworkError("network summary/envelope SHA linkage mismatch")
    return {
        "evidence_id": summary["evidence_id"],
        "observation_count": envelope["observation_count"],
        "service_envelope_mbps": float(service),
        "envelope_sha256": stated_sha,
    }


def validate_corpus(definition: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    summary = _read_canonical(context, "scientific_corpus", "processed/summary.json")
    required_profiles = definition["requirements"]["profiles"]
    observed = [row.get("profile_id") for row in summary.get("profiles", [])]
    if sorted(observed) != sorted(required_profiles):
        raise FrameworkError("scientific corpus profile set mismatch")
    hacc = summary.get("hacc")
    if not isinstance(hacc, dict):
        raise FrameworkError("HACC corpus summary is missing")
    if hacc.get("logical_objects") != 19260:
        raise FrameworkError("HACC logical object count no longer matches frozen corpus")
    if hacc.get("logical_bytes") != 4442781786482:
        raise FrameworkError("HACC logical byte total no longer matches frozen corpus")
    if sorted(hacc.get("coverage_modes", [])) != sorted(
        ["full", "deterministic-stratified", "time-window"]
    ):
        raise FrameworkError("HACC coverage modes do not match frozen contract")
    return {
        "corpus_id": summary["corpus_id"],
        "corpus_registry_sha256": summary["corpus_registry_sha256"],
        "hacc_logical_objects": hacc["logical_objects"],
        "hacc_logical_bytes": hacc["logical_bytes"],
    }


def validate_telemetry(context: dict[str, Any]) -> dict[str, Any]:
    summary = _read_canonical(context, "dual_host_telemetry", "processed/summary.json")
    net = _read_canonical(context, "network_evidence", "processed/summary.json")
    load = _read_canonical(context, "loadgen_runtime", "processed/summary.json")
    security = _read_canonical(context, "transport_security", "processed/summary.json")
    if summary.get("network_evidence_id") != net.get("evidence_id"):
        raise FrameworkError("telemetry network evidence linkage mismatch")
    if summary.get("loadgen_runtime_id") != load.get("runtime_id"):
        raise FrameworkError("telemetry loadgen linkage mismatch")
    if summary.get("transport_security_id") != security.get("qualification_id"):
        raise FrameworkError("telemetry security linkage mismatch")
    if int(summary.get("samples_per_host", 0)) < 4:
        raise FrameworkError("telemetry qualification has too few samples")
    capabilities = summary.get("capabilities")
    if not isinstance(capabilities, dict):
        raise FrameworkError("telemetry capabilities are missing")
    power = summary.get("dut_estimated_power")
    if not isinstance(power, dict):
        raise FrameworkError("DUT power telemetry contract is missing")
    if power.get("comparison_scope") != "same-host-paired-only":
        raise FrameworkError("DUT power comparison scope changed")
    load_power = summary.get("loadgen_power")
    if not isinstance(load_power, dict) or load_power.get("available") is not False:
        raise FrameworkError("loadgen power contract must remain unavailable without external sensor")
    return {
        "qualification_id": summary["qualification_id"],
        "samples_per_host": summary["samples_per_host"],
        "interval_seconds": summary["interval_seconds"],
        "telemetry_contract_sha256": summary["telemetry_contract_sha256"],
        "dut_estimated_package_power_available": bool(power.get("available")),
    }


def _plan_semantic_sha(plan: dict[str, Any]) -> str:
    copy = deepcopy(plan)
    stated = copy.pop("plan_sha256", None)
    actual = _semantic_sha256(copy)
    if stated != actual:
        raise FrameworkError("workload plan semantic SHA mismatch")
    return actual


def validate_planner_probe(context: dict[str, Any]) -> dict[str, Any]:
    summary = _read_canonical(context, "workload_planner", "processed/summary.json")
    plan = _read_canonical(context, "workload_planner", "processed/workload-plan.json")
    if summary.get("calibration_variant") != "stock" or plan.get("calibration_variant") != "stock":
        raise FrameworkError("workload planner must be calibrated on stock only")
    if int(summary.get("probe_count", 0)) <= 0:
        raise FrameworkError("workload planner has no stock calibration probes")
    if plan.get("planner_policy", {}).get("candidate_variant_bias_prohibited") is not True:
        raise FrameworkError("candidate variant bias prohibition is missing")
    return {
        "qualification_id": summary["qualification_id"],
        "probe_count": summary["probe_count"],
        "calibration_variant": "stock",
    }


def validate_plan(definition: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    summary = _read_canonical(context, "workload_planner", "processed/summary.json")
    plan = _read_canonical(context, "workload_planner", "processed/workload-plan.json")
    req = definition["requirements"]["plan"]
    if plan.get("claim_scope") != "frozen-workload-plan-no-performance-claim":
        raise FrameworkError("workload plan claim scope changed")
    if plan.get("calibration_variant") != req["calibration_variant"]:
        raise FrameworkError("workload plan calibration variant mismatch")
    conditions = plan.get("conditions")
    if not isinstance(conditions, list) or len(conditions) != req["condition_count"]:
        raise FrameworkError("workload plan condition count mismatch")

    required_profiles = definition["requirements"]["profiles"]
    required_fractions = req["service_target_fractions"]
    required_workers = req["worker_semantics"]
    expected = {
        (profile, float(fraction), worker)
        for profile in required_profiles
        for fraction in required_fractions
        for worker in required_workers
    }
    observed: set[tuple[str, float, str]] = set()
    condition_ids: set[str] = set()
    for row in conditions:
        key = (
            row.get("profile_id"),
            float(row.get("service_fraction")),
            row.get("worker_semantic"),
        )
        observed.add(key)
        cid = row.get("condition_id")
        if not isinstance(cid, str) or cid in condition_ids:
            raise FrameworkError("workload plan condition IDs must be unique")
        condition_ids.add(cid)
        client = row.get("client")
        if not isinstance(client, dict):
            raise FrameworkError(f"workload plan client shape missing: {cid}")
        for field in ("connections", "max_concurrent_streams_per_connection", "threads"):
            if not isinstance(client.get(field), int) or isinstance(client.get(field), bool) or client[field] < 1:
                raise FrameworkError(f"invalid workload-plan client field {field}: {cid}")
        if not isinstance(row.get("target_goodput_mbps"), (int, float)) or row["target_goodput_mbps"] <= 0:
            raise FrameworkError(f"invalid target_goodput_mbps: {cid}")
    if observed != expected:
        raise FrameworkError("workload plan does not contain the exact profile × service-target × worker cross-product")

    network = _read_canonical(context, "network_evidence", "processed/summary.json")
    runtime = _read_canonical(context, "loadgen_runtime", "processed/summary.json")
    corpus = _read_canonical(context, "scientific_corpus", "processed/summary.json")
    security = _read_canonical(context, "transport_security", "processed/summary.json")
    telemetry = _read_canonical(context, "dual_host_telemetry", "processed/summary.json")
    expected_links = {
        "network_evidence_id": network["evidence_id"],
        "loadgen_runtime_id": runtime["runtime_id"],
        "scientific_corpus_id": corpus["corpus_id"],
        "transport_security_id": security["qualification_id"],
        "telemetry_qualification_id": telemetry["qualification_id"],
    }
    for key, value in expected_links.items():
        if summary.get(key) != value:
            raise FrameworkError(f"workload planner linkage mismatch: {key}")

    if plan.get("network", {}).get("evidence_id") != network["evidence_id"]:
        raise FrameworkError("workload plan network evidence linkage mismatch")
    if plan.get("scientific_corpus", {}).get("corpus_id") != corpus["corpus_id"]:
        raise FrameworkError("workload plan scientific corpus linkage mismatch")
    if plan.get("transport") != {
        "protocol": "http3-only",
        "tls_version": "1.3",
        "cipher_suite": "TLS_AES_128_GCM_SHA256",
        "allow_0rtt": False,
    }:
        raise FrameworkError("workload plan transport contract mismatch")
    if plan.get("measurement", {}).get("qlog") != "disabled-by-default-performance-run":
        raise FrameworkError("workload plan qlog policy mismatch")
    if plan.get("measurement", {}).get("h2load_json_quic_metrics") != "required":
        raise FrameworkError("workload plan QUIC metric contract mismatch")
    if plan.get("planner_policy", {}).get("candidate_variant_bias_prohibited") is not True:
        raise FrameworkError("workload plan candidate bias prohibition is missing")

    planner_inputs_path = context["roots"]["workload_planner"] / "inputs" / "resolved-inputs.json"
    planner_inputs = read_json(planner_inputs_path)
    if planner_inputs.get("network_envelope_sha256") != _sha256_file(
        context["roots"]["network_evidence"] / "processed" / "network-envelope.json"
    ):
        raise FrameworkError("workload planner network-envelope SHA linkage mismatch")
    if planner_inputs.get("loadgen_summary_sha256") != _sha256_file(
        context["roots"]["loadgen_runtime"] / "processed" / "summary.json"
    ):
        raise FrameworkError("workload planner loadgen summary SHA linkage mismatch")
    if planner_inputs.get("transport_security_sha256") != _sha256_file(
        context["roots"]["transport_security"] / "processed" / "security-gate.json"
    ):
        raise FrameworkError("workload planner security-gate SHA linkage mismatch")
    if planner_inputs.get("telemetry_summary_sha256") != _sha256_file(
        context["roots"]["dual_host_telemetry"] / "processed" / "summary.json"
    ):
        raise FrameworkError("workload planner telemetry summary SHA linkage mismatch")
    if planner_inputs.get("scientific_corpus_summary_sha256") != _sha256_file(
        context["roots"]["scientific_corpus"] / "processed" / "summary.json"
    ):
        raise FrameworkError("workload planner scientific-corpus summary SHA linkage mismatch")
    if plan.get("resolved_input_sha256") != summary.get("resolved_input_sha256"):
        raise FrameworkError("workload plan/summary resolved-input SHA linkage mismatch")

    plan_sha = _plan_semantic_sha(plan)
    if summary.get("plan_sha256") != plan_sha:
        raise FrameworkError("workload planner summary/plan SHA linkage mismatch")
    if summary.get("plan_id") != plan.get("plan_id"):
        raise FrameworkError("workload planner summary/plan ID linkage mismatch")
    return {
        "plan_id": plan["plan_id"],
        "plan_sha256": plan_sha,
        "condition_count": len(conditions),
        "measurement": plan["measurement"],
        "service_target_fractions": plan["network"]["service_target_fractions"],
    }


def build_final_manifest(
    definition: dict[str, Any],
    resolved: dict[str, Any],
    context: dict[str, Any],
) -> dict[str, Any]:
    profiles = validate_profiles(definition, context)
    runtime = validate_runtime(context)
    security = validate_security(definition, context)
    network = validate_network(definition, context)
    corpus = validate_corpus(definition, context)
    telemetry = validate_telemetry(context)
    planner = validate_planner_probe(context)
    plan = validate_plan(definition, context)

    security_definition = context["definitions"]["transport_security"]
    variants = {
        name: {
            "binary_sha256": spec["sha256"],
            "runtime_libraries": [
                {"sha256": lib["sha256"]} for lib in spec.get("runtime_libraries", [])
            ],
        }
        for name, spec in security_definition["variants"].items()
    }

    identity = {
        "schema_version": 1,
        "freeze_name": definition["freeze"]["name"],
        "claim_scope": CLAIM_SCOPE,
        "resolved_input_sha256": resolved["resolved_input_sha256"],
        "inputs": resolved["artifacts"],
        "qualification": {
            "scientific_profiles": profiles,
            "loadgen_runtime": runtime,
            "transport_security": security,
            "network_envelope": network,
            "scientific_corpus": corpus,
            "dual_host_telemetry": telemetry,
            "stock_planning": planner,
            "workload_plan": plan,
        },
        "variants": variants,
        "r6_5_4_execution_contract": {
            "variants": definition["requirements"]["variants"],
            "workload_plan_id": plan["plan_id"],
            "workload_plan_sha256": plan["plan_sha256"],
            "same_frozen_plan_for_all_variants": True,
            "adaptive_replanning_prohibited": True,
            "candidate_variant_tuning_prohibited": True,
            "metric_dependent_retry_prohibited": True,
            "metric_dependent_outlier_deletion_prohibited": True,
            "qlog_default": "disabled-by-default-performance-run",
            "h2load_json_quic_metrics": "required",
        },
    }
    final = {**identity, "freeze_sha256": _semantic_sha256(identity)}
    return final


def _initial_state(freeze_id: str, def_sha: str) -> dict[str, Any]:
    now = _utc_rfc3339()
    return {
        "schema_version": 1,
        "freeze_id": freeze_id,
        "definition_sha256": def_sha,
        "state": "CREATED",
        "last_completed_state": "CREATED",
        "created_at": now,
        "updated_at": now,
        "completed_at": None,
        "failure": None,
        "history": [{"state": "CREATED", "at": now}],
    }


def _transition(root: Path, target: str) -> dict[str, Any]:
    if target not in LIFECYCLE_STATES:
        raise FrameworkError(f"invalid R6.5.3h lifecycle target: {target}")
    path = root / "state.json"
    state = read_json(path)
    current = state.get("state")
    if current == "FAILED":
        current = state.get("last_completed_state")
    if current not in LIFECYCLE_STATES:
        raise FrameworkError(f"invalid R6.5.3h lifecycle state: {current!r}")
    current_index = LIFECYCLE_STATES.index(current)
    target_index = LIFECYCLE_STATES.index(target)
    if target_index != current_index + 1:
        raise FrameworkError(f"illegal R6.5.3h lifecycle transition: {current} -> {target}")
    now = _utc_rfc3339()
    updated = deepcopy(state)
    updated["state"] = target
    updated["last_completed_state"] = target
    updated["updated_at"] = now
    updated["failure"] = None
    updated.setdefault("history", []).append({"state": target, "at": now})
    if target == "COMPLETE":
        updated["completed_at"] = now
    atomic_write_json(path, updated)
    return updated


def _mark_failed(root: Path, stage: str, exc: Exception) -> None:
    path = root / "state.json"
    state = read_json(path)
    if state.get("state") == "COMPLETE":
        return
    now = _utc_rfc3339()
    state["state"] = "FAILED"
    state["updated_at"] = now
    state["failure"] = {
        "stage": stage,
        "message": str(exc),
        "at": now,
    }
    atomic_write_json(path, state)


def _resume_failed(root: Path) -> dict[str, Any]:
    path = root / "state.json"
    state = read_json(path)
    if state.get("state") != "FAILED":
        return state
    last = state.get("last_completed_state")
    if last not in LIFECYCLE_STATES:
        raise FrameworkError("FAILED R6.5.3h state has invalid last_completed_state")
    now = _utc_rfc3339()
    state["state"] = last
    state["updated_at"] = now
    state["failure"] = None
    state.setdefault("history", []).append({"state": last, "at": now, "event": "resume"})
    atomic_write_json(path, state)
    return state


def _find_incomplete(output_root: Path, def_sha: str) -> list[Path]:
    matches: list[Path] = []
    if not output_root.is_dir():
        return matches
    for child in sorted((p for p in output_root.iterdir() if p.is_dir()), reverse=True):
        state_path = child / "state.json"
        definition_path = child / "definition.json"
        if not state_path.is_file() or not definition_path.is_file():
            continue
        frozen_definition = read_json(definition_path)
        if definition_sha256(frozen_definition) != def_sha:
            continue
        state = read_json(state_path)
        if state.get("state") != "COMPLETE":
            matches.append(child)
    return matches


def _find_reusable(output_root: Path, def_sha: str, input_sha: str) -> Path | None:
    if not output_root.is_dir():
        return None
    for child in sorted((p for p in output_root.iterdir() if p.is_dir()), reverse=True):
        state_path = child / "state.json"
        resolved_path = child / "inputs" / "resolved-inputs.json"
        manifest_path = child / "processed" / "final-manifest.json"
        if not (state_path.is_file() and resolved_path.is_file() and manifest_path.is_file()):
            continue
        state = read_json(state_path)
        if state.get("state") != "COMPLETE" or state.get("definition_sha256") != def_sha:
            continue
        resolved = read_json(resolved_path)
        if resolved.get("resolved_input_sha256") != input_sha:
            continue
        return child
    return None


def _final_inventory(root: Path) -> str:
    rows: list[str] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        if rel in {"artifacts.sha256", "state.json"}:
            continue
        rows.append(f"{_sha256_file(path)}  {rel}")
    content = "\n".join(rows) + "\n"
    atomic_write_text(root / "artifacts.sha256", content)
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _write_summary(root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    summary = {
        "schema_version": 1,
        "freeze_id": root.name,
        "status": "COMPLETE",
        "claim_scope": CLAIM_SCOPE,
        "resolved_input_sha256": manifest["resolved_input_sha256"],
        "freeze_sha256": manifest["freeze_sha256"],
        "workload_plan_id": manifest["qualification"]["workload_plan"]["plan_id"],
        "workload_plan_sha256": manifest["qualification"]["workload_plan"]["plan_sha256"],
        "condition_count": manifest["qualification"]["workload_plan"]["condition_count"],
        "variants": manifest["r6_5_4_execution_contract"]["variants"],
    }
    write_immutable_json(root / "processed" / "summary.json", summary)
    write_immutable_json(root / "processed" / "final-manifest.json", manifest)
    atomic_write_text(
        root / "processed" / "SUMMARY.md",
        "# R6.5.3h final freeze\n\n"
        f"- Freeze: `{root.name}`\n"
        f"- Freeze SHA-256: `{manifest['freeze_sha256']}`\n"
        f"- Workload plan: `{summary['workload_plan_id']}`\n"
        f"- Workload plan SHA-256: `{summary['workload_plan_sha256']}`\n"
        f"- Conditions: {summary['condition_count']}\n"
        "- Variants for R6.5.4: `stock`, `ngi541-direct`\n"
        "- Adaptive replanning after freeze: prohibited\n"
        "- Candidate variant participated in planning: no\n"
        "- Performance claim at R6.5.3h: none\n"
        "- Status: COMPLETE\n",
    )
    return summary


def _validate_final_bundle(root: Path, manifest: dict[str, Any]) -> None:
    if manifest.get("claim_scope") != CLAIM_SCOPE:
        raise FrameworkError("final manifest claim scope mismatch")
    identity = deepcopy(manifest)
    stated = identity.pop("freeze_sha256", None)
    if _semantic_sha256(identity) != stated:
        raise FrameworkError("final manifest semantic SHA mismatch")
    contract = manifest.get("r6_5_4_execution_contract", {})
    for key in (
        "same_frozen_plan_for_all_variants",
        "adaptive_replanning_prohibited",
        "candidate_variant_tuning_prohibited",
        "metric_dependent_retry_prohibited",
        "metric_dependent_outlier_deletion_prohibited",
    ):
        if contract.get(key) is not True:
            raise FrameworkError(f"final R6.5.4 contract invariant missing: {key}")
    if contract.get("variants") != ["stock", "ngi541-direct"]:
        raise FrameworkError("final R6.5.4 variant contract mismatch")


def run_final_freeze(
    definition: dict[str, Any],
    *,
    repo_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    validate_definition(definition)
    def_sha = definition_sha256(definition)
    output_root.mkdir(parents=True, exist_ok=True)

    incomplete = _find_incomplete(output_root, def_sha)
    if len(incomplete) > 1:
        ids = ", ".join(path.name for path in incomplete)
        raise FrameworkError(f"multiple incomplete R6.5.3h freezes match this definition: {ids}")

    if incomplete:
        root = incomplete[0]
        frozen_definition = read_json(root / "definition.json")
        if definition_sha256(frozen_definition) != def_sha:
            raise FrameworkError("incomplete freeze definition changed")
        state = _resume_failed(root)
        resolved_path = root / "inputs" / "resolved-inputs.json"
        if resolved_path.is_file():
            resolved = read_json(resolved_path)
            context = _load_pinned_context(resolved, repo_root)
        else:
            resolved = None
            context = None
        reused = False
    else:
        resolved, context = resolve_inputs(definition, repo_root)
        reusable = _find_reusable(output_root, def_sha, resolved["resolved_input_sha256"])
        if reusable is not None:
            context = _load_pinned_context(read_json(reusable / "inputs" / "resolved-inputs.json"), repo_root)
            manifest = read_json(reusable / "processed" / "final-manifest.json")
            _validate_final_bundle(reusable, manifest)
            if not (reusable / "artifacts.sha256").is_file():
                raise FrameworkError("COMPLETE final freeze is missing artifacts.sha256")
            return {
                "root": reusable,
                "summary": read_json(reusable / "processed" / "summary.json"),
                "manifest": manifest,
                "state": read_json(reusable / "state.json"),
                "reused": True,
            }
        freeze_id = (
            f"{_slug(definition['freeze']['name'])}-{_utc_id_timestamp()}-"
            f"{resolved['resolved_input_sha256'][:6]}"
        )
        root = output_root / freeze_id
        if root.exists():
            raise FrameworkError(f"refusing to overwrite final freeze directory: {root}")
        (root / "inputs").mkdir(parents=True)
        (root / "processed").mkdir(parents=True)
        write_immutable_json(root / "definition.json", definition)
        atomic_write_json(root / "state.json", _initial_state(freeze_id, def_sha))
        state = read_json(root / "state.json")
        reused = False

    def ensure_context() -> tuple[dict[str, Any], dict[str, Any]]:
        nonlocal resolved, context
        if resolved is None:
            resolved, context = resolve_inputs(definition, repo_root)
        elif context is None:
            context = _load_pinned_context(resolved, repo_root)
        return resolved, context

    stage_actions: dict[str, Callable[[dict[str, Any], dict[str, Any]], Any]] = {
        "INPUTS_RESOLVING": lambda _r, _c: True,
        "INPUTS_FROZEN": lambda _r, _c: True,
        "PROFILES_VALIDATED": lambda _r, c: validate_profiles(definition, c),
        "RUNTIME_READY": lambda _r, c: validate_runtime(c),
        "SECURITY_VERIFIED": lambda _r, c: validate_security(definition, c),
        "NETWORK_ENVELOPE_FROZEN": lambda _r, c: validate_network(definition, c),
        "CORPUS_READY": lambda _r, c: validate_corpus(definition, c),
        "TELEMETRY_READY": lambda _r, c: validate_telemetry(c),
        "STOCK_PROBING": lambda _r, c: validate_planner_probe(c),
        "PLAN_DERIVED": lambda _r, c: validate_plan(definition, c),
        "PLAN_FROZEN": lambda _r, c: build_final_manifest(definition, _r, c),
        "VALIDATED": lambda _r, c: True,
        "COMPLETE": lambda _r, c: True,
    }

    try:
        while True:
            state = read_json(root / "state.json")
            current = state["state"]
            if current == "FAILED":
                state = _resume_failed(root)
                current = state["state"]
            if current == "COMPLETE":
                manifest = read_json(root / "processed" / "final-manifest.json")
                _validate_final_bundle(root, manifest)
                if not (root / "artifacts.sha256").is_file():
                    _final_inventory(root)
                return {
                    "root": root,
                    "summary": read_json(root / "processed" / "summary.json"),
                    "manifest": manifest,
                    "state": read_json(root / "state.json"),
                    "reused": reused,
                }

            next_state = LIFECYCLE_STATES[LIFECYCLE_STATES.index(current) + 1]
            stage = next_state
            try:
                if next_state == "INPUTS_RESOLVING":
                    ensure_context()
                    _transition(root, next_state)
                    continue

                pinned_resolved, pinned_context = ensure_context()

                if next_state == "INPUTS_FROZEN":
                    write_immutable_json(root / "inputs" / "resolved-inputs.json", pinned_resolved)
                    _load_pinned_context(pinned_resolved, repo_root)
                    _transition(root, next_state)
                    continue

                if current == "INPUTS_RESOLVING" and not (root / "inputs" / "resolved-inputs.json").is_file():
                    raise FrameworkError("INPUTS_RESOLVING cannot advance without frozen inputs")

                if (root / "inputs" / "resolved-inputs.json").is_file():
                    pinned_resolved = read_json(root / "inputs" / "resolved-inputs.json")
                    pinned_context = _load_pinned_context(pinned_resolved, repo_root)
                    resolved, context = pinned_resolved, pinned_context

                action = stage_actions[next_state]
                result = action(pinned_resolved, pinned_context)

                if next_state == "PLAN_FROZEN":
                    manifest = result
                    write_immutable_json(root / "processed" / "final-manifest.json", manifest)
                elif next_state == "VALIDATED":
                    manifest = read_json(root / "processed" / "final-manifest.json")
                    _validate_final_bundle(root, manifest)
                    _write_summary(root, manifest)
                    _final_inventory(root)

                _transition(root, next_state)
            except Exception as exc:
                _mark_failed(root, stage, exc)
                raise
    except Exception:
        raise
