from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from framework.io_utils import FrameworkError, atomic_write_json, atomic_write_text
from framework.network_qualification import (
    SSHSession,
    definition_sha256 as network_definition_sha256,
    load_network_qualification_definition,
    run_network_qualification,
)


NETWORK_EVIDENCE_SCHEMA_VERSION = 1
COMPATIBILITY_POLICY = "strict-path-v1"
SELECTION_POLICY = "latest-compatible"
AGGREGATION_POLICY = "minimum"


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def definition_sha256(definition: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(definition)).hexdigest()


def _semantic_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _utc_rfc3339() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _slug(text: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    if not value:
        raise FrameworkError("evidence.name must contain an alphanumeric character")
    return value


def load_definition(path: Path) -> dict[str, Any]:
    try:
        definition = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FrameworkError(f"network evidence config not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise FrameworkError(
            f"invalid network evidence JSON: line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    validate_definition(definition)
    return definition


def validate_definition(definition: dict[str, Any]) -> None:
    if definition.get("schema_version") != NETWORK_EVIDENCE_SCHEMA_VERSION:
        raise FrameworkError("network evidence schema_version must be 1")

    evidence = definition.get("evidence")
    source = definition.get("source")
    envelope = definition.get("envelope")

    if not isinstance(evidence, dict):
        raise FrameworkError("evidence must be an object")
    if not isinstance(evidence.get("name"), str) or not evidence["name"].strip():
        raise FrameworkError("evidence.name must be a non-empty string")

    if not isinstance(source, dict):
        raise FrameworkError("source must be an object")
    qualification_config = source.get("qualification_config")
    if not isinstance(qualification_config, str) or not qualification_config.strip():
        raise FrameworkError("source.qualification_config must be a non-empty string")
    if Path(qualification_config).is_absolute():
        raise FrameworkError("source.qualification_config must be repository-relative")

    qualification_root = source.get("qualification_root", "qualifications/network")
    if not isinstance(qualification_root, str) or not qualification_root.strip():
        raise FrameworkError("source.qualification_root must be a non-empty string")
    if Path(qualification_root).is_absolute():
        raise FrameworkError("source.qualification_root must be repository-relative")

    minimum = source.get("minimum_observations", 3)
    selected = source.get("selected_observations", minimum)
    if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 3:
        raise FrameworkError("source.minimum_observations must be an integer >= 3")
    if not isinstance(selected, int) or isinstance(selected, bool) or selected < minimum:
        raise FrameworkError(
            "source.selected_observations must be an integer >= source.minimum_observations"
        )
    if source.get("selection_policy", SELECTION_POLICY) != SELECTION_POLICY:
        raise FrameworkError("source.selection_policy must be 'latest-compatible'")
    if source.get("compatibility_policy", COMPATIBILITY_POLICY) != COMPATIBILITY_POLICY:
        raise FrameworkError("source.compatibility_policy must be 'strict-path-v1'")
    auto_collect = source.get("auto_collect_missing", True)
    if not isinstance(auto_collect, bool):
        raise FrameworkError("source.auto_collect_missing must be boolean")

    if definition.get("direction", "dut-to-loadgen") != "dut-to-loadgen":
        raise FrameworkError("direction must be 'dut-to-loadgen'")

    if not isinstance(envelope, dict):
        raise FrameworkError("envelope must be an object")
    max_loss = envelope.get("udp_max_loss_percent", 0.1)
    min_ratio = envelope.get("udp_min_achieved_requested_ratio", 0.95)
    if not isinstance(max_loss, (int, float)) or isinstance(max_loss, bool) or max_loss < 0:
        raise FrameworkError("envelope.udp_max_loss_percent must be >= 0")
    if (
        not isinstance(min_ratio, (int, float))
        or isinstance(min_ratio, bool)
        or not 0 < float(min_ratio) <= 1
    ):
        raise FrameworkError(
            "envelope.udp_min_achieved_requested_ratio must be in (0, 1]"
        )
    if envelope.get("aggregation", AGGREGATION_POLICY) != AGGREGATION_POLICY:
        raise FrameworkError("envelope.aggregation must be 'minimum'")


def _resolve_repo_relative(repo_root: Path, value: str, label: str) -> Path:
    path = (repo_root / value).resolve()
    try:
        path.relative_to(repo_root.resolve())
    except ValueError as exc:
        raise FrameworkError(f"{label} escapes repository root: {value}") from exc
    return path


def _expected_transport_direction(network_definition: dict[str, Any]) -> str:
    local_role = network_definition.get("local", {}).get("role")
    remote_role = network_definition.get("remote", {}).get("role")
    if local_role == "dut" and remote_role == "loadgen":
        return "local-to-remote"
    if remote_role == "dut" and local_role == "loadgen":
        return "remote-to-local"
    raise FrameworkError(
        "network qualification must have one DUT and one loadgen to derive dut-to-loadgen evidence"
    )


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FrameworkError(f"missing {label}: {path}") from exc
    except json.JSONDecodeError as exc:
        raise FrameworkError(
            f"invalid {label} JSON at {path}: line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    if not isinstance(value, dict):
        raise FrameworkError(f"{label} must contain a JSON object: {path}")
    return value


def _validate_artifact_inventory(root: Path) -> None:
    inventory = root / "artifacts.sha256"
    if not inventory.is_file():
        raise FrameworkError(
            f"network qualification {root.name} has no artifacts.sha256 integrity inventory"
        )

    seen: set[str] = set()
    for line_number, raw_line in enumerate(inventory.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        if "  " not in line:
            raise FrameworkError(
                f"invalid artifacts.sha256 line {line_number} in {root.name}"
            )
        expected, relative = line.split("  ", 1)
        if not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
            raise FrameworkError(
                f"invalid SHA-256 on artifacts.sha256 line {line_number} in {root.name}"
            )
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise FrameworkError(
                f"unsafe path in artifacts.sha256 line {line_number} in {root.name}"
            )
        if relative in seen:
            raise FrameworkError(f"duplicate artifact inventory path in {root.name}: {relative}")
        seen.add(relative)
        path = root / relative_path
        if not path.is_file():
            raise FrameworkError(f"missing hashed artifact in {root.name}: {relative}")
        actual = _sha256_file(path)
        if actual.lower() != expected.lower():
            raise FrameworkError(
                f"artifact hash mismatch in {root.name}: {relative}; "
                f"expected={expected.lower()} actual={actual.lower()}"
            )

    required = {"processed/summary.json", "processed/reference.json", "config.json"}
    missing = sorted(required - seen)
    if missing:
        raise FrameworkError(
            f"network qualification {root.name} integrity inventory is incomplete: "
            + ", ".join(missing)
        )


def topology_fingerprint(summary: dict[str, Any]) -> dict[str, Any]:
    topology = summary.get("topology")
    if not isinstance(topology, dict):
        raise FrameworkError("network qualification summary has no topology object")
    local = topology.get("local")
    remote = topology.get("remote")
    if not isinstance(local, dict) or not isinstance(remote, dict):
        raise FrameworkError("network qualification summary topology endpoints are missing")

    required_local = ("address", "interface")
    required_remote = ("address", "interface")
    for key in required_local:
        if not local.get(key):
            raise FrameworkError(f"network qualification local topology is missing {key}")
    for key in required_remote:
        if not remote.get(key):
            raise FrameworkError(f"network qualification remote topology is missing {key}")
    if not topology.get("classification"):
        raise FrameworkError("network qualification topology classification is missing")
    if not summary.get("http3_response_direction"):
        raise FrameworkError("network qualification HTTP/3 response direction is missing")

    # Keep this fingerprint limited to path identity/capability, not observed
    # performance values.  Performance measurements belong to the envelope.
    return {
        "topology_classification": topology["classification"],
        "http3_response_direction": summary["http3_response_direction"],
        "local": {
            "system": local.get("system"),
            "address": local.get("address"),
            "interface": local.get("interface"),
            "hardware_port": local.get("hardware_port"),
            "gateway": local.get("gateway"),
        },
        "remote": {
            "system": remote.get("system"),
            "address": remote.get("address"),
            "configured_address": remote.get("configured_address"),
            "interface": remote.get("interface"),
            "gateway": remote.get("gateway"),
            "speed_mbps": remote.get("speed_mbps"),
            "duplex": remote.get("duplex"),
            "link_detected": remote.get("link_detected"),
        },
    }


@dataclass(frozen=True)
class Observation:
    qualification_id: str
    root: Path
    summary: dict[str, Any]
    summary_sha256: str
    topology: dict[str, Any]
    topology_sha256: str
    finished_at: str

    def identity_record(self) -> dict[str, Any]:
        return {
            "qualification_id": self.qualification_id,
            "finished_at": self.finished_at,
            "summary_sha256": self.summary_sha256,
            "topology_fingerprint_sha256": self.topology_sha256,
        }


def _observation_sort_key(observation: Observation) -> tuple[str, str]:
    return (observation.finished_at, observation.qualification_id)


def discover_observations(
    qualification_root: Path,
    *,
    expected_definition_sha256: str,
    expected_transport_direction: str,
) -> list[Observation]:
    if not qualification_root.exists():
        return []

    observations: list[Observation] = []
    for root in sorted(path for path in qualification_root.iterdir() if path.is_dir()):
        summary_path = root / "processed" / "summary.json"
        if not summary_path.is_file():
            continue
        summary = _read_json(summary_path, "network qualification summary")
        if summary.get("definition_sha256") != expected_definition_sha256:
            continue
        if summary.get("status") != "COMPLETE":
            continue

        # A matching COMPLETE observation is evidence, so corruption is fatal;
        # never silently skip it and replace it with a more favorable run.
        _validate_artifact_inventory(root)

        qualification_id = summary.get("qualification_id")
        if not isinstance(qualification_id, str) or qualification_id != root.name:
            raise FrameworkError(
                f"network qualification id/path mismatch: directory={root.name} "
                f"summary={qualification_id!r}"
            )
        if summary.get("http3_response_direction") != expected_transport_direction:
            raise FrameworkError(
                f"network qualification {qualification_id} has response direction "
                f"{summary.get('http3_response_direction')!r}; expected "
                f"{expected_transport_direction!r}"
            )
        finished_at = summary.get("finished_at")
        if not isinstance(finished_at, str) or not finished_at:
            raise FrameworkError(
                f"network qualification {qualification_id} has no finished_at timestamp"
            )
        fingerprint = topology_fingerprint(summary)
        observations.append(
            Observation(
                qualification_id=qualification_id,
                root=root,
                summary=summary,
                summary_sha256=_sha256_file(summary_path),
                topology=fingerprint,
                topology_sha256=_semantic_sha256(fingerprint),
                finished_at=finished_at,
            )
        )
    return sorted(observations, key=_observation_sort_key)


def _safe_udp_reference(
    summary: dict[str, Any],
    *,
    direction: str,
    max_loss_percent: float,
    min_achieved_requested_ratio: float,
) -> dict[str, Any]:
    rows = summary.get("udp")
    if not isinstance(rows, list):
        raise FrameworkError("network qualification summary has no UDP rows")

    eligible: list[tuple[float, float, dict[str, Any]]] = []
    for row in rows:
        if not isinstance(row, dict) or row.get("direction") != direction:
            continue
        requested = row.get("requested_mbps")
        achieved = row.get("throughput_mbps")
        loss = row.get("lost_percent")
        if not all(
            isinstance(value, (int, float)) and not isinstance(value, bool)
            for value in (requested, achieved, loss)
        ):
            continue
        requested_f = float(requested)
        achieved_f = float(achieved)
        loss_f = float(loss)
        if requested_f <= 0 or achieved_f < 0:
            continue
        ratio = achieved_f / requested_f
        if loss_f <= max_loss_percent and ratio >= min_achieved_requested_ratio:
            eligible.append((requested_f, achieved_f, row))

    if not eligible:
        raise FrameworkError(
            "selected network observation has no UDP point satisfying both "
            f"loss <= {max_loss_percent}% and achieved/requested >= "
            f"{min_achieved_requested_ratio}"
        )

    requested_f, achieved_f, row = max(eligible, key=lambda item: (item[0], item[1]))
    return {
        "requested_mbps": round(requested_f, 6),
        "achieved_mbps": round(achieved_f, 6),
        "achieved_requested_ratio": round(achieved_f / requested_f, 6),
        "loss_percent": round(float(row["lost_percent"]), 6),
        "jitter_ms": (
            round(float(row["jitter_ms"]), 6)
            if isinstance(row.get("jitter_ms"), (int, float))
            and not isinstance(row.get("jitter_ms"), bool)
            else None
        ),
        "datagram_bytes": row.get("datagram_bytes"),
    }


def _tcp_reference(summary: dict[str, Any], *, direction: str) -> dict[str, Any]:
    rows = summary.get("tcp")
    if not isinstance(rows, list):
        raise FrameworkError("network qualification summary has no TCP rows")
    candidates = [
        row
        for row in rows
        if isinstance(row, dict)
        and row.get("direction") == direction
        and isinstance(row.get("throughput_mbps"), (int, float))
        and not isinstance(row.get("throughput_mbps"), bool)
    ]
    if not candidates:
        raise FrameworkError(
            f"selected network observation has no TCP measurement for {direction}"
        )
    best = max(candidates, key=lambda row: float(row["throughput_mbps"]))
    return {
        "best_throughput_mbps": round(float(best["throughput_mbps"]), 6),
        "parallel_streams": best.get("parallel_streams"),
        "retransmits": best.get("retransmits"),
    }


def _ping_reference(summary: dict[str, Any], *, direction: str) -> dict[str, Any] | None:
    ping = summary.get("ping")
    if not isinstance(ping, dict) or not ping.get("enabled"):
        return None
    key = "local_to_remote" if direction == "local-to-remote" else "remote_to_local"
    value = ping.get(key)
    if not isinstance(value, dict):
        return None
    result: dict[str, Any] = {}
    for source, target in (
        ("rtt_avg_ms", "rtt_avg_ms"),
        ("packet_loss_percent", "packet_loss_percent"),
    ):
        raw = value.get(source)
        result[target] = (
            round(float(raw), 6)
            if isinstance(raw, (int, float)) and not isinstance(raw, bool)
            else None
        )
    return result


def derive_network_envelope(
    observations: list[Observation],
    *,
    direction: str,
    max_loss_percent: float,
    min_achieved_requested_ratio: float,
    aggregation: str = AGGREGATION_POLICY,
) -> dict[str, Any]:
    if len(observations) < 3:
        raise FrameworkError("at least 3 compatible network observations are required")
    if aggregation != AGGREGATION_POLICY:
        raise FrameworkError("only minimum envelope aggregation is supported")
    topology_hashes = {observation.topology_sha256 for observation in observations}
    if len(topology_hashes) != 1:
        raise FrameworkError("network envelope observations do not share one topology fingerprint")

    per_observation: list[dict[str, Any]] = []
    for observation in sorted(observations, key=_observation_sort_key):
        tcp = _tcp_reference(observation.summary, direction=direction)
        udp = _safe_udp_reference(
            observation.summary,
            direction=direction,
            max_loss_percent=max_loss_percent,
            min_achieved_requested_ratio=min_achieved_requested_ratio,
        )
        per_observation.append(
            {
                **observation.identity_record(),
                "tcp": tcp,
                "udp_safe": udp,
                "ping": _ping_reference(observation.summary, direction=direction),
            }
        )

    tcp_floor = min(row["tcp"]["best_throughput_mbps"] for row in per_observation)
    udp_floor = min(row["udp_safe"]["achieved_mbps"] for row in per_observation)
    udp_requested_floor = min(row["udp_safe"]["requested_mbps"] for row in per_observation)
    service_envelope = min(tcp_floor, udp_floor)
    limiting_reference = (
        "tcp-capacity-floor" if tcp_floor <= udp_floor else "udp-safe-achieved-floor"
    )

    evidence_identity = [
        {
            "qualification_id": row["qualification_id"],
            "summary_sha256": row["summary_sha256"],
            "topology_fingerprint_sha256": row["topology_fingerprint_sha256"],
        }
        for row in per_observation
    ]
    evidence_set_sha = _semantic_sha256(evidence_identity)

    document: dict[str, Any] = {
        "schema_version": 1,
        "claim_scope": "empirically-qualified-network-service-envelope",
        "direction_semantic": "dut-to-loadgen",
        "direction_transport": direction,
        "compatibility_policy": COMPATIBILITY_POLICY,
        "selection_policy": SELECTION_POLICY,
        "aggregation": AGGREGATION_POLICY,
        "udp_policy": {
            "max_loss_percent": float(max_loss_percent),
            "min_achieved_requested_ratio": float(min_achieved_requested_ratio),
        },
        "topology": observations[0].topology,
        "topology_fingerprint_sha256": observations[0].topology_sha256,
        "evidence_set_sha256": evidence_set_sha,
        "observation_count": len(per_observation),
        "observations": per_observation,
        "floors": {
            "tcp_capacity_mbps": round(float(tcp_floor), 6),
            "udp_safe_requested_mbps": round(float(udp_requested_floor), 6),
            "udp_safe_achieved_mbps": round(float(udp_floor), 6),
        },
        "service_envelope_mbps": round(float(service_envelope), 6),
        "limiting_reference": limiting_reference,
    }
    document["envelope_sha256"] = _semantic_sha256(document)
    return document


def _group_by_topology(observations: list[Observation]) -> dict[str, list[Observation]]:
    groups: dict[str, list[Observation]] = {}
    for observation in observations:
        groups.setdefault(observation.topology_sha256, []).append(observation)
    for group in groups.values():
        group.sort(key=_observation_sort_key)
    return groups


def select_observations(
    observations: list[Observation],
    *,
    count: int,
) -> tuple[str, list[Observation]]:
    if not observations:
        raise FrameworkError("no matching COMPLETE network qualifications were found")
    groups = _group_by_topology(observations)
    # The newest matching COMPLETE observation establishes the current path.
    # Older topology groups are not mixed into the evidence set.
    newest = max(observations, key=_observation_sort_key)
    target_hash = newest.topology_sha256
    group = groups[target_hash]
    if len(group) < count:
        raise FrameworkError(
            f"current topology has only {len(group)} compatible observations; {count} required"
        )
    return target_hash, group[-count:]


def _artifact_hashes(root: Path) -> str:
    lines: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == "artifacts.sha256":
            continue
        lines.append(f"{_sha256_file(path)}  {path.relative_to(root)}")
    return "\n".join(lines) + "\n"


def _summary_markdown(summary: dict[str, Any], envelope: dict[str, Any]) -> str:
    lines = [
        f"# Network evidence {summary['evidence_id']}",
        "",
        f"Status: `{summary['status']}`",
        f"Selected observations: `{envelope['observation_count']}`",
        f"Topology: `{envelope['topology']['topology_classification']}`",
        f"Direction: `{envelope['direction_transport']}` (DUT → loadgen)",
        "",
        "## Deterministic envelope",
        "",
        f"- TCP capacity floor: `{envelope['floors']['tcp_capacity_mbps']}` Mb/s",
        f"- UDP safe requested floor: `{envelope['floors']['udp_safe_requested_mbps']}` Mb/s",
        f"- UDP safe achieved floor: `{envelope['floors']['udp_safe_achieved_mbps']}` Mb/s",
        f"- Service envelope: `{envelope['service_envelope_mbps']}` Mb/s",
        f"- Limiting reference: `{envelope['limiting_reference']}`",
        "",
        "UDP safe points require both the configured loss limit and the configured achieved/requested ratio.",
        "No compatible observation is discarded because of an unfavorable measured result.",
        "This is an empirically qualified local path envelope, not a guaranteed/reserved bandwidth claim.",
        "",
    ]
    return "\n".join(lines)


def _network_config_path(definition: dict[str, Any], repo_root: Path) -> Path:
    return _resolve_repo_relative(
        repo_root,
        definition["source"]["qualification_config"],
        "source.qualification_config",
    )


def _qualification_root(definition: dict[str, Any], repo_root: Path) -> Path:
    return _resolve_repo_relative(
        repo_root,
        definition["source"].get("qualification_root", "qualifications/network"),
        "source.qualification_root",
    )


def run_network_evidence(
    definition: dict[str, Any],
    *,
    repo_root: Path,
    output_root: Path,
    bootstrap: bool = False,
    collector: Callable[[], Any] | None = None,
) -> dict[str, Any]:
    validate_definition(definition)

    network_config_path = _network_config_path(definition, repo_root)
    network_definition = load_network_qualification_definition(network_config_path)
    network_definition_sha = network_definition_sha256(network_definition)
    direction = _expected_transport_direction(network_definition)
    qualification_root = _qualification_root(definition, repo_root)

    source = definition["source"]
    minimum = int(source.get("minimum_observations", 3))
    count = int(source.get("selected_observations", minimum))
    auto_collect = bool(source.get("auto_collect_missing", True))

    def scan() -> list[Observation]:
        return discover_observations(
            qualification_root,
            expected_definition_sha256=network_definition_sha,
            expected_transport_direction=direction,
        )

    observations = scan()
    target_topology_hash: str | None = None
    if observations:
        target_topology_hash = max(observations, key=_observation_sort_key).topology_sha256

    collected = 0
    shared_ssh: SSHSession | None = None
    try:
        while True:
            current = (
                [o for o in observations if o.topology_sha256 == target_topology_hash]
                if target_topology_hash is not None
                else []
            )
            if len(current) >= count:
                break
            if not auto_collect:
                raise FrameworkError(
                    f"current topology has {len(current)} compatible observations; {count} required "
                    "and source.auto_collect_missing is false"
                )

            previous_ids = {observation.qualification_id for observation in observations}
            if collector is not None:
                collector()
            else:
                if shared_ssh is None:
                    remote_cfg = network_definition["remote"]
                    shared_ssh = SSHSession(
                        remote_cfg["ssh_target"],
                        int(remote_cfg.get("connect_timeout_seconds", 10)),
                    )
                    # One interactive authentication is reused for all missing
                    # observations collected in this resolver invocation.
                    shared_ssh.start()
                run_network_qualification(
                    network_definition,
                    config_path=network_config_path,
                    output_root=qualification_root,
                    repo_root=repo_root,
                    bootstrap=bootstrap,
                    ssh_session=shared_ssh,
                )
            collected += 1
            observations = scan()
            new_ids = {observation.qualification_id for observation in observations}
            if new_ids == previous_ids:
                raise FrameworkError(
                    "network evidence collection completed without producing a new "
                    "matching COMPLETE qualification"
                )
            newest = max(observations, key=_observation_sort_key)
            if target_topology_hash is None:
                target_topology_hash = newest.topology_sha256
            elif newest.topology_sha256 != target_topology_hash:
                raise FrameworkError(
                    "network topology changed while collecting evidence: "
                    f"expected fingerprint {target_topology_hash}, got {newest.topology_sha256}; "
                    "refusing to combine observations across path changes"
                )
    finally:
        if shared_ssh is not None:
            shared_ssh.close()

    _, selected = select_observations(observations, count=count)
    if len(selected) < minimum:
        raise FrameworkError(
            f"selected evidence set has {len(selected)} observations; minimum is {minimum}"
        )

    envelope_cfg = definition["envelope"]
    envelope = derive_network_envelope(
        selected,
        direction=direction,
        max_loss_percent=float(envelope_cfg.get("udp_max_loss_percent", 0.1)),
        min_achieved_requested_ratio=float(
            envelope_cfg.get("udp_min_achieved_requested_ratio", 0.95)
        ),
        aggregation=envelope_cfg.get("aggregation", AGGREGATION_POLICY),
    )

    definition_sha = definition_sha256(definition)
    evidence_id = (
        f"{_slug(definition['evidence']['name'])}-{_utc_timestamp()}-{definition_sha[:6]}"
    )
    root = output_root / evidence_id
    if root.exists():
        raise FrameworkError(f"refusing to overwrite network evidence directory: {root}")
    inputs_dir = root / "inputs"
    processed_dir = root / "processed"
    inputs_dir.mkdir(parents=True)
    processed_dir.mkdir(parents=True)

    config_record = {
        "schema_version": 1,
        "definition_sha256": definition_sha,
        "definition": definition,
    }
    selected_inputs = {
        "schema_version": 1,
        "network_qualification_definition_sha256": network_definition_sha,
        "network_qualification_config": source["qualification_config"],
        "selection_policy": SELECTION_POLICY,
        "compatibility_policy": COMPATIBILITY_POLICY,
        "topology_fingerprint_sha256": envelope["topology_fingerprint_sha256"],
        "evidence_set_sha256": envelope["evidence_set_sha256"],
        "observations": [observation.identity_record() for observation in selected],
    }
    summary = {
        "schema_version": 1,
        "evidence_id": evidence_id,
        "definition_sha256": definition_sha,
        "created_at": _utc_rfc3339(),
        "status": "COMPLETE",
        "claim_scope": definition["evidence"].get(
            "claim_scope", "network-envelope-derivation-only"
        ),
        "collected_observations": collected,
        "selected_observations": len(selected),
        "topology_fingerprint_sha256": envelope["topology_fingerprint_sha256"],
        "evidence_set_sha256": envelope["evidence_set_sha256"],
        "envelope_sha256": envelope["envelope_sha256"],
        "service_envelope_mbps": envelope["service_envelope_mbps"],
        "limiting_reference": envelope["limiting_reference"],
    }

    atomic_write_json(root / "config.json", config_record)
    atomic_write_json(inputs_dir / "network-qualifications.json", selected_inputs)
    atomic_write_json(processed_dir / "network-envelope.json", envelope)
    atomic_write_json(processed_dir / "summary.json", summary)
    atomic_write_text(processed_dir / "SUMMARY.md", _summary_markdown(summary, envelope))
    atomic_write_text(root / "artifacts.sha256", _artifact_hashes(root))

    return {
        "root": root,
        "summary": summary,
        "envelope": envelope,
        "selected": selected,
    }
