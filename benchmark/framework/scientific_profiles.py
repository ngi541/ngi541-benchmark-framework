from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from framework.io_utils import FrameworkError


SCIENTIFIC_PROFILE_SCHEMA_VERSION = 1

_ALLOWED_IRI_PATTERNS = {
    "time-sensitive",
    "data-integration-bulk",
}

_ALLOWED_WORKLOAD_KINDS = {
    "event-stream",
    "detector-frame-stream",
    "heterogeneous-object-set",
}

_ALLOWED_EXECUTION_MODES = {
    "service-envelope",
    "transport-capacity",
}

_ALLOWED_OBJECT_MODEL_KINDS = {
    "fixed-representative",
    "fixed",
    "published-histogram",
}

_FORBIDDEN_EXECUTION_KEYS = {
    "topology",
    "network_bandwidth",
    "network_bandwidth_mbps",
    "network_envelope",
    "workers",
    "connections",
    "clients",
    "streams_per_connection",
    "max_concurrent_streams",
    "max_concurrent_streams_per_connection",
    "target_goodput_mbps",
    "service_target_fraction",
    "service_target_fractions",
    "dut_variant",
    "server_host",
    "server_port",
    "execution_projection",
    "rate_control",
}

_PROFILE_ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_SOURCE_ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


@dataclass(frozen=True)
class ScientificProfileRecord:
    profile_id: str
    profile_version: int
    sha256: str
    path: Path
    definition: dict[str, Any]

    @property
    def filename(self) -> str:
        return self.path.name

    def manifest_entry(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "sha256": self.sha256,
            "filename": self.filename,
        }


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def profile_sha256(profile: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(profile)).hexdigest()


def registry_manifest(records: Iterable[ScientificProfileRecord]) -> dict[str, Any]:
    entries = sorted(
        (record.manifest_entry() for record in records),
        key=lambda value: (value["profile_id"], value["profile_version"]),
    )
    identity = {
        "schema_version": SCIENTIFIC_PROFILE_SCHEMA_VERSION,
        "profiles": entries,
    }
    return {
        **identity,
        "registry_sha256": hashlib.sha256(_canonical_json(identity)).hexdigest(),
    }


def _require_object(parent: dict[str, Any], field: str) -> dict[str, Any]:
    value = parent.get(field)
    if not isinstance(value, dict):
        raise FrameworkError(f"scientific profile {field} must be an object")
    return value


def _require_nonempty_string(parent: dict[str, Any], field: str, *, context: str) -> str:
    value = parent.get(field)
    if not isinstance(value, str) or not value.strip():
        raise FrameworkError(f"{context}.{field} must be a non-empty string")
    return value


def _require_positive_number(parent: dict[str, Any], field: str, *, context: str) -> float:
    value = parent.get(field)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise FrameworkError(f"{context}.{field} must be > 0")
    return float(value)


def _require_nonnegative_int(parent: dict[str, Any], field: str, *, context: str) -> int:
    value = parent.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise FrameworkError(f"{context}.{field} must be an integer >= 0")
    return value


def _require_positive_int(parent: dict[str, Any], field: str, *, context: str) -> int:
    value = _require_nonnegative_int(parent, field, context=context)
    if value == 0:
        raise FrameworkError(f"{context}.{field} must be > 0")
    return value


def _walk_forbidden_execution_keys(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in _FORBIDDEN_EXECUTION_KEYS:
                raise FrameworkError(
                    f"scientific profile must be environment-independent; forbidden key at {path}.{key}"
                )
            _walk_forbidden_execution_keys(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk_forbidden_execution_keys(child, f"{path}[{index}]")


def _validate_sources(scientific_basis: dict[str, Any]) -> None:
    sources = scientific_basis.get("sources")
    if not isinstance(sources, list) or not sources:
        raise FrameworkError("scientific_basis.sources must be a non-empty array")
    source_ids: set[str] = set()
    for index, source in enumerate(sources):
        context = f"scientific_basis.sources[{index}]"
        if not isinstance(source, dict):
            raise FrameworkError(f"{context} must be an object")
        source_id = _require_nonempty_string(source, "source_id", context=context)
        if not _SOURCE_ID_RE.fullmatch(source_id):
            raise FrameworkError(f"{context}.source_id must be a lower-case slug")
        if source_id in source_ids:
            raise FrameworkError(f"duplicate scientific source_id: {source_id}")
        source_ids.add(source_id)
        _require_nonempty_string(source, "title", context=context)
        url = _require_nonempty_string(source, "url", context=context)
        if not url.startswith("https://"):
            raise FrameworkError(f"{context}.url must use https://")
        supports = source.get("supports")
        if not isinstance(supports, list) or not supports:
            raise FrameworkError(f"{context}.supports must be a non-empty array")
        for support in supports:
            if not isinstance(support, str) or not support.strip():
                raise FrameworkError(f"{context}.supports entries must be non-empty strings")


def _validate_common(profile: dict[str, Any]) -> tuple[str, dict[str, Any], dict[str, Any], dict[str, Any]]:
    if profile.get("schema_version") != SCIENTIFIC_PROFILE_SCHEMA_VERSION:
        raise FrameworkError("scientific profile schema_version must be 1")

    profile_id = profile.get("profile_id")
    if not isinstance(profile_id, str) or not _PROFILE_ID_RE.fullmatch(profile_id):
        raise FrameworkError("profile_id must be a lower-case slug")

    version = profile.get("profile_version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise FrameworkError("profile_version must be an integer >= 1")

    title = profile.get("title")
    if not isinstance(title, str) or not title.strip():
        raise FrameworkError("title must be a non-empty string")

    classification = _require_object(profile, "classification")
    iri_pattern = _require_nonempty_string(classification, "iri_pattern", context="classification")
    workload_kind = _require_nonempty_string(classification, "workload_kind", context="classification")
    if iri_pattern not in _ALLOWED_IRI_PATTERNS:
        raise FrameworkError(f"unsupported IRI pattern: {iri_pattern}")
    if workload_kind not in _ALLOWED_WORKLOAD_KINDS:
        raise FrameworkError(f"unsupported scientific workload_kind: {workload_kind}")

    scientific_basis = _require_object(profile, "scientific_basis")
    _require_nonempty_string(scientific_basis, "domain", context="scientific_basis")
    _require_nonempty_string(scientific_basis, "organization", context="scientific_basis")
    _require_nonempty_string(scientific_basis, "workflow", context="scientific_basis")
    _validate_sources(scientific_basis)

    native_workload = _require_object(profile, "native_workload")
    object_model = _require_object(profile, "object_model")
    model_kind = _require_nonempty_string(object_model, "kind", context="object_model")
    if model_kind not in _ALLOWED_OBJECT_MODEL_KINDS:
        raise FrameworkError(f"unsupported object_model.kind: {model_kind}")

    content_model = _require_object(profile, "content_model")
    if content_model.get("kind") != "deterministic-surrogate":
        raise FrameworkError("content_model.kind must be 'deterministic-surrogate'")
    if content_model.get("generator") != "splitmix64":
        raise FrameworkError("content_model.generator must be 'splitmix64'")
    _require_nonempty_string(content_model, "seed_namespace", context="content_model")
    if content_model.get("compressibility_policy") != "pseudo-random-uncompressed":
        raise FrameworkError(
            "content_model.compressibility_policy must be 'pseudo-random-uncompressed'"
        )

    modes = profile.get("supported_execution_modes")
    if not isinstance(modes, list) or not modes:
        raise FrameworkError("supported_execution_modes must be a non-empty array")
    if len(set(modes)) != len(modes):
        raise FrameworkError("supported_execution_modes must not contain duplicates")
    for mode in modes:
        if mode not in _ALLOWED_EXECUTION_MODES:
            raise FrameworkError(f"unsupported scientific execution mode: {mode}")

    _walk_forbidden_execution_keys(profile)
    return workload_kind, native_workload, object_model, scientific_basis


def _validate_event_stream(
    profile: dict[str, Any],
    native: dict[str, Any],
    object_model: dict[str, Any],
) -> None:
    if object_model.get("kind") != "fixed-representative":
        raise FrameworkError("event-stream object_model.kind must be 'fixed-representative'")
    object_bytes = _require_positive_int(object_model, "bytes", context="object_model")
    if object_model.get("semantic_unit") != "event":
        raise FrameworkError("event-stream object_model.semantic_unit must be 'event'")
    derivation = _require_object(object_model, "derivation")
    if derivation.get("kind") != "published-rate-derived-representative":
        raise FrameworkError(
            "event-stream object_model.derivation.kind must be 'published-rate-derived-representative'"
        )
    _require_nonempty_string(derivation, "explanation", context="object_model.derivation")

    event_rate = _require_object(native, "event_rate_hz")
    data_rate = _require_object(native, "data_rate_Bps")
    min_events = _require_positive_number(event_rate, "min", context="native_workload.event_rate_hz")
    max_events = _require_positive_number(event_rate, "max", context="native_workload.event_rate_hz")
    min_bytes = _require_positive_number(data_rate, "min", context="native_workload.data_rate_Bps")
    max_bytes = _require_positive_number(data_rate, "max", context="native_workload.data_rate_Bps")
    if min_events > max_events or min_bytes > max_bytes:
        raise FrameworkError("event-stream native workload min values must not exceed max values")
    representative = _require_positive_int(
        native, "representative_event_bytes", context="native_workload"
    )
    if representative != object_bytes:
        raise FrameworkError(
            "native_workload.representative_event_bytes must equal object_model.bytes"
        )

    # The CLAS12 profile intentionally uses a binary-friendly 32 KiB representative
    # derived from published rate pairs (~33.3 kB/event), rather than claiming an
    # exact event size. Keep future derived profiles within 10% of both endpoint ratios.
    endpoint_estimates = (min_bytes / min_events, max_bytes / max_events)
    for estimate in endpoint_estimates:
        if abs(representative - estimate) / estimate > 0.10:
            raise FrameworkError(
                "event-stream representative_event_bytes must remain within 10% of the "
                "published data-rate/event-rate endpoint ratios"
            )


def _validate_detector_frame_stream(
    profile: dict[str, Any],
    native: dict[str, Any],
    object_model: dict[str, Any],
) -> None:
    if object_model.get("kind") != "fixed":
        raise FrameworkError("detector-frame-stream object_model.kind must be 'fixed'")
    frame_bytes = _require_positive_int(object_model, "bytes", context="object_model")
    if object_model.get("semantic_unit") != "detector-frame":
        raise FrameworkError(
            "detector-frame-stream object_model.semantic_unit must be 'detector-frame'"
        )
    native_frame_bytes = _require_positive_int(native, "frame_bytes", context="native_workload")
    frame_rate = _require_positive_number(native, "frame_rate_hz", context="native_workload")
    data_rate = _require_positive_number(native, "data_rate_Bps", context="native_workload")
    if native_frame_bytes != frame_bytes:
        raise FrameworkError("native_workload.frame_bytes must equal object_model.bytes")
    expected = frame_bytes * frame_rate
    if not math.isclose(data_rate, expected, rel_tol=1e-12, abs_tol=0.0):
        raise FrameworkError(
            "detector-frame-stream data_rate_Bps must equal frame_bytes * frame_rate_hz"
        )


def _validate_histogram(object_model: dict[str, Any]) -> None:
    if object_model.get("kind") != "published-histogram":
        raise FrameworkError(
            "heterogeneous-object-set object_model.kind must be 'published-histogram'"
        )
    total_objects = _require_positive_int(
        object_model, "logical_total_objects", context="object_model"
    )
    _require_positive_int(object_model, "logical_total_bytes", context="object_model")
    _require_nonnegative_int(object_model, "directories", context="object_model")
    smallest = _require_nonnegative_int(
        object_model, "smallest_object_bytes", context="object_model"
    )
    largest = _require_positive_int(object_model, "largest_object_bytes", context="object_model")
    if smallest > largest:
        raise FrameworkError("object_model smallest_object_bytes must not exceed largest_object_bytes")
    if object_model.get("bucket_semantics") != "lower-inclusive-upper-exclusive":
        raise FrameworkError(
            "published histogram bucket_semantics must be 'lower-inclusive-upper-exclusive'"
        )
    _require_nonempty_string(object_model, "normalization", context="object_model")

    buckets = object_model.get("buckets")
    if not isinstance(buckets, list) or not buckets:
        raise FrameworkError("published histogram buckets must be a non-empty array")

    count_sum = 0
    previous_upper: int | None = None
    for index, bucket in enumerate(buckets):
        context = f"object_model.buckets[{index}]"
        if not isinstance(bucket, dict):
            raise FrameworkError(f"{context} must be an object")
        lower = _require_nonnegative_int(bucket, "lower_inclusive", context=context)
        upper = _require_positive_int(bucket, "upper_exclusive", context=context)
        count = _require_nonnegative_int(bucket, "count", context=context)
        if lower >= upper:
            raise FrameworkError(f"{context} lower bound must be < upper bound")
        if previous_upper is not None and lower != previous_upper:
            raise FrameworkError("published histogram buckets must be contiguous and non-overlapping")
        previous_upper = upper
        count_sum += count

    if count_sum != total_objects:
        raise FrameworkError(
            f"published histogram bucket count sum {count_sum} != logical_total_objects {total_objects}"
        )
    first = buckets[0]
    last = buckets[-1]
    if smallest < first["lower_inclusive"] or smallest >= first["upper_exclusive"]:
        raise FrameworkError("smallest_object_bytes must fall inside the first histogram bucket")
    if largest < last["lower_inclusive"] or largest >= last["upper_exclusive"]:
        raise FrameworkError("largest_object_bytes must fall inside the last histogram bucket")


def _validate_heterogeneous_object_set(
    profile: dict[str, Any],
    native: dict[str, Any],
    object_model: dict[str, Any],
) -> None:
    _validate_histogram(object_model)
    native_objects = _require_positive_int(native, "dataset_total_objects", context="native_workload")
    native_bytes = _require_positive_int(native, "dataset_total_bytes", context="native_workload")
    if native_objects != object_model["logical_total_objects"]:
        raise FrameworkError(
            "native_workload.dataset_total_objects must equal object_model.logical_total_objects"
        )
    if native_bytes != object_model["logical_total_bytes"]:
        raise FrameworkError(
            "native_workload.dataset_total_bytes must equal object_model.logical_total_bytes"
        )
    if native.get("dataset_semantics") != "finite-multifile-transfer":
        raise FrameworkError(
            "heterogeneous-object-set native_workload.dataset_semantics must be "
            "'finite-multifile-transfer'"
        )


def validate_profile(profile: dict[str, Any]) -> None:
    if not isinstance(profile, dict):
        raise FrameworkError("scientific profile must be a JSON object")
    workload_kind, native, object_model, _ = _validate_common(profile)
    if workload_kind == "event-stream":
        _validate_event_stream(profile, native, object_model)
    elif workload_kind == "detector-frame-stream":
        _validate_detector_frame_stream(profile, native, object_model)
    elif workload_kind == "heterogeneous-object-set":
        _validate_heterogeneous_object_set(profile, native, object_model)
    else:  # guarded by _validate_common
        raise FrameworkError(f"unsupported scientific workload_kind: {workload_kind}")


def load_profile(path: Path) -> dict[str, Any]:
    try:
        profile = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FrameworkError(f"scientific profile not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise FrameworkError(
            f"invalid scientific profile JSON: {path}: line {exc.lineno}, "
            f"column {exc.colno}: {exc.msg}"
        ) from exc
    validate_profile(profile)
    return profile


def load_registry(root: Path) -> list[ScientificProfileRecord]:
    if not root.is_dir():
        raise FrameworkError(f"scientific profile registry not found: {root}")
    paths = sorted(root.glob("*.json"))
    if not paths:
        raise FrameworkError(f"scientific profile registry is empty: {root}")

    records: list[ScientificProfileRecord] = []
    identities: set[tuple[str, int]] = set()
    for path in paths:
        definition = load_profile(path)
        profile_id = definition["profile_id"]
        version = definition["profile_version"]
        expected_name = f"{profile_id}-v{version}.json"
        if path.name != expected_name:
            raise FrameworkError(
                f"scientific profile filename must be {expected_name}, got {path.name}"
            )
        identity = (profile_id, version)
        if identity in identities:
            raise FrameworkError(
                f"duplicate scientific profile identity: {profile_id} v{version}"
            )
        identities.add(identity)
        records.append(
            ScientificProfileRecord(
                profile_id=profile_id,
                profile_version=version,
                sha256=profile_sha256(definition),
                path=path,
                definition=definition,
            )
        )
    return sorted(records, key=lambda record: (record.profile_id, record.profile_version))
