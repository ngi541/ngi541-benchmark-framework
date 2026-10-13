from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import struct
from dataclasses import dataclass
from decimal import Decimal, ROUND_CEILING
from pathlib import Path
from typing import Any, Iterable, Iterator

from framework.io_utils import FrameworkError, atomic_write_json, atomic_write_text
from framework.scientific_profiles import (
    ScientificProfileRecord,
    load_registry,
)


SCIENTIFIC_CORPUS_SCHEMA_VERSION = 1
CORPUS_MANIFEST_SCHEMA_VERSION = 1
COVERAGE_MANIFEST_SCHEMA_VERSION = 1

GENERATOR_ALGORITHM = "splitmix64-v1"
SEED_DERIVATION = "sha256-first-u64-be-v1"
BYTE_ORDER = "little-endian-u64"
HACC_SIZE_ASSIGNMENT = "capacity-weighted-largest-remainder-v1"
HACC_ORDERING = "sha256-object-key-v1"

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_MASK64 = (1 << 64) - 1
_SPLITMIX_GAMMA = 0x9E3779B97F4A7C15


@dataclass(frozen=True)
class CorpusRecord:
    profile_id: str
    profile_version: int
    profile_sha256: str
    manifest: dict[str, Any]

    @property
    def corpus_sha256(self) -> str:
        return str(self.manifest["corpus_sha256"])


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _semantic_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def definition_sha256(definition: dict[str, Any]) -> str:
    return _semantic_sha256(definition)


def _require_object(parent: dict[str, Any], field: str, *, context: str = "$" ) -> dict[str, Any]:
    value = parent.get(field)
    if not isinstance(value, dict):
        raise FrameworkError(f"{context}.{field} must be an object")
    return value


def _require_nonempty_string(parent: dict[str, Any], field: str, *, context: str) -> str:
    value = parent.get(field)
    if not isinstance(value, str) or not value.strip():
        raise FrameworkError(f"{context}.{field} must be a non-empty string")
    return value


def _require_positive_int(parent: dict[str, Any], field: str, *, context: str) -> int:
    value = parent.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise FrameworkError(f"{context}.{field} must be an integer > 0")
    return value


def _portable_relative_path(value: str, *, field: str) -> None:
    path = Path(value)
    if path.is_absolute():
        raise FrameworkError(f"{field} must be repository-relative")
    if ".." in path.parts:
        raise FrameworkError(f"{field} must not contain '..'")


def validate_definition(definition: dict[str, Any]) -> None:
    if not isinstance(definition, dict):
        raise FrameworkError("scientific corpus definition must be a JSON object")
    if definition.get("schema_version") != SCIENTIFIC_CORPUS_SCHEMA_VERSION:
        raise FrameworkError("scientific corpus schema_version must be 1")

    corpus = _require_object(definition, "corpus")
    name = _require_nonempty_string(corpus, "name", context="corpus")
    if not _NAME_RE.fullmatch(name):
        raise FrameworkError("corpus.name contains unsupported characters")
    _require_nonempty_string(corpus, "claim_scope", context="corpus")

    registry = _require_nonempty_string(definition, "profile_registry", context="$")
    _portable_relative_path(registry, field="profile_registry")

    profiles = definition.get("profiles")
    if not isinstance(profiles, list) or not profiles:
        raise FrameworkError("profiles must be a non-empty array")
    identities: set[tuple[str, int]] = set()
    for index, item in enumerate(profiles):
        context = f"profiles[{index}]"
        if not isinstance(item, dict):
            raise FrameworkError(f"{context} must be an object")
        profile_id = _require_nonempty_string(item, "profile_id", context=context)
        version = item.get("profile_version")
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            raise FrameworkError(f"{context}.profile_version must be an integer >= 1")
        identity = (profile_id, version)
        if identity in identities:
            raise FrameworkError(f"duplicate scientific profile identity: {profile_id} v{version}")
        identities.add(identity)

    generator = _require_object(definition, "generator")
    if generator.get("algorithm") != GENERATOR_ALGORITHM:
        raise FrameworkError(f"generator.algorithm must be '{GENERATOR_ALGORITHM}'")
    if generator.get("seed_derivation") != SEED_DERIVATION:
        raise FrameworkError(f"generator.seed_derivation must be '{SEED_DERIVATION}'")
    if generator.get("byte_order") != BYTE_ORDER:
        raise FrameworkError(f"generator.byte_order must be '{BYTE_ORDER}'")

    hacc = _require_object(definition, "hacc")
    if hacc.get("size_assignment") != HACC_SIZE_ASSIGNMENT:
        raise FrameworkError(f"hacc.size_assignment must be '{HACC_SIZE_ASSIGNMENT}'")
    if hacc.get("ordering") != HACC_ORDERING:
        raise FrameworkError(f"hacc.ordering must be '{HACC_ORDERING}'")
    coverage = _require_object(hacc, "coverage", context="hacc")
    if coverage.get("modes") != ["full", "deterministic-stratified", "time-window"]:
        raise FrameworkError(
            "hacc.coverage.modes must be ['full', 'deterministic-stratified', 'time-window']"
        )
    stratified = _require_object(coverage, "deterministic_stratified", context="hacc.coverage")
    if stratified.get("minimum_one_per_nonempty_bucket") is not True:
        raise FrameworkError(
            "hacc.coverage.deterministic_stratified.minimum_one_per_nonempty_bucket must be true"
        )
    if stratified.get("include_published_extrema") is not True:
        raise FrameworkError(
            "hacc.coverage.deterministic_stratified.include_published_extrema must be true"
        )
    time_window = _require_object(coverage, "time_window", context="hacc.coverage")
    if time_window.get("selection") != "ordered-prefix-through-byte-budget":
        raise FrameworkError(
            "hacc.coverage.time_window.selection must be 'ordered-prefix-through-byte-budget'"
        )

    materialization = _require_object(definition, "materialization")
    _require_positive_int(materialization, "chunk_bytes", context="materialization")


def load_definition(path: Path) -> dict[str, Any]:
    try:
        definition = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FrameworkError(f"scientific corpus config not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise FrameworkError(
            f"invalid scientific corpus JSON: {path}: line {exc.lineno}, "
            f"column {exc.colno}: {exc.msg}"
        ) from exc
    validate_definition(definition)
    return definition


def derive_seed_u64(namespace: str, profile_sha256: str, object_id: str) -> int:
    payload = (
        namespace.encode("utf-8")
        + b"\0"
        + profile_sha256.encode("ascii")
        + b"\0"
        + object_id.encode("utf-8")
    )
    return int.from_bytes(hashlib.sha256(payload).digest()[:8], "big")


def _splitmix64_step(state: int) -> tuple[int, int]:
    state = (state + _SPLITMIX_GAMMA) & _MASK64
    z = state
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & _MASK64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & _MASK64
    z ^= z >> 31
    return state, z & _MASK64


def iter_surrogate_bytes(seed_u64: int, size_bytes: int, *, chunk_bytes: int = 1 << 20) -> Iterator[bytes]:
    if isinstance(size_bytes, bool) or not isinstance(size_bytes, int) or size_bytes < 0:
        raise FrameworkError("size_bytes must be an integer >= 0")
    if isinstance(chunk_bytes, bool) or not isinstance(chunk_bytes, int) or chunk_bytes <= 0:
        raise FrameworkError("chunk_bytes must be an integer > 0")

    state = seed_u64 & _MASK64
    remaining = size_bytes
    buffer = bytearray()
    while remaining:
        state, word = _splitmix64_step(state)
        encoded = struct.pack("<Q", word)
        take = min(remaining, len(encoded))
        buffer.extend(encoded[:take])
        remaining -= take
        if len(buffer) >= chunk_bytes or remaining == 0:
            yield bytes(buffer)
            buffer.clear()


def materialize_surrogate(
    path: Path,
    *,
    seed_u64: int,
    size_bytes: int,
    chunk_bytes: int = 1 << 20,
) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    written = 0
    with path.open("wb") as handle:
        for chunk in iter_surrogate_bytes(seed_u64, size_bytes, chunk_bytes=chunk_bytes):
            handle.write(chunk)
            digest.update(chunk)
            written += len(chunk)
    if written != size_bytes:
        raise FrameworkError(f"materialized size mismatch for {path}: {written} != {size_bytes}")
    return {
        "size_bytes": written,
        "sha256": digest.hexdigest(),
    }


def _content_recipe(
    *,
    namespace: str,
    profile_sha256: str,
    object_id: str,
    size_bytes: int,
) -> dict[str, Any]:
    seed = derive_seed_u64(namespace, profile_sha256, object_id)
    identity = {
        "generator": GENERATOR_ALGORITHM,
        "seed_derivation": SEED_DERIVATION,
        "byte_order": BYTE_ORDER,
        "seed_u64_hex": f"{seed:016x}",
        "object_id": object_id,
        "size_bytes": size_bytes,
    }
    return {
        **identity,
        "recipe_sha256": _semantic_sha256(identity),
    }


def _with_corpus_sha(manifest: dict[str, Any]) -> dict[str, Any]:
    value = dict(manifest)
    value["corpus_sha256"] = _semantic_sha256(manifest)
    return value


def build_stream_manifest(record: ScientificProfileRecord) -> dict[str, Any]:
    profile = record.definition
    model = profile["object_model"]
    workload_kind = profile["classification"]["workload_kind"]
    if workload_kind == "event-stream":
        prefix = "event"
    elif workload_kind == "detector-frame-stream":
        prefix = "frame"
    else:
        raise FrameworkError(f"profile {record.profile_id} is not an indexed stream")

    manifest = {
        "schema_version": CORPUS_MANIFEST_SCHEMA_VERSION,
        "corpus_kind": "indexed-stream",
        "profile": {
            "profile_id": record.profile_id,
            "profile_version": record.profile_version,
            "profile_sha256": record.sha256,
        },
        "semantic_unit": model["semantic_unit"],
        "object_size_bytes": model["bytes"],
        "logical_extent": {
            "kind": "unbounded-indexed-stream",
            "start_index": 0,
        },
        "object_identity": {
            "format": f"{prefix}-%012d",
        },
        "content": {
            "generator": GENERATOR_ALGORITHM,
            "seed_derivation": SEED_DERIVATION,
            "byte_order": BYTE_ORDER,
            "seed_namespace": profile["content_model"]["seed_namespace"],
            "compressibility_policy": profile["content_model"]["compressibility_policy"],
        },
        "coverage_modes": ["object-count", "time-window"],
    }
    return _with_corpus_sha(manifest)


def _tie_key(namespace: str, label: str, object_id: str) -> bytes:
    return hashlib.sha256(
        namespace.encode("utf-8") + b"\0" + label.encode("utf-8") + b"\0" + object_id.encode("utf-8")
    ).digest()


def _allocate_hacc_sizes(record: ScientificProfileRecord) -> list[dict[str, Any]]:
    profile = record.definition
    model = profile["object_model"]
    namespace = profile["content_model"]["seed_namespace"]
    smallest = int(model["smallest_object_bytes"])
    largest = int(model["largest_object_bytes"])
    target_total = int(model["logical_total_bytes"])

    entries: list[dict[str, Any]] = []
    for bucket_index, bucket in enumerate(model["buckets"]):
        lower = int(bucket["lower_inclusive"])
        upper_exclusive = int(bucket["upper_exclusive"])
        effective_max = min(upper_exclusive - 1, largest)
        if effective_max < lower:
            raise FrameworkError(f"HACC bucket {bucket_index} cannot contain published largest bound")
        for local_index in range(int(bucket["count"])):
            object_id = f"hacc-b{bucket_index:02d}-{local_index:05d}"
            entries.append(
                {
                    "object_id": object_id,
                    "bucket_index": bucket_index,
                    "bucket_local_index": local_index,
                    "lower": lower,
                    "effective_max": effective_max,
                    "base": lower,
                    "capacity": effective_max - lower,
                    "extreme": None,
                }
            )

    if len(entries) != int(model["logical_total_objects"]):
        raise FrameworkError("HACC generated object count does not match scientific profile")

    first_bucket = [entry for entry in entries if entry["bucket_index"] == 0]
    last_bucket_index = len(model["buckets"]) - 1
    last_bucket = [entry for entry in entries if entry["bucket_index"] == last_bucket_index]
    if not first_bucket or not last_bucket:
        raise FrameworkError("HACC histogram must have non-empty first and last buckets")

    smallest_entry = first_bucket[0]
    smallest_entry["base"] = smallest
    smallest_entry["capacity"] = 0
    smallest_entry["extreme"] = "published-smallest"

    largest_entry = last_bucket[0]
    largest_entry["base"] = largest
    largest_entry["capacity"] = 0
    largest_entry["extreme"] = "published-largest"

    base_total = sum(int(entry["base"]) for entry in entries)
    remaining = target_total - base_total
    total_capacity = sum(int(entry["capacity"]) for entry in entries)
    if remaining < 0 or remaining > total_capacity:
        raise FrameworkError(
            "HACC published logical_total_bytes cannot be satisfied by normalized histogram bounds"
        )

    # The publication constrains bucket populations, total bytes and extrema but
    # does not expose each original file size.  Use deterministic object-specific
    # weights to create within-bucket variation without claiming an empirical
    # intra-bucket distribution.  Capacity caps are honored exactly and any
    # integer remainder is assigned by deterministic largest remainder.
    allocation = [0] * len(entries)
    remaining_extra = remaining
    active = [index for index, entry in enumerate(entries) if int(entry["capacity"]) > 0]
    weights = {
        index: (1 << 64)
        + int.from_bytes(
            _tie_key(namespace, "hacc-size-weight", str(entries[index]["object_id"]))[:8],
            "big",
        )
        for index in active
    }

    while remaining_extra > 0:
        if not active:
            raise FrameworkError("HACC weighted size allocation exhausted legal capacity")
        denominator = sum(int(entries[index]["capacity"]) * weights[index] for index in active)
        if denominator <= 0:
            raise FrameworkError("HACC weighted size allocation has zero denominator")

        provisional: dict[int, tuple[int, int]] = {}
        saturated: list[int] = []
        for index in active:
            cap = int(entries[index]["capacity"])
            numerator = remaining_extra * cap * weights[index]
            share, remainder_value = divmod(numerator, denominator)
            if share >= cap:
                saturated.append(index)
            else:
                provisional[index] = (share, remainder_value)

        if saturated:
            for index in saturated:
                cap = int(entries[index]["capacity"])
                allocation[index] = cap
                remaining_extra -= cap
            active = [index for index in active if index not in set(saturated)]
            continue

        allocated_now = sum(share for share, _ in provisional.values())
        leftover = remaining_extra - allocated_now
        remainder_rows = sorted(
            (
                remainder_value,
                _tie_key(namespace, "hacc-size-remainder", str(entries[index]["object_id"])),
                index,
            )
            for index, (share, remainder_value) in provisional.items()
            if share < int(entries[index]["capacity"])
        )
        remainder_rows.sort(key=lambda row: (-row[0], row[1], row[2]))
        if leftover < 0 or leftover > len(remainder_rows):
            raise FrameworkError("HACC weighted largest-remainder size allocation failed")
        for index, (share, _) in provisional.items():
            allocation[index] = share
        for _, _, index in remainder_rows[:leftover]:
            allocation[index] += 1
        remaining_extra = 0

    for index, entry in enumerate(entries):
        entry["size_bytes"] = int(entry["base"]) + allocation[index]

    actual_total = sum(int(entry["size_bytes"]) for entry in entries)
    if actual_total != target_total:
        raise FrameworkError(f"HACC generated byte total {actual_total} != {target_total}")
    if min(int(entry["size_bytes"]) for entry in entries) != smallest:
        raise FrameworkError("HACC generated corpus lost published smallest object")
    if max(int(entry["size_bytes"]) for entry in entries) != largest:
        raise FrameworkError("HACC generated corpus lost published largest object")

    for entry in entries:
        size = int(entry["size_bytes"])
        bucket = model["buckets"][int(entry["bucket_index"])]
        if size < int(bucket["lower_inclusive"]) or size >= int(bucket["upper_exclusive"]):
            raise FrameworkError(f"HACC object {entry['object_id']} escaped histogram bucket")
        if size > largest:
            raise FrameworkError(f"HACC object {entry['object_id']} exceeds published largest object")

    return entries


def build_hacc_manifest(record: ScientificProfileRecord) -> dict[str, Any]:
    profile = record.definition
    if profile["classification"]["workload_kind"] != "heterogeneous-object-set":
        raise FrameworkError(f"profile {record.profile_id} is not a heterogeneous object set")
    model = profile["object_model"]
    namespace = profile["content_model"]["seed_namespace"]

    entries = _allocate_hacc_sizes(record)
    ordered = sorted(
        entries,
        key=lambda entry: (
            _tie_key(namespace, "hacc-object-order", str(entry["object_id"])),
            str(entry["object_id"]),
        ),
    )

    objects: list[dict[str, Any]] = []
    for sequence, entry in enumerate(ordered):
        object_id = str(entry["object_id"])
        size_bytes = int(entry["size_bytes"])
        recipe = _content_recipe(
            namespace=namespace,
            profile_sha256=record.sha256,
            object_id=object_id,
            size_bytes=size_bytes,
        )
        row = {
            "sequence": sequence,
            "object_id": object_id,
            "bucket_index": int(entry["bucket_index"]),
            "size_bytes": size_bytes,
            "content_seed_u64_hex": recipe["seed_u64_hex"],
            "content_recipe_sha256": recipe["recipe_sha256"],
        }
        if entry["extreme"] is not None:
            row["extreme"] = entry["extreme"]
        objects.append(row)

    bucket_counts = [0] * len(model["buckets"])
    bucket_bytes = [0] * len(model["buckets"])
    for obj in objects:
        idx = int(obj["bucket_index"])
        bucket_counts[idx] += 1
        bucket_bytes[idx] += int(obj["size_bytes"])

    buckets = []
    for index, source in enumerate(model["buckets"]):
        buckets.append(
            {
                "bucket_index": index,
                "lower_inclusive": int(source["lower_inclusive"]),
                "upper_exclusive": int(source["upper_exclusive"]),
                "object_count": bucket_counts[index],
                "logical_bytes": bucket_bytes[index],
            }
        )

    manifest = {
        "schema_version": CORPUS_MANIFEST_SCHEMA_VERSION,
        "corpus_kind": "finite-object-set",
        "profile": {
            "profile_id": record.profile_id,
            "profile_version": record.profile_version,
            "profile_sha256": record.sha256,
        },
        "semantic_unit": "dataset-object",
        "logical_extent": {
            "kind": "finite",
            "object_count": len(objects),
            "logical_total_bytes": sum(int(obj["size_bytes"]) for obj in objects),
            "directories": int(model["directories"]),
            "smallest_object_bytes": min(int(obj["size_bytes"]) for obj in objects),
            "largest_object_bytes": max(int(obj["size_bytes"]) for obj in objects),
        },
        "size_model": {
            "kind": "published-histogram-constrained",
            "assignment_algorithm": HACC_SIZE_ASSIGNMENT,
            "bucket_semantics": model["bucket_semantics"],
            "normalization": model["normalization"],
            "buckets": buckets,
        },
        "ordering": {
            "algorithm": HACC_ORDERING,
            "seed_namespace": namespace,
        },
        "content": {
            "generator": GENERATOR_ALGORITHM,
            "seed_derivation": SEED_DERIVATION,
            "byte_order": BYTE_ORDER,
            "seed_namespace": namespace,
            "compressibility_policy": profile["content_model"]["compressibility_policy"],
        },
        "coverage_modes": ["full", "deterministic-stratified", "time-window"],
        "objects": objects,
    }
    return _with_corpus_sha(manifest)


def build_corpus_manifest(record: ScientificProfileRecord) -> dict[str, Any]:
    kind = record.definition["classification"]["workload_kind"]
    if kind in {"event-stream", "detector-frame-stream"}:
        return build_stream_manifest(record)
    if kind == "heterogeneous-object-set":
        return build_hacc_manifest(record)
    raise FrameworkError(f"unsupported scientific workload kind for corpus generation: {kind}")


def stream_object_descriptor(manifest: dict[str, Any], index: int) -> dict[str, Any]:
    if manifest.get("corpus_kind") != "indexed-stream":
        raise FrameworkError("stream_object_descriptor requires an indexed-stream corpus")
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise FrameworkError("stream object index must be an integer >= 0")
    fmt = manifest["object_identity"]["format"]
    object_id = fmt % index
    profile = manifest["profile"]
    content = manifest["content"]
    recipe = _content_recipe(
        namespace=content["seed_namespace"],
        profile_sha256=profile["profile_sha256"],
        object_id=object_id,
        size_bytes=int(manifest["object_size_bytes"]),
    )
    return {
        "index": index,
        "object_id": object_id,
        "size_bytes": int(manifest["object_size_bytes"]),
        "content_seed_u64_hex": recipe["seed_u64_hex"],
        "content_recipe_sha256": recipe["recipe_sha256"],
    }


def _byte_budget(duration_seconds: float | int, target_goodput_mbps: float | int) -> int:
    if isinstance(duration_seconds, bool) or not isinstance(duration_seconds, (int, float)) or duration_seconds <= 0:
        raise FrameworkError("duration_seconds must be > 0")
    if isinstance(target_goodput_mbps, bool) or not isinstance(target_goodput_mbps, (int, float)) or target_goodput_mbps <= 0:
        raise FrameworkError("target_goodput_mbps must be > 0")
    value = (
        Decimal(str(duration_seconds))
        * Decimal(str(target_goodput_mbps))
        * Decimal(1_000_000)
        / Decimal(8)
    )
    return int(value.to_integral_value(rounding=ROUND_CEILING))


def resolve_stream_coverage(manifest: dict[str, Any], spec: dict[str, Any]) -> dict[str, Any]:
    if manifest.get("corpus_kind") != "indexed-stream":
        raise FrameworkError("stream coverage requires indexed-stream corpus")
    mode = spec.get("mode")
    size = int(manifest["object_size_bytes"])
    if mode == "object-count":
        count = spec.get("object_count")
        if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
            raise FrameworkError("object-count coverage requires object_count > 0")
        byte_budget = None
    elif mode == "time-window":
        byte_budget = _byte_budget(spec.get("duration_seconds"), spec.get("target_goodput_mbps"))
        count = max(1, math.ceil(byte_budget / size))
    else:
        raise FrameworkError("indexed-stream coverage mode must be object-count or time-window")

    identity = {
        "schema_version": COVERAGE_MANIFEST_SCHEMA_VERSION,
        "corpus_sha256": manifest["corpus_sha256"],
        "profile_id": manifest["profile"]["profile_id"],
        "mode": mode,
        "selection": {
            "kind": "contiguous-index-range",
            "start_index": 0,
            "object_count": count,
        },
        "selected_object_count": count,
        "selected_logical_bytes": count * size,
    }
    if byte_budget is not None:
        identity["byte_budget"] = byte_budget
        identity["overshoot_bytes"] = count * size - byte_budget
        identity["duration_seconds"] = spec["duration_seconds"]
        identity["target_goodput_mbps"] = spec["target_goodput_mbps"]
    return {
        **identity,
        "coverage_sha256": _semantic_sha256(identity),
    }


def _largest_remainder_quotas(counts: list[int], target: int) -> list[int]:
    nonempty = [index for index, count in enumerate(counts) if count > 0]
    if target < len(nonempty):
        raise FrameworkError(
            f"deterministic-stratified coverage requires at least {len(nonempty)} objects"
        )
    if target > sum(counts):
        raise FrameworkError("coverage object_count exceeds logical dataset object count")

    quotas = [1 if count > 0 else 0 for count in counts]
    remaining = target - sum(quotas)
    available = [max(0, count - quota) for count, quota in zip(counts, quotas)]
    available_total = sum(available)
    if remaining == 0:
        return quotas
    if available_total == 0:
        raise FrameworkError("no capacity remains for requested stratified coverage")

    allocated = 0
    remainders: list[tuple[int, int]] = []
    for index, capacity in enumerate(available):
        numerator = remaining * capacity
        extra, remainder = divmod(numerator, available_total)
        quotas[index] += extra
        allocated += extra
        if quotas[index] < counts[index]:
            remainders.append((remainder, index))

    leftover = remaining - allocated
    remainders.sort(key=lambda row: (-row[0], row[1]))
    for _, index in remainders[:leftover]:
        quotas[index] += 1

    if sum(quotas) != target:
        raise FrameworkError("stratified quota allocation failed")
    if any(quota > count for quota, count in zip(quotas, counts)):
        raise FrameworkError("stratified quota exceeds source bucket population")
    return quotas


def resolve_hacc_coverage(manifest: dict[str, Any], spec: dict[str, Any]) -> dict[str, Any]:
    if manifest.get("corpus_kind") != "finite-object-set":
        raise FrameworkError("HACC coverage requires finite-object-set corpus")
    if manifest.get("profile", {}).get("profile_id") != "hacc-multifile-dataset":
        raise FrameworkError("HACC coverage requires hacc-multifile-dataset corpus")

    objects = list(manifest["objects"])
    mode = spec.get("mode")
    byte_budget: int | None = None
    bucket_quotas: list[int] | None = None

    if mode == "full":
        selected = objects
    elif mode == "deterministic-stratified":
        target = spec.get("object_count")
        if isinstance(target, bool) or not isinstance(target, int) or target <= 0:
            raise FrameworkError("deterministic-stratified coverage requires object_count > 0")
        bucket_count = len(manifest["size_model"]["buckets"])
        counts = [0] * bucket_count
        grouped: list[list[dict[str, Any]]] = [[] for _ in range(bucket_count)]
        for obj in objects:
            idx = int(obj["bucket_index"])
            counts[idx] += 1
            grouped[idx].append(obj)
        bucket_quotas = _largest_remainder_quotas(counts, target)

        selected_ids: set[str] = set()
        namespace = manifest["ordering"]["seed_namespace"]
        for bucket_index, quota in enumerate(bucket_quotas):
            candidates = grouped[bucket_index]
            required = [
                obj
                for obj in candidates
                if obj.get("extreme") in {"published-smallest", "published-largest"}
            ]
            required = sorted(required, key=lambda obj: str(obj["object_id"]))
            if len(required) > quota:
                required = required[:quota]
            for obj in required:
                selected_ids.add(str(obj["object_id"]))
            remaining_needed = quota - len(required)
            if remaining_needed:
                pool = [obj for obj in candidates if str(obj["object_id"]) not in selected_ids]
                pool.sort(
                    key=lambda obj: (
                        _tie_key(namespace, "hacc-stratified-selection", str(obj["object_id"])),
                        str(obj["object_id"]),
                    )
                )
                for obj in pool[:remaining_needed]:
                    selected_ids.add(str(obj["object_id"]))
        selected = [obj for obj in objects if str(obj["object_id"]) in selected_ids]
        if len(selected) != target:
            raise FrameworkError("deterministic-stratified selection count mismatch")
    elif mode == "time-window":
        byte_budget = _byte_budget(spec.get("duration_seconds"), spec.get("target_goodput_mbps"))
        selected = []
        accumulated = 0
        for obj in objects:
            selected.append(obj)
            accumulated += int(obj["size_bytes"])
            if accumulated >= byte_budget:
                break
    else:
        raise FrameworkError(
            "HACC coverage mode must be full, deterministic-stratified, or time-window"
        )

    selected_bytes = sum(int(obj["size_bytes"]) for obj in selected)
    selected_ids = [str(obj["object_id"]) for obj in selected]
    selected_buckets: dict[str, int] = {}
    for obj in selected:
        key = str(int(obj["bucket_index"]))
        selected_buckets[key] = selected_buckets.get(key, 0) + 1

    identity: dict[str, Any] = {
        "schema_version": COVERAGE_MANIFEST_SCHEMA_VERSION,
        "corpus_sha256": manifest["corpus_sha256"],
        "profile_id": manifest["profile"]["profile_id"],
        "mode": mode,
        "selected_object_count": len(selected),
        "selected_logical_bytes": selected_bytes,
        "logical_dataset_object_count": int(manifest["logical_extent"]["object_count"]),
        "logical_dataset_bytes": int(manifest["logical_extent"]["logical_total_bytes"]),
        "selected_bucket_counts": selected_buckets,
        "selected_object_ids": selected_ids,
    }
    if bucket_quotas is not None:
        identity["bucket_quotas"] = bucket_quotas
        identity["coverage_fraction_objects"] = len(selected) / int(manifest["logical_extent"]["object_count"])
    if byte_budget is not None:
        identity["byte_budget"] = byte_budget
        identity["overshoot_bytes"] = max(0, selected_bytes - byte_budget)
        identity["dataset_exhausted"] = selected_bytes < byte_budget
        identity["duration_seconds"] = spec["duration_seconds"]
        identity["target_goodput_mbps"] = spec["target_goodput_mbps"]

    return {
        **identity,
        "coverage_sha256": _semantic_sha256(identity),
    }


def _slug(text: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    if not value:
        raise FrameworkError("unable to derive scientific corpus id from corpus.name")
    return value


def _resolve_selected_records(
    definition: dict[str, Any],
    *,
    repo_root: Path,
) -> list[ScientificProfileRecord]:
    registry_root = repo_root / definition["profile_registry"]
    records = load_registry(registry_root)
    by_identity = {(record.profile_id, record.profile_version): record for record in records}
    selected: list[ScientificProfileRecord] = []
    for item in definition["profiles"]:
        identity = (item["profile_id"], item["profile_version"])
        try:
            selected.append(by_identity[identity])
        except KeyError as exc:
            raise FrameworkError(
                f"scientific profile not found in registry: {identity[0]} v{identity[1]}"
            ) from exc
    return selected


def _hash_inventory(root: Path) -> str:
    lines: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == "artifacts.sha256":
            continue
        rel = path.relative_to(root).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {rel}")
    content = "\n".join(lines) + "\n"
    atomic_write_text(root / "artifacts.sha256", content)
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _verify_hash_inventory(root: Path) -> None:
    inventory = root / "artifacts.sha256"
    if not inventory.is_file():
        raise FrameworkError(f"existing scientific corpus is missing artifacts.sha256: {root}")
    for line in inventory.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            expected, relative = line.split("  ", 1)
        except ValueError as exc:
            raise FrameworkError(f"invalid corpus artifact inventory line: {line}") from exc
        path = root / relative
        if not path.is_file():
            raise FrameworkError(f"scientific corpus artifact is missing: {relative}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise FrameworkError(f"scientific corpus artifact hash mismatch: {relative}")


def run_scientific_corpus(
    definition: dict[str, Any],
    *,
    repo_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    validate_definition(definition)
    definition_sha = definition_sha256(definition)
    records = _resolve_selected_records(definition, repo_root=repo_root)
    resolved_profiles = sorted(
        (
            {
                "profile_id": record.profile_id,
                "profile_version": record.profile_version,
                "profile_sha256": record.sha256,
            }
            for record in records
        ),
        key=lambda row: (row["profile_id"], row["profile_version"]),
    )
    input_identity = {
        "schema_version": 1,
        "definition_sha256": definition_sha,
        "profiles": resolved_profiles,
    }
    input_sha = _semantic_sha256(input_identity)
    corpus_id = f"{_slug(definition['corpus']['name'])}-{input_sha[:12]}"
    root = output_root / corpus_id

    if root.exists():
        _verify_hash_inventory(root)
        summary_path = root / "processed" / "summary.json"
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise FrameworkError(f"existing scientific corpus is incomplete: {summary_path}") from exc
        if summary.get("definition_sha256") != definition_sha:
            raise FrameworkError("existing scientific corpus definition hash mismatch")
        if summary.get("input_sha256") != input_sha:
            raise FrameworkError("existing scientific corpus resolved-input hash mismatch")
        return {"root": root, "summary": summary, "reused": True}

    temp = output_root / f".{corpus_id}.tmp"
    if temp.exists():
        shutil.rmtree(temp)
    (temp / "processed" / "profiles").mkdir(parents=True, exist_ok=True)

    profile_rows: list[dict[str, Any]] = []
    manifests: list[CorpusRecord] = []
    for record in records:
        manifest = build_corpus_manifest(record)
        manifests.append(
            CorpusRecord(
                profile_id=record.profile_id,
                profile_version=record.profile_version,
                profile_sha256=record.sha256,
                manifest=manifest,
            )
        )
        atomic_write_json(
            temp / "processed" / "profiles" / f"{record.profile_id}-v{record.profile_version}.corpus.json",
            manifest,
        )
        profile_rows.append(
            {
                "profile_id": record.profile_id,
                "profile_version": record.profile_version,
                "profile_sha256": record.sha256,
                "corpus_sha256": manifest["corpus_sha256"],
                "corpus_kind": manifest["corpus_kind"],
            }
        )

    registry_identity = {
        "schema_version": 1,
        "profiles": sorted(profile_rows, key=lambda row: (row["profile_id"], row["profile_version"])),
    }
    registry_output = {
        **registry_identity,
        "corpus_registry_sha256": _semantic_sha256(registry_identity),
    }

    coverage_contract = {
        "schema_version": 1,
        "indexed_stream": {
            "modes": ["object-count", "time-window"],
            "time_window": {
                "byte_budget": "ceil(duration_seconds * target_goodput_mbps * 1000000 / 8)",
                "selection": "contiguous-index-range-from-zero",
            },
        },
        "hacc_multifile_dataset": {
            "modes": ["full", "deterministic-stratified", "time-window"],
            "deterministic_stratified": {
                "minimum_one_per_nonempty_bucket": True,
                "include_published_extrema": True,
                "quota_algorithm": "published-bucket-population-largest-remainder-v1",
                "within_bucket_selection": "sha256-object-key-v1",
            },
            "time_window": {
                "byte_budget": "ceil(duration_seconds * target_goodput_mbps * 1000000 / 8)",
                "selection": "ordered-prefix-through-byte-budget",
            },
        },
    }

    definition_record = {
        "schema_version": 1,
        "definition_sha256": definition_sha,
        "input_sha256": input_sha,
        "resolved_profiles": resolved_profiles,
        "definition": definition,
    }
    summary = {
        "schema_version": 1,
        "corpus_id": corpus_id,
        "definition_sha256": definition_sha,
        "input_sha256": input_sha,
        "claim_scope": definition["corpus"]["claim_scope"],
        "status": "COMPLETE",
        "profile_count": len(profile_rows),
        "profiles": registry_output["profiles"],
        "corpus_registry_sha256": registry_output["corpus_registry_sha256"],
        "hacc": next(
            (
                {
                    "logical_objects": item.manifest["logical_extent"]["object_count"],
                    "logical_bytes": item.manifest["logical_extent"]["logical_total_bytes"],
                    "smallest_object_bytes": item.manifest["logical_extent"]["smallest_object_bytes"],
                    "largest_object_bytes": item.manifest["logical_extent"]["largest_object_bytes"],
                    "coverage_modes": item.manifest["coverage_modes"],
                }
                for item in manifests
                if item.profile_id == "hacc-multifile-dataset"
            ),
            None,
        ),
    }

    atomic_write_json(temp / "definition.json", definition_record)
    atomic_write_json(temp / "processed" / "registry.json", registry_output)
    atomic_write_json(temp / "processed" / "coverage-contract.json", coverage_contract)
    atomic_write_json(temp / "processed" / "summary.json", summary)
    _hash_inventory(temp)

    output_root.mkdir(parents=True, exist_ok=True)
    os.replace(temp, root)
    return {"root": root, "summary": summary, "reused": False}
