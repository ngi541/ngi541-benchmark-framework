from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
import sys

TEST_DIR = Path(__file__).resolve().parent
BENCHMARK_DIR = TEST_DIR.parents[1]
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))

from framework.io_utils import FrameworkError
from framework.scientific_corpus import (
    BYTE_ORDER,
    GENERATOR_ALGORITHM,
    HACC_ORDERING,
    HACC_SIZE_ASSIGNMENT,
    SEED_DERIVATION,
    build_corpus_manifest,
    definition_sha256,
    derive_seed_u64,
    iter_surrogate_bytes,
    load_definition,
    materialize_surrogate,
    resolve_hacc_coverage,
    resolve_stream_coverage,
    run_scientific_corpus,
    stream_object_descriptor,
    validate_definition,
)
from framework.scientific_profiles import load_registry


CONFIG = BENCHMARK_DIR / "configs" / "r6.5.3d-scientific-corpus.json"
REGISTRY = BENCHMARK_DIR / "scientific-profiles"


def _definition() -> dict:
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def _records():
    return {record.profile_id: record for record in load_registry(REGISTRY)}


class ScientificCorpusDefinitionTests(unittest.TestCase):
    def test_valid_definition(self):
        validate_definition(_definition())

    def test_definition_hash_is_semantic(self):
        value = _definition()
        clone = json.loads(json.dumps(value, indent=4))
        self.assertEqual(definition_sha256(value), definition_sha256(clone))

    def test_registry_path_must_be_relative(self):
        value = _definition()
        value["profile_registry"] = "/tmp/scientific-profiles"
        with self.assertRaises(FrameworkError):
            validate_definition(value)

    def test_generator_contract_is_pinned(self):
        value = _definition()
        self.assertEqual(value["generator"]["algorithm"], GENERATOR_ALGORITHM)
        self.assertEqual(value["generator"]["seed_derivation"], SEED_DERIVATION)
        self.assertEqual(value["generator"]["byte_order"], BYTE_ORDER)
        self.assertEqual(value["hacc"]["size_assignment"], HACC_SIZE_ASSIGNMENT)
        self.assertEqual(value["hacc"]["ordering"], HACC_ORDERING)


class DeterministicContentTests(unittest.TestCase):
    def test_seed_derivation_is_stable_and_object_specific(self):
        a = derive_seed_u64("ns", "a" * 64, "event-000000000001")
        b = derive_seed_u64("ns", "a" * 64, "event-000000000001")
        c = derive_seed_u64("ns", "a" * 64, "event-000000000002")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_splitmix64_bytes_are_chunk_size_independent(self):
        a = b"".join(iter_surrogate_bytes(0x12345678, 1003, chunk_bytes=17))
        b = b"".join(iter_surrogate_bytes(0x12345678, 1003, chunk_bytes=1024))
        self.assertEqual(a, b)
        self.assertEqual(len(a), 1003)

    def test_materialization_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            a = materialize_surrogate(root / "a.bin", seed_u64=7, size_bytes=8193, chunk_bytes=127)
            b = materialize_surrogate(root / "b.bin", seed_u64=7, size_bytes=8193, chunk_bytes=4096)
            self.assertEqual(a, b)
            self.assertEqual((root / "a.bin").read_bytes(), (root / "b.bin").read_bytes())


class CorpusManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = _records()
        cls.clas12 = build_corpus_manifest(cls.records["clas12-event-stream"])
        cls.lcls = build_corpus_manifest(cls.records["lcls-detector-frame"])
        cls.hacc = build_corpus_manifest(cls.records["hacc-multifile-dataset"])

    def test_stream_profiles_preserve_scientific_object_sizes(self):
        self.assertEqual(self.clas12["object_size_bytes"], 32768)
        self.assertEqual(self.lcls["object_size_bytes"], 10000000)
        self.assertEqual(self.clas12["corpus_kind"], "indexed-stream")
        self.assertEqual(self.lcls["corpus_kind"], "indexed-stream")

    def test_stream_object_recipe_is_stable_and_varies_by_index(self):
        a = stream_object_descriptor(self.clas12, 7)
        b = stream_object_descriptor(self.clas12, 7)
        c = stream_object_descriptor(self.clas12, 8)
        self.assertEqual(a, b)
        self.assertNotEqual(a["content_recipe_sha256"], c["content_recipe_sha256"])
        self.assertEqual(a["size_bytes"], 32768)

    def test_hacc_manifest_matches_published_logical_totals(self):
        extent = self.hacc["logical_extent"]
        self.assertEqual(extent["object_count"], 19260)
        self.assertEqual(extent["logical_total_bytes"], 4442781786482)
        self.assertEqual(extent["smallest_object_bytes"], 0)
        self.assertEqual(extent["largest_object_bytes"], 11313896248)

    def test_hacc_bucket_population_and_bounds_are_exact(self):
        objects = self.hacc["objects"]
        buckets = self.hacc["size_model"]["buckets"]
        for bucket in buckets:
            idx = bucket["bucket_index"]
            rows = [row for row in objects if row["bucket_index"] == idx]
            self.assertEqual(len(rows), bucket["object_count"])
            for row in rows:
                self.assertGreaterEqual(row["size_bytes"], bucket["lower_inclusive"])
                self.assertLess(row["size_bytes"], bucket["upper_exclusive"])
                self.assertLessEqual(row["size_bytes"], 11313896248)

    def test_hacc_manifest_is_deterministic(self):
        again = build_corpus_manifest(self.records["hacc-multifile-dataset"])
        self.assertEqual(self.hacc, again)
        self.assertEqual(self.hacc["corpus_sha256"], again["corpus_sha256"])

    def test_hacc_synthetic_sizes_have_within_bucket_variation(self):
        objects = self.hacc["objects"]
        for bucket_index in (2, 3, 4, 5, 6, 7, 8, 9):
            sizes = {row["size_bytes"] for row in objects if row["bucket_index"] == bucket_index}
            self.assertGreater(len(sizes), 1)

    def test_builtin_corpus_hashes_pin_algorithm_v1(self):
        self.assertEqual(
            self.clas12["corpus_sha256"],
            "6710dad93e8740b868693cebec5c218ca5825d204315198d1ee87ab4b08f60e4",
        )
        self.assertEqual(
            self.hacc["corpus_sha256"],
            "a49bce70c3ca61df1b5970ad50ca19e50f3d7e91e37f3920e5a31d7d25f5f541",
        )
        self.assertEqual(
            self.lcls["corpus_sha256"],
            "cca9517e214f00a407fea01ad45a2f4b5a620f4f819ab58fe86240dd2cf5daab",
        )


class HaccCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hacc = build_corpus_manifest(_records()["hacc-multifile-dataset"])

    def test_full_coverage_selects_entire_logical_dataset(self):
        coverage = resolve_hacc_coverage(self.hacc, {"mode": "full"})
        self.assertEqual(coverage["selected_object_count"], 19260)
        self.assertEqual(coverage["selected_logical_bytes"], 4442781786482)

    def test_stratified_coverage_is_deterministic_and_covers_every_bucket(self):
        a = resolve_hacc_coverage(
            self.hacc,
            {"mode": "deterministic-stratified", "object_count": 384},
        )
        b = resolve_hacc_coverage(
            self.hacc,
            {"mode": "deterministic-stratified", "object_count": 384},
        )
        self.assertEqual(a, b)
        self.assertEqual(a["selected_object_count"], 384)
        self.assertEqual(len(a["selected_bucket_counts"]), 11)
        self.assertTrue(all(value >= 1 for value in a["selected_bucket_counts"].values()))

    def test_stratified_coverage_includes_published_extrema(self):
        coverage = resolve_hacc_coverage(
            self.hacc,
            {"mode": "deterministic-stratified", "object_count": 384},
        )
        by_id = {row["object_id"]: row for row in self.hacc["objects"]}
        selected = [by_id[object_id] for object_id in coverage["selected_object_ids"]]
        self.assertIn(0, [row["size_bytes"] for row in selected])
        self.assertIn(11313896248, [row["size_bytes"] for row in selected])

    def test_stratified_coverage_rejects_fewer_objects_than_nonempty_buckets(self):
        with self.assertRaisesRegex(FrameworkError, "at least 11"):
            resolve_hacc_coverage(
                self.hacc,
                {"mode": "deterministic-stratified", "object_count": 10},
            )

    def test_time_window_is_ordered_prefix_through_byte_budget(self):
        coverage = resolve_hacc_coverage(
            self.hacc,
            {"mode": "time-window", "duration_seconds": 10, "target_goodput_mbps": 100},
        )
        self.assertGreaterEqual(coverage["selected_logical_bytes"], coverage["byte_budget"])
        expected_prefix = [
            row["object_id"] for row in self.hacc["objects"][:coverage["selected_object_count"]]
        ]
        self.assertEqual(coverage["selected_object_ids"], expected_prefix)


class StreamCoverageTests(unittest.TestCase):
    def test_time_window_derives_object_count_from_byte_budget(self):
        lcls = build_corpus_manifest(_records()["lcls-detector-frame"])
        coverage = resolve_stream_coverage(
            lcls,
            {"mode": "time-window", "duration_seconds": 20, "target_goodput_mbps": 80},
        )
        # 20 s * 80 Mbit/s = 200 MB, exactly twenty 10 MB frames.
        self.assertEqual(coverage["byte_budget"], 200000000)
        self.assertEqual(coverage["selected_object_count"], 20)
        self.assertEqual(coverage["selected_logical_bytes"], 200000000)


class ScientificCorpusRunTests(unittest.TestCase):
    def test_run_is_idempotent_and_outputs_deterministic_registry(self):
        definition = load_definition(CONFIG)
        repo_root = BENCHMARK_DIR.parent
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "scientific"
            first = run_scientific_corpus(definition, repo_root=repo_root, output_root=output)
            second = run_scientific_corpus(definition, repo_root=repo_root, output_root=output)
            self.assertFalse(first["reused"])
            self.assertTrue(second["reused"])
            self.assertEqual(first["root"], second["root"])
            self.assertEqual(first["summary"]["corpus_registry_sha256"], second["summary"]["corpus_registry_sha256"])
            self.assertTrue((first["root"] / "artifacts.sha256").is_file())

    def test_corpus_id_changes_when_resolved_profile_bytes_change(self):
        definition = load_definition(CONFIG)
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "repo"
            registry = repo / "benchmark" / "scientific-profiles"
            registry.mkdir(parents=True)
            for source in REGISTRY.glob("*.json"):
                (registry / source.name).write_bytes(source.read_bytes())
            output = Path(td) / "corpora"
            first = run_scientific_corpus(definition, repo_root=repo, output_root=output)

            lcls_path = registry / "lcls-detector-frame-v1.json"
            lcls = json.loads(lcls_path.read_text(encoding="utf-8"))
            lcls["title"] += " semantic-revision"
            lcls_path.write_text(json.dumps(lcls, indent=2), encoding="utf-8")

            second = run_scientific_corpus(definition, repo_root=repo, output_root=output)
            self.assertNotEqual(first["summary"]["input_sha256"], second["summary"]["input_sha256"])
            self.assertNotEqual(first["summary"]["corpus_id"], second["summary"]["corpus_id"])


if __name__ == "__main__":
    unittest.main()
