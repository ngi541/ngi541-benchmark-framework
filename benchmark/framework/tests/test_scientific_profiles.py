import copy
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
from framework.scientific_profiles import (
    load_profile,
    load_registry,
    profile_sha256,
    registry_manifest,
    validate_profile,
)


REGISTRY = BENCHMARK_DIR / "scientific-profiles"


def _profile(profile_id: str) -> dict:
    return load_profile(REGISTRY / f"{profile_id}-v1.json")


class ScientificProfileRegistryTests(unittest.TestCase):
    def test_builtin_registry_contains_three_profiles(self):
        records = load_registry(REGISTRY)
        self.assertEqual(
            [record.profile_id for record in records],
            ["clas12-event-stream", "hacc-multifile-dataset", "lcls-detector-frame"],
        )
        hacc = next(record.definition for record in records if record.profile_id == "hacc-multifile-dataset")
        self.assertEqual(hacc["object_model"]["logical_total_objects"], 19260)
        self.assertEqual(hacc["object_model"]["logical_total_bytes"], 4442781786482)

    def test_builtin_profile_hashes_are_semantic(self):
        value = _profile("lcls-detector-frame")
        reordered = json.loads(json.dumps(value, sort_keys=False))
        self.assertEqual(profile_sha256(value), profile_sha256(reordered))

    def test_registry_manifest_is_deterministic(self):
        records = load_registry(REGISTRY)
        a = registry_manifest(records)
        b = registry_manifest(reversed(records))
        self.assertEqual(a, b)
        self.assertRegex(a["registry_sha256"], r"^[0-9a-f]{64}$")

    def test_filename_contract_is_enforced(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            value = _profile("lcls-detector-frame")
            (root / "wrong-name.json").write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(FrameworkError):
                load_registry(root)


class ScientificProfileInvariantTests(unittest.TestCase):
    def test_environment_execution_key_is_rejected(self):
        value = _profile("lcls-detector-frame")
        value["scientific_basis"]["topology"] = "pi-to-mac"
        with self.assertRaises(FrameworkError):
            validate_profile(value)

    def test_non_https_source_is_rejected(self):
        value = _profile("clas12-event-stream")
        value["scientific_basis"]["sources"][0]["url"] = "http://example.invalid/source"
        with self.assertRaises(FrameworkError):
            validate_profile(value)

    def test_duplicate_source_id_is_rejected(self):
        value = _profile("clas12-event-stream")
        duplicate = copy.deepcopy(value["scientific_basis"]["sources"][0])
        value["scientific_basis"]["sources"].append(duplicate)
        with self.assertRaises(FrameworkError):
            validate_profile(value)

    def test_unsupported_execution_mode_is_rejected(self):
        value = _profile("lcls-detector-frame")
        value["supported_execution_modes"].append("request-capacity")
        with self.assertRaises(FrameworkError):
            validate_profile(value)

    def test_clas12_representative_event_matches_rate_basis(self):
        value = _profile("clas12-event-stream")
        self.assertEqual(value["object_model"]["bytes"], 32768)
        low = value["native_workload"]["data_rate_Bps"]["min"] / value["native_workload"]["event_rate_hz"]["min"]
        high = value["native_workload"]["data_rate_Bps"]["max"] / value["native_workload"]["event_rate_hz"]["max"]
        self.assertLess(abs(32768 - low) / low, 0.10)
        self.assertLess(abs(32768 - high) / high, 0.10)

    def test_clas12_inconsistent_representative_event_rejected(self):
        value = _profile("clas12-event-stream")
        value["native_workload"]["representative_event_bytes"] = 4096
        value["object_model"]["bytes"] = 4096
        with self.assertRaises(FrameworkError):
            validate_profile(value)

    def test_lcls_native_rate_equals_frame_size_times_rate(self):
        value = _profile("lcls-detector-frame")
        self.assertEqual(
            value["native_workload"]["data_rate_Bps"],
            value["native_workload"]["frame_bytes"] * value["native_workload"]["frame_rate_hz"],
        )

    def test_hacc_bucket_count_mismatch_is_rejected(self):
        value = _profile("hacc-multifile-dataset")
        value["object_model"]["buckets"][4]["count"] += 1
        with self.assertRaises(FrameworkError):
            validate_profile(value)

    def test_hacc_noncontiguous_histogram_is_rejected(self):
        value = _profile("hacc-multifile-dataset")
        value["object_model"]["buckets"][5]["lower_inclusive"] += 1
        with self.assertRaises(FrameworkError):
            validate_profile(value)

    def test_hacc_largest_object_must_fall_inside_histogram(self):
        value = _profile("hacc-multifile-dataset")
        value["object_model"]["largest_object_bytes"] = 100000000000
        with self.assertRaises(FrameworkError):
            validate_profile(value)


if __name__ == "__main__":
    unittest.main()
