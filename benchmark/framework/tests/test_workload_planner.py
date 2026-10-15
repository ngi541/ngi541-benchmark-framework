from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from framework.io_utils import FrameworkError
from framework.workload_planner import (
    _hacc_calibration_objects,
    build_hacc_timing_script,
    definition_sha256,
    derive_target_goodput_mbps,
    evaluate_probe,
    fixed_object_rate_hz,
    load_definition,
    parse_h2load_json,
    per_client_rps,
    select_first_passing_candidate,
    summarize_loadgen_telemetry,
    validate_definition,
)

ROOT = Path(__file__).resolve().parents[3]
CONFIG = ROOT / "benchmark" / "configs" / "r6.5.4.2-pi-mac-stock-workload-planner.json"


class WorkloadPlannerDefinitionTests(unittest.TestCase):
    def setUp(self):
        self.definition = json.loads(CONFIG.read_text(encoding="utf-8"))

    def test_valid_definition(self):
        validate_definition(self.definition)
        self.assertEqual(load_definition(CONFIG), self.definition)

    def test_definition_hash_is_semantic(self):
        self.assertEqual(
            definition_sha256(self.definition),
            definition_sha256(json.loads(json.dumps(self.definition, sort_keys=True))),
        )

    def test_keepalive_requests_is_frozen_above_nginx_default(self):
        self.assertEqual(
            self.definition["planning"]["server_controls"],
            {"keepalive_requests": 20000},
        )

        broken = copy.deepcopy(self.definition)
        broken["planning"]["server_controls"]["keepalive_requests"] = 1000

        with self.assertRaises(FrameworkError):
            validate_definition(broken)

    def test_calibration_variant_is_stock_only(self):
        value = copy.deepcopy(self.definition)
        value["planning"]["calibration_variant"] = "ngi541-direct"
        with self.assertRaises(FrameworkError):
            validate_definition(value)

    def test_service_targets_are_frozen(self):
        value = copy.deepcopy(self.definition)
        value["planning"]["service_target_fractions"] = [0.6, 0.9]
        with self.assertRaises(FrameworkError):
            validate_definition(value)

    def test_worker_points_are_semantic(self):
        value = copy.deepcopy(self.definition)
        value["planning"]["worker_points"] = [1, 4]
        with self.assertRaises(FrameworkError):
            validate_definition(value)

    def test_input_paths_are_portable(self):
        value = copy.deepcopy(self.definition)
        value["inputs"]["network_evidence_config"] = "/tmp/evidence.json"
        with self.assertRaises(FrameworkError):
            validate_definition(value)

    def test_candidate_order_is_staged_by_connections(self):
        value = copy.deepcopy(self.definition)
        value["planning"]["concurrency_candidates"] = [
            {"connections": 2, "max_concurrent_streams_per_connection": 4},
            {"connections": 1, "max_concurrent_streams_per_connection": 64},
        ]
        with self.assertRaises(FrameworkError):
            validate_definition(value)


class WorkloadDerivationTests(unittest.TestCase):
    def test_service_target_derivation(self):
        self.assertEqual(derive_target_goodput_mbps(99.99998, 0.5), 49.99999)
        self.assertEqual(derive_target_goodput_mbps(99.99998, 0.8), 79.999984)

    def test_clas12_rps_derivation(self):
        rate = fixed_object_rate_hz(80.0, 32768)
        self.assertAlmostEqual(rate, 305.17578125)
        self.assertAlmostEqual(per_client_rps(80.0, 32768, 4), rate / 4)

    def test_lcls_rate_preserves_ten_megabyte_frame(self):
        self.assertAlmostEqual(fixed_object_rate_hz(80.0, 10_000_000), 1.0)

    def test_hacc_timing_script_is_deterministic_and_byte_paced(self):
        objects = [
            {"object_id": "a", "size_bytes": 1_000_000},
            {"object_id": "b", "size_bytes": 2_000_000},
        ]
        kwargs = dict(
            target_goodput_mbps=24.0,
            connections=1,
            duration_seconds=2.0,
            base_uri="https://example.test:8443",
            object_paths={"a": "a.bin", "b": "b.bin"},
        )
        first = build_hacc_timing_script(objects, **kwargs)
        second = build_hacc_timing_script(objects, **kwargs)
        self.assertEqual(first, second)
        rows = first.strip().splitlines()
        self.assertTrue(rows[0].startswith("0.001000\t"))
        self.assertIn("333.333333\thttps://example.test:8443/b.bin", rows[1])

    def test_hacc_calibration_selection_is_bucket_bounded(self):
        manifest = {"objects": [
            {"bucket_index": 6, "sequence": 2, "object_id": "c", "size_bytes": 3},
            {"bucket_index": 6, "sequence": 0, "object_id": "a", "size_bytes": 1},
            {"bucket_index": 6, "sequence": 1, "object_id": "b", "size_bytes": 2},
            {"bucket_index": 7, "sequence": 3, "object_id": "d", "size_bytes": 4},
        ]}
        selected = _hacc_calibration_objects(manifest, {
            "bucket_indices": [6], "objects_per_bucket": 2, "max_materialized_bytes": 10
        })
        self.assertEqual([obj["object_id"] for obj in selected], ["a", "b"])


class H2loadResultTests(unittest.TestCase):
    def test_parse_h2load_json_uses_exact_main_window_body_bytes(self):
        row = parse_h2load_json(
            {
                "measurements": {
                    "duration": 13.0,
                    "request_per_second": 100,
                    "bytes_per_second": 7_000_000,
                    "requests": {
                        "started": 1001,
                        "done": 1000,
                        "succeeded": 1000,
                        "failed": 0,
                        "errored": 0,
                        "timeout": 0,
                    },
                    "status_codes": {
                        "2xx": 1001,
                        "3xx": 0,
                        "4xx": 0,
                        "5xx": 0,
                    },
                    "traffic": {
                        "data": 62_500_000,
                    },
                    "udp_datagram": {
                        "sent": 1,
                        "recv": 1,
                    },
                    "performance": {},
                }
            },
            target_goodput_mbps=50.0,
            measurement_seconds=10.0,
        )

        self.assertAlmostEqual(
            row["application_goodput_mbps"],
            50.0,
        )
        self.assertAlmostEqual(
            row["achieved_target_ratio"],
            1.0,
        )
        self.assertEqual(
            row["requests_inflight_at_cutoff"],
            1,
        )
        self.assertEqual(
            row["requests_completed_failures"],
            0,
        )
        self.assertFalse(
            row["h2load_accounting_anomaly"]
        )

    def test_headroom_summary_tracks_peak_core(self):
        samples = [
            {"cpu": {"busy_percent": None, "per_core_busy_percent": [None, None]}, "thermal": {"throttling_active": False}, "process": None, "network": {}, "udp": {}},
            {"cpu": {"busy_percent": 40.0, "per_core_busy_percent": [30.0, 90.0]}, "thermal": {"throttling_active": False}, "process": {"cpu_seconds": 1.0}, "network": {"rx_bytes": 10, "tx_bytes": 20}, "udp": {"in_errors": 0}},
            {"cpu": {"busy_percent": 45.0, "per_core_busy_percent": [35.0, 92.0]}, "thermal": {"throttling_active": False}, "process": {"cpu_seconds": 2.0}, "network": {"rx_bytes": 30, "tx_bytes": 40}, "udp": {"in_errors": 0}},
        ]
        summary = summarize_loadgen_telemetry(samples)
        self.assertEqual(summary["max_total_cpu_busy_percent"], 45.0)
        self.assertEqual(summary["max_single_core_busy_percent"], 92.0)
        self.assertEqual(summary["process_cpu_seconds_delta"], 1.0)

    def test_probe_requires_goodput_and_headroom(self):
        h2 = {"achieved_target_ratio": 0.98, "requests_failed": 0, "requests_errored": 0, "requests_timeout": 0}
        load = {"max_total_cpu_busy_percent": 50.0, "max_single_core_busy_percent": 90.0, "firmware_throttling_active": False}
        dut = {"throttling_active": False}
        policy = {"achieved_target_ratio_min": 0.95, "loadgen_total_cpu_max_percent": 85, "loadgen_core_cpu_max_percent": 95, "require_no_throttling": True}
        self.assertTrue(evaluate_probe(h2, load, dut, policy)["passed"])
        load["max_single_core_busy_percent"] = 97.0
        result = evaluate_probe(h2, load, dut, policy)
        self.assertFalse(result["passed"])
        self.assertIn("loadgen-single-core-headroom", result["reasons"])

    def test_inflight_at_cutoff_is_not_http_failure(self):
        h2 = {
            "achieved_target_ratio": 0.98,
            "requests_timeout": 0,
            "requests_completed_failures": 0,
            "requests_inflight_at_cutoff": 1,
            "status_4xx": 0,
            "status_5xx": 0,
            "h2load_accounting_anomaly": False,
        }

        load = {
            "max_total_cpu_busy_percent": 50.0,
            "max_single_core_busy_percent": 90.0,
            "firmware_throttling_active": False,
        }

        dut = {
            "throttling_active": False,
        }

        policy = {
            "achieved_target_ratio_min": 0.95,
            "loadgen_total_cpu_max_percent": 85,
            "loadgen_core_cpu_max_percent": 95,
            "require_no_throttling": True,
        }

        self.assertTrue(
            evaluate_probe(h2, load, dut, policy)["passed"]
        )

        h2["requests_completed_failures"] = 1

        result = evaluate_probe(
            h2,
            load,
            dut,
            policy,
        )

        self.assertFalse(result["passed"])
        self.assertIn(
            "http-request-failure",
            result["reasons"],
        )

    def test_first_passing_candidate_is_selected_without_metric_ranking(self):
        probes = [
            {"probe_id": "a", "evaluation": {"passed": False}},
            {"probe_id": "b", "evaluation": {"passed": True}, "h2load": {"application_goodput_mbps": 50}},
            {"probe_id": "c", "evaluation": {"passed": True}, "h2load": {"application_goodput_mbps": 100}},
        ]
        self.assertEqual(select_first_passing_candidate(probes)["probe_id"], "b")

    def test_no_passing_candidate_fails_instead_of_lowering_target(self):
        with self.assertRaises(FrameworkError):
            select_first_passing_candidate([
                {"probe_id": "a", "evaluation": {"passed": False}},
                {"probe_id": "b", "evaluation": {"passed": False}},
            ])


if __name__ == "__main__":
    unittest.main()
