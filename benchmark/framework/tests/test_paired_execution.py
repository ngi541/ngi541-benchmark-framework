from __future__ import annotations

import copy
import json
import sys
import unittest
from unittest.mock import patch
from pathlib import Path

BENCHMARK = Path(__file__).resolve().parents[2]
if str(BENCHMARK) not in sys.path:
    sys.path.insert(0, str(BENCHMARK))

from framework.io_utils import FrameworkError
from framework.paired_execution import (
    analyze_paired_results,
    build_paired_schedule,
    definition_sha256,
    evaluate_measurement_validity,
    load_definition,
    paired_delta_percent,
    telemetry_integrity_reasons,
    _parse_scientific_h2load_result,
    _required_keepalive_requests,
    _summarize_dut_exact_window,
    _window_samples,
    _wait_udp_stably_bindable,
    validate_balanced_schedule,
    validate_definition,
)

CONFIG = BENCHMARK / "configs" / "r6.5.4.5-pi-mac-paired-scientific-execution.json"


def fake_plan():
    rows=[]
    for workers, semantic in ((1,"single"),(4,"physical-core-count")):
        for profile in ("clas12-event-stream","hacc-multifile-dataset","lcls-detector-frame"):
            for fraction in (0.5,0.8):
                rows.append({
                    "condition_id": f"w{workers}-{profile}-s{int(fraction*100)}",
                    "profile_id": profile,
                    "worker_processes": workers,
                    "worker_semantic": semantic,
                    "service_fraction": fraction,
                    "target_goodput_mbps": 100*fraction,
                    "client": {"connections": 1, "max_concurrent_streams_per_connection": 1, "threads": 1},
                    "pacing": "per-client-rps" if profile != "hacc-multifile-dataset" else "deterministic-byte-timing-script",
                })
    return {"conditions": rows}


class DefinitionTests(unittest.TestCase):
    def setUp(self):
        self.definition=json.loads(CONFIG.read_text())

    def test_valid_definition(self):
        validate_definition(self.definition)

    def test_definition_hash_is_semantic(self):
        a=definition_sha256(self.definition)
        b=definition_sha256(json.loads(json.dumps(self.definition, sort_keys=True)))
        self.assertEqual(a,b)

    def test_final_freeze_path_is_portable(self):
        broken=copy.deepcopy(self.definition); broken["inputs"]["final_freeze_config"]="/tmp/freeze.json"
        with self.assertRaises(FrameworkError): validate_definition(broken)

    def test_repetitions_are_frozen_to_four(self):
        broken=copy.deepcopy(self.definition); broken["execution"]["repetitions"]=5
        with self.assertRaises(FrameworkError): validate_definition(broken)

    def test_retry_and_outlier_policies_are_strict(self):
        broken=copy.deepcopy(self.definition); broken["execution"]["retry_policy"]="retry-on-low-throughput"
        with self.assertRaises(FrameworkError): validate_definition(broken)
        broken=copy.deepcopy(self.definition); broken["execution"]["outlier_policy"]="trim-5-percent"
        with self.assertRaises(FrameworkError): validate_definition(broken)

    def test_hacc_scope_is_not_full_dataset_claim(self):
        self.assertTrue(self.definition["execution"]["hacc_execution"]["not_a_full_dataset_claim"])

    def test_measurement_protocol_revision_and_server_control_are_pinned(self):
        execution = self.definition["execution"]
        controls = execution["server_controls"]

        self.assertEqual(
            execution["measurement_protocol_revision"],
            "r6.5.4.5",
        )
        self.assertEqual(
            controls["keepalive_requests"],
            20000,
        )
        self.assertIs(
            controls["require_prestart_udp_bindable"],
            True,
        )
        self.assertEqual(
            controls["remote_http3_readiness"],
            "pinned-curl-single-request",
        )
        self.assertEqual(
            controls["startup_readiness_timeout_seconds"],
            5.0,
        )
        self.assertEqual(
            controls["prestart_udp_stable_seconds"],
            5.0,
        )
        self.assertEqual(
            controls[
                "prestart_quiescence_timeout_seconds"
            ],
            15.0,
        )
        self.assertEqual(
            controls["shutdown_release_timeout_seconds"],
            15.0,
        )
        self.assertEqual(
            execution["telemetry"]["dut_sampling"],
            "nonblocking-window-v2",
        )

    def test_strict_main_window_selection_is_frozen(self):
        telemetry = (
            self.definition["execution"]["telemetry"]
        )

        self.assertEqual(
            telemetry[
                "measurement_window_selection"
            ],
            "strict-main-no-tolerance",
        )

        broken = copy.deepcopy(
            self.definition
        )

        broken["execution"]["telemetry"][
            "measurement_window_selection"
        ] = "main-with-one-second-tolerance"

        with self.assertRaises(
            FrameworkError
        ):
            validate_definition(
                broken
            )

    def test_quiescence_controls_cannot_regress(self):
        broken = copy.deepcopy(
            self.definition
        )

        broken["execution"]["server_controls"][
            "prestart_udp_stable_seconds"
        ] = 0.0

        with self.assertRaises(
            FrameworkError
        ):
            validate_definition(
                broken
            )

        broken = copy.deepcopy(
            self.definition
        )

        broken["execution"]["server_controls"][
            "prestart_quiescence_timeout_seconds"
        ] = 4.0

        with self.assertRaises(
            FrameworkError
        ):
            validate_definition(
                broken
            )

    def test_keepalive_request_cap_cannot_regress_to_nginx_default_scale(self):
        broken=copy.deepcopy(self.definition); broken["execution"]["server_controls"]["keepalive_requests"]=1000
        with self.assertRaises(FrameworkError): validate_definition(broken)

    def test_server_lifecycle_controls_cannot_regress(self):
        broken = copy.deepcopy(self.definition)
        broken["execution"]["server_controls"]["require_prestart_udp_bindable"] = False
        with self.assertRaises(FrameworkError):
            validate_definition(broken)

        broken = copy.deepcopy(self.definition)
        broken["execution"]["server_controls"]["remote_http3_readiness"] = "none"
        with self.assertRaises(FrameworkError):
            validate_definition(broken)

        for key in (
            "startup_readiness_timeout_seconds",
            "shutdown_release_timeout_seconds",
        ):
            broken = copy.deepcopy(self.definition)
            broken["execution"]["server_controls"][key] = 0.0
            with self.assertRaises(FrameworkError):
                validate_definition(broken)


class ServerLifecycleIsolationTests(
    unittest.TestCase
):
    @staticmethod
    def _probe(bindable):
        return {
            "bindable": bindable,
            "host": "127.0.0.1",
            "port": 8443,
            "errno": (
                None
                if bindable
                else 48
            ),
            "error": (
                None
                if bindable
                else "busy"
            ),
        }

    def test_stable_window_resets_after_busy_probe(self):
        probes = [
            self._probe(True),
            self._probe(True),
            self._probe(False),
            self._probe(True),
            self._probe(True),
            self._probe(True),
        ]

        times = [
            0.0,
            0.0,
            1.0,
            2.0,
            3.0,
            4.0,
            5.0,
        ]

        with (
            patch(
                "framework.paired_execution."
                "_udp_bind_probe",
                side_effect=probes,
            ),
            patch(
                "framework.paired_execution."
                "time.monotonic",
                side_effect=times,
            ),
            patch(
                "framework.paired_execution."
                "time.sleep",
            ),
        ):
            out = _wait_udp_stably_bindable(
                "127.0.0.1",
                8443,
                timeout_seconds=10.0,
                stable_seconds=2.0,
                poll_interval_seconds=0.1,
            )

        self.assertIs(
            out["stable_bindable"],
            True,
        )

        self.assertEqual(
            out["attempts"],
            6,
        )

        self.assertEqual(
            out["stable_observed_seconds"],
            2.0,
        )

    def test_stable_window_timeout_fails_closed(self):
        probes = [
            self._probe(True),
            self._probe(False),
            self._probe(True),
            self._probe(False),
        ]

        times = [
            0.0,
            0.0,
            1.0,
            2.0,
            3.0,
        ]

        with (
            patch(
                "framework.paired_execution."
                "_udp_bind_probe",
                side_effect=probes,
            ),
            patch(
                "framework.paired_execution."
                "time.monotonic",
                side_effect=times,
            ),
            patch(
                "framework.paired_execution."
                "time.sleep",
            ),
        ):
            out = _wait_udp_stably_bindable(
                "127.0.0.1",
                8443,
                timeout_seconds=3.0,
                stable_seconds=2.0,
                poll_interval_seconds=0.1,
            )

        self.assertIs(
            out["stable_bindable"],
            False,
        )

        self.assertEqual(
            out["attempts"],
            4,
        )

    def test_runtime_prestart_uses_stable_gate(self):
        source = (
            BENCHMARK
            / "framework"
            / "paired_execution.py"
        ).read_text(
            encoding="utf-8"
        )

        start = source.index(
            "                    prestart = "
        )

        end = source.index(
            "                    out_handle = (",
            start,
        )

        block = source[
            start:end
        ]

        self.assertIn(
            "_wait_udp_stably_bindable(",
            block,
        )

        self.assertNotIn(
            "prestart = _udp_bind_probe(",
            block,
        )

        self.assertIn(
            "prestart_quiescence_timeout_seconds",
            block,
        )

        self.assertIn(
            "prestart_udp_stable_seconds",
            block,
        )


class ScheduleTests(unittest.TestCase):
    def test_schedule_has_96_runs_and_48_pairs(self):
        runs=build_paired_schedule(fake_plan())
        self.assertEqual(len(runs),96)
        self.assertEqual(len({r["pair_id"] for r in runs}),48)
        validate_balanced_schedule(runs)

    def test_each_condition_has_two_each_first_orders(self):
        runs=build_paired_schedule(fake_plan())
        ids={r["condition"]["condition_id"] for r in runs}
        for cid in ids:
            first=[]
            pairs={}
            for r in runs:
                if r["condition"]["condition_id"]==cid:
                    pairs.setdefault(r["pair_id"],[]).append(r)
            for rows in pairs.values():
                first.append(sorted(rows,key=lambda x:x["pair_position"])[0]["variant"])
            self.assertEqual(first.count("stock"),2)
            self.assertEqual(first.count("ngi541-direct"),2)

    def test_schedule_is_deterministic(self):
        self.assertEqual(build_paired_schedule(fake_plan()), build_paired_schedule(fake_plan()))


class ValidityTests(unittest.TestCase):
    policy={"require_zero_http_failures":True,"require_no_throttling":True,"loadgen_total_cpu_max_percent":85.0,"loadgen_core_cpu_max_percent":95.0}

    def test_low_goodput_is_result_not_invalidity(self):
        h2={
            "requests_started":10,
            "requests_succeeded":10,
            "application_data_bytes":327680,
            "requests_failed":0,
            "requests_errored":0,
            "requests_timeout":0,
            "requests_completed_failures":0,
            "status_4xx":0,
            "status_5xx":0,
            "achieved_target_ratio":0.5,
        }
        lg={"max_total_cpu_busy_percent":40,"max_single_core_busy_percent":60,"firmware_throttling_active":False}
        dut={"throttling_active":False}
        self.assertTrue(evaluate_measurement_validity(h2,lg,dut,self.policy)["valid"])

    def test_zero_traffic_measurement_is_invalid(self):
        h2={
            "requests_started":0,
            "requests_succeeded":0,
            "application_data_bytes":0,
            "requests_failed":0,
            "requests_errored":0,
            "requests_timeout":0,
            "requests_completed_failures":0,
            "status_4xx":0,
            "status_5xx":0,
        }
        lg={"max_total_cpu_busy_percent":40,"max_single_core_busy_percent":60,"firmware_throttling_active":False}
        dut={"throttling_active":False}

        out=evaluate_measurement_validity(
            h2,
            lg,
            dut,
            self.policy,
        )

        self.assertFalse(out["valid"])
        self.assertIn(
            "no-measurement-traffic",
            out["reasons"],
        )
        self.assertIn(
            "no-application-data",
            out["reasons"],
        )

    def test_started_requests_without_application_data_are_invalid(self):
        h2={
            "requests_started":10,
            "requests_succeeded":10,
            "application_data_bytes":0,
            "requests_failed":0,
            "requests_errored":0,
            "requests_timeout":0,
            "requests_completed_failures":0,
            "status_4xx":0,
            "status_5xx":0,
        }
        lg={"max_total_cpu_busy_percent":40,"max_single_core_busy_percent":60,"firmware_throttling_active":False}
        dut={"throttling_active":False}

        out=evaluate_measurement_validity(
            h2,
            lg,
            dut,
            self.policy,
        )

        self.assertFalse(out["valid"])
        self.assertNotIn(
            "no-measurement-traffic",
            out["reasons"],
        )
        self.assertIn(
            "no-application-data",
            out["reasons"],
        )

    def test_loadgen_saturation_invalidates_without_retry_semantics(self):
        h2={
            "requests_started":10,
            "requests_succeeded":10,
            "application_data_bytes":327680,
            "requests_failed":0,
            "requests_errored":0,
            "requests_timeout":0,
            "requests_completed_failures":0,
            "status_4xx":0,
            "status_5xx":0,
        }
        lg={"max_total_cpu_busy_percent":86,"max_single_core_busy_percent":60,"firmware_throttling_active":False}
        dut={"throttling_active":False}
        result=evaluate_measurement_validity(h2,lg,dut,self.policy)
        self.assertFalse(result["valid"])
        self.assertEqual(
            result["reasons"],
            ["loadgen-total-cpu-headroom"],
        )


    def test_telemetry_integrity_requires_process_and_throttling_signals(self):
        local=[{"process":None,"thermal":{"throttling_active":False,"temperature_c":50.0}} for _ in range(2)]
        remote=[{"process":{"cpu_seconds":1.0},"cpu":{"busy_percent":10.0,"per_core_busy_percent":[10.0]},"thermal":{"throttling_active":False,"temperature_c":45.0},"udp":{"in_errors":0}} for _ in range(2)]
        self.assertIn("dut-process-telemetry-incomplete", telemetry_integrity_reasons(local,remote))

    def test_inferred_h2load_unissued_accounting_does_not_fake_http_failure(self):
        h2={
            "requests_failed":1,"requests_errored":1,"requests_timeout":0,
            "requests_started":2481,"requests_succeeded":2481,
            "application_data_bytes":81297408,
            "status_4xx":0,"status_5xx":0,
        }
        lg={"max_total_cpu_busy_percent":40,"max_single_core_busy_percent":60,"firmware_throttling_active":False}
        dut={"throttling_active":False}
        self.assertTrue(evaluate_measurement_validity(h2,lg,dut,self.policy)["valid"])

    def test_actual_started_request_without_success_invalidates(self):
        h2={
            "requests_failed":1,"requests_errored":1,"requests_timeout":0,
            "requests_started":2481,"requests_succeeded":2480,
            "application_data_bytes":81264640,
            "requests_completed_failures": 1,
            "status_4xx":0,"status_5xx":0,
        }
        lg={"max_total_cpu_busy_percent":40,"max_single_core_busy_percent":60,"firmware_throttling_active":False}
        dut={"throttling_active":False}
        out=evaluate_measurement_validity(h2,lg,dut,self.policy)
        self.assertFalse(out["valid"]); self.assertIn("http-request-failure",out["reasons"])

    def test_warmup_carryover_is_accounting_failure_not_http_failure(self):
        h2 = {
            "requests_failed": 0,
            "requests_errored": 0,
            "requests_timeout": 0,
            "requests_started": 3812,
            "requests_succeeded": 3814,
            "application_data_bytes": 156106752,
            "status_4xx": 0,
            "status_5xx": 0,
        }
        lg = {
            "max_total_cpu_busy_percent": 40,
            "max_single_core_busy_percent": 60,
            "firmware_throttling_active": False,
        }
        dut = {
            "throttling_active": False,
        }

        out = evaluate_measurement_validity(
            h2,
            lg,
            dut,
            self.policy,
        )

        self.assertFalse(out["valid"])

        self.assertIn(
            "h2load-phase-boundary-accounting",
            out["reasons"],
        )

        self.assertNotIn(
            "http-request-failure",
            out["reasons"],
        )

class StrictMainTelemetryWindowTests(unittest.TestCase):
    @staticmethod
    def _remote_sample(
        index,
        offset_seconds,
        *,
        total_cpu,
        core_cpu,
        process_present=True,
    ):
        return {
            "sample_index": index,
            "monotonic_ns": int(
                offset_seconds * 1e9
            ),
            "cpu": {
                "busy_percent":
                    total_cpu,
                "per_core_busy_percent": [
                    core_cpu
                ],
            },
            "thermal": {
                "throttling_active":
                    False,
                "temperature_c":
                    45.0,
            },
            "process": (
                {
                    "cpu_seconds":
                        float(index),
                }
                if process_present
                else None
            ),
            "network": {
                "rx_bytes":
                    index * 100,
                "tx_bytes":
                    index * 200,
            },
            "udp": {
                "in_errors": 0,
            },
        }

    @staticmethod
    def _valid_local_samples():
        return [
            {
                "process": {
                    "cpu_seconds": 1.0,
                },
                "thermal": {
                    "throttling_active":
                        False,
                    "temperature_c":
                        50.0,
                },
            },
            {
                "process": {
                    "cpu_seconds": 2.0,
                },
                "thermal": {
                    "throttling_active":
                        False,
                    "temperature_c":
                        50.0,
                },
            },
        ]

    def test_strict_main_excludes_warmup_and_post_main_cpu_spikes(self):
        samples = [
            self._remote_sample(
                0,
                0.0,
                total_cpu=10.0,
                core_cpu=20.0,
            ),
            self._remote_sample(
                1,
                4.1,
                total_cpu=99.0,
                core_cpu=99.0,
            ),
            self._remote_sample(
                2,
                5.2,
                total_cpu=20.0,
                core_cpu=40.0,
            ),
            self._remote_sample(
                3,
                10.0,
                total_cpu=30.0,
                core_cpu=50.0,
            ),
            self._remote_sample(
                4,
                24.6,
                total_cpu=25.0,
                core_cpu=45.0,
            ),
            self._remote_sample(
                5,
                25.6,
                total_cpu=98.0,
                core_cpu=98.0,
                process_present=False,
            ),
        ]

        selected = _window_samples(
            samples,
            start_ns=int(5.0e9),
            end_ns=int(25.0e9),
        )

        self.assertEqual(
            [
                row["sample_index"]
                for row in selected
            ],
            [2, 3, 4],
        )

        total_cpu_max = max(
            float(
                row["cpu"]["busy_percent"]
            )
            for row in selected
        )

        core_cpu_max = max(
            float(value)
            for row in selected
            for value in row["cpu"][
                "per_core_busy_percent"
            ]
        )

        self.assertEqual(
            total_cpu_max,
            30.0,
        )

        self.assertEqual(
            core_cpu_max,
            50.0,
        )

        reasons = telemetry_integrity_reasons(
            self._valid_local_samples(),
            selected,
        )

        self.assertNotIn(
            "loadgen-process-telemetry-incomplete",
            reasons,
        )

    def test_post_main_process_disappearance_is_not_main_failure(self):
        samples = [
            self._remote_sample(
                0,
                5.2,
                total_cpu=20.0,
                core_cpu=30.0,
            ),
            self._remote_sample(
                1,
                15.0,
                total_cpu=25.0,
                core_cpu=35.0,
            ),
            self._remote_sample(
                2,
                24.6,
                total_cpu=30.0,
                core_cpu=40.0,
            ),
            self._remote_sample(
                3,
                25.63,
                total_cpu=20.0,
                core_cpu=30.0,
                process_present=False,
            ),
        ]

        selected = _window_samples(
            samples,
            start_ns=int(5.0e9),
            end_ns=int(25.0e9),
        )

        self.assertEqual(
            [
                row["sample_index"]
                for row in selected
            ],
            [0, 1, 2],
        )

        reasons = telemetry_integrity_reasons(
            self._valid_local_samples(),
            selected,
        )

        self.assertNotIn(
            "loadgen-process-telemetry-incomplete",
            reasons,
        )

    def test_in_main_process_disappearance_remains_invalid(self):
        samples = [
            self._remote_sample(
                0,
                5.2,
                total_cpu=20.0,
                core_cpu=30.0,
            ),
            self._remote_sample(
                1,
                15.0,
                total_cpu=25.0,
                core_cpu=35.0,
                process_present=False,
            ),
            self._remote_sample(
                2,
                24.6,
                total_cpu=30.0,
                core_cpu=40.0,
            ),
        ]

        selected = _window_samples(
            samples,
            start_ns=int(5.0e9),
            end_ns=int(25.0e9),
        )

        self.assertEqual(
            [
                row["sample_index"]
                for row in selected
            ],
            [0, 1, 2],
        )

        reasons = telemetry_integrity_reasons(
            self._valid_local_samples(),
            selected,
        )

        self.assertIn(
            "loadgen-process-telemetry-incomplete",
            reasons,
        )

    def test_runtime_main_selection_has_no_tolerance_or_fallback(self):
        source = (
            BENCHMARK
            / "framework"
            / "paired_execution.py"
        ).read_text(
            encoding="utf-8"
        )

        start_marker = (
            "    remote_all = "
            "_parse_remote_jsonl(telemetry_text)"
        )

        end_marker = (
            "    h2 = "
            "_parse_scientific_h2load_result("
        )

        start = source.index(
            start_marker
        )

        end = source.index(
            end_marker,
            start,
        )

        block = source[start:end]

        self.assertNotIn(
            "tolerance_ns",
            block,
        )

        self.assertNotIn(
            "_measurement_slice(",
            block,
        )

        self.assertIn(
            "local_measurement = "
            "_window_samples(",
            block,
        )

        self.assertIn(
            "remote_measurement = "
            "_window_samples(",
            block,
        )

        self.assertIn(
            "loadgen = "
            "summarize_loadgen_telemetry("
            "remote_measurement)",
            source,
        )


class MeasurementProtocolCorrectionTests(unittest.TestCase):
    def test_clas12_80mbps_requires_more_than_default_1000_requests_per_connection(self):
        profile={"kind":"fixed-object","object_size_bytes":32768}
        required=_required_keepalive_requests(
            profile,target_goodput_mbps=80.0,connections=4,
            warmup_seconds=5.0,measurement_seconds=20.0,
        )
        self.assertGreater(required,1000)
        self.assertLess(required,20000)

    def test_scientific_goodput_uses_phase_scoped_main_body_bytes(self):
        value = {
            "measurements": {
                "duration": 25.011915,
                "requests": {
                    "started": 2482,
                    "done": 2481,
                    "failed": 0,
                    "errored": 0,
                    "timeout": 0,
                    "succeeded": 2481,
                },
                "status_codes": {
                    "2xx": 2482,
                    "3xx": 0,
                    "4xx": 0,
                    "5xx": 0,
                },
                "traffic": {
                    "data": 125000000,
                    "total": 150000000,
                },
                "request_per_second": 124.1,
                "bytes_per_second": 4080319,
                "performance": {},
                "udp_datagram": {
                    "sent": 14431,
                    "recv": 96132,
                },
            }
        }

        profile = {
            "kind": "fixed-object",
            "object_size_bytes": 32768,
        }

        out = _parse_scientific_h2load_result(
            value,
            target_goodput_mbps=50.0,
            measurement_seconds=20.0,
            profile=profile,
        )

        self.assertEqual(
            out["application_data_bytes"],
            125000000,
        )
        self.assertAlmostEqual(
            out["application_goodput_mbps"],
            50.0,
        )
        self.assertEqual(
            out["requests_inflight_at_cutoff"],
            1,
        )
        self.assertEqual(
            out["requests_completed_failures"],
            0,
        )
        self.assertFalse(
            out["h2load_accounting_anomaly"]
        )

    def test_dut_cpu_and_power_are_integrated_only_over_exact_main_window(self):
        # 1 GiB scientific payload.  Main window is 5..25 s.
        gib=1024**3
        samples=[]
        for i,(sec,cpu,power) in enumerate(((0,0.0,10.0),(5,5.0,10.0),(15,15.0,10.0),(25,25.0,10.0),(30,30.0,10.0))):
            samples.append({
                "monotonic_ns":sec*1_000_000_000,
                "process":{"cpu_seconds":cpu},
                "power":{"package_power_w_estimate":power},
                "thermal":{"throttling_active":False},
            })
        out=_summarize_dut_exact_window(
            samples,application_data_bytes=gib,
            start_ns=5_000_000_000,end_ns=25_000_000_000,
        )
        self.assertAlmostEqual(out["process_cpu_seconds_delta"],20.0)
        self.assertAlmostEqual(out["process_cpu_seconds_per_gib"],20.0)
        self.assertAlmostEqual(out["estimated_energy_j"],200.0)
        self.assertAlmostEqual(out["estimated_energy_j_per_gib"],200.0)
        self.assertTrue(out["boundary_covered"])

    def test_h2load_warmup_carryover_is_detected(self):
        value = {
            "measurements": {
                "duration": 25.000862,
                "requests": {
                    "started": 3812,
                    "done": 3814,
                    "failed": 0,
                    "errored": 0,
                    "timeout": 0,
                    "succeeded": 3814,
                },
                "status_codes": {
                    "2xx": 3814,
                    "3xx": 0,
                    "4xx": 0,
                    "5xx": 0,
                },
                "traffic": {
                    "data": 156106752,
                    "total": 125450088,
                },
                "request_per_second": 190.7,
                "bytes_per_second": 6272504,
                "performance": {},
                "udp_datagram": {
                    "sent": 19131,
                    "recv": 114614,
                },
            }
        }

        profile = {
            "kind": "fixed-object",
            "object_size_bytes": 32768,
        }

        out = _parse_scientific_h2load_result(
            value,
            target_goodput_mbps=50.0,
            measurement_seconds=20.0,
            profile=profile,
        )

        self.assertTrue(
            out["h2load_accounting_anomaly"]
        )

        self.assertEqual(
            out["h2load_phase_boundary_excess_successes"],
            2,
        )


class ResumePolicyTests(unittest.TestCase):
    def test_completed_invalid_run_cannot_be_retried_semantically(self):
        definition=json.loads(CONFIG.read_text())
        self.assertEqual(definition["execution"]["retry_policy"], "no-metric-dependent-retry")
        self.assertEqual(definition["execution"]["outlier_policy"], "retain-all-valid-runs")


class PairedAnalysisTests(unittest.TestCase):
    def test_delta_direction(self):
        self.assertAlmostEqual(paired_delta_percent(100,105,higher_is_better=True),5.0)
        self.assertAlmostEqual(paired_delta_percent(10,9,higher_is_better=False),10.0)

    def test_paired_analysis_retains_all_pairs(self):
        rows=[]
        for rep,(stock_g,ngi_g) in enumerate(((100,105),(100,103),(100,99),(100,104)),start=1):
            pair=f"pair-{rep:04d}"; order="stock/ngi541-direct" if rep%2 else "ngi541-direct/stock"
            rows.append({"condition_id":"c1","repetition":rep,"pair_id":pair,"pair_order":order,"variant":"stock","metrics":{"application_goodput_mbps":stock_g,"dut_process_cpu_seconds_per_gib":10.0,"dut_estimated_energy_j_per_gib":20.0}})
            rows.append({"condition_id":"c1","repetition":rep,"pair_id":pair,"pair_order":order,"variant":"ngi541-direct","metrics":{"application_goodput_mbps":ngi_g,"dut_process_cpu_seconds_per_gib":9.0,"dut_estimated_energy_j_per_gib":18.0}})
        out=analyze_paired_results(rows)
        self.assertEqual(out["pair_count"],4)
        self.assertEqual(out["outlier_deletion"],"none")
        goodput=out["conditions"][0]["metrics"]["application_goodput_mbps"]
        self.assertEqual(goodput["pair_count"],4)
        self.assertEqual(goodput["ngi541_pair_wins"],3)


if __name__ == "__main__":
    unittest.main()
