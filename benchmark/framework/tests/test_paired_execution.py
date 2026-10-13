from __future__ import annotations

import copy
import json
import sys
import unittest
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
    validate_balanced_schedule,
    validate_definition,
)

CONFIG = BENCHMARK / "configs" / "r6.5.4-pi-mac-paired-scientific-execution.json"


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
        h2={"requests_failed":0,"requests_errored":0,"requests_timeout":0,"achieved_target_ratio":0.5}
        lg={"max_total_cpu_busy_percent":40,"max_single_core_busy_percent":60,"firmware_throttling_active":False}
        dut={"throttling_active":False}
        self.assertTrue(evaluate_measurement_validity(h2,lg,dut,self.policy)["valid"])

    def test_loadgen_saturation_invalidates_without_retry_semantics(self):
        h2={"requests_failed":0,"requests_errored":0,"requests_timeout":0}
        lg={"max_total_cpu_busy_percent":86,"max_single_core_busy_percent":60,"firmware_throttling_active":False}
        dut={"throttling_active":False}
        result=evaluate_measurement_validity(h2,lg,dut,self.policy)
        self.assertFalse(result["valid"]); self.assertIn("loadgen-total-cpu-headroom",result["reasons"])


    def test_telemetry_integrity_requires_process_and_throttling_signals(self):
        local=[{"process":None,"thermal":{"throttling_active":False,"temperature_c":50.0}} for _ in range(2)]
        remote=[{"process":{"cpu_seconds":1.0},"cpu":{"busy_percent":10.0,"per_core_busy_percent":[10.0]},"thermal":{"throttling_active":False,"temperature_c":45.0},"udp":{"in_errors":0}} for _ in range(2)]
        self.assertIn("dut-process-telemetry-incomplete", telemetry_integrity_reasons(local,remote))

    def test_http_failure_invalidates(self):
        h2={"requests_failed":1,"requests_errored":0,"requests_timeout":0}
        lg={"max_total_cpu_busy_percent":40,"max_single_core_busy_percent":60,"firmware_throttling_active":False}
        dut={"throttling_active":False}
        self.assertFalse(evaluate_measurement_validity(h2,lg,dut,self.policy)["valid"])


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
