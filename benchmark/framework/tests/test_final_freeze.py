from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from framework.final_freeze import (
    CLAIM_SCOPE,
    LIFECYCLE_STATES,
    _initial_state,
    _mark_failed,
    _plan_semantic_sha,
    _resume_failed,
    _semantic_sha256,
    _transition,
    _verify_artifact_inventory,
    build_final_manifest,
    definition_sha256,
    load_definition,
    validate_definition,
    validate_network,
    validate_plan,
    validate_security,
)
from framework.io_utils import FrameworkError, atomic_write_json, atomic_write_text

ROOT = Path(__file__).resolve().parents[3]
CONFIG = ROOT / "benchmark" / "configs" / "r6.5.4.2-pi-mac-final-freeze.json"


class FinalFreezeDefinitionTests(unittest.TestCase):
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

    def test_claim_scope_is_no_performance_claim(self):
        value = copy.deepcopy(self.definition)
        value["freeze"]["claim_scope"] = "performance-claim"
        with self.assertRaises(FrameworkError):
            validate_definition(value)
        self.assertEqual(self.definition["freeze"]["claim_scope"], CLAIM_SCOPE)

    def test_input_paths_are_portable(self):
        value = copy.deepcopy(self.definition)
        value["inputs"]["workload_planner_config"] = "/tmp/planner.json"
        with self.assertRaises(FrameworkError):
            validate_definition(value)

    def test_exact_variants_are_frozen(self):
        value = copy.deepcopy(self.definition)
        value["requirements"]["variants"] = ["stock", "ngi541-provider"]
        with self.assertRaises(FrameworkError):
            validate_definition(value)

    def test_transport_contract_is_frozen(self):
        value = copy.deepcopy(self.definition)
        value["requirements"]["transport"]["allow_0rtt"] = True
        with self.assertRaises(FrameworkError):
            validate_definition(value)

    def test_plan_shape_is_frozen(self):
        value = copy.deepcopy(self.definition)
        value["requirements"]["plan"]["condition_count"] = 6
        with self.assertRaises(FrameworkError):
            validate_definition(value)


class FinalFreezeLifecycleTests(unittest.TestCase):
    def test_lifecycle_order_matches_frozen_contract(self):
        self.assertEqual(
            LIFECYCLE_STATES,
            [
                "CREATED", "INPUTS_RESOLVING", "INPUTS_FROZEN",
                "PROFILES_VALIDATED", "RUNTIME_READY", "SECURITY_VERIFIED",
                "NETWORK_ENVELOPE_FROZEN", "CORPUS_READY", "TELEMETRY_READY",
                "STOCK_PROBING", "PLAN_DERIVED", "PLAN_FROZEN",
                "VALIDATED", "COMPLETE",
            ],
        )

    def test_transition_is_strictly_sequential(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            atomic_write_json(root / "state.json", _initial_state("freeze", "a" * 64))
            _transition(root, "INPUTS_RESOLVING")
            with self.assertRaises(FrameworkError):
                _transition(root, "PROFILES_VALIDATED")

    def test_failed_state_resumes_from_last_completed_phase(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            atomic_write_json(root / "state.json", _initial_state("freeze", "a" * 64))
            _transition(root, "INPUTS_RESOLVING")
            _transition(root, "INPUTS_FROZEN")
            _mark_failed(root, "PROFILES_VALIDATED", FrameworkError("boom"))
            failed = json.loads((root / "state.json").read_text())
            self.assertEqual(failed["state"], "FAILED")
            self.assertEqual(failed["last_completed_state"], "INPUTS_FROZEN")
            resumed = _resume_failed(root)
            self.assertEqual(resumed["state"], "INPUTS_FROZEN")


class FinalFreezeIntegrityTests(unittest.TestCase):
    def test_artifact_inventory_detects_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "processed").mkdir()
            payload = root / "processed" / "summary.json"
            payload.write_text('{"status":"COMPLETE"}\n', encoding="utf-8")
            import hashlib
            sha = hashlib.sha256(payload.read_bytes()).hexdigest()
            atomic_write_text(root / "artifacts.sha256", f"{sha}  processed/summary.json\n")
            _verify_artifact_inventory(root)
            payload.write_text('{"status":"FAILED"}\n', encoding="utf-8")
            with self.assertRaises(FrameworkError):
                _verify_artifact_inventory(root)

    def test_plan_semantic_sha_excludes_only_plan_sha_field(self):
        plan = {"schema_version": 1, "plan_id": "x", "conditions": []}
        plan["plan_sha256"] = _semantic_sha256(plan)
        self.assertEqual(_plan_semantic_sha(plan), plan["plan_sha256"])
        plan["conditions"].append({"condition_id": "changed"})
        with self.assertRaises(FrameworkError):
            _plan_semantic_sha(plan)


class FinalFreezeContractTests(unittest.TestCase):
    def _definition(self):
        return json.loads(CONFIG.read_text(encoding="utf-8"))

    def _context(self):
        # Only canonical documents required by validate_network/security/plan.
        tmp = tempfile.TemporaryDirectory()
        repo = Path(tmp.name)
        roots = {}
        for name in [
            "network_evidence", "loadgen_runtime", "scientific_corpus",
            "transport_security", "dual_host_telemetry", "workload_planner",
        ]:
            roots[name] = repo / name
            (roots[name] / "processed").mkdir(parents=True)

        envelope_identity = {
            "schema_version": 1,
            "claim_scope": "empirically-qualified-network-service-envelope",
            "direction_semantic": "dut-to-loadgen",
            "direction_transport": "local-to-remote",
            "compatibility_policy": "strict-path-v1",
            "selection_policy": "latest-compatible",
            "aggregation": "minimum",
            "udp_policy": {"max_loss_percent": 0.1, "min_achieved_requested_ratio": 0.95},
            "topology": {},
            "topology_fingerprint_sha256": "1" * 64,
            "evidence_set_sha256": "2" * 64,
            "observation_count": 3,
            "observations": [],
            "floors": {"tcp_capacity_mbps": 314.0, "udp_safe_requested_mbps": 100.0, "udp_safe_achieved_mbps": 100.0},
            "service_envelope_mbps": 100.0,
            "limiting_reference": "udp-safe-achieved-floor",
        }
        envelope = {**envelope_identity, "envelope_sha256": _semantic_sha256(envelope_identity)}
        network_summary = {"status": "COMPLETE", "evidence_id": "net", "envelope_sha256": envelope["envelope_sha256"]}
        atomic_write_json(roots["network_evidence"] / "processed" / "network-envelope.json", envelope)
        atomic_write_json(roots["network_evidence"] / "processed" / "summary.json", network_summary)

        runtime_summary = {
            "status": "COMPLETE", "runtime_id": "runtime",
            "runtime": {"http3_capable": True, "curl_sha256": "3" * 64, "h2load": {
                "sha256": "4" * 64, "http3_capable": True, "json_output_capable": True,
                "timing_script_capable": True, "rps_capable": True, "connections_streams_capable": True,
            }},
            "remote": {"architecture": "aarch64"},
        }
        atomic_write_json(roots["loadgen_runtime"] / "processed" / "summary.json", runtime_summary)

        registry_identity = {
            "profiles": [
                {"profile_id": "clas12-event-stream", "profile_sha256": "6" * 64, "corpus_sha256": "7" * 64},
                {"profile_id": "lcls-detector-frame", "profile_sha256": "8" * 64, "corpus_sha256": "9" * 64},
                {"profile_id": "hacc-multifile-dataset", "profile_sha256": "a" * 64, "corpus_sha256": "b" * 64},
            ],
        }
        registry = {**registry_identity, "corpus_registry_sha256": _semantic_sha256(registry_identity)}
        corpus_summary = {
            "status": "COMPLETE", "corpus_id": "corpus", "profile_count": 3,
            "corpus_registry_sha256": registry["corpus_registry_sha256"],
            "profiles": [
                {"profile_id": "clas12-event-stream"},
                {"profile_id": "lcls-detector-frame"},
                {"profile_id": "hacc-multifile-dataset"},
            ],
            "hacc": {"logical_objects": 19260, "logical_bytes": 4442781786482,
                     "coverage_modes": ["full", "deterministic-stratified", "time-window"]},
        }
        atomic_write_json(roots["scientific_corpus"] / "processed" / "summary.json", corpus_summary)
        atomic_write_json(roots["scientific_corpus"] / "processed" / "registry.json", registry)

        gate_identity = {
            "schema_version": 1, "protocol": "http3-only", "tls_version": "1.3",
            "cipher_suite": "TLS_AES_128_GCM_SHA256",
            "peer_verification": "required-and-verified-by-curl", "zero_rtt": "disabled",
            "http_fallback": "prohibited", "server_name": "x", "dut_address": "x", "loadgen_address": "y",
            "variants": [{"variant": "stock", "passed": True}, {"variant": "ngi541-direct", "passed": True}],
            "passed": True,
        }
        gate = {**gate_identity, "security_gate_sha256": _semantic_sha256(gate_identity)}
        security_summary = {
            "status": "COMPLETE", "qualification_id": "sec", "security_gate_sha256": gate["security_gate_sha256"],
            "network_evidence_id": "net", "loadgen_runtime_id": "runtime", "scientific_corpus_id": "corpus",
        }
        atomic_write_json(roots["transport_security"] / "processed" / "security-gate.json", gate)
        atomic_write_json(roots["transport_security"] / "processed" / "summary.json", security_summary)

        telemetry_summary = {
            "status": "COMPLETE", "qualification_id": "tel", "network_evidence_id": "net",
            "loadgen_runtime_id": "runtime", "transport_security_id": "sec", "samples_per_host": 6,
            "interval_seconds": 1.0, "capabilities": {"ok": True}, "telemetry_contract_sha256": "c" * 64,
            "dut_estimated_power": {"available": True, "comparison_scope": "same-host-paired-only"},
            "loadgen_power": {"available": False},
        }
        atomic_write_json(roots["dual_host_telemetry"] / "processed" / "summary.json", telemetry_summary)

        conditions = []
        for workers, wp in [("single", 1), ("physical-core-count", 4)]:
            for profile in ["clas12-event-stream", "lcls-detector-frame", "hacc-multifile-dataset"]:
                for fraction in [0.5, 0.8]:
                    conditions.append({
                        "condition_id": f"{workers}-{profile}-{fraction}", "profile_id": profile,
                        "service_fraction": fraction, "worker_semantic": workers, "worker_processes": wp,
                        "target_goodput_mbps": 50 if fraction == 0.5 else 80,
                        "client": {"connections": 1, "max_concurrent_streams_per_connection": 1, "threads": 1},
                    })
        plan_identity = {
            "schema_version": 1, "plan_name": "x", "claim_scope": "frozen-workload-plan-no-performance-claim",
            "calibration_variant": "stock", "resolved_input_sha256": "d" * 64,
            "network": {"evidence_id": "net", "service_envelope_mbps": 100.0, "direction": "dut-to-loadgen", "service_target_fractions": [0.5, 0.8]},
            "transport": {"protocol": "http3-only", "tls_version": "1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256", "allow_0rtt": False},
            "environment": {"dut_physical_cores": 4, "loadgen_logical_cpus": 4},
            "scientific_corpus": {"corpus_id": "corpus", "hacc_planner_coverage": {}, "hacc_planner_coverage_is_not_full_dataset": True},
            "measurement": {"warmup_seconds": 5.0, "measurement_seconds": 20.0, "qlog": "disabled-by-default-performance-run", "h2load_json_quic_metrics": "required"},
            "conditions": sorted(conditions, key=lambda x: x["condition_id"]),
            "planner_policy": {"candidate_variant_bias_prohibited": True},
        }
        plan_id = "plan"
        plan = {**plan_identity, "plan_id": plan_id}
        plan["plan_sha256"] = _semantic_sha256(plan)
        planner_summary = {
            "status": "COMPLETE", "qualification_id": "planner", "calibration_variant": "stock", "probe_count": 40,
            "plan_id": plan_id, "plan_sha256": plan["plan_sha256"], "resolved_input_sha256": "d" * 64,
            "network_evidence_id": "net", "loadgen_runtime_id": "runtime", "scientific_corpus_id": "corpus",
            "transport_security_id": "sec", "telemetry_qualification_id": "tel",
        }
        atomic_write_json(roots["workload_planner"] / "processed" / "workload-plan.json", plan)
        atomic_write_json(roots["workload_planner"] / "processed" / "summary.json", planner_summary)
        (roots["workload_planner"] / "inputs").mkdir()
        import hashlib
        def fsha(path):
            return hashlib.sha256(path.read_bytes()).hexdigest()
        atomic_write_json(roots["workload_planner"] / "inputs" / "resolved-inputs.json", {
            "network_envelope_sha256": fsha(roots["network_evidence"] / "processed" / "network-envelope.json"),
            "loadgen_summary_sha256": fsha(roots["loadgen_runtime"] / "processed" / "summary.json"),
            "transport_security_sha256": fsha(roots["transport_security"] / "processed" / "security-gate.json"),
            "telemetry_summary_sha256": fsha(roots["dual_host_telemetry"] / "processed" / "summary.json"),
            "scientific_corpus_summary_sha256": fsha(roots["scientific_corpus"] / "processed" / "summary.json"),
        })

        definitions = {"transport_security": {"variants": {
            "stock": {"sha256": "e" * 64, "runtime_libraries": []},
            "ngi541-direct": {"sha256": "f" * 64, "runtime_libraries": [{"sha256": "0" * 64}]},
        }}}
        return tmp, {"roots": roots, "definitions": definitions}

    def test_network_validation_recomputes_envelope_sha(self):
        tmp, ctx = self._context()
        self.addCleanup(tmp.cleanup)
        result = validate_network(self._definition(), ctx)
        self.assertEqual(result["observation_count"], 3)
        envelope_path = ctx["roots"]["network_evidence"] / "processed" / "network-envelope.json"
        envelope = json.loads(envelope_path.read_text())
        envelope["service_envelope_mbps"] = 101.0
        atomic_write_json(envelope_path, envelope)
        with self.assertRaises(FrameworkError):
            validate_network(self._definition(), ctx)

    def test_security_validation_rejects_cipher_drift(self):
        tmp, ctx = self._context()
        self.addCleanup(tmp.cleanup)
        validate_security(self._definition(), ctx)
        gate_path = ctx["roots"]["transport_security"] / "processed" / "security-gate.json"
        gate = json.loads(gate_path.read_text())
        gate["cipher_suite"] = "TLS_AES_256_GCM_SHA384"
        atomic_write_json(gate_path, gate)
        with self.assertRaises(FrameworkError):
            validate_security(self._definition(), ctx)

    def test_plan_validation_requires_exact_twelve_condition_cross_product(self):
        tmp, ctx = self._context()
        self.addCleanup(tmp.cleanup)
        result = validate_plan(self._definition(), ctx)
        self.assertEqual(result["condition_count"], 12)
        plan_path = ctx["roots"]["workload_planner"] / "processed" / "workload-plan.json"
        plan = json.loads(plan_path.read_text())
        plan["conditions"] = plan["conditions"][:-1]
        plan.pop("plan_sha256")
        plan["plan_sha256"] = _semantic_sha256(plan)
        atomic_write_json(plan_path, plan)
        with self.assertRaises(FrameworkError):
            validate_plan(self._definition(), ctx)

    def test_final_manifest_freezes_r654_anti_bias_contract(self):
        tmp, ctx = self._context()
        self.addCleanup(tmp.cleanup)
        artifacts = {}
        for name in ctx["roots"]:
            artifacts[name] = {"artifact_id": name, "root": name, "summary_sha256": "1" * 64}
        resolved = {"resolved_input_sha256": "2" * 64, "artifacts": artifacts}
        manifest = build_final_manifest(self._definition(), resolved, ctx)
        contract = manifest["r6_5_4_execution_contract"]
        self.assertTrue(contract["same_frozen_plan_for_all_variants"])
        self.assertTrue(contract["adaptive_replanning_prohibited"])
        self.assertTrue(contract["candidate_variant_tuning_prohibited"])
        self.assertTrue(contract["metric_dependent_retry_prohibited"])
        self.assertTrue(contract["metric_dependent_outlier_deletion_prohibited"])
        self.assertEqual(contract["variants"], ["stock", "ngi541-direct"])

    def test_final_manifest_sha_is_semantic(self):
        tmp, ctx = self._context()
        self.addCleanup(tmp.cleanup)
        resolved = {"resolved_input_sha256": "2" * 64, "artifacts": {}}
        manifest = build_final_manifest(self._definition(), resolved, ctx)
        copy_manifest = copy.deepcopy(manifest)
        stated = copy_manifest.pop("freeze_sha256")
        self.assertEqual(stated, _semantic_sha256(copy_manifest))


if __name__ == "__main__":
    unittest.main()
