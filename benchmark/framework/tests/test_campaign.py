from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


BENCHMARK_DIR = Path(__file__).resolve().parents[2]
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))

from framework.campaign import (
    campaign_definition_sha256,
    discover_campaign_instances,
    next_campaign_stage,
    request_from_campaign,
)
from framework.io_utils import atomic_write_json
from framework.lifecycle import initial_state
from framework.schedule import build_schedule, resolve_common_request
from framework.validation import validate_request
from workloads.http3.adapter import resolve_http3_config


class ExplicitConditionTests(unittest.TestCase):
    def _definition(self):
        return {
            "schema_version": 1,
            "campaign": {"name": "c2.2-local-http3"},
            "experiment": {
                "workload": "http3",
                "environment": "local",
                "variants": ["stock", "ngi541-direct"],
                "repetitions": 10,
                "comparison": {"mode": "paired-balanced"},
                "parameters": {
                    "requests_per_client": 5000,
                    "warmup_requests_per_client": 50,
                },
                "conditions": [
                    {"payload_bytes": 16384, "workers": 1, "clients": 1},
                    {"payload_bytes": 16384, "workers": 2, "clients": 8},
                    {"payload_bytes": 1024, "workers": 2, "clients": 16},
                ],
            },
            "preparation": {
                "binaries": {
                    "stock": {"path": "build/stock", "sha256": "0" * 64},
                    "ngi541-direct": {"path": "build/direct", "sha256": "1" * 64},
                },
                "runtime_libraries": {},
            },
        }

    def test_explicit_conditions_do_not_form_cartesian_product(self):
        request = request_from_campaign(self._definition())
        validate_request(request)
        resolved = resolve_common_request(request)
        resolved = resolve_http3_config(request, resolved)
        schedule = build_schedule(
            "http3-local-20261009T050000Z-aabbcc",
            resolved,
        )
        self.assertEqual(len(schedule["runs"]), 3 * 10 * 2)

        seen = []
        for run in schedule["runs"]:
            key = (
                run["parameters"]["payload_bytes"],
                run["parameters"]["workers"],
                run["parameters"]["clients"],
            )
            if key not in seen:
                seen.append(key)
        self.assertEqual(
            seen,
            [
                (16384, 1, 1),
                (16384, 2, 8),
                (1024, 2, 16),
            ],
        )

    def test_each_even_repetition_condition_is_balanced(self):
        request = request_from_campaign(self._definition())
        resolved = resolve_http3_config(
            request,
            resolve_common_request(request),
        )
        schedule = build_schedule(
            "http3-local-20261009T050000Z-aabbcc",
            resolved,
        )
        first_condition = schedule["runs"][:20]
        first_variants = [
            first_condition[index]["variant"]
            for index in range(0, len(first_condition), 2)
        ]
        self.assertEqual(first_variants.count("stock"), 5)
        self.assertEqual(first_variants.count("ngi541-direct"), 5)

    def test_http3_explicit_condition_requires_axes(self):
        definition = self._definition()
        del definition["experiment"]["conditions"][0]["clients"]
        request = request_from_campaign(definition)
        common = resolve_common_request(request)
        with self.assertRaises(Exception):
            resolve_http3_config(request, common)




class ControlledScheduleTests(unittest.TestCase):
    def _resolved(self):
        request = {
            "workload": "http3",
            "environment": "local",
            "variants": ["stock", "ngi541-direct"],
            "parameters": {
                "repetitions": 4,
                "requests_per_client": 100,
                "warmup_requests_per_client": 5,
            },
            "conditions": [
                {"payload_bytes": 16384, "workers": 1, "clients": 1},
                {"payload_bytes": 16384, "workers": 2, "clients": 16},
                {"payload_bytes": 16384, "workers": 4, "clients": 32},
            ],
            "comparison": {"mode": "paired-balanced"},
            "scheduling": {
                "condition_order": "rotating-rounds",
                "variant_order": "balanced-by-condition-round",
            },
        }
        resolved = resolve_common_request(request)
        return resolve_http3_config(request, resolved)

    def test_rotating_rounds_are_deterministic(self):
        schedule = build_schedule(
            "http3-local-20261010T050000Z-aabbcc",
            self._resolved(),
        )
        self.assertEqual(len(schedule["runs"]), 24)
        pairs = [schedule["runs"][i] for i in range(0, 24, 2)]
        rounds = {}
        for run in pairs:
            rounds.setdefault(run["repetition_round"], []).append(run["condition_id"])
        self.assertEqual(rounds[1], ["condition-0001", "condition-0002", "condition-0003"])
        self.assertEqual(rounds[2], ["condition-0002", "condition-0003", "condition-0001"])
        self.assertEqual(rounds[3], ["condition-0003", "condition-0001", "condition-0002"])
        self.assertEqual(rounds[4], ["condition-0001", "condition-0002", "condition-0003"])

    def test_each_condition_gets_two_ab_and_two_ba_pairs(self):
        schedule = build_schedule(
            "http3-local-20261010T050000Z-aabbcc",
            self._resolved(),
        )
        first_by_condition = {}
        for i in range(0, len(schedule["runs"]), 2):
            run = schedule["runs"][i]
            first_by_condition.setdefault(run["condition_id"], []).append(run["variant"])
        for values in first_by_condition.values():
            self.assertEqual(values.count("stock"), 2)
            self.assertEqual(values.count("ngi541-direct"), 2)

class CampaignIdentityTests(unittest.TestCase):
    def test_definition_hash_is_semantic_and_deterministic(self):
        one = {"b": 2, "a": {"y": 2, "x": 1}}
        two = {"a": {"x": 1, "y": 2}, "b": 2}
        self.assertEqual(
            campaign_definition_sha256(one),
            campaign_definition_sha256(two),
        )

    def test_matching_incomplete_campaign_is_discovered(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exp = root / "http3-local-20261009T050000Z-aabbcc"
            (exp / "config").mkdir(parents=True)
            atomic_write_json(
                exp / "config" / "campaign.json",
                {
                    "schema_version": 1,
                    "campaign_name": "c2.2-local-http3",
                    "definition_sha256": "a" * 64,
                    "definition": {},
                },
            )
            state = initial_state(exp.name)
            state["state"] = "RUNNING"
            atomic_write_json(exp / "state.json", state)

            found = discover_campaign_instances(
                root,
                campaign_name="c2.2-local-http3",
                definition_sha256="a" * 64,
            )
            self.assertEqual(found["exact_incomplete"], [exp])


class CampaignResumeStageTests(unittest.TestCase):
    def test_aborted_execution_resumes_at_execute(self):
        with tempfile.TemporaryDirectory() as tmp:
            exp = Path(tmp)
            atomic_write_json(
                exp / "state.json",
                {
                    **initial_state("http3-local-20261009T050000Z-aabbcc"),
                    "state": "ABORTED",
                },
            )
            self.assertEqual(next_campaign_stage(exp), "execute")

    def test_complete_campaign_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            exp = Path(tmp)
            atomic_write_json(
                exp / "state.json",
                {
                    **initial_state("http3-local-20261009T050000Z-aabbcc"),
                    "state": "COMPLETE",
                },
            )
            self.assertEqual(next_campaign_stage(exp), "complete")


if __name__ == "__main__":
    unittest.main()
