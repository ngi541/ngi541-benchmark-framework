from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


BENCHMARK_DIR = Path(__file__).resolve().parents[2]
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))

from framework.deployment import (
    deployment_definition_sha256,
    deployment_role_map,
    load_deployment_definition,
    normalize_deployment_definition,
)
from framework.io_utils import FrameworkError


ROOT = BENCHMARK_DIR.parent
LOCAL = (
    ROOT
    / "environments"
    / "local"
    / "single-host.json"
)


class DeploymentContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.definition = {
            "schema_version": 1,
            "deployment": {
                "name":
                    "local-single-host",
                "provider":
                    "local",
                "topology_class":
                    "single-host",
            },
            "nodes": {
                "host": {
                    "roles": [
                        "dut",
                        "loadgen",
                    ],
                    "access": {
                        "mode": "local",
                    },
                    "data_address":
                        "auto",
                },
            },
        }

    def test_tracked_local_descriptor(self):
        value = load_deployment_definition(
            LOCAL
        )

        self.assertEqual(
            value["deployment"]["provider"],
            "local",
        )
        self.assertEqual(
            deployment_role_map(value),
            {
                "dut": "host",
                "loadgen": "host",
            },
        )

    def test_same_node_may_hold_both_roles(self):
        value = (
            normalize_deployment_definition(
                self.definition
            )
        )

        self.assertEqual(
            value["nodes"]["host"]["roles"],
            [
                "dut",
                "loadgen",
            ],
        )

    def test_duplicate_canonical_role_fails(self):
        value = copy.deepcopy(
            self.definition
        )
        value["nodes"]["client"] = {
            "roles": ["loadgen"],
            "access": {
                "mode": "local",
            },
        }

        with self.assertRaisesRegex(
            FrameworkError,
            "assigned exactly once",
        ):
            normalize_deployment_definition(
                value
            )

    def test_missing_role_fails(self):
        value = copy.deepcopy(
            self.definition
        )
        value["nodes"]["host"]["roles"] = [
            "dut",
        ]

        with self.assertRaisesRegex(
            FrameworkError,
            "must assign canonical role",
        ):
            normalize_deployment_definition(
                value
            )

    def test_ssh_requires_target(self):
        value = copy.deepcopy(
            self.definition
        )
        value["nodes"]["host"]["access"] = {
            "mode": "ssh",
        }

        with self.assertRaisesRegex(
            FrameworkError,
            "required for ssh access",
        ):
            normalize_deployment_definition(
                value
            )

    def test_provider_is_part_of_deployment_provenance(self):
        one = copy.deepcopy(
            self.definition
        )
        two = copy.deepcopy(
            self.definition
        )
        two["deployment"]["provider"] = (
            "cloudlab"
        )

        self.assertNotEqual(
            deployment_definition_sha256(
                one
            ),
            deployment_definition_sha256(
                two
            ),
        )


if __name__ == "__main__":
    unittest.main()
