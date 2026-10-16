from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


BENCHMARK_DIR = Path(__file__).resolve().parents[2]
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))

from framework.experiment_identity import (
    scientific_definition_id,
    scientific_identity_projection,
    scientific_identity_sha256,
)
from framework.io_utils import FrameworkError


class ScientificIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.request = {
            "workload": "http3",
            "environment": "local",
            "deployment": {
                "provider": "local",
            },
            "alias": "developer-run",
            "variants": [
                "stock",
                "ngi541-direct",
            ],
            "parameters": {
                "workers": 4,
                "repetitions": 4,
                "measurement_seconds": 20,
            },
            "comparison": {
                "mode":
                    "paired-balanced",
            },
            "conditions": [
                {
                    "profile": "clas12",
                    "target_goodput_mbps": 50,
                },
            ],
        }

    def test_projection_excludes_deployment_metadata(self):
        identity = (
            scientific_identity_projection(
                self.request
            )
        )

        self.assertNotIn(
            "environment",
            identity,
        )
        self.assertNotIn(
            "deployment",
            identity,
        )
        self.assertNotIn(
            "alias",
            identity,
        )

    def test_provider_change_preserves_scientific_identity(self):
        local = copy.deepcopy(
            self.request
        )
        cloudlab = copy.deepcopy(
            self.request
        )

        cloudlab["environment"] = (
            "cloudlab"
        )
        cloudlab["deployment"] = {
            "provider": "cloudlab",
        }
        cloudlab["alias"] = (
            "cloudlab-execution"
        )

        self.assertEqual(
            scientific_identity_sha256(
                local
            ),
            scientific_identity_sha256(
                cloudlab
            ),
        )
        self.assertEqual(
            scientific_definition_id(
                local
            ),
            scientific_definition_id(
                cloudlab
            ),
        )

    def test_scientific_parameter_change_changes_identity(self):
        changed = copy.deepcopy(
            self.request
        )
        changed["parameters"][
            "measurement_seconds"
        ] = 30

        self.assertNotEqual(
            scientific_identity_sha256(
                self.request
            ),
            scientific_identity_sha256(
                changed
            ),
        )

    def test_definition_id_is_host_neutral(self):
        value = scientific_definition_id(
            self.request
        )

        self.assertRegex(
            value,
            r"^http3-[0-9a-f]{12}$",
        )

        for forbidden in (
            "local",
            "cloudlab",
            "pi",
            "mac",
            "raspberry",
        ):
            self.assertNotIn(
                forbidden,
                value,
            )

    def test_unknown_request_field_fails_closed(self):
        value = copy.deepcopy(
            self.request
        )
        value["mystery"] = 1

        with self.assertRaisesRegex(
            FrameworkError,
            "cannot classify",
        ):
            scientific_identity_projection(
                value
            )


if __name__ == "__main__":
    unittest.main()
