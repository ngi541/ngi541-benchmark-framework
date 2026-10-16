from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

BENCHMARK_DIR = Path(__file__).resolve().parents[2]
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))

from framework.environment import prepare_environment
from framework.experiment_identity import scientific_identity_sha256
from framework.ids import generate_portable_experiment_id
from framework.io_utils import FrameworkError, atomic_write_json
from framework.manifest import build_manifest
from framework.schedule import resolve_common_request
from framework.validation import validate_request


class PortableRuntimeTests(unittest.TestCase):
    def deployment(self):
        return {
            "schema_version": 1,
            "deployment": {
                "name": "local-single-host",
                "provider": "local",
                "topology_class": "single-host",
            },
            "nodes": {
                "host": {
                    "roles": ["dut", "loadgen"],
                    "access": {"mode": "local"},
                    "data_address": "auto",
                }
            },
        }

    def request(self):
        return {
            "workload": "http3",
            "deployment": self.deployment(),
            "variants": ["stock", "ngi541-direct"],
            "parameters": {"repetitions": 2},
        }

    def test_portable_request_validates(self):
        validate_request(self.request())

    def test_request_rejects_environment_and_deployment_together(self):
        request = self.request()
        request["environment"] = "local"
        with self.assertRaisesRegex(FrameworkError, "exactly one"):
            validate_request(request)

    def test_request_rejects_missing_placement(self):
        request = self.request()
        del request["deployment"]
        with self.assertRaisesRegex(FrameworkError, "exactly one"):
            validate_request(request)

    def test_resolved_request_preserves_deployment_not_environment(self):
        resolved = resolve_common_request(self.request())
        self.assertIn("deployment", resolved)
        self.assertNotIn("environment", resolved)

    def test_portable_id_is_provider_neutral(self):
        request = self.request()
        digest = scientific_identity_sha256(request)
        value = generate_portable_experiment_id(
            "http3",
            digest,
            now=datetime(2026, 10, 16, 1, 2, 3, tzinfo=timezone.utc),
            short_id="a31f92",
        )
        self.assertEqual(
            value,
            f"http3-{digest[:12]}-20261016T010203Z-a31f92",
        )
        self.assertNotIn("local", value)

    def test_local_portable_environment_realization(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "environment").mkdir()
            adapter = prepare_environment(root, deployment=self.deployment())
            self.assertEqual(adapter["schema_version"], 2)
            self.assertEqual(adapter["provider"], "local")
            self.assertEqual(adapter["nodes"]["host"]["roles"], ["dut", "loadgen"])
            for name in ("system.json", "cpu.json", "memory.json", "network.json"):
                self.assertTrue((root / "environment" / "nodes" / "host" / name).is_file())

    def test_nonlocal_provider_fails_until_adapter_exists(self):
        deployment = self.deployment()
        deployment["deployment"]["provider"] = "cloudlab"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "environment").mkdir()
            with self.assertRaisesRegex(FrameworkError, "not implemented yet"):
                prepare_environment(root, deployment=deployment)

    def test_portable_manifest_records_identity_and_deployment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "http3-0123456789ab-20261016T010203Z-a31f92"
            (root / "config").mkdir(parents=True)
            (root / "environment").mkdir()
            (root / "provenance").mkdir()

            request = self.request()
            atomic_write_json(root / "config" / "request.json", request)
            atomic_write_json(
                root / "state.json",
                {
                    "schema_version": 1,
                    "experiment_id": root.name,
                    "created_at": "2026-10-16T01:02:03Z",
                },
            )
            prepare_environment(root, deployment=request["deployment"])
            atomic_write_json(
                root / "provenance" / "sources.json",
                {
                    "sources": {
                        "ngi541-nginx": {
                            "commit": "a" * 40,
                            "describe": "test",
                            "remote": None,
                            "dirty": False,
                            "untracked_present": False,
                        }
                    }
                },
            )
            atomic_write_json(
                root / "provenance" / "dependencies.json",
                {"pinned_versions": {}},
            )

            manifest = build_manifest(root)
            self.assertNotIn("environment", manifest["experiment"])
            self.assertRegex(
                manifest["experiment"]["scientific_identity_sha256"],
                r"^[0-9a-f]{64}$",
            )
            self.assertEqual(manifest["deployment"]["provider"], "local")
            self.assertEqual(manifest["topology"]["nodes"]["host"]["roles"], ["dut", "loadgen"])


if __name__ == "__main__":
    unittest.main()
