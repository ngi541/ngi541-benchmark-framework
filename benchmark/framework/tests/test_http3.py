from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path


BENCHMARK_DIR = Path(__file__).resolve().parents[2]
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))

from framework.io_utils import FrameworkError
from workloads.http3.adapter import (
    _nginx_config,
    _stage_shared_artifacts,
    _write_payload,
    resolve_http3_config,
)


class Http3ResolveTests(unittest.TestCase):
    def test_defaults_are_resolved(self):
        request = {
            "workload": "http3",
            "environment": "local",
            "variants": ["stock", "ngi541-direct"],
            "parameters": {"repetitions": 2},
        }
        common = {
            "workload": "http3",
            "environment": "local",
            "variants": ["stock", "ngi541-direct"],
            "parameters": {"repetitions": 2},
            "comparison": {
                "mode": "paired-balanced",
                "random_seed": None,
            },
        }

        resolved = resolve_http3_config(request, common)
        params = resolved["parameters"]

        self.assertEqual(params["payload_bytes"], [16384])
        self.assertEqual(params["workers"], [1])
        self.assertEqual(params["clients"], [1])
        self.assertEqual(params["requests_per_client"], 5000)
        self.assertEqual(params["warmup_requests_per_client"], 50)
        self.assertEqual(
            params["cipher_suite"],
            "TLS_AES_128_GCM_SHA256",
        )

    def test_explicit_conditions_keep_axes_out_of_common_parameters(self):
        request = {
            "workload": "http3",
            "environment": "local",
            "variants": ["stock", "ngi541-direct"],
            "parameters": {"repetitions": 2},
            "conditions": [
                {"payload_bytes": 16384, "workers": 2, "clients": 16}
            ],
        }
        common = {
            "workload": "http3",
            "environment": "local",
            "variants": ["stock", "ngi541-direct"],
            "parameters": {"repetitions": 2},
            "conditions": [
                {"payload_bytes": 16384, "workers": 2, "clients": 16}
            ],
            "comparison": {
                "mode": "paired-balanced",
                "random_seed": None,
            },
        }

        resolved = resolve_http3_config(request, common)
        self.assertNotIn("payload_bytes", resolved["parameters"])
        self.assertEqual(resolved["conditions"][0]["clients"], 16)

    def test_invalid_axis_rejected(self):
        request = {
            "workload": "http3",
            "environment": "local",
            "variants": ["stock"],
            "parameters": {},
        }
        common = {
            "workload": "http3",
            "environment": "local",
            "variants": ["stock"],
            "parameters": {
                "repetitions": 1,
                "clients": [0],
            },
            "comparison": {
                "mode": "single",
                "random_seed": None,
            },
        }

        with self.assertRaises(FrameworkError):
            resolve_http3_config(request, common)


class Http3PayloadTests(unittest.TestCase):
    def test_historical_1k_payload_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "1024.bin"
            digest = _write_payload(path, 1024)
            self.assertEqual(
                digest,
                "5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
            )

    def test_historical_16k_payload_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "16384.bin"
            digest = _write_payload(path, 16384)
            self.assertEqual(
                digest,
                "4fe7b59af6de3b665b67788cc2f99892ab827efae3a467342b3bb4e3bc8e5bfe",
            )


class Http3ConfigTests(unittest.TestCase):
    def test_multiworker_uses_reuseport(self):
        config = _nginx_config(
            workers=2,
            host="127.0.0.1",
            port=8443,
            worker_connections=4096,
            keepalive_requests=20000,
        )
        self.assertIn(
            "listen 127.0.0.1:8443 quic reuseport;",
            config,
        )

    def test_single_worker_does_not_use_reuseport(self):
        config = _nginx_config(
            workers=1,
            host="127.0.0.1",
            port=8443,
            worker_connections=4096,
            keepalive_requests=20000,
        )
        self.assertIn(
            "listen 127.0.0.1:8443 quic;",
            config,
        )
        self.assertNotIn("quic reuseport", config)




class Http3SharedArtifactTests(unittest.TestCase):
    def test_runtime_artifacts_are_staged_once_per_variant(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exp = root / "experiments" / "http3-local-20261010T050000Z-aabbcc"
            exp.mkdir(parents=True)
            build = root / "build"
            build.mkdir()
            stock = build / "stock-nginx"
            direct = build / "direct-nginx"
            library = build / "libngi541_engine.0.1.dylib"
            stock.write_bytes(b"stock")
            direct.write_bytes(b"direct")
            library.write_bytes(b"library")

            def record(name, path):
                return {
                    "name": name,
                    "basename": path.name,
                    "location": str(path.relative_to(root)),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "size_bytes": path.stat().st_size,
                }

            bindings = {
                "variants": {
                    "stock": {"binary": record("stock", stock), "libraries": []},
                    "ngi541-direct": {
                        "binary": record("ngi541-direct", direct),
                        "libraries": [record("ngi541-direct-library", library)],
                    },
                }
            }
            resolved = {
                "variants": ["stock", "ngi541-direct"],
                "measurement_control": {
                    "runtime": {
                        "stage_artifacts_once": True,
                        "cleanup_attempt_runtime": True,
                    }
                },
            }
            manifest = _stage_shared_artifacts(exp, resolved, bindings)
            self.assertIsNotNone(manifest)
            self.assertTrue((exp / "execution/artifacts/stock/bin/nginx").is_file())
            self.assertTrue((exp / "execution/artifacts/ngi541-direct/bin/nginx").is_file())
            self.assertTrue((exp / "execution/artifacts/ngi541-direct/lib/libngi541_engine.0.1.dylib").is_file())
            self.assertEqual(
                len(list((exp / "execution/artifacts").rglob("nginx"))),
                2,
            )


class Http3TlsPathTests(unittest.TestCase):
    def test_tls_paths_are_relative_to_config_directory(self):
        config = _nginx_config(
            workers=1, host="127.0.0.1", port=8443,
            worker_connections=4096, keepalive_requests=20000,
        )
        self.assertIn("ssl_certificate server.crt;", config)
        self.assertIn("ssl_certificate_key server.key;", config)
        self.assertNotIn("ssl_certificate conf/server.crt;", config)
        self.assertNotIn("ssl_certificate_key conf/server.key;", config)


if __name__ == "__main__":
    unittest.main()
