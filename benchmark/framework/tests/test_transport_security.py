from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
import sys

TEST_DIR = Path(__file__).resolve().parent
BENCHMARK_DIR = TEST_DIR.parents[1]
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))

from framework.io_utils import FrameworkError
from framework.scientific_corpus import build_corpus_manifest
from framework.scientific_profiles import load_registry
from framework.transport_security import (
    curl_smoke_command,
    definition_sha256,
    h2load_smoke_command,
    nginx_config,
    parse_curl_writeout,
    parse_h2load_stdout,
    select_smoke_objects,
    validate_definition,
)

CONFIG = BENCHMARK_DIR / "configs" / "r6.5.3e-pi-mac-http3-security.json"
REGISTRY = BENCHMARK_DIR / "scientific-profiles"


def _definition() -> dict:
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def _manifests() -> dict:
    return {
        record.profile_id: build_corpus_manifest(record)
        for record in load_registry(REGISTRY)
    }


class TransportSecurityDefinitionTests(unittest.TestCase):
    def test_valid_definition(self):
        validate_definition(_definition())

    def test_definition_hash_is_semantic(self):
        value = _definition()
        clone = json.loads(json.dumps(value, indent=4))
        self.assertEqual(definition_sha256(value), definition_sha256(clone))

    def test_absolute_input_path_is_rejected(self):
        value = _definition()
        value["inputs"]["scientific_corpus_config"] = "/tmp/corpus.json"
        with self.assertRaises(FrameworkError):
            validate_definition(value)

    def test_transport_contract_is_strict(self):
        for field, bad in (
            ("protocol", "http2"),
            ("tls_version", "1.2"),
            ("verify_peer", False),
            ("allow_0rtt", True),
        ):
            value = _definition()
            value["transport"][field] = bad
            with self.subTest(field=field), self.assertRaises(FrameworkError):
                validate_definition(value)

    def test_exact_variants_are_required(self):
        value = _definition()
        del value["variants"]["stock"]
        with self.assertRaises(FrameworkError):
            validate_definition(value)

    def test_all_three_scientific_profiles_are_required_once(self):
        value = _definition()
        value["smoke"]["objects"] = value["smoke"]["objects"][:-1]
        with self.assertRaises(FrameworkError):
            validate_definition(value)


class ScientificSmokeSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.definition = _definition()
        cls.manifests = _manifests()
        cls.selected = select_smoke_objects(cls.definition, cls.manifests)

    def test_selection_has_one_object_per_scientific_profile(self):
        self.assertEqual(
            {row["profile_id"] for row in self.selected},
            {"clas12-event-stream", "lcls-detector-frame", "hacc-multifile-dataset"},
        )

    def test_stream_object_sizes_preserve_frozen_science_semantics(self):
        by_profile = {row["profile_id"]: row for row in self.selected}
        self.assertEqual(by_profile["clas12-event-stream"]["size_bytes"], 32768)
        self.assertEqual(by_profile["lcls-detector-frame"]["size_bytes"], 10000000)

    def test_hacc_bucket_selector_is_deterministic_and_bounded(self):
        a = select_smoke_objects(self.definition, self.manifests)
        b = select_smoke_objects(self.definition, self.manifests)
        self.assertEqual(a, b)
        hacc = next(row for row in a if row["profile_id"] == "hacc-multifile-dataset")
        self.assertGreaterEqual(hacc["size_bytes"], 1_000_000)
        self.assertLess(hacc["size_bytes"], 10_000_000)


class SecurityCommandContractTests(unittest.TestCase):
    def test_nginx_config_forces_tls13_cipher_and_disables_early_data(self):
        config = nginx_config(
            host="192.168.1.173",
            port=8443,
            workers=1,
            worker_connections=4096,
            cipher_suite="TLS_AES_128_GCM_SHA256",
        )
        self.assertIn("ssl_protocols TLSv1.3;", config)
        self.assertIn("ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256;", config)
        self.assertIn("ssl_early_data off;", config)
        self.assertIn("listen 192.168.1.173:8443 quic;", config)
        self.assertIn("http3 on;", config)

    def test_curl_gate_requires_http3_peer_verification_and_exact_tls13(self):
        command = curl_smoke_command(
            curl_binary="/runtime/curl",
            server_name="ngi541-dut.local",
            host="192.168.1.173",
            port=8443,
            cipher_suite="TLS_AES_128_GCM_SHA256",
            ca_path="/tmp/ca.crt",
            object_path="scientific/x.bin",
            output_path="/tmp/out.bin",
            timeout_seconds=30,
        )
        text = " ".join(command)
        self.assertIn("--http3-only", command)
        self.assertIn("--cacert", command)
        self.assertIn("--tlsv1.3", command)
        self.assertIn("--tls-max", command)
        self.assertIn("--tls13-ciphers", command)
        self.assertIn("--resolve", command)
        self.assertNotIn("--insecure", command)
        self.assertNotIn("--tls-earlydata", command)
        self.assertIn("TLS_AES_128_GCM_SHA256", text)

    def test_h2load_transport_smoke_is_single_connection_single_stream_h3(self):
        command = h2load_smoke_command(
            h2load_binary="/runtime/h2load",
            server_name="ngi541-dut.local",
            host="192.168.1.173",
            port=8443,
            cipher_suite="TLS_AES_128_GCM_SHA256",
            ca_path="/tmp/ca.crt",
            object_path="scientific/x.bin",
            json_path="/tmp/h2.json",
        )
        self.assertIn("--h3", command)
        self.assertIn("--tls13-ciphers", command)
        self.assertIn("SSL_CERT_FILE=/tmp/ca.crt", command)
        self.assertIn("-n", command)
        self.assertIn("-c", command)
        self.assertIn("-m", command)
        self.assertIn("-t", command)
        self.assertEqual(command[command.index("-n") + 1], "1")
        self.assertEqual(command[command.index("-c") + 1], "1")
        self.assertEqual(command[command.index("-m") + 1], "1")


class TransportResultParsingTests(unittest.TestCase):
    def test_parse_curl_writeout(self):
        result = parse_curl_writeout("3\t200\t0\t32768\n")
        self.assertEqual(result["http_version"], "3")
        self.assertEqual(result["response_code"], 200)
        self.assertEqual(result["ssl_verify_result"], 0)
        self.assertEqual(result["size_download"], 32768)

    def test_parse_h2load_http3_tls13_success(self):
        text = """starting benchmark...\nTLS Protocol: TLSv1.3\nCipher: TLS_AES_128_GCM_SHA256\nrequests: 1 total, 1 started, 1 done, 1 succeeded, 0 failed, 0 errored\n"""
        result = parse_h2load_stdout(text, cipher_suite="TLS_AES_128_GCM_SHA256")
        self.assertTrue(result["passed"])

    def test_parse_h2load_rejects_wrong_cipher(self):
        text = """TLS Protocol: TLSv1.3\nCipher: TLS_AES_256_GCM_SHA384\nrequests: 1 total, 1 started, 1 done, 1 succeeded, 0 failed, 0 errored\n"""
        result = parse_h2load_stdout(text, cipher_suite="TLS_AES_128_GCM_SHA256")
        self.assertFalse(result["passed"])


if __name__ == "__main__":
    unittest.main()
