from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

BENCHMARK_DIR = Path(__file__).resolve().parents[2]
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))

from framework.paired_protocol import (
    load_paired_protocol,
    paired_protocol_sha256,
)

ROOT = BENCHMARK_DIR.parent
PROTOCOL = ROOT / "benchmark" / "protocols" / "http3-paired-r6.5.4.5.json"
HISTORICAL = ROOT / "benchmark" / "configs" / "r6.5.4.5-pi-mac-paired-scientific-execution.json"


class PairedProtocolTests(unittest.TestCase):
    def test_canonical_protocol_is_provider_independent(self):
        protocol = load_paired_protocol(PROTOCOL)
        encoded = json.dumps(protocol, sort_keys=True).lower()
        for forbidden in ("pi-mac", "cloudlab", "raspberry", "darwin-local", "linux-ssh"):
            self.assertNotIn(forbidden, encoded)
        self.assertRegex(paired_protocol_sha256(protocol), r"^[0-9a-f]{64}$")

    def test_protocol_matches_historical_r6545_methodology(self):
        protocol = load_paired_protocol(PROTOCOL)
        historical = json.loads(HISTORICAL.read_text(encoding="utf-8"))
        self.assertEqual(protocol["execution"], historical["execution"])
        self.assertEqual(protocol["analysis"], historical["analysis"])
        self.assertEqual(protocol["protocol"]["claim_scope"], historical["experiment"]["claim_scope"])


if __name__ == "__main__":
    unittest.main()
