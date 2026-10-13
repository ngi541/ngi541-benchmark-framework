from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from framework.dual_host_telemetry import (
    REMOTE_SAMPLER,
    definition_sha256,
    integrate_power_energy_j,
    load_definition,
    parse_cpu_time,
    parse_darwin_netstat,
    parse_powermetrics_line,
    parse_ps_process_tree,
    validate_definition,
)
from framework.io_utils import FrameworkError


ROOT = Path(__file__).resolve().parents[3]
CONFIG = ROOT / "benchmark" / "configs" / "r6.5.3f-pi-mac-dual-host-telemetry.json"


class DualHostTelemetryDefinitionTests(unittest.TestCase):
    def setUp(self):
        self.definition = json.loads(CONFIG.read_text(encoding="utf-8"))

    def test_valid_definition(self):
        validate_definition(self.definition)
        self.assertEqual(load_definition(CONFIG), self.definition)

    def test_definition_hash_is_semantic(self):
        first = definition_sha256(self.definition)
        reordered = json.loads(json.dumps(self.definition, sort_keys=True))
        self.assertEqual(first, definition_sha256(reordered))

    def test_requires_at_least_four_samples(self):
        value = copy.deepcopy(self.definition)
        value["sampling"]["sample_count"] = 3
        with self.assertRaises(FrameworkError):
            validate_definition(value)

    def test_input_paths_must_be_relative(self):
        value = copy.deepcopy(self.definition)
        value["inputs"]["network_evidence_config"] = "/tmp/network.json"
        with self.assertRaises(FrameworkError):
            validate_definition(value)

    def test_dut_requires_no_throttling(self):
        value = copy.deepcopy(self.definition)
        value["dut"]["require_no_throttling"] = False
        with self.assertRaises(FrameworkError):
            validate_definition(value)

    def test_power_comparison_is_same_host_only(self):
        value = copy.deepcopy(self.definition)
        value["dut"]["power"]["comparison_scope"] = "cross-device"
        with self.assertRaises(FrameworkError):
            validate_definition(value)

    def test_raspberry_pi_power_never_claims_inferred_watts(self):
        self.assertEqual(
            self.definition["loadgen"]["power"]["mode"],
            "unavailable-without-external-sensor",
        )
        self.assertIn("unavailable-no-onboard-current-sensor", REMOTE_SAMPLER)
        self.assertNotIn("measure_volts", REMOTE_SAMPLER)

    def test_raspberry_pi_temperature_uses_sysfs_symlink_safe_paths(self):
        self.assertIn("glob.glob('/sys/class/thermal/thermal_zone*/temp')", REMOTE_SAMPLER)
        self.assertIn("glob.glob('/sys/class/hwmon/hwmon*/temp*_input')", REMOTE_SAMPLER)
        self.assertNotIn("os.walk('/sys/class/thermal')", REMOTE_SAMPLER)

    def test_raspberry_pi_temperature_has_vcgencmd_fallback(self):
        self.assertIn("[v,'measure_temp']", REMOTE_SAMPLER)


class PowermetricsParsingTests(unittest.TestCase):
    def test_parse_intel_package_power(self):
        row = parse_powermetrics_line(
            "Intel energy model derived package power (CPUs+GT+SA): 7.25W"
        )
        self.assertEqual(row["package_power_w_estimate"], 7.25)
        self.assertEqual(row["package_power_source"], "powermetrics-intel-energy-model")

    def test_parse_apple_silicon_package_power_mw(self):
        row = parse_powermetrics_line("Package Power: 7348 mW")
        self.assertAlmostEqual(row["package_power_w_estimate"], 7.348)

    def test_parse_temperature_frequency_and_pressure(self):
        self.assertEqual(parse_powermetrics_line("CPU die temperature: 46.96 C")["temperature_c"], 46.96)
        self.assertEqual(parse_powermetrics_line("Current pressure level: Nominal")["thermal_pressure"], "nominal")
        self.assertEqual(
            parse_powermetrics_line("System Average frequency as fraction of nominal: 59.63% (1550.27 Mhz)")["average_frequency_mhz"],
            1550.27,
        )


class ProcessAndNetworkParsingTests(unittest.TestCase):
    def test_cpu_time_parser(self):
        self.assertEqual(parse_cpu_time("01:02"), 62.0)
        self.assertEqual(parse_cpu_time("01:02:03"), 3723.0)
        self.assertEqual(parse_cpu_time("2-01:00:00"), 176400.0)

    def test_cpu_time_parser_accepts_darwin_fractional_seconds(self):
        self.assertEqual(parse_cpu_time("0:00.00"), 0.0)
        self.assertAlmostEqual(parse_cpu_time("1:02.34"), 62.34)
        self.assertAlmostEqual(parse_cpu_time("01:02:03.45"), 3723.45)

    def test_process_tree_accepts_darwin_fractional_time(self):
        text = """
100 1 0:00.00 100 sleep
101 100 0:00.02 200 child
"""
        row = parse_ps_process_tree(text, 100)
        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual(row["process_count"], 2)
        self.assertAlmostEqual(row["cpu_seconds"], 0.02)
        self.assertEqual(row["rss_bytes"], 300 * 1024)

    def test_process_tree_aggregates_descendants(self):
        text = """
100 1 00:01 100 root
101 100 00:02 200 worker-a
102 100 00:03 300 worker-b
999 1 00:50 999 other
"""
        row = parse_ps_process_tree(text, 100)
        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual(row["process_count"], 3)
        self.assertEqual(row["cpu_seconds"], 6.0)
        self.assertEqual(row["rss_bytes"], 600 * 1024)

    def test_darwin_netstat_parser_uses_interface_counters(self):
        text = """Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
en0 1500 <Link#4> aa:bb 100 1 10000 200 2 20000 0
en0 1500 192.168.1 192.168.1.2 100 1 10000 200 2 20000 0
"""
        row = parse_darwin_netstat(text, "en0")
        self.assertEqual(row["rx_bytes"], 10000)
        self.assertEqual(row["tx_bytes"], 20000)
        self.assertEqual(row["rx_errors"], 1)
        self.assertEqual(row["tx_errors"], 2)


class PowerIntegrationTests(unittest.TestCase):
    def test_energy_integrates_estimated_package_power(self):
        samples = [
            {"monotonic_ns": 0, "power": {"package_power_w_estimate": 10.0}},
            {"monotonic_ns": 1_000_000_000, "power": {"package_power_w_estimate": 20.0}},
            {"monotonic_ns": 2_000_000_000, "power": {"package_power_w_estimate": 10.0}},
        ]
        self.assertAlmostEqual(integrate_power_energy_j(samples), 30.0)

    def test_energy_is_unavailable_with_one_power_sample(self):
        self.assertIsNone(
            integrate_power_energy_j([
                {"monotonic_ns": 0, "power": {"package_power_w_estimate": 10.0}}
            ])
        )


if __name__ == "__main__":
    unittest.main()
