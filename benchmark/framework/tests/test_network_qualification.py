from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

FRAMEWORK_ROOT = Path(__file__).resolve().parents[2]
if str(FRAMEWORK_ROOT) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK_ROOT))

from framework.network_qualification import (
    definition_sha256,
    parse_darwin_route,
    parse_ethtool,
    parse_iperf_tcp,
    parse_iperf_udp,
    parse_linux_route_get,
    parse_networksetup_ports,
    parse_os_release,
    _bullseye_archive_install_command,
    _resolve_remote_binary,
    CommandResult,
    SSHSession,
    parse_ping_summary,
    validate_network_qualification_definition,
)
from framework.io_utils import FrameworkError


class NetworkQualificationConfigTests(unittest.TestCase):
    def _definition(self):
        return {
            "schema_version": 1,
            "qualification": {"name": "r6.5.1-pi-mac-network"},
            "local": {"role": "dut", "provider": "local", "data_address": "auto"},
            "remote": {
                "role": "loadgen",
                "provider": "linux-ssh",
                "ssh_target": "pi@192.168.1.65",
                "data_address": "192.168.1.65",
            },
            "tests": {
                "ping": {"enabled": True, "count": 10},
                "tcp": {"enabled": True, "duration_seconds": 10, "parallel_streams": [1, 4]},
                "udp": {"enabled": True, "duration_seconds": 5, "datagram_bytes": 1200, "rates_mbps": [50, 100]},
            },
        }

    def test_definition_hash_is_semantic(self):
        a = self._definition()
        b = json.loads(json.dumps(a, indent=4))
        self.assertEqual(definition_sha256(a), definition_sha256(b))

    def test_valid_definition(self):
        validate_network_qualification_definition(self._definition())

    def test_udp_requires_rates(self):
        definition = self._definition()
        definition["tests"]["udp"]["rates_mbps"] = []
        with self.assertRaises(FrameworkError):
            validate_network_qualification_definition(definition)




class NetworkBootstrapTests(unittest.TestCase):
    def test_ssh_session_limits_agent_identities(self):
        session = SSHSession("pi@example.invalid")
        self.assertIn("IdentitiesOnly=yes", session._base())

    def test_parse_bullseye_os_release(self):
        parsed = parse_os_release(
            'PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"\n'
            'VERSION_ID="11"\n'
            'VERSION_CODENAME=bullseye\n'
        )
        self.assertEqual(parsed["VERSION_ID"], "11")
        self.assertEqual(parsed["VERSION_CODENAME"], "bullseye")

    def test_bullseye_archive_bootstrap_is_isolated(self):
        command = _bullseye_archive_install_command()
        self.assertIn("archive.debian.org/debian", command)
        self.assertIn("Dir::Etc::sourcelist", command)
        self.assertIn("Dir::Etc::sourceparts=-", command)
        self.assertIn("Acquire::Check-Valid-Until=false", command)
        self.assertNotIn("/etc/apt/sources.list", command)



class RemoteBinaryResolutionTests(unittest.TestCase):
    class FakeSSH:
        def __init__(self):
            self.calls = []

        def run(self, argv, *, check=False, timeout=None):
            self.calls.append(list(argv))
            if argv[:2] == ["sh", "-lc"]:
                return CommandResult(argv=list(argv), returncode=0, stdout="", stderr="", started_at="", finished_at="", elapsed_ns=0)
            if argv == ["test", "-x", "/usr/sbin/ethtool"]:
                return CommandResult(argv=list(argv), returncode=0, stdout="", stderr="", started_at="", finished_at="", elapsed_ns=0)
            return CommandResult(argv=list(argv), returncode=1, stdout="", stderr="", started_at="", finished_at="", elapsed_ns=0)

    def test_remote_binary_uses_usr_sbin_fallback_when_noninteractive_path_omits_it(self):
        ssh = self.FakeSSH()
        path = _resolve_remote_binary(ssh, "ethtool", ["/usr/sbin/ethtool", "/sbin/ethtool"])
        self.assertEqual(path, "/usr/sbin/ethtool")

class NetworkInventoryParsingTests(unittest.TestCase):
    def test_parse_darwin_route(self):
        parsed = parse_darwin_route(
            "route to: 192.168.1.65\n"
            "gateway: 192.168.1.1\n"
            "interface: en0\n"
        )
        self.assertEqual(parsed["interface"], "en0")
        self.assertEqual(parsed["gateway"], "192.168.1.1")

    def test_parse_linux_route(self):
        parsed = parse_linux_route_get(
            "192.168.1.173 via 192.168.1.1 dev eth0 src 192.168.1.65 uid 1000\n"
        )
        self.assertEqual(parsed["interface"], "eth0")
        self.assertEqual(parsed["source"], "192.168.1.65")
        self.assertEqual(parsed["gateway"], "192.168.1.1")

    def test_parse_networksetup_ports(self):
        parsed = parse_networksetup_ports(
            "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb\n\n"
            "Hardware Port: Thunderbolt 1\nDevice: en1\nEthernet Address: cc:dd\n"
        )
        self.assertEqual(parsed["en0"], "Wi-Fi")
        self.assertEqual(parsed["en1"], "Thunderbolt 1")

    def test_parse_ethtool(self):
        parsed = parse_ethtool(
            "Speed: 1000Mb/s\nDuplex: Full\nLink detected: yes\n"
        )
        self.assertEqual(parsed["speed_mbps"], 1000)
        self.assertEqual(parsed["duplex"], "full")
        self.assertTrue(parsed["link_detected"])


class NetworkMetricParsingTests(unittest.TestCase):
    def test_parse_darwin_ping(self):
        parsed = parse_ping_summary(
            "10 packets transmitted, 10 packets received, 0.0% packet loss\n"
            "round-trip min/avg/max/stddev = 1.000/2.000/4.000/0.500 ms\n"
        )
        self.assertEqual(parsed["packet_loss_percent"], 0.0)
        self.assertEqual(parsed["rtt_avg_ms"], 2.0)

    def test_parse_linux_ping(self):
        parsed = parse_ping_summary(
            "10 packets transmitted, 9 received, 10% packet loss, time 1000ms\n"
            "rtt min/avg/max/mdev = 1.100/2.200/3.300/0.400 ms\n"
        )
        self.assertEqual(parsed["received"], 9)
        self.assertEqual(parsed["rtt_deviation_ms"], 0.4)

    def test_parse_iperf_tcp(self):
        parsed = parse_iperf_tcp(json.dumps({
            "end": {
                "sum_sent": {"bits_per_second": 940000000.0, "retransmits": 2},
                "sum_received": {"bits_per_second": 935000000.0, "seconds": 10.0},
            }
        }))
        self.assertAlmostEqual(parsed["throughput_mbps"], 935.0)
        self.assertEqual(parsed["retransmits"], 2)

    def test_parse_iperf_udp(self):
        parsed = parse_iperf_udp(json.dumps({
            "end": {
                "sum": {
                    "bits_per_second": 499000000.0,
                    "lost_percent": 0.02,
                    "jitter_ms": 0.11,
                    "packets": 1000,
                    "lost_packets": 1,
                }
            }
        }))
        self.assertAlmostEqual(parsed["throughput_mbps"], 499.0)
        self.assertAlmostEqual(parsed["lost_percent"], 0.02)
        self.assertAlmostEqual(parsed["jitter_ms"], 0.11)


if __name__ == "__main__":
    unittest.main()
