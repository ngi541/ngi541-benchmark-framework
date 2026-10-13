from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

TEST_DIR = Path(__file__).resolve().parent
BENCHMARK_DIR = TEST_DIR.parents[1]
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))

from framework.io_utils import FrameworkError
from framework.network_evidence import (
    Observation,
    derive_network_envelope,
    discover_observations,
    definition_sha256,
    run_network_evidence,
    select_observations,
    topology_fingerprint,
    validate_definition,
)
from framework.network_qualification import definition_sha256 as network_definition_sha256


CONFIG = BENCHMARK_DIR / "configs" / "r6.5.3c-pi-mac-network-evidence.json"
NETWORK_CONFIG = BENCHMARK_DIR / "configs" / "r6.5.1-pi-mac-network.json"


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _definition() -> dict:
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def _network_definition() -> dict:
    return json.loads(NETWORK_CONFIG.read_text(encoding="utf-8"))


def _summary(
    qualification_id: str,
    *,
    finished_at: str,
    definition_sha: str,
    topology_class: str = "mixed-wired-wifi",
    remote_speed: int | None = 1000,
    tcp_mbps: float = 400.0,
    udp_rows: list[dict] | None = None,
) -> dict:
    if udp_rows is None:
        udp_rows = [
            {
                "direction": "local-to-remote",
                "requested_mbps": 50.0,
                "throughput_mbps": 49.5,
                "lost_percent": 0.0,
                "jitter_ms": 0.1,
                "datagram_bytes": 1200,
            },
            {
                "direction": "local-to-remote",
                "requested_mbps": 100.0,
                "throughput_mbps": 98.0,
                "lost_percent": 0.05,
                "jitter_ms": 0.2,
                "datagram_bytes": 1200,
            },
        ]
    return {
        "schema_version": 1,
        "qualification_id": qualification_id,
        "qualification_name": "r6.5.1-pi-mac-network",
        "definition_sha256": definition_sha,
        "started_at": finished_at,
        "finished_at": finished_at,
        "status": "COMPLETE",
        "claim_scope": "network-characterization-only",
        "topology": {
            "classification": topology_class,
            "local": {
                "system": "Darwin",
                "interface": "en0",
                "address": "192.168.1.173",
                "hardware_port": "Wi-Fi",
                "gateway": "192.168.1.1",
            },
            "remote": {
                "system": "Linux",
                "interface": "eth0",
                "address": "192.168.1.65",
                "gateway": "192.168.1.1",
                "speed_mbps": remote_speed,
                "duplex": "Full" if remote_speed else None,
                "link_detected": True if remote_speed else None,
            },
        },
        "ping": {
            "enabled": True,
            "local_to_remote": {"rtt_avg_ms": 1.1, "packet_loss_percent": 0.0},
            "remote_to_local": {"rtt_avg_ms": 1.0, "packet_loss_percent": 0.0},
        },
        "tcp": [
            {
                "direction": "local-to-remote",
                "parallel_streams": 1,
                "throughput_mbps": tcp_mbps - 20,
                "retransmits": 0,
            },
            {
                "direction": "local-to-remote",
                "parallel_streams": 4,
                "throughput_mbps": tcp_mbps,
                "retransmits": 0,
            },
            {
                "direction": "remote-to-local",
                "parallel_streams": 4,
                "throughput_mbps": 350.0,
                "retransmits": 0,
            },
        ],
        "udp": udp_rows
        + [
            {
                "direction": "remote-to-local",
                "requested_mbps": 50.0,
                "throughput_mbps": 49.0,
                "lost_percent": 0.0,
                "jitter_ms": 0.2,
                "datagram_bytes": 1200,
            }
        ],
        "http3_response_direction": "local-to-remote",
        "references": {},
        "tools": {},
        "framework": {"commit": "deadbeef", "tracked_dirty": False},
    }


def _write_observation(root: Path, summary: dict, network_definition: dict) -> Path:
    qroot = root / summary["qualification_id"]
    processed = qroot / "processed"
    processed.mkdir(parents=True)
    config = {
        "schema_version": 1,
        "definition_sha256": summary["definition_sha256"],
        "definition": network_definition,
    }
    reference = {
        "schema_version": 1,
        "qualification_id": summary["qualification_id"],
        "definition_sha256": summary["definition_sha256"],
    }
    (qroot / "config.json").write_text(json.dumps(config, sort_keys=True), encoding="utf-8")
    (processed / "summary.json").write_text(
        json.dumps(summary, sort_keys=True), encoding="utf-8"
    )
    (processed / "reference.json").write_text(
        json.dumps(reference, sort_keys=True), encoding="utf-8"
    )
    lines = []
    for relative in ("config.json", "processed/reference.json", "processed/summary.json"):
        lines.append(f"{_sha(qroot / relative)}  {relative}")
    (qroot / "artifacts.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return qroot


def _observation(summary: dict) -> Observation:
    topo = topology_fingerprint(summary)
    topo_sha = hashlib.sha256(_canonical(topo)).hexdigest()
    return Observation(
        qualification_id=summary["qualification_id"],
        root=Path(summary["qualification_id"]),
        summary=summary,
        summary_sha256=hashlib.sha256(_canonical(summary)).hexdigest(),
        topology=topo,
        topology_sha256=topo_sha,
        finished_at=summary["finished_at"],
    )


class NetworkEvidenceDefinitionTests(unittest.TestCase):
    def test_valid_definition(self):
        validate_definition(_definition())

    def test_definition_hash_is_semantic(self):
        value = _definition()
        clone = json.loads(json.dumps(value, indent=4))
        self.assertEqual(definition_sha256(value), definition_sha256(clone))

    def test_requires_at_least_three_observations(self):
        value = _definition()
        value["source"]["minimum_observations"] = 2
        with self.assertRaises(FrameworkError):
            validate_definition(value)

    def test_absolute_source_path_is_rejected(self):
        value = _definition()
        value["source"]["qualification_config"] = "/tmp/network.json"
        with self.assertRaises(FrameworkError):
            validate_definition(value)


class NetworkEnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.net_def = _network_definition()
        self.net_sha = network_definition_sha256(self.net_def)

    def test_udp_requires_loss_and_achieved_ratio(self):
        rows = [
            {
                "direction": "local-to-remote",
                "requested_mbps": 100.0,
                "throughput_mbps": 99.0,
                "lost_percent": 0.0,
                "jitter_ms": 0.1,
                "datagram_bytes": 1200,
            },
            {
                "direction": "local-to-remote",
                "requested_mbps": 250.0,
                "throughput_mbps": 200.0,
                "lost_percent": 0.0,
                "jitter_ms": 0.1,
                "datagram_bytes": 1200,
            },
        ]
        obs = []
        for i in range(3):
            obs.append(
                _observation(
                    _summary(
                        f"q{i}",
                        finished_at=f"2026-10-13T00:00:0{i}Z",
                        definition_sha=self.net_sha,
                        udp_rows=copy.deepcopy(rows),
                    )
                )
            )
        envelope = derive_network_envelope(
            obs,
            direction="local-to-remote",
            max_loss_percent=0.1,
            min_achieved_requested_ratio=0.95,
        )
        self.assertEqual(envelope["floors"]["udp_safe_requested_mbps"], 100.0)
        self.assertEqual(envelope["floors"]["udp_safe_achieved_mbps"], 99.0)

    def test_envelope_is_minimum_across_all_selected_observations(self):
        throughputs = [(430.0, 98.0), (390.0, 79.0), (450.0, 97.0)]
        obs = []
        for i, (tcp, udp) in enumerate(throughputs):
            rows = [
                {
                    "direction": "local-to-remote",
                    "requested_mbps": 80.0,
                    "throughput_mbps": udp,
                    "lost_percent": 0.0,
                    "jitter_ms": 0.1,
                    "datagram_bytes": 1200,
                }
            ]
            obs.append(
                _observation(
                    _summary(
                        f"q{i}",
                        finished_at=f"2026-10-13T00:00:0{i}Z",
                        definition_sha=self.net_sha,
                        tcp_mbps=tcp,
                        udp_rows=rows,
                    )
                )
            )
        envelope = derive_network_envelope(
            obs,
            direction="local-to-remote",
            max_loss_percent=0.1,
            min_achieved_requested_ratio=0.95,
        )
        self.assertEqual(envelope["floors"]["tcp_capacity_mbps"], 390.0)
        self.assertEqual(envelope["floors"]["udp_safe_achieved_mbps"], 79.0)
        self.assertEqual(envelope["service_envelope_mbps"], 79.0)
        self.assertEqual(envelope["limiting_reference"], "udp-safe-achieved-floor")

    def test_envelope_is_deterministic_independent_of_input_order(self):
        obs = [
            _observation(
                _summary(
                    f"q{i}",
                    finished_at=f"2026-10-13T00:00:0{i}Z",
                    definition_sha=self.net_sha,
                    tcp_mbps=400.0 + i,
                )
            )
            for i in range(3)
        ]
        kwargs = dict(
            direction="local-to-remote",
            max_loss_percent=0.1,
            min_achieved_requested_ratio=0.95,
        )
        a = derive_network_envelope(obs, **kwargs)
        b = derive_network_envelope(list(reversed(obs)), **kwargs)
        self.assertEqual(a, b)
        self.assertEqual(a["envelope_sha256"], b["envelope_sha256"])

    def test_bad_observation_is_not_silently_discarded(self):
        obs = []
        for i in range(3):
            rows = [
                {
                    "direction": "local-to-remote",
                    "requested_mbps": 50.0,
                    "throughput_mbps": 49.0 if i < 2 else 20.0,
                    "lost_percent": 0.0,
                    "jitter_ms": 0.1,
                    "datagram_bytes": 1200,
                }
            ]
            obs.append(
                _observation(
                    _summary(
                        f"q{i}",
                        finished_at=f"2026-10-13T00:00:0{i}Z",
                        definition_sha=self.net_sha,
                        udp_rows=rows,
                    )
                )
            )
        with self.assertRaisesRegex(FrameworkError, "no UDP point"):
            derive_network_envelope(
                obs,
                direction="local-to-remote",
                max_loss_percent=0.1,
                min_achieved_requested_ratio=0.95,
            )

    def test_latest_topology_group_is_selected_without_mixing_old_group(self):
        old = _observation(
            _summary(
                "old",
                finished_at="2026-10-10T00:00:00Z",
                definition_sha=self.net_sha,
                topology_class="wifi-path",
                remote_speed=None,
            )
        )
        current = [
            _observation(
                _summary(
                    f"new{i}",
                    finished_at=f"2026-10-13T00:00:0{i}Z",
                    definition_sha=self.net_sha,
                )
            )
            for i in range(3)
        ]
        _, selected = select_observations([old, *current], count=3)
        self.assertEqual([o.qualification_id for o in selected], ["new0", "new1", "new2"])


class NetworkEvidenceResolverTests(unittest.TestCase):
    def setUp(self):
        self.net_def = _network_definition()
        self.net_sha = network_definition_sha256(self.net_def)

    def test_discovery_rejects_tampered_matching_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            qroot = _write_observation(
                root,
                _summary(
                    "q1",
                    finished_at="2026-10-13T00:00:00Z",
                    definition_sha=self.net_sha,
                ),
                self.net_def,
            )
            tampered = json.loads((qroot / "processed" / "summary.json").read_text(encoding="utf-8"))
            tampered["tcp"][0]["throughput_mbps"] = 999.0
            (qroot / "processed" / "summary.json").write_text(
                json.dumps(tampered, sort_keys=True), encoding="utf-8"
            )
            with self.assertRaisesRegex(FrameworkError, "hash mismatch"):
                discover_observations(
                    root,
                    expected_definition_sha256=self.net_sha,
                    expected_transport_direction="local-to-remote",
                )

    def test_auto_collection_reaches_three_current_topology_observations(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "benchmark" / "configs").mkdir(parents=True)
            (repo / "qualifications" / "network").mkdir(parents=True)
            (repo / "qualifications" / "network-evidence").mkdir(parents=True)
            net_cfg = repo / "benchmark" / "configs" / "r6.5.1-pi-mac-network.json"
            net_cfg.write_text(json.dumps(self.net_def), encoding="utf-8")

            _write_observation(
                repo / "qualifications" / "network",
                _summary(
                    "q0",
                    finished_at="2026-10-13T00:00:00Z",
                    definition_sha=self.net_sha,
                ),
                self.net_def,
            )

            call_count = 0

            def collect():
                nonlocal call_count
                call_count += 1
                _write_observation(
                    repo / "qualifications" / "network",
                    _summary(
                        f"q{call_count}",
                        finished_at=f"2026-10-13T00:00:0{call_count}Z",
                        definition_sha=self.net_sha,
                    ),
                    self.net_def,
                )

            definition = _definition()
            result = run_network_evidence(
                definition,
                repo_root=repo,
                output_root=repo / "qualifications" / "network-evidence",
                collector=collect,
            )
            self.assertEqual(call_count, 2)
            self.assertEqual(result["summary"]["selected_observations"], 3)
            self.assertEqual(result["summary"]["collected_observations"], 2)
            self.assertTrue((result["root"] / "processed" / "network-envelope.json").is_file())

    def test_collection_fails_on_topology_drift(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "benchmark" / "configs").mkdir(parents=True)
            (repo / "qualifications" / "network").mkdir(parents=True)
            (repo / "qualifications" / "network-evidence").mkdir(parents=True)
            net_cfg = repo / "benchmark" / "configs" / "r6.5.1-pi-mac-network.json"
            net_cfg.write_text(json.dumps(self.net_def), encoding="utf-8")

            _write_observation(
                repo / "qualifications" / "network",
                _summary(
                    "q0",
                    finished_at="2026-10-13T00:00:00Z",
                    definition_sha=self.net_sha,
                ),
                self.net_def,
            )

            def collect():
                _write_observation(
                    repo / "qualifications" / "network",
                    _summary(
                        "q1",
                        finished_at="2026-10-13T00:00:01Z",
                        definition_sha=self.net_sha,
                        topology_class="wired-wired",
                    ),
                    self.net_def,
                )

            with self.assertRaisesRegex(FrameworkError, "topology changed"):
                run_network_evidence(
                    _definition(),
                    repo_root=repo,
                    output_root=repo / "qualifications" / "network-evidence",
                    collector=collect,
                )


if __name__ == "__main__":
    unittest.main()
