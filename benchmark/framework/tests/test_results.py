from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from framework.results import (
    _attempt_count,
    _deterministic_tar_gz,
    _manifest_yaml_text,
    _metric_summary,
    _result_id,
    _semantic_sha256,
    _sha256_file,
    _strict_nominal_loadgen_samples,
)


class ResultsArtifactTests(unittest.TestCase):

    def test_result_id_is_host_neutral(self) -> None:
        summary = {
            "measurement_protocol_revision":
                "r6.5.4.5",
            "experiment_id":
                (
                    "r6-5-4-5-pi-mac-"
                    "paired-scientific-execution-"
                    "20261014T191115Z-055f1a"
                ),
        }

        frozen = {
            "resolved_execution_input_sha256":
                "055f1a"
                + "0" * 58,
        }

        value = _result_id(
            summary,
            frozen,
        )

        self.assertEqual(
            value,
            (
                "r6-5-4-5-http3-paired-result-"
                "20261014T191115Z-055f1a"
            ),
        )

        self.assertNotIn(
            "pi",
            value,
        )

        self.assertNotIn(
            "mac",
            value,
        )

    def test_semantic_sha_is_key_order_independent(
        self,
    ) -> None:

        left = {
            "b": 2,
            "a": 1,
        }

        right = {
            "a": 1,
            "b": 2,
        }

        self.assertEqual(
            _semantic_sha256(left),
            _semantic_sha256(right),
        )

    def test_manifest_yaml_is_yaml12_json_subset(
        self,
    ) -> None:

        value = {
            "artifact": {
                "state": "COMPLETE",
            },
            "schema_version": 1,
        }

        text = _manifest_yaml_text(
            value
        )

        self.assertEqual(
            json.loads(text),
            value,
        )

    def test_deterministic_tar_gzip(
        self,
    ) -> None:

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            a = root / "a.txt"
            b = root / "b.txt"

            a.write_text(
                "alpha\n",
                encoding="utf-8",
            )

            b.write_text(
                "beta\n",
                encoding="utf-8",
            )

            first = root / "first.tar.gz"
            second = root / "second.tar.gz"

            entries = [
                (
                    a,
                    "a.txt",
                ),
                (
                    b,
                    "b.txt",
                ),
            ]

            _deterministic_tar_gz(
                first,
                entries,
            )

            _deterministic_tar_gz(
                second,
                entries,
            )

            self.assertEqual(
                _sha256_file(first),
                _sha256_file(second),
            )

    def test_metric_summary(
        self,
    ) -> None:

        pairs = []

        for index in range(48):
            value = (
                1.0
                if index < 44
                else -1.0
            )

            pairs.append(
                {
                    "delta_percent_positive_favors_ngi541": {
                        "application_goodput_mbps":
                            0.0,
                        "dut_process_cpu_seconds_per_gib":
                            value,
                        "dut_estimated_energy_j_per_gib":
                            value,
                    }
                }
            )

        result = _metric_summary(
            {
                "pairs":
                    pairs,
            }
        )

        cpu = result[
            "dut_process_cpu_seconds_per_gib"
        ]

        self.assertEqual(
            cpu[
                "pair_count"
            ],
            48,
        )

        self.assertEqual(
            cpu[
                "ngi541_pair_wins"
            ],
            44,
        )

        self.assertEqual(
            cpu[
                "stock_pair_wins"
            ],
            4,
        )


    def test_attempt_count_accepts_real_lifecycle_shapes(
        self,
    ) -> None:

        self.assertEqual(
            _attempt_count(
                [
                    {"returncode": 0},
                ]
            ),
            1,
        )

        self.assertEqual(
            _attempt_count(1),
            1,
        )

        self.assertEqual(
            _attempt_count(None),
            0,
        )

    def test_strict_remote_main_uses_first_sample_monotonic_anchor(
        self,
    ) -> None:

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "loadgen.jsonl"
            anchor = 10_000_000_000

            rows = [
                {
                    "sample_index": 100 + index,
                    "monotonic_ns":
                        anchor
                        + index
                        * 1_000_000_000,
                }
                for index in range(7)
            ]

            path.write_text(
                "".join(
                    json.dumps(row)
                    + "\n"
                    for row in rows
                ),
                encoding="utf-8",
            )

            selected = (
                _strict_nominal_loadgen_samples(
                    path,
                    warmup_seconds=2.0,
                    measurement_seconds=3.0,
                )
            )

            self.assertEqual(
                [
                    row["sample_index"]
                    for row in selected
                ],
                [102, 103, 104],
            )


if __name__ == "__main__":
    unittest.main()
