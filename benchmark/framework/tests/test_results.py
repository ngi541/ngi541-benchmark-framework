from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from framework.results import (
    _attempt_count,
    _condition_display_label,
    _deterministic_tar_gz,
    _manifest_yaml_text,
    _metric_summary,
    _publication_bundle_record,
    _result_id,
    _semantic_sha256,
    _sha256_file,
    _strict_nominal_loadgen_samples,
    _svg_condition_delta_plot,
    _verify_inventory,
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


    def test_inventory_allows_only_explicit_historical_extra(
        self,
    ) -> None:

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            payload = root / "definition.json"
            payload.write_text(
                "{}\n",
                encoding="utf-8",
            )

            state = root / "state.json"
            state.write_text(
                "{}\n",
                encoding="utf-8",
            )

            inventory = root / "artifacts.sha256"
            inventory.write_text(
                (
                    _sha256_file(payload)
                    + "  definition.json\n"
                ),
                encoding="utf-8",
            )

            result = _verify_inventory(
                root,
                allowed_unrecorded={
                    "state.json",
                },
            )

            self.assertEqual(
                result[
                    "recorded_entry_count"
                ],
                1,
            )

            self.assertEqual(
                result[
                    "unrecorded_files"
                ],
                ["state.json"],
            )

            with self.assertRaises(Exception):
                _verify_inventory(root)

    def test_inventory_rejects_non_allowlisted_extra(
        self,
    ) -> None:

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            payload = root / "definition.json"
            payload.write_text(
                "{}\n",
                encoding="utf-8",
            )

            extra = root / "unexpected.json"
            extra.write_text(
                "{}\n",
                encoding="utf-8",
            )

            inventory = root / "artifacts.sha256"
            inventory.write_text(
                (
                    _sha256_file(payload)
                    + "  definition.json\n"
                ),
                encoding="utf-8",
            )

            with self.assertRaises(Exception):
                _verify_inventory(
                    root,
                    allowed_unrecorded={
                        "state.json",
                    },
                )


    def test_condition_display_label_is_human_readable(
        self,
    ) -> None:

        self.assertEqual(
            _condition_display_label(
                "w4-hacc-multifile-dataset-s80"
            ),
            "4 workers · HACC · 80 Mb/s",
        )

    def test_publication_bundle_identity_is_content_addressed(
        self,
    ) -> None:

        first = _publication_bundle_record(
            result_id="result-x",
            generator_commit="a" * 40,
            results_archive_sha256="b" * 64,
            evidence_archive_sha256="c" * 64,
            sha256sums_sha256="d" * 64,
        )

        second = _publication_bundle_record(
            result_id="result-x",
            generator_commit="a" * 40,
            results_archive_sha256="b" * 64,
            evidence_archive_sha256="c" * 64,
            sha256sums_sha256="d" * 64,
        )

        self.assertEqual(
            first,
            second,
        )

        changed = _publication_bundle_record(
            result_id="result-x",
            generator_commit="a" * 40,
            results_archive_sha256="e" * 64,
            evidence_archive_sha256="c" * 64,
            sha256sums_sha256="d" * 64,
        )

        self.assertNotEqual(
            first["bundle_id"],
            changed["bundle_id"],
        )

    def test_condition_figure_explains_axes_and_zero_line(
        self,
    ) -> None:

        conditions = []

        for index in range(12):
            condition_id = (
                "w1-clas12-event-stream-s50"
                if index == 0
                else f"condition-{index:02d}"
            )

            conditions.append(
                {
                    "condition_id":
                        condition_id,
                    "metrics": {
                        "application_goodput_mbps": {
                            "pair_count": 4,
                            "median_delta_percent": 0.25,
                            "ngi541_pair_wins": 2,
                            "stock_pair_wins": 2,
                            "ties": 0,
                        }
                    },
                }
            )

        pairs = [
            {
                "delta_percent_positive_favors_ngi541": {
                    "application_goodput_mbps": 0.25,
                }
            }
            for _ in range(48)
        ]

        svg = _svg_condition_delta_plot(
            "application_goodput_mbps",
            {
                "conditions":
                    conditions,
                "pairs":
                    pairs,
            },
        )

        self.assertIn(
            "Goodput change vs stock (%) "
            "— positive = higher goodput",
            svg,
        )

        self.assertIn(
            "positive = higher goodput "
            "for NGI541-direct; "
            "negative = lower goodput",
            svg,
        )

        self.assertIn(
            "0% = no difference; "
            "left = NGI541-direct worse, "
            "right = better",
            svg,
        )

        self.assertIn(
            "1 worker · CLAS12 · 50 Mb/s",
            svg,
        )

        self.assertIn(
            "NGI541-direct wins 2/4",
            svg,
        )


    def test_cpu_and_energy_figures_explain_sign_direction(
        self,
    ) -> None:

        metrics = (
            (
                "dut_process_cpu_seconds_per_gib",
                "CPU cost change vs stock (%) "
                "— positive = lower CPU cost",
                "positive = lower CPU cost "
                "for NGI541-direct; "
                "negative = higher CPU cost",
            ),
            (
                "dut_estimated_energy_j_per_gib",
                "Energy change vs stock (%) "
                "— positive = lower energy use",
                "positive = lower energy use "
                "for NGI541-direct; "
                "negative = higher energy use",
            ),
        )

        condition_ids = [
            "w1-clas12-event-stream-s50",
            "w1-clas12-event-stream-s80",
            "w1-hacc-multifile-dataset-s50",
            "w1-hacc-multifile-dataset-s80",
            "w1-lcls-detector-frame-s50",
            "w1-lcls-detector-frame-s80",
            "w4-clas12-event-stream-s50",
            "w4-clas12-event-stream-s80",
            "w4-hacc-multifile-dataset-s50",
            "w4-hacc-multifile-dataset-s80",
            "w4-lcls-detector-frame-s50",
            "w4-lcls-detector-frame-s80",
        ]

        for metric, axis_label, interpretation in metrics:
            conditions = [
                {
                    "condition_id":
                        condition_id,
                    "metrics": {
                        metric: {
                            "pair_count": 4,
                            "median_delta_percent": 1.0,
                            "ngi541_pair_wins": 3,
                            "stock_pair_wins": 1,
                            "ties": 0,
                        }
                    },
                }
                for condition_id
                in condition_ids
            ]

            pairs = [
                {
                    "delta_percent_positive_favors_ngi541": {
                        metric: 1.0,
                    }
                }
                for _ in range(48)
            ]

            svg = _svg_condition_delta_plot(
                metric,
                {
                    "conditions":
                        conditions,
                    "pairs":
                        pairs,
                },
            )

            self.assertIn(
                axis_label,
                svg,
            )

            self.assertIn(
                interpretation,
                svg,
            )

            self.assertIn(
                "left = NGI541-direct worse, "
                "right = better",
                svg,
            )


if __name__ == "__main__":
    unittest.main()
