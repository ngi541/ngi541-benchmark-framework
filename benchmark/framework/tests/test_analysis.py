from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


BENCHMARK_DIR = Path(__file__).resolve().parents[2]
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))

from framework.analysis import (
    _first_valid_measurement,
    _order_effect_statistics,
    _paired_statistics,
    _paired_svg,
    _requests_svg,
    _variant_statistics,
    analyze_experiment,
    validate_analysis_outputs,
)
from framework.io_utils import FrameworkError, atomic_write_json


EXPERIMENT_ID = "http3-local-20261009T013001Z-17c942"


def _measurement(
    *,
    run_id: str,
    pair_id: str,
    variant: str,
    attempt: int,
    rps: float | None,
    valid: bool,
) -> dict:
    return {
        "schema_version": 1,
        "experiment_id": EXPERIMENT_ID,
        "run_id": run_id,
        "pair_id": pair_id,
        "attempt": attempt,
        "variant": variant,
        "parameters": {},
        "timing": {
            "started_at": "2026-10-09T01:00:00Z",
            "finished_at": "2026-10-09T01:00:01Z",
            "elapsed_ns": 100_000_000 if valid else 0,
        },
        "requests": {
            "planned": 200,
            "completed": 200 if valid else 0,
        },
        "metrics": {"requests_per_second": rps},
        "execution": {
            "exit_code": 0 if valid else 1,
            "valid": valid,
            "failure": None if valid else "synthetic failure",
        },
        "observations": {
            "attempt_started_at": "2026-10-09T01:00:00Z",
            "completed_count_known": valid,
        },
    }


class AnalysisStatisticsTests(unittest.TestCase):
    def test_single_sample_dispersion_is_null(self):
        stats = _variant_statistics([100.0])
        self.assertEqual(stats["n"], 1)
        self.assertIsNone(stats["sample_standard_deviation"])
        self.assertIsNone(stats["coefficient_of_variation_percent"])


    def test_order_effect_is_split_by_first_variant(self):
        rows = [
            {"condition_id": "condition-0001", "first_variant": "stock", "delta_percent": 3.0},
            {"condition_id": "condition-0001", "first_variant": "stock", "delta_percent": 5.0},
            {"condition_id": "condition-0001", "first_variant": "ngi541-direct", "delta_percent": -4.0},
            {"condition_id": "condition-0001", "first_variant": "ngi541-direct", "delta_percent": -2.0},
        ]
        _, summary = _order_effect_statistics(
            rows, warning_pp=2.0, strong_warning_pp=5.0
        )
        effect = summary["condition-0001"]
        self.assertAlmostEqual(
            effect["absolute_median_gap_percentage_points"],
            7.0,
        )
        self.assertEqual(effect["warning_level"], "strongly-order-sensitive")

    def test_paired_statistics(self):
        stats = _paired_statistics([
            {"delta_percent": 10.0, "ratio": 1.1, "winner": "candidate"},
            {"delta_percent": 20.0, "ratio": 1.2, "winner": "candidate"},
        ])
        self.assertEqual(stats["n_pairs"], 2)
        self.assertAlmostEqual(stats["median_delta_percent"], 15.0)
        self.assertEqual(stats["wins"], 2)
        self.assertEqual(stats["losses"], 0)
        self.assertEqual(stats["ties"], 0)


class AnalysisVisualizationTests(unittest.TestCase):
    def test_requests_svg_uses_grouped_bars_and_workload_labels(self):
        variant_summary = {
            "condition-0001": {
                "parameters": {"payload_bytes": 16384, "workers": 1, "clients": 2},
                "variants": {
                    "stock": {"median": 2048.7},
                    "ngi541-direct": {"median": 2037.7},
                },
            }
        }
        key = json.dumps(
            {"payload_bytes": 16384, "workers": 1, "clients": 2},
            sort_keys=True,
            separators=(",", ":"),
        )
        catalog = {
            key: {
                "condition_id": "condition-0001",
                "parameters": {"payload_bytes": 16384, "workers": 1, "clients": 2},
            }
        }
        svg = _requests_svg(
            variant_summary,
            [key],
            catalog,
            ["stock", "ngi541-direct"],
        )
        self.assertIn("<rect", svg)
        self.assertIn("16 KiB", svg)
        self.assertIn("1w/2c", svg)
        self.assertIn("Stock OpenSSL", svg)
        self.assertIn("NGI541 direct", svg)
        self.assertIn("Completed HTTP/3 requests/s", svg)

    def test_paired_svg_aggregates_by_condition(self):
        rows = [
            {
                "condition_id": "condition-0001",
                "payload_bytes": 16384,
                "workers": 2,
                "clients": 16,
                "pair_id": "pair-0001",
                "repetition": 1,
                "baseline_variant": "stock",
                "candidate_variant": "ngi541-direct",
                "baseline_requests_per_second": 100.0,
                "candidate_requests_per_second": 105.0,
                "ratio": 1.05,
                "delta_percent": 5.0,
                "winner": "candidate",
            },
            {
                "condition_id": "condition-0001",
                "payload_bytes": 16384,
                "workers": 2,
                "clients": 16,
                "pair_id": "pair-0002",
                "repetition": 2,
                "baseline_variant": "stock",
                "candidate_variant": "ngi541-direct",
                "baseline_requests_per_second": 100.0,
                "candidate_requests_per_second": 106.0,
                "ratio": 1.06,
                "delta_percent": 6.0,
                "winner": "candidate",
            },
        ]
        svg = _paired_svg(rows)
        self.assertIn("NGI541 relative throughput delta", svg)
        self.assertIn("16 KiB", svg)
        self.assertIn("2w/16c", svg)
        self.assertIn("+5.50%", svg)
        self.assertIn("condition-0001 · n=2", svg)
        self.assertNotIn(">pair-0001<", svg)


class AttemptSelectionTests(unittest.TestCase):
    def test_first_valid_attempt_is_selected_metric_independently(self):
        with tempfile.TemporaryDirectory() as tmp:
            exp = Path(tmp)
            run = {
                "run_id": "run-0001",
                "pair_id": "pair-0001",
                "variant": "stock",
            }
            run_dir = exp / "raw" / "runs" / "run-0001"
            for attempt, rps, valid in [
                (1, None, False),
                (2, 100.0, True),
                (3, 9999.0, True),
            ]:
                out = run_dir / f"attempt-{attempt:02d}"
                out.mkdir(parents=True)
                atomic_write_json(
                    out / "measurement.json",
                    _measurement(
                        run_id="run-0001",
                        pair_id="pair-0001",
                        variant="stock",
                        attempt=attempt,
                        rps=rps,
                        valid=valid,
                    ),
                )

            measurement, _, selection = _first_valid_measurement(exp, run)
            self.assertEqual(measurement["attempt"], 2)
            self.assertEqual(measurement["metrics"]["requests_per_second"], 100.0)
            self.assertEqual(selection["earlier_invalid_attempts"], 1)
            self.assertEqual(selection["later_attempts_ignored"], 1)

    def test_malformed_first_valid_attempt_fails_instead_of_falling_forward(self):
        with tempfile.TemporaryDirectory() as tmp:
            exp = Path(tmp)
            run = {
                "run_id": "run-0001",
                "pair_id": "pair-0001",
                "variant": "stock",
            }
            run_dir = exp / "raw" / "runs" / "run-0001"
            first = run_dir / "attempt-01"
            second = run_dir / "attempt-02"
            first.mkdir(parents=True)
            second.mkdir(parents=True)

            malformed = _measurement(
                run_id="run-0001", pair_id="pair-0001", variant="stock",
                attempt=1, rps=None, valid=True,
            )
            atomic_write_json(first / "measurement.json", malformed)
            atomic_write_json(
                second / "measurement.json",
                _measurement(
                    run_id="run-0001", pair_id="pair-0001", variant="stock",
                    attempt=2, rps=500.0, valid=True,
                ),
            )

            with self.assertRaises(FrameworkError):
                _first_valid_measurement(exp, run)


@unittest.skipUnless(shutil.which("git"), "git is required")
class AnalysisIntegrationTests(unittest.TestCase):
    def _git_repo(self, root: Path) -> Path:
        repo = root / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
        (repo / "framework.txt").write_text("r5.5\n", encoding="utf-8")
        subprocess.run(["git", "add", "framework.txt"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "framework"], cwd=repo, check=True)
        return repo

    def _experiment(self, repo: Path) -> Path:
        exp = repo / "experiments" / EXPERIMENT_ID
        for rel in ("config", "execution", "raw/runs", "processed", "figures"):
            (exp / rel).mkdir(parents=True, exist_ok=True)

        resolved = {
            "workload": "http3",
            "environment": "local",
            "variants": ["stock", "ngi541-direct"],
            "parameters": {
                "payload_bytes": [16384],
                "workers": [1],
                "clients": [2],
                "repetitions": 2,
            },
            "comparison": {"mode": "paired-balanced", "random_seed": None},
        }
        schedule = {
            "schema_version": 1,
            "experiment_id": EXPERIMENT_ID,
            "comparison_mode": "paired-balanced",
            "random_seed": None,
            "runs": [
                {"sequence": 1, "run_id": "run-0001", "pair_id": "pair-0001", "variant": "stock", "repetition": 1, "parameters": {"clients": 2, "payload_bytes": 16384, "workers": 1}},
                {"sequence": 2, "run_id": "run-0002", "pair_id": "pair-0001", "variant": "ngi541-direct", "repetition": 1, "parameters": {"clients": 2, "payload_bytes": 16384, "workers": 1}},
                {"sequence": 3, "run_id": "run-0003", "pair_id": "pair-0002", "variant": "ngi541-direct", "repetition": 2, "parameters": {"clients": 2, "payload_bytes": 16384, "workers": 1}},
                {"sequence": 4, "run_id": "run-0004", "pair_id": "pair-0002", "variant": "stock", "repetition": 2, "parameters": {"clients": 2, "payload_bytes": 16384, "workers": 1}},
            ],
        }
        atomic_write_json(exp / "config" / "resolved.json", resolved)
        atomic_write_json(exp / "execution" / "schedule.json", schedule)

        values = {
            "run-0001": ("pair-0001", "stock", 100.0),
            "run-0002": ("pair-0001", "ngi541-direct", 110.0),
            "run-0003": ("pair-0002", "ngi541-direct", 120.0),
            "run-0004": ("pair-0002", "stock", 100.0),
        }
        for run_id, (pair_id, variant, rps) in values.items():
            attempt = exp / "raw" / "runs" / run_id / "attempt-01"
            attempt.mkdir(parents=True)
            atomic_write_json(
                attempt / "measurement.json",
                _measurement(
                    run_id=run_id, pair_id=pair_id, variant=variant,
                    attempt=1, rps=rps, valid=True,
                ),
            )

        # Add an earlier operational failure and a later high metric to run-0001.
        run1 = exp / "raw" / "runs" / "run-0001"
        (run1 / "attempt-01").rename(run1 / "attempt-02")
        m2 = json.loads((run1 / "attempt-02" / "measurement.json").read_text())
        m2["attempt"] = 2
        atomic_write_json(run1 / "attempt-02" / "measurement.json", m2)
        a1 = run1 / "attempt-01"
        a1.mkdir()
        atomic_write_json(
            a1 / "measurement.json",
            _measurement(
                run_id="run-0001", pair_id="pair-0001", variant="stock",
                attempt=1, rps=None, valid=False,
            ),
        )
        a3 = run1 / "attempt-03"
        a3.mkdir()
        atomic_write_json(
            a3 / "measurement.json",
            _measurement(
                run_id="run-0001", pair_id="pair-0001", variant="stock",
                attempt=3, rps=9999.0, valid=True,
            ),
        )
        return exp

    def test_analysis_is_deterministic_and_paired(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._git_repo(Path(tmp))
            exp = self._experiment(repo)

            result = analyze_experiment(exp)
            self.assertEqual(result["selected_runs"], 4)
            self.assertEqual(result["conditions"], 1)
            self.assertEqual(result["pairs"], 2)

            selection = json.loads((exp / "processed" / "selection.json").read_text())
            self.assertEqual(selection["runs"][0]["selected_attempt"], 2)

            stats = json.loads((exp / "processed" / "statistics.json").read_text())
            paired = stats["paired"]["condition-0001"]
            self.assertAlmostEqual(paired["median_delta_percent"], 15.0)
            self.assertEqual(paired["wins"], 2)

            generated = [
                exp / "processed" / "selection.json",
                exp / "processed" / "runs.csv",
                exp / "processed" / "summary.csv",
                exp / "processed" / "pairs.csv",
                exp / "processed" / "statistics.json",
                exp / "processed" / "analysis-provenance.json",
                exp / "processed" / "README.md",
                exp / "processed" / "artifacts.sha256",
                exp / "figures" / "requests-per-second.svg",
                exp / "figures" / "paired-delta.svg",
            ]
            before = {path.relative_to(exp): path.read_bytes() for path in generated}
            analyze_experiment(exp)
            after = {path.relative_to(exp): path.read_bytes() for path in generated}
            self.assertEqual(before, after)
            self.assertEqual(validate_analysis_outputs(exp), [])

    def test_artifact_hash_validation_detects_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._git_repo(Path(tmp))
            exp = self._experiment(repo)
            analyze_experiment(exp)
            (exp / "processed" / "runs.csv").write_text("tampered\n", encoding="utf-8")
            errors = validate_analysis_outputs(exp)
            self.assertTrue(any("hash mismatch" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
