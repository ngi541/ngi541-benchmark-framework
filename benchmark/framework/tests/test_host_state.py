from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock


BENCHMARK_DIR = Path(__file__).resolve().parents[2]
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))

from framework.host_state import (
    _darwin_thermal,
    _launch_persistent_powermetrics,
    _nearest_rank,
    _parse_temperature,
    calibrate_host_state,
    normalize_measurement_control,
    readiness,
    wait_until_ready,
)
from framework.io_utils import FrameworkError


class HostStateConfigTests(unittest.TestCase):
    def test_no_universal_temperature_or_cpu_busy_threshold_is_defined(self):
        control = normalize_measurement_control({
            "host_state": {
                "enabled": True,
                "temperature": {"required": True, "command": ["temp-helper"]},
                "require_ac_power": True,
                "require_no_throttling": True,
            },
            "calibration": {
                "enabled": True,
                "samples": 15,
                "sample_interval_seconds": 1,
                "cpu_busy_upper_quantile": 0.9,
            },
            "readiness": {
                "required_consecutive_ready_samples": 3,
            },
        })
        self.assertNotIn("max_temperature_c", control["host_state"])
        self.assertNotIn("max_cpu_busy_percent", control["host_state"])
        self.assertEqual(control["calibration"]["cpu_busy_upper_quantile"], 0.9)
        self.assertEqual(control["readiness"]["required_consecutive_ready_samples"], 3)

    def test_legacy_absolute_cpu_busy_threshold_is_rejected(self):
        with self.assertRaises(FrameworkError):
            normalize_measurement_control({
                "host_state": {
                    "max_cpu_busy_percent": 20,
                }
            })

    def test_invalid_calibration_quantile_is_rejected(self):
        with self.assertRaises(FrameworkError):
            normalize_measurement_control({
                "calibration": {
                    "cpu_busy_upper_quantile": 0,
                }
            })

    def test_invalid_calibration_timeout_is_rejected(self):
        with self.assertRaises(FrameworkError):
            normalize_measurement_control({
                "calibration": {
                    "timeout_seconds": 0,
                }
            })

    def test_invalid_order_thresholds_are_rejected(self):
        with self.assertRaises(FrameworkError):
            normalize_measurement_control({
                "analysis": {
                    "order_effect_warning_pp": 5,
                    "order_effect_strong_warning_pp": 2,
                }
            })




class DarwinSamplerLaunchTests(unittest.TestCase):
    def test_persistent_sampler_keeps_callers_tty_session(self):
        process = mock.Mock()
        with mock.patch(
            "framework.host_state.subprocess.Popen",
            return_value=process,
        ) as popen:
            returned = _launch_persistent_powermetrics(
                ["/usr/bin/sudo", "-n", "/usr/bin/powermetrics"]
            )

        self.assertIs(returned, process)
        _, kwargs = popen.call_args
        self.assertIsNone(kwargs["stdin"])
        self.assertNotIn("start_new_session", kwargs)




class DarwinThermalClassificationTests(unittest.TestCase):
    def test_thermal_pressure_alone_is_not_classified_as_throttling(self):
        output = (
            "CPU_Scheduler_Limit = 100\n"
            "CPU_Available_CPUs = 8\n"
            "CPU_Speed_Limit = 100\n"
            "No thermal warning level has been recorded\n"
            "No performance warning level has been recorded\n"
        )
        with mock.patch("framework.host_state._run", return_value=(0, output, "")):
            thermal = _darwin_thermal(8, thermal_pressure="constrained")

        self.assertEqual(thermal["thermal_state"], "constrained")
        self.assertTrue(thermal["thermal_pressure_constrained"])
        self.assertFalse(thermal["performance_limit_active"])
        self.assertFalse(thermal["throttling_active"])

    def test_pmset_capacity_reduction_is_classified_as_throttling(self):
        output = (
            "CPU_Scheduler_Limit = 100\n"
            "CPU_Available_CPUs = 8\n"
            "CPU_Speed_Limit = 80\n"
        )
        with mock.patch("framework.host_state._run", return_value=(0, output, "")):
            thermal = _darwin_thermal(8, thermal_pressure="nominal")

        self.assertTrue(thermal["performance_limit_active"])
        self.assertTrue(thermal["throttling_active"])

class TemperatureParsingTests(unittest.TestCase):
    def test_powermetrics_temperature_is_parsed(self):
        self.assertEqual(
            _parse_temperature("CPU die temperature: 78.42 C\n"),
            78.42,
        )


class CalibrationTests(unittest.TestCase):
    def _control(self):
        return normalize_measurement_control({
            "host_state": {
                "enabled": True,
                "temperature": {"required": True, "command": ["temp-helper"]},
                "require_ac_power": True,
                "require_no_throttling": True,
            },
            "calibration": {
                "enabled": True,
                "samples": 5,
                "sample_interval_seconds": 0.0001,
                "cpu_busy_upper_quantile": 0.8,
            },
        })

    @staticmethod
    def _snapshot(busy):
        return {
            "temperature": {"temperature_c": 70.0},
            "power": {"source": "ac"},
            "thermal": {"throttling_active": False},
            "load": {"cpu_busy_percent": busy},
        }

    def test_nearest_rank_quantile(self):
        self.assertEqual(_nearest_rank([10, 20, 30, 40, 50], 0.8), 40)

    def test_calibration_derives_host_specific_cpu_envelope(self):
        values = [10.0, 20.0, 15.0, 40.0, 25.0]
        snapshots = [self._snapshot(value) for value in values]
        with mock.patch("framework.host_state.capture_host_state", side_effect=snapshots):
            calibration = calibrate_host_state(self._control())
        self.assertEqual(calibration["samples_collected"], 5)
        self.assertEqual(calibration["cpu_busy_percent"]["median"], 20.0)
        self.assertEqual(calibration["cpu_busy_percent"]["upper_limit"], 25.0)

    def test_calibration_waits_through_transient_throttling_and_restarts_window(self):
        first = self._snapshot(10.0)
        blocked = self._snapshot(11.0)
        blocked["thermal"]["throttling_active"] = True
        stable = [self._snapshot(v) for v in (12.0, 13.0, 14.0, 15.0, 16.0)]
        seen = []
        with mock.patch(
            "framework.host_state.capture_host_state",
            side_effect=[first, blocked, *stable],
        ):
            calibration = calibrate_host_state(self._control(), on_snapshot=seen.append)

        self.assertEqual(calibration["samples_collected"], 5)
        self.assertEqual(calibration["snapshots_observed"], 7)
        self.assertEqual(calibration["snapshots_rejected_static"], 1)
        self.assertEqual(calibration["window_resets"], 1)
        self.assertEqual(calibration["cpu_busy_percent"]["median"], 14.0)
        self.assertEqual(len(seen), 7)


    def test_calibration_retries_transient_missing_cpu_busy_and_restarts_window(self):
        good1 = self._snapshot(10.0)
        missing = self._snapshot(None)
        stable = [self._snapshot(v) for v in (12.0, 13.0, 14.0, 15.0, 16.0)]
        seen = []
        with mock.patch(
            "framework.host_state.capture_host_state",
            side_effect=[good1, missing, *stable],
        ):
            calibration = calibrate_host_state(self._control(), on_snapshot=seen.append)

        self.assertEqual(calibration["samples_collected"], 5)
        self.assertEqual(calibration["snapshots_observed"], 7)
        self.assertEqual(calibration["snapshots_rejected_static"], 1)
        self.assertEqual(calibration["window_resets"], 1)
        self.assertEqual(calibration["cpu_busy_percent"]["median"], 14.0)
        self.assertIn("cpu-busy-state-unavailable", seen[1]["calibration"]["reasons"])

    def test_calibration_times_out_instead_of_failing_immediately_on_static_block(self):
        control = self._control()
        control["calibration"]["timeout_seconds"] = 0.01
        blocked = self._snapshot(10.0)
        blocked["thermal"]["throttling_active"] = True
        with mock.patch(
            "framework.host_state.capture_host_state",
            return_value=blocked,
        ):
            with self.assertRaisesRegex(FrameworkError, "host calibration timeout"):
                calibrate_host_state(control)


class ReadinessTests(unittest.TestCase):
    def _control(self, *, calibrated=True, consecutive=1):
        return normalize_measurement_control({
            "host_state": {
                "enabled": True,
                "temperature": {"required": True, "command": ["temp-helper"]},
                "require_ac_power": True,
                "require_no_throttling": True,
            },
            "calibration": {
                "enabled": calibrated,
                "samples": 5,
                "sample_interval_seconds": 0.0001,
                "cpu_busy_upper_quantile": 0.8,
            },
            "readiness": {
                "timeout_seconds": 1,
                "poll_interval_seconds": 0.0001,
                "required_consecutive_ready_samples": consecutive,
            },
        })

    @staticmethod
    def _snapshot(busy=5.0):
        return {
            "temperature": {"temperature_c": 95.0},
            "power": {"source": "ac"},
            "thermal": {"throttling_active": False},
            "load": {"cpu_busy_percent": busy},
        }

    @staticmethod
    def _calibration(limit=20.0):
        return {
            "enabled": True,
            "cpu_busy_percent": {
                "upper_limit": limit,
            },
        }

    def test_high_temperature_alone_does_not_fail_without_firmware_signal(self):
        result = readiness(self._snapshot(), self._control(), self._calibration())
        self.assertTrue(result["ready"])
        self.assertEqual(result["reasons"], [])

    def test_firmware_throttling_blocks_execution(self):
        snapshot = self._snapshot()
        snapshot["thermal"]["throttling_active"] = True
        result = readiness(snapshot, self._control(), self._calibration())
        self.assertFalse(result["ready"])
        self.assertIn("thermal-or-performance-throttling-active", result["reasons"])

    def test_missing_required_temperature_is_fatal(self):
        snapshot = self._snapshot()
        snapshot["temperature"]["temperature_c"] = None
        result = readiness(snapshot, self._control(), self._calibration())
        self.assertFalse(result["ready"])
        self.assertTrue(result["fatal"])

    def test_cpu_busy_is_compared_with_calibrated_envelope(self):
        result = readiness(self._snapshot(25.0), self._control(), self._calibration(20.0))
        self.assertFalse(result["ready"])
        self.assertIn("cpu-busy-above-calibrated-envelope", result["reasons"])

    def test_missing_calibration_is_fatal(self):
        result = readiness(self._snapshot(), self._control(), None)
        self.assertFalse(result["ready"])
        self.assertTrue(result["fatal"])
        self.assertIn("cpu-busy-calibration-unavailable", result["reasons"])


    def test_missing_cpu_busy_sample_is_retryable(self):
        snapshot = self._snapshot(None)
        result = readiness(snapshot, self._control(), self._calibration())
        self.assertFalse(result["ready"])
        self.assertFalse(result["fatal"])
        self.assertIn("cpu-busy-state-unavailable", result["reasons"])

    def test_wait_until_ready_retries_transient_missing_cpu_busy(self):
        control = self._control(consecutive=2)
        calibration = self._calibration(20.0)
        samples = [
            self._snapshot(None),
            self._snapshot(10.0),
            self._snapshot(11.0),
        ]
        seen = []
        with mock.patch("framework.host_state.capture_host_state", side_effect=samples):
            snapshot, count, _ = wait_until_ready(
                control,
                calibration=calibration,
                on_snapshot=seen.append,
            )
        self.assertEqual(count, 3)
        self.assertEqual(snapshot["readiness"]["consecutive_ready_samples"], 2)
        self.assertFalse(seen[0]["readiness"]["fatal"])
        self.assertIn("cpu-busy-state-unavailable", seen[0]["readiness"]["reasons"])

    def test_three_consecutive_samples_are_required(self):
        control = self._control(consecutive=3)
        calibration = self._calibration(20.0)
        samples = [
            self._snapshot(10.0),
            self._snapshot(30.0),
            self._snapshot(10.0),
            self._snapshot(11.0),
            self._snapshot(12.0),
        ]
        seen = []
        with mock.patch("framework.host_state.capture_host_state", side_effect=samples):
            snapshot, count, _ = wait_until_ready(
                control,
                calibration=calibration,
                on_snapshot=seen.append,
            )
        self.assertEqual(count, 5)
        self.assertEqual(snapshot["readiness"]["consecutive_ready_samples"], 3)
        self.assertEqual(len(seen), 5)


if __name__ == "__main__":
    unittest.main()
