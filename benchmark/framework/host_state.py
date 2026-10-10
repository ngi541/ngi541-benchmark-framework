from __future__ import annotations

import json
import math
import os
import platform
import re
import shutil
import statistics
import subprocess
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

from framework.ids import utc_rfc3339
from framework.io_utils import FrameworkError


DEFAULT_MEASUREMENT_CONTROL: dict[str, Any] = {
    "host_state": {
        "enabled": False,
        "temperature": {
            "required": False,
            "command": None,
            "sampler_interval_seconds": 1.0,
            "max_sample_age_seconds": 5.0,
            "sampler_start_timeout_seconds": 15.0,
        },
        "require_ac_power": False,
        "require_no_throttling": False,
    },
    "calibration": {
        "enabled": False,
        "samples": 15,
        "sample_interval_seconds": 1.0,
        "cpu_busy_upper_quantile": 0.90,
        "timeout_seconds": 180,
    },
    "readiness": {
        "timeout_seconds": 120,
        "poll_interval_seconds": 2.0,
        "required_consecutive_ready_samples": 1,
    },
    "runtime": {
        "stage_artifacts_once": False,
        "cleanup_attempt_runtime": False,
    },
    "analysis": {
        "order_effect_warning_pp": 2.0,
        "order_effect_strong_warning_pp": 5.0,
    },
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in base.items():
        if isinstance(value, dict):
            result[key] = _deep_merge(value, {})
        else:
            result[key] = value
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _positive_number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise FrameworkError(f"{name} must be > 0")
    return float(value)


def normalize_measurement_control(value: Any) -> dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise FrameworkError("measurement_control must be an object")

    control = _deep_merge(DEFAULT_MEASUREMENT_CONTROL, value)
    allowed = {"host_state", "calibration", "readiness", "runtime", "analysis"}
    unknown = set(value).difference(allowed)
    if unknown:
        raise FrameworkError(
            "measurement_control has unsupported keys: " + ", ".join(sorted(unknown))
        )

    host = control["host_state"]
    if not isinstance(host, dict):
        raise FrameworkError("measurement_control.host_state must be an object")
    allowed_host = {
        "enabled", "temperature", "require_ac_power", "require_no_throttling"
    }
    unknown_host = set(host).difference(allowed_host)
    if unknown_host:
        raise FrameworkError(
            "measurement_control.host_state has unsupported keys: "
            + ", ".join(sorted(unknown_host))
        )
    for key in ("enabled", "require_ac_power", "require_no_throttling"):
        if not isinstance(host.get(key), bool):
            raise FrameworkError(f"measurement_control.host_state.{key} must be boolean")

    temperature = host.get("temperature")
    if not isinstance(temperature, dict):
        raise FrameworkError(
            "measurement_control.host_state.temperature must be an object"
        )
    allowed_temperature = {
        "required", "command", "sampler_interval_seconds",
        "max_sample_age_seconds", "sampler_start_timeout_seconds",
    }
    unknown_temperature = set(temperature).difference(allowed_temperature)
    if unknown_temperature:
        raise FrameworkError(
            "measurement_control.host_state.temperature has unsupported keys: "
            + ", ".join(sorted(unknown_temperature))
        )
    if not isinstance(temperature.get("required"), bool):
        raise FrameworkError(
            "measurement_control.host_state.temperature.required must be boolean"
        )
    command = temperature.get("command")
    if command is not None:
        if (
            not isinstance(command, list)
            or not command
            or any(not isinstance(item, str) or not item for item in command)
        ):
            raise FrameworkError(
                "measurement_control.host_state.temperature.command must be "
                "a non-empty string array or null"
            )
    for key in (
        "sampler_interval_seconds",
        "max_sample_age_seconds",
        "sampler_start_timeout_seconds",
    ):
        temperature[key] = _positive_number(
            temperature.get(key),
            f"measurement_control.host_state.temperature.{key}",
        )

    calibration = control["calibration"]
    if not isinstance(calibration, dict):
        raise FrameworkError("measurement_control.calibration must be an object")
    allowed_calibration = {
        "enabled", "samples", "sample_interval_seconds",
        "cpu_busy_upper_quantile", "timeout_seconds"
    }
    unknown_calibration = set(calibration).difference(allowed_calibration)
    if unknown_calibration:
        raise FrameworkError(
            "measurement_control.calibration has unsupported keys: "
            + ", ".join(sorted(unknown_calibration))
        )
    if not isinstance(calibration.get("enabled"), bool):
        raise FrameworkError("measurement_control.calibration.enabled must be boolean")
    samples = calibration.get("samples")
    if not isinstance(samples, int) or isinstance(samples, bool) or samples < 2:
        raise FrameworkError("measurement_control.calibration.samples must be an integer >= 2")
    calibration["sample_interval_seconds"] = _positive_number(
        calibration.get("sample_interval_seconds"),
        "measurement_control.calibration.sample_interval_seconds",
    )
    calibration["timeout_seconds"] = _positive_number(
        calibration.get("timeout_seconds"),
        "measurement_control.calibration.timeout_seconds",
    )
    quantile = calibration.get("cpu_busy_upper_quantile")
    if (
        isinstance(quantile, bool)
        or not isinstance(quantile, (int, float))
        or not 0 < float(quantile) <= 1
    ):
        raise FrameworkError(
            "measurement_control.calibration.cpu_busy_upper_quantile must be in (0, 1]"
        )
    calibration["cpu_busy_upper_quantile"] = float(quantile)

    readiness_cfg = control["readiness"]
    if not isinstance(readiness_cfg, dict):
        raise FrameworkError("measurement_control.readiness must be an object")
    allowed_readiness = {
        "timeout_seconds", "poll_interval_seconds", "required_consecutive_ready_samples"
    }
    unknown_readiness = set(readiness_cfg).difference(allowed_readiness)
    if unknown_readiness:
        raise FrameworkError(
            "measurement_control.readiness has unsupported keys: "
            + ", ".join(sorted(unknown_readiness))
        )
    readiness_cfg["timeout_seconds"] = _positive_number(
        readiness_cfg.get("timeout_seconds"),
        "measurement_control.readiness.timeout_seconds",
    )
    readiness_cfg["poll_interval_seconds"] = _positive_number(
        readiness_cfg.get("poll_interval_seconds"),
        "measurement_control.readiness.poll_interval_seconds",
    )
    consecutive = readiness_cfg.get("required_consecutive_ready_samples")
    if not isinstance(consecutive, int) or isinstance(consecutive, bool) or consecutive < 1:
        raise FrameworkError(
            "measurement_control.readiness.required_consecutive_ready_samples "
            "must be a positive integer"
        )

    runtime = control["runtime"]
    if not isinstance(runtime, dict):
        raise FrameworkError("measurement_control.runtime must be an object")
    for key in ("stage_artifacts_once", "cleanup_attempt_runtime"):
        if not isinstance(runtime.get(key), bool):
            raise FrameworkError(f"measurement_control.runtime.{key} must be boolean")

    analysis = control["analysis"]
    if not isinstance(analysis, dict):
        raise FrameworkError("measurement_control.analysis must be an object")
    warning = analysis.get("order_effect_warning_pp")
    strong = analysis.get("order_effect_strong_warning_pp")
    for name, number in (
        ("order_effect_warning_pp", warning),
        ("order_effect_strong_warning_pp", strong),
    ):
        if isinstance(number, bool) or not isinstance(number, (int, float)) or number < 0:
            raise FrameworkError(f"measurement_control.analysis.{name} must be >= 0")
    if float(strong) < float(warning):
        raise FrameworkError(
            "order_effect_strong_warning_pp must be >= order_effect_warning_pp"
        )
    analysis["order_effect_warning_pp"] = float(warning)
    analysis["order_effect_strong_warning_pp"] = float(strong)
    return control


def _run(command: list[str], timeout: float = 8.0) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            command,
            check=False,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", str(exc)
    return result.returncode, result.stdout, result.stderr


def _parse_temperature(text: str) -> float | None:
    patterns = (
        r"CPU die temperature:\s*([0-9]+(?:\.[0-9]+)?)\s*C",
        r"CPU temperature:\s*([0-9]+(?:\.[0-9]+)?)\s*C",
        r"temp(?:erature)?[^0-9-]*([0-9]+(?:\.[0-9]+)?)\s*['°]?C",
        r"^\s*([0-9]+(?:\.[0-9]+)?)\s*$",
    )
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE)
        if match:
            return float(match.group(1))
    return None


def _parse_thermal_pressure(text: str) -> str | None:
    match = re.search(
        r"Current pressure level:\s*([A-Za-z]+)",
        text,
        flags=re.IGNORECASE,
    )
    return match.group(1).lower() if match else None


def _launch_persistent_powermetrics(command: list[str]) -> subprocess.Popen[str]:
    """Launch powermetrics without detaching from the caller's controlling TTY.

    macOS sudo timestamp credentials are commonly TTY-scoped.  Keeping the
    sampler in the same session allows `sudo -n` to reuse credentials obtained
    by the preceding interactive `sudo -v`, while stdout/stderr remain piped to
    the in-memory normalizer.
    """
    return subprocess.Popen(
        command,
        stdin=None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )


class DarwinPowermetricsSampler:
    """Long-lived Darwin temperature sampler.

    The sampler authenticates sudo once, then keeps one privileged powermetrics
    process alive for the execution session. Only the latest normalized sample
    is retained in memory; the continuous powermetrics stream is not persisted.
    """

    def __init__(self, control: dict[str, Any]):
        self.control = normalize_measurement_control(control)
        self.process: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()
        self._temperature_c: float | None = None
        self._thermal_pressure: str | None = None
        self._sample_monotonic: float | None = None
        self._stderr_lines: list[str] = []
        self._threads: list[threading.Thread] = []

    @property
    def required(self) -> bool:
        temperature = self.control["host_state"]["temperature"]
        return (
            platform.system() == "Darwin"
            and self.control["host_state"]["enabled"]
            and temperature["required"]
            and temperature["command"] is None
        )

    def start(self) -> None:
        if not self.required or self.process is not None:
            return

        sudo = shutil.which("sudo") or "/usr/bin/sudo"
        powermetrics = shutil.which("powermetrics") or "/usr/bin/powermetrics"

        # Authenticate while the framework still owns the user's controlling TTY.
        # macOS sudo commonly scopes timestamp credentials to that TTY.  The
        # persistent sampler therefore must remain in the same session/TTY;
        # detaching it with setsid()/start_new_session would make `sudo -n` miss
        # the credential established here even immediately after a successful
        # password prompt.
        privilege = subprocess.run([sudo, "-v"], check=False)
        if privilege.returncode != 0:
            raise FrameworkError("unable to establish sudo credentials for powermetrics")

        verification = subprocess.run(
            [sudo, "-n", "-v"],
            check=False,
            text=True,
            capture_output=True,
        )
        if verification.returncode != 0:
            detail = verification.stderr.strip() or "sudo credential is not reusable non-interactively"
            raise FrameworkError(
                "unable to reuse sudo credentials for persistent powermetrics: "
                + detail
            )

        interval_ms = max(
            100,
            int(round(
                self.control["host_state"]["temperature"]["sampler_interval_seconds"]
                * 1000.0
            )),
        )
        command = [
            sudo,
            "-n",
            powermetrics,
            "--samplers",
            "smc,thermal",
            "-i",
            str(interval_ms),
        ]
        try:
            self.process = _launch_persistent_powermetrics(command)
        except OSError as exc:
            raise FrameworkError(f"unable to start persistent powermetrics sampler: {exc}") from exc

        assert self.process.stdout is not None
        assert self.process.stderr is not None
        stdout_thread = threading.Thread(
            target=self._consume_stdout,
            args=(self.process.stdout,),
            name="ngi541-powermetrics-stdout",
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=self._consume_stderr,
            args=(self.process.stderr,),
            name="ngi541-powermetrics-stderr",
            daemon=True,
        )
        self._threads = [stdout_thread, stderr_thread]
        for thread in self._threads:
            thread.start()

        timeout = self.control["host_state"]["temperature"]["sampler_start_timeout_seconds"]
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                error = self._stderr_text() or f"exit code {self.process.returncode}"
                self.stop()
                raise FrameworkError(
                    "persistent powermetrics sampler exited before the first "
                    f"temperature sample: {error}"
                )
            if self.temperature_record()["temperature_c"] is not None:
                return
            time.sleep(0.1)

        error = self._stderr_text()
        self.stop()
        suffix = f": {error}" if error else ""
        raise FrameworkError(
            "persistent powermetrics sampler did not provide a temperature "
            f"sample within {timeout:g}s{suffix}"
        )

    def _consume_stdout(self, stream) -> None:
        for line in stream:
            temp = _parse_temperature(line)
            pressure = _parse_thermal_pressure(line)
            if temp is None and pressure is None:
                continue
            with self._lock:
                if temp is not None:
                    self._temperature_c = temp
                    self._sample_monotonic = time.monotonic()
                if pressure is not None:
                    self._thermal_pressure = pressure

    def _consume_stderr(self, stream) -> None:
        for line in stream:
            stripped = line.strip()
            if not stripped:
                continue
            with self._lock:
                self._stderr_lines.append(stripped)
                del self._stderr_lines[:-20]

    def _stderr_text(self) -> str:
        with self._lock:
            return " | ".join(self._stderr_lines)[-800:]

    def temperature_record(self) -> dict[str, Any]:
        with self._lock:
            temperature = self._temperature_c
            pressure = self._thermal_pressure
            sampled = self._sample_monotonic

        age = None if sampled is None else max(0.0, time.monotonic() - sampled)
        max_age = self.control["host_state"]["temperature"]["max_sample_age_seconds"]
        stale = age is None or age > max_age
        process_rc = self.process.poll() if self.process is not None else None
        error = None
        if process_rc is not None:
            error = self._stderr_text() or f"powermetrics exited with code {process_rc}"
        elif stale:
            error = "persistent powermetrics sample is unavailable or stale"

        return {
            "temperature_c": None if stale else temperature,
            "thermal_pressure": pressure,
            "temperature_source": "powermetrics-persistent",
            "temperature_command": None,
            "temperature_command_exit_code": process_rc,
            "temperature_error": error,
            "temperature_sample_age_seconds": age,
        }

    def stop(self) -> None:
        process = self.process
        self.process = None
        if process is None:
            return
        if process.poll() is None:
            # The sampler intentionally remains in the framework's login
            # session so sudo can reuse the TTY-scoped credential.  Do not kill
            # a process group here: that could target the shell/framework group.
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for thread in self._threads:
            thread.join(timeout=0.5)
        self._threads = []

    def __enter__(self) -> "DarwinPowermetricsSampler":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()


@contextmanager
def host_state_session(control: dict[str, Any]) -> Iterator[DarwinPowermetricsSampler | None]:
    control = normalize_measurement_control(control)
    sampler = DarwinPowermetricsSampler(control)
    if sampler.required:
        with sampler:
            yield sampler
    else:
        yield None


def _darwin_temperature(
    command: list[str] | None,
    session: DarwinPowermetricsSampler | None = None,
) -> dict[str, Any]:
    if session is not None:
        return session.temperature_record()

    if command is None:
        powermetrics = shutil.which("powermetrics") or "/usr/bin/powermetrics"
        command = [
            "/usr/bin/sudo",
            "-n",
            powermetrics,
            "--samplers",
            "smc,thermal",
            "-n",
            "1",
        ]
        source = "powermetrics-one-shot"
    else:
        source = "command"
    rc, stdout, stderr = _run(command, timeout=12.0)
    combined = stdout + "\n" + stderr
    return {
        "temperature_c": _parse_temperature(combined) if rc == 0 else None,
        "thermal_pressure": _parse_thermal_pressure(combined) if rc == 0 else None,
        "temperature_source": source,
        "temperature_command": command,
        "temperature_command_exit_code": rc,
        "temperature_error": stderr.strip()[:400] if rc != 0 else None,
        "temperature_sample_age_seconds": 0.0 if rc == 0 else None,
    }


def _linux_temperature(command: list[str] | None) -> dict[str, Any]:
    if command is not None:
        rc, stdout, stderr = _run(command)
        combined = stdout + "\n" + stderr
        return {
            "temperature_c": _parse_temperature(combined) if rc == 0 else None,
            "temperature_source": "command",
            "temperature_command": command,
            "temperature_command_exit_code": rc,
            "temperature_error": stderr.strip()[:400] if rc != 0 else None,
            "temperature_sample_age_seconds": 0.0 if rc == 0 else None,
        }

    candidates = sorted(Path("/sys/class/thermal").glob("thermal_zone*/temp"))
    for path in candidates:
        try:
            raw = path.read_text(encoding="utf-8").strip()
            value = float(raw)
            if value > 1000:
                value /= 1000.0
            return {
                "temperature_c": value,
                "temperature_source": str(path),
                "temperature_command": None,
                "temperature_command_exit_code": 0,
                "temperature_error": None,
                "temperature_sample_age_seconds": 0.0,
            }
        except (OSError, ValueError):
            continue
    return {
        "temperature_c": None,
        "temperature_source": None,
        "temperature_command": None,
        "temperature_command_exit_code": 127,
        "temperature_error": "no readable Linux thermal zone",
        "temperature_sample_age_seconds": None,
    }


def _darwin_power() -> dict[str, Any]:
    pmset = shutil.which("pmset") or "/usr/bin/pmset"
    rc, stdout, stderr = _run([pmset, "-g", "batt"])
    source = "unknown"
    battery_percent = None
    if rc == 0:
        match = re.search(r"Now drawing from '([^']+)'", stdout)
        if match:
            text = match.group(1).lower()
            source = "ac" if "ac" in text else "battery" if "battery" in text else text
        match = re.search(r"(\d{1,3})%", stdout)
        if match:
            battery_percent = int(match.group(1))
    return {
        "source": source,
        "battery_percent": battery_percent,
        "provider_exit_code": rc,
        "provider_error": stderr.strip()[:400] if rc != 0 else None,
    }


def _darwin_thermal(logical_cpus: int, thermal_pressure: str | None = None) -> dict[str, Any]:
    pmset = shutil.which("pmset") or "/usr/bin/pmset"
    rc, stdout, stderr = _run([pmset, "-g", "therm"])

    def integer(name: str) -> int | None:
        match = re.search(rf"{re.escape(name)}\s*=\s*(\d+)", stdout)
        return int(match.group(1)) if match else None

    scheduler = integer("CPU_Scheduler_Limit")
    available = integer("CPU_Available_CPUs")
    speed = integer("CPU_Speed_Limit")

    # Keep thermal-pressure telemetry distinct from an actual CPU-capacity
    # restriction.  On Darwin, powermetrics may report a non-nominal thermal
    # pressure while pmset still exposes the full scheduler/speed/CPU capacity.
    # A continuously running fan or elevated thermal pressure is therefore
    # evidence, not by itself proof that benchmark throughput is being capped.
    performance_limited = False
    known = False
    for value in (scheduler, speed):
        if value is not None:
            known = True
            performance_limited = performance_limited or value < 100
    if available is not None:
        known = True
        performance_limited = performance_limited or available < logical_cpus

    pressure = thermal_pressure.lower() if isinstance(thermal_pressure, str) else None
    pressure_constrained = pressure is not None and pressure not in {"nominal"}
    if pressure is not None:
        known = True

    warning_text = stdout.lower()
    if "no thermal warning" in warning_text or "no performance warning" in warning_text:
        known = True
    if "thermal warning" in warning_text and "no thermal warning" not in warning_text:
        performance_limited = True
        known = True
    if "performance warning" in warning_text and "no performance warning" not in warning_text:
        performance_limited = True
        known = True

    constrained = performance_limited or pressure_constrained

    return {
        "thermal_state": "constrained" if constrained else "nominal" if known else "unknown",
        "thermal_pressure": pressure,
        "thermal_pressure_constrained": pressure_constrained if pressure is not None else None,
        "performance_limit_active": performance_limited if known else None,
        "throttling_active": performance_limited if known else None,
        "cpu_scheduler_limit_percent": scheduler,
        "cpu_available_cpus": available,
        "cpu_speed_limit_percent": speed,
        "provider_exit_code": rc,
        "provider_error": stderr.strip()[:400] if rc != 0 else None,
    }


def _linux_power() -> dict[str, Any]:
    for path in sorted(Path("/sys/class/power_supply").glob("*/online")):
        try:
            online = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if online == "1":
            return {"source": "ac", "battery_percent": None}
    for path in sorted(Path("/sys/class/power_supply").glob("*/capacity")):
        try:
            percent = int(path.read_text(encoding="utf-8").strip())
            return {"source": "battery", "battery_percent": percent}
        except (OSError, ValueError):
            continue
    return {"source": "unknown", "battery_percent": None}


def _linux_thermal(logical_cpus: int) -> dict[str, Any]:
    # Generic Linux does not expose one portable "currently throttled" bit.
    # Preserve unknown rather than inferring throttling from current frequency.
    return {
        "thermal_state": "unknown",
        "throttling_active": None,
        "cpu_scheduler_limit_percent": None,
        "cpu_available_cpus": logical_cpus,
        "cpu_speed_limit_percent": None,
    }


def _darwin_cpu_busy_percent() -> float | None:
    top = shutil.which("top") or "/usr/bin/top"
    rc, stdout, _ = _run([top, "-l", "1", "-n", "0"], timeout=5.0)
    if rc != 0:
        return None
    match = re.search(r"CPU usage:.*?([0-9]+(?:\.[0-9]+)?)%\s*idle", stdout)
    if not match:
        return None
    return max(0.0, min(100.0, 100.0 - float(match.group(1))))


def _linux_cpu_busy_percent() -> float | None:
    def sample() -> tuple[int, int] | None:
        try:
            parts = Path("/proc/stat").read_text(encoding="utf-8").splitlines()[0].split()
            values = [int(value) for value in parts[1:]]
        except (OSError, ValueError, IndexError):
            return None
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        total = sum(values)
        return total, idle

    first = sample()
    if first is None:
        return None
    time.sleep(0.2)
    second = sample()
    if second is None:
        return None
    total_delta = second[0] - first[0]
    idle_delta = second[1] - first[1]
    if total_delta <= 0:
        return None
    return max(0.0, min(100.0, (1.0 - idle_delta / total_delta) * 100.0))


def capture_host_state(
    control: dict[str, Any],
    *,
    session: DarwinPowermetricsSampler | None = None,
) -> dict[str, Any]:
    control = normalize_measurement_control(control)
    system = platform.system()
    logical_cpus = os.cpu_count() or 1
    load1, load5, load15 = os.getloadavg()
    temperature_cfg = control["host_state"]["temperature"]
    temperature_command = temperature_cfg.get("command")

    if system == "Darwin":
        power = _darwin_power()
        temperature = _darwin_temperature(temperature_command, session=session)
        thermal = _darwin_thermal(logical_cpus, temperature.get("thermal_pressure"))
        cpu_busy_percent = _darwin_cpu_busy_percent()
        provider = "darwin"
    elif system == "Linux":
        power = _linux_power()
        thermal = _linux_thermal(logical_cpus)
        temperature = _linux_temperature(temperature_command)
        cpu_busy_percent = _linux_cpu_busy_percent()
        provider = "linux"
    else:
        power = {"source": "unknown", "battery_percent": None}
        thermal = {
            "thermal_state": "unknown",
            "throttling_active": None,
            "cpu_scheduler_limit_percent": None,
            "cpu_available_cpus": logical_cpus,
            "cpu_speed_limit_percent": None,
        }
        temperature = {
            "temperature_c": None,
            "temperature_source": None,
            "temperature_command": temperature_command,
            "temperature_command_exit_code": 127,
            "temperature_error": f"unsupported host-state platform: {system}",
            "temperature_sample_age_seconds": None,
        }
        cpu_busy_percent = None
        provider = system.lower() or "unknown"

    return {
        "schema_version": 2,
        "captured_at": utc_rfc3339(),
        "monotonic_ns": time.monotonic_ns(),
        "provider": provider,
        "system": system,
        "logical_cpus": logical_cpus,
        "temperature": temperature,
        "thermal": thermal,
        "power": power,
        "load": {
            "cpu_busy_percent": cpu_busy_percent,
            "load_1m": load1,
            "load_5m": load5,
            "load_15m": load15,
            "load_1m_per_logical_cpu": load1 / logical_cpus,
        },
    }


def static_readiness(snapshot: dict[str, Any], control: dict[str, Any]) -> dict[str, Any]:
    host = control["host_state"]
    reasons: list[str] = []
    fatal = False

    temperature = snapshot.get("temperature", {}).get("temperature_c")
    if host["temperature"]["required"] and temperature is None:
        reasons.append("temperature-unavailable")
        fatal = True

    if host["require_ac_power"] and snapshot.get("power", {}).get("source") != "ac":
        reasons.append("ac-power-required")

    if host["require_no_throttling"]:
        active = snapshot.get("thermal", {}).get("throttling_active")
        if active is True:
            reasons.append("thermal-or-performance-throttling-active")
        elif active is None:
            reasons.append("throttling-state-unavailable")
            fatal = True

    return {"ready": not reasons, "reasons": reasons, "fatal": fatal}


def _nearest_rank(values: list[float], quantile: float) -> float:
    if not values:
        raise FrameworkError("cannot calculate a quantile from an empty sample")
    ordered = sorted(values)
    rank = max(1, math.ceil(quantile * len(ordered)))
    return ordered[rank - 1]


def calibrate_host_state(
    control: dict[str, Any],
    *,
    session: DarwinPowermetricsSampler | None = None,
    on_snapshot: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    control = normalize_measurement_control(control)
    cfg = control["calibration"]
    if not control["host_state"]["enabled"] or not cfg["enabled"]:
        return {
            "schema_version": 2,
            "enabled": False,
            "algorithm": None,
            "cpu_busy_percent": None,
            "temperature_c": None,
        }

    started_at = utc_rfc3339()
    target_samples = int(cfg["samples"])
    interval = float(cfg["sample_interval_seconds"])
    timeout = float(cfg["timeout_seconds"])
    deadline = time.monotonic() + timeout

    busy_values: list[float] = []
    temperature_values: list[float] = []
    accepted_samples = 0
    observed_snapshots = 0
    rejected_snapshots = 0
    window_resets = 0
    next_sample_at = time.monotonic()
    last_reasons: list[str] = []

    # Calibration is a consecutive window of statically acceptable host state.
    # A transient AC/thermal/performance constraint is not fatal: wait for the
    # host to recover and restart the baseline window. This keeps calibration
    # state-driven without weakening the no-throttling policy or introducing a
    # fixed cooldown delay.
    while accepted_samples < target_samples:
        delay = next_sample_at - time.monotonic()
        if delay > 0:
            time.sleep(delay)

        snapshot = capture_host_state(control, session=session)
        static = static_readiness(snapshot, control)
        observed_snapshots += 1

        # CPU-busy telemetry is required to build the calibrated envelope, but
        # an individual missing sample is not a fatal capability loss.  The
        # Darwin provider obtains this value from a short `top` invocation,
        # which can occasionally fail or time out under transient host load.
        # Treat that exactly like any other rejected calibration sample: reset
        # the consecutive clean window and wait for a fresh sample.  Persistent
        # loss is still bounded by the calibration timeout.
        busy = snapshot.get("load", {}).get("cpu_busy_percent")
        sample_reasons = list(static["reasons"])
        sample_ready = bool(static["ready"])
        if sample_ready and not isinstance(busy, (int, float)):
            sample_reasons.append("cpu-busy-state-unavailable")
            sample_ready = False
        last_reasons = sample_reasons

        snapshot["calibration"] = {
            "observed_snapshot": observed_snapshots,
            "accepted_sample": accepted_samples + 1 if sample_ready else None,
            "samples": target_samples,
            "static_ready": static["ready"],
            "sample_ready": sample_ready,
            "reasons": sample_reasons,
            "window_resets": window_resets,
        }
        if on_snapshot is not None:
            on_snapshot(snapshot)

        if static["fatal"]:
            raise FrameworkError(
                "host calibration cannot proceed: " + ", ".join(static["reasons"])
            )

        if not sample_ready:
            rejected_snapshots += 1
            if accepted_samples:
                window_resets += 1
            accepted_samples = 0
            busy_values.clear()
            temperature_values.clear()
        else:
            busy_values.append(float(busy))

            temperature = snapshot.get("temperature", {}).get("temperature_c")
            if isinstance(temperature, (int, float)):
                temperature_values.append(float(temperature))
            accepted_samples += 1

        if accepted_samples >= target_samples:
            break

        if time.monotonic() >= deadline:
            reasons = last_reasons or [
                f"waiting-for-{target_samples}-consecutive-static-ready-samples"
            ]
            raise FrameworkError(
                "host calibration timeout after "
                f"{timeout:g}s: " + ", ".join(reasons)
            )

        next_sample_at = time.monotonic() + interval

    quantile = float(cfg["cpu_busy_upper_quantile"])
    limit = _nearest_rank(busy_values, quantile)
    temp_summary = None
    if temperature_values:
        temp_summary = {
            "min": min(temperature_values),
            "median": statistics.median(temperature_values),
            "max": max(temperature_values),
        }

    return {
        "schema_version": 2,
        "enabled": True,
        "started_at": started_at,
        "finished_at": utc_rfc3339(),
        "algorithm": "consecutive-static-ready-nearest-rank-upper-quantile",
        "samples_requested": target_samples,
        "samples_collected": accepted_samples,
        "snapshots_observed": observed_snapshots,
        "snapshots_rejected_static": rejected_snapshots,
        "window_resets": window_resets,
        "sample_interval_seconds": interval,
        "timeout_seconds": timeout,
        "cpu_busy_percent": {
            "min": min(busy_values),
            "median": statistics.median(busy_values),
            "mean": statistics.fmean(busy_values),
            "max": max(busy_values),
            "upper_quantile": quantile,
            "upper_limit": limit,
        },
        "temperature_c": temp_summary,
    }


def readiness(
    snapshot: dict[str, Any],
    control: dict[str, Any],
    calibration: dict[str, Any] | None = None,
) -> dict[str, Any]:
    control = normalize_measurement_control(control)
    host = control["host_state"]
    if not host["enabled"]:
        return {"ready": True, "reasons": [], "fatal": False}

    result = static_readiness(snapshot, control)
    reasons = list(result["reasons"])
    fatal = bool(result["fatal"])

    if control["calibration"]["enabled"]:
        cpu_cal = (calibration or {}).get("cpu_busy_percent")
        upper_limit = cpu_cal.get("upper_limit") if isinstance(cpu_cal, dict) else None
        if not isinstance(upper_limit, (int, float)):
            reasons.append("cpu-busy-calibration-unavailable")
            fatal = True
        else:
            current_busy = snapshot.get("load", {}).get("cpu_busy_percent")
            if not isinstance(current_busy, (int, float)):
                # A single CPU-busy sample can be unavailable transiently
                # (for example if the Darwin `top` snapshot times out).
                # Capabilities were verified before execution, so make this a
                # retryable readiness miss rather than aborting the campaign.
                # Persistent loss still ends at the readiness timeout.
                reasons.append("cpu-busy-state-unavailable")
            elif float(current_busy) > float(upper_limit):
                reasons.append("cpu-busy-above-calibrated-envelope")

    return {"ready": not reasons, "reasons": reasons, "fatal": fatal}


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(encoded + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def wait_until_ready(
    control: dict[str, Any],
    *,
    calibration: dict[str, Any] | None = None,
    session: DarwinPowermetricsSampler | None = None,
    on_snapshot: Callable[[dict[str, Any]], None],
) -> tuple[dict[str, Any], int, int]:
    control = normalize_measurement_control(control)
    required_streak = control["readiness"]["required_consecutive_ready_samples"]
    if not control["host_state"]["enabled"]:
        snapshot = {
            "schema_version": 2,
            "captured_at": utc_rfc3339(),
            "monotonic_ns": time.monotonic_ns(),
            "provider": "disabled",
            "temperature": {"temperature_c": None},
            "thermal": {"thermal_state": "unknown", "throttling_active": None},
            "power": {"source": "unknown", "battery_percent": None},
            "load": {"cpu_busy_percent": None},
            "readiness": {
                "ready": True,
                "reasons": [],
                "fatal": False,
                "consecutive_ready_samples": required_streak,
                "required_consecutive_ready_samples": required_streak,
            },
        }
        return snapshot, 0, 0

    timeout = control["readiness"]["timeout_seconds"]
    interval = control["readiness"]["poll_interval_seconds"]
    deadline = time.monotonic() + timeout
    started = time.perf_counter_ns()
    samples = 0
    streak = 0

    while True:
        snapshot = capture_host_state(control, session=session)
        result = readiness(snapshot, control, calibration)
        samples += 1
        if result["ready"]:
            streak += 1
        else:
            streak = 0
        result = dict(result)
        result["consecutive_ready_samples"] = streak
        result["required_consecutive_ready_samples"] = required_streak
        snapshot["readiness"] = result
        on_snapshot(snapshot)

        if result["fatal"]:
            raise FrameworkError(
                "host readiness cannot be established: " + ", ".join(result["reasons"])
            )
        if result["ready"] and streak >= required_streak:
            return snapshot, samples, time.perf_counter_ns() - started
        if time.monotonic() >= deadline:
            current = result["reasons"] or [
                f"waiting-for-{required_streak}-consecutive-ready-samples"
            ]
            raise FrameworkError("host readiness timeout: " + ", ".join(current))
        time.sleep(interval)


def validate_host_state_capabilities(
    control: dict[str, Any],
    *,
    session: DarwinPowermetricsSampler | None = None,
) -> dict[str, Any]:
    control = normalize_measurement_control(control)
    if not control["host_state"]["enabled"]:
        return {
            "schema_version": 2,
            "passed": True,
            "errors": [],
            "snapshot": None,
            "static_readiness_at_preflight": {
                "ready": True,
                "reasons": [],
                "fatal": False,
            },
            "calibration_required": False,
        }

    snapshot = capture_host_state(control, session=session)
    static = static_readiness(snapshot, control)
    capability_errors: list[str] = []
    if control["host_state"]["temperature"]["required"]:
        if snapshot.get("temperature", {}).get("temperature_c") is None:
            capability_errors.append("required temperature telemetry is unavailable")
    if control["host_state"]["require_no_throttling"]:
        if snapshot.get("thermal", {}).get("throttling_active") is None:
            capability_errors.append("required throttling telemetry is unavailable")
    if control["calibration"]["enabled"]:
        if not isinstance(snapshot.get("load", {}).get("cpu_busy_percent"), (int, float)):
            capability_errors.append("required CPU busy telemetry is unavailable")

    return {
        "schema_version": 2,
        "passed": not capability_errors,
        "errors": capability_errors,
        "snapshot": snapshot,
        "static_readiness_at_preflight": static,
        "calibration_required": bool(control["calibration"]["enabled"]),
    }
