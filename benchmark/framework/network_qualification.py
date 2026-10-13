from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from framework.io_utils import FrameworkError, atomic_write_json, atomic_write_text
from framework.provenance import sha256_file


QUALIFICATION_SCHEMA_VERSION = 1


def _utc_id_timestamp(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _utc_rfc3339(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def definition_sha256(definition: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(definition)).hexdigest()


def _slug(text: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    if not value:
        raise FrameworkError("qualification.name must contain an alphanumeric character")
    return value


def generate_qualification_id(name: str) -> str:
    return f"{_slug(name)}-{_utc_id_timestamp()}-{secrets.token_hex(3)}"


def load_network_qualification_definition(path: Path) -> dict[str, Any]:
    try:
        definition = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FrameworkError(f"network qualification config not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise FrameworkError(
            f"invalid network qualification JSON: line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    validate_network_qualification_definition(definition)
    return definition


def validate_network_qualification_definition(definition: dict[str, Any]) -> None:
    if definition.get("schema_version") != QUALIFICATION_SCHEMA_VERSION:
        raise FrameworkError("network qualification schema_version must be 1")

    qualification = definition.get("qualification")
    if not isinstance(qualification, dict):
        raise FrameworkError("qualification must be an object")
    if not isinstance(qualification.get("name"), str) or not qualification["name"].strip():
        raise FrameworkError("qualification.name must be a non-empty string")

    local = definition.get("local")
    remote = definition.get("remote")
    tests = definition.get("tests")
    if not isinstance(local, dict):
        raise FrameworkError("local must be an object")
    if not isinstance(remote, dict):
        raise FrameworkError("remote must be an object")
    if not isinstance(tests, dict):
        raise FrameworkError("tests must be an object")

    if local.get("provider") != "local":
        raise FrameworkError("R6.5.1 local.provider must be 'local'")
    if local.get("role") not in {"dut", "loadgen", "peer"}:
        raise FrameworkError("local.role must be dut, loadgen, or peer")

    if remote.get("provider") != "linux-ssh":
        raise FrameworkError("R6.5.1 remote.provider must be 'linux-ssh'")
    if remote.get("role") not in {"dut", "loadgen", "peer"}:
        raise FrameworkError("remote.role must be dut, loadgen, or peer")
    if not isinstance(remote.get("ssh_target"), str) or not remote["ssh_target"].strip():
        raise FrameworkError("remote.ssh_target must be a non-empty string")
    if not isinstance(remote.get("data_address"), str) or not remote["data_address"].strip():
        raise FrameworkError("remote.data_address must be a non-empty string")

    ping = tests.get("ping", {})
    tcp = tests.get("tcp", {})
    udp = tests.get("udp", {})
    for name, section in (("ping", ping), ("tcp", tcp), ("udp", udp)):
        if not isinstance(section, dict):
            raise FrameworkError(f"tests.{name} must be an object")

    if ping.get("enabled", True):
        count = ping.get("count", 10)
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise FrameworkError("tests.ping.count must be a positive integer")

    if tcp.get("enabled", True):
        duration = tcp.get("duration_seconds", 10)
        if not isinstance(duration, int) or isinstance(duration, bool) or duration < 1:
            raise FrameworkError("tests.tcp.duration_seconds must be a positive integer")
        streams = tcp.get("parallel_streams", [1])
        if not isinstance(streams, list) or not streams:
            raise FrameworkError("tests.tcp.parallel_streams must be a non-empty list")
        if any(not isinstance(x, int) or isinstance(x, bool) or x < 1 for x in streams):
            raise FrameworkError("tests.tcp.parallel_streams entries must be positive integers")

    if udp.get("enabled", True):
        duration = udp.get("duration_seconds", 5)
        if not isinstance(duration, int) or isinstance(duration, bool) or duration < 1:
            raise FrameworkError("tests.udp.duration_seconds must be a positive integer")
        rates = udp.get("rates_mbps", [])
        if not isinstance(rates, list) or not rates:
            raise FrameworkError("tests.udp.rates_mbps must be a non-empty list")
        if any(not isinstance(x, (int, float)) or isinstance(x, bool) or x <= 0 for x in rates):
            raise FrameworkError("tests.udp.rates_mbps entries must be positive numbers")
        datagram = udp.get("datagram_bytes", 1200)
        if not isinstance(datagram, int) or isinstance(datagram, bool) or datagram < 1:
            raise FrameworkError("tests.udp.datagram_bytes must be a positive integer")

    reporting = definition.get("reporting", {})
    if not isinstance(reporting, dict):
        raise FrameworkError("reporting must be an object")
    loss_ref = reporting.get("udp_reference_max_loss_percent", 0.1)
    if not isinstance(loss_ref, (int, float)) or isinstance(loss_ref, bool) or loss_ref < 0:
        raise FrameworkError("reporting.udp_reference_max_loss_percent must be >= 0")


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    started_at: str
    finished_at: str
    elapsed_ns: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "argv": self.argv,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed_ns": self.elapsed_ns,
        }


def run_command(
    argv: list[str],
    *,
    check: bool = False,
    timeout: float | None = None,
    env: dict[str, str] | None = None,
) -> CommandResult:
    started_at = _utc_rfc3339()
    started_ns = time.monotonic_ns()
    try:
        result = subprocess.run(
            argv,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise FrameworkError(f"command timed out: {shlex.join(argv)}") from exc
    finished_ns = time.monotonic_ns()
    record = CommandResult(
        argv=list(argv),
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
        started_at=started_at,
        finished_at=_utc_rfc3339(),
        elapsed_ns=finished_ns - started_ns,
    )
    if check and record.returncode != 0:
        detail = record.stderr.strip() or record.stdout.strip()
        raise FrameworkError(
            f"command failed ({record.returncode}): {shlex.join(argv)}"
            + (f": {detail}" if detail else "")
        )
    return record


def _write_command_record(raw_dir: Path, name: str, result: CommandResult) -> None:
    atomic_write_json(raw_dir / "commands" / f"{name}.json", result.as_dict())


def parse_darwin_route(text: str) -> dict[str, str | None]:
    result: dict[str, str | None] = {"interface": None, "gateway": None}
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("interface:"):
            result["interface"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("gateway:"):
            result["gateway"] = stripped.split(":", 1)[1].strip()
    return result


def parse_linux_route_get(text: str) -> dict[str, str | None]:
    first = text.strip().splitlines()[0] if text.strip() else ""
    tokens = first.split()
    result: dict[str, str | None] = {"interface": None, "source": None, "gateway": None}
    for key, out_key in (("dev", "interface"), ("src", "source"), ("via", "gateway")):
        if key in tokens:
            index = tokens.index(key)
            if index + 1 < len(tokens):
                result[out_key] = tokens[index + 1]
    return result


def parse_networksetup_ports(text: str) -> dict[str, str]:
    ports: dict[str, str] = {}
    current_port: str | None = None
    for line in text.splitlines():
        if line.startswith("Hardware Port:"):
            current_port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and current_port:
            device = line.split(":", 1)[1].strip()
            ports[device] = current_port
            current_port = None
    return ports


def parse_ethtool(text: str) -> dict[str, Any]:
    speed: int | None = None
    duplex: str | None = None
    link_detected: bool | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Speed:"):
            match = re.search(r"(\d+)Mb/s", stripped)
            if match:
                speed = int(match.group(1))
        elif stripped.startswith("Duplex:"):
            duplex = stripped.split(":", 1)[1].strip().lower()
        elif stripped.startswith("Link detected:"):
            value = stripped.split(":", 1)[1].strip().lower()
            link_detected = value == "yes"
    return {
        "speed_mbps": speed,
        "duplex": duplex,
        "link_detected": link_detected,
    }


def parse_ping_summary(text: str) -> dict[str, float | int | None]:
    loss_percent: float | None = None
    transmitted: int | None = None
    received: int | None = None
    minimum: float | None = None
    average: float | None = None
    maximum: float | None = None
    deviation: float | None = None

    packet = re.search(
        r"(\d+) packets transmitted,\s*(\d+) packets received,\s*([\d.]+)% packet loss",
        text,
    )
    if packet is None:
        packet = re.search(
            r"(\d+) packets transmitted,\s*(\d+) received,.*?([\d.]+)% packet loss",
            text,
        )
    if packet:
        transmitted = int(packet.group(1))
        received = int(packet.group(2))
        loss_percent = float(packet.group(3))

    timing = re.search(
        r"(?:round-trip|rtt) min/avg/max/(?:stddev|mdev) = "
        r"([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms",
        text,
    )
    if timing:
        minimum = float(timing.group(1))
        average = float(timing.group(2))
        maximum = float(timing.group(3))
        deviation = float(timing.group(4))

    return {
        "transmitted": transmitted,
        "received": received,
        "packet_loss_percent": loss_percent,
        "rtt_min_ms": minimum,
        "rtt_avg_ms": average,
        "rtt_max_ms": maximum,
        "rtt_deviation_ms": deviation,
    }


def _load_iperf_json(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise FrameworkError(f"iperf3 did not return valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise FrameworkError("iperf3 JSON must be an object")
    if value.get("error"):
        raise FrameworkError(f"iperf3 error: {value['error']}")
    return value


def parse_iperf_tcp(text: str) -> dict[str, Any]:
    value = _load_iperf_json(text)
    end = value.get("end") or {}
    received = end.get("sum_received") or {}
    sent = end.get("sum_sent") or {}
    bps = received.get("bits_per_second")
    if not isinstance(bps, (int, float)):
        bps = sent.get("bits_per_second")
    if not isinstance(bps, (int, float)):
        raise FrameworkError("iperf3 TCP JSON has no throughput")
    retransmits = sent.get("retransmits")
    return {
        "throughput_mbps": float(bps) / 1_000_000.0,
        "retransmits": int(retransmits) if isinstance(retransmits, int) else None,
        "seconds": received.get("seconds") or sent.get("seconds"),
    }


def parse_iperf_udp(text: str) -> dict[str, Any]:
    value = _load_iperf_json(text)
    end = value.get("end") or {}
    summary = end.get("sum") or end.get("sum_received") or {}
    bps = summary.get("bits_per_second")
    if not isinstance(bps, (int, float)):
        raise FrameworkError("iperf3 UDP JSON has no throughput")
    lost_percent = summary.get("lost_percent")
    jitter_ms = summary.get("jitter_ms")
    return {
        "throughput_mbps": float(bps) / 1_000_000.0,
        "lost_percent": float(lost_percent) if isinstance(lost_percent, (int, float)) else None,
        "jitter_ms": float(jitter_ms) if isinstance(jitter_ms, (int, float)) else None,
        "packets": summary.get("packets"),
        "lost_packets": summary.get("lost_packets"),
        "seconds": summary.get("seconds"),
    }


class SSHSession:
    def __init__(self, target: str, connect_timeout_seconds: int = 10):
        self.target = target
        self.connect_timeout_seconds = connect_timeout_seconds
        self.control_path = str(
            Path(tempfile.gettempdir()) / f"ngi541-netq-{secrets.token_hex(6)}.sock"
        )
        self.started = False

    def _base(self) -> list[str]:
        return [
            "ssh",
            "-o", "ControlMaster=auto",
            # Prevent an ssh-agent with many unrelated keys from exhausting
            # the server's MaxAuthTries before password authentication is offered.
            "-o", "IdentitiesOnly=yes",
            "-o", f"ControlPath={self.control_path}",
            "-o", "ControlPersist=300",
            "-o", f"ConnectTimeout={self.connect_timeout_seconds}",
        ]

    def start(self) -> None:
        if shutil.which("ssh") is None:
            raise FrameworkError("ssh is required for remote network qualification")
        # The first connection is deliberately interactive: without a key the user
        # authenticates once, then ControlMaster is reused for the full qualification.
        result = subprocess.run(
            [*self._base(), "-MNf", self.target],
            check=False,
        )
        if result.returncode != 0:
            raise FrameworkError(f"unable to establish SSH control connection to {self.target}")
        self.started = True

    def close(self) -> None:
        if not self.started:
            return
        subprocess.run(
            [*self._base(), "-O", "exit", self.target],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.started = False
        try:
            Path(self.control_path).unlink()
        except FileNotFoundError:
            pass

    def run(self, argv: list[str], *, check: bool = False, timeout: float | None = None) -> CommandResult:
        command = shlex.join(argv)
        return run_command(
            [*self._base(), self.target, command],
            check=check,
            timeout=timeout,
        )

    def run_interactive(self, command: str) -> int:
        return subprocess.run(
            [*self._base(), "-t", self.target, command],
            check=False,
        ).returncode

    def __enter__(self) -> "SSHSession":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def _which_any(candidates: list[str]) -> str | None:
    for candidate in candidates:
        if os.path.isabs(candidate) and Path(candidate).is_file():
            return candidate
        found = shutil.which(candidate)
        if found:
            return found
    return None


def _ensure_local_iperf3(*, bootstrap: bool) -> str:
    binary = shutil.which("iperf3")
    if binary:
        return binary
    if not bootstrap:
        raise FrameworkError(
            "local iperf3 is missing; rerun with --bootstrap or install iperf3 first"
        )
    if os.uname().sysname != "Darwin":
        raise FrameworkError("automatic local iperf3 bootstrap is currently supported only on Darwin")
    brew = _which_any(["brew", "/opt/homebrew/bin/brew", "/usr/local/bin/brew"])
    if brew is None:
        raise FrameworkError("Homebrew is required for automatic iperf3 installation on Darwin")
    result = subprocess.run([brew, "install", "iperf3"], check=False)
    if result.returncode != 0:
        raise FrameworkError("Homebrew failed to install iperf3")
    binary = shutil.which("iperf3") or _which_any([
        "/opt/homebrew/bin/iperf3",
        "/usr/local/bin/iperf3",
    ])
    if binary is None:
        raise FrameworkError("iperf3 is still unavailable after Homebrew installation")
    return binary


def parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"').strip("'")
    return values


def _bullseye_archive_install_command() -> str:
    # Debian 11/Bullseye is EOL. Avoid rewriting /etc/apt sources on the
    # qualification peer; provision iperf3 from an isolated archive source.
    return (
        "set -eu; "
        "src=$(mktemp /tmp/ngi541-bullseye-archive.XXXXXX.list); "
        "trap 'rm -f \"$src\"' EXIT; "
        "printf '%s\\n' 'deb https://archive.debian.org/debian bullseye main' > \"$src\"; "
        "sudo apt-get "
        "-o Dir::Etc::sourcelist=\"$src\" "
        "-o Dir::Etc::sourceparts=- "
        "-o APT::Get::List-Cleanup=0 "
        "-o Acquire::Check-Valid-Until=false update; "
        "sudo env DEBIAN_FRONTEND=noninteractive apt-get "
        "-o Dir::Etc::sourcelist=\"$src\" "
        "-o Dir::Etc::sourceparts=- "
        "-o APT::Get::List-Cleanup=0 "
        "-o Acquire::Check-Valid-Until=false install -y iperf3"
    )


def _ensure_remote_iperf3(ssh: SSHSession, *, bootstrap: bool) -> str:
    probe = ssh.run(["sh", "-lc", "command -v iperf3 || true"], check=True)
    binary = probe.stdout.strip().splitlines()[0] if probe.stdout.strip() else ""
    if binary:
        return binary
    if not bootstrap:
        raise FrameworkError(
            "remote iperf3 is missing; rerun with --bootstrap or install iperf3 on the remote host"
        )

    os_release_result = ssh.run(["cat", "/etc/os-release"], check=False)
    os_release = parse_os_release(os_release_result.stdout)
    codename = os_release.get("VERSION_CODENAME", "").lower()
    version_id = os_release.get("VERSION_ID", "")

    if codename == "bullseye" or version_id == "11":
        print(
            "remote-bootstrap: Debian/Raspberry Pi OS Bullseye detected; "
            "using isolated archive.debian.org source",
            flush=True,
        )
        rc = ssh.run_interactive(_bullseye_archive_install_command())
    else:
        command = (
            "sudo apt-get update && "
            "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y iperf3"
        )
        rc = ssh.run_interactive(command)

    if rc != 0:
        raise FrameworkError("remote package manager failed to install iperf3")
    probe = ssh.run(["sh", "-lc", "command -v iperf3 || true"], check=True)
    binary = probe.stdout.strip().splitlines()[0] if probe.stdout.strip() else ""
    if not binary:
        raise FrameworkError("remote iperf3 is still unavailable after installation")
    return binary

def _local_data_path(remote_address: str, raw_dir: Path) -> dict[str, Any]:
    if os.uname().sysname == "Darwin":
        route = run_command(["route", "-n", "get", remote_address], check=True)
        _write_command_record(raw_dir, "local-route", route)
        parsed = parse_darwin_route(route.stdout)
        interface = parsed["interface"]
        if not interface:
            raise FrameworkError("unable to determine local interface for remote data address")
        address = run_command(["ipconfig", "getifaddr", str(interface)], check=True)
        _write_command_record(raw_dir, "local-address", address)
        ports = run_command(["networksetup", "-listallhardwareports"], check=True)
        _write_command_record(raw_dir, "local-network-hardware", ports)
        port_map = parse_networksetup_ports(ports.stdout)
        ifconfig = run_command(["ifconfig", str(interface)], check=True)
        _write_command_record(raw_dir, "local-ifconfig", ifconfig)
        return {
            "system": "Darwin",
            "interface": interface,
            "address": address.stdout.strip(),
            "hardware_port": port_map.get(str(interface)),
            "gateway": parsed.get("gateway"),
        }
    raise FrameworkError("R6.5.1 local data-path discovery currently supports Darwin")


def _resolve_remote_binary(
    ssh: SSHSession,
    name: str,
    fallback_paths: list[str],
) -> str | None:
    # Non-interactive SSH sessions can have a narrower PATH than an interactive
    # login shell (notably omitting /usr/sbin on Debian/Raspberry Pi OS).
    probe = ssh.run(["sh", "-lc", f"command -v {shlex.quote(name)} || true"], check=True)
    if probe.stdout.strip():
        return probe.stdout.strip().splitlines()[0]
    for candidate in fallback_paths:
        exists = ssh.run(["test", "-x", candidate], check=False)
        if exists.returncode == 0:
            return candidate
    return None


def _remote_data_path(ssh: SSHSession, local_address: str, raw_dir: Path) -> dict[str, Any]:
    route = ssh.run(["ip", "route", "get", local_address], check=True)
    _write_command_record(raw_dir, "remote-route", route)
    parsed = parse_linux_route_get(route.stdout)
    interface = parsed["interface"]
    if not interface:
        raise FrameworkError("unable to determine remote interface for local data address")

    ethtool_binary = _resolve_remote_binary(
        ssh,
        "ethtool",
        ["/usr/sbin/ethtool", "/sbin/ethtool"],
    )
    if ethtool_binary is None:
        eth = {
            "speed_mbps": None,
            "duplex": None,
            "link_detected": None,
        }
    else:
        ethtool = ssh.run([ethtool_binary, str(interface)], check=False)
        _write_command_record(raw_dir, "remote-ethtool", ethtool)
        eth = parse_ethtool(ethtool.stdout) if ethtool.returncode == 0 else {
            "speed_mbps": None,
            "duplex": None,
            "link_detected": None,
        }
    return {
        "system": "Linux",
        "interface": interface,
        "address": parsed.get("source"),
        "gateway": parsed.get("gateway"),
        **eth,
    }


def _topology_class(local: dict[str, Any], remote: dict[str, Any]) -> str:
    local_port = (local.get("hardware_port") or "").lower()
    remote_wired = bool(remote.get("speed_mbps")) and remote.get("link_detected") is not False
    if "wi-fi" in local_port or "wifi" in local_port:
        return "mixed-wired-wifi" if remote_wired else "wifi-path"
    if "ethernet" in local_port and remote_wired:
        return "wired-wired"
    return "mixed-or-unknown"


@contextmanager
def _iperf_server(binary: str, bind_address: str, port: int, raw_dir: Path) -> Iterator[None]:
    stdout_path = raw_dir / "iperf3-server.stdout.log"
    stderr_path = raw_dir / "iperf3-server.stderr.log"
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open("w", encoding="utf-8") as stderr:
        proc = subprocess.Popen(
            [binary, "-s", "-B", bind_address, "-p", str(port)],
            stdout=stdout,
            stderr=stderr,
            text=True,
        )
        try:
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise FrameworkError(
                        f"iperf3 server exited early; inspect {stderr_path}"
                    )
                time.sleep(0.1)
                # Avoid connecting to the control socket because that would create a
                # synthetic iperf session. A short process-alive stabilization window
                # is enough before the real client starts.
                if time.monotonic() + 4.5 >= deadline:
                    break
            yield
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)


def _inventory(ssh: SSHSession, raw_dir: Path) -> None:
    local_commands = {
        "local-uname": ["uname", "-a"],
        "local-system-version": ["sw_vers"],
    }
    remote_commands = {
        "remote-uname": ["uname", "-a"],
        "remote-os-release": ["cat", "/etc/os-release"],
        "remote-lscpu": ["lscpu"],
        "remote-link": ["ip", "-br", "link"],
        "remote-address": ["ip", "-br", "addr"],
    }
    for name, argv in local_commands.items():
        result = run_command(argv, check=False)
        _write_command_record(raw_dir, name, result)
    for name, argv in remote_commands.items():
        result = ssh.run(argv, check=False)
        _write_command_record(raw_dir, name, result)


def _run_ping_tests(
    definition: dict[str, Any],
    ssh: SSHSession,
    local_address: str,
    remote_address: str,
    raw_dir: Path,
) -> dict[str, Any]:
    cfg = definition["tests"].get("ping", {})
    if not cfg.get("enabled", True):
        return {"enabled": False}
    count = int(cfg.get("count", 10))
    interval = float(cfg.get("interval_seconds", 0.2))

    local = run_command(
        ["ping", "-c", str(count), "-i", str(interval), remote_address],
        check=False,
        timeout=max(10.0, count * interval + 10.0),
    )
    _write_command_record(raw_dir, "ping-local-to-remote", local)
    remote = ssh.run(
        ["ping", "-c", str(count), "-i", str(interval), local_address],
        check=False,
        timeout=max(10.0, count * interval + 10.0),
    )
    _write_command_record(raw_dir, "ping-remote-to-local", remote)

    return {
        "enabled": True,
        "local_to_remote": parse_ping_summary(local.stdout),
        "remote_to_local": parse_ping_summary(remote.stdout),
    }


def _run_iperf_tests(
    definition: dict[str, Any],
    ssh: SSHSession,
    local_iperf: str,
    remote_iperf: str,
    local_address: str,
    raw_dir: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    tests = definition["tests"]
    port = int(tests.get("iperf3_port", 5201))
    tcp_results: list[dict[str, Any]] = []
    udp_results: list[dict[str, Any]] = []

    with _iperf_server(local_iperf, local_address, port, raw_dir):
        tcp = tests.get("tcp", {})
        if tcp.get("enabled", True):
            duration = int(tcp.get("duration_seconds", 10))
            for streams in tcp.get("parallel_streams", [1]):
                for reverse, direction in ((False, "remote-to-local"), (True, "local-to-remote")):
                    argv = [
                        remote_iperf,
                        "-c", local_address,
                        "-p", str(port),
                        "-t", str(duration),
                        "-P", str(streams),
                        "-J",
                    ]
                    if reverse:
                        argv.append("-R")
                    name = f"iperf3-tcp-{direction}-p{streams}"
                    result = ssh.run(argv, check=True, timeout=duration + 20)
                    _write_command_record(raw_dir, name, result)
                    parsed = parse_iperf_tcp(result.stdout)
                    tcp_results.append({
                        "direction": direction,
                        "parallel_streams": streams,
                        **parsed,
                    })

        udp = tests.get("udp", {})
        if udp.get("enabled", True):
            duration = int(udp.get("duration_seconds", 5))
            datagram = int(udp.get("datagram_bytes", 1200))
            for rate in udp.get("rates_mbps", []):
                for reverse, direction in ((False, "remote-to-local"), (True, "local-to-remote")):
                    argv = [
                        remote_iperf,
                        "-c", local_address,
                        "-p", str(port),
                        "-u",
                        "-b", f"{rate}M",
                        "-l", str(datagram),
                        "-t", str(duration),
                        "-J",
                    ]
                    if reverse:
                        argv.append("-R")
                    rate_label = str(rate).replace(".", "p")
                    name = f"iperf3-udp-{direction}-{rate_label}mbps"
                    result = ssh.run(argv, check=True, timeout=duration + 20)
                    _write_command_record(raw_dir, name, result)
                    parsed = parse_iperf_udp(result.stdout)
                    udp_results.append({
                        "direction": direction,
                        "requested_mbps": float(rate),
                        "datagram_bytes": datagram,
                        **parsed,
                    })

    return tcp_results, udp_results


def _udp_reference(
    rows: list[dict[str, Any]],
    *,
    direction: str,
    max_loss_percent: float,
) -> dict[str, Any]:
    eligible = [
        row for row in rows
        if row["direction"] == direction
        and isinstance(row.get("lost_percent"), (int, float))
        and float(row["lost_percent"]) <= max_loss_percent
    ]
    if not eligible:
        return {
            "max_loss_percent": max_loss_percent,
            "highest_requested_mbps": None,
            "achieved_mbps": None,
        }
    best = max(eligible, key=lambda row: float(row["requested_mbps"]))
    return {
        "max_loss_percent": max_loss_percent,
        "highest_requested_mbps": best["requested_mbps"],
        "achieved_mbps": best["throughput_mbps"],
        "observed_loss_percent": best["lost_percent"],
        "jitter_ms": best["jitter_ms"],
    }


def _tcp_reference(rows: list[dict[str, Any]], direction: str) -> dict[str, Any]:
    selected = [row for row in rows if row["direction"] == direction]
    if not selected:
        return {"best_throughput_mbps": None, "parallel_streams": None}
    best = max(selected, key=lambda row: float(row["throughput_mbps"]))
    return {
        "best_throughput_mbps": best["throughput_mbps"],
        "parallel_streams": best["parallel_streams"],
        "retransmits": best["retransmits"],
    }


def _artifact_hashes(root: Path) -> str:
    lines: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.name == "artifacts.sha256":
            continue
        lines.append(f"{sha256_file(path)}  {path.relative_to(root)}")
    return "\n".join(lines) + "\n"



def _git_identity(repo_root: Path) -> dict[str, Any]:
    def git(*argv: str) -> CommandResult:
        return run_command(["git", "-C", str(repo_root), *argv], check=True)

    commit = git("rev-parse", "HEAD").stdout.strip()
    describe_result = run_command(
        ["git", "-C", str(repo_root), "describe", "--always", "--dirty"],
        check=False,
    )
    status = git("status", "--porcelain", "--untracked-files=no").stdout
    return {
        "commit": commit,
        "describe": describe_result.stdout.strip() if describe_result.returncode == 0 else None,
        "tracked_dirty": bool(status.strip()),
    }

def _write_summary_markdown(summary: dict[str, Any]) -> str:
    topo = summary["topology"]
    ping = summary["ping"]
    refs = summary["references"]
    lines = [
        f"# Network qualification {summary['qualification_id']}",
        "",
        f"Topology: `{topo['classification']}`",
        f"Local: `{topo['local']['address']}` via `{topo['local']['interface']}` ({topo['local'].get('hardware_port') or 'unknown'})",
        f"Remote: `{topo['remote']['address']}` via `{topo['remote']['interface']}` ({topo['remote'].get('speed_mbps') or 'unknown'} Mb/s)",
        "",
        "## Latency",
        "",
    ]
    if ping.get("enabled"):
        lines.append(
            f"- local → remote: avg `{ping['local_to_remote'].get('rtt_avg_ms')}` ms, loss `{ping['local_to_remote'].get('packet_loss_percent')}`%"
        )
        lines.append(
            f"- remote → local: avg `{ping['remote_to_local'].get('rtt_avg_ms')}` ms, loss `{ping['remote_to_local'].get('packet_loss_percent')}`%"
        )
    else:
        lines.append("- ping disabled")
    lines += [
        "",
        "## Capacity references",
        "",
        f"- HTTP/3 response direction (DUT → loadgen): `{summary['http3_response_direction']}`",
        f"- TCP best local → remote: `{refs['tcp']['local-to-remote']['best_throughput_mbps']}` Mb/s",
        f"- TCP best remote → local: `{refs['tcp']['remote-to-local']['best_throughput_mbps']}` Mb/s",
        f"- UDP reference local → remote: `{refs['udp']['local-to-remote']['highest_requested_mbps']}` Mb/s requested at <= `{refs['udp']['local-to-remote']['max_loss_percent']}`% loss",
        f"- UDP reference remote → local: `{refs['udp']['remote-to-local']['highest_requested_mbps']}` Mb/s requested at <= `{refs['udp']['remote-to-local']['max_loss_percent']}`% loss",
        "",
        "This qualification characterizes the path only. It is not an NGI541 performance claim.",
        "",
    ]
    return "\n".join(lines)


def run_network_qualification(
    definition: dict[str, Any],
    *,
    config_path: Path,
    output_root: Path,
    repo_root: Path,
    bootstrap: bool = False,
    ssh_session: SSHSession | None = None,
) -> dict[str, Any]:
    validate_network_qualification_definition(definition)
    qualification_id = generate_qualification_id(definition["qualification"]["name"])
    root = output_root / qualification_id
    if root.exists():
        raise FrameworkError(f"refusing to overwrite qualification directory: {root}")
    raw_dir = root / "raw"
    processed_dir = root / "processed"
    raw_dir.mkdir(parents=True)
    processed_dir.mkdir(parents=True)

    definition_sha = definition_sha256(definition)
    atomic_write_json(root / "config.json", {
        "schema_version": 1,
        "source": str(config_path),
        "definition_sha256": definition_sha,
        "definition": definition,
    })

    remote_cfg = definition["remote"]
    remote_address = remote_cfg["data_address"]
    ssh_timeout = int(remote_cfg.get("connect_timeout_seconds", 10))

    started_at = _utc_rfc3339()
    try:
        session_context = (
            nullcontext(ssh_session)
            if ssh_session is not None
            else SSHSession(remote_cfg["ssh_target"], ssh_timeout)
        )
        with session_context as ssh:
            local_iperf = _ensure_local_iperf3(bootstrap=bootstrap)
            remote_iperf = _ensure_remote_iperf3(ssh, bootstrap=bootstrap)

            local_iperf_version = run_command([local_iperf, "--version"], check=True)
            _write_command_record(raw_dir, "local-iperf3-version", local_iperf_version)
            remote_iperf_version = ssh.run([remote_iperf, "--version"], check=True)
            _write_command_record(raw_dir, "remote-iperf3-version", remote_iperf_version)

            _inventory(ssh, raw_dir)
            local_path = _local_data_path(remote_address, raw_dir)
            remote_path = _remote_data_path(ssh, local_path["address"], raw_dir)

            if remote_path.get("address") and remote_path["address"] != remote_address:
                # Preserve the configured address as the qualification target but expose
                # route-source drift in the summary rather than silently changing paths.
                remote_path["configured_address"] = remote_address

            ping = _run_ping_tests(
                definition,
                ssh,
                local_path["address"],
                remote_address,
                raw_dir,
            )
            tcp_rows, udp_rows = _run_iperf_tests(
                definition,
                ssh,
                local_iperf,
                remote_iperf,
                local_path["address"],
                raw_dir,
            )

            max_loss = float(
                definition.get("reporting", {}).get("udp_reference_max_loss_percent", 0.1)
            )
            topology = {
                "classification": _topology_class(local_path, remote_path),
                "local": local_path,
                "remote": remote_path,
            }
            local_version_text = local_iperf_version.stdout.strip() or local_iperf_version.stderr.strip()
            remote_version_text = remote_iperf_version.stdout.strip() or remote_iperf_version.stderr.strip()
            framework = _git_identity(repo_root)
            response_direction = "local-to-remote" if definition["local"].get("role") == "dut" else "remote-to-local"
            summary = {
                "schema_version": 1,
                "qualification_id": qualification_id,
                "qualification_name": definition["qualification"]["name"],
                "definition_sha256": definition_sha,
                "started_at": started_at,
                "finished_at": _utc_rfc3339(),
                "status": "COMPLETE",
                "claim_scope": definition["qualification"].get(
                    "claim_scope", "network-characterization-only"
                ),
                "topology": topology,
                "ping": ping,
                "tcp": tcp_rows,
                "udp": udp_rows,
                "http3_response_direction": response_direction,
                "references": {
                    "tcp": {
                        "local-to-remote": _tcp_reference(tcp_rows, "local-to-remote"),
                        "remote-to-local": _tcp_reference(tcp_rows, "remote-to-local"),
                    },
                    "udp": {
                        "local-to-remote": _udp_reference(
                            udp_rows,
                            direction="local-to-remote",
                            max_loss_percent=max_loss,
                        ),
                        "remote-to-local": _udp_reference(
                            udp_rows,
                            direction="remote-to-local",
                            max_loss_percent=max_loss,
                        ),
                    },
                },
                "tools": {
                    "local_iperf3": local_iperf,
                    "local_iperf3_version": local_version_text.splitlines()[0] if local_version_text else None,
                    "remote_iperf3": remote_iperf,
                    "remote_iperf3_version": remote_version_text.splitlines()[0] if remote_version_text else None,
                },
                "framework": framework,
            }
            response_tcp = summary["references"]["tcp"][response_direction]
            response_udp = summary["references"]["udp"][response_direction]
            reference = {
                "schema_version": 1,
                "qualification_id": qualification_id,
                "definition_sha256": definition_sha,
                "topology_classification": topology["classification"],
                "http3_response_direction": response_direction,
                "tcp_capacity_reference_mbps": response_tcp.get("best_throughput_mbps"),
                "tcp_parallel_streams": response_tcp.get("parallel_streams"),
                "udp_reference_requested_mbps": response_udp.get("highest_requested_mbps"),
                "udp_reference_achieved_mbps": response_udp.get("achieved_mbps"),
                "udp_reference_max_loss_percent": response_udp.get("max_loss_percent"),
                "udp_reference_observed_loss_percent": response_udp.get("observed_loss_percent"),
            }
            atomic_write_json(processed_dir / "summary.json", summary)
            atomic_write_json(processed_dir / "reference.json", reference)
            atomic_write_text(processed_dir / "SUMMARY.md", _write_summary_markdown(summary))
            atomic_write_text(root / "artifacts.sha256", _artifact_hashes(root))
            return {"root": root, "summary": summary}
    except Exception:
        atomic_write_json(root / "status.json", {
            "schema_version": 1,
            "status": "FAILED",
            "started_at": started_at,
            "finished_at": _utc_rfc3339(),
        })
        raise
