from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import signal
import stat
import subprocess
import time
from pathlib import Path
from typing import Any

from framework.ids import utc_rfc3339
from framework.host_state import (
    append_jsonl,
    calibrate_host_state,
    capture_host_state,
    host_state_session,
    normalize_measurement_control,
    static_readiness,
    validate_host_state_capabilities,
    wait_until_ready,
)
from framework.io_utils import (
    FrameworkError,
    append_log,
    atomic_write_json,
    atomic_write_text,
    read_json,
)
from framework.lifecycle import (
    load_state,
    transition,
    update_run_counts,
)
from framework.provenance import (
    resolve_recorded_location,
    sha256_file,
)


DEFAULTS = {
    "requests_per_client": 5000,
    "warmup_requests_per_client": 50,
    "cipher_suite": "TLS_AES_128_GCM_SHA256",
    "server_host": "127.0.0.1",
    "server_port": 8443,
    "worker_connections": 4096,
    "keepalive_requests": 20000,
    "startup_timeout_seconds": 10,
    "client_timeout_seconds": 60,
}


def _positive_int(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise FrameworkError(f"{name} must be a positive integer")
    return value


def _validate_int_axis(value: Any, name: str) -> None:
    if isinstance(value, list):
        if not value:
            raise FrameworkError(f"{name} must not be an empty list")
        for item in value:
            _positive_int(item, name)
    else:
        _positive_int(value, name)


def resolve_http3_config(
    request: dict[str, Any],
    resolved: dict[str, Any],
) -> dict[str, Any]:
    parameters = dict(resolved["parameters"])
    conditions = resolved.get("conditions")

    required_axes = {
        "payload_bytes": [16384],
        "workers": [1],
        "clients": [1],
    }

    if conditions is None:
        for name, default in required_axes.items():
            parameters.setdefault(name, default)
            _validate_int_axis(parameters[name], name)
    else:
        normalized_conditions = []
        for index, condition in enumerate(conditions):
            row = dict(condition)
            for name in required_axes:
                if name not in row:
                    raise FrameworkError(
                        f"explicit HTTP/3 condition {index} is missing {name!r}"
                    )
                _positive_int(row[name], name)
            normalized_conditions.append(row)
        conditions = normalized_conditions

    for name, value in DEFAULTS.items():
        parameters.setdefault(name, value)

    for name in (
        "requests_per_client",
        "warmup_requests_per_client",
        "server_port",
        "worker_connections",
        "keepalive_requests",
        "startup_timeout_seconds",
        "client_timeout_seconds",
    ):
        _positive_int(parameters[name], name)

    cipher = parameters["cipher_suite"]
    if not isinstance(cipher, str) or not cipher:
        raise FrameworkError("cipher_suite must be a non-empty string")

    host = parameters["server_host"]
    if not isinstance(host, str) or not host:
        raise FrameworkError("server_host must be a non-empty string")

    resolved = dict(resolved)
    resolved["parameters"] = parameters
    resolved["measurement_control"] = normalize_measurement_control(
        resolved.get("measurement_control")
    )
    if conditions is not None:
        resolved["conditions"] = conditions
    resolved["workload_contract"] = {
        "adapter": "http3",
        "version": 1,
        "primary_metric": "requests_per_second",
        "transport": "QUIC",
        "application_protocol": "HTTP/3",
    }
    return resolved


def _tool_path(
    dependencies: dict[str, Any],
    name: str,
) -> str:
    record = dependencies.get("tools", {}).get(name, {})
    command = record.get("command")

    if not record.get("available") or not command:
        raise FrameworkError(f"required tool is unavailable: {name}")

    return command[0]


def _write_payload(path: Path, size: int) -> str:
    expected = hashlib.sha256(b"\x00" * size).hexdigest()

    if path.exists():
        if path.stat().st_size != size:
            raise FrameworkError(
                f"existing HTTP/3 payload has wrong size: {path}"
            )
        current = sha256_file(path)
        if current != expected:
            raise FrameworkError(
                f"existing HTTP/3 payload has wrong content: {path}"
            )
        return expected

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x00" * size)
    return expected


def _axis_values(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _runtime_env_for_binding(
    binding: dict[str, Any],
    repo_root: Path,
) -> dict[str, str]:
    env = dict(os.environ)
    library_dirs = []

    for library in binding.get("libraries", []):
        path = resolve_recorded_location(
            library.get("location"),
            repo_root,
        )
        library_dirs.append(str(path.parent))

    if library_dirs:
        joined = os.pathsep.join(dict.fromkeys(library_dirs))
        for key in ("DYLD_LIBRARY_PATH", "LD_LIBRARY_PATH"):
            previous = env.get(key)
            env[key] = joined if not previous else joined + os.pathsep + previous

    return env


def _check_nginx_variant(
    variant: str,
    binding: dict[str, Any],
    repo_root: Path,
    output_dir: Path,
) -> dict[str, Any]:
    binary = resolve_recorded_location(
        binding["binary"].get("location"),
        repo_root,
    )

    if sha256_file(binary) != binding["binary"]["sha256"]:
        raise FrameworkError(
            f"sealed binary hash mismatch during HTTP/3 preparation: {variant}"
        )

    env = _runtime_env_for_binding(binding, repo_root)
    result = subprocess.run(
        [str(binary), "-V"],
        env=env,
        check=False,
        text=True,
        capture_output=True,
    )

    stdout_path = output_dir / f"{variant}-nginx-V.stdout.log"
    stderr_path = output_dir / f"{variant}-nginx-V.stderr.log"
    atomic_write_text(stdout_path, result.stdout)
    atomic_write_text(stderr_path, result.stderr)

    combined = result.stdout + "\n" + result.stderr
    http3 = "--with-http_v3_module" in combined

    return {
        "name": f"{variant}-nginx-http3",
        "passed": result.returncode == 0 and http3,
        "exit_code": result.returncode,
        "http3_module": http3,
        "stdout": (
            f"execution/workload/preflight/{stdout_path.name}"
        ),
        "stderr": (
            f"execution/workload/preflight/{stderr_path.name}"
        ),
    }


def _stage_shared_artifacts(
    experiment_dir: Path,
    resolved: dict[str, Any],
    runtime_bindings: dict[str, Any],
) -> dict[str, Any] | None:
    control = normalize_measurement_control(resolved.get("measurement_control"))
    if not control["runtime"]["stage_artifacts_once"]:
        return None

    repo_root = experiment_dir.parents[1]
    root = experiment_dir / "execution" / "artifacts"
    records: dict[str, Any] = {}

    for variant in resolved["variants"]:
        binding = runtime_bindings["variants"][variant]
        binary_dst = root / variant / "bin" / "nginx"
        _verify_and_copy(binding["binary"], repo_root, binary_dst)
        binary_dst.chmod(
            binary_dst.stat().st_mode
            | stat.S_IXUSR
            | stat.S_IXGRP
            | stat.S_IXOTH
        )
        libraries = []
        for library in binding.get("libraries", []):
            library_dst = root / variant / "lib" / library["basename"]
            _verify_and_copy(library, repo_root, library_dst)
            libraries.append({
                "basename": library["basename"],
                "path": str(library_dst.relative_to(experiment_dir)),
                "sha256": library["sha256"],
            })
        records[variant] = {
            "binary": {
                "path": str(binary_dst.relative_to(experiment_dir)),
                "sha256": binding["binary"]["sha256"],
            },
            "libraries": libraries,
        }

    manifest = {
        "schema_version": 1,
        "policy": "stage-once-per-experiment",
        "variants": records,
    }
    atomic_write_json(root / "manifest.json", manifest)
    return manifest


def prepare_http3_workload(
    experiment_dir: Path,
    resolved: dict[str, Any],
    dependencies: dict[str, Any],
    runtime_bindings: dict[str, Any],
) -> dict[str, Any]:
    workload_dir = experiment_dir / "execution" / "workload"
    assets_dir = workload_dir / "assets"
    preflight_dir = workload_dir / "preflight"
    assets_dir.mkdir(parents=True, exist_ok=True)
    preflight_dir.mkdir(parents=True, exist_ok=True)

    parameters = resolved["parameters"]
    if resolved.get("conditions") is not None:
        payload_sizes = sorted(
            {
                int(condition["payload_bytes"])
                for condition in resolved["conditions"]
            }
        )
    else:
        payload_sizes = sorted(
            {
                int(value)
                for value in _axis_values(parameters["payload_bytes"])
            }
        )

    payload_records = []
    for size in payload_sizes:
        payload_path = assets_dir / f"{size}.bin"
        digest = _write_payload(payload_path, size)
        payload_records.append(
            {
                "bytes": size,
                "path": f"execution/workload/assets/{size}.bin",
                "sha256": digest,
            }
        )

    curl = _tool_path(dependencies, "curl")
    openssl = _tool_path(dependencies, "openssl")

    curl_help = subprocess.run(
        [curl, "--help", "all"],
        check=False,
        text=True,
        capture_output=True,
    )
    curl_help_text = curl_help.stdout + "\n" + curl_help.stderr

    checks = [
        {
            "name": "curl-http3-only",
            "passed": (
                curl_help.returncode == 0
                and "--http3-only" in curl_help_text
            ),
        },
        {
            "name": "curl-tls13-ciphers",
            "passed": (
                curl_help.returncode == 0
                and "--tls13-ciphers" in curl_help_text
            ),
        },
        {
            "name": "curl-out-null",
            "passed": (
                curl_help.returncode == 0
                and "--out-null" in curl_help_text
            ),
        },
        {
            "name": "openssl-available",
            "passed": bool(openssl),
        },
    ]

    control = normalize_measurement_control(resolved.get("measurement_control"))
    with host_state_session(control) as host_session:
        host_capabilities = validate_host_state_capabilities(
            control, session=host_session
        )
    atomic_write_json(
        preflight_dir / "host-state.json",
        host_capabilities,
    )
    if control["host_state"]["enabled"]:
        checks.append({
            "name": "host-state-capabilities",
            "passed": host_capabilities["passed"],
            "details": "execution/workload/preflight/host-state.json",
        })

    repo_root = experiment_dir.parents[1]
    bindings = runtime_bindings["variants"]

    for variant in resolved["variants"]:
        binding = bindings.get(variant)
        if binding is None:
            raise FrameworkError(
                f"HTTP/3 runtime binding is missing variant: {variant}"
            )

        checks.append(
            _check_nginx_variant(
                variant,
                binding,
                repo_root,
                preflight_dir,
            )
        )

    preflight = {
        "schema_version": 1,
        "checks": checks,
        "passed": all(bool(check["passed"]) for check in checks),
    }
    atomic_write_json(
        workload_dir / "preflight.json",
        preflight,
    )

    shared_artifacts = _stage_shared_artifacts(
        experiment_dir,
        resolved,
        runtime_bindings,
    )

    manifest = {
        "schema_version": 1,
        "adapter": "http3",
        "transport": "QUIC",
        "application_protocol": "HTTP/3",
        "cipher_suite": parameters["cipher_suite"],
        "server": {
            "host": parameters["server_host"],
            "port": parameters["server_port"],
        },
        "payloads": payload_records,
        "client": {
            "curl": curl,
            "requests_per_client": parameters["requests_per_client"],
            "warmup_requests_per_client": (
                parameters["warmup_requests_per_client"]
            ),
        },
        "preflight": "execution/workload/preflight.json",
        "runtime_artifacts": (
            "execution/artifacts/manifest.json"
            if shared_artifacts is not None else None
        ),
    }
    atomic_write_json(
        workload_dir / "manifest.json",
        manifest,
    )

    if not preflight["passed"]:
        failed = [
            check["name"]
            for check in checks
            if not check["passed"]
        ]
        raise FrameworkError(
            "HTTP/3 workload preflight failed: "
            + ", ".join(failed)
        )

    return manifest


def _nginx_config(
    *,
    workers: int,
    host: str,
    port: int,
    worker_connections: int,
    keepalive_requests: int,
) -> str:
    reuseport = " reuseport" if workers > 1 else ""

    return f"""worker_processes {workers};
pid logs/nginx.pid;

events {{
    worker_connections {worker_connections};
}}

http {{
    access_log off;
    keepalive_requests {keepalive_requests};

    server {{
        listen {host}:{port} quic{reuseport};

        ssl_protocols TLSv1.3;
        ssl_certificate server.crt;
        ssl_certificate_key server.key;

        http3 on;

        root html;
    }}
}}
"""


def _verify_and_copy(
    record: dict[str, Any],
    repo_root: Path,
    destination: Path,
) -> None:
    source = resolve_recorded_location(
        record.get("location"),
        repo_root,
    )

    expected = record["sha256"]
    actual = sha256_file(source)
    if actual != expected:
        raise FrameworkError(
            f"sealed artifact hash mismatch: {record['name']}"
        )

    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)

    copied = sha256_file(destination)
    if copied != expected:
        raise FrameworkError(
            f"runtime copy hash mismatch: {record['name']}"
        )


def _materialize_runtime(
    experiment_dir: Path,
    run_id: str,
    attempt_number: int,
    variant: str,
    binding: dict[str, Any],
    parameters: dict[str, Any],
    workload_manifest: dict[str, Any],
    dependencies: dict[str, Any],
    measurement_control: dict[str, Any],
) -> tuple[Path, Path, dict[str, str]]:
    repo_root = experiment_dir.parents[1]
    control = normalize_measurement_control(measurement_control)

    runtime = (
        experiment_dir
        / "execution"
        / "runtime"
        / run_id
        / f"attempt-{attempt_number:02d}"
    )
    if runtime.exists():
        shutil.rmtree(runtime)

    for rel in ("conf", "html", "logs"):
        (runtime / rel).mkdir(parents=True, exist_ok=True)

    if control["runtime"]["stage_artifacts_once"]:
        manifest_path = experiment_dir / "execution" / "artifacts" / "manifest.json"
        if not manifest_path.is_file():
            raise FrameworkError("shared runtime artifact manifest is missing")
        artifact_manifest = read_json(manifest_path)
        variant_record = artifact_manifest.get("variants", {}).get(variant)
        if not variant_record:
            raise FrameworkError(f"shared runtime artifact is missing variant: {variant}")
        nginx_path = experiment_dir / variant_record["binary"]["path"]
        if sha256_file(nginx_path) != variant_record["binary"]["sha256"]:
            raise FrameworkError(f"shared runtime binary hash mismatch: {variant}")
        library_dirs = []
        for library in variant_record.get("libraries", []):
            library_path = experiment_dir / library["path"]
            if sha256_file(library_path) != library["sha256"]:
                raise FrameworkError(
                    f"shared runtime library hash mismatch: {library['basename']}"
                )
            library_dirs.append(str(library_path.parent))
    else:
        for rel in ("bin", "lib"):
            (runtime / rel).mkdir(parents=True, exist_ok=True)
        nginx_path = runtime / "bin" / "nginx"
        _verify_and_copy(
            binding["binary"],
            repo_root,
            nginx_path,
        )
        nginx_path.chmod(
            nginx_path.stat().st_mode
            | stat.S_IXUSR
            | stat.S_IXGRP
            | stat.S_IXOTH
        )
        library_dirs = []
        for library in binding.get("libraries", []):
            destination = runtime / "lib" / library["basename"]
            _verify_and_copy(
                library,
                repo_root,
                destination,
            )
            library_dirs.append(str(destination.parent))

    for payload in workload_manifest["payloads"]:
        source = experiment_dir / payload["path"]
        if sha256_file(source) != payload["sha256"]:
            raise FrameworkError(
                f"sealed payload hash mismatch: {payload['path']}"
            )
        destination = runtime / "html" / Path(payload["path"]).name
        try:
            os.link(source, destination)
        except OSError:
            shutil.copy2(source, destination)

    config = _nginx_config(
        workers=int(parameters["workers"]),
        host=str(parameters["server_host"]),
        port=int(parameters["server_port"]),
        worker_connections=int(parameters["worker_connections"]),
        keepalive_requests=int(parameters["keepalive_requests"]),
    )
    atomic_write_text(runtime / "conf" / "nginx.conf", config)

    openssl = _tool_path(dependencies, "openssl")
    cert = runtime / "conf" / "server.crt"
    key = runtime / "conf" / "server.key"

    cert_result = subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-subj",
            "/CN=localhost",
            "-days",
            "1",
        ],
        check=False,
        text=True,
        capture_output=True,
    )
    if cert_result.returncode != 0:
        raise FrameworkError(
            "unable to generate ephemeral HTTP/3 TLS certificate: "
            + cert_result.stderr.strip()
        )

    env = dict(os.environ)
    if library_dirs:
        joined = os.pathsep.join(dict.fromkeys(library_dirs))
        for key_name in ("DYLD_LIBRARY_PATH", "LD_LIBRARY_PATH"):
            previous = env.get(key_name)
            env[key_name] = joined if not previous else joined + os.pathsep + previous

    return runtime, nginx_path, env

def _curl_command(
    *,
    curl: str,
    host: str,
    port: int,
    payload_bytes: int,
    count: int,
    client_index: int,
    cipher_suite: str,
    timeout_seconds: int,
) -> list[str]:
    url = (
        f"https://{host}:{port}/{payload_bytes}.bin"
        f"?client={client_index}&i=[1-{count}]"
    )

    return [
        curl,
        "--http3-only",
        "--tls13-ciphers",
        cipher_suite,
        "--insecure",
        "--silent",
        "--show-error",
        "--fail",
        "--fail-early",
        "--out-null",
        "--connect-timeout",
        str(timeout_seconds),
        "--max-time",
        str(timeout_seconds),
        url,
    ]


def _run_clients(
    *,
    curl: str,
    host: str,
    port: int,
    payload_bytes: int,
    count_per_client: int,
    clients: int,
    cipher_suite: str,
    timeout_seconds: int,
    output_dir: Path,
    phase: str,
) -> tuple[bool, int, str | None]:
    phase_dir = output_dir / phase
    phase_dir.mkdir(parents=True, exist_ok=True)

    processes = []

    for client_index in range(1, clients + 1):
        stdout_path = phase_dir / f"client-{client_index:03d}.stdout.log"
        stderr_path = phase_dir / f"client-{client_index:03d}.stderr.log"

        stdout_handle = stdout_path.open("wb")
        stderr_handle = stderr_path.open("wb")

        command = _curl_command(
            curl=curl,
            host=host,
            port=port,
            payload_bytes=payload_bytes,
            count=count_per_client,
            client_index=client_index,
            cipher_suite=cipher_suite,
            timeout_seconds=timeout_seconds,
        )

        process = subprocess.Popen(
            command,
            stdout=stdout_handle,
            stderr=stderr_handle,
        )
        processes.append(
            (
                client_index,
                process,
                stdout_handle,
                stderr_handle,
                stdout_path,
                stderr_path,
            )
        )

    failure = None
    exit_code = 0

    for (
        client_index,
        process,
        stdout_handle,
        stderr_handle,
        stdout_path,
        stderr_path,
    ) in processes:
        rc = process.wait()
        stdout_handle.close()
        stderr_handle.close()

        stderr_nonempty = stderr_path.stat().st_size > 0

        if rc != 0 and failure is None:
            exit_code = rc
            failure = (
                f"{phase} curl client {client_index} failed "
                f"with exit code {rc}"
            )
        elif stderr_nonempty and failure is None:
            exit_code = 1
            failure = (
                f"{phase} curl client {client_index} produced stderr"
            )

    return failure is None, exit_code, failure


def _probe_server(
    *,
    curl: str,
    host: str,
    port: int,
    payload_bytes: int,
    cipher_suite: str,
    timeout_seconds: int,
    server_process: subprocess.Popen[Any],
    output_dir: Path,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    probe_dir = output_dir / "probe"
    probe_dir.mkdir(parents=True, exist_ok=True)

    last_error = "server probe did not run"

    while time.monotonic() < deadline:
        if server_process.poll() is not None:
            raise FrameworkError(
                f"NGINX exited during startup with code "
                f"{server_process.returncode}"
            )

        command = _curl_command(
            curl=curl,
            host=host,
            port=port,
            payload_bytes=payload_bytes,
            count=1,
            client_index=0,
            cipher_suite=cipher_suite,
            timeout_seconds=2,
        )
        result = subprocess.run(
            command,
            check=False,
            text=True,
            capture_output=True,
        )

        atomic_write_text(
            probe_dir / "stdout.log",
            result.stdout,
        )
        atomic_write_text(
            probe_dir / "stderr.log",
            result.stderr,
        )

        if result.returncode == 0:
            return

        last_error = result.stderr.strip() or f"curl exit {result.returncode}"
        time.sleep(0.2)

    raise FrameworkError(
        f"HTTP/3 server did not become ready: {last_error}"
    )


def _stop_server(
    process: subprocess.Popen[Any],
) -> None:
    if process.poll() is not None:
        return

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        process.terminate()

    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()
        process.wait(timeout=5)


def _allocate_attempt(
    experiment_dir: Path,
    run_id: str,
) -> tuple[Path, int]:
    run_dir = experiment_dir / "raw" / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    numbers = []
    for child in run_dir.iterdir():
        if child.is_dir() and child.name.startswith("attempt-"):
            try:
                numbers.append(int(child.name.split("-", 1)[1]))
            except (ValueError, IndexError):
                pass

    number = max(numbers, default=0) + 1
    attempt_dir = run_dir / f"attempt-{number:02d}"
    attempt_dir.mkdir()
    return attempt_dir, number


def _latest_valid_attempt(
    experiment_dir: Path,
    run_id: str,
) -> bool:
    run_dir = experiment_dir / "raw" / "runs" / run_id
    if not run_dir.is_dir():
        return False

    for measurement_path in sorted(
        run_dir.glob("attempt-*/measurement.json"),
        reverse=True,
    ):
        try:
            measurement = read_json(measurement_path)
        except FrameworkError:
            continue

        if measurement.get("execution", {}).get("valid") is True:
            return True

    return False


def _aggregate_client_logs(
    attempt_dir: Path,
    phase: str,
) -> None:
    source_dir = attempt_dir / phase

    stdout_parts = []
    stderr_parts = []

    for path in sorted(source_dir.glob("client-*.stdout.log")):
        data = path.read_text(encoding="utf-8", errors="replace")
        if data:
            stdout_parts.append(f"===== {path.name} =====\n{data}")

    for path in sorted(source_dir.glob("client-*.stderr.log")):
        data = path.read_text(encoding="utf-8", errors="replace")
        if data:
            stderr_parts.append(f"===== {path.name} =====\n{data}")

    atomic_write_text(
        attempt_dir / "stdout.log",
        "\n".join(stdout_parts),
    )
    atomic_write_text(
        attempt_dir / "stderr.log",
        "\n".join(stderr_parts),
    )


def _execute_run(
    experiment_dir: Path,
    run: dict[str, Any],
    *,
    host_session=None,
    host_calibration: dict[str, Any] | None = None,
    host_calibration_id: str | None = None,
) -> dict[str, Any]:
    dependencies = read_json(
        experiment_dir / "provenance" / "dependencies.json"
    )
    bindings = read_json(
        experiment_dir / "provenance" / "runtime-bindings.json"
    )
    workload_manifest = read_json(
        experiment_dir / "execution" / "workload" / "manifest.json"
    )
    resolved = read_json(
        experiment_dir / "config" / "resolved.json"
    )

    parameters = dict(resolved["parameters"])
    parameters.update(run["parameters"])
    control = normalize_measurement_control(resolved.get("measurement_control"))

    variant = run["variant"]
    binding = bindings["variants"][variant]
    attempt_dir, attempt_number = _allocate_attempt(
        experiment_dir,
        run["run_id"],
    )

    attempt_started_at = utc_rfc3339()
    attempt_start_ns = time.perf_counter_ns()
    server = None
    server_stdout_handle = None
    server_stderr_handle = None
    runtime: Path | None = None
    phases: dict[str, int] = {}

    measurement: dict[str, Any] = {
        "schema_version": 2,
        "experiment_id": experiment_dir.name,
        "run_id": run["run_id"],
        "pair_id": run.get("pair_id"),
        "attempt": attempt_number,
        "variant": variant,
        "parameters": parameters,
        "schedule": {
            "sequence": run.get("sequence"),
            "condition_id": run.get("condition_id"),
            "condition_index": run.get("condition_index"),
            "condition_position_in_round": run.get("condition_position_in_round"),
            "repetition": run.get("repetition"),
            "repetition_round": run.get("repetition_round", run.get("repetition")),
            "pair_position": run.get("pair_position"),
            "pair_order": run.get("pair_order"),
        },
        "timing": {
            "started_at": attempt_started_at,
            "finished_at": attempt_started_at,
            "elapsed_ns": 0,
            "attempt_started_at": attempt_started_at,
            "attempt_finished_at": attempt_started_at,
            "attempt_elapsed_ns": 0,
        },
        "phases": phases,
        "requests": {
            "planned": (
                int(parameters["clients"])
                * int(parameters["requests_per_client"])
            ),
            "completed": 0,
        },
        "metrics": {
            "requests_per_second": None,
        },
        "execution": {
            "exit_code": 1,
            "valid": False,
            "failure": "attempt did not complete",
        },
        "observations": {
            "attempt_started_at": attempt_started_at,
            "completed_count_known": False,
        },
    }

    def record_host_snapshot(snapshot: dict[str, Any], phase: str) -> None:
        record = dict(snapshot)
        record.update({
            "experiment_id": experiment_dir.name,
            "run_id": run["run_id"],
            "pair_id": run.get("pair_id"),
            "variant": variant,
            "repetition": run.get("repetition"),
            "condition_id": run.get("condition_id"),
            "sequence": run.get("sequence"),
            "phase": phase,
            "host_calibration_id": host_calibration_id,
        })
        append_jsonl(experiment_dir / "raw" / "host-state.jsonl", record)

    try:
        gate_phase = "pre-pair" if run.get("pair_position") in (None, 1) else "pre-variant"
        gate_start = time.perf_counter_ns()
        pre_snapshot, gate_samples, gate_wait_ns = wait_until_ready(
            control,
            calibration=host_calibration,
            session=host_session,
            on_snapshot=lambda snap: record_host_snapshot(snap, gate_phase),
        )
        phases["host_readiness_wait_ns"] = time.perf_counter_ns() - gate_start
        measurement["observations"]["host_readiness_samples"] = gate_samples
        measurement["observations"]["host_readiness_wait_ns"] = gate_wait_ns
        measurement["observations"]["host_calibration_id"] = host_calibration_id
        atomic_write_json(attempt_dir / "host-state-pre.json", pre_snapshot)

        phase_start = time.perf_counter_ns()
        runtime, nginx, env = _materialize_runtime(
            experiment_dir,
            run["run_id"],
            attempt_number,
            variant,
            binding,
            parameters,
            workload_manifest,
            dependencies,
            control,
        )
        phases["runtime_setup_ns"] = time.perf_counter_ns() - phase_start

        shutil.copy2(
            runtime / "conf" / "nginx.conf",
            attempt_dir / "nginx.conf",
        )

        phase_start = time.perf_counter_ns()
        test_result = subprocess.run(
            [
                str(nginx),
                "-p",
                str(runtime) + os.sep,
                "-c",
                "conf/nginx.conf",
                "-t",
            ],
            env=env,
            check=False,
            text=True,
            capture_output=True,
        )
        phases["nginx_test_ns"] = time.perf_counter_ns() - phase_start
        atomic_write_text(
            attempt_dir / "nginx-test.stdout.log",
            test_result.stdout,
        )
        atomic_write_text(
            attempt_dir / "nginx-test.stderr.log",
            test_result.stderr,
        )

        if test_result.returncode != 0:
            raise FrameworkError(
                f"NGINX configuration test failed for {variant}"
            )

        server_stdout_handle = (
            attempt_dir / "server.stdout.log"
        ).open("wb")
        server_stderr_handle = (
            attempt_dir / "server.stderr.log"
        ).open("wb")

        phase_start = time.perf_counter_ns()
        server = subprocess.Popen(
            [
                str(nginx),
                "-p",
                str(runtime) + os.sep,
                "-c",
                "conf/nginx.conf",
                "-g",
                "daemon off;",
            ],
            env=env,
            stdout=server_stdout_handle,
            stderr=server_stderr_handle,
            start_new_session=True,
        )

        curl = _tool_path(dependencies, "curl")

        _probe_server(
            curl=curl,
            host=str(parameters["server_host"]),
            port=int(parameters["server_port"]),
            payload_bytes=int(parameters["payload_bytes"]),
            cipher_suite=str(parameters["cipher_suite"]),
            timeout_seconds=int(parameters["startup_timeout_seconds"]),
            server_process=server,
            output_dir=attempt_dir,
        )
        phases["server_start_probe_ns"] = time.perf_counter_ns() - phase_start

        phase_start = time.perf_counter_ns()
        warm_ok, warm_rc, warm_failure = _run_clients(
            curl=curl,
            host=str(parameters["server_host"]),
            port=int(parameters["server_port"]),
            payload_bytes=int(parameters["payload_bytes"]),
            count_per_client=int(
                parameters["warmup_requests_per_client"]
            ),
            clients=int(parameters["clients"]),
            cipher_suite=str(parameters["cipher_suite"]),
            timeout_seconds=int(parameters["client_timeout_seconds"]),
            output_dir=attempt_dir,
            phase="warmup",
        )
        phases["warmup_ns"] = time.perf_counter_ns() - phase_start
        if not warm_ok:
            raise FrameworkError(
                warm_failure or f"warmup failed with exit code {warm_rc}"
            )

        if control["host_state"]["enabled"]:
            pre_measurement_snapshot = capture_host_state(
                control, session=host_session
            )
            pre_measurement_state = static_readiness(
                pre_measurement_snapshot, control
            )
            pre_measurement_snapshot["readiness"] = pre_measurement_state
            record_host_snapshot(pre_measurement_snapshot, "pre-measurement")
            atomic_write_json(
                attempt_dir / "host-state-pre-measurement.json",
                pre_measurement_snapshot,
            )
            if pre_measurement_state["fatal"] or not pre_measurement_state["ready"]:
                raise FrameworkError(
                    "host state became unsuitable after warmup: "
                    + ", ".join(pre_measurement_state["reasons"])
                )

        measured_started_at = utc_rfc3339()
        start_ns = time.perf_counter_ns()

        ok, exit_code, failure = _run_clients(
            curl=curl,
            host=str(parameters["server_host"]),
            port=int(parameters["server_port"]),
            payload_bytes=int(parameters["payload_bytes"]),
            count_per_client=int(parameters["requests_per_client"]),
            clients=int(parameters["clients"]),
            cipher_suite=str(parameters["cipher_suite"]),
            timeout_seconds=int(parameters["client_timeout_seconds"]),
            output_dir=attempt_dir,
            phase="measured",
        )

        end_ns = time.perf_counter_ns()
        elapsed_ns = end_ns - start_ns
        phases["measurement_ns"] = elapsed_ns

        _aggregate_client_logs(attempt_dir, "measured")

        if not ok:
            raise FrameworkError(
                failure or f"measured clients failed with exit code {exit_code}"
            )

        planned = measurement["requests"]["planned"]
        requests_per_second = (
            planned / (elapsed_ns / 1_000_000_000)
            if elapsed_ns > 0 else None
        )

        measurement["timing"].update({
            "started_at": measured_started_at,
            "finished_at": utc_rfc3339(),
            "elapsed_ns": elapsed_ns,
        })
        measurement["requests"]["completed"] = planned
        measurement["metrics"]["requests_per_second"] = requests_per_second
        measurement["execution"] = {
            "exit_code": 0,
            "valid": True,
            "failure": None,
        }
        measurement["observations"]["completed_count_known"] = True

    except Exception as exc:
        measurement["timing"]["finished_at"] = utc_rfc3339()
        measurement["execution"] = {
            "exit_code": 1,
            "valid": False,
            "failure": str(exc),
        }

    finally:
        teardown_start = time.perf_counter_ns()
        if server is not None:
            _stop_server(server)

        if server_stdout_handle is not None:
            server_stdout_handle.close()
        if server_stderr_handle is not None:
            server_stderr_handle.close()

        if runtime is not None:
            error_log = runtime / "logs" / "error.log"
            if error_log.is_file():
                shutil.copy2(error_log, attempt_dir / "nginx-error.log")
        phases["teardown_ns"] = time.perf_counter_ns() - teardown_start

        if control["host_state"]["enabled"]:
            try:
                post_snapshot = capture_host_state(control, session=host_session)
                post_snapshot["readiness"] = {"ready": None, "reasons": [], "fatal": False}
                record_host_snapshot(post_snapshot, "post-variant")
                atomic_write_json(attempt_dir / "host-state-post.json", post_snapshot)
            except Exception as host_exc:
                measurement["observations"]["post_host_state_error"] = str(host_exc)

        if runtime is not None and control["runtime"]["cleanup_attempt_runtime"]:
            shutil.rmtree(runtime, ignore_errors=True)

        attempt_finished_at = utc_rfc3339()
        measurement["timing"]["attempt_finished_at"] = attempt_finished_at
        measurement["timing"]["attempt_elapsed_ns"] = time.perf_counter_ns() - attempt_start_ns
        atomic_write_json(
            attempt_dir / "measurement.json",
            measurement,
        )

    return measurement

def _recount(
    experiment_dir: Path,
    schedule: dict[str, Any],
) -> tuple[int, int]:
    completed = 0
    failed = 0

    for run in schedule["runs"]:
        if _latest_valid_attempt(experiment_dir, run["run_id"]):
            completed += 1
            continue

        run_dir = experiment_dir / "raw" / "runs" / run["run_id"]
        if run_dir.is_dir() and any(
            run_dir.glob("attempt-*/measurement.json")
        ):
            failed += 1

    return completed, failed


def _allocate_host_control_session(experiment_dir: Path) -> tuple[str, Path]:
    root = experiment_dir / "raw" / "host-calibration"
    root.mkdir(parents=True, exist_ok=True)
    numbers: list[int] = []
    for path in root.glob("session-*.json"):
        try:
            numbers.append(int(path.stem.split("-", 1)[1]))
        except (IndexError, ValueError):
            continue
    number = max(numbers, default=0) + 1
    session_id = f"session-{number:04d}"
    return session_id, root / f"{session_id}.json"


def execute_http3_schedule(
    experiment_dir: Path,
) -> None:
    state = load_state(experiment_dir)

    if state["state"] == "READY":
        transition(experiment_dir, "RUNNING")
    elif state["state"] in {"FAILED", "ABORTED"}:
        transition(experiment_dir, "RUNNING")
    elif state["state"] != "RUNNING":
        raise FrameworkError(
            "execute requires READY, RUNNING, FAILED, or ABORTED state; "
            f"current state is {state['state']}"
        )

    schedule = read_json(
        experiment_dir / "execution" / "schedule.json"
    )
    resolved = read_json(experiment_dir / "config" / "resolved.json")
    control = normalize_measurement_control(resolved.get("measurement_control"))

    try:
        with host_state_session(control) as host_session:
            calibration_id: str | None = None
            calibration: dict[str, Any] | None = None

            if control["host_state"]["enabled"]:
                capabilities = validate_host_state_capabilities(
                    control, session=host_session
                )
                if not capabilities["passed"]:
                    raise FrameworkError(
                        "host-state capabilities failed before execution: "
                        + "; ".join(capabilities.get("errors", []))
                    )

                if control["calibration"]["enabled"]:
                    calibration_id, calibration_path = _allocate_host_control_session(
                        experiment_dir
                    )

                    def record_calibration_snapshot(snapshot: dict[str, Any]) -> None:
                        record = dict(snapshot)
                        record.update({
                            "experiment_id": experiment_dir.name,
                            "run_id": None,
                            "pair_id": None,
                            "variant": None,
                            "repetition": None,
                            "condition_id": None,
                            "sequence": None,
                            "phase": "calibration",
                            "host_calibration_id": calibration_id,
                        })
                        append_jsonl(
                            experiment_dir / "raw" / "host-state.jsonl",
                            record,
                        )

                    print(
                        "host-calibration: collecting "
                        f"{control['calibration']['samples']} idle samples; "
                        "keep the benchmark host idle"
                    )
                    calibration = calibrate_host_state(
                        control,
                        session=host_session,
                        on_snapshot=record_calibration_snapshot,
                    )
                    calibration = dict(calibration)
                    calibration["session_id"] = calibration_id
                    atomic_write_json(calibration_path, calibration)
                    busy = calibration["cpu_busy_percent"]
                    print(
                        "host-calibration: PASS "
                        f"median={busy['median']:.1f}% "
                        f"q{int(round(busy['upper_quantile'] * 100))}="
                        f"{busy['upper_limit']:.1f}%"
                    )

            for run in schedule["runs"]:
                if _latest_valid_attempt(
                    experiment_dir,
                    run["run_id"],
                ):
                    continue

                append_log(
                    experiment_dir / "logs" / "framework.log",
                    f"{utc_rfc3339()} executing "
                    f"{run['run_id']} variant={run['variant']}",
                )

                measurement = _execute_run(
                    experiment_dir,
                    run,
                    host_session=host_session,
                    host_calibration=calibration,
                    host_calibration_id=calibration_id,
                )

                completed, failed = _recount(
                    experiment_dir,
                    schedule,
                )
                update_run_counts(
                    experiment_dir,
                    completed=completed,
                    failed=failed,
                )

                if not measurement["execution"]["valid"]:
                    transition(
                        experiment_dir,
                        "FAILED",
                        failure={
                            "stage": "running",
                            "message": (
                                measurement["execution"]["failure"]
                                or "HTTP/3 run failed"
                            ),
                            "run_id": run["run_id"],
                        },
                    )
                    raise FrameworkError(
                        f"HTTP/3 run failed: {run['run_id']}: "
                        f"{measurement['execution']['failure']}"
                    )

            completed, failed = _recount(
                experiment_dir,
                schedule,
            )
            update_run_counts(
                experiment_dir,
                completed=completed,
                failed=failed,
            )

            if completed != len(schedule["runs"]):
                raise FrameworkError(
                    "HTTP/3 schedule ended without all runs completing"
                )

            transition(experiment_dir, "ANALYZING")

    except KeyboardInterrupt:
        current = load_state(experiment_dir)
        if current["state"] == "RUNNING":
            transition(experiment_dir, "ABORTED")
        raise
    except Exception as exc:
        current = load_state(experiment_dir)
        if current["state"] == "RUNNING":
            transition(
                experiment_dir,
                "FAILED",
                failure={
                    "stage": "running",
                    "message": str(exc),
                    "run_id": None,
                },
            )
        raise

