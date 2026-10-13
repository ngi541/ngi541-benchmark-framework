from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from framework.io_utils import FrameworkError, atomic_write_json, atomic_write_text
from framework.loadgen_runtime import (
    definition_sha256 as loadgen_definition_sha256,
    load_definition as load_loadgen_definition,
)
from framework.network_evidence import (
    definition_sha256 as network_evidence_definition_sha256,
    load_definition as load_network_evidence_definition,
)
from framework.network_qualification import SSHSession
from framework.scientific_corpus import (
    load_definition as load_corpus_definition,
    materialize_surrogate,
    run_scientific_corpus,
    stream_object_descriptor,
)

SCHEMA_VERSION = 1
TRANSPORT = "http3-only"
TLS_VERSION = "1.3"
DEFAULT_CIPHER = "TLS_AES_128_GCM_SHA256"


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _semantic_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def definition_sha256(definition: dict[str, Any]) -> str:
    return _semantic_sha256(definition)


def _slug(text: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    if not value:
        raise FrameworkError("qualification.name must contain an alphanumeric character")
    return value


def _portable_relative_path(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FrameworkError(f"{field} must be a non-empty repository-relative path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise FrameworkError(f"{field} must be a repository-relative path without '..'")
    return value


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise FrameworkError(f"{field} must be a positive integer")
    return value


def _validate_sha(value: Any, field: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise FrameworkError(f"{field} must be a 64-digit SHA-256")
    return value.lower()


def load_definition(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FrameworkError(f"transport security config not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise FrameworkError(
            f"invalid transport security JSON: {path}: line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    validate_definition(value)
    return value


def validate_definition(definition: dict[str, Any]) -> None:
    if definition.get("schema_version") != SCHEMA_VERSION:
        raise FrameworkError("transport security schema_version must be 1")

    qualification = definition.get("qualification")
    if not isinstance(qualification, dict) or not isinstance(qualification.get("name"), str) or not qualification["name"].strip():
        raise FrameworkError("qualification.name must be a non-empty string")

    inputs = definition.get("inputs")
    if not isinstance(inputs, dict):
        raise FrameworkError("inputs must be an object")
    for field in ("network_evidence_config", "loadgen_runtime_config", "scientific_corpus_config"):
        _portable_relative_path(inputs.get(field), f"inputs.{field}")

    transport = definition.get("transport")
    if not isinstance(transport, dict):
        raise FrameworkError("transport must be an object")
    if transport.get("protocol") != TRANSPORT:
        raise FrameworkError("transport.protocol must be 'http3-only'")
    if str(transport.get("tls_version")) != TLS_VERSION:
        raise FrameworkError("transport.tls_version must be '1.3'")
    cipher = transport.get("cipher_suite")
    if not isinstance(cipher, str) or not cipher:
        raise FrameworkError("transport.cipher_suite must be a non-empty string")
    if transport.get("verify_peer") is not True:
        raise FrameworkError("transport.verify_peer must be true")
    if transport.get("allow_0rtt") is not False:
        raise FrameworkError("transport.allow_0rtt must be false")

    server = definition.get("server")
    if not isinstance(server, dict):
        raise FrameworkError("server must be an object")
    if not isinstance(server.get("name"), str) or not server["name"].strip():
        raise FrameworkError("server.name must be a non-empty DNS name")
    _positive_int(server.get("port"), "server.port")
    _positive_int(server.get("workers", 1), "server.workers")
    _positive_int(server.get("worker_connections", 4096), "server.worker_connections")
    _positive_int(server.get("startup_timeout_seconds", 10), "server.startup_timeout_seconds")
    _positive_int(server.get("client_timeout_seconds", 30), "server.client_timeout_seconds")

    variants = definition.get("variants")
    if not isinstance(variants, dict) or set(variants) != {"stock", "ngi541-direct"}:
        raise FrameworkError("variants must contain exactly stock and ngi541-direct")
    for name, spec in variants.items():
        if not isinstance(spec, dict):
            raise FrameworkError(f"variants.{name} must be an object")
        _portable_relative_path(spec.get("binary"), f"variants.{name}.binary")
        _validate_sha(spec.get("sha256"), f"variants.{name}.sha256")
        libraries = spec.get("runtime_libraries", [])
        if not isinstance(libraries, list):
            raise FrameworkError(f"variants.{name}.runtime_libraries must be an array")
        for index, library in enumerate(libraries):
            if not isinstance(library, dict):
                raise FrameworkError(f"variants.{name}.runtime_libraries[{index}] must be an object")
            _portable_relative_path(library.get("path"), f"variants.{name}.runtime_libraries[{index}].path")
            _validate_sha(library.get("sha256"), f"variants.{name}.runtime_libraries[{index}].sha256")

    smoke = definition.get("smoke")
    if not isinstance(smoke, dict):
        raise FrameworkError("smoke must be an object")
    objects = smoke.get("objects")
    if not isinstance(objects, list) or not objects:
        raise FrameworkError("smoke.objects must be a non-empty array")
    seen_profiles: set[str] = set()
    for index, item in enumerate(objects):
        if not isinstance(item, dict):
            raise FrameworkError(f"smoke.objects[{index}] must be an object")
        profile_id = item.get("profile_id")
        if profile_id not in {
            "clas12-event-stream",
            "lcls-detector-frame",
            "hacc-multifile-dataset",
        }:
            raise FrameworkError(f"unsupported smoke profile_id: {profile_id!r}")
        if profile_id in seen_profiles:
            raise FrameworkError(f"duplicate smoke profile_id: {profile_id}")
        seen_profiles.add(profile_id)
        selector = item.get("selector")
        if not isinstance(selector, dict):
            raise FrameworkError(f"smoke.objects[{index}].selector must be an object")
        kind = selector.get("kind")
        if profile_id in {"clas12-event-stream", "lcls-detector-frame"}:
            if kind != "stream-index":
                raise FrameworkError(f"{profile_id} smoke selector kind must be 'stream-index'")
            stream_index = selector.get("index")
            if isinstance(stream_index, bool) or not isinstance(stream_index, int) or stream_index < 0:
                raise FrameworkError(f"{profile_id} smoke selector index must be an integer >= 0")
        else:
            if kind != "bucket-first":
                raise FrameworkError("HACC smoke selector kind must be 'bucket-first'")
            bucket = selector.get("bucket_index")
            if isinstance(bucket, bool) or not isinstance(bucket, int) or bucket < 0:
                raise FrameworkError("HACC smoke selector bucket_index must be an integer >= 0")

    required = {"clas12-event-stream", "lcls-detector-frame", "hacc-multifile-dataset"}
    if seen_profiles != required:
        raise FrameworkError("smoke.objects must contain exactly one CLAS12, LCLS, and HACC selector")


def _resolve_repo_path(repo_root: Path, value: str, field: str) -> Path:
    path = (repo_root / value).resolve()
    try:
        path.relative_to(repo_root.resolve())
    except ValueError as exc:
        raise FrameworkError(f"{field} escapes repository root: {value}") from exc
    return path


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FrameworkError(f"missing {label}: {path}") from exc
    except json.JSONDecodeError as exc:
        raise FrameworkError(f"invalid {label} JSON: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise FrameworkError(f"{label} must be a JSON object: {path}")
    return value


def _verify_artifact_inventory(root: Path) -> None:
    inventory = root / "artifacts.sha256"
    if not inventory.is_file():
        raise FrameworkError(f"missing artifact inventory: {inventory}")
    for line in inventory.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            expected, rel = line.split("  ", 1)
        except ValueError as exc:
            raise FrameworkError(f"invalid artifact inventory line in {root.name}: {line}") from exc
        path = root / rel
        if not path.is_file():
            raise FrameworkError(f"missing artifact listed by {root.name}: {rel}")
        actual = _sha256_file(path)
        if actual != expected:
            raise FrameworkError(
                f"artifact hash mismatch in {root.name}: {rel}; expected={expected} actual={actual}"
            )


def _discover_latest_summary(
    root: Path,
    *,
    definition_sha: str,
    id_field: str,
    require_inventory: bool,
) -> tuple[Path, dict[str, Any]]:
    matches: list[tuple[str, Path, dict[str, Any]]] = []
    if not root.is_dir():
        raise FrameworkError(f"qualification root not found: {root}")
    for child in sorted(path for path in root.iterdir() if path.is_dir()):
        summary_path = child / "processed" / "summary.json"
        if not summary_path.is_file():
            continue
        summary = _read_json(summary_path, "qualification summary")
        if summary.get("status") != "COMPLETE" or summary.get("definition_sha256") != definition_sha:
            continue
        if summary.get(id_field) != child.name:
            raise FrameworkError(f"qualification id/path mismatch in {child}")
        if require_inventory:
            _verify_artifact_inventory(child)
        matches.append((child.name, child, summary))
    if not matches:
        raise FrameworkError(
            f"no COMPLETE qualification with definition SHA {definition_sha} found in {root}"
        )
    _, child, summary = matches[-1]
    return child, summary


def _resolve_network_input(definition: dict[str, Any], repo_root: Path) -> dict[str, Any]:
    path = _resolve_repo_path(repo_root, definition["inputs"]["network_evidence_config"], "inputs.network_evidence_config")
    evidence_definition = load_network_evidence_definition(path)
    definition_sha = network_evidence_definition_sha256(evidence_definition)
    root, summary = _discover_latest_summary(
        repo_root / "qualifications" / "network-evidence",
        definition_sha=definition_sha,
        id_field="evidence_id",
        require_inventory=True,
    )
    envelope_path = root / "processed" / "network-envelope.json"
    envelope = _read_json(envelope_path, "network envelope")
    if envelope.get("direction_semantic") != "dut-to-loadgen":
        raise FrameworkError("network evidence direction must be dut-to-loadgen")
    topology = envelope.get("topology", {})
    local = topology.get("local", {})
    remote = topology.get("remote", {})
    if local.get("system") != "Darwin" or not local.get("address"):
        raise FrameworkError("R6.5.3e expects a Darwin local DUT address from network evidence")
    if remote.get("system") != "Linux" or not remote.get("address"):
        raise FrameworkError("R6.5.3e expects a Linux remote loadgen address from network evidence")
    return {
        "root": root,
        "summary": summary,
        "envelope": envelope,
        "envelope_sha256": _sha256_file(envelope_path),
        "dut_address": local["address"],
        "loadgen_address": remote["address"],
    }


def _resolve_loadgen_input(definition: dict[str, Any], repo_root: Path) -> dict[str, Any]:
    path = _resolve_repo_path(repo_root, definition["inputs"]["loadgen_runtime_config"], "inputs.loadgen_runtime_config")
    runtime_definition = load_loadgen_definition(path)
    definition_sha = loadgen_definition_sha256(runtime_definition)
    root, summary = _discover_latest_summary(
        repo_root / "qualifications" / "loadgen-runtime",
        definition_sha=definition_sha,
        id_field="runtime_id",
        require_inventory=False,
    )
    runtime = summary.get("runtime", {})
    h2load = runtime.get("h2load")
    if runtime.get("http3_capable") is not True or not isinstance(h2load, dict) or h2load.get("http3_capable") is not True:
        raise FrameworkError("resolved load-generator runtime is not HTTP/3 capable for curl and h2load")
    if summary.get("remote", {}).get("ssh_target") != runtime_definition["remote"]["ssh_target"]:
        raise FrameworkError("load-generator runtime SSH target does not match its definition")
    return {
        "root": root,
        "summary": summary,
        "definition": runtime_definition,
        "summary_sha256": _sha256_file(root / "processed" / "summary.json"),
    }


def _resolve_corpus_input(definition: dict[str, Any], repo_root: Path) -> dict[str, Any]:
    path = _resolve_repo_path(repo_root, definition["inputs"]["scientific_corpus_config"], "inputs.scientific_corpus_config")
    corpus_definition = load_corpus_definition(path)
    result = run_scientific_corpus(
        corpus_definition,
        repo_root=repo_root,
        output_root=repo_root / "corpora" / "scientific",
    )
    root = result["root"]
    manifests: dict[str, dict[str, Any]] = {}
    for profile in result["summary"]["profiles"]:
        profile_id = profile["profile_id"]
        manifests[profile_id] = _read_json(
            root / "processed" / "profiles" / f"{profile_id}-v{profile['profile_version']}.corpus.json",
            f"{profile_id} corpus manifest",
        )
    return {
        "root": root,
        "summary": result["summary"],
        "summary_sha256": _sha256_file(root / "processed" / "summary.json"),
        "manifests": manifests,
    }


def select_smoke_objects(
    definition: dict[str, Any],
    manifests: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for item in definition["smoke"]["objects"]:
        profile_id = item["profile_id"]
        manifest = manifests[profile_id]
        selector = item["selector"]
        if selector["kind"] == "stream-index":
            descriptor = stream_object_descriptor(manifest, int(selector["index"]))
        else:
            bucket_index = int(selector["bucket_index"])
            candidates = [
                obj for obj in manifest.get("objects", [])
                if int(obj.get("bucket_index", -1)) == bucket_index
            ]
            if not candidates:
                raise FrameworkError(
                    f"HACC smoke selector bucket {bucket_index} has no corpus objects"
                )
            descriptor = min(candidates, key=lambda obj: (int(obj["sequence"]), str(obj["object_id"])))
        selected.append({
            "profile_id": profile_id,
            "profile_version": manifest["profile"]["profile_version"],
            "profile_sha256": manifest["profile"]["profile_sha256"],
            "corpus_sha256": manifest["corpus_sha256"],
            "object_id": descriptor["object_id"],
            "size_bytes": int(descriptor["size_bytes"]),
            "content_seed_u64_hex": descriptor["content_seed_u64_hex"],
            "content_recipe_sha256": descriptor["content_recipe_sha256"],
        })
    return sorted(selected, key=lambda row: row["profile_id"])


def _materialize_smoke_objects(
    objects: list[dict[str, Any]],
    *,
    root: Path,
    chunk_bytes: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in objects:
        safe_object = re.sub(r"[^A-Za-z0-9._-]+", "-", item["object_id"])
        rel = Path("scientific") / item["profile_id"] / f"{safe_object}.bin"
        path = root / rel
        result = materialize_surrogate(
            path,
            seed_u64=int(item["content_seed_u64_hex"], 16),
            size_bytes=int(item["size_bytes"]),
            chunk_bytes=chunk_bytes,
        )
        rows.append({**item, "relative_path": rel.as_posix(), "sha256": result["sha256"]})
    return rows


def nginx_config(
    *,
    host: str,
    port: int,
    workers: int,
    worker_connections: int,
    cipher_suite: str,
) -> str:
    reuseport = " reuseport" if workers > 1 else ""
    return f"""worker_processes {workers};
pid logs/nginx.pid;
error_log stderr notice;

events {{
    worker_connections {worker_connections};
}}

http {{
    access_log off;

    server {{
        listen {host}:{port} quic{reuseport};
        server_name ngi541-dut.local;

        ssl_protocols TLSv1.3;
        ssl_certificate server.crt;
        ssl_certificate_key server.key;
        ssl_conf_command Ciphersuites {cipher_suite};
        ssl_early_data off;

        http3 on;
        root html;
    }}
}}
"""


def curl_smoke_command(
    *,
    curl_binary: str,
    server_name: str,
    host: str,
    port: int,
    cipher_suite: str,
    ca_path: str,
    object_path: str,
    output_path: str,
    timeout_seconds: int,
) -> list[str]:
    return [
        curl_binary,
        "--http3-only",
        "--tlsv1.3",
        "--tls-max", "1.3",
        "--tls13-ciphers", cipher_suite,
        "--cacert", ca_path,
        "--resolve", f"{server_name}:{port}:{host}",
        "--silent",
        "--show-error",
        "--fail",
        "--verbose",
        "--connect-timeout", str(timeout_seconds),
        "--max-time", str(timeout_seconds),
        "--output", output_path,
        "--write-out", "%{http_version}\t%{response_code}\t%{ssl_verify_result}\t%{size_download}\\n",
        f"https://{server_name}:{port}/{object_path}",
    ]


def parse_curl_writeout(text: str) -> dict[str, Any]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise FrameworkError("remote curl smoke produced no write-out result")
    fields = lines[-1].split("\t")
    if len(fields) != 4:
        raise FrameworkError(f"unexpected curl write-out result: {lines[-1]!r}")
    try:
        response_code = int(fields[1])
        ssl_verify_result = int(fields[2])
        size_download = int(round(float(fields[3])))
    except ValueError as exc:
        raise FrameworkError(f"invalid curl write-out result: {lines[-1]!r}") from exc
    return {
        "http_version": fields[0],
        "response_code": response_code,
        "ssl_verify_result": ssl_verify_result,
        "size_download": size_download,
    }


def h2load_smoke_command(
    *,
    h2load_binary: str,
    server_name: str,
    host: str,
    port: int,
    cipher_suite: str,
    ca_path: str,
    object_path: str,
    json_path: str,
) -> list[str]:
    return [
        "env",
        f"SSL_CERT_FILE={ca_path}",
        h2load_binary,
        "--h3",
        "--tls13-ciphers", cipher_suite,
        "--connect-to", f"{host}:{port}",
        "--sni", server_name,
        "--output-file", json_path,
        "-n", "1",
        "-c", "1",
        "-m", "1",
        "-t", "1",
        f"https://{server_name}:{port}/{object_path}",
    ]


def parse_h2load_stdout(text: str, *, cipher_suite: str) -> dict[str, Any]:
    protocol = None
    cipher = None
    request_match = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("TLS Protocol:"):
            protocol = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Cipher:"):
            cipher = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("requests:"):
            request_match = re.search(
                r"requests:\s+(\d+) total,\s+(\d+) started,\s+(\d+) done,\s+(\d+) succeeded,\s+(\d+) failed,\s+(\d+) errored",
                stripped,
            )
    if request_match is None:
        raise FrameworkError("h2load smoke output does not contain request summary")
    values = [int(value) for value in request_match.groups()]
    result = {
        "tls_protocol": protocol,
        "cipher": cipher,
        "requests_total": values[0],
        "requests_started": values[1],
        "requests_done": values[2],
        "requests_succeeded": values[3],
        "requests_failed": values[4],
        "requests_errored": values[5],
    }
    result["passed"] = (
        protocol == "TLSv1.3"
        and cipher == cipher_suite
        and values[0] == 1
        and values[2] == 1
        and values[3] == 1
        and values[4] == 0
        and values[5] == 0
    )
    return result


def _variant_environment(spec: dict[str, Any], repo_root: Path) -> dict[str, str]:
    env = dict(os.environ)
    library_dirs: list[str] = []
    for library in spec.get("runtime_libraries", []):
        path = _resolve_repo_path(repo_root, library["path"], "runtime library")
        if _sha256_file(path) != library["sha256"].lower():
            raise FrameworkError(f"runtime library hash mismatch: {library['path']}")
        library_dirs.append(str(path.parent))
    if library_dirs:
        joined = os.pathsep.join(dict.fromkeys(library_dirs))
        for key in ("DYLD_LIBRARY_PATH", "LD_LIBRARY_PATH"):
            previous = env.get(key)
            env[key] = joined if not previous else joined + os.pathsep + previous
    return env


def _generate_tls_material(
    *,
    openssl: str,
    root: Path,
    server_name: str,
    host: str,
) -> dict[str, Path]:
    root.mkdir(parents=True, exist_ok=True)
    ca_key = root / "ca.key"
    ca_crt = root / "ca.crt"
    server_key = root / "server.key"
    server_csr = root / "server.csr"
    server_crt = root / "server.crt"
    ext = root / "server.ext"
    atomic_write_text(
        ext,
        "basicConstraints=CA:FALSE\n"
        "keyUsage=digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        f"subjectAltName=DNS:{server_name},IP:{host}\n",
    )
    commands = [
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key), "-out", str(ca_crt), "-subj", "/CN=NGI541 R6.5.3e Test CA", "-days", "1", "-sha256"],
        [openssl, "req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(server_key), "-out", str(server_csr), "-subj", f"/CN={server_name}", "-sha256"],
        [openssl, "x509", "-req", "-in", str(server_csr), "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(server_crt), "-days", "1", "-sha256", "-extfile", str(ext)],
    ]
    for command in commands:
        result = subprocess.run(command, check=False, text=True, capture_output=True)
        if result.returncode != 0:
            raise FrameworkError(
                "failed to generate R6.5.3e TLS material: " + (result.stderr.strip() or shlex.join(command))
            )
    return {"ca_crt": ca_crt, "server_crt": server_crt, "server_key": server_key}


def _write_remote_file_base64(ssh: SSHSession, remote_path: str, data: bytes) -> None:
    encoded = base64.b64encode(data).decode("ascii")
    command = (
        f"umask 077; mkdir -p {shlex.quote(str(Path(remote_path).parent))}; "
        f"printf '%s' {shlex.quote(encoded)} | base64 -d > {shlex.quote(remote_path)}"
    )
    ssh.run(["bash", "-lc", command], check=True, timeout=30)


def _stop_server(process: subprocess.Popen[Any]) -> None:
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


def _artifact_hashes(root: Path) -> str:
    lines: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == "artifacts.sha256":
            continue
        lines.append(f"{_sha256_file(path)}  {path.relative_to(root).as_posix()}")
    return "\n".join(lines) + "\n"


def _record_input_identity(
    *,
    network: dict[str, Any],
    loadgen: dict[str, Any],
    corpus: dict[str, Any],
    definition: dict[str, Any],
) -> dict[str, Any]:
    value = {
        "schema_version": 1,
        "network_evidence": {
            "evidence_id": network["summary"]["evidence_id"],
            "envelope_sha256": network["envelope"]["envelope_sha256"],
            "artifact_sha256": network["envelope_sha256"],
        },
        "loadgen_runtime": {
            "runtime_id": loadgen["summary"]["runtime_id"],
            "summary_sha256": loadgen["summary_sha256"],
            "curl_sha256": loadgen["summary"]["runtime"]["curl_sha256"],
            "h2load_sha256": loadgen["summary"]["runtime"]["h2load"]["sha256"],
        },
        "scientific_corpus": {
            "corpus_id": corpus["summary"]["corpus_id"],
            "summary_sha256": corpus["summary_sha256"],
            "input_sha256": corpus["summary"]["input_sha256"],
        },
        "variants": {
            name: {
                "binary": spec["binary"],
                "sha256": spec["sha256"].lower(),
                "runtime_libraries": [
                    {"path": row["path"], "sha256": row["sha256"].lower()}
                    for row in spec.get("runtime_libraries", [])
                ],
            }
            for name, spec in sorted(definition["variants"].items())
        },
    }
    value["input_sha256"] = _semantic_sha256(value)
    return value


def run_transport_security(
    definition: dict[str, Any],
    *,
    repo_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    validate_definition(definition)
    network = _resolve_network_input(definition, repo_root)
    loadgen = _resolve_loadgen_input(definition, repo_root)
    corpus = _resolve_corpus_input(definition, repo_root)

    runtime_def = loadgen["definition"]
    ssh_target = runtime_def["remote"]["ssh_target"]
    remote_timeout = int(runtime_def["remote"].get("connect_timeout_seconds", 10))
    server_cfg = definition["server"]
    transport = definition["transport"]
    host = network["dut_address"]
    server_name = server_cfg["name"]
    port = int(server_cfg["port"])

    input_identity = _record_input_identity(
        network=network,
        loadgen=loadgen,
        corpus=corpus,
        definition=definition,
    )
    def_sha = definition_sha256(definition)
    qualification_id = (
        f"{_slug(definition['qualification']['name'])}-{_utc_timestamp()}-{def_sha[:6]}"
    )
    root = output_root / qualification_id
    if root.exists():
        raise FrameworkError(f"refusing to overwrite transport security qualification: {root}")
    inputs_dir = root / "inputs"
    raw_dir = root / "raw"
    processed_dir = root / "processed"
    inputs_dir.mkdir(parents=True)
    raw_dir.mkdir(parents=True)
    processed_dir.mkdir(parents=True)

    atomic_write_json(root / "config.json", {
        "schema_version": 1,
        "definition_sha256": def_sha,
        "definition": definition,
    })
    atomic_write_json(inputs_dir / "resolved-inputs.json", input_identity)

    for name, spec in definition["variants"].items():
        binary = _resolve_repo_path(repo_root, spec["binary"], f"variants.{name}.binary")
        actual = _sha256_file(binary)
        if actual != spec["sha256"].lower():
            raise FrameworkError(
                f"variant binary hash mismatch for {name}: expected={spec['sha256']} actual={actual}"
            )
        _variant_environment(spec, repo_root)

    smoke_objects = select_smoke_objects(definition, corpus["manifests"])
    chunk_bytes = int(load_corpus_definition(
        _resolve_repo_path(repo_root, definition["inputs"]["scientific_corpus_config"], "inputs.scientific_corpus_config")
    )["materialization"]["chunk_bytes"])

    openssl = shutil.which("openssl") or "/usr/bin/openssl"
    if not Path(openssl).is_file():
        raise FrameworkError("openssl command is required for R6.5.3e certificate generation")
    openssl_version = subprocess.run([openssl, "version", "-a"], check=False, text=True, capture_output=True)
    if openssl_version.returncode != 0:
        raise FrameworkError("unable to query local openssl version")
    atomic_write_text(raw_dir / "openssl-version.txt", openssl_version.stdout + openssl_version.stderr)

    runtime = loadgen["summary"]["runtime"]
    curl_bin = runtime["curl_binary"]
    h2load_bin = runtime["h2load"]["binary"]
    curl_sha = runtime["curl_sha256"]
    h2load_sha = runtime["h2load"]["sha256"]

    variant_results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="ngi541-r653e-") as temp_name:
        temp = Path(temp_name)
        object_root = temp / "objects"
        materialized = _materialize_smoke_objects(
            smoke_objects,
            root=object_root,
            chunk_bytes=chunk_bytes,
        )
        atomic_write_json(processed_dir / "scientific-objects.json", {
            "schema_version": 1,
            "objects": materialized,
            "selection_sha256": _semantic_sha256(materialized),
        })

        tls = _generate_tls_material(
            openssl=openssl,
            root=temp / "tls",
            server_name=server_name,
            host=host,
        )
        shutil.copy2(tls["ca_crt"], raw_dir / "ca.crt")
        shutil.copy2(tls["server_crt"], raw_dir / "server.crt")
        tls_public = {
            "ca_sha256": _sha256_file(tls["ca_crt"]),
            "server_cert_sha256": _sha256_file(tls["server_crt"]),
            "server_name": server_name,
            "subject_alt_names": [f"DNS:{server_name}", f"IP:{host}"],
        }
        atomic_write_json(processed_dir / "tls-material.json", tls_public)

        with SSHSession(ssh_target, remote_timeout) as ssh:
            remote_root = f"/tmp/{qualification_id}"
            ssh.run(["bash", "-lc", f"rm -rf {shlex.quote(remote_root)} && mkdir -p {shlex.quote(remote_root)}"], check=True)
            try:
                _write_remote_file_base64(ssh, f"{remote_root}/ca.crt", tls["ca_crt"].read_bytes())

                # Verify that the actual remote executables still match the frozen R6.5.3b evidence.
                curl_hash_result = ssh.run(["sha256sum", curl_bin], check=True)
                h2load_hash_result = ssh.run(["sha256sum", h2load_bin], check=True)
                remote_curl_sha = curl_hash_result.stdout.strip().split()[0]
                remote_h2load_sha = h2load_hash_result.stdout.strip().split()[0]
                if remote_curl_sha != curl_sha:
                    raise FrameworkError("remote curl SHA-256 no longer matches R6.5.3b evidence")
                if remote_h2load_sha != h2load_sha:
                    raise FrameworkError("remote h2load SHA-256 no longer matches R6.5.3b evidence")

                for variant in ("stock", "ngi541-direct"):
                    variant_raw = raw_dir / variant
                    variant_raw.mkdir(parents=True, exist_ok=True)
                    spec = definition["variants"][variant]
                    binary = _resolve_repo_path(repo_root, spec["binary"], f"variants.{variant}.binary")
                    env = _variant_environment(spec, repo_root)
                    server_runtime = temp / "server" / variant
                    for rel in ("conf", "html", "logs"):
                        (server_runtime / rel).mkdir(parents=True, exist_ok=True)
                    for obj in materialized:
                        source = object_root / obj["relative_path"]
                        destination = server_runtime / "html" / obj["relative_path"]
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        try:
                            os.link(source, destination)
                        except OSError:
                            shutil.copy2(source, destination)
                    shutil.copy2(tls["server_crt"], server_runtime / "conf" / "server.crt")
                    shutil.copy2(tls["server_key"], server_runtime / "conf" / "server.key")
                    config = nginx_config(
                        host=host,
                        port=port,
                        workers=int(server_cfg.get("workers", 1)),
                        worker_connections=int(server_cfg.get("worker_connections", 4096)),
                        cipher_suite=transport["cipher_suite"],
                    ).replace("server_name ngi541-dut.local;", f"server_name {server_name};")
                    atomic_write_text(server_runtime / "conf" / "nginx.conf", config)

                    test_result = subprocess.run(
                        [str(binary), "-p", str(server_runtime) + os.sep, "-c", "conf/nginx.conf", "-t"],
                        env=env,
                        check=False,
                        text=True,
                        capture_output=True,
                    )
                    atomic_write_text(variant_raw / "nginx-test.stdout.log", test_result.stdout)
                    atomic_write_text(variant_raw / "nginx-test.stderr.log", test_result.stderr)
                    if test_result.returncode != 0:
                        raise FrameworkError(f"NGINX configuration test failed for {variant}")

                    stdout_handle = (variant_raw / "server.stdout.log").open("wb")
                    stderr_handle = (variant_raw / "server.stderr.log").open("wb")
                    process = subprocess.Popen(
                        [str(binary), "-p", str(server_runtime) + os.sep, "-c", "conf/nginx.conf", "-g", "daemon off;"],
                        env=env,
                        stdout=stdout_handle,
                        stderr=stderr_handle,
                        start_new_session=True,
                    )
                    try:
                        deadline = time.monotonic() + int(server_cfg.get("startup_timeout_seconds", 10))
                        object_results: list[dict[str, Any]] | None = None
                        last_error = "remote security probe did not run"
                        while time.monotonic() < deadline:
                            if process.poll() is not None:
                                raise FrameworkError(f"NGINX {variant} exited during startup with code {process.returncode}")
                            try:
                                object_results = []
                                for index, obj in enumerate(materialized):
                                    remote_output = f"{remote_root}/{variant}-{index:02d}.bin"
                                    cmd = curl_smoke_command(
                                        curl_binary=curl_bin,
                                        server_name=server_name,
                                        host=host,
                                        port=port,
                                        cipher_suite=transport["cipher_suite"],
                                        ca_path=f"{remote_root}/ca.crt",
                                        object_path=obj["relative_path"],
                                        output_path=remote_output,
                                        timeout_seconds=int(server_cfg.get("client_timeout_seconds", 30)),
                                    )
                                    result = ssh.run(cmd, check=False, timeout=float(server_cfg.get("client_timeout_seconds", 30)) + 5)
                                    parsed = parse_curl_writeout(result.stdout) if result.returncode == 0 else None
                                    hash_result = ssh.run(["sha256sum", remote_output], check=False) if result.returncode == 0 else None
                                    remote_sha = (
                                        hash_result.stdout.strip().split()[0]
                                        if hash_result is not None and hash_result.returncode == 0 and hash_result.stdout.strip()
                                        else None
                                    )
                                    passed = bool(
                                        result.returncode == 0
                                        and parsed is not None
                                        and str(parsed["http_version"]).startswith("3")
                                        and parsed["response_code"] == 200
                                        and parsed["ssl_verify_result"] == 0
                                        and parsed["size_download"] == obj["size_bytes"]
                                        and remote_sha == obj["sha256"]
                                    )
                                    record = {
                                        "profile_id": obj["profile_id"],
                                        "object_id": obj["object_id"],
                                        "size_bytes": obj["size_bytes"],
                                        "expected_sha256": obj["sha256"],
                                        "remote_sha256": remote_sha,
                                        "curl_exit_code": result.returncode,
                                        "curl": parsed,
                                        "passed": passed,
                                    }
                                    object_results.append(record)
                                    atomic_write_json(variant_raw / f"curl-{index:02d}.json", {
                                        **record,
                                        "argv": result.argv,
                                        "stdout": result.stdout,
                                        "stderr": result.stderr,
                                    })
                                    if not passed:
                                        last_error = (
                                            result.stderr.strip()
                                            or f"curl security/correctness gate failed for {obj['profile_id']}"
                                        )
                                        raise FrameworkError(last_error)
                                break
                            except FrameworkError as exc:
                                object_results = None
                                last_error = str(exc)
                                time.sleep(0.25)
                        if object_results is None:
                            raise FrameworkError(f"remote HTTP/3 security smoke did not become ready for {variant}: {last_error}")

                        # Exercise the actual R6.5.3b h2load QUIC path once per variant.
                        probe_obj = next(obj for obj in materialized if obj["profile_id"] == "clas12-event-stream")
                        remote_json = f"{remote_root}/{variant}-h2load.json"
                        h2cmd = h2load_smoke_command(
                            h2load_binary=h2load_bin,
                            server_name=server_name,
                            host=host,
                            port=port,
                            cipher_suite=transport["cipher_suite"],
                            ca_path=f"{remote_root}/ca.crt",
                            object_path=probe_obj["relative_path"],
                            json_path=remote_json,
                        )
                        h2result = ssh.run(h2cmd, check=False, timeout=float(server_cfg.get("client_timeout_seconds", 30)) + 5)
                        h2parsed = parse_h2load_stdout(h2result.stdout, cipher_suite=transport["cipher_suite"]) if h2result.returncode == 0 else {"passed": False}
                        h2json_result = ssh.run(["cat", remote_json], check=False) if h2result.returncode == 0 else None
                        h2json_valid = False
                        if h2json_result is not None and h2json_result.returncode == 0:
                            try:
                                json.loads(h2json_result.stdout)
                                h2json_valid = True
                            except json.JSONDecodeError:
                                h2json_valid = False
                        h2passed = h2result.returncode == 0 and bool(h2parsed.get("passed")) and h2json_valid
                        atomic_write_json(variant_raw / "h2load.json", {
                            "argv": h2result.argv,
                            "stdout": h2result.stdout,
                            "stderr": h2result.stderr,
                            "parsed": h2parsed,
                            "json_output_valid": h2json_valid,
                            "json_output": h2json_result.stdout if h2json_result is not None else None,
                            "passed": h2passed,
                        })
                        if not h2passed:
                            raise FrameworkError(f"h2load HTTP/3 functional smoke failed for {variant}")

                        variant_results.append({
                            "variant": variant,
                            "binary_sha256": spec["sha256"].lower(),
                            "curl_objects": object_results,
                            "h2load": h2parsed,
                            "passed": all(row["passed"] for row in object_results) and h2passed,
                        })
                    finally:
                        _stop_server(process)
                        stdout_handle.close()
                        stderr_handle.close()
            finally:
                ssh.run(["bash", "-lc", f"rm -rf {shlex.quote(remote_root)}"], check=False)

    security_gate = {
        "schema_version": 1,
        "protocol": TRANSPORT,
        "tls_version": TLS_VERSION,
        "cipher_suite": transport["cipher_suite"],
        "peer_verification": "required-and-verified-by-curl",
        "zero_rtt": "disabled",
        "http_fallback": "prohibited",
        "server_name": server_name,
        "dut_address": host,
        "loadgen_address": network["loadgen_address"],
        "variants": variant_results,
        "passed": all(row["passed"] for row in variant_results),
    }
    security_gate["security_gate_sha256"] = _semantic_sha256(security_gate)
    atomic_write_json(processed_dir / "security-gate.json", security_gate)

    summary = {
        "schema_version": 1,
        "qualification_id": qualification_id,
        "definition_sha256": def_sha,
        "input_sha256": input_identity["input_sha256"],
        "claim_scope": definition["qualification"].get(
            "claim_scope", "functional-security-transport-qualification-only"
        ),
        "status": "COMPLETE" if security_gate["passed"] else "FAILED",
        "network_evidence_id": network["summary"]["evidence_id"],
        "loadgen_runtime_id": loadgen["summary"]["runtime_id"],
        "scientific_corpus_id": corpus["summary"]["corpus_id"],
        "security_gate_sha256": security_gate["security_gate_sha256"],
        "profiles": [row["profile_id"] for row in materialized],
        "variants": [row["variant"] for row in variant_results],
    }
    atomic_write_json(processed_dir / "summary.json", summary)
    atomic_write_text(
        processed_dir / "SUMMARY.md",
        "# R6.5.3e HTTP/3 transport security qualification\n\n"
        f"- Status: `{summary['status']}`\n"
        f"- Network evidence: `{summary['network_evidence_id']}`\n"
        f"- Load-generator runtime: `{summary['loadgen_runtime_id']}`\n"
        f"- Scientific corpus: `{summary['scientific_corpus_id']}`\n"
        f"- Transport: `HTTP/3 only`\n"
        f"- TLS: `1.3`\n"
        f"- Cipher suite: `{transport['cipher_suite']}`\n"
        "- Peer verification: `PASS` (pinned curl + ephemeral test CA)\n"
        "- 0-RTT: `disabled`\n"
        "- stock functional smoke: `PASS`\n"
        "- ngi541-direct functional smoke: `PASS`\n"
        "- Performance claim: `none`\n",
    )
    atomic_write_text(root / "artifacts.sha256", _artifact_hashes(root))
    if summary["status"] != "COMPLETE":
        raise FrameworkError("R6.5.3e transport security qualification failed")
    return {
        "root": root,
        "summary": summary,
        "security_gate": security_gate,
        "objects": materialized,
    }
