from __future__ import annotations

import hashlib
import json
import re
import shlex
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from framework.io_utils import FrameworkError, atomic_write_json, atomic_write_text
from framework.network_qualification import SSHSession, parse_os_release


RUNTIME_SCHEMA_VERSION = 1


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def definition_sha256(definition: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(definition)).hexdigest()


def _slug(text: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    if not value:
        raise FrameworkError("runtime.name must contain an alphanumeric character")
    return value


def load_definition(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FrameworkError(f"load-generator runtime config not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise FrameworkError(
            f"invalid load-generator runtime JSON: line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    validate_definition(value)
    return value


def validate_definition(definition: dict[str, Any]) -> None:
    if definition.get("schema_version") != RUNTIME_SCHEMA_VERSION:
        raise FrameworkError("load-generator runtime schema_version must be 1")
    runtime = definition.get("runtime")
    remote = definition.get("remote")
    sources = definition.get("sources")
    if not isinstance(runtime, dict) or not runtime.get("name"):
        raise FrameworkError("runtime.name must be a non-empty string")
    if runtime.get("kind") != "curl-http3-ngtcp2":
        raise FrameworkError("runtime.kind must be 'curl-http3-ngtcp2'")
    install_root = runtime.get("install_root")
    if not isinstance(install_root, str) or not install_root.strip() or install_root.startswith("/"):
        raise FrameworkError("runtime.install_root must be a non-empty path relative to remote HOME")
    if not isinstance(remote, dict) or remote.get("provider") != "linux-ssh":
        raise FrameworkError("remote.provider must be 'linux-ssh'")
    if not isinstance(remote.get("ssh_target"), str) or not remote["ssh_target"].strip():
        raise FrameworkError("remote.ssh_target must be a non-empty string")
    if not isinstance(sources, dict):
        raise FrameworkError("sources must be an object")
    for name in ("openssl", "nghttp3", "ngtcp2", "curl"):
        src = sources.get(name)
        if not isinstance(src, dict):
            raise FrameworkError(f"sources.{name} must be an object")
        for field in ("version", "url", "sha256"):
            if not isinstance(src.get(field), str) or not src[field].strip():
                raise FrameworkError(f"sources.{name}.{field} must be a non-empty string")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", src["sha256"]):
            raise FrameworkError(f"sources.{name}.sha256 must be a 64-digit SHA-256")


def _bullseye_build_deps_command() -> str:
    packages = "build-essential perl pkg-config ca-certificates curl xz-utils"
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
        "-o Acquire::Check-Valid-Until=false install -y " + packages
    )


def _generic_build_deps_command() -> str:
    return (
        "sudo apt-get update && "
        "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y "
        "build-essential perl pkg-config ca-certificates curl xz-utils"
    )


def _required_tools_probe() -> str:
    return (
        "missing=''; "
        "for x in cc c++ make perl pkg-config curl tar xz sha256sum; do "
        "command -v \"$x\" >/dev/null 2>&1 || missing=\"$missing $x\"; "
        "done; printf '%s\\n' \"${missing# }\""
    )


def _runtime_prefix_shell(definition: dict[str, Any]) -> str:
    root = definition["runtime"]["install_root"].strip("/")
    digest = definition_sha256(definition)[:16]
    return f"$HOME/{root}/{digest}"


def _runtime_prefix_for_home(definition: dict[str, Any], home: str) -> str:
    root = definition["runtime"]["install_root"].strip("/")
    digest = definition_sha256(definition)[:16]
    return f"{home.rstrip('/')}/{root}/{digest}"


def render_build_script(definition: dict[str, Any]) -> str:
    prefix = _runtime_prefix_shell(definition)
    src = definition["sources"]
    jobs = int(definition.get("build", {}).get("jobs", 4))
    if jobs < 1:
        raise FrameworkError("build.jobs must be >= 1")

    def q(v: str) -> str:
        return shlex.quote(v)

    entries = []
    for name in ("openssl", "nghttp3", "ngtcp2", "curl"):
        e = src[name]
        entries.append(
            f"fetch {q(name)} {q(e['url'])} {q(e['sha256'].lower())}"
        )

    openssl_v = src["openssl"]["version"]
    nghttp3_v = src["nghttp3"]["version"]
    ngtcp2_v = src["ngtcp2"]["version"]
    curl_v = src["curl"]["version"]
    digest = definition_sha256(definition)

    script = f'''set -euo pipefail
PREFIX={prefix}
DEF_SHA={q(digest)}
WORK="$PREFIX/work"
SRC="$WORK/src"
DL="$WORK/downloads"
LOG="$PREFIX/build.log"
mkdir -p "$SRC" "$DL" "$PREFIX"

if [ -x "$PREFIX/curl/bin/curl" ] && [ -f "$PREFIX/definition.sha256" ] && [ "$(cat "$PREFIX/definition.sha256")" = "$DEF_SHA" ]; then
  if "$PREFIX/curl/bin/curl" --version | grep -q 'HTTP3'; then
    echo "runtime-reuse: $PREFIX"
    exit 0
  fi
fi

: > "$LOG"
fetch() {{
  name="$1"; url="$2"; expected="$3"
  file="$DL/${{url##*/}}"
  echo "==> fetch $name"
  if [ ! -f "$file" ]; then
    curl -fL --retry 3 --retry-delay 2 -o "$file" "$url" >>"$LOG" 2>&1
  fi
  actual=$(sha256sum "$file" | awk '{{print $1}}')
  if [ "$actual" != "$expected" ]; then
    echo "SHA-256 mismatch for $name: expected=$expected actual=$actual" >&2
    exit 20
  fi
}}

{chr(10).join(entries)}

rm -rf "$SRC"/*

echo "==> build OpenSSL {openssl_v}"
tar -xf "$DL/${{OPENSSL_ARCHIVE:-openssl-{openssl_v}.tar.gz}}" -C "$SRC"
(
  cd "$SRC/openssl-{openssl_v}"
  ./config --prefix="$PREFIX/openssl" --libdir=lib
  make -j{jobs}
  make install_sw
) >>"$LOG" 2>&1

echo "==> build nghttp3 {nghttp3_v}"
tar -xf "$DL/nghttp3-{nghttp3_v}.tar.gz" -C "$SRC"
(
  cd "$SRC/nghttp3-{nghttp3_v}"
  ./configure --prefix="$PREFIX/nghttp3" --enable-lib-only
  make -j{jobs}
  make install
) >>"$LOG" 2>&1

echo "==> build ngtcp2 {ngtcp2_v}"
tar -xf "$DL/ngtcp2-{ngtcp2_v}.tar.gz" -C "$SRC"
(
  cd "$SRC/ngtcp2-{ngtcp2_v}"
  export PKG_CONFIG_PATH="$PREFIX/openssl/lib/pkgconfig:$PREFIX/nghttp3/lib/pkgconfig"
  export LDFLAGS="-Wl,-rpath,$PREFIX/openssl/lib"
  ./configure --prefix="$PREFIX/ngtcp2" --enable-lib-only --with-openssl
  make -j{jobs}
  make install
) >>"$LOG" 2>&1

echo "==> build curl {curl_v}"
tar -xf "$DL/curl-{curl_v}.tar.xz" -C "$SRC"
(
  cd "$SRC/curl-{curl_v}"
  export PKG_CONFIG_PATH="$PREFIX/openssl/lib/pkgconfig:$PREFIX/nghttp3/lib/pkgconfig:$PREFIX/ngtcp2/lib/pkgconfig"
  export LDFLAGS="-Wl,-rpath,$PREFIX/openssl/lib -Wl,-rpath,$PREFIX/nghttp3/lib -Wl,-rpath,$PREFIX/ngtcp2/lib"
  ./configure \
    --prefix="$PREFIX/curl" \
    --with-openssl="$PREFIX/openssl" \
    --with-nghttp3="$PREFIX/nghttp3" \
    --with-ngtcp2="$PREFIX/ngtcp2" \
    --without-libpsl \
    --without-brotli \
    --without-zstd
  make -j{jobs}
  make install
) >>"$LOG" 2>&1

if ! "$PREFIX/curl/bin/curl" --version | grep -q 'HTTP3'; then
  echo "built curl does not advertise HTTP3" >&2
  "$PREFIX/curl/bin/curl" --version >&2 || true
  exit 21
fi
printf '%s\\n' "$DEF_SHA" > "$PREFIX/definition.sha256"
echo "runtime-ready: $PREFIX"
'''
    return script


def _record_remote(ssh: SSHSession, argv: list[str]) -> dict[str, Any]:
    result = ssh.run(argv, check=False, timeout=120)
    return result.as_dict()


def run_loadgen_runtime(
    definition: dict[str, Any],
    *,
    config_path: Path,
    output_root: Path,
    bootstrap: bool,
) -> dict[str, Any]:
    validate_definition(definition)
    runtime_id = f"{_slug(definition['runtime']['name'])}-{_utc_timestamp()}-{definition_sha256(definition)[:6]}"
    root = output_root / runtime_id
    raw = root / "raw"
    processed = root / "processed"
    raw.mkdir(parents=True, exist_ok=False)
    processed.mkdir(parents=True)
    atomic_write_json(root / "config.json", definition)

    remote = definition["remote"]
    timeout = int(remote.get("connect_timeout_seconds", 10))
    with SSHSession(remote["ssh_target"], timeout) as ssh:
        os_rel = ssh.run(["cat", "/etc/os-release"], check=True)
        atomic_write_json(raw / "os-release.json", os_rel.as_dict())
        os_release = parse_os_release(os_rel.stdout)

        probe = ssh.run(["bash", "-lc", _required_tools_probe()], check=True)
        atomic_write_json(raw / "tool-probe.json", probe.as_dict())
        missing = probe.stdout.strip().split()
        if missing:
            if not bootstrap:
                raise FrameworkError(
                    "remote build tools are missing: " + ", ".join(missing) + "; rerun with --bootstrap"
                )
            print("remote-bootstrap: installing build dependencies", flush=True)
            if os_release.get("VERSION_CODENAME", "").lower() == "bullseye" or os_release.get("VERSION_ID") == "11":
                rc = ssh.run_interactive(_bullseye_build_deps_command())
            else:
                rc = ssh.run_interactive(_generic_build_deps_command())
            if rc != 0:
                raise FrameworkError("remote package manager failed to install build dependencies")
            probe = ssh.run(["bash", "-lc", _required_tools_probe()], check=True)
            missing = probe.stdout.strip().split()
            if missing:
                raise FrameworkError("remote build tools still missing: " + ", ".join(missing))

        script = render_build_script(definition)
        atomic_write_text(raw / "build-script.sh", script + "\n")
        print("loadgen-runtime: building pinned HTTP/3 client stack on remote host", flush=True)
        rc = ssh.run_interactive("bash -lc " + shlex.quote(script))
        if rc != 0:
            home_result = ssh.run(["bash", "-lc", "printf '%s\n' \"$HOME\""], check=True)
            prefix = _runtime_prefix_for_home(definition, home_result.stdout.strip())
            tail = ssh.run(["bash", "-lc", f"tail -n 120 {shlex.quote(prefix + '/build.log')} 2>/dev/null || true"], check=False)
            atomic_write_text(raw / "build-log-tail.txt", tail.stdout + tail.stderr)
            raise FrameworkError(
                "remote HTTP/3 runtime build failed; see raw/build-log-tail.txt"
            )

        home_result = ssh.run(["bash", "-lc", "printf '%s\n' \"$HOME\""], check=True)
        prefix = _runtime_prefix_for_home(definition, home_result.stdout.strip())
        curl_bin = prefix + "/curl/bin/curl"
        records = {
            "uname": _record_remote(ssh, ["uname", "-a"]),
            "arch": _record_remote(ssh, ["uname", "-m"]),
            "cc": _record_remote(ssh, ["cc", "--version"]),
            "curl_version": _record_remote(ssh, ["bash", "-lc", f"{shlex.quote(curl_bin)} --version"]),
            "curl_sha256": _record_remote(ssh, ["bash", "-lc", f"sha256sum {shlex.quote(curl_bin)}"]),
            "ldd": _record_remote(ssh, ["bash", "-lc", f"ldd {shlex.quote(curl_bin)} || true"]),
        }
        for name, record in records.items():
            atomic_write_json(raw / f"{name}.json", record)

        version_text = records["curl_version"]["stdout"]
        if "HTTP3" not in version_text:
            raise FrameworkError("remote curl runtime does not advertise HTTP3")
        curl_sha = records["curl_sha256"]["stdout"].strip().split()[0]
        summary = {
            "schema_version": 1,
            "runtime_id": runtime_id,
            "definition_sha256": definition_sha256(definition),
            "remote": {
                "ssh_target": remote["ssh_target"],
                "architecture": records["arch"]["stdout"].strip(),
                "os_release": os_release,
            },
            "runtime": {
                "kind": definition["runtime"]["kind"],
                "remote_prefix": prefix,
                "curl_binary": curl_bin,
                "curl_sha256": curl_sha,
                "http3_capable": True,
                "curl_version_output": version_text.strip(),
            },
            "sources": definition["sources"],
            "status": "COMPLETE",
        }
        atomic_write_json(processed / "summary.json", summary)
        atomic_write_text(
            processed / "SUMMARY.md",
            "# R6.5.2 HTTP/3 load-generator runtime\n\n"
            f"- Runtime: `{runtime_id}`\n"
            f"- Remote: `{remote['ssh_target']}`\n"
            f"- Architecture: `{summary['remote']['architecture']}`\n"
            f"- curl SHA-256: `{curl_sha}`\n"
            f"- HTTP/3: `PASS`\n",
        )
        return {"root": root, "summary": summary}
