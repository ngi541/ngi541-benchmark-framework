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
BASE_RUNTIME_KIND = "curl-http3-ngtcp2"
H2LOAD_RUNTIME_KIND = "curl-h2load-http3-ngtcp2"
SUPPORTED_RUNTIME_KINDS = {BASE_RUNTIME_KIND, H2LOAD_RUNTIME_KIND}


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


def _wants_h2load(definition: dict[str, Any]) -> bool:
    return definition["runtime"].get("kind") == H2LOAD_RUNTIME_KIND


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
    if runtime.get("kind") not in SUPPORTED_RUNTIME_KINDS:
        raise FrameworkError(
            "runtime.kind must be 'curl-http3-ngtcp2' or 'curl-h2load-http3-ngtcp2'"
        )

    install_root = runtime.get("install_root")
    if not isinstance(install_root, str) or not install_root.strip() or install_root.startswith("/"):
        raise FrameworkError("runtime.install_root must be a non-empty path relative to remote HOME")

    if not isinstance(remote, dict) or remote.get("provider") != "linux-ssh":
        raise FrameworkError("remote.provider must be 'linux-ssh'")
    if not isinstance(remote.get("ssh_target"), str) or not remote["ssh_target"].strip():
        raise FrameworkError("remote.ssh_target must be a non-empty string")

    if not isinstance(sources, dict):
        raise FrameworkError("sources must be an object")

    source_names = ["openssl", "nghttp3", "ngtcp2", "curl"]
    if _wants_h2load(definition):
        source_names.append("nghttp2")

    for name in source_names:
        src = sources.get(name)
        if not isinstance(src, dict):
            raise FrameworkError(f"sources.{name} must be an object")
        for field in ("version", "url", "sha256"):
            if not isinstance(src.get(field), str) or not src[field].strip():
                raise FrameworkError(f"sources.{name}.{field} must be a non-empty string")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", src["sha256"]):
            raise FrameworkError(f"sources.{name}.sha256 must be a 64-digit SHA-256")

    jobs = int(definition.get("build", {}).get("jobs", 4))
    if jobs < 1:
        raise FrameworkError("build.jobs must be >= 1")


def _build_packages(definition: dict[str, Any]) -> list[str]:
    packages = [
        "build-essential",
        "perl",
        "pkg-config",
        "ca-certificates",
        "curl",
        "xz-utils",
    ]
    if _wants_h2load(definition):
        packages.extend(["libev-dev", "zlib1g-dev", "libc-ares-dev"])
    return packages


def _bullseye_build_deps_command(definition: dict[str, Any]) -> str:
    packages = " ".join(_build_packages(definition))
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


def _generic_build_deps_command(definition: dict[str, Any]) -> str:
    packages = " ".join(_build_packages(definition))
    return (
        "sudo apt-get update && "
        "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y " + packages
    )


def _required_tools_probe() -> str:
    return (
        "missing=''; "
        "for x in cc c++ make perl pkg-config curl tar xz sha256sum; do "
        "command -v \"$x\" >/dev/null 2>&1 || missing=\"$missing $x\"; "
        "done; printf '%s\\n' \"${missing# }\""
    )


def _required_packages_probe(definition: dict[str, Any]) -> str:
    packages = " ".join(shlex.quote(p) for p in _build_packages(definition))
    return (
        "missing=''; "
        f"for p in {packages}; do "
        "dpkg-query -W -f='${Status}' \"$p\" 2>/dev/null | "
        "grep -q 'install ok installed' || missing=\"$missing $p\"; "
        "done; printf '%s\\n' \"${missing# }\""
    )


def _cxx20_probe_script() -> str:
    return r'''set -eu
probe_src=$(mktemp /tmp/ngi541-cxx20.XXXXXX.cpp)
probe_bin=${probe_src%.cpp}
trap 'rm -f "$probe_src" "$probe_bin"' EXIT
cat > "$probe_src" <<'EOF'
#include <concepts>
#include <ranges>
#include <span>
int main() {
  int a[2] = {1, 2};
  std::span<int> s(a);
  auto r = std::views::iota(0, 2);
  return (s.size() == 2 && *r.begin() == 0) ? 0 : 1;
}
EOF
c++ -std=c++20 "$probe_src" -o "$probe_bin"
"$probe_bin"
'''


def _runtime_prefix_shell(definition: dict[str, Any]) -> str:
    root = definition["runtime"]["install_root"].strip("/")
    digest = definition_sha256(definition)[:16]
    return f"$HOME/{root}/{digest}"


def _runtime_prefix_for_home(definition: dict[str, Any], home: str) -> str:
    root = definition["runtime"]["install_root"].strip("/")
    digest = definition_sha256(definition)[:16]
    return f"{home.rstrip('/')}/{root}/{digest}"


def render_build_script(definition: dict[str, Any]) -> str:
    validate_definition(definition)
    prefix = _runtime_prefix_shell(definition)
    src = definition["sources"]
    jobs = int(definition.get("build", {}).get("jobs", 4))
    want_h2load = _wants_h2load(definition)

    def q(v: str) -> str:
        return shlex.quote(v)

    source_names = ["openssl", "nghttp3", "ngtcp2", "curl"]
    if want_h2load:
        source_names.append("nghttp2")

    entries = []
    for name in source_names:
        e = src[name]
        entries.append(f"fetch {q(name)} {q(e['url'])} {q(e['sha256'].lower())}")

    openssl_v = src["openssl"]["version"]
    nghttp3_v = src["nghttp3"]["version"]
    ngtcp2_v = src["ngtcp2"]["version"]
    curl_v = src["curl"]["version"]
    nghttp2_v = src.get("nghttp2", {}).get("version")
    digest = definition_sha256(definition)

    h2load_reuse_gate = ""
    h2load_build = ""
    if want_h2load:
        h2load_reuse_gate = r'''      H2LOAD_OK=0
      if [ -x "$PREFIX/nghttp2/bin/h2load" ] && \
         "$PREFIX/nghttp2/bin/h2load" --help 2>&1 | grep -q -- '--h3' && \
         "$PREFIX/nghttp2/bin/h2load" --help 2>&1 | grep -q -- '--output-file'; then
        H2LOAD_OK=1
      fi
'''
        h2load_build = f'''
echo "==> validate C++20 compiler for nghttp2 {nghttp2_v}"
{_cxx20_probe_script()}

echo "==> build nghttp2 {nghttp2_v} with HTTP/3 h2load"
tar -xf "$DL/nghttp2-{nghttp2_v}.tar.xz" -C "$SRC"
(
  cd "$SRC/nghttp2-{nghttp2_v}"
  export PKG_CONFIG_PATH="$PREFIX/openssl/lib/pkgconfig:$PREFIX/nghttp3/lib/pkgconfig:$PREFIX/ngtcp2/lib/pkgconfig"
  export CPPFLAGS="-I$PREFIX/openssl/include -I$PREFIX/nghttp3/include -I$PREFIX/ngtcp2/include"
  # nghttp2 1.69.0 requires C++20 for its applications.  Its bundled
  # Autoconf C++ standard probe can leave CXX1XCXXFLAGS empty on older
  # compilers even when the compiler accepts -std=c++20.  The explicit
  # flag keeps the actual h2load build in the same language mode that
  # passed the capability probe above.
  export CXXFLAGS="-std=c++20"
  export LDFLAGS="-Wl,-rpath,$PREFIX/openssl/lib -Wl,-rpath,$PREFIX/nghttp3/lib -Wl,-rpath,$PREFIX/ngtcp2/lib -Wl,-rpath,$PREFIX/nghttp2/lib"
  echo "NGI541 nghttp2 CXXFLAGS: $CXXFLAGS"
  ./configure --prefix="$PREFIX/nghttp2" --enable-app --enable-http3 --disable-examples

  # R6.5.3b.2 deliberately builds only the h2load application and its
  # required libraries.  A full nghttp2 application build also compiles
  # nghttpx; nghttpx 1.69.0 uses std::source_location, which is absent in
  # the Bullseye libstdc++ on this Raspberry Pi.  h2load does not depend
  # on the nghttpx/shrpx sources, so building nghttpx would add an
  # irrelevant toolchain requirement to the load-generator runtime.
  make -j{jobs} -C lib
  make -j{jobs} -C third-party
  make -j{jobs} -C src h2load

  # Install libnghttp2 first, then use libtool's install mode to relink
  # just h2load against the installed prefix.  Do not invoke the src
  # install target because it depends on all enabled applications.
  make -C lib install
  mkdir -p "$PREFIX/nghttp2/bin"
  ./libtool --mode=install /usr/bin/install -c src/h2load "$PREFIX/nghttp2/bin/h2load"
) >>"$LOG" 2>&1

if ! "$PREFIX/nghttp2/bin/h2load" --help 2>&1 | grep -q -- '--h3'; then
  echo "built h2load does not advertise --h3" >&2
  exit 22
fi
if ! "$PREFIX/nghttp2/bin/h2load" --help 2>&1 | grep -q -- '--output-file'; then
  echo "built h2load does not advertise --output-file" >&2
  exit 23
fi
if ! "$PREFIX/nghttp2/bin/h2load" --help 2>&1 | grep -q -- '--timing-script-file'; then
  echo "built h2load does not advertise --timing-script-file" >&2
  exit 24
fi
if ! "$PREFIX/nghttp2/bin/h2load" --help 2>&1 | grep -q -- '--rps'; then
  echo "built h2load does not advertise --rps" >&2
  exit 25
fi
'''

    if want_h2load:
        reuse_body = f'''  if "$PREFIX/curl/bin/curl" --version | grep -q 'HTTP3'; then
    H2LOAD_OK=0
{h2load_reuse_gate}    if [ "$H2LOAD_OK" -eq 1 ]; then
      echo "runtime-reuse: $PREFIX"
      exit 0
    fi
  fi'''
    else:
        reuse_body = '''  if "$PREFIX/curl/bin/curl" --version | grep -q 'HTTP3'; then
    echo "runtime-reuse: $PREFIX"
    exit 0
  fi'''

    script = f'''set -euo pipefail
PREFIX={prefix}
DEF_SHA={q(digest)}
WORK="$PREFIX/work"
SRC="$WORK/src"
DL="$WORK/downloads"
LOG="$PREFIX/build.log"
mkdir -p "$SRC" "$DL" "$PREFIX"

if [ -x "$PREFIX/curl/bin/curl" ] && [ -f "$PREFIX/definition.sha256" ] && [ "$(cat "$PREFIX/definition.sha256")" = "$DEF_SHA" ]; then
{reuse_body}
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

{h2load_build}
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
    runtime_id = (
        f"{_slug(definition['runtime']['name'])}-{_utc_timestamp()}-"
        f"{definition_sha256(definition)[:6]}"
    )
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

        tool_probe = ssh.run(["bash", "-lc", _required_tools_probe()], check=True)
        atomic_write_json(raw / "tool-probe.json", tool_probe.as_dict())
        missing_tools = tool_probe.stdout.strip().split()

        package_probe = ssh.run(
            ["bash", "-lc", _required_packages_probe(definition)], check=True
        )
        atomic_write_json(raw / "package-probe.json", package_probe.as_dict())
        missing_packages = package_probe.stdout.strip().split()

        if missing_tools or missing_packages:
            if not bootstrap:
                missing = missing_tools + missing_packages
                raise FrameworkError(
                    "remote build dependencies are missing: "
                    + ", ".join(missing)
                    + "; rerun with --bootstrap"
                )

            print("remote-bootstrap: installing build dependencies", flush=True)
            if (
                os_release.get("VERSION_CODENAME", "").lower() == "bullseye"
                or os_release.get("VERSION_ID") == "11"
            ):
                rc = ssh.run_interactive(_bullseye_build_deps_command(definition))
            else:
                rc = ssh.run_interactive(_generic_build_deps_command(definition))
            if rc != 0:
                raise FrameworkError("remote package manager failed to install build dependencies")

            tool_probe = ssh.run(["bash", "-lc", _required_tools_probe()], check=True)
            missing_tools = tool_probe.stdout.strip().split()
            package_probe = ssh.run(
                ["bash", "-lc", _required_packages_probe(definition)], check=True
            )
            missing_packages = package_probe.stdout.strip().split()
            if missing_tools or missing_packages:
                missing = missing_tools + missing_packages
                raise FrameworkError(
                    "remote build dependencies still missing: " + ", ".join(missing)
                )

        script = render_build_script(definition)
        atomic_write_text(raw / "build-script.sh", script + "\n")
        if _wants_h2load(definition):
            print(
                "loadgen-runtime: building pinned HTTP/3 curl + h2load stack on remote host",
                flush=True,
            )
        else:
            print(
                "loadgen-runtime: building pinned HTTP/3 client stack on remote host",
                flush=True,
            )

        rc = ssh.run_interactive("bash -lc " + shlex.quote(script))
        if rc != 0:
            home_result = ssh.run(["bash", "-lc", "printf '%s\n' \"$HOME\""], check=True)
            prefix = _runtime_prefix_for_home(definition, home_result.stdout.strip())
            tail = ssh.run(
                [
                    "bash",
                    "-lc",
                    f"tail -n 160 {shlex.quote(prefix + '/build.log')} 2>/dev/null || true",
                ],
                check=False,
            )
            atomic_write_text(raw / "build-log-tail.txt", tail.stdout + tail.stderr)
            raise FrameworkError(
                "remote HTTP/3 runtime build failed; see raw/build-log-tail.txt"
            )

        home_result = ssh.run(["bash", "-lc", "printf '%s\n' \"$HOME\""], check=True)
        prefix = _runtime_prefix_for_home(definition, home_result.stdout.strip())
        curl_bin = prefix + "/curl/bin/curl"
        h2load_bin = prefix + "/nghttp2/bin/h2load" if _wants_h2load(definition) else None

        records: dict[str, dict[str, Any]] = {
            "uname": _record_remote(ssh, ["uname", "-a"]),
            "arch": _record_remote(ssh, ["uname", "-m"]),
            "cc": _record_remote(ssh, ["cc", "--version"]),
            "cxx": _record_remote(ssh, ["c++", "--version"]),
            "curl_version": _record_remote(
                ssh, ["bash", "-lc", f"{shlex.quote(curl_bin)} --version"]
            ),
            "curl_sha256": _record_remote(
                ssh, ["bash", "-lc", f"sha256sum {shlex.quote(curl_bin)}"]
            ),
            "curl_ldd": _record_remote(
                ssh, ["bash", "-lc", f"ldd {shlex.quote(curl_bin)} || true"]
            ),
        }

        if h2load_bin:
            records.update(
                {
                    "h2load_version": _record_remote(
                        ssh, ["bash", "-lc", f"{shlex.quote(h2load_bin)} --version"]
                    ),
                    "h2load_help": _record_remote(
                        ssh, ["bash", "-lc", f"{shlex.quote(h2load_bin)} --help"]
                    ),
                    "h2load_sha256": _record_remote(
                        ssh, ["bash", "-lc", f"sha256sum {shlex.quote(h2load_bin)}"]
                    ),
                    "h2load_ldd": _record_remote(
                        ssh, ["bash", "-lc", f"ldd {shlex.quote(h2load_bin)} || true"]
                    ),
                }
            )

        for name, record in records.items():
            atomic_write_json(raw / f"{name}.json", record)

        version_text = records["curl_version"]["stdout"]
        if "HTTP3" not in version_text:
            raise FrameworkError("remote curl runtime does not advertise HTTP3")
        curl_sha = records["curl_sha256"]["stdout"].strip().split()[0]

        h2load_summary: dict[str, Any] | None = None
        if h2load_bin:
            help_text = records["h2load_help"]["stdout"] + records["h2load_help"]["stderr"]
            required_flags = ["--h3", "--output-file", "--timing-script-file", "--rps"]
            missing_flags = [flag for flag in required_flags if flag not in help_text]
            if missing_flags:
                raise FrameworkError(
                    "remote h2load runtime is missing required capabilities: "
                    + ", ".join(missing_flags)
                )
            h2load_sha = records["h2load_sha256"]["stdout"].strip().split()[0]
            h2load_summary = {
                "binary": h2load_bin,
                "sha256": h2load_sha,
                "http3_capable": True,
                "json_output_capable": True,
                "timing_script_capable": True,
                "rps_capable": True,
                "connections_streams_capable": True,
                "version_output": records["h2load_version"]["stdout"].strip(),
            }

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
                "h2load": h2load_summary,
            },
            "sources": definition["sources"],
            "status": "COMPLETE",
        }
        atomic_write_json(processed / "summary.json", summary)

        h2load_lines = ""
        if h2load_summary:
            h2load_lines = (
                f"- h2load SHA-256: `{h2load_summary['sha256']}`\n"
                "- h2load HTTP/3 capability: `PASS`\n"
                "- h2load JSON output capability: `PASS`\n"
            )

        atomic_write_text(
            processed / "SUMMARY.md",
            "# HTTP/3 load-generator runtime\n\n"
            f"- Runtime: `{runtime_id}`\n"
            f"- Remote: `{remote['ssh_target']}`\n"
            f"- Architecture: `{summary['remote']['architecture']}`\n"
            f"- curl SHA-256: `{curl_sha}`\n"
            "- curl HTTP/3: `PASS`\n"
            + h2load_lines,
        )
        return {"root": root, "summary": summary}
