"""B2 CloudLab deterministic standalone source-build bootstrap profiles.

This module has no SSH or DUT side effects. It packages native pinned recipes
and explicitly records all inputs. The framework is never shipped to a DUT.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from framework import cloudlab_artifacts, loadgen_runtime

REPO = Path(__file__).resolve().parents[2]
DEFAULT_NODES = 'benchmark/configs/abc-cloudlab-bootstrap-nodes.json'
CLIENT_DEFINITION = 'benchmark/configs/r6.5.4.2-pi-http3-loadgen.json'
VERIFY_SCRIPT = 'integration/bootstraps/verify_bundle.py'
GENERATORS = (
    'benchmark/framework/cloudlab_bootstrap_b2.py',
    'benchmark/framework/cloudlab_artifacts.py',
    'benchmark/framework/loadgen_runtime.py',
)


def _sha(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical(value):
    return cloudlab_artifacts.canonical(value)


def _hash(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _versions(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        if not re.fullmatch(r'[A-Z0-9_]+=[0-9A-Za-z:/.+_-]+', line):
            raise ValueError('invalid versions.env entry')
        k, v = line.split('=', 1)
        if k in values:
            raise ValueError('duplicate versions.env entry')
        values[k] = v
    for key in ('NGI541_COMMIT', 'NGINX_VERSION', 'NGINX_SHA256', 'OPENSSL_VERSION', 'OPENSSL_SHA256'):
        if key not in values:
            raise ValueError('missing versions.env pin: ' + key)
    if not re.fullmatch(r'[0-9a-f]{40}', values['NGI541_COMMIT']):
        raise ValueError('NGI541_COMMIT must be exact 40-digit hash')
    return values


def _server_bootstrap():
    return r'''#!/usr/bin/env bash
set -euo pipefail
BUNDLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$BUNDLE_DIR/verify-bundle.py" "$BUNDLE_DIR"
RUN_ROOT="${NGI541_RUN_ROOT:?NGI541_RUN_ROOT must be set by launcher}"
mkdir -p "$RUN_ROOT" "$RUN_ROOT/source"
exec > >(tee -a "$RUN_ROOT/server-build.log") 2>&1
for tool in git cmake make curl patch sha256sum nproc python3 cc perl; do
  command -v "$tool" >/dev/null || { echo "missing build dependency: $tool" >&2; exit 30; }
done
source "$BUNDLE_DIR/integration/versions/versions.env"
AVAILABLE_CPUS=$(nproc)
AVAILABLE_MEM_KIB=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)
MEM_JOBS=$((AVAILABLE_MEM_KIB / 1572864))
(( MEM_JOBS >= 1 )) || MEM_JOBS=1
BUILD_JOBS="${ABC_BUILD_JOBS:-$AVAILABLE_CPUS}"
[[ "$BUILD_JOBS" =~ ^[1-9][0-9]*$ ]] || exit 31
(( BUILD_JOBS <= AVAILABLE_CPUS )) || BUILD_JOBS=$AVAILABLE_CPUS
(( BUILD_JOBS <= MEM_JOBS )) || BUILD_JOBS=$MEM_JOBS
(( BUILD_JOBS <= 16 )) || BUILD_JOBS=16
echo "CloudLab server build parallel jobs: $BUILD_JOBS"
git clone -q "$NGI541_GIT_URL" "$RUN_ROOT/source/ngi541"
git -C "$RUN_ROOT/source/ngi541" checkout -q --detach "$NGI541_COMMIT"
test "$(git -C "$RUN_ROOT/source/ngi541" rev-parse HEAD)" = "$NGI541_COMMIT"
cmake -S "$RUN_ROOT/source/ngi541" -B "$RUN_ROOT/ngi541-build" \
  -DCMAKE_BUILD_TYPE=Release -DNGI541_BUILD_ENGINE=ON -DBUILD_SHARED_LIBS=ON \
  -DCMAKE_INSTALL_PREFIX="$RUN_ROOT/ngi541-install"
cmake --build "$RUN_ROOT/ngi541-build" --parallel "$BUILD_JOBS"
cmake --install "$RUN_ROOT/ngi541-build"
export NGI541_PREFIX="$RUN_ROOT/ngi541-install"
(cd "$BUNDLE_DIR" && ABC_BUILD_JOBS="$BUILD_JOBS" bash scripts/abc-linux-build.sh --build)
mkdir -p "$RUN_ROOT/bin" "$RUN_ROOT/lib"
ln -s "$BUNDLE_DIR/build/abc-linux/stock/sbin/nginx" "$RUN_ROOT/bin/stock-nginx"
ln -s "$BUNDLE_DIR/build/abc-linux/ngi541-direct/sbin/nginx" "$RUN_ROOT/bin/candidate-nginx"
ln -s "$NGI541_PREFIX/lib/libngi541_engine.so" "$RUN_ROOT/lib/libngi541_engine.so.0.1"
ldd "$RUN_ROOT/bin/stock-nginx" > "$RUN_ROOT/stock-ldd.txt"
ldd "$RUN_ROOT/bin/candidate-nginx" > "$RUN_ROOT/candidate-ldd.txt"
! grep -q 'not found' "$RUN_ROOT/stock-ldd.txt"
! grep -q 'not found' "$RUN_ROOT/candidate-ldd.txt"
! grep -q 'libngi541_engine.so' "$RUN_ROOT/stock-ldd.txt"
grep -q 'libngi541_engine.so' "$RUN_ROOT/candidate-ldd.txt"
sha256sum "$RUN_ROOT/bin/stock-nginx" "$RUN_ROOT/bin/candidate-nginx" "$RUN_ROOT/lib/libngi541_engine.so.0.1" | tee "$RUN_ROOT/server-binaries.sha256"
echo SOURCE_BUILD_SERVER_PASS
'''


def _client_bootstrap():
    return r'''#!/usr/bin/env bash
set -euo pipefail
BUNDLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$BUNDLE_DIR/verify-bundle.py" "$BUNDLE_DIR"
RUN_ROOT="${NGI541_RUN_ROOT:?NGI541_RUN_ROOT must be set by launcher}"
mkdir -p "$RUN_ROOT"
exec > >(tee -a "$RUN_ROOT/client-build.log") 2>&1
bash "$BUNDLE_DIR/client-build.sh"
RUNTIME_ID=$(python3 - "$BUNDLE_DIR/build.lock.json" <<'PYCODE'
import json, sys
print(json.load(open(sys.argv[1]))['recipe_identity'])
PYCODE
)
PREFIX="$HOME/.local/ngi541/cloudlab/loadgen/$RUNTIME_ID"
mkdir -p "$RUN_ROOT/client"
for comp in curl openssl ngtcp2 nghttp3 nghttp2; do
  test -d "$PREFIX/$comp"
  ln -s "$PREFIX/$comp" "$RUN_ROOT/client/$comp"
done
"$RUN_ROOT/client/curl/bin/curl" --version | grep -qw 'HTTP2'
"$RUN_ROOT/client/curl/bin/curl" --version | grep -qw 'HTTP3'
ldd "$RUN_ROOT/client/curl/lib/libcurl.so.4" | grep -q 'libnghttp2.so'
sha256sum "$RUN_ROOT/client/curl/bin/curl" "$RUN_ROOT/client/nghttp2/bin/h2load" | tee "$RUN_ROOT/client-binaries.sha256"
echo SOURCE_BUILD_CLIENT_PASS
'''


def _copy(root: Path, dst: Path, rel: str):
    if not cloudlab_artifacts.valid_name(rel):
        raise ValueError('unsafe input path: ' + rel)
    source = (root / rel).resolve()
    if not source.is_relative_to(root) or not source.is_file():
        raise ValueError('missing/unsafe build source: ' + rel)
    target = dst / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)


def _git_info(repo: Path, inputs: list[str]):
    def call(*args):
        return subprocess.run(['git', *args], cwd=repo, capture_output=True, text=True, check=True).stdout.strip()
    try:
        commit = call('rev-parse', 'HEAD')
        if not re.fullmatch(r'[0-9a-f]{40}', commit):
            raise ValueError('unexpected Git commit format')
        clean_tracked = {}
        for rel in sorted(set(inputs)):
            tracked = subprocess.run(['git','ls-files','--error-unmatch',rel],cwd=repo,capture_output=True).returncode == 0
            unchanged = subprocess.run(['git','diff','--quiet','HEAD','--',rel],cwd=repo,capture_output=True).returncode == 0
            clean_tracked[rel] = bool(tracked and unchanged)
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise ValueError('B2 must be generated from a Git checkout') from exc
    return commit, clean_tracked


def _load_nodes(path):
    doc = json.loads(Path(path).read_text())
    nodes = doc.get('nodes')
    if doc.get('schema_version') != 1 or not isinstance(nodes, list) or not nodes:
        raise ValueError('node config requires schema_version=1 and nodes[]')
    seen = set()
    for item in nodes:
        if not isinstance(item, dict) or set(item) != {'node_id', 'communication_role', 'stack_profile'}:
            raise ValueError('node descriptor must contain exactly node_id/communication_role/stack_profile')
        if not all(isinstance(item[f], str) and cloudlab_artifacts.SLUG_RE.fullmatch(item[f]) for f in item):
            raise ValueError('invalid node descriptor identifiers')
        if item['node_id'] in seen:
            raise ValueError('duplicate node_id')
        seen.add(item['node_id'])
        if item['stack_profile'] == 'nginx-ngi541' and item['communication_role'] != 'server':
            raise ValueError('nginx-ngi541 profile currently requires a server communication role')
        if item['stack_profile'] == 'http-loadgen' and item['communication_role'] != 'client':
            raise ValueError('http-loadgen profile currently requires a client communication role')
        if item['stack_profile'] not in ('nginx-ngi541', 'http-loadgen'):
            raise ValueError('unsupported current stack profile: ' + item['stack_profile'])
    return nodes


def _write(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data)


def _lock(repo: Path, node: dict, payload_dir: Path, identity: str,
          git_commit: str, tracked: dict, generator_hashes: dict):
    hashes = {
        str(p.relative_to(payload_dir)): _sha(p)
        for p in sorted(payload_dir.rglob('*')) if p.is_file()
    }
    lock = {
        'schema_version': 1,
        'contract': 'cloudlab-bootstrap-b2',
        'node_id': node['node_id'],
        'communication_role': node['communication_role'],
        'stack_profile': node['stack_profile'],
        'recipe_identity': identity,
        'framework_commit': git_commit,
        'generator_sources_sha256': generator_hashes,
        'generator_sources_tracked': tracked,
        'publication_eligible': all(tracked.values()),
        'inputs_sha256': hashes,
    }
    _write(payload_dir / 'build.lock.json', _canonical(lock).decode())


def prepare(repo: Path, output: Path, revision: str, nodes_config: Path | None = None):
    repo = Path(repo).resolve()
    output = Path(output).resolve()
    if not cloudlab_artifacts.SLUG_RE.fullmatch(revision):
        raise ValueError('invalid revision')
    if output.exists():
        raise FileExistsError(f'output exists: {output}')
    nodes_config = Path(nodes_config) if nodes_config is not None else repo / DEFAULT_NODES
    nodes = _load_nodes(nodes_config)
    generator_hashes = {rel: _sha(repo / rel) for rel in GENERATORS}
    pins_rel = 'integration/versions/versions.env'
    pins = _versions(repo / pins_rel)
    nginx_patch = f'integration/patches/nginx-{pins["NGINX_VERSION"]}/0001-ngi541-quic-crypto.patch'
    server_files = ('scripts/abc-linux-build.sh', pins_rel, nginx_patch)
    client_files = (CLIENT_DEFINITION,)
    definition = loadgen_runtime.load_definition(repo / CLIENT_DEFINITION)
    if not loadgen_runtime._wants_h2load(definition):
        raise ValueError('CloudLab requires pinned h2load')
    patch_spec = loadgen_runtime._resolve_nghttp2_patch(definition)
    if not patch_spec:
        raise ValueError('pinned nghttp2 patch is required')
    patch_source = repo / patch_spec['path']
    input_paths = [*GENERATORS, *server_files, *client_files, patch_spec['path']]
    if nodes_config.is_relative_to(repo):
        input_paths.append(str(nodes_config.relative_to(repo)))
    git_commit, tracked = _git_info(repo, input_paths)
    if _sha(patch_source) != patch_spec['sha256']:
        raise ValueError('nghttp2 patch hash mismatch')
    with tempfile.TemporaryDirectory(prefix='ngi541-cloudlab-b2-inputs-') as temp:
        root = Path(temp)
        plan_nodes = []
        for item in nodes:
            nid, profile = item['node_id'], item['stack_profile']
            dst = root / nid
            dst.mkdir()
            shutil.copyfile(repo / VERIFY_SCRIPT, dst / 'verify-bundle.py')
            if profile == 'nginx-ngi541':
                for rel in server_files:
                    _copy(repo, dst, rel)
                _write(dst / 'bootstrap.sh', _server_bootstrap())
                input_hashes = {str(p.relative_to(dst)): _sha(p) for p in dst.rglob('*') if p.is_file()}
                identity = _hash({'contract': 2, 'profile': profile, 'files_sha256': input_hashes,
                                  'generator_sha256': generator_hashes})
            elif profile == 'http-loadgen':
                for rel in client_files:
                    _copy(repo, dst, rel)
                shutil.copyfile(patch_source, dst / 'nghttp2-h2load.patch')
                _write(dst / 'bootstrap.sh', _client_bootstrap())
                input_hashes = {str(p.relative_to(dst)): _sha(p) for p in dst.rglob('*') if p.is_file()}
                identity = _hash({'contract': 2, 'profile': profile, 'files_sha256': input_hashes,
                                  'generator_sha256': generator_hashes})
                script = loadgen_runtime.render_build_script(
                    definition, profile='cloudlab-http2-http3', runtime_identity=identity)
                _write(dst / 'client-build.sh', '#!/usr/bin/env bash\n' + script)
            else:
                raise ValueError('unsupported build profile')
            _lock(repo, item, dst, identity, git_commit, tracked, generator_hashes)
            payload_files = {
                str(p.relative_to(dst)): str(p.relative_to(root))
                for p in sorted(dst.rglob('*')) if p.is_file()
            }
            plan_nodes.append({**item, 'files': payload_files})
        _write(root / 'plan.json', _canonical({'schema_version': 1, 'revision': revision, 'nodes': plan_nodes}).decode())
        return cloudlab_artifacts.package(root / 'plan.json', output)


def main(argv=None):
    ap = argparse.ArgumentParser(description='Create B2 node-specific standalone CloudLab bootstrap archives')
    ap.add_argument('--repo', type=Path, default=REPO)
    ap.add_argument('--revision', required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--nodes-config', type=Path, default=None)
    args = ap.parse_args(argv)
    print(json.dumps(prepare(args.repo, args.output, args.revision, args.nodes_config), indent=2))


if __name__ == '__main__':
    main()
