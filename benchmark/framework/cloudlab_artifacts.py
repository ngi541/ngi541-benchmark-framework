#!/usr/bin/env python3
"""B2 deterministic node-specific CloudLab bootstrap archives.

The packaging step is offline, makes no network requests and never writes to a
published output until all member archives/locks have been built and checked.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import tempfile

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
SLUG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def valid_name(s):
    if not isinstance(s, str) or not s or '\\' in s:
        return False
    p = PurePosixPath(s)
    return not p.is_absolute() and '..' not in p.parts and str(p) == s and not s.startswith('./')


def _slug(value):
    return isinstance(value, str) and SLUG_RE.fullmatch(value) is not None


def _load_payload(plan_root: Path, files: dict) -> dict[str, bytes]:
    if not isinstance(files, dict) or not files:
        raise ValueError('files must be a nonempty map')
    if not {'bootstrap.sh', 'build.lock.json'}.issubset(files):
        raise ValueError('bootstrap.sh and build.lock.json required')
    payload = {}
    for name, src in files.items():
        if not valid_name(name) or name == 'bundle.manifest.json' or not valid_name(src):
            raise ValueError('unsafe destination or source path')
        source = plan_root / src
        # Reject symlinks in every path component, not only on the leaf.
        probe = source
        while probe != plan_root:
            if probe.is_symlink():
                raise ValueError(f'unsafe symlink in input path: {src}')
            probe = probe.parent
        resolved = source.resolve()
        if not resolved.is_relative_to(plan_root) or not resolved.is_file():
            raise ValueError(f'unsafe or missing source: {src}')
        payload[name] = resolved.read_bytes()
    return payload


def _validate_lock(payload: dict[str, bytes], profile: str):
    lock = json.loads(payload['build.lock.json'])
    if lock.get('schema_version') != 1 or lock.get('stack_profile') != profile:
        raise ValueError('build lock schema/profile mismatch')
    inputs = lock.get('inputs_sha256', {})
    if not isinstance(inputs, dict):
        raise ValueError('lock inputs_sha256 must be an object')
    for name, expected in inputs.items():
        if not valid_name(name) or name not in payload or not isinstance(expected, str) or not SHA256_RE.fullmatch(expected):
            raise ValueError(f'build lock references missing/invalid payload: {name}')
        if digest(payload[name]) != expected:
            raise ValueError(f'build lock digest mismatch: {name}')
    # Strict B2 lock: all shipped inputs except the lock itself are authenticated.
    if lock.get('contract') == 'cloudlab-bootstrap-b2':
        if set(inputs) != set(payload) - {'build.lock.json'}:
            raise ValueError('B2 build lock does not cover the entire payload')
        if not _slug(lock.get('node_id')) or lock.get('recipe_identity') is None:
            raise ValueError('B2 build lock missing node/recipe identity')
    return lock


def verify_archive(path, expected_sha256=None):
    """Verify the actual archive and its own manifest/lock, not only staging data."""
    archive = Path(path)
    if expected_sha256 is not None and digest(archive.read_bytes()) != expected_sha256:
        raise ValueError('archive SHA-256 mismatch')
    with tarfile.open(archive, 'r:gz') as tf:
        members = tf.getmembers()
        names = [m.name for m in members]
        if len(names) != len(set(names)):
            raise ValueError('duplicate archive entries')
        if any(not valid_name(m.name) or not m.isfile() for m in members):
            raise ValueError('archive contains unsafe/non-file entry')
        payload = {m.name: tf.extractfile(m).read() for m in members}
    raw_manifest = payload.pop('bundle.manifest.json', None)
    if raw_manifest is None:
        raise ValueError('bundle manifest missing')
    manifest = json.loads(raw_manifest)
    if manifest.get('schema_version') != 1:
        raise ValueError('bundle manifest schema mismatch')
    if manifest.get('files_sha256') != {k: digest(v) for k, v in sorted(payload.items())}:
        raise ValueError('bundle manifest file hash mismatch')
    _validate_lock(payload, manifest['stack_profile'])
    return manifest


def _pack_one(output: Path, name: str, payload: dict[str, bytes], manifest: dict):
    all_payload = dict(payload)
    all_payload['bundle.manifest.json'] = canonical(manifest)
    with output.open('wb') as fp:
        with gzip.GzipFile(fileobj=fp, mode='wb', filename='', mtime=0, compresslevel=9) as gz:
            with tarfile.open(fileobj=gz, mode='w', format=tarfile.USTAR_FORMAT) as tf:
                for entry, content in sorted(all_payload.items()):
                    item = tarfile.TarInfo(entry)
                    item.size = len(content)
                    item.uid = item.gid = 0
                    item.uname = item.gname = ''
                    item.mtime = 0
                    item.mode = 0o755 if entry == 'bootstrap.sh' else 0o644
                    tf.addfile(item, io.BytesIO(content))
    actual = verify_archive(output)
    if actual != manifest:
        raise ValueError(f'archive verification failed: {name}')


def package(plan_path, dest):
    plan_path = Path(plan_path).resolve()
    root = plan_path.parent
    plan = json.loads(plan_path.read_text())
    if plan.get('schema_version') != 1 or not _slug(plan.get('revision')):
        raise ValueError('invalid schema_version or revision')
    nodes = plan.get('nodes')
    if not isinstance(nodes, list) or not nodes:
        raise ValueError('nodes must be a nonempty array')
    output = Path(dest).resolve()
    if output.exists():
        raise FileExistsError(f'output exists: {output}')
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.ngi541-bootstrap-stage-', dir=output.parent))
    index = {'schema_version': 1, 'revision': plan['revision'], 'nodes': []}
    try:
        seen = set()
        for node in nodes:
            nid, role, profile = node['node_id'], node['communication_role'], node['stack_profile']
            if not all(_slug(x) for x in (nid, role, profile)) or nid in seen:
                raise ValueError('invalid or duplicate node_id/role/profile')
            seen.add(nid)
            payload = _load_payload(root, node['files'])
            lock = _validate_lock(payload, profile)
            if lock.get('contract') == 'cloudlab-bootstrap-b2' and lock['node_id'] != nid:
                raise ValueError('node_id does not match build lock')
            hashes = {name: digest(blob) for name, blob in sorted(payload.items())}
            manifest = {'schema_version': 1, 'revision': plan['revision'],
                        'node_id': nid, 'communication_role': role,
                        'stack_profile': profile, 'files_sha256': hashes}
            name = f'ngi541-cloudlab-{nid}-bootstrap-{plan["revision"]}.tar.gz'
            archive = staging / name
            _pack_one(archive, name, payload, manifest)
            index['nodes'].append({'node_id': nid, 'communication_role': role,
                                   'stack_profile': profile, 'archive': name,
                                   'sha256': digest(archive.read_bytes()),
                                   'bundle_manifest_sha256': digest(canonical(manifest)),
                                   'recipe_identity': lock.get('recipe_identity')})
        (staging / 'bootstrap-index.json').write_bytes(canonical(index))
        # Stage is private and complete. Never overwrite an existing publication.
        if output.exists():
            raise FileExistsError(f'output exists: {output}')
        os.rename(staging, output)
        return index
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--plan', required=True)
    ap.add_argument('--output', required=True)
    args = ap.parse_args(argv)
    print(json.dumps(package(args.plan, args.output), indent=2))


if __name__ == '__main__':
    main()
