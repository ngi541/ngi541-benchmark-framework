#!/usr/bin/env python3
"""Deterministic, role-agnostic CloudLab bootstrap archive packaging (B1)."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def valid_name(s):
    p = PurePosixPath(s)
    return bool(s) and not p.is_absolute() and '..' not in p.parts and str(p) == s and not s.startswith('./')


def package(plan_path, dest):
    plan_path = Path(plan_path).resolve()
    root = plan_path.parent
    plan = json.loads(plan_path.read_text())
    if plan.get('schema_version') != 1 or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', plan.get('revision', '')):
        raise ValueError('invalid schema_version or revision')
    nodes = plan.get('nodes')
    if not isinstance(nodes, list) or not nodes:
        raise ValueError('nodes must be a nonempty array')
    out = Path(dest).resolve()
    out.mkdir(parents=True, exist_ok=True)
    index = {'schema_version': 1, 'revision': plan['revision'], 'nodes': []}
    seen = set()
    for node in nodes:
        nid = node['node_id']
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', nid) or nid in seen:
            raise ValueError('invalid or duplicate node_id')
        seen.add(nid)
        role, profile = node['communication_role'], node['stack_profile']
        if not all(isinstance(x, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', x) for x in (role, profile)):
            raise ValueError('invalid communication role or stack profile')
        files = node['files']
        if not isinstance(files, dict) or not files:
            raise ValueError('files must be a nonempty map')
        if 'bootstrap.sh' not in files or 'build.lock.json' not in files:
            raise ValueError('bootstrap.sh and build.lock.json required')
        payload = {}
        for dest_path, src in files.items():
            if not valid_name(dest_path) or dest_path in ('bundle.manifest.json',):
                raise ValueError('unsafe archive destination')
            raw_local = root / src
            local = raw_local.resolve()
            if not local.is_relative_to(root) or not local.is_file() or raw_local.is_symlink():
                raise ValueError(f'unsafe or missing source: {src}')
            payload[dest_path] = local.read_bytes()
        lock = json.loads(payload['build.lock.json'])
        if lock.get('schema_version') != 1 or lock.get('stack_profile') != profile:
            raise ValueError('build lock schema/profile mismatch')
        file_hashes = {name: digest(content) for name, content in sorted(payload.items())}
        manifest = {'schema_version': 1, 'revision': plan['revision'],
                    'node_id': nid, 'communication_role': role, 'stack_profile': profile,
                    'files_sha256': file_hashes}
        payload['bundle.manifest.json'] = canonical(manifest)
        archive_name = f"ngi541-cloudlab-{role}-bootstrap-{plan['revision']}.tar.gz"
        if any(entry['archive'] == archive_name for entry in index['nodes']):
            raise ValueError('duplicate role: filenames would collide')
        archive = out / archive_name
        if archive.exists():
            raise FileExistsError(f'bootstrap archive already exists: {archive}')
        with archive.open('wb') as fp:
            with gzip.GzipFile(fileobj=fp, mode='wb', filename='', mtime=0, compresslevel=9) as gz:
                with tarfile.open(fileobj=gz, mode='w', format=tarfile.USTAR_FORMAT) as tar:
                    for name, content in sorted(payload.items()):
                        ti = tarfile.TarInfo(name)
                        ti.size = len(content)
                        ti.uid = ti.gid = 0
                        ti.uname = ti.gname = ''
                        ti.mtime = 0
                        ti.mode = 0o755 if name == 'bootstrap.sh' else 0o644
                        tar.addfile(ti, io.BytesIO(content))
        index['nodes'].append({'node_id': nid, 'communication_role': role,
                               'stack_profile': profile, 'archive': archive_name,
                               'sha256': digest(archive.read_bytes()),
                               'bundle_manifest_sha256': digest(payload['bundle.manifest.json'])})
    index_path = out / 'bootstrap-index.json'
    if index_path.exists():
        raise FileExistsError(f'bootstrap index already exists: {index_path}')
    index_path.write_bytes(canonical(index))
    return index


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--plan', required=True)
    ap.add_argument('--output', required=True)
    args = ap.parse_args(argv)
    result = package(args.plan, args.output)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
