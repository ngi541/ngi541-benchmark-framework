#!/usr/bin/env python3
"""DUT-local structural and SHA-256 validation after archive verification.

B3 must authenticate the whole archive using the orchestrator's expected digest
BEFORE extraction. This tool provides additional internal payload validation.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys


def sha(data):
    return hashlib.sha256(data).hexdigest()


def safe(name):
    if not isinstance(name, str) or not name or '\\' in name:
        return False
    p = PurePosixPath(name)
    return not p.is_absolute() and '..' not in p.parts and str(p) == name and not name.startswith('./')


def verify(root):
    root = Path(root).resolve()
    manifest = json.loads((root / 'bundle.manifest.json').read_text())
    lock = json.loads((root / 'build.lock.json').read_text())
    files = manifest['files_sha256']
    if manifest['schema_version'] != 1 or lock['contract'] != 'cloudlab-bootstrap-b2':
        raise ValueError('unexpected bundle schema/contract')
    if manifest['node_id'] != lock['node_id'] or manifest['stack_profile'] != lock['stack_profile']:
        raise ValueError('bundle/lock identity mismatch')
    if set(lock['inputs_sha256']) != set(files) - {'build.lock.json'}:
        raise ValueError('lock does not cover all inputs')
    for name, expected in files.items():
        if not safe(name):
            raise ValueError('unsafe file path in manifest')
        file = root / name
        if file.is_symlink() or not file.is_file() or not file.resolve().is_relative_to(root):
            raise ValueError(f'missing or unsafe file: {name}')
        actual = sha(file.read_bytes())
        if actual != expected:
            raise ValueError(f'bundle payload checksum mismatch: {name}')
        if name in lock['inputs_sha256'] and actual != lock['inputs_sha256'][name]:
            raise ValueError(f'lock checksum mismatch: {name}')
    present = {str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()}
    if present != set(files) | {'bundle.manifest.json'}:
        raise ValueError('unmanifested or missing payload file')
    return {'node_id': manifest['node_id'], 'recipe_identity': lock['recipe_identity']}


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: verify_bundle.py EXTRACTED_BUNDLE_DIRECTORY')
    try:
        print('PASS: DUT-local bundle identity: ' + json.dumps(verify(sys.argv[1]), sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SystemExit('FAIL: ' + str(exc))
