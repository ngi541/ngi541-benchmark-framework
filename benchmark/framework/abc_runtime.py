"""Additive CloudLab A/B/C runtime qualification helpers (not R6 execution)."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from framework.io_utils import FrameworkError

PINNED_CIPHER = "TLS_AES_128_GCM_SHA256"
EXPECTED_PROTOCOL = {"A": "2", "B": "3", "C": "3"}
EXPECTED_SERVER = {"A": "stock", "B": "stock", "C": "ngi541-direct"}


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def validate_build_receipt(receipt: dict[str, Any], *, arm: str) -> None:
    """Check semantic build identity; a receipt is not proof of runtime ALPN."""
    if arm not in EXPECTED_SERVER:
        raise FrameworkError(f"unexpected ABC arm: {arm}")
    if not isinstance(receipt, dict) or receipt.get('schema_version') != 1:
        raise FrameworkError('ABC Linux build receipt schema_version must be 1')
    if receipt.get('os') != 'linux' or receipt.get('arch') not in ('x86_64', 'aarch64'):
        raise FrameworkError('ABC build requires qualified Linux architecture')
    if receipt.get('variant') != EXPECTED_SERVER[arm]:
        raise FrameworkError(f'ABC {arm} server build variant mismatch')
    if receipt.get('nginx_version') != '1.31.6' or receipt.get('openssl_version') != '3.5.9':
        raise FrameworkError('ABC server version mismatch')
    sha = receipt.get('binary_sha256')
    if not isinstance(sha, str) or not re.fullmatch(r'[0-9a-f]{64}', sha):
        raise FrameworkError('ABC build receipt lacks binary hash')
    args = receipt.get('configure_arguments')
    if not isinstance(args, str) or not all(flag in args for flag in
       ('--with-http_v2_module', '--with-http_v3_module', '--with-http_ssl_module')):
        raise FrameworkError('ABC build missing required HTTP2/HTTP3/TLS modules')
    enabled = receipt.get('ngi541_enabled')
    if enabled is not (arm == 'C'):
        raise FrameworkError('ABC server NGI541 state mismatch')
    has_macro = '-DNGX_QUIC_NGI541=1' in args
    if has_macro != (arm == 'C'):
        raise FrameworkError('ABC build macro does not match server arm')
    if arm == 'C' and not re.fullmatch(r'[0-9a-f]{64}', str(receipt.get('ngi541_library_sha256', ''))):
        raise FrameworkError('ABC C lacks valid NGI541 library hash')
    if arm != 'C' and receipt.get('ngi541_library_sha256') is not None:
        raise FrameworkError('ABC reference/baseline cannot depend on NGI541 library')


def validate_smoke_evidence(value: dict[str, Any]) -> None:
    """Require successful HTTP and payload proof, without inventing TLS cipher evidence."""
    if not isinstance(value, dict) or value.get('schema_version') != 1:
        raise FrameworkError('ABC smoke evidence schema mismatch')
    arm = value.get('arm')
    if arm not in EXPECTED_PROTOCOL:
        raise FrameworkError('ABC smoke evidence invalid arm')
    if value.get('protocol_http_version') != EXPECTED_PROTOCOL[arm]:
        raise FrameworkError('ABC smoke negotiated incorrect HTTP version')
    if value.get('response_code') != 200 or value.get('ssl_verify_result') != 0:
        raise FrameworkError('ABC smoke HTTP/TLS verification failed')
    if value.get('expected_sha256') != value.get('received_sha256') or not re.fullmatch(
        r'[0-9a-f]{64}', str(value.get('expected_sha256', ''))):
        raise FrameworkError('ABC smoke payload SHA mismatch')
    if type(value.get('received_bytes')) is not int or value['received_bytes'] <= 0:
        raise FrameworkError('ABC smoke response invalid')
    if value.get('client_uses_ngi541') is not False:
        raise FrameworkError('ABC client crypto is not independent')
    if not re.fullmatch(r'[0-9a-f]{64}', str(value.get('client_binary_sha256', ''))):
        raise FrameworkError('ABC smoke client identity missing')
    # TLS 1.3 & cipher are separately qualified; never infer them from request options.
    cipher_evidence = value.get('cipher_evidence')
    if not isinstance(cipher_evidence, dict) or cipher_evidence.get('state') not in (
        'observed', 'unavailable'):
        raise FrameworkError('ABC smoke cipher evidence needs explicit state')
    if cipher_evidence['state'] == 'observed':
        if cipher_evidence.get('value') != PINNED_CIPHER:
            raise FrameworkError('ABC smoke observed incorrect TLS cipher')
    else:
        if not isinstance(cipher_evidence.get('reason'), str) or not cipher_evidence['reason']:
            raise FrameworkError('ABC smoke absent cipher reason')


def write_evidence(path: Path, obj: dict[str, Any]) -> None:
    validate_smoke_evidence(obj)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FrameworkError(f'ABC smoke evidence already exists: {path}')
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + '\n', encoding='utf-8')
