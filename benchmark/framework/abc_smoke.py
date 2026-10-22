"""A/B/C functional protocol and payload smoke; no throughput benchmarking."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

from framework.abc_runtime import file_sha256, validate_smoke_evidence, write_evidence
from framework.io_utils import FrameworkError


def smoke_curl_command(*, arm: str, binary: Path, server_name: str, address: str,
                       port: int, ca_file: Path, object_path: str, output_path: Path,
                       cipher: str) -> list[str]:
    if arm not in ('A','B','C') or not re.fullmatch(r'[a-zA-Z0-9.-]+', server_name):
        raise FrameworkError('invalid ABC smoke arm/server_name')
    if not (1 <= port <= 65535) or not ca_file.is_file() or not binary.is_file():
        raise FrameworkError('invalid port or missing client/certificate')
    if not object_path or object_path.startswith('/') or '..' in Path(object_path).parts or '?' in object_path:
        raise FrameworkError('invalid relative object path')
    return [str(binary), '--http2' if arm=='A' else '--http3-only',
            '--tlsv1.3', '--tls-max', '1.3', '--tls13-ciphers', cipher,
            '--cacert', str(ca_file), '--resolve', f'{server_name}:{port}:{address}',
            '--silent', '--show-error', '--fail', '--verbose',
            '--connect-timeout','10', '--max-time','90',
            '--output',str(output_path), '--write-out',
            '%{http_version}\t%{response_code}\t%{ssl_verify_result}\t%{size_download}\\n',
            f'https://{server_name}:{port}/{object_path}']


def inspect_client_linkage(binary: Path) -> bool:
    """Check Linux dynamic dependencies; return True if no NGI541-linked library."""
    if sys.platform != 'linux':
        raise FrameworkError('ABC functional smoke currently requires Linux ldd')
    out = subprocess.run(['ldd', str(binary)], capture_output=True, text=True, check=False)
    if out.returncode != 0 or 'not found' in out.stdout:
        raise FrameworkError(f'cannot verify client linkage: {out.stdout} {out.stderr}')
    return 'ngi541' not in out.stdout.lower()


def parse_writeout(text: str) -> tuple[str,int,int,int]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise FrameworkError('ABC curl emitted no write-out')
    parts=lines[-1].split('\t')
    if len(parts)!=4:
        raise FrameworkError('ABC curl write-out malformed')
    try:
        proto,status,verify,size=parts[0],int(parts[1]),int(parts[2]),int(float(parts[3]))
    except ValueError as e:
        raise FrameworkError('ABC curl numeric write-out malformed') from e
    return proto,status,verify,size


def extract_cipher_evidence(stderr: str) -> dict[str,str | None]:
    # Be conservative: do not mistake client-requested ciphers for negotiated ciphers.
    lines=[x for x in stderr.splitlines() if re.search(r'SSL connection using\s+TLSv1\.3', x)]
    for line in lines:
        match=re.search(r'\bTLS_AES_(?:128_GCM_SHA256|256_GCM_SHA384)\b',line)
        if match:
            return {'state':'observed','value':match.group(0),'reason':None}
    return {'state':'unavailable','value':None,
            'reason':'curl verbose did not explicitly expose negotiated TLS 1.3 cipher; server-side proof required'}


def run_smoke(args: argparse.Namespace) -> dict:
    expected=Path(args.expected_file).resolve(strict=True)
    binary=Path(args.curl_binary).resolve(strict=True)
    ca_file=Path(args.ca_file).resolve(strict=True)
    if not inspect_client_linkage(binary):
        raise FrameworkError('ABC client links NGI541; server-only invariant violated')
    output_dir=Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True,exist_ok=True)
    content=output_dir / f'{args.arm.lower()}-received.bin'
    evidence_file=output_dir / f'{args.arm.lower()}-smoke-evidence.json'
    # Refuse to replace accepted evidence from any prior attempt.
    if content.exists() or evidence_file.exists():
        raise FrameworkError('ABC smoke artifact already exists; use a fresh output directory')
    command=smoke_curl_command(arm=args.arm,binary=binary,server_name=args.server_name,
                               address=args.address,port=args.port,ca_file=ca_file,
                               object_path=args.object_path,output_path=content,
                               cipher=args.cipher)
    proc=subprocess.run(command, capture_output=True, text=True, check=False)
    if proc.returncode:
        raise FrameworkError(f'ABC curl failed (exit={proc.returncode}): {proc.stderr[-1200:]}')
    http_version,status,verify,size=parse_writeout(proc.stdout)
    if not content.exists():
        raise FrameworkError('ABC curl did not write object')
    evidence={
      'schema_version':1, 'arm':args.arm, 'protocol_http_version':http_version,
      'response_code':status, 'ssl_verify_result':verify,
      'received_bytes':content.stat().st_size,
      'expected_sha256':file_sha256(expected),'received_sha256':file_sha256(content),
      'client_uses_ngi541':False,'client_binary_sha256':file_sha256(binary),
      'cipher_evidence':extract_cipher_evidence(proc.stderr),
    }
    if size != evidence['received_bytes'] or evidence['received_bytes'] != expected.stat().st_size:
        raise FrameworkError('ABC curl downloaded byte count mismatch')
    validate_smoke_evidence(evidence)
    write_evidence(evidence_file,evidence)
    return evidence


def main() -> int:
    p=argparse.ArgumentParser(description='ABC HTTP/2/HTTP/3 functional smoke (not benchmark)')
    p.add_argument('--arm', choices=['A','B','C'], required=True)
    p.add_argument('--curl-binary', required=True)
    p.add_argument('--server-name',default='ngi541-dut.local')
    p.add_argument('--address',required=True)
    p.add_argument('--port',type=int,required=True)
    p.add_argument('--ca-file',required=True)
    p.add_argument('--object-path',required=True)
    p.add_argument('--expected-file',required=True)
    p.add_argument('--output-dir',required=True)
    p.add_argument('--cipher',default='TLS_AES_128_GCM_SHA256')
    args=p.parse_args()
    try:
        result=run_smoke(args)
    except (FrameworkError, FileNotFoundError) as e:
        print(f'FAIL: ABC functional smoke: {e}', file=sys.stderr)
        return 2
    print('PASS: ABC functional protocol and byte-identical object delivery')
    print(json.dumps(result, indent=2,sort_keys=True))
    if result['cipher_evidence']['state']!='observed':
        print('CIPHER QUALIFICATION PENDING: capture independent server-side negotiated cipher evidence')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
