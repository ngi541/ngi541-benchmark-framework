"""M2.0+M2.1 evidence CLI: capture / derive / validate / registry.

Execution: cd benchmark && python3 -m framework.abc_m2_cli ...
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from framework.abc_m2_contract import load_registry, validate_observation_v2
from framework.abc_m2_linux import capture, derive, parse_cpu_set
from framework.io_utils import FrameworkError


def save_new(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open('x', encoding='utf-8') as f:
            json.dump(obj, f, sort_keys=True, indent=2)
            f.write('\n')
    except FileExistsError:
        raise FrameworkError(f'append-only evidence policy: file already exists: {path}')
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    print(f'SHA256 {digest} {path}')


def main() -> int:
    p = argparse.ArgumentParser(description='NGI541 additive M2 telemetry; NOT a performance qualification')
    sub = p.add_subparsers(dest='command', required=True)
    c = sub.add_parser('capture', help='Linux primary start/end snapshot, no mutation')
    for arg in ('run-id', 'attempt-id', 'window-id'):
        c.add_argument('--'+arg, required=True)
    c.add_argument('--host-role', choices=['dut', 'client'], required=True)
    c.add_argument('--phase', choices=['start', 'end'], required=True)
    c.add_argument('--cpus', required=True, help='explicit CPU set, e.g. 4-7,16-19')
    c.add_argument('--iface', required=True, help='dedicated experiment interface; lo only for functional test')
    c.add_argument('--cgroup', type=Path, help='dedicated v2 cgroup directory; no auto-inference')
    c.add_argument('--out', type=Path, required=True)
    d = sub.add_parser('derive', help='calculate same-host deltas, explicitly not a qualified result')
    d.add_argument('--start', type=Path, required=True)
    d.add_argument('--end', type=Path, required=True)
    d.add_argument('--arm', choices=['A', 'B', 'C'], required=True)
    d.add_argument('--out', type=Path, required=True)
    v = sub.add_parser('validate', help='strictly validate M2 v2 observation')
    v.add_argument('--observation', type=Path, required=True)
    sub.add_parser('registry', help='verify metric registry v0.2; print metric counts')
    args = p.parse_args()
    try:
        if args.command == 'registry':
            r = load_registry()
            print(f'PASS: {r["registry_version"]} metrics={len(r["metrics"])} states={len(r["states"])}')
        elif args.command == 'capture':
            record = capture(run_id=args.run_id, attempt_id=args.attempt_id,
                             window_id=args.window_id, phase=args.phase, host_role=args.host_role,
                             cpus=parse_cpu_set(args.cpus), iface=args.iface, cgroup_path=args.cgroup)
            save_new(args.out, record)
            print(f'PASS: phase={args.phase} role={args.host_role} (evidence only)')
        elif args.command == 'derive':
            start = json.loads(args.start.read_text(encoding='utf-8'))
            end = json.loads(args.end.read_text(encoding='utf-8'))
            obs = derive(start, end, arm=args.arm)
            obs['input_sha256'] = {
                'start': hashlib.sha256(args.start.read_bytes()).hexdigest(),
                'end': hashlib.sha256(args.end.read_bytes()).hexdigest()}
            save_new(args.out, obs)
            print('PASS: M2 evidence-only deltas (NOT primary performance qualification)')
        elif args.command == 'validate':
            validate_observation_v2(json.loads(args.observation.read_text(encoding='utf-8')))
            print('PASS: M2 evidence contract valid; qualification NOT implied')
    except (FrameworkError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
