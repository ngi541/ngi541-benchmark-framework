"""M2.1.2a read-only environment inventory + deterministic drift CLI."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from framework.abc_m2_environment import canonical, collect, compare, completeness, digest, validate


def read(path:Path)->dict:
    data=json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data,dict): raise ValueError('JSON document must be object')
    return data


def save_new(path:Path,obj:dict)->str:
    payload=canonical(obj)+b'\n'
    path.parent.mkdir(parents=True,exist_ok=True)
    # Fail closed: never silently overwrite scientific evidence.
    with path.open('xb') as f:f.write(payload)
    return digest(payload)


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description='M2.1.2a identity/drift evidence (never scientific qualification)')
    sub=p.add_subparsers(dest='command',required=True)
    c=sub.add_parser('capture')
    c.add_argument('--role',choices=['dut','client'],required=True)
    c.add_argument('--arm',choices=['A','B','C'],required=True)
    c.add_argument('--interface',required=True)
    c.add_argument('--run-id',required=True)
    c.add_argument('--attempt-id',required=True)
    c.add_argument('--assets',required=True,type=Path,
                   help='JSON map of operator-declared asset file paths and controls')
    c.add_argument('--out',required=True,type=Path)
    a=sub.add_parser('assess')
    a.add_argument('--evidence',type=Path,required=True)
    a.add_argument('--out',type=Path,required=True)
    d=sub.add_parser('compare')
    d.add_argument('--before',type=Path,required=True)
    d.add_argument('--after',type=Path,required=True)
    d.add_argument('--mode',choices=['same-role','bc-pair'],default='same-role')
    d.add_argument('--out',type=Path,required=True)
    d.add_argument('--approved-differences',type=Path,help='B/C only: JSON exact before/after exception approvals')
    ns=p.parse_args(argv)
    try:
        if ns.command=='capture':
            obj=collect(host_role=ns.role,arm=ns.arm,interface=ns.interface,
                        run_id=ns.run_id,attempt_id=ns.attempt_id,assets=read(ns.assets))
        elif ns.command=='assess':
            obj=completeness(read(ns.evidence))
        else:obj=compare(read(ns.before),read(ns.after),mode=ns.mode,
                         approved_differences=read(ns.approved_differences) if ns.approved_differences else None)
        result=save_new(ns.out,obj)
        print(f'SHA256 {result} {ns.out}')
        print(f'PASS: M2.1.2a {ns.command} evidence written (NOT scientific qualification)')
        return 0
    except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as exc:
        print(f'FAIL: {type(exc).__name__}: {exc}',file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
