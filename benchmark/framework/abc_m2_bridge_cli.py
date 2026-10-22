"""M2.1.1 read-only window/byte evidence CLI; no research claim promotion."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from framework.abc_m2_cli import save_new
from framework.abc_m2_coordination import (marker, local_receipt, ssh_receipt, assess,
    assess_snapshot_enclosure)
from framework.abc_m2_payload import extract_h2load_evidence
from framework.io_utils import FrameworkError


def load(path: Path):
    return json.loads(path.read_text(encoding='utf-8'))


def main() -> int:
    p=argparse.ArgumentParser(description='NGI541 M2.1.1 evidence-only coordination & payload')
    sub=p.add_subparsers(dest='cmd',required=True)
    def ids(cmd):
        for name in ('run-id','attempt-id','window-id'):
            cmd.add_argument('--'+name,required=True)
    def identity(args):
        return dict(run_id=args.run_id,attempt_id=args.attempt_id,window_id=args.window_id)
    m=sub.add_parser('marker',help='host-local Linux monotonic marker JSON on stdout')
    ids(m)
    m.add_argument('--host-role',choices=['dut','client'],required=True)
    m.add_argument('--edge',choices=['start','end'],required=True)
    l=sub.add_parser('local-probe',help='same-host smoke only; NOT CloudLab clock qualification')
    ids(l)
    l.add_argument('--host-role',choices=['dut','client'],required=True)
    l.add_argument('--edge',choices=['start','end'],required=True)
    l.add_argument('--out',type=Path,required=True)
    r=sub.add_parser('remote-probe',help='one SSH controller bracket; no retries')
    ids(r)
    r.add_argument('--host-role',choices=['dut','client'],required=True)
    r.add_argument('--edge',choices=['start','end'],required=True)
    r.add_argument('--ssh-target',required=True)
    r.add_argument('--remote-repo',required=True)
    r.add_argument('--out',type=Path,required=True)
    a=sub.add_parser('assess',help='evaluate controller-boundary uncertainty')
    a.add_argument('--start-dut',type=Path,required=True)
    a.add_argument('--start-client',type=Path,required=True)
    a.add_argument('--end-dut',type=Path,required=True)
    a.add_argument('--end-client',type=Path,required=True)
    a.add_argument('--max-boundary-ms',type=float,required=True,
                   help='pilot threshold, explicitly NOT protocol frozen')
    a.add_argument('--out',type=Path,required=True)
    e=sub.add_parser('enclosure',help='host-local snapshot/marker inclusion check')
    for k in ('start-snapshot','end-snapshot','start-marker','end-marker'):
        e.add_argument('--'+k,type=Path,required=True)
    e.add_argument('--out',type=Path,required=True)
    b=sub.add_parser('h2load',help='adapt patched h2load MAIN DATA bytes, not validated bytes')
    ids(b)
    b.add_argument('--arm',choices=['A','B','C'],required=True)
    b.add_argument('--raw-json',type=Path,required=True)
    b.add_argument('--client-executable',type=Path)
    b.add_argument('--expected-client-sha256')
    b.add_argument('--declared-main-seconds',type=float)
    b.add_argument('--out',type=Path,required=True)
    args=p.parse_args()
    try:
        if args.cmd=='marker':
            print(json.dumps(marker(**identity(args),host_role=args.host_role,
                                    edge=args.edge),sort_keys=True))
        elif args.cmd=='local-probe':
            save_new(args.out,local_receipt(**identity(args),role=args.host_role,edge=args.edge))
        elif args.cmd=='remote-probe':
            save_new(args.out,ssh_receipt(**identity(args),role=args.host_role,
                      edge=args.edge,ssh_target=args.ssh_target,remote_repo=args.remote_repo))
        elif args.cmd=='assess':
            save_new(args.out,assess(start_receipts={'dut':load(args.start_dut),
                  'client':load(args.start_client)},
                  end_receipts={'dut':load(args.end_dut),'client':load(args.end_client)},
                  max_boundary_uncertainty_ms=args.max_boundary_ms))
        elif args.cmd=='enclosure':
            save_new(args.out,assess_snapshot_enclosure(
                start=load(args.start_snapshot),end=load(args.end_snapshot),
                start_marker=load(args.start_marker),end_marker=load(args.end_marker)))
        elif args.cmd=='h2load':
            fail_actual=(hashlib.sha256(args.client_executable.read_bytes()).hexdigest()
                         if args.client_executable else None)
            save_new(args.out,extract_h2load_evidence(source=args.raw_json.read_bytes(),
                 **identity(args),arm=args.arm,
                 expected_client_sha256=args.expected_client_sha256,
                 actual_client_sha256=fail_actual,
                 declared_main_seconds=args.declared_main_seconds))
    except (FrameworkError,OSError,ValueError,KeyError,TypeError,TimeoutError) as exc:
        print(f'FAIL: {exc}',file=sys.stderr)
        return 2
    print('PASS: M2.1.1 evidence generated; NOT performance-qualified',file=sys.stderr)
    return 0

if __name__=='__main__':
    raise SystemExit(main())
