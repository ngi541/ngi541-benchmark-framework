"""M2.1.2b offline reconciliation CLI; always evidence-only."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from framework.abc_m2_cli import save_new
from framework.abc_m2_main_validity import evaluate
from framework.io_utils import FrameworkError


def main() -> int:
    parser=argparse.ArgumentParser(description='NGI541 M2.1.2b offline MAIN and payload reconciliation')
    parser.add_argument('--corpus-manifest',type=Path,required=True)
    parser.add_argument('--expected-corpus-sha256',required=True)
    parser.add_argument('--phase',type=Path,required=True)
    parser.add_argument('--completion-ledger',type=Path,required=True)
    parser.add_argument('--h2load-evidence',type=Path,required=True)
    parser.add_argument('--response-dir',type=Path,required=True)
    parser.add_argument('--client-start',type=Path)
    parser.add_argument('--client-end',type=Path)
    parser.add_argument('--coordination',type=Path)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    def read(path):return json.loads(path.read_text(encoding='utf-8'))
    try:
        result=evaluate(corpus_source=args.corpus_manifest.read_bytes(),
            expected_corpus_sha256=args.expected_corpus_sha256,
            ledger=read(args.completion_ledger),phase=read(args.phase),
            h2load=read(args.h2load_evidence),response_dir=args.response_dir,
            client_start_snapshot=read(args.client_start) if args.client_start else None,
            client_end_snapshot=read(args.client_end) if args.client_end else None,
            controller_coordination=read(args.coordination) if args.coordination else None)
        save_new(args.out,result)
    except (FrameworkError, OSError, ValueError, TypeError, KeyError) as exc:
        print(f'FAIL: {exc}',file=sys.stderr);return 2
    print('PASS: M2.1.2b offline payload reconciliation (UNATTESTED / NOT SCIENTIFICALLY QUALIFIED)')
    return 0

if __name__=='__main__':raise SystemExit(main())
