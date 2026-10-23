#!/usr/bin/env python3
"""CloudLab single-command SSH/pinned source build/ABC functional qualification."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'benchmark'/'framework'))
from abc_cloudlab_source_v3 import main
if __name__=='__main__':raise SystemExit(main())
