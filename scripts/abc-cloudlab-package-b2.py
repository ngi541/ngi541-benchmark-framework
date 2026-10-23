#!/usr/bin/env python3
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'benchmark'))
from framework.cloudlab_bootstrap_b2 import main
if __name__ == '__main__':
    main()
