#!/usr/bin/env python
"""pegrex -- unified CLI (legacy entry; delegates to pegrex.cli).
     ~$ python -m pegrex.cli --help
     ~$ python pegrex.py --help
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from pegrex.cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
