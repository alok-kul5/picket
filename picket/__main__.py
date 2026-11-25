"""picket command line.

    python -m picket fetch      download and normalise datasets
    python -m picket lint       lint rules and docs
    python -m picket convert    pySigma conversion to SPL / Lucene / KQL
    python -m picket replay     replay datasets, assert TP and FP budgets
    python -m picket coverage   ATT&CK layer + dashboard data
    python -m picket all        everything above, in order
"""
from __future__ import annotations

import sys

from . import convert, coverage, fetch, lint, replay

STEPS = {
    "fetch": fetch.main,
    "lint": lint.main,
    "convert": convert.main,
    "replay": replay.main,
    "coverage": coverage.main,
}


def main(argv: list[str]) -> int:
    if not argv or argv[0] in {"-h", "--help"}:
        print(__doc__)
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd == "all":
        code = 0
        for name, fn in STEPS.items():
            print(f"\n== {name}")
            code |= fn(rest)
        return code
    if cmd not in STEPS:
        print(f"unknown command {cmd!r}\n{__doc__}")
        return 2
    return STEPS[cmd](rest)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
