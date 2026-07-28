#!/usr/bin/env python3
"""Fail the build when coverage drops below the recorded floors.

A job that only prints a number cannot fail, and a gate that cannot fail is a report. This reads
`forge coverage --report summary` from stdin or a file and exits non-zero when any total falls below
its floor.

Floors are set just below current so a regression trips them, rather than so high that the next
honest commit has to argue with the gate. **Raise them as coverage improves; never lower one to make
a build pass** — if a change genuinely justifies a lower floor, that belongs in the commit message
where a reviewer sees it.

Usage:
    forge coverage --report summary --no-match-coverage '(script|test)' | script/check-coverage.py
"""

from __future__ import annotations

import re
import sys

# lines, statements, branches, functions
FLOORS = {"lines": 95.0, "statements": 93.0, "branches": 78.0, "functions": 95.0}
ORDER = ["lines", "statements", "branches", "functions"]


def main() -> int:
    text = sys.stdin.read() if len(sys.argv) < 2 else open(sys.argv[1], encoding="utf-8").read()

    total = next((line for line in text.splitlines() if line.startswith("| Total")), None)
    if total is None:
        print("::error::could not find the Total row in the coverage summary", file=sys.stderr)
        print(text, file=sys.stderr)
        return 1

    percentages = [float(value) for value in re.findall(r"(\d+\.\d+)%", total)]
    if len(percentages) < len(ORDER):
        print(f"::error::expected {len(ORDER)} percentages, parsed {percentages}", file=sys.stderr)
        return 1

    failures = [
        f"{name} {value:.2f}% < {FLOORS[name]:.2f}%"
        for name, value in zip(ORDER, percentages)
        if value < FLOORS[name]
    ]
    if failures:
        print("::error::coverage below threshold — " + "; ".join(failures))
        return 1

    print("ok: " + ", ".join(f"{n} {v:.2f}%" for n, v in zip(ORDER, percentages)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
