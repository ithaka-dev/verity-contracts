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
    forge coverage --report summary --no-match-coverage '(script|test)' \
        --no-match-test invariant | script/check-coverage.py

`--no-match-test invariant` is for speed — ~33 minutes against seconds, for a number that does not
change, since coverage is 100% without the invariant suite. It runs in full in CI's `check` job.
"""

from __future__ import annotations

import re
import sys

# lines, statements, branches, functions
#
# **100, deliberately, and only for this repo.** Elsewhere a 100% floor turns coverage into a target
# and invites tests written to touch lines rather than to check them. Contracts are the exception:
# they are immutable once deployed, so an unexercised line is not "not covered yet", it is a line
# that will ship in that state forever and cannot be patched afterwards. There is also nowhere for
# genuinely dead code to hide here — 175 lines, all of them reachable, as T-08 established by
# reaching the last nine.
#
# What this floor does *not* claim is that the tests are good. Coverage counts execution; the suite
# here once scored 2/12 against `script/mutate.sh` while looking healthy. **That** is the gate on
# quality. This one only stops a line from going dark.
#
# If a change genuinely cannot reach a branch — a defensive guard against a compiler-impossible
# state, say — the answer is to justify it in the commit message and lower the floor there, in view
# of a reviewer. Not to quietly delete the branch, and not to write a test that executes it without
# asserting anything.
FLOORS = {"lines": 100.0, "statements": 100.0, "branches": 100.0, "functions": 100.0}
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
