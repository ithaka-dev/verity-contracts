#!/usr/bin/env python3
"""Assert `ecrecover` is called only from `SignatureChecker`.

ADR 0005 rule 1: every signature check routes through one place, so the smart-account branch cannot
be bypassed. Deployed contracts are effectively immutable, so a contract that calls `ecrecover`
directly works perfectly until a holder's account is an ERC-4337 wallet, and then it cannot be
fixed. This is the rule most likely to erode quietly — one hurried commit reads as harmless.

## Why this is not a grep

The previous version was `grep -rn ecrecover src/ | grep -v SignatureChecker.sol`, and it failed
the build on a **comment** that used the word while explaining why a check exists. That is worse
than it sounds. A gate that fires on prose gets weakened by whoever is unblocking the build, and
weakening it is precisely how the real check gets lost — the rule survives right up until someone
needs to ship.

So this strips comments and string literals first, and looks for an actual call. It can then be
strict about calls without being wrong about mentions, which is what lets it stay strict.

Usage:
    python3 script/check-no-raw-ecrecover.py [src-dir]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

#: The one file permitted to call it.
ALLOWED = "SignatureChecker.sol"

#: A call, not a mention: the identifier followed by an opening parenthesis.
CALL = re.compile(r"\becrecover\s*\(")

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_LINE_COMMENT = re.compile(r"//[^\n]*")
_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')


def strip_noncode(source: str) -> str:
    """Remove block comments, line comments and string literals.

    Order matters: block comments first, since a `//` inside one is not a line comment. Newlines are
    preserved so reported line numbers stay true.
    """
    def blank(match: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    source = _BLOCK_COMMENT.sub(blank, source)
    source = _LINE_COMMENT.sub(blank, source)
    return _STRING.sub(blank, source)


def offenders(src_dir: Path) -> list[tuple[Path, int, str]]:
    found: list[tuple[Path, int, str]] = []
    for path in sorted(src_dir.rglob("*.sol")):
        if path.name == ALLOWED:
            continue
        code = strip_noncode(path.read_text(encoding="utf-8"))
        for number, line in enumerate(code.splitlines(), start=1):
            if CALL.search(line):
                found.append((path, number, line.strip()))
    return found


def main() -> int:
    src_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "src")
    if not src_dir.is_dir():
        print(f"::error::{src_dir} is not a directory")
        return 2

    found = offenders(src_dir)
    if found:
        for path, number, line in found:
            print(f"{path}:{number}: {line}")
        print(
            f"::error::ecrecover is called outside {ALLOWED}. Route it through "
            "SignatureChecker.requireValidSignature — see ADR 0005."
        )
        return 1

    print(f"ok: ecrecover is called only from {ALLOWED}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
