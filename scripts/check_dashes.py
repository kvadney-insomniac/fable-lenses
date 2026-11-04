#!/usr/bin/env python3
"""Fail if any tracked text file contains an em dash or an en dash.

The repository's prose uses plain hyphens and commas on purpose, and CI
enforces it so the rule does not depend on anyone remembering it.

    python3 scripts/check_dashes.py            # every git-tracked file
    python3 scripts/check_dashes.py README.md  # named files only
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

# Built from code points so this file contains neither character itself.
BAD = {chr(0x2014): "em dash", chr(0x2013): "en dash"}
BINARY = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".ico", ".woff", ".woff2", ".lock"}


def tracked_files() -> list[Path]:
    out = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True)
    return [Path(p) for p in out.stdout.splitlines()]


def main() -> int:
    paths = [Path(a) for a in sys.argv[1:]] or tracked_files()
    hits = []
    for path in paths:
        if path.suffix.lower() in BINARY or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            for ch, label in BAD.items():
                if ch in line:
                    hits.append(f"{path}:{n}: {label}")
    print("\n".join(hits) if hits else "check_dashes: no em dash or en dash")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
