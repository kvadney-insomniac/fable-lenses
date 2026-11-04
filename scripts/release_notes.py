#!/usr/bin/env python3
"""Print the CHANGELOG.md section for the version in VERSION, as release notes.

The release workflow feeds this to `gh release create --notes-file`, so the
GitHub Release body is the CHANGELOG entry verbatim and nothing is written
twice. Exits 1 if CHANGELOG.md has no section for the current version.

    python3 scripts/release_notes.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HEADING = re.compile(r"^## \[(?P<version>[^\]]+)\]")


def section_for(version: str, changelog: str) -> str | None:
    lines = changelog.splitlines()
    start = next((i for i, line in enumerate(lines)
                  if (m := HEADING.match(line)) and m.group("version") == version), None)
    if start is None:
        return None
    end = next((i for i in range(start + 1, len(lines)) if HEADING.match(lines[i])),
               len(lines))
    body = lines[start + 1:end]
    # Drop the link-reference definitions that Keep a Changelog puts at the foot.
    body = [line for line in body if not re.match(r"^\[[^\]]+\]:\s*\S+", line)]
    return "\n".join(body).strip() + "\n"


def main() -> int:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    notes = section_for(version, (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"))
    if notes is None:
        print(f"release_notes: CHANGELOG.md has no section for {version}", file=sys.stderr)
        return 1
    sys.stdout.write(notes)
    return 0


if __name__ == "__main__":
    sys.exit(main())
