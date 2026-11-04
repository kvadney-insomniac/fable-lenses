#!/usr/bin/env python3
"""Check that the toolkit's version is stated once and agrees everywhere.

The single source of truth is the VERSION file at the repository root. This
script verifies, and exits 1 on the first mismatch:

  1. VERSION holds one semantic version, MAJOR.MINOR.PATCH with an optional
     pre-release suffix (https://semver.org/spec/v2.0.0.html).
  2. The newest versioned heading in CHANGELOG.md is that same version, in the
     Keep a Changelog shape `## [X.Y.Z] - YYYY-MM-DD`
     (https://keepachangelog.com/en/1.1.0/), and its date parses.
  3. `python3 lenses/run_all.py --version` prints that version.
  4. If `--tag vX.Y.Z` is given (CI passes the pushed git tag), the tag is
     `v` + VERSION. A release tag that disagrees with the files is refused
     before any release is created.

    python3 scripts/check_version.py
    python3 scripts/check_version.py --tag v0.1.0
"""
from __future__ import annotations

import argparse
import datetime as dt
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEMVER = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*)?$")
HEADING = re.compile(r"^## \[(?P<version>[^\]]+)\](?: - (?P<date>\d{4}-\d{2}-\d{2}))?\s*$")


def fail(msg: str) -> int:
    print(f"check_version: {msg}", file=sys.stderr)
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tag", help="a git tag that must equal 'v' + VERSION")
    args = ap.parse_args()

    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not SEMVER.match(version):
        return fail(f"VERSION {version!r} is not a semantic version")

    headings = [HEADING.match(line) for line in
                (ROOT / "CHANGELOG.md").read_text(encoding="utf-8").splitlines()]
    versioned = [m for m in headings if m and m.group("version").lower() != "unreleased"]
    if not versioned:
        return fail("CHANGELOG.md has no '## [X.Y.Z] - YYYY-MM-DD' heading")
    newest = versioned[0]
    if newest.group("version") != version:
        return fail(f"newest CHANGELOG heading is {newest.group('version')}, "
                    f"VERSION is {version}")
    if not newest.group("date"):
        return fail(f"CHANGELOG heading for {version} has no release date")
    try:
        dt.date.fromisoformat(newest.group("date"))
    except ValueError:
        return fail(f"CHANGELOG date {newest.group('date')!r} is not YYYY-MM-DD")

    proc = subprocess.run([sys.executable, str(ROOT / "lenses" / "run_all.py"), "--version"],
                          capture_output=True, text=True)
    printed = proc.stdout.strip()
    if proc.returncode != 0 or printed != f"fable-lenses {version}":
        return fail(f"run_all.py --version printed {printed!r}, expected "
                    f"'fable-lenses {version}'")

    if args.tag is not None and args.tag != f"v{version}":
        return fail(f"tag {args.tag} does not match VERSION {version} (expected v{version})")

    print(f"check_version: ok, {version}"
          + (f", tag {args.tag} matches" if args.tag else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
