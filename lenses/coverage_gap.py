#!/usr/bin/env python3
"""Lens 2: test-coverage gap = high churn x weak test coverage.

The churn data score_targets.py already produced tells us what changes a lot.
This crosses it with a cheap coverage proxy (how many test files even mention
the module) to find the high-value files most dangerous to refactor without a
characterization test first. These are the pre-Fable golden-master targets.

Heuristic, not pytest-cov: test-file *reference count* is a recall filter, not
precision. A file with high churn and 0-1 referencing test files is where a
golden master buys the most safety before any aggressive refactor.

Usage:
  python3 coverage_gap.py <scores.json> <repo_path> [--tests-dir tests/]
      [--include /services/ --include /routes/] [--top 18]

<scores.json> is the `--json` output of score_targets.py, run against the same
repo — the churn and complexity numbers are read straight out of it.
"""
import argparse
import json
import subprocess
from pathlib import Path


def load_tests(repo: str, tests_dir: str) -> list[str]:
    """Contents of every tracked test file, read once.

    The ranking asks "which tests mention this module?" for every candidate, so
    reading the test suite per candidate would be quadratic for no reason.
    """
    names = subprocess.run(
        ["git", "-C", repo, "ls-files", tests_dir],
        capture_output=True, text=True).stdout.splitlines()
    bodies = []
    for tf in names:
        try:
            bodies.append((Path(repo) / tf).read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            pass
    return bodies


def refs(module_path: str, tests: list[str]) -> int:
    """How many test files mention this module's stem.

    Stem, not full path: `pkg/services/widget_service.py` -> `widget_service`,
    which is what an import or a fixture name would actually say.
    """
    stem = Path(module_path).stem
    if stem in ("__init__",):
        return 99  # package markers are never the refactor target
    return sum(1 for body in tests if stem in body)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("scores", help="JSON written by score_targets.py --json")
    ap.add_argument("repo", help="path to the same git repo those scores describe")
    ap.add_argument("--tests-dir", default="tests/",
                    help="git pathspec for the test suite (default: tests/)")
    ap.add_argument("--include", action="append", default=[],
                    help="only rank files whose path contains this substring; "
                         "repeatable. Useful to keep the list on behavioral code "
                         "(e.g. --include /services/) rather than config and glue, "
                         "where a golden master proves nothing. Default: no filter.")
    ap.add_argument("--min-impact", type=int, default=4,
                    help="churn bucket floor, 1-5 (default: 4 = top 40%% by churn)")
    ap.add_argument("--top", type=int, default=18)
    args = ap.parse_args()

    rows = json.loads(Path(args.scores).read_text(encoding="utf-8"))
    tests = load_tests(args.repo, args.tests_dir)

    out = []
    for r in rows:
        if r["impact"] < args.min_impact:      # high-churn only
            continue
        if args.include and not any(tok in r["file"] for tok in args.include):
            continue
        tr = refs(r["file"], tests)
        # gap: churn weighted down by coverage. 0 test refs = full churn weight.
        gap = round(r["churn_raw"] / (1 + tr), 1)
        out.append((gap, r["file"], r["commits"], r["impact"], r["complexity"]["raw"], tr))

    out.sort(reverse=True)
    print(f"{'gap':>7}  {'commits':>7}  {'cx':>6}  {'tests':>5}  file")
    print("-" * 78)
    for gap, f, commits, imp, cx, tr in out[: args.top]:
        print(f"{gap:>7}  {commits:>7}  {cx:>6}  {tr:>5}  {f}")


if __name__ == "__main__":
    main()
