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
  python3 coverage_gap.py <repo_path> [--scores data.json] [--since "180 days ago"]
      [--tests-dir tests/] [--include /services/ --include /routes/] [--top 18]
      [--md REPORT-coverage.md] [--json data-coverage.json]

Like every other lens, the FIRST positional is the repository path. ``--scores``
is optional: without it the churn/complexity pass (score_targets.py) is run
in-process against the same repo and the same ``--since`` window, so a single
command is enough. Pass ``--scores`` to reuse a ranking you already produced.

The older two-positional form, ``coverage_gap.py <scores.json> <repo>``, still
works and prints a deprecation notice to stderr.
"""
import argparse
import json
import subprocess
import sys
import re
from pathlib import Path

from score_targets import score_repo


# Conventional test-file names, for repos that keep tests beside the code
# rather than in one directory. Covers pytest (`test_x.py`, `x_test.py`),
# vitest/jest (`x.test.ts`, `x.spec.tsx`), and Go (`x_test.go`).
_TEST_FILENAME = re.compile(
    r"(^|/)(test_[^/]+\.py|[^/]+_test\.(py|go)|[^/]+\.(test|spec)\.[jt]sx?)$")


def _tracked(repo: str, *args: str) -> list[str]:
    return subprocess.run(
        ["git", "-C", repo, "ls-files", *args],
        capture_output=True, text=True).stdout.splitlines()


def find_tests(repo: str, tests_dir: str) -> tuple[list[str], str]:
    """Tracked test files, and a label saying how they were found.

    Looks in `tests_dir` first, because a repo that has one usually means it.
    When that comes back empty, fall back to matching conventional test
    filenames anywhere in the tree.

    The fallback exists because the directory default is wrong for a whole
    class of repo. Most JS and TS projects co-locate (`Foo.tsx` beside
    `Foo.test.tsx`), so the lens found zero tests, every gap collapsed to the
    raw churn number, and every row read "0 test file(s) mention it". The
    report did say `0 test files read from 'tests/'`, but run_all's index does
    not carry that line, so the ranking looked authoritative when its
    denominator was empty for every file. Silent-zero, in other words: the
    input was missing and the output still looked like an answer.
    """
    names = _tracked(repo, tests_dir)
    if names:
        return names, f"`{tests_dir}`"
    names = [f for f in _tracked(repo) if _TEST_FILENAME.search(f)]
    if names:
        return names, "co-located test files (no `%s` in this repo)" % tests_dir
    return [], f"`{tests_dir}` (none found)"


def read_tests(repo: str, names: list[str]) -> list[str]:
    """Contents of every test file, read once.

    The ranking asks "which tests mention this module?" for every candidate, so
    reading the test suite per candidate would be quadratic for no reason.
    """
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


def rank(rows: list[dict], tests: list[str], include: list[str],
         min_impact: int) -> list[dict]:
    """Cross the churn ranking with the test-reference count.

    ``rows`` is score_targets.py's output shape, whether it arrived through
    ``--scores`` or from an in-process run.
    """
    out: list[dict] = []
    for r in rows:
        if r["impact"] < min_impact:          # high-churn only
            continue
        if include and not any(tok in r["file"] for tok in include):
            continue
        tr = refs(r["file"], tests)
        # gap: churn weighted down by coverage. 0 test refs = full churn weight.
        out.append({
            "file": r["file"],
            "gap": round(r["churn_raw"] / (1 + tr), 1),
            "commits": r["commits"],
            "impact": r["impact"],
            "complexity_raw": r["complexity"]["raw"],
            "test_refs": tr,
        })
    out.sort(key=lambda r: (r["gap"], r["file"]), reverse=True)
    return out


def render_md(repo: str, rows: list[dict], top: int, tests_dir: str,
              n_tests: int, min_impact: int, source: str) -> str:
    out = [
        f"# Fable-target, COVERAGE-GAP lens, `{repo}`",
        "",
        f"_{len(rows)} high-churn files ranked (churn bucket >= {min_impact}) · "
        f"{n_tests} test files read from {tests_dir} · scores from {source}._",
        "",
        "`gap = churn / (1 + test files that mention this module)`. A big gap is "
        "a much-edited file that almost nothing tests: write the golden master "
        "*before* the refactor, not after.",
        "",
        "> **Reference count, not coverage.** This counts test files whose text "
        "mentions the module stem, which over-counts (a passing mention is not a "
        "test) and under-counts (a module exercised only through an integration "
        "path is never named). It ranks where a characterization test buys the "
        "most safety; it does not measure coverage. Use `pytest-cov` for that.",
        "",
        "| # | gap | file | commits | cx(raw) | test files |",
        "|--:|----:|------|--------:|--------:|-----------:|",
    ]
    for i, r in enumerate(rows[:top], 1):
        out.append(f"| {i} | **{r['gap']}** | `{r['file']}` | {r['commits']} | "
                   f"{r['complexity_raw']} | {r['test_refs']} |")
    out.append("")
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("repo", help="path to the git repo to rank")
    ap.add_argument("legacy_repo", nargs="?", help=argparse.SUPPRESS)
    ap.add_argument("--scores", metavar="FILE",
                    help="JSON written by score_targets.py --json against this "
                         "same repo. Default: run that pass in-process.")
    ap.add_argument("--since", default="180 days ago",
                    help="git churn window used when --scores is not given "
                         "(default: 180 days ago)")
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
    ap.add_argument("--md", help="write the markdown report here (default: stdout)")
    ap.add_argument("--json", help="write the full ranked data here")
    args = ap.parse_args()

    scores_file = args.scores
    repo = args.repo
    if args.legacy_repo is not None:
        # Old shape: coverage_gap.py <scores.json> <repo>. Keep it working, the
        # flag form is what the README documents now.
        scores_file, repo = args.repo, args.legacy_repo
        print("[coverage_gap] deprecated positional form "
              "'<scores.json> <repo>'; use '<repo> --scores <scores.json>'",
              file=sys.stderr)

    if scores_file:
        rows = json.loads(Path(scores_file).read_text(encoding="utf-8"))
        source = f"`{scores_file}`"
    else:
        rows = score_repo(repo, args.since)
        source = f"an in-process score_targets pass, since {args.since}"

    test_names, tests_label = find_tests(repo, args.tests_dir)
    tests = read_tests(repo, test_names)
    ranked = rank(rows, tests, args.include, args.min_impact)
    if not tests:
        print(f"[coverage_gap] no test files under {args.tests_dir!r} and none "
              "matching the conventional test-file names either; every gap is "
              "the raw churn number. Pass --tests-dir to point at your suite.",
              file=sys.stderr)

    md = render_md(repo, ranked, args.top, tests_label, len(tests),
                   args.min_impact, source)
    if args.md:
        Path(args.md).write_text(md, encoding="utf-8")
        print(f"wrote {args.md}")
    else:
        print(md)
    if args.json:
        Path(args.json).write_text(json.dumps(ranked, indent=2), encoding="utf-8")
        print(f"wrote {args.json}")


if __name__ == "__main__":
    main()
