#!/usr/bin/env python3
"""Fable-target, the "targeting machine".

Sweep a repo with a cheap, deterministic pass and score every code file on
``impact x opportunity`` so a premium model (Fable 5) can be aimed at the
highest-leverage work instead of roaming free and burning context/credits.

The worked lens here is **tech debt**, exactly as in the source method:

    score = git_churn(impact)  x  complexity(opportunity)

Both axes are computed INDEPENDENTLY, normalised to a 1-5 quintile bucket
across the repo, then multiplied (1..25). Files where either axis is a 1 or 2
are discarded; the "high x high" quadrant (both axes >= 3) is the target list.

Why this split:
  * churn is EXACT (git history) - don't waste model tokens estimating it.
  * complexity is a recall filter (cast wide, cheap). It flags BIG/branchy
    files, not necessarily BAD ones - precision is the job of the follow-up
    model pass that actually reads the top slice.

Python files get REAL complexity via stdlib ``ast`` (cyclomatic + nesting),
which avoids counting branch keywords inside SQL strings/comments. TS/JS has
no stdlib parser, so it uses a line heuristic.

Usage:
    python3 score_targets.py <repo_path> [--since 180d] [--top 40] \
        [--md out.md] [--json out.json]

Buckets are quintiles WITHIN a repo, so a score of 16 in one repo is not
comparable to a score of 16 in another - rank within a repo only.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path

PY_EXT = {".py"}
TS_EXT = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}

# Load-bearing exclusions. Without these, append-only / generated / vendored
# files dominate the churn ranking and bury the real product code.
DENY = (
    # Schema migrations are append-only: maximum churn, zero refactor value.
    "alembic/versions/",
    "migrations/",
    # Vendored / installed dependencies - somebody else's code.
    "node_modules/",
    "vendor/",
    ".venv/",
    "site-packages/",
    "__pycache__/",
    # Build output and lockfiles - generated, not authored.
    "dist/",
    "build/",
    ".next/",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "__snapshots__/",
    "/__mocks__/",
    "/tests/",
    "test_",
    "_test.",
    ".test.",
    ".spec.",
    ".stories.",
    ".min.",
    "/generated/",
    ".gen.",
    "_pb2",
    "conftest.py",
    ".d.ts",
)


def denied(path: str) -> bool:
    return any(token in path for token in DENY)


def git(args: list[str], cwd: str) -> str:
    return subprocess.run(
        ["git", "-C", cwd, *args],
        capture_output=True,
        text=True,
        check=False,
    ).stdout


# --------------------------------------------------------------------------- #
# IMPACT: git churn
# --------------------------------------------------------------------------- #
def _resolve_rename(path: str) -> str:
    """Attribute churn under a renamed path to its CURRENT name where possible.

    git numstat encodes renames as ``old => new`` or ``dir/{old => new}/x``.
    """
    if "=>" not in path:
        return path
    if "{" in path and "}" in path:
        pre, rest = path.split("{", 1)
        mid, post = rest.split("}", 1)
        new = mid.split("=>", 1)[1].strip()
        return (pre + new + post).replace("//", "/")
    return path.split("=>", 1)[1].strip()


def collect_churn(repo: str, since: str) -> tuple[dict[str, int], dict[str, int]]:
    """Return (commits_touching_file, lines_churned) over the window."""
    out = git(
        # NB: must be `--pretty=format:...`; a bare `--format=FOO` is read as a
        # *named* builtin format and git rejects an unknown name.
        ["log", f"--since={since}", "--no-merges", "--numstat", "--pretty=format:__COMMIT__"],
        repo,
    )
    commits: dict[str, int] = defaultdict(int)
    lines: dict[str, int] = defaultdict(int)
    for raw in out.splitlines():
        if not raw or raw == "__COMMIT__":
            continue
        parts = raw.split("\t")
        if len(parts) != 3:
            continue
        added, deleted, path = parts
        path = _resolve_rename(path)
        commits[path] += 1  # one numstat row per (commit, file)
        if added != "-" and deleted != "-":
            lines[path] += int(added) + int(deleted)
    return commits, lines


# --------------------------------------------------------------------------- #
# OPPORTUNITY: complexity
# --------------------------------------------------------------------------- #
_PY_DECISION = (
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.ExceptHandler,
    ast.With,
    ast.AsyncWith,
    ast.IfExp,  # ternary
    ast.comprehension,  # each for-clause in a comprehension
    ast.Assert,
)
# ast.Match exists only on Python >= 3.10; isinstance(x, ()) is False, so an
# empty tuple makes the check a no-op on older interpreters instead of crashing.
_PY_MATCH = getattr(ast, "Match", ())
_PY_NESTING = (
    ast.If,
    ast.For,
    ast.While,
    ast.With,
    ast.Try,
    ast.AsyncFor,
    ast.AsyncWith,
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
)


def _py_max_depth(node: ast.AST, depth: int = 0) -> int:
    best = depth
    for child in ast.iter_child_nodes(node):
        step = depth + 1 if isinstance(child, _PY_NESTING) else depth
        best = max(best, _py_max_depth(child, step))
    return best


def py_complexity(src: str) -> dict:
    tree = ast.parse(src)
    cc = 1
    funcs = 0
    for node in ast.walk(tree):
        if isinstance(node, _PY_DECISION):
            cc += 1
        elif isinstance(node, ast.BoolOp):
            cc += len(node.values) - 1
        elif _PY_MATCH and isinstance(node, _PY_MATCH):
            cc += len(node.cases)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs += 1
    loc = sum(
        1 for ln in src.splitlines() if ln.strip() and not ln.strip().startswith("#")
    )
    depth = _py_max_depth(tree)
    raw = cc + 0.05 * loc + 1.5 * depth
    return {"loc": loc, "cc": cc, "depth": depth, "funcs": funcs, "raw": round(raw, 1)}


_TS_BRANCH = re.compile(r"\b(if|for|while|case|catch|switch)\b|&&|\|\||\?\?|\?\.")


def ts_complexity(src: str) -> dict:
    loc = 0
    branches = 0
    for ln in src.splitlines():
        s = ln.strip()
        if not s or s.startswith(("//", "*", "/*")):
            continue
        loc += 1
        branches += len(_TS_BRANCH.findall(s))
    funcs = src.count("=>")
    raw = branches + 0.05 * loc
    return {"loc": loc, "cc": branches, "depth": 0, "funcs": funcs, "raw": round(raw, 1)}


# --------------------------------------------------------------------------- #
# Normalisation
# --------------------------------------------------------------------------- #
def quintile_bucketer(values: list[float]):
    """Map a value to a 1..5 bucket by quintile of the supplied distribution."""
    sv = sorted(values)
    if not sv:
        return lambda _v: 1
    thresholds = [sv[int(len(sv) * q)] for q in (0.2, 0.4, 0.6, 0.8)]

    def bucket(v: float) -> int:
        return 1 + sum(v > t for t in thresholds)

    return bucket


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #
def score_repo(repo: str, since: str) -> list[dict]:
    repo_path = Path(repo)
    commits, lines = collect_churn(repo, since)

    tracked = git(["ls-files"], repo).splitlines()
    rows: list[dict] = []
    for rel in tracked:
        ext = Path(rel).suffix
        if ext not in PY_EXT and ext not in TS_EXT:
            continue
        if denied(rel):
            continue
        full = repo_path / rel
        try:
            src = full.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        try:
            cx = py_complexity(src) if ext in PY_EXT else ts_complexity(src)
        except (SyntaxError, ValueError):
            cx = ts_complexity(src)  # fall back to heuristic on unparseable py
        n_commits = commits.get(rel, 0)
        n_lines = lines.get(rel, 0)
        rows.append(
            {
                "file": rel,
                "commits": n_commits,
                "lines": n_lines,
                "churn_raw": n_commits + n_lines / 1000.0,
                "complexity": cx,
            }
        )

    churn_bucket = quintile_bucketer([r["churn_raw"] for r in rows])
    cx_bucket = quintile_bucketer([r["complexity"]["raw"] for r in rows])
    for r in rows:
        r["impact"] = churn_bucket(r["churn_raw"])  # git churn
        r["opportunity"] = cx_bucket(r["complexity"]["raw"])  # complexity
        r["score"] = r["impact"] * r["opportunity"]
    rows.sort(key=lambda r: (r["score"], r["churn_raw"]), reverse=True)
    return rows


def render_md(repo: str, since: str, rows: list[dict], top: int) -> str:
    # Strict top-right corner: both axes in the top 40% of the repo. (A looser
    # "both >= 3" keeps ~46% of files because churn and complexity correlate -
    # too wide to call a target list.)
    target = [r for r in rows if r["impact"] >= 4 and r["opportunity"] >= 4]
    out = []
    out.append(f"# Fable-target ranking, `{repo}`")
    out.append("")
    out.append(
        f"_Window: commits since **{since}** · {len(rows)} code files scored · "
        f"**{len(target)}** in the high-impact x high-opportunity quadrant._"
    )
    out.append("")
    out.append(
        "`score = impact(git churn 1-5) x opportunity(complexity 1-5)`. "
        "Buckets are quintiles **within this repo**, don't compare scores across repos."
    )
    out.append("")

    def table(items: list[dict]) -> list[str]:
        lines = [
            "| # | score | I×O | file | commits | churn LOC | cx(raw) | cc | loc | depth |",
            "|--:|------:|:---:|------|--------:|----------:|--------:|---:|----:|------:|",
        ]
        for i, r in enumerate(items, 1):
            cx = r["complexity"]
            lines.append(
                f"| {i} | **{r['score']}** | {r['impact']}×{r['opportunity']} | "
                f"`{r['file']}` | {r['commits']} | {r['lines']} | {cx['raw']} | "
                f"{cx['cc']} | {cx['loc']} | {cx['depth']} |"
            )
        return lines

    out.append("## 🎯 Target list, high impact × high opportunity (both ≥ 4)")
    out.append("")
    out.append("These are where to point Fable 5 first. Ordered by score.")
    out.append("")
    out += table(target[:top])
    out.append("")
    out.append(f"## Full top {top} (all surviving the 1-2 discard)")
    out.append("")
    kept = [r for r in rows if r["impact"] >= 3 or r["opportunity"] >= 3]
    out += table(kept[:top])
    out.append("")
    out.append("---")
    out.append(
        "**How to use:** point the premium model at the top of the target list, "
        "and ask for the *root-cause / meta-level* fix, not a point fix, "
        "models default to patching the symptom unless told to go architectural."
    )
    out.append("")
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("repo", help="path to the git repo to score")
    ap.add_argument("--since", default="180 days ago", help="git churn window")
    ap.add_argument("--top", type=int, default=40, help="rows to render")
    ap.add_argument("--md", help="write the markdown report here")
    ap.add_argument("--json", help="write the full ranked data here")
    args = ap.parse_args()

    rows = score_repo(args.repo, args.since)
    md = render_md(args.repo, args.since, rows, args.top)

    if args.md:
        Path(args.md).write_text(md, encoding="utf-8")
        print(f"wrote {args.md}")
    else:
        print(md)
    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=2), encoding="utf-8")
        print(f"wrote {args.json}")


if __name__ == "__main__":
    main()
